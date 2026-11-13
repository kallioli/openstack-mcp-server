/**
 * A fake OpenStack cloud for the tests: Keystone (password, application credential, token and federation methods,
 * /v3/auth/projects) and a recorder for every other API call.
 */
export const AUTH_URL = "https://keystone.test:5000";
export const PROJECTS = [
  { id: "a1b2c3d4e5f60718293a4b5c6d7e8f90", name: "prod", domain_id: "default" },
  { id: "0f9e8d7c6b5a49382716f5e4d3c2b1a0", name: "staging", domain_id: "default" },
];
export const APP_CRED_PROJECT = PROJECTS[1];

export interface FakeCall {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
}

export interface FakeCloud {
  fetch: typeof fetch;
  calls: FakeCall[];
  /** Calls to anything but Keystone's auth endpoints. */
  apiCalls: () => FakeCall[];
  authCount: () => number;
  /** Next API answer (status and JSON body), reset after use. */
  respond: (status: number, payload: unknown, headers?: Record<string, string>) => void;
  /** Revokes every issued token: the next API call answers 401. */
  revokeTokens: () => void;
}

function catalogFor(projectId: string) {
  const ep = (url: string, region = "RegionOne") => [
    { interface: "public", region_id: region, region, url },
    { interface: "internal", region_id: region, region, url: url.replace("https://", "http://internal.") },
  ];
  return [
    { type: "identity", endpoints: ep(`${AUTH_URL}/v3`) },
    { type: "compute", endpoints: [...ep("https://nova.test:8774/v2.1"), ...ep("https://nova-two.test/v2.1", "RegionTwo")] },
    { type: "network", endpoints: ep("https://neutron.test:9696") },
    { type: "volumev3", endpoints: ep(`https://cinder.test:8776/v3/${projectId}`) },
    { type: "image", endpoints: ep("https://glance.test:9292") },
    { type: "object-store", endpoints: ep(`https://swift.test:8080/v1/AUTH_${projectId}`) },
    { type: "placement", endpoints: ep("https://placement.test/placement") },
    { type: "orchestration", endpoints: ep(`https://heat.test:8004/v1/${projectId}`) },
    { type: "key-manager", endpoints: ep("https://barbican.test:9311") },
  ];
}

export function fakeCloud(
  options: { password?: string; appCredSecret?: string; acceptOidc?: (token: string) => boolean } = {},
): FakeCloud {
  const password = options.password ?? "s3cret";
  const calls: FakeCall[] = [];
  let auths = 0;
  let next: { status: number; payload: unknown; headers?: Record<string, string> } | undefined;
  let generation = 0;
  const tokens = new Map<string, { project?: (typeof PROJECTS)[number]; generation: number }>();

  const issue = (project: (typeof PROJECTS)[number] | undefined, method: string) => {
    const value = `tok-${tokens.size + 1}`;
    tokens.set(value, { project, generation });
    return new Response(
      JSON.stringify({
        token: {
          methods: [method],
          expires_at: new Date(Date.now() + 3600_000).toISOString(),
          user: { id: "u1", name: "alice", domain: { id: "default", name: "Default" } },
          ...(project ? { project: { id: project.id, name: project.name, domain: { id: "default", name: "Default" } } } : {}),
          roles: project ? [{ id: "r1", name: "member" }] : [],
          ...(project ? { catalog: catalogFor(project.id) } : {}),
        },
      }),
      { status: 201, headers: { "content-type": "application/json", "x-subject-token": value } },
    );
  };
  const unauthorized = () =>
    new Response(JSON.stringify({ error: { code: 401, message: "The request you have made requires authentication.", title: "Unauthorized" } }), {
      status: 401,
      headers: { "content-type": "application/json" },
    });
  const valid = (token: string | undefined) => {
    const t = token ? tokens.get(token) : undefined;
    return t && t.generation === generation ? t : undefined;
  };

  const impl = (async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const headers = Object.fromEntries(Object.entries((init?.headers as Record<string, string>) ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? init.body : undefined;
    calls.push({ url, method, headers, body });
    const u = new URL(url);

    if (u.origin === AUTH_URL && u.pathname === "/v3/auth/tokens" && method === "POST") {
      auths++;
      const { auth } = JSON.parse(body ?? "{}");
      const identity = auth?.identity ?? {};
      const scopeProject = auth?.scope?.project;
      const findProject = () =>
        scopeProject ? PROJECTS.find((p) => p.id === scopeProject.id || p.name === scopeProject.name) : undefined;
      if (identity.methods?.[0] === "password") {
        if (identity.password?.user?.password !== password) return unauthorized();
        if (scopeProject && !findProject()) return unauthorized();
        return issue(findProject(), "password");
      }
      if (identity.methods?.[0] === "application_credential") {
        if (identity.application_credential?.secret !== (options.appCredSecret ?? "app-secret")) return unauthorized();
        return issue(APP_CRED_PROJECT, "application_credential");
      }
      if (identity.methods?.[0] === "token") {
        if (!valid(identity.token?.id)) return unauthorized();
        return issue(findProject(), "token");
      }
      return unauthorized();
    }
    if (u.origin === AUTH_URL && /^\/v3\/OS-FEDERATION\/identity_providers\/[^/]+\/protocols\/[^/]+\/auth$/.test(u.pathname)) {
      auths++;
      const bearer = headers.authorization?.replace(/^Bearer /, "") ?? "";
      if (!(options.acceptOidc ?? ((t) => t === "oidc-access"))(bearer)) return unauthorized();
      return issue(undefined, "openid");
    }
    if (u.origin === AUTH_URL && u.pathname === "/v3/auth/projects") {
      if (!valid(headers["x-auth-token"])) return unauthorized();
      return Response.json({ projects: PROJECTS.map((p) => ({ ...p, enabled: true })) });
    }

    if (!valid(headers["x-auth-token"])) return unauthorized();
    const answer = next ?? { status: 200, payload: { ok: true } };
    next = undefined;
    if (method === "HEAD" || answer.status === 204) return new Response(null, { status: answer.status, headers: answer.headers });
    return new Response(JSON.stringify(answer.payload), {
      status: answer.status,
      headers: { "content-type": "application/json", "x-openstack-request-id": "req-1", ...answer.headers },
    });
  }) as typeof fetch;

  return {
    fetch: impl,
    calls,
    apiCalls: () => calls.filter((c) => !c.url.startsWith(`${AUTH_URL}/v3/auth/`) && !c.url.includes("/OS-FEDERATION/")),
    authCount: () => auths,
    respond: (status, payload, headers) => {
      next = { status, payload, headers };
    },
    revokeTokens: () => {
      generation++;
    },
  };
}

export const PASSWORD_CREDENTIALS = {
  authUrl: AUTH_URL,
  auth: { type: "password" as const, username: "alice", userDomainName: "Default", password: "s3cret" },
  project: { name: "prod", domainName: "Default" },
  region: "RegionOne",
  interface: "public" as const,
};
