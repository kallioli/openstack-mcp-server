import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { Catalog } from "../src/catalog.js";
import { loadConfig } from "../src/config.js";
import { createHttpApp } from "../src/http.js";
import { OpenStackClient } from "../src/openstack/client.js";
import { OidcOAuthProvider } from "../src/oauth/provider.js";
import { type OAuthIdentity, Store } from "../src/store/db.js";
import { APP_CRED_PROJECT, AUTH_URL, PROJECTS, fakeCloud } from "./fake-openstack.js";
import { ISSUER, fakeIdp } from "./fake-idp.js";

const PORT = 41_000 + Math.floor(Math.random() * 9_000);
const BASE = `http://localhost:${PORT}`;
const REDIRECT = "http://localhost:9/callback";

const cloud = fakeCloud({ acceptOidc: (t) => t.startsWith("idp-access-") });
const idp = fakeIdp(cloud.fetch);
const OAUTH = { issuer: ISSUER, clientId: "app-id", clientSecret: "app-secret", secret: "x".repeat(40), scopes: ["openid", "email"] };
const FEDERATION = { authUrl: AUTH_URL, identityProvider: "sso", protocol: "openid" };

/** Project of the last Cinder call: the shared connection is bound to staging, personal calls name prod. */
const lastProject = () => {
  const url = cloud.apiCalls().at(-1)?.url ?? "";
  return url.includes(APP_CRED_PROJECT.id) ? "shared" : url.includes(PROJECTS[0].id) ? "personal" : "none";
};
const VOLUMES = { service: "block-storage", path: "/v3/volumes" };

const dir = mkdtempSync(join(tmpdir(), "osmcp-oauth-rules-"));
const store = new Store(join(dir, "rules.db"), "r".repeat(40));
let server: ReturnType<ReturnType<typeof createHttpApp>["listen"]>;
let shared: string;

beforeAll(async () => {
  const config = loadConfig({ HOST: "localhost", PUBLIC_URL: BASE });
  const provider = new OidcOAuthProvider({
    ...OAUTH,
    publicUrl: config.publicUrl!,
    fetch: idp.fetch,
    authorizeLogin: (id) => store.checkOAuthLogin(id, true),
  });
  shared = store.createConnection({
    name: "Acme",
    credentials: { authUrl: AUTH_URL, auth: { type: "application_credential", id: "ac", secret: "app-secret" } },
  }).id;
  const app = createHttpApp(config, Catalog.load(), new OpenStackClient({ fetch: idp.fetch }), {
    oauth: provider,
    store,
    settings: () => ({ publicUrl: config.publicUrl, readOnly: false, maxResponseChars: 60_000, oauth: OAUTH, federation: FEDERATION }),
  });
  server = app.listen(PORT, "localhost");
  await new Promise((r) => server.once("listening", r));
});

afterAll(() => {
  server.close();
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

beforeEach(() => {
  for (const r of store.listOAuthRules()) store.deleteOAuthRule(r.id);
  store.setOAuthDefaultPolicy("personal");
});

const form = (params: Record<string, string>) => ({
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams(params),
});

/** Registers a client and starts an authorization; returns the state the identity provider would send back. */
async function authorize() {
  const { client_id } = await (
    await fetch(`${BASE}/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ redirect_uris: [REDIRECT], token_endpoint_auth_method: "none" }),
    })
  ).json();
  const verifier = randomBytes(32).toString("base64url");
  const started = await fetch(
    `${BASE}/authorize?${new URLSearchParams({
      response_type: "code",
      client_id,
      redirect_uri: REDIRECT,
      code_challenge: createHash("sha256").update(verifier).digest("base64url"),
      code_challenge_method: "S256",
    })}`,
    { redirect: "manual" },
  );
  const state = new URL(started.headers.get("location")!).searchParams.get("state")!;
  return { client_id, verifier, state };
}

/** Runs the whole OAuth dance; returns the access token, or the error the client is redirected with. */
async function signIn(who: Record<string, unknown>): Promise<{ accessToken?: string; error?: string; description?: string }> {
  idp.setIdentity(who);
  const { client_id, verifier, state } = await authorize();
  const callback = await fetch(`${BASE}/oauth/callback?code=c&state=${encodeURIComponent(state)}`, { redirect: "manual" });
  const back = new URL(callback.headers.get("location")!);
  if (back.searchParams.get("error")) {
    return { error: back.searchParams.get("error")!, description: back.searchParams.get("error_description") ?? undefined };
  }
  const tokens = await (
    await fetch(`${BASE}/token`, form({ grant_type: "authorization_code", code: back.searchParams.get("code")!, client_id, code_verifier: verifier, redirect_uri: REDIRECT }))
  ).json();
  return { accessToken: tokens.access_token };
}

function mcp(token: string, method: string, params?: object) {
  return fetch(`${BASE}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}` },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
}

async function connectionChoices(token: string): Promise<string[] | undefined> {
  const { result } = await (await mcp(token, "tools/list")).json();
  const get = result.tools.find((t: { name: string }) => t.name === "openstack_get");
  return get.inputSchema.properties.connection?.enum;
}

const JANE: Record<string, unknown> = { sub: "1001", email: "jane@example.com", email_verified: true, name: "Jane" };

describe("OAuth users and the admin's rules", () => {
  it("gives users matching no rule their personal access only (default policy)", async () => {
    const { accessToken } = await signIn(JANE);
    expect(await connectionChoices(accessToken!)).toBeUndefined();
    await mcp(accessToken!, "tools/call", { name: "openstack_get", arguments: { ...VOLUMES, project: "prod" } });
    expect(lastProject()).toBe("personal");
    const seen = store.listOAuthIdentities().find((i) => i.sub === "1001");
    expect(seen).toMatchObject({ email: "jane@example.com", emailVerified: true, ruleId: null });
  });

  it("grants shared connections to a domain, alongside the personal access", async () => {
    store.createOAuthRule({ name: "Support team", matchType: "domain", matchValue: "@Example.com", connectionIds: [shared], defaultConnectionId: shared });
    const { accessToken } = await signIn(JANE);
    expect(await connectionChoices(accessToken!)).toEqual(["Acme", "Personal"]);

    await mcp(accessToken!, "tools/call", { name: "openstack_get", arguments: VOLUMES });
    expect(lastProject()).toBe("shared");
    await mcp(accessToken!, "tools/call", { name: "openstack_get", arguments: { ...VOLUMES, connection: "Personal", project: "prod" } });
    expect(lastProject()).toBe("personal");
  });

  it("applies the rule's restrictions and is re-evaluated on every request", async () => {
    const rule = store.createOAuthRule({
      name: "Jane",
      matchType: "email",
      matchValue: "jane@example.com",
      connectionIds: [shared],
      includePersonal: false,
      readOnly: true,
      categories: ["Block Storage"],
    });
    const { accessToken } = await signIn(JANE);
    const tools = (await (await mcp(accessToken!, "tools/list")).json()).result.tools.map((t: { name: string }) => t.name);
    expect(tools).not.toContain("openstack_request");
    const network = await (await mcp(accessToken!, "tools/call", { name: "openstack_get", arguments: { service: "network", path: "/v2.0/networks" } })).json();
    expect(network.result.isError).toBe(true);
    const volumes = await (await mcp(accessToken!, "tools/call", { name: "openstack_get", arguments: VOLUMES })).json();
    expect(volumes.result.isError).toBeFalsy();

    // Disabling the rule takes effect on the next request; with the deny policy the user is now refused.
    store.updateOAuthRule(rule.id, { enabled: false });
    store.setOAuthDefaultPolicy("deny");
    expect((await mcp(accessToken!, "tools/list")).status).toBe(403);
  });

  it("refuses users matching no rule at login when the policy is deny", async () => {
    store.setOAuthDefaultPolicy("deny");
    const refused = await signIn({ sub: "2002", email: "someone@example.com", email_verified: true });
    expect(refused.error).toBe("access_denied");
    expect(refused.description).toContain("not allowed");
    // The attempt is visible to the admin, who can then create a rule for this user.
    expect(store.listOAuthIdentities().some((i) => i.sub === "2002")).toBe(true);

    store.createOAuthRule({ name: "Someone", matchType: "user", matchValue: "2002", includePersonal: true });
    expect((await signIn({ sub: "2002", email: "someone@example.com", email_verified: true })).accessToken).toBeTruthy();
  });

  it("never matches e-mail rules on unverified addresses", async () => {
    store.createOAuthRule({ name: "Team", matchType: "domain", matchValue: "example.com", connectionIds: [shared], defaultConnectionId: shared });
    store.setOAuthDefaultPolicy("deny");
    const spoofed = await signIn({ sub: "3003", email: "intruder@example.com", email_verified: false });
    expect(spoofed.error).toBe("access_denied");
  });
});

describe("identity provider errors on the callback", () => {
  it("are logged and passed on to the client", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const { state } = await authorize();
      const callback = await fetch(
        `${BASE}/oauth/callback?${new URLSearchParams({ state, error: "invalid_scope", error_description: "Unknown scope\nfake log line" })}`,
        { redirect: "manual" },
      );
      const back = new URL(callback.headers.get("location")!);
      expect(back.searchParams.get("error")).toBe("server_error");
      expect(back.searchParams.get("error_description")).toContain("Unknown scope");
      const logged = warn.mock.calls.map((c) => String(c[0])).join("\n");
      expect(logged).toContain('"invalid_scope" "Unknown scope\\nfake log line"');

      await fetch(`${BASE}/oauth/callback?state=forged&error=access_denied`);
      expect(String(warn.mock.calls.at(-1)?.[0])).toContain("invalid or expired state");
    } finally {
      warn.mockRestore();
    }
  });
});

describe("rule validation", () => {
  it("rejects incoherent rules", () => {
    expect(() => store.createOAuthRule({ name: "x", matchType: "email", matchValue: "not-an-email" })).toThrow(/e-mail/);
    expect(() => store.createOAuthRule({ name: "x", matchType: "domain", matchValue: "nodot" })).toThrow(/domain/);
    expect(() => store.createOAuthRule({ name: "x", matchType: "user", matchValue: "1", includePersonal: false })).toThrow(/at least one/);
    expect(() =>
      store.createOAuthRule({ name: "x", matchType: "user", matchValue: "1", connectionIds: [shared], defaultConnectionId: "other" }),
    ).toThrow(/default connection/);
    // A connection used by a rule cannot be deleted.
    store.createOAuthRule({ name: "Uses shared", matchType: "user", matchValue: "9", connectionIds: [shared] });
    expect(() => store.deleteConnection(shared)).toThrow(/OAuth rule/);
  });

  it("matches user id before e-mail before domain", () => {
    const domain = store.createOAuthRule({ name: "Domain", matchType: "domain", matchValue: "example.com", includePersonal: true });
    const email = store.createOAuthRule({ name: "Email", matchType: "email", matchValue: "jane@example.com", includePersonal: true });
    const user = store.createOAuthRule({ name: "User", matchType: "user", matchValue: "1001", includePersonal: true });
    const jane: OAuthIdentity = { sub: "1001", email: "jane@example.com", emailVerified: true };
    expect(store.matchOAuthRule(jane)?.id).toBe(user.id);
    expect(store.matchOAuthRule({ ...jane, sub: "x" })?.id).toBe(email.id);
    expect(store.matchOAuthRule({ ...jane, sub: "x", email: "anna@example.com" })?.id).toBe(domain.id);
  });
});
