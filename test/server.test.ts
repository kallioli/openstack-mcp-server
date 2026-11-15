import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { Catalog, isDangerous } from "../src/catalog.js";
import { loadConfig } from "../src/config.js";
import { createHttpApp } from "../src/http.js";
import { OpenStackClient } from "../src/openstack/client.js";
import { loadProjects } from "../src/projects.js";
import { type ConnectionContext, createServer } from "../src/server.js";
import { AUTH_URL, PASSWORD_CREDENTIALS, PROJECTS, type FakeCloud, fakeCloud } from "./fake-openstack.js";

const catalog = Catalog.load();

async function connect(
  opts: { readOnly?: boolean; cloud?: FakeCloud; connections?: ConnectionContext[]; elicit?: unknown; maxResponseChars?: number } = {},
) {
  const cloud = opts.cloud ?? fakeCloud();
  const openstack = new OpenStackClient({ fetch: cloud.fetch });
  const connections = opts.connections ?? [{ name: "prod-cloud", credentials: PASSWORD_CREDENTIALS }];
  const server = createServer({
    catalog,
    client: openstack,
    connections,
    projects: await loadProjects(openstack, connections),
    readOnly: opts.readOnly,
    maxResponseChars: opts.maxResponseChars,
  });
  const client = new Client({ name: "test", version: "1.0.0" }, opts.elicit ? { capabilities: { elicitation: {} } } : undefined);
  if (opts.elicit) client.setRequestHandler(ElicitRequestSchema, async () => opts.elicit as never);
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  return { client, cloud };
}

function textOf(result: Awaited<ReturnType<Client["callTool"]>>): string {
  return (result.content as { type: string; text: string }[])[0].text;
}

describe("catalog", () => {
  it("covers the main OpenStack services", () => {
    expect(catalog.operations.length).toBeGreaterThan(1500);
    expect(catalog.services()).toEqual(
      expect.arrayContaining(["compute", "network", "block-storage", "image", "identity", "object-store", "load-balancer", "dns"]),
    );
  });

  it("finds operations with everyday words and project code names", () => {
    expect(catalog.search({ query: "list servers", limit: 5 }).map((o) => o.id)).toContain("compute GET /v2.1/servers");
    expect(catalog.search({ query: "vm", service: "compute", limit: 10 }).some((o) => o.path.startsWith("/v2.1/servers"))).toBe(true);
    expect(catalog.search({ query: "neutron floating ip", limit: 5 }).every((o) => o.service === "network")).toBe(true);
    expect(catalog.search({ query: "reboot", limit: 3 }).map((o) => o.id)).toContain("compute POST /v2.1/servers/{id}/action");
  });

  it("matches concrete paths, with or without the version prefix", () => {
    const m = catalog.match("compute", "GET", "/v2.1/servers/abc");
    expect(m?.op.id).toBe("compute GET /v2.1/servers/{id}");
    expect(m?.pathParams).toEqual({ id: "abc" });
    expect(catalog.match("compute", "GET", "/servers/detail")?.op.id).toBe("compute GET /v2.1/servers/detail");
    expect(catalog.match("network", "GET", "/networks")?.path).toBe("/v2.0/networks");
    expect(catalog.match("object-store", "GET", "/v1/AUTH_x/bucket/dir/file.txt")?.pathParams.object).toBe("dir/file.txt");
    expect(catalog.match("compute", "GET", "/v2.0/networks")).toBeUndefined();
  });

  it("flags deletions and destructive actions only", () => {
    const action = catalog.get("compute POST /v2.1/servers/{id}/action")!;
    expect(isDangerous(catalog.get("compute DELETE /v2.1/servers/{id}")!)).toBe(true);
    expect(isDangerous(catalog.get("compute GET /v2.1/servers")!)).toBe(false);
    expect(isDangerous(action, { reboot: { type: "SOFT" } })).toBe(false);
    expect(isDangerous(action, { rebuild: { imageRef: "x" } })).toBe(true);
    expect(isDangerous(action, { forceDelete: null })).toBe(true);
    const volumeAction = catalog.match("block-storage", "POST", "/v3/volumes/v1/action")!.op;
    expect(isDangerous(volumeAction, { "os-reset_status": { status: "available" } })).toBe(true);
    expect(isDangerous(volumeAction, { "os-extend": { new_size: 20 } })).toBe(false);
  });
});

describe("mcp tools", () => {
  it("hides the write tool in read-only mode", async () => {
    const { client } = await connect({ readOnly: true });
    const tools = (await client.listTools()).tools.map((t) => t.name);
    expect(tools).toEqual(expect.arrayContaining(["openstack_list_clouds", "openstack_get", "openstack_search_operations"]));
    expect(tools).not.toContain("openstack_request");
  });

  it("lists the connection's identity, projects, regions and services", async () => {
    const { client } = await connect();
    const out = textOf(await client.callTool({ name: "openstack_list_clouds", arguments: {} }));
    expect(out).toContain('Connection "prod-cloud" (default, read/write)');
    expect(out).toContain("Identity: alice@Default (roles: member)");
    expect(out).toContain("Regions: RegionOne (default), RegionTwo");
    expect(out).toContain(`- staging: ${PROJECTS[1].id}`);
    expect(out).toMatch(/Services in the catalog: .*compute/);
  });

  it("lists the projects in the tool schema", async () => {
    const { client } = await connect();
    const get = (await client.listTools()).tools.find((t) => t.name === "openstack_get")!;
    const project = (get.inputSchema.properties as Record<string, { description: string }>).project;
    expect(project.description).toContain(`prod (${PROJECTS[0].id})`);
  });

  it("describes an operation, and one action of an action endpoint", async () => {
    const { client } = await connect();
    const details = JSON.parse(
      textOf(await client.callTool({ name: "openstack_describe_operation", arguments: { operation: "network POST /v2.0/networks" } })),
    );
    expect(details.body.schema.properties.network).toBeDefined();
    expect(details.tool).toBe("openstack_request");

    const action = JSON.parse(
      textOf(await client.callTool({ name: "openstack_describe_operation", arguments: { operation: "compute POST /v2.1/servers/{id}/action" } })),
    );
    expect(action.actions.map((a: { name: string }) => a.name)).toContain("reboot");
    expect(action.needsConfirmation).toMatch(/rebuild/);
    const reboot = JSON.parse(
      textOf(
        await client.callTool({
          name: "openstack_describe_operation",
          arguments: { operation: "compute POST /v2.1/servers/{id}/action", action: "reboot" },
        }),
      ),
    );
    expect(reboot.body.properties.reboot).toBeDefined();
    expect(reboot.needsConfirmation).toBe(false);
  });

  it("calls the right endpoint with the token, path params and query", async () => {
    const { client, cloud } = await connect();
    const res = await client.callTool({
      name: "openstack_get",
      arguments: { service: "compute", path: "/servers/{id}", path_params: { id: "srv-1" }, query: { fields: "name" } },
    });
    expect(res.isError).toBeFalsy();
    expect(textOf(res)).toMatch(/^HTTP 200 compute GET \/v2.1\/servers\/\{id\} \[project prod \(a1b2.*\), region RegionOne\]/);
    const call = cloud.apiCalls()[0];
    expect(call.url).toBe("https://nova.test:8774/v2.1/servers/srv-1?fields=name");
    expect(call.headers["x-auth-token"]).toMatch(/^tok-/);
  });

  it("acts on another project by name and fills its id in the path", async () => {
    const { client, cloud } = await connect();
    await client.callTool({
      name: "openstack_get",
      arguments: { service: "network", path: "/v2.0/quotas/{project_id}", project: "staging" },
    });
    expect(cloud.apiCalls()[0].url).toBe(`https://neutron.test:9696/v2.0/quotas/${PROJECTS[1].id}`);
    const unknown = await client.callTool({ name: "openstack_get", arguments: { service: "network", path: "/v2.0/networks", project: "nope" } });
    expect(unknown.isError).toBe(true);
    expect(textOf(unknown)).toContain("Known: prod, staging");
  });

  it("fills the Swift account and keeps object names with slashes", async () => {
    const { client, cloud } = await connect();
    await client.callTool({
      name: "openstack_get",
      arguments: { service: "object-store", path: "/v1/{account}/{container}/{object}", path_params: { container: "docs", object: "a/b c.txt" } },
    });
    expect(cloud.apiCalls()[0].url).toBe(`https://swift.test:8080/v1/AUTH_${PROJECTS[0].id}/docs/a/b%20c.txt`);

    cloud.respond(204, null, { "x-container-object-count": "3" });
    const head = await client.callTool({
      name: "openstack_get",
      arguments: { service: "object-store", method: "HEAD", path: "/v1/{account}/{container}", path_params: { container: "docs" } },
    });
    expect(textOf(head)).toContain("x-container-object-count: 3");
  });

  it("uses the operation's minimum microversion and refuses removed ones", async () => {
    const op = catalog.operations.find((o) => o.service === "compute" && o.method === "GET" && o.maxVersion && !o.path.includes("{"))!;
    const { client } = await connect();
    const res = await client.callTool({ name: "openstack_get", arguments: { service: "compute", path: op.path, microversion: "latest" } });
    expect(res.isError).toBe(true);
    expect(textOf(res)).toContain(`removed after microversion ${op.maxVersion}`);
    const noMv = await client.callTool({ name: "openstack_get", arguments: { service: "network", path: "/v2.0/networks", microversion: "2.1" } });
    expect(textOf(noMv)).toContain("has no microversions");
  });

  it("rejects paths, services and headers it does not know", async () => {
    const { client, cloud } = await connect();
    expect((await client.callTool({ name: "openstack_get", arguments: { service: "compute", path: "/v9/nope" } })).isError).toBe(true);
    const badHeader = await client.callTool({
      name: "openstack_request",
      arguments: { service: "object-store", method: "PUT", path: "/v1/{account}/c", headers: { "X-Auth-Token": "x" } },
    });
    expect(textOf(badHeader)).toContain("cannot be set");
    const badAction = await client.callTool({
      name: "openstack_request",
      arguments: { service: "compute", method: "POST", path: "/v2.1/servers/s1/action", body: { explode: {} } },
    });
    expect(textOf(badAction)).toContain("Unknown action(s) explode");
    expect(cloud.apiCalls()).toHaveLength(0);
  });

  it("flags API errors and truncates long answers", async () => {
    const cloud = fakeCloud();
    const { client } = await connect({ cloud, maxResponseChars: 1_000 });
    cloud.respond(404, { itemNotFound: { code: 404, message: "Instance x could not be found." } });
    const res = await client.callTool({ name: "openstack_get", arguments: { service: "compute", path: "/v2.1/servers/x" } });
    expect(res.isError).toBe(true);
    expect(textOf(res)).toContain("HTTP 404");
    cloud.respond(200, { servers: Array.from({ length: 200 }, (_, i) => ({ id: `s${i}` })) });
    const long = await client.callTool({ name: "openstack_get", arguments: { service: "compute", path: "/v2.1/servers" } });
    expect(textOf(long)).toContain("[truncated");
  });

  it("switches between connections and keeps read-only ones read-only", async () => {
    const cloud = fakeCloud();
    const { client } = await connect({
      cloud,
      connections: [
        { name: "main", credentials: PASSWORD_CREDENTIALS },
        { name: "audit", credentials: { ...PASSWORD_CREDENTIALS, project: { id: PROJECTS[1].id } }, readOnly: true },
      ],
    });
    await client.callTool({ name: "openstack_get", arguments: { service: "network", path: "/v2.0/networks", connection: "audit" } });
    expect(cloud.apiCalls()[0].url).toBe("https://neutron.test:9696/v2.0/networks");
    const refused = await client.callTool({
      name: "openstack_request",
      arguments: { service: "network", method: "POST", path: "/v2.0/networks", body: { network: { name: "n" } }, connection: "audit" },
    });
    expect(textOf(refused)).toContain("read-only");
    // A project name that exists in both connections is ambiguous.
    const ambiguous = await client.callTool({ name: "openstack_get", arguments: { service: "network", path: "/v2.0/networks", project: "prod" } });
    expect(textOf(ambiguous)).toContain("matches several projects");
  });
});

describe("curated services", () => {
  it("reaches Heat stacks under the project of the endpoint", async () => {
    const { client, cloud } = await connect();
    const res = await client.callTool({
      name: "openstack_get",
      arguments: { service: "orchestration", path: "/v1/{tenant_id}/stacks/{stack_name}/{stack_id}/events", path_params: { stack_name: "web", stack_id: "st-1" } },
    });
    expect(res.isError).toBeFalsy();
    expect(cloud.apiCalls()[0].url).toBe(`https://heat.test:8004/v1/${PROJECTS[0].id}/stacks/web/st-1/events`);
    const details = JSON.parse(
      textOf(await client.callTool({ name: "openstack_describe_operation", arguments: { operation: "heat POST /v1/{tenant_id}/stacks" } })),
    );
    expect(details.source).toMatch(/^curated/);
  });

  it("asks before showing a Barbican secret payload, as text", async () => {
    const { client, cloud } = await connect();
    const args = { service: "key-manager", path: "/v1/secrets/s-1/payload" };
    expect(textOf(await client.callTool({ name: "openstack_get", arguments: args }))).toContain("confirm: true");
    expect(cloud.apiCalls()).toHaveLength(0);
    cloud.respond(200, "hunter2", { "content-type": "text/plain" });
    await client.callTool({ name: "openstack_get", arguments: { ...args, confirm: true } });
    expect(cloud.apiCalls()[0].url).toBe("https://barbican.test:9311/v1/secrets/s-1/payload");
    expect(cloud.apiCalls()[0].headers.accept).toBe("text/plain");
  });
});

describe("dangerous operations", () => {
  it("needs confirm: true for deletions and destructive actions, not for harmless ones", async () => {
    const { client, cloud } = await connect();
    for (const path of ["/v2.1/servers/s1", "/servers/s1", "/v2.1/servers/{id}"]) {
      const refused = await client.callTool({
        name: "openstack_request",
        arguments: { service: "compute", method: "DELETE", path, path_params: { id: "s1" } },
      });
      expect(textOf(refused)).toContain("confirm: true");
    }
    const rebuild = await client.callTool({
      name: "openstack_request",
      arguments: { service: "compute", method: "POST", path: "/v2.1/servers/s1/action", body: { rebuild: { imageRef: "i" } } },
    });
    expect(textOf(rebuild)).toContain("confirm: true");
    expect(cloud.apiCalls()).toHaveLength(0);

    await client.callTool({
      name: "openstack_request",
      arguments: { service: "compute", method: "POST", path: "/v2.1/servers/s1/action", body: { reboot: { type: "SOFT" } } },
    });
    await client.callTool({ name: "openstack_request", arguments: { service: "compute", method: "DELETE", path: "/v2.1/servers/s1", confirm: true } });
    expect(cloud.apiCalls().map((c) => `${c.method} ${c.url}`)).toEqual([
      "POST https://nova.test:8774/v2.1/servers/s1/action",
      "DELETE https://nova.test:8774/v2.1/servers/s1",
    ]);
  });

  it("refuses dot segments and backslashes that would reach another operation than the one checked", async () => {
    const { client, cloud } = await connect();
    const calls = [
      // A Barbican secret payload through the harmless GET /v1/secrets/{uuid}.
      { name: "openstack_get", arguments: { service: "key-manager", path: "/v1/secrets/x\\..\\s-1\\payload" } },
      { name: "openstack_get", arguments: { service: "key-manager", path: "/v1/secrets/x/%2e%2E/s-1/payload" } },
      { name: "openstack_get", arguments: { service: "compute", path: "/v2.1/servers/x/../../identity/v3/users" } },
      // Swift object names keep their slashes, not their dot segments.
      {
        name: "openstack_request",
        arguments: {
          service: "object-store",
          method: "POST",
          path: "/v1/{account}/c/{object}",
          path_params: { object: "a/../../../../compute/v2.1/servers/s1/action" },
          body: { rebuild: { imageRef: "i" } },
        },
      },
    ];
    for (const call of calls) expect(textOf(await client.callTool(call))).toContain("Invalid path");
    expect(cloud.apiCalls()).toHaveLength(0);
  });

  it("asks the user through elicitation when the client supports it", async () => {
    for (const [answer, expected] of [
      [{ action: "accept", content: { confirm: true } }, 1],
      [{ action: "decline" }, 0],
    ] as const) {
      const { client, cloud } = await connect({ elicit: answer });
      // confirm: true alone is not enough when the user can be asked directly.
      const res = await client.callTool({
        name: "openstack_request",
        arguments: { service: "network", method: "DELETE", path: "/v2.0/networks/n1", confirm: true },
      });
      expect(cloud.apiCalls()).toHaveLength(expected);
      expect(Boolean(res.isError)).toBe(expected === 0);
    }
  });
});

describe("http auth", () => {
  async function start(env: Record<string, string>) {
    const cloud = fakeCloud();
    const app = createHttpApp(loadConfig({ HOST: "127.0.0.1", ...env }), catalog, new OpenStackClient({ fetch: cloud.fetch }));
    const server = app.listen(0);
    await new Promise((r) => server.once("listening", r));
    const port = (server.address() as { port: number }).port;
    return { url: `http://127.0.0.1:${port}/mcp`, close: () => server.close(), cloud };
  }

  const initBody = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } },
  });
  const headers = { "content-type": "application/json", accept: "application/json, text/event-stream" };

  it("refuses requests without a known token", async () => {
    const srv = await start({});
    try {
      expect((await fetch(srv.url, { method: "POST", headers, body: initBody })).status).toBe(401);
      const res = await fetch(srv.url, { method: "POST", headers: { ...headers, authorization: "Bearer tok" }, body: initBody });
      expect(res.status).toBe(401);
    } finally {
      srv.close();
    }
  });

  it("checks API keys and acts with the cloud of the OS_* variables", async () => {
    const srv = await start({
      MCP_API_KEYS: "k1,k2",
      OS_AUTH_URL: AUTH_URL,
      OS_USERNAME: "alice",
      OS_PASSWORD: "s3cret",
      OS_USER_DOMAIN_NAME: "Default",
      OS_PROJECT_NAME: "prod",
      OS_PROJECT_DOMAIN_NAME: "Default",
    });
    try {
      const bad = await fetch(srv.url, { method: "POST", headers: { ...headers, authorization: "Bearer nope" }, body: initBody });
      expect(bad.status).toBe(401);
      const ok = await fetch(srv.url, { method: "POST", headers: { ...headers, authorization: "Bearer k2" }, body: initBody });
      expect(ok.status).toBe(200);
    } finally {
      srv.close();
    }
  });
});
