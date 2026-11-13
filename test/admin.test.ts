import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createAdminApp } from "../src/admin/app.js";
import { Catalog } from "../src/catalog.js";
import { loadConfig } from "../src/config.js";
import { createHttpApp } from "../src/http.js";
import { OpenStackClient } from "../src/openstack/client.js";
import { AUTH_URL, PASSWORD_CREDENTIALS, PROJECTS, fakeCloud } from "./fake-openstack.js";
import { Store, normalizeIpRules } from "../src/store/db.js";

const SECRET = "k".repeat(40);
const PASSWORD = "correct horse battery";
const catalog = Catalog.load();
const dir = mkdtempSync(join(tmpdir(), "osmcp-"));
const store = new Store(join(dir, "test.db"), SECRET);
store.setAdminPassword(PASSWORD);

const cloud = fakeCloud();
const client = new OpenStackClient({ fetch: cloud.fetch });
const CREDS = PASSWORD_CREDENTIALS;
const APP_CREDS = { authUrl: AUTH_URL, auth: { type: "application_credential", id: "ac", secret: "app-secret" } };
const config = loadConfig({ HOST: "127.0.0.1", DATA_DIR: dir });

let admin: ReturnType<ReturnType<typeof createAdminApp>["listen"]>;
let mcp: ReturnType<ReturnType<typeof createHttpApp>["listen"]>;
let adminUrl = "";
let mcpUrl = "";
let session = "";

async function listen(app: { listen: (port: number, host: string) => any }) {
  const server = app.listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  return { server, url: `http://127.0.0.1:${server.address().port}` };
}

beforeAll(async () => {
  ({ server: admin, url: adminUrl } = await listen(createAdminApp({ config, store, catalog, client, secretKey: SECRET })));
  ({ server: mcp, url: mcpUrl } = await listen(createHttpApp(config, catalog, client, { store })));
});

afterAll(() => {
  admin.close();
  mcp.close();
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

function call(method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
  return fetch(`${adminUrl}/api${path}`, {
    method,
    headers: {
      "content-type": "application/json",
      "x-requested-with": "openstack-mcp-admin",
      ...(session ? { cookie: session } : {}),
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

function mcpCall(token: string, name: string, args: object) {
  return fetch(`${mcpUrl}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}` },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
  });
}

function listTools(token: string) {
  return fetch(`${mcpUrl}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}` },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
}

describe("store", () => {
  it("never stores OpenStack credentials in clear", () => {
    const c = store.createConnection({ name: "clear-check", credentials: { ...CREDS, auth: { ...CREDS.auth, password: "super-secret-password" } } });
    expect(JSON.stringify(c)).not.toContain("super-secret");
    expect(c.identity).toBe("alice@Default");
    expect(store.connectionCredentials(c.id)?.auth).toMatchObject({ password: "super-secret-password" });
    expect(new Store(join(dir, "test.db"), "z".repeat(40)).connectionCredentials(c.id)).toBeUndefined();
    store.deleteConnection(c.id);
  });

  it("keeps the stored secret when an update leaves it blank", () => {
    const c = store.createConnection({ name: "keep", credentials: CREDS });
    const updated = store.updateConnection(c.id, { credentials: { ...CREDS, region: "RegionTwo", auth: { ...CREDS.auth, password: "" } } });
    expect(updated.credentials.region).toBe("RegionTwo");
    expect(store.connectionCredentials(c.id)?.auth).toMatchObject({ password: "s3cret" });
    expect(() => store.updateConnection(c.id, { credentials: { ...APP_CREDS, auth: { ...APP_CREDS.auth, secret: "" } } as never })).toThrow(/secret/);
    store.deleteConnection(c.id);
  });

  it("validates IP rules", () => {
    expect(normalizeIpRules(["10.0.0.0/8", " 2001:db8::1 "])).toEqual(["10.0.0.0/8", "2001:db8::1"]);
    expect(() => normalizeIpRules(["10.0.0.0/33"])).toThrow();
    expect(() => normalizeIpRules(["example.com"])).toThrow();
  });
});

describe("admin api", () => {
  it("requires a session and the CSRF header", async () => {
    expect((await call("GET", "/dashboard")).status).toBe(401);
    expect((await call("POST", "/auth/login", { password: "wrong" })).status).toBe(401);
    const login = await call("POST", "/auth/login", { password: PASSWORD });
    expect(login.status).toBe(200);
    const setCookie = login.headers.get("set-cookie")!;
    expect(setCookie).toMatch(/HttpOnly/i);
    expect(setCookie).toMatch(/SameSite=Strict/i);
    session = setCookie.split(";")[0];
    expect((await call("GET", "/dashboard")).status).toBe(200);
    expect((await call("POST", "/connections", { name: "x", credentials: CREDS }, { "x-requested-with": "" })).status).toBe(403);
  });

  it("parses clouds.yaml and openrc files to fill the form", async () => {
    const yaml = await (
      await call("POST", "/connections/parse", { text: `clouds:\n  prod:\n    auth:\n      auth_url: ${AUTH_URL}\n      application_credential_id: a\n      application_credential_secret: b\n    auth_type: v3applicationcredential\n` })
    ).json();
    expect(yaml).toMatchObject({ format: "clouds.yaml", clouds: [{ name: "prod", credentials: { auth: { type: "application_credential", id: "a" } } }] });
    const openrc = await (
      await call("POST", "/connections/parse", {
        text: `export OS_AUTH_URL=${AUTH_URL}\nexport OS_USERNAME=alice\nexport OS_USER_DOMAIN_NAME=Default\nexport OS_PROJECT_NAME=prod\nexport OS_PASSWORD=$OS_PASSWORD_INPUT\n`,
      })
    ).json();
    expect(openrc).toMatchObject({ format: "openrc", clouds: [{ name: "prod", credentials: { auth: { username: "alice", password: "" } } }] });
    const noPassword = await (
      await call("POST", "/connections/parse", { text: `clouds:\n  p:\n    auth:\n      auth_url: ${AUTH_URL}\n      username: alice\n      user_domain_name: Default\n` })
    ).json();
    expect(noPassword.clouds[0]).toMatchObject({ name: "p", credentials: { auth: { type: "password", password: "" } } });
    expect((await call("POST", "/connections/parse", { text: "hello" })).status).toBe(400);
  });

  it("manages connections and tests them against Keystone", async () => {
    const created = await (await call("POST", "/connections", { name: "Prod", credentials: CREDS })).json();
    expect(created.secretHint).toBe("cret");
    expect(JSON.stringify(created)).not.toContain("s3cret");
    const tested = await (await call("POST", `/connections/${created.id}/test`)).json();
    expect(tested.lastCheck.ok).toBe(true);
    expect(tested.lastCheck.detail).toBe("Authenticated as alice@Default · project prod · regions RegionOne, RegionTwo · 9 services · 2 projects");
    expect((await (await call("GET", `/connections/${created.id}/projects`)).json()).map((p: { name: string }) => p.name)).toEqual(["prod", "staging"]);

    const bad = await (await call("POST", "/connections", { name: "Broken", credentials: { ...CREDS, auth: { ...CREDS.auth, password: "wrong" } } })).json();
    const badTest = (await (await call("POST", `/connections/${bad.id}/test`)).json()).lastCheck;
    expect(badTest.ok).toBe(false);
    expect(badTest.detail).toContain("HTTP 401");
    expect((await call("POST", "/connections", { name: "Prod", credentials: CREDS })).status).toBe(400);
    expect((await call("POST", "/connections", { name: "Nope", credentials: { authUrl: AUTH_URL, auth: { type: "magic" } } })).status).toBe(400);
    expect((await call("DELETE", `/connections/${bad.id}`)).status).toBe(204);
  });

  it("issues managed tokens usable on /mcp, restricted by category and read-only", async () => {
    const [connection] = (await (await call("GET", "/connections")).json()) as { id: string; name: string }[];
    const created = await (
      await call("POST", "/tokens", { name: "Claude", connectionId: connection.id, readOnly: true, categories: ["Network"] })
    ).json();
    expect(created.secret).toMatch(/^osmt_/);
    expect(created.token.status).toBe("active");
    expect(JSON.stringify(await (await call("GET", "/tokens")).json())).not.toContain(created.secret);

    // Read-only: the write tool is hidden.
    const tools = (await (await listTools(created.secret)).json()).result.tools.map((t: { name: string }) => t.name);
    expect(tools).not.toContain("openstack_request");

    // Allowed category goes through with the connection's credentials.
    const ok = await (await mcpCall(created.secret, "openstack_get", { service: "network", path: "/v2.0/networks" })).json();
    expect(ok.result.isError).toBeFalsy();
    expect(cloud.apiCalls().at(-1)?.url).toBe("https://neutron.test:9696/v2.0/networks");

    // Other services are invisible.
    const denied = await (await mcpCall(created.secret, "openstack_get", { service: "compute", path: "/v2.1/servers" })).json();
    expect(denied.result.isError).toBe(true);
    const search = await (await mcpCall(created.secret, "openstack_search_operations", { query: "list servers" })).json();
    expect(search.result.content[0].text).not.toContain("compute ");

    // Revocation is immediate.
    await call("POST", `/tokens/${created.token.id}/revoke`);
    expect((await listTools(created.secret)).status).toBe(401);
  });

  it("enforces IP restrictions and expiry", async () => {
    const [connection] = (await (await call("GET", "/connections")).json()) as { id: string }[];
    const ipBound = await (await call("POST", "/tokens", { name: "IP", connectionId: connection.id, allowedIps: ["203.0.113.0/24"] })).json();
    const res = await listTools(ipBound.secret);
    expect(res.status).toBe(401);
    expect((await res.json()).error.message).toContain("IP address");

    const local = await (await call("POST", "/tokens", { name: "Local", connectionId: connection.id, allowedIps: ["127.0.0.1"] })).json();
    expect((await listTools(local.secret)).status).toBe(200);

    expect((await call("POST", "/tokens", { name: "Past", connectionId: connection.id, expiresAt: Date.now() - 1000 })).status).toBe(400);
    expect((await call("POST", "/tokens", { name: "Bad", connectionId: connection.id, categories: ["Nope"] })).status).toBe(400);
    expect((await call("DELETE", `/connections/${connection.id}`)).status).toBe(400);
  });

  it("issues tokens spanning several connections, with a default project", async () => {
    const [prod] = (await (await call("GET", "/connections")).json()) as { id: string }[];
    const other = await (await call("POST", "/connections", { name: "Client B", credentials: CREDS })).json();
    expect((await call("PATCH", `/connections/${other.id}`, { defaultProjectId: PROJECTS[1].id })).status).toBe(200);
    expect((await call("PATCH", `/connections/${other.id}`, { defaultProjectId: "not a project" })).status).toBe(400);

    const created = await (
      await call("POST", "/tokens", { name: "Multi", connectionIds: [prod.id, other.id], defaultConnectionId: other.id })
    ).json();
    expect(created.token.connections.map((c: { id: string }) => c.id)).toEqual([other.id, prod.id]);

    await mcpCall(created.secret, "openstack_get", { service: "network", path: "/v2.0/quotas/{project_id}" });
    expect(cloud.apiCalls().at(-1)?.url).toBe(`https://neutron.test:9696/v2.0/quotas/${PROJECTS[1].id}`);
    await mcpCall(created.secret, "openstack_get", { service: "network", path: "/v2.0/quotas/{project_id}", connection: "Prod" });
    expect(cloud.apiCalls().at(-1)?.url).toBe(`https://neutron.test:9696/v2.0/quotas/${PROJECTS[0].id}`);

    await call("DELETE", `/tokens/${created.token.id}`);
    expect((await call("DELETE", `/connections/${other.id}`)).status).toBe(204);
  });

  it("manages OAuth access rules and the default policy", async () => {
    const overview = await (await call("GET", "/oauth")).json();
    expect(overview).toMatchObject({ enabled: false, defaultPolicy: "personal", rules: [] });

    const [connection] = (await (await call("GET", "/connections")).json()) as { id: string; name: string }[];
    const created = await call("POST", "/oauth/rules", {
      name: "Team",
      matchType: "domain",
      matchValue: "@example.com",
      connectionIds: [connection.id],
      defaultConnectionId: connection.id,
      includePersonal: true,
      categories: ["Network"],
    });
    expect(created.status).toBe(201);
    const rule = await created.json();
    expect(rule).toMatchObject({ matchValue: "example.com", connections: [{ id: connection.id, name: connection.name }] });

    expect((await call("PATCH", `/oauth/rules/${rule.id}`, { enabled: false })).status).toBe(200);
    expect((await call("POST", "/oauth/rules", { name: "Bad", matchType: "email", matchValue: "nope" })).status).toBe(400);
    expect((await call("PUT", "/oauth/policy", { defaultPolicy: "deny" })).status).toBe(200);
    expect((await call("PUT", "/oauth/policy", { defaultPolicy: "maybe" })).status).toBe(400);
    expect((await call("DELETE", `/connections/${connection.id}`)).status).toBe(400);

    expect((await call("DELETE", `/oauth/rules/${rule.id}`)).status).toBe(204);
    await call("PUT", "/oauth/policy", { defaultPolicy: "personal" });
  });

  it("disables categories globally", async () => {
    const categories = (await (await call("GET", "/categories")).json()) as { name: string; enabled: boolean }[];
    expect(categories.find((c) => c.name === "Compute")?.enabled).toBe(true);
    expect((await call("PUT", "/categories", { disabled: ["Compute"] })).status).toBe(200);

    const [connection] = (await (await call("GET", "/connections")).json()) as { id: string }[];
    const all = await (await call("POST", "/tokens", { name: "All", connectionId: connection.id })).json();
    const denied = await (await mcpCall(all.secret, "openstack_get", { service: "compute", path: "/v2.1/servers" })).json();
    expect(denied.result.isError).toBe(true);
    const allowed = await (await mcpCall(all.secret, "openstack_get", { service: "network", path: "/v2.0/networks" })).json();
    expect(allowed.result.isError).toBeFalsy();

    expect((await call("PUT", "/categories", { disabled: ["Nope"] })).status).toBe(400);
    await call("PUT", "/categories", { disabled: [] });
  });
});
