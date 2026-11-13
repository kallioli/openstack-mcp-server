import { describe, expect, it } from "vitest";
import { OpenStackClient, endpointTail, identityV3, joinEndpoint } from "../src/openstack/client.js";
import {
  credentialsFromEnv,
  normalizeCredentials,
  parseCloudsYaml,
  parseOpenrc,
} from "../src/openstack/credentials.js";
import { serviceInfo } from "../src/services.js";
import { APP_CRED_PROJECT, AUTH_URL, PASSWORD_CREDENTIALS, PROJECTS, fakeCloud } from "./fake-openstack.js";

describe("endpoints", () => {
  it("joins spec paths to every shape of endpoint", () => {
    expect(joinEndpoint("https://neutron:9696", "/v2.0/networks")).toBe("https://neutron:9696/v2.0/networks");
    expect(joinEndpoint("https://neutron:9696/", "/v2.0/networks")).toBe("https://neutron:9696/v2.0/networks");
    expect(joinEndpoint("https://nova/v2.1", "/v2.1/servers/detail")).toBe("https://nova/v2.1/servers/detail");
    expect(joinEndpoint("https://nova/v2.1/abc", "/v2.1/servers")).toBe("https://nova/v2.1/abc/servers");
    expect(joinEndpoint("https://cloud/compute/v2.1", "/v2.1/flavors")).toBe("https://cloud/compute/v2.1/flavors");
    expect(joinEndpoint("https://cinder:8776/v3/p1", "/v3/volumes/detail")).toBe("https://cinder:8776/v3/p1/volumes/detail");
    expect(joinEndpoint("https://swift/v1/AUTH_p1", "/v1/AUTH_p1/bucket/a/b.txt")).toBe("https://swift/v1/AUTH_p1/bucket/a/b.txt");
    expect(joinEndpoint("https://placement/placement", "/resource_providers")).toBe("https://placement/placement/resource_providers");
    expect(joinEndpoint("https://manila/v2/p1", "/shares")).toBe("https://manila/v2/p1/shares");
    expect(joinEndpoint("https://keystone:5000", "/v3/projects")).toBe("https://keystone:5000/v3/projects");
    expect(joinEndpoint("https://keystone:5000/v3/", "/v3/projects")).toBe("https://keystone:5000/v3/projects");
  });

  it("finds what follows the version and the identity root", () => {
    expect(endpointTail("https://swift/v1/AUTH_p1")).toBe("AUTH_p1");
    expect(endpointTail("https://neutron:9696")).toBeUndefined();
    expect(identityV3("https://k:5000")).toBe("https://k:5000/v3");
    expect(identityV3("https://k:5000/v3/")).toBe("https://k:5000/v3");
  });
});

describe("credentials", () => {
  it("validates what each authentication type needs", () => {
    expect(() => normalizeCredentials({ ...PASSWORD_CREDENTIALS, authUrl: "nope" })).toThrow(/valid URL/);
    expect(() => normalizeCredentials({ ...PASSWORD_CREDENTIALS, auth: { ...PASSWORD_CREDENTIALS.auth, password: "" } })).toThrow(/password/);
    expect(() =>
      normalizeCredentials({ ...PASSWORD_CREDENTIALS, auth: { ...PASSWORD_CREDENTIALS.auth, userDomainName: undefined } }),
    ).toThrow(/user domain/);
    expect(() => normalizeCredentials({ ...PASSWORD_CREDENTIALS, project: { name: "prod" } })).toThrow(/project domain/);
    expect(() =>
      normalizeCredentials({ authUrl: AUTH_URL, auth: { type: "application_credential", id: "x", secret: "y" }, project: { id: "p" } }),
    ).toThrow(/bound to their project/);
    expect(normalizeCredentials({ ...PASSWORD_CREDENTIALS, authUrl: `${AUTH_URL}/v3/`, interface: "publicURL" as never })).toMatchObject({
      authUrl: `${AUTH_URL}/v3`,
      interface: "public",
    });
  });

  it("reads openrc files and the OS_* variables", () => {
    const vars = parseOpenrc(`
      export OS_AUTH_URL=https://keystone.test:5000/v3
      export OS_PROJECT_NAME="prod"
      export OS_USER_DOMAIN_NAME="Default"
      export OS_PROJECT_DOMAIN_ID=default
      export OS_USERNAME='alice'
      export OS_PASSWORD=$OS_PASSWORD_INPUT
      export OS_REGION_NAME=RegionOne
    `);
    expect(vars.OS_PASSWORD).toBeUndefined();
    expect(credentialsFromEnv({ ...vars, OS_PASSWORD: "pw" })).toEqual({
      authUrl: "https://keystone.test:5000/v3",
      auth: { type: "password", username: "alice", userId: undefined, userDomainName: "Default", userDomainId: undefined, password: "pw" },
      project: { id: undefined, name: "prod", domainName: undefined, domainId: "default" },
      region: "RegionOne",
      interface: "public",
    });
    expect(
      credentialsFromEnv({ OS_AUTH_URL: AUTH_URL, OS_AUTH_TYPE: "v3applicationcredential", OS_APPLICATION_CREDENTIAL_ID: "id1", OS_APPLICATION_CREDENTIAL_SECRET: "sec" })
        ?.auth,
    ).toMatchObject({ type: "application_credential", id: "id1", secret: "sec" });
    expect(credentialsFromEnv({})).toBeUndefined();
  });

  it("reads clouds.yaml, reporting unusable clouds", () => {
    const clouds = parseCloudsYaml(`
clouds:
  prod:
    auth:
      auth_url: https://keystone.test:5000
      username: alice
      password: pw
      project_name: prod
      user_domain_name: Default
      project_domain_name: Default
    region_name: RegionOne
    interface: internal
  app:
    auth_type: v3applicationcredential
    auth:
      auth_url: https://keystone.test:5000
      application_credential_id: abc
      application_credential_secret: def
  broken:
    auth:
      username: bob
`);
    expect(clouds.prod).toMatchObject({ region: "RegionOne", interface: "internal", project: { name: "prod", domainName: "Default" } });
    expect(clouds.app).toMatchObject({ auth: { type: "application_credential", id: "abc", secret: "def" } });
    expect(clouds.broken).toMatch(/auth URL/);
    expect(() => parseCloudsYaml("foo: [")).toThrow(/Invalid YAML/);
  });
});

describe("keystone client", () => {
  const compute = serviceInfo("compute")!;

  it("authenticates with a password, caches the token and scopes to other projects", async () => {
    const cloud = fakeCloud();
    const client = new OpenStackClient({ fetch: cloud.fetch });
    const token = await client.authenticate(PASSWORD_CREDENTIALS);
    expect(token.project?.name).toBe("prod");
    expect(JSON.parse(cloud.calls[0].body!).auth).toEqual({
      identity: { methods: ["password"], password: { user: { name: "alice", domain: { name: "Default" }, password: "s3cret" } } },
      scope: { project: { name: "prod", domain: { name: "Default" } } },
    });
    await client.authenticate(PASSWORD_CREDENTIALS);
    expect(cloud.authCount()).toBe(1);

    const staging = await client.authenticate(PASSWORD_CREDENTIALS, PROJECTS[1].id);
    expect(staging.project?.id).toBe(PROJECTS[1].id);
    expect(cloud.authCount()).toBe(2);
    expect((await client.listProjects(PASSWORD_CREDENTIALS)).map((p) => p.name)).toEqual(["prod", "staging"]);
  });

  it("reports Keystone refusals", async () => {
    const client = new OpenStackClient({ fetch: fakeCloud().fetch });
    const wrong = { ...PASSWORD_CREDENTIALS, auth: { ...PASSWORD_CREDENTIALS.auth, password: "nope" } };
    await expect(client.authenticate(wrong)).rejects.toThrow(/HTTP 401 .*requires authentication/);
  });

  it("keeps application credentials on their project", async () => {
    const cloud = fakeCloud();
    const client = new OpenStackClient({ fetch: cloud.fetch });
    const creds = { authUrl: AUTH_URL, auth: { type: "application_credential" as const, id: "ac", secret: "app-secret" } };
    expect((await client.authenticate(creds)).project?.id).toBe(APP_CRED_PROJECT.id);
    expect((await client.authenticate(creds, APP_CRED_PROJECT.id)).project?.id).toBe(APP_CRED_PROJECT.id);
    await expect(client.authenticate(creds, PROJECTS[0].id)).rejects.toThrow(/bound to project/);
    expect((await client.listProjects(creds)).map((p) => p.id)).toEqual([APP_CRED_PROJECT.id]);
  });

  it("exchanges an OpenID Connect token through Keystone federation", async () => {
    const cloud = fakeCloud();
    const client = new OpenStackClient({ fetch: cloud.fetch });
    const creds = {
      authUrl: AUTH_URL,
      auth: { type: "oidc_access_token" as const, identityProvider: "sso", protocol: "openid", accessToken: "oidc-access" },
    };
    expect((await client.authenticate(creds)).catalog).toEqual([]);
    const scoped = await client.authenticate(creds, PROJECTS[0].id);
    expect(scoped.project?.name).toBe("prod");
    expect(cloud.calls.map((c) => new URL(c.url).pathname)).toContain("/v3/OS-FEDERATION/identity_providers/sso/protocols/openid/auth");
  });

  it("sends calls to the catalog endpoint with region, interface and microversion", async () => {
    const cloud = fakeCloud();
    const client = new OpenStackClient({ fetch: cloud.fetch });
    const res = await client.request({
      credentials: PASSWORD_CREDENTIALS,
      service: compute,
      method: "GET",
      path: "/v2.1/servers/detail",
      query: { status: ["ACTIVE", "ERROR"], limit: 5 },
      microversion: "2.79",
      region: "RegionTwo",
    });
    expect(res.ok).toBe(true);
    const call = cloud.apiCalls()[0];
    expect(call.url).toBe("https://nova-two.test/v2.1/servers/detail?status=ACTIVE&status=ERROR&limit=5");
    expect(call.headers["openstack-api-version"]).toBe("compute 2.79");
    expect(call.headers["x-auth-token"]).toMatch(/^tok-/);
    expect(res.headers["x-openstack-request-id"]).toBe("req-1");

    await client.request({ credentials: { ...PASSWORD_CREDENTIALS, interface: "internal" }, service: compute, method: "GET", path: "/v2.1/flavors" });
    expect(cloud.apiCalls()[1].url).toBe("http://internal.nova.test:8774/v2.1/flavors");
    await expect(
      client.request({ credentials: PASSWORD_CREDENTIALS, service: compute, method: "GET", path: "/v2.1/flavors", region: "Mars" }),
    ).rejects.toThrow(/no public endpoint in region "Mars"/);
    await expect(
      client.request({ credentials: PASSWORD_CREDENTIALS, service: serviceInfo("dns")!, method: "GET", path: "/v2/zones" }),
    ).rejects.toThrow(/not in this cloud's service catalog/);
  });

  it("authenticates again once when a token is revoked", async () => {
    const cloud = fakeCloud();
    const client = new OpenStackClient({ fetch: cloud.fetch });
    await client.request({ credentials: PASSWORD_CREDENTIALS, service: compute, method: "GET", path: "/v2.1/flavors" });
    cloud.revokeTokens();
    const res = await client.request({ credentials: PASSWORD_CREDENTIALS, service: compute, method: "GET", path: "/v2.1/flavors" });
    expect(res.status).toBe(200);
    expect(cloud.authCount()).toBe(2);
  });
});
