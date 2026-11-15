import { createHash, randomBytes } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Catalog } from "../src/catalog.js";
import { loadConfig } from "../src/config.js";
import { createHttpApp } from "../src/http.js";
import { OpenStackClient } from "../src/openstack/client.js";
import { OidcOAuthProvider } from "../src/oauth/provider.js";
import { Sealer } from "../src/oauth/seal.js";
import { AUTH_URL, fakeCloud } from "./fake-openstack.js";
import { ISSUER, consent, fakeIdp } from "./fake-idp.js";

const PORT = 40_000 + Math.floor(Math.random() * 10_000);
const BASE = `http://localhost:${PORT}`;
const REDIRECT = "http://localhost:9/callback";

const cloud = fakeCloud({ acceptOidc: (t) => t.startsWith("idp-access-") });
const idp = fakeIdp(cloud.fetch);
const upstream = { tokenRequests: idp.tokenRequests };
const OAUTH = { issuer: ISSUER, clientId: "app-id", clientSecret: "app-secret", secret: "x".repeat(40), scopes: ["openid", "email"] };
const FEDERATION = { authUrl: AUTH_URL, identityProvider: "sso", protocol: "openid" };

let server: ReturnType<ReturnType<typeof createHttpApp>["listen"]>;

beforeAll(async () => {
  const config = loadConfig({ HOST: "localhost", PUBLIC_URL: BASE });
  const provider = new OidcOAuthProvider({ ...OAUTH, publicUrl: config.publicUrl!, fetch: idp.fetch });
  const app = createHttpApp(config, Catalog.load(), new OpenStackClient({ fetch: idp.fetch }), {
    oauth: provider,
    settings: () => ({ publicUrl: config.publicUrl, readOnly: false, maxResponseChars: 60_000, oauth: OAUTH, federation: FEDERATION }),
  });
  server = app.listen(PORT, "localhost");
  await new Promise((r) => server.once("listening", r));
});

afterAll(() => server.close());

/** Federated token request seen by Keystone, with the identity provider's access token. */
const lastFederatedAuth = () =>
  cloud.calls.filter((c) => c.url.includes("/OS-FEDERATION/")).at(-1)?.headers.authorization;

function form(params: Record<string, string>) {
  return { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(params) };
}

function mcp(token: string | undefined, body: object) {
  return fetch(`${BASE}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
}

describe("sealer", () => {
  it("rejects other types, tampering and expiry", () => {
    const sealer = new Sealer("s".repeat(32));
    const blob = sealer.seal("a", { v: 1 }, 60);
    expect(sealer.open("a", blob)).toMatchObject({ v: 1 });
    expect(sealer.open("b", blob)).toBeUndefined();
    expect(sealer.open("a", blob.slice(0, -2) + "AA")).toBeUndefined();
    expect(sealer.open("a", sealer.seal("a", { v: 1 }, -1))).toBeUndefined();
    expect(new Sealer("t".repeat(32)).open("a", blob)).toBeUndefined();
  });
});

describe("oauth flow", () => {
  it("challenges unauthenticated clients with the resource metadata", async () => {
    const res = await mcp(undefined, { jsonrpc: "2.0", id: 1, method: "tools/list" });
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain(
      `resource_metadata="${BASE}/.well-known/oauth-protected-resource/mcp"`,
    );
    const meta = await (await fetch(`${BASE}/.well-known/oauth-protected-resource/mcp`)).json();
    expect(meta.authorization_servers).toEqual([`${BASE}/`]);
  });

  it("signs in through the identity provider, calls OpenStack through federation and refreshes", async () => {
    // 1. Dynamic client registration (public client, PKCE only).
    const registration = await (
      await fetch(`${BASE}/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ redirect_uris: [REDIRECT], token_endpoint_auth_method: "none", client_name: "test" }),
      })
    ).json();
    const clientId: string = registration.client_id;
    expect(clientId).toBeTruthy();

    // 2. Authorization request: the user approves the client on the consent page, then is redirected to the identity
    // provider with this server's own client.
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const authorize = await fetch(
      `${BASE}/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: clientId,
        redirect_uri: REDIRECT,
        code_challenge: challenge,
        code_challenge_method: "S256",
        state: "client-state",
      })}`,
      { redirect: "manual" },
    );
    expect(authorize.status).toBe(200);
    const { location: toIdp, cookie } = await consent(authorize);
    expect(toIdp.origin + toIdp.pathname).toBe(`${ISSUER}/protocol/openid-connect/auth`);
    expect(toIdp.searchParams.get("scope")).toBe("openid email");
    expect(toIdp.searchParams.get("client_id")).toBe("app-id");
    expect(toIdp.searchParams.get("redirect_uri")).toBe(`${BASE}/oauth/callback`);
    expect(toIdp.searchParams.get("code_challenge_method")).toBe("S256");

    // 3. The identity provider sends the user back; the server exchanges the code and redirects to the client.
    const callback = await fetch(
      `${BASE}/oauth/callback?code=upstream-code&state=${encodeURIComponent(toIdp.searchParams.get("state")!)}`,
      { redirect: "manual", headers: { cookie } },
    );
    const toClient = new URL(callback.headers.get("location")!);
    expect(toClient.origin + toClient.pathname).toBe(REDIRECT);
    expect(toClient.searchParams.get("state")).toBe("client-state");
    const exchange = upstream.tokenRequests[0];
    expect(exchange.get("code")).toBe("upstream-code");
    expect(exchange.get("client_secret")).toBe("app-secret");
    expect(exchange.get("code_verifier")).toBeTruthy();

    // 4. Token request: a wrong verifier fails, the right one yields our own tokens.
    const code = toClient.searchParams.get("code")!;
    const bad = await fetch(`${BASE}/token`, form({ grant_type: "authorization_code", code, client_id: clientId, code_verifier: "nope".repeat(11), redirect_uri: REDIRECT }));
    expect(bad.status).toBe(400);
    const tokens = await (
      await fetch(`${BASE}/token`, form({ grant_type: "authorization_code", code, client_id: clientId, code_verifier: verifier, redirect_uri: REDIRECT }))
    ).json();
    expect(tokens.access_token).toMatch(/^osmcp_/);
    expect(tokens.access_token).not.toContain("idp-access");
    expect(tokens.expires_in).toBe(7200);

    // 5. MCP call: the wrapped access token buys a Keystone token through federation.
    const call = await mcp(tokens.access_token, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "openstack_get", arguments: { service: "network", path: "/v2.0/networks", project: "prod" } },
    });
    expect(call.status).toBe(200);
    expect((await call.json()).result.isError).toBeFalsy();
    expect(lastFederatedAuth()).toBe("Bearer idp-access-1");
    expect(cloud.apiCalls().at(-1)?.url).toBe("https://neutron.test:9696/v2.0/networks");

    // 6. Refresh: the identity provider is asked for a new token with its own refresh token.
    const refreshed = await (
      await fetch(`${BASE}/token`, form({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: clientId }))
    ).json();
    expect(upstream.tokenRequests[1].get("refresh_token")).toBe("idp-refresh-1");
    await mcp(refreshed.access_token, { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "openstack_list_clouds", arguments: {} } });
    expect(lastFederatedAuth()).toBe("Bearer idp-access-2");

    // 7. A tampered access token is rejected.
    const forged = await mcp(tokens.access_token.slice(0, -4) + "AAAA", { jsonrpc: "2.0", id: 4, method: "tools/list" });
    expect(forged.status).toBe(401);
    expect(forged.headers.get("www-authenticate")).toContain('error="invalid_token"');
  });

  it("refuses codes issued to another client", async () => {
    const register = async () =>
      (
        await (
          await fetch(`${BASE}/register`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ redirect_uris: [REDIRECT], token_endpoint_auth_method: "none" }),
          })
        ).json()
      ).client_id as string;
    const [victim, attacker] = [await register(), await register()];
    const verifier = randomBytes(32).toString("base64url");
    const authorize = await fetch(
      `${BASE}/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: victim,
        redirect_uri: REDIRECT,
        code_challenge: createHash("sha256").update(verifier).digest("base64url"),
        code_challenge_method: "S256",
      })}`,
      { redirect: "manual" },
    );
    const { location, cookie } = await consent(authorize);
    const state = location.searchParams.get("state")!;
    const callback = await fetch(`${BASE}/oauth/callback?code=c&state=${encodeURIComponent(state)}`, { redirect: "manual", headers: { cookie } });
    const code = new URL(callback.headers.get("location")!).searchParams.get("code")!;
    const res = await fetch(`${BASE}/token`, form({ grant_type: "authorization_code", code, client_id: attacker, code_verifier: verifier, redirect_uri: REDIRECT }));
    expect(res.status).toBe(400);
  });
  it("asks the user to approve each client and binds the authorization to their browser", async () => {
    const evil = "https://evil.example/cb";
    const { client_id: clientId } = await (
      await fetch(`${BASE}/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ redirect_uris: [evil], token_endpoint_auth_method: "none", client_name: "<b>Claude</b>" }),
      })
    ).json();
    const start = () =>
      fetch(
        `${BASE}/authorize?${new URLSearchParams({
          response_type: "code",
          client_id: clientId,
          redirect_uri: evil,
          code_challenge: createHash("sha256").update("v".repeat(43)).digest("base64url"),
          code_challenge_method: "S256",
          state: "s",
        })}`,
        { redirect: "manual" },
      );

    // The consent page names the client (escaped) and where the access goes, and cannot be framed.
    const page = await start();
    expect(page.headers.get("x-frame-options")).toBe("DENY");
    const html = await page.clone().text();
    expect(html).toContain("evil.example");
    expect(html).toContain("&#60;b&#62;Claude&#60;/b&#62;");
    expect(html).not.toContain("<b>Claude");

    // Declining goes back to the client with access_denied.
    const declined = await consent(await start(), "deny");
    expect(declined.location.origin + declined.location.pathname).toBe(evil);
    expect(declined.location.searchParams.get("error")).toBe("access_denied");

    // Approving without the browser's cookie (a forged cross-site form) is refused.
    const request = html.match(/name="request" value="([^"]+)"/)![1];
    const forged = await fetch(`${BASE}/oauth/consent`, form({ request, decision: "allow" }));
    expect(forged.status).toBe(400);

    // An authorization approved in one browser cannot be completed in another one.
    const { location } = await consent(page);
    const state = encodeURIComponent(location.searchParams.get("state")!);
    const other = await consent(await start());
    for (const headers of [{}, { cookie: other.cookie }]) {
      const callback = await fetch(`${BASE}/oauth/callback?code=c&state=${state}`, { redirect: "manual", headers });
      expect(callback.status).toBe(400);
    }
  });
});
