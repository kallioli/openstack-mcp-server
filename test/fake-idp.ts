/** A fake OpenID Connect identity provider (discovery, token, userinfo) in front of a fake OpenStack cloud. */
export const ISSUER = "https://idp.test/realms/cloud";

export interface FakeIdp {
  fetch: typeof fetch;
  tokenRequests: URLSearchParams[];
  /** Identity the userinfo endpoint reports for the next login. */
  setIdentity: (identity: Record<string, unknown>) => void;
}

export function fakeIdp(next: typeof fetch): FakeIdp {
  const tokenRequests: URLSearchParams[] = [];
  let identity: Record<string, unknown> = { sub: "u-1", email: "jane@example.com", email_verified: true, name: "Jane" };
  const impl = (async (url: string | URL, init?: RequestInit) => {
    const href = String(url);
    if (href === `${ISSUER}/.well-known/openid-configuration`) {
      return Response.json({
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/protocol/openid-connect/auth`,
        token_endpoint: `${ISSUER}/protocol/openid-connect/token`,
        userinfo_endpoint: `${ISSUER}/protocol/openid-connect/userinfo`,
      });
    }
    if (href === `${ISSUER}/protocol/openid-connect/token`) {
      const params = new URLSearchParams(String(init?.body));
      tokenRequests.push(params);
      const n = tokenRequests.length;
      return Response.json({ access_token: `idp-access-${n}`, refresh_token: `idp-refresh-${n}`, expires_in: 7200 });
    }
    if (href === `${ISSUER}/protocol/openid-connect/userinfo`) return Response.json(identity);
    return next(url, init);
  }) as typeof fetch;
  return { fetch: impl, tokenRequests, setIdentity: (i) => (identity = i) };
}

/**
 * Plays the user on the consent page returned by /authorize: submits it with the cookie it set, as the browser would.
 * Returns where the browser is sent next and the cookie to keep for the identity provider's callback.
 */
export async function consent(page: Response, decision = "allow"): Promise<{ location: URL; cookie: string }> {
  const cookie = page.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
  const html = await page.text();
  const action = html.match(/<form method="post" action="([^"]+)"/)![1];
  const request = html.match(/name="request" value="([^"]+)"/)![1];
  const res = await fetch(action, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded", cookie },
    body: new URLSearchParams({ request, decision }),
  });
  return { location: new URL(res.headers.get("location")!), cookie };
}
