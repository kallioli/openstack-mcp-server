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
