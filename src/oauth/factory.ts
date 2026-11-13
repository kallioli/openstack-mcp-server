import type { Settings } from "../settings.js";
import type { Store } from "../store/db.js";
import { OidcOAuthProvider } from "./provider.js";

/**
 * Returns the OAuth provider matching the current settings, or undefined while OAuth is not fully configured.
 * A new provider is built only when a relevant setting changes.
 */
export function oauthProviderFromSettings(settings: Settings, store: Store, fetchImpl?: typeof fetch) {
  let cached: { key: string; provider: OidcOAuthProvider } | undefined;
  return (): OidcOAuthProvider | undefined => {
    const { oauth, publicUrl } = settings.effective();
    if (!oauth || !publicUrl) return undefined;
    const key = JSON.stringify([oauth.issuer, oauth.clientId, oauth.clientSecret, oauth.secret, oauth.scopes, publicUrl.href]);
    if (cached?.key !== key) {
      cached = {
        key,
        provider: new OidcOAuthProvider({
          ...oauth,
          publicUrl,
          authorizeLogin: (identity) => store.checkOAuthLogin(identity, Boolean(settings.effective().federation)),
          fetch: fetchImpl,
        }),
      };
    }
    return cached.provider;
  };
}
