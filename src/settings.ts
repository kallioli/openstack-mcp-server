import { randomBytes } from "node:crypto";
import { type Config, DEFAULT_OAUTH_SCOPES, type FederationConfig, type OAuthConfig } from "./config.js";
import { type Store, ValidationError } from "./store/db.js";

/** Settings that can change at runtime; every consumer reads them per request. */
export interface EffectiveSettings {
  publicUrl?: URL;
  trustProxy?: string;
  readOnly: boolean;
  maxResponseChars: number;
  /** Set when OAuth is fully configured (issuer, client id, client secret and public URL). */
  oauth?: OAuthConfig;
  /** Set when Keystone federation is configured: OAuth users then get their own OpenStack access. */
  federation?: FederationConfig;
}

/** Editable settings, as shown to and sent by the admin portal. */
export interface SettingsValues {
  publicUrl: string | null;
  trustProxy: string | null;
  readOnly: boolean;
  maxResponseChars: number;
  oauthIssuer: string | null;
  oauthClientId: string | null;
  oauthScopes: string[];
  federationAuthUrl: string | null;
  federationIdentityProvider: string | null;
  federationProtocol: string;
  federationRegion: string | null;
}

export type SettingKey = keyof SettingsValues | "oauthClientSecret";

/** Environment variable taking precedence over each setting (the setting is then locked in the portal). */
const ENV_VARS: Record<SettingKey, string> = {
  publicUrl: "PUBLIC_URL",
  trustProxy: "TRUST_PROXY",
  readOnly: "OPENSTACK_READ_ONLY",
  maxResponseChars: "MAX_RESPONSE_CHARS",
  oauthIssuer: "OIDC_ISSUER",
  oauthClientId: "OIDC_CLIENT_ID",
  oauthClientSecret: "OIDC_CLIENT_SECRET",
  oauthScopes: "OIDC_SCOPES",
  federationAuthUrl: "OS_FEDERATION_AUTH_URL",
  federationIdentityProvider: "OS_FEDERATION_IDP",
  federationProtocol: "OS_FEDERATION_PROTOCOL",
  federationRegion: "OS_FEDERATION_REGION",
};

export interface SettingsView {
  values: SettingsValues;
  oauthClientSecretSet: boolean;
  /** Variable name for settings fixed by the environment. */
  locked: Partial<Record<SettingKey, string>>;
  defaults: { oauthScopes: string[]; maxResponseChars: number; federationProtocol: string };
  /** Redirect URI to register in the identity provider. */
  callbackUrl: string | null;
  oauthActive: boolean;
  federationActive: boolean;
  setupCompleted: boolean;
}

export type SettingsPatch = Partial<Omit<SettingsValues, "oauthScopes" | "federationProtocol">> & {
  oauthScopes?: string[] | null;
  /** null resets it to the default ("openid"). */
  federationProtocol?: string | null;
  oauthClientSecret?: string | null;
};

const DEFAULT_MAX_RESPONSE_CHARS = 60_000;
const DEFAULT_FEDERATION_PROTOCOL = "openid";

function parseUrl(value: string, label: string): URL {
  try {
    return new URL(value.trim());
  } catch {
    throw new ValidationError(`The ${label} is not a valid URL.`);
  }
}

function isLocal(url: URL): boolean {
  return ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
}

/** Origin of a public URL; https is required except for local testing. */
export function normalizePublicUrl(value: string): string {
  const url = parseUrl(value, "public URL");
  if (url.protocol !== "https:" && !(isLocal(url) && url.protocol === "http:")) {
    throw new ValidationError("The public URL must use https (http is only accepted for localhost).");
  }
  if (url.pathname !== "/" || url.search) {
    throw new ValidationError("The public URL must be an origin without path, e.g. https://mcp.example.com.");
  }
  return url.origin;
}

/** OpenID Connect issuer: https (http for localhost), without trailing slash. */
export function normalizeIssuer(value: string): string {
  const url = parseUrl(value, "issuer URL");
  if (url.protocol !== "https:" && !(isLocal(url) && url.protocol === "http:")) {
    throw new ValidationError("The issuer URL must use https (http is only accepted for localhost).");
  }
  if (url.search || url.hash) throw new ValidationError("The issuer URL must not have a query string.");
  return url.href.replace(/\/+$/, "");
}

/**
 * Runtime settings: the environment wins, then the database (set through the admin portal), then defaults.
 * Changes made in the portal apply without restart.
 */
export class Settings {
  constructor(
    private readonly config: Config,
    private readonly store: Store,
    private readonly env: NodeJS.ProcessEnv = process.env,
  ) {}

  private fromEnv(key: SettingKey): boolean {
    return Boolean(this.env[ENV_VARS[key]]);
  }

  locked(): Partial<Record<SettingKey, string>> {
    return Object.fromEntries(
      (Object.keys(ENV_VARS) as SettingKey[]).filter((k) => this.fromEnv(k)).map((k) => [k, ENV_VARS[k]]),
    );
  }

  values(): SettingsValues {
    const db = <T>(key: string, fallback: T) => this.store.getSetting<T>(`settings.${key}`, fallback);
    const text = (key: SettingKey): string | null =>
      this.fromEnv(key) ? (this.env[ENV_VARS[key]]?.trim() ?? null) : db<string | null>(key, null);
    return {
      publicUrl: this.fromEnv("publicUrl") ? (this.config.publicUrl?.origin ?? null) : db<string | null>("publicUrl", null),
      trustProxy: this.fromEnv("trustProxy") ? (this.config.trustProxy ?? null) : db<string | null>("trustProxy", null),
      readOnly: this.fromEnv("readOnly") ? this.config.readOnly : db("readOnly", false),
      maxResponseChars: this.fromEnv("maxResponseChars")
        ? this.config.maxResponseChars
        : db("maxResponseChars", DEFAULT_MAX_RESPONSE_CHARS),
      oauthIssuer: text("oauthIssuer"),
      oauthClientId: text("oauthClientId"),
      oauthScopes: this.fromEnv("oauthScopes")
        ? this.env.OIDC_SCOPES!.split(/[,\s]+/).filter(Boolean)
        : (db<string[] | null>("oauthScopes", null) ?? DEFAULT_OAUTH_SCOPES),
      federationAuthUrl: text("federationAuthUrl"),
      federationIdentityProvider: text("federationIdentityProvider"),
      federationProtocol: text("federationProtocol") ?? DEFAULT_FEDERATION_PROTOCOL,
      federationRegion: text("federationRegion"),
    };
  }

  private oauthClientSecret(): string | undefined {
    if (this.fromEnv("oauthClientSecret")) return this.env.OIDC_CLIENT_SECRET;
    return this.store.getSecretSetting("settings.oauthClientSecret");
  }

  /** Key sealing OAuth clients and tokens: OAUTH_SECRET, or one generated once and kept (encrypted) in the database. */
  private oauthSealSecret(): string {
    if (this.env.OAUTH_SECRET) return this.env.OAUTH_SECRET;
    let secret = this.store.getSecretSetting("settings.oauthSealSecret");
    if (!secret) {
      secret = randomBytes(48).toString("base64url");
      this.store.setSecretSetting("settings.oauthSealSecret", secret);
    }
    return secret;
  }

  effective(): EffectiveSettings {
    const v = this.values();
    const publicUrl = v.publicUrl ? new URL(v.publicUrl) : undefined;
    const clientSecret = this.oauthClientSecret();
    return {
      publicUrl,
      trustProxy: v.trustProxy ?? undefined,
      readOnly: v.readOnly,
      maxResponseChars: v.maxResponseChars,
      oauth:
        publicUrl && v.oauthIssuer && v.oauthClientId && clientSecret
          ? { issuer: v.oauthIssuer, clientId: v.oauthClientId, clientSecret, secret: this.oauthSealSecret(), scopes: v.oauthScopes }
          : undefined,
      federation:
        v.federationAuthUrl && v.federationIdentityProvider
          ? {
              authUrl: v.federationAuthUrl,
              identityProvider: v.federationIdentityProvider,
              protocol: v.federationProtocol,
              ...(v.federationRegion ? { region: v.federationRegion } : {}),
            }
          : undefined,
    };
  }

  view(): SettingsView {
    const values = this.values();
    const effective = this.effective();
    return {
      values,
      oauthClientSecretSet: Boolean(this.oauthClientSecret()),
      locked: this.locked(),
      defaults: { oauthScopes: DEFAULT_OAUTH_SCOPES, maxResponseChars: DEFAULT_MAX_RESPONSE_CHARS, federationProtocol: DEFAULT_FEDERATION_PROTOCOL },
      callbackUrl: values.publicUrl ? new URL("/oauth/callback", values.publicUrl).href : null,
      oauthActive: Boolean(effective.oauth),
      federationActive: Boolean(effective.oauth && effective.federation),
      setupCompleted: this.setupCompleted(),
    };
  }

  update(patch: SettingsPatch): SettingsView {
    const locked = this.locked();
    const lockedKeys = (Object.keys(patch) as SettingKey[]).filter((k) => patch[k as keyof SettingsPatch] !== undefined && locked[k]);
    if (lockedKeys.length) {
      throw new ValidationError(`Set by environment variables: ${lockedKeys.map((k) => locked[k]).join(", ")}.`);
    }

    // Validate everything before writing anything.
    const writes: [string, unknown][] = [];
    const name = (value: string | null | undefined, label: string) => {
      const v = value?.trim() || null;
      if (v && !/^[\w.:@-]{1,255}$/.test(v)) throw new ValidationError(`Invalid ${label}.`);
      return v;
    };
    if (patch.publicUrl !== undefined) writes.push(["publicUrl", patch.publicUrl ? normalizePublicUrl(patch.publicUrl) : null]);
    if (patch.trustProxy !== undefined) {
      const value = patch.trustProxy?.trim() || null;
      if (value && !/^[\w.,:/\s-]{1,200}$/.test(value)) throw new ValidationError("Invalid trust proxy value.");
      writes.push(["trustProxy", value]);
    }
    if (patch.readOnly !== undefined) writes.push(["readOnly", Boolean(patch.readOnly)]);
    if (patch.maxResponseChars !== undefined) {
      const n = Number(patch.maxResponseChars);
      if (!Number.isInteger(n) || n < 1_000 || n > 1_000_000) {
        throw new ValidationError("The response size limit must be between 1,000 and 1,000,000 characters.");
      }
      writes.push(["maxResponseChars", n]);
    }
    if (patch.oauthIssuer !== undefined) writes.push(["oauthIssuer", patch.oauthIssuer?.trim() ? normalizeIssuer(patch.oauthIssuer) : null]);
    if (patch.oauthClientId !== undefined) writes.push(["oauthClientId", patch.oauthClientId?.trim() || null]);
    if (patch.oauthScopes !== undefined) {
      const scopes = patch.oauthScopes?.map((s) => s.trim()).filter(Boolean) ?? null;
      if (scopes?.some((s) => !/^[\w:./-]+$/.test(s))) throw new ValidationError("Invalid OAuth scope.");
      writes.push(["oauthScopes", scopes?.length ? [...new Set(scopes)] : null]);
    }
    if (patch.federationAuthUrl !== undefined) {
      const value = patch.federationAuthUrl?.trim() || null;
      if (value) {
        const url = parseUrl(value, "Keystone URL");
        if (url.protocol !== "https:" && url.protocol !== "http:") throw new ValidationError("The Keystone URL must use http(s).");
      }
      writes.push(["federationAuthUrl", value?.replace(/\/+$/, "") ?? null]);
    }
    if (patch.federationIdentityProvider !== undefined) {
      writes.push(["federationIdentityProvider", name(patch.federationIdentityProvider, "identity provider")]);
    }
    if (patch.federationProtocol !== undefined) writes.push(["federationProtocol", name(patch.federationProtocol, "federation protocol")]);
    if (patch.federationRegion !== undefined) writes.push(["federationRegion", name(patch.federationRegion, "region")]);

    for (const [key, value] of writes) this.store.setSetting(`settings.${key}`, value);
    if (patch.oauthClientSecret !== undefined) {
      const secret = patch.oauthClientSecret?.trim();
      if (secret) this.store.setSecretSetting("settings.oauthClientSecret", secret);
      else this.store.deleteSetting("settings.oauthClientSecret");
    }
    return this.view();
  }

  setupCompleted(): boolean {
    return this.store.getSetting("setup_completed", false);
  }

  completeSetup(): void {
    this.store.setSetting("setup_completed", true);
  }
}
