import { type CloudCredentials, credentialsFromEnv } from "./openstack/credentials.js";

/** OpenID Connect application used for "Sign in" (OAuth) of MCP clients. */
export interface OAuthConfig {
  /** Issuer URL of the identity provider; its endpoints come from /.well-known/openid-configuration. */
  issuer: string;
  clientId: string;
  clientSecret: string;
  /** Key material used to seal clients, codes and tokens (at least 32 characters). */
  secret: string;
  scopes: string[];
}

/** Keystone federation: lets OAuth users act with their own OpenStack identity. */
export interface FederationConfig {
  authUrl: string;
  identityProvider: string;
  protocol: string;
  region?: string;
}

export interface AdminConfig {
  enabled: boolean;
  port: number;
  host: string;
  /** Sets (or resets) the admin password at startup. */
  password?: string;
}

export interface Config {
  port: number;
  host: string;
  /** Public base URL of the server (required for OAuth), e.g. https://mcp.example.com */
  publicUrl?: URL;
  /** Static API keys; requests carrying one act with the cloud described by the OS_* variables. */
  apiKeys: string[];
  /** Cloud described by the usual OS_* variables, for --stdio mode or together with apiKeys. */
  envCloud?: CloudCredentials;
  /** Why the OS_* variables could not be used, if they are set but incomplete. */
  envCloudError?: string;
  /** Directory holding the SQLite database (and the generated secret key, if any). */
  dataDir: string;
  /** Key encrypting stored OpenStack credentials; generated into dataDir when unset. */
  secretKey?: string;
  admin: AdminConfig;
  readOnly: boolean;
  allowedHosts?: string[];
  trustProxy?: string;
  maxResponseChars: number;
}

/** Scopes requested from the identity provider by default. */
export const DEFAULT_OAUTH_SCOPES = ["openid", "profile", "email"];

function list(value: string | undefined, separator = /[,\s]+/): string[] {
  return (value ?? "")
    .split(separator)
    .map((v) => v.trim())
    .filter(Boolean);
}

function bool(value: string | undefined): boolean {
  return ["1", "true", "yes", "on"].includes((value ?? "").toLowerCase());
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const allowedHosts = list(env.MCP_ALLOWED_HOSTS);
  const publicUrl = env.PUBLIC_URL ? new URL(env.PUBLIC_URL) : undefined;

  let envCloud: CloudCredentials | undefined;
  let envCloudError: string | undefined;
  try {
    envCloud = credentialsFromEnv(env);
  } catch (err) {
    envCloudError = (err as Error).message;
  }

  const host = env.HOST ?? "0.0.0.0";
  return {
    port: Number(env.PORT ?? 3000),
    host,
    publicUrl,
    apiKeys: list(env.MCP_API_KEYS, /,/),
    envCloud,
    envCloudError,
    dataDir: env.DATA_DIR ?? "./data",
    secretKey: env.MCP_SECRET_KEY || undefined,
    admin: {
      enabled: env.ADMIN_ENABLED === undefined ? true : bool(env.ADMIN_ENABLED),
      port: Number(env.ADMIN_PORT ?? 9090),
      host: env.ADMIN_HOST ?? host,
      password: env.ADMIN_PASSWORD || undefined,
    },
    readOnly: bool(env.OPENSTACK_READ_ONLY),
    allowedHosts: allowedHosts.length ? allowedHosts : undefined,
    trustProxy: env.TRUST_PROXY || undefined,
    maxResponseChars: Number(env.MAX_RESPONSE_CHARS ?? 60_000),
  };
}
