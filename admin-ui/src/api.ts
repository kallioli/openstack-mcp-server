export interface LastCheck {
  at: number;
  ok: boolean;
  detail: string;
}

export type EndpointInterface = "public" | "internal" | "admin";

/** How the server authenticates to Keystone; secrets are never sent back by the API (blank on edit). */
export type AuthMethod =
  | {
      type: "password";
      username?: string;
      userId?: string;
      userDomainName?: string;
      userDomainId?: string;
      password?: string;
    }
  | {
      type: "application_credential";
      id?: string;
      name?: string;
      username?: string;
      userDomainName?: string;
      secret?: string;
    };

export type AuthType = AuthMethod["type"];

export interface ProjectScope {
  id?: string;
  name?: string;
  domainName?: string;
  domainId?: string;
}

export interface CloudCredentials {
  authUrl: string;
  auth: AuthMethod;
  project?: ProjectScope;
  region?: string;
  interface?: EndpointInterface;
}

export interface Connection {
  id: string;
  name: string;
  description: string;
  readOnly: boolean;
  /** Project used by default (the credentials' own scope when null). */
  defaultProjectId: string | null;
  authUrl: string;
  authType: AuthType;
  /** Non-secret description of the identity, e.g. "alice@Default". */
  identity: string;
  /** The credentials without their secret. */
  credentials: CloudCredentials;
  /** Last characters of the password or secret. */
  secretHint: string;
  createdAt: number;
  updatedAt: number;
  lastCheck?: LastCheck;
  tokenCount: number;
}

/** A Keystone project reachable with a connection's credentials. */
export interface Project {
  id: string;
  name: string;
  domainId?: string;
  enabled?: boolean;
}

/** Result of POST /connections/parse (clouds.yaml or openrc file). */
export interface ParsedClouds {
  format: "clouds.yaml" | "openrc";
  clouds: ({ name: string; credentials: CloudCredentials } | { name: string; error: string })[];
}

export type TokenStatus = "active" | "expired" | "revoked";

export interface McpToken {
  id: string;
  name: string;
  tokenPrefix: string;
  connectionIds: string[];
  defaultConnectionId: string;
  connections: { id: string; name: string | null }[];
  readOnly: boolean;
  allowedIps: string[];
  categories: string[] | null;
  expiresAt: number | null;
  createdAt: number;
  lastUsedAt: number | null;
  lastUsedIp: string | null;
  revokedAt: number | null;
  status: TokenStatus;
}

export interface Category {
  name: string;
  count: number;
  enabled: boolean;
  tags: { tag: string; count: number }[];
}

export interface Dashboard {
  version: string;
  uptimeSeconds: number;
  mcpUrl: string;
  catalog: { operations: number; generatedAt: string };
  categories: { total: number; enabled: number };
  connections: { id: string; name: string; lastCheck?: LastCheck }[];
  tokens: { active: number; expired: number; revoked: number };
  auth: { managedTokens: boolean; oauth: boolean; federation: boolean; apiKeys: boolean };
  readOnly: boolean;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

/** Called when the session has expired, so the app can show the login screen. */
let onUnauthorized: () => void = () => {};
export function setUnauthorizedHandler(handler: () => void) {
  onUnauthorized = handler;
}

export async function api<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`/api${path}`, {
    method,
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      "X-Requested-With": "openstack-mcp-admin",
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 204) return undefined as T;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401 && !path.startsWith("/auth/")) onUnauthorized();
    throw new ApiError(data.error ?? `HTTP error ${res.status}`, res.status);
  }
  return data as T;
}

export type OAuthMatchType = "user" | "email" | "domain";

export interface OAuthRule {
  id: string;
  name: string;
  matchType: OAuthMatchType;
  matchValue: string;
  connectionIds: string[];
  defaultConnectionId: string | null;
  connections: { id: string; name: string | null }[];
  includePersonal: boolean;
  readOnly: boolean;
  categories: string[] | null;
  enabled: boolean;
  createdAt: number;
  lastUsedAt: number | null;
}

export interface OAuthIdentity {
  sub: string;
  email?: string;
  emailVerified?: boolean;
  name?: string;
  lastSeenAt: number;
  ruleId: string | null;
  ruleName: string | null;
}

export interface OAuthOverview {
  enabled: boolean;
  defaultPolicy: "personal" | "deny";
  rules: OAuthRule[];
  identities: OAuthIdentity[];
}

export interface AuthState {
  authenticated: boolean;
  needsSetup: boolean;
  setupCompleted: boolean;
}

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

export interface SettingsView {
  values: SettingsValues;
  oauthClientSecretSet: boolean;
  locked: Partial<Record<SettingKey, string>>;
  defaults: { oauthScopes: string[]; maxResponseChars: number; federationProtocol: string };
  callbackUrl: string | null;
  oauthActive: boolean;
  federationActive: boolean;
  setupCompleted: boolean;
}

export type SettingsPatch = Partial<Omit<SettingsValues, "oauthScopes" | "federationProtocol">> & {
  oauthScopes?: string[] | null;
  /** null goes back to the default ("openid"). */
  federationProtocol?: string | null;
  oauthClientSecret?: string | null;
};
