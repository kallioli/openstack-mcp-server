import { createHash, randomBytes, randomUUID, scryptSync, timingSafeEqual } from "node:crypto";
import { BlockList, isIP } from "node:net";
import { DatabaseSync } from "node:sqlite";
import { Sealer } from "../oauth/seal.js";
import {
  type CloudCredentials,
  CredentialsError,
  describeIdentity,
  normalizeCredentials,
  secretOf,
} from "../openstack/credentials.js";

/** Prefix of MCP tokens managed from the admin portal. */
export const MCP_TOKEN_PREFIX = "osmt_";

export interface Connection {
  id: string;
  name: string;
  description: string;
  readOnly: boolean;
  /** Project used by default with this connection (the credentials' own scope when null). */
  defaultProjectId: string | null;
  authUrl: string;
  authType: CloudCredentials["auth"]["type"];
  /** Non-secret description of the identity, e.g. "alice@Default". */
  identity: string;
  /** The credentials without their secret, to edit them in the portal. */
  credentials: CloudCredentials;
  /** Last characters of the password or secret, to recognise it without exposing it. */
  secretHint: string;
  createdAt: number;
  updatedAt: number;
  lastCheck?: { at: number; ok: boolean; detail: string };
}

export interface McpToken {
  id: string;
  name: string;
  tokenPrefix: string;
  /** Connections this token may act with; the default one comes first. */
  connectionIds: string[];
  defaultConnectionId: string;
  readOnly: boolean;
  allowedIps: string[];
  /** Allowed API categories; null means every globally enabled category. */
  categories: string[] | null;
  expiresAt: number | null;
  createdAt: number;
  lastUsedAt: number | null;
  lastUsedIp: string | null;
  revokedAt: number | null;
}

export interface ConnectionInput {
  name: string;
  description?: string;
  /** On update, an empty password or secret keeps the stored one. */
  credentials?: CloudCredentials;
  readOnly?: boolean;
  defaultProjectId?: string | null;
}

/** What a connection gives an MCP request. */
export interface GrantedConnection {
  id: string;
  name: string;
  credentials: CloudCredentials;
  readOnly: boolean;
  defaultProjectId: string | null;
}

export interface McpTokenInput {
  name: string;
  /** Defaults to [defaultConnectionId]. */
  connectionIds?: string[];
  defaultConnectionId: string;
  readOnly?: boolean;
  allowedIps?: string[];
  categories?: string[] | null;
  expiresAt?: number | null;
}

/** What an MCP request authenticated with a managed token is allowed to do. */
export interface McpGrant {
  tokenId: string;
  /** Usable connections, default first. */
  connections: GrantedConnection[];
  readOnly: boolean;
  categories: string[] | null;
}

/** Who signed in through OAuth, as reported by the identity provider's userinfo endpoint. */
export interface OAuthIdentity {
  sub: string;
  email?: string;
  emailVerified?: boolean;
  name?: string;
}

export type OAuthMatchType = "user" | "email" | "domain";

/** Grants shared connections to the users who sign in through OAuth and match it. */
export interface OAuthRule {
  id: string;
  name: string;
  matchType: OAuthMatchType;
  /** User id at the identity provider (sub), e-mail address, or domain without the "@". */
  matchValue: string;
  connectionIds: string[];
  /** null: the user's personal (federated) access is the default (requires includePersonal). */
  defaultConnectionId: string | null;
  /** Also lets the user act with their own identity, through Keystone federation. */
  includePersonal: boolean;
  readOnly: boolean;
  categories: string[] | null;
  enabled: boolean;
  createdAt: number;
  lastUsedAt: number | null;
}

export interface OAuthRuleInput {
  name: string;
  matchType: OAuthMatchType;
  matchValue: string;
  connectionIds?: string[];
  defaultConnectionId?: string | null;
  includePersonal?: boolean;
  readOnly?: boolean;
  categories?: string[] | null;
  enabled?: boolean;
}

/** What happens to an OAuth user no rule matches. */
export type OAuthDefaultPolicy = "personal" | "deny";

export interface OAuthSeenIdentity extends OAuthIdentity {
  lastSeenAt: number;
  ruleId: string | null;
}

/** Name of the connection standing for the signed-in user's own identity (Keystone federation). */
export const PERSONAL_CONNECTION = "Personal";

export class ValidationError extends Error {}

const NOT_ALLOWED = "Your account is not allowed on this MCP server. Ask its administrator for access.";
const NO_FEDERATION =
  "No OpenStack access is configured for your account (no shared connection, and Keystone federation is not set up). Ask the administrator of this MCP server.";

const now = () => Date.now();

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

/** Validates IPs and CIDR ranges, e.g. 203.0.113.4 or 10.0.0.0/8 or 2001:db8::/32. */
export function normalizeIpRules(rules: string[]): string[] {
  return rules
    .map((r) => r.trim())
    .filter(Boolean)
    .map((rule) => {
      const [address, bits] = rule.split("/");
      const family = isIP(address);
      const max = family === 6 ? 128 : 32;
      if (!family || (bits !== undefined && !(/^\d+$/.test(bits) && Number(bits) <= max))) {
        throw new ValidationError(`Invalid IP address or CIDR range: ${rule}`);
      }
      return rule;
    });
}

function ipAllowed(rules: string[], ip: string | undefined): boolean {
  if (!rules.length) return true;
  if (!ip) return false;
  const address = ip.startsWith("::ffff:") && isIP(ip.slice(7)) === 4 ? ip.slice(7) : ip;
  const family = isIP(address) === 6 ? "ipv6" : "ipv4";
  const list = new BlockList();
  for (const rule of rules) {
    const [base, bits] = rule.split("/");
    const ruleFamily = isIP(base) === 6 ? "ipv6" : "ipv4";
    if (bits === undefined) list.addAddress(base, ruleFamily);
    else list.addSubnet(base, Number(bits), ruleFamily);
  }
  return list.check(address, family);
}

export class Store {
  private readonly db: DatabaseSync;
  private readonly sealer: Sealer;

  constructor(path: string, secretKey: string) {
    this.db = new DatabaseSync(path);
    this.sealer = new Sealer(secretKey);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA foreign_keys = ON;
      CREATE TABLE IF NOT EXISTS connections (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        description TEXT NOT NULL DEFAULT '',
        credentials_enc TEXT NOT NULL,
        secret_hint TEXT NOT NULL,
        read_only INTEGER NOT NULL DEFAULT 0,
        default_project_id TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        last_check_at INTEGER,
        last_check_ok INTEGER,
        last_check_detail TEXT
      );
      CREATE TABLE IF NOT EXISTS mcp_tokens (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        token_prefix TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        connection_id TEXT NOT NULL REFERENCES connections(id) ON DELETE RESTRICT,
        read_only INTEGER NOT NULL DEFAULT 0,
        allowed_ips TEXT NOT NULL DEFAULT '[]',
        categories TEXT,
        expires_at INTEGER,
        created_at INTEGER NOT NULL,
        last_used_at INTEGER,
        last_used_ip TEXT,
        revoked_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
      -- mcp_tokens.connection_id holds the default connection; this table lists every allowed one.
      CREATE TABLE IF NOT EXISTS token_connections (
        token_id TEXT NOT NULL REFERENCES mcp_tokens(id) ON DELETE CASCADE,
        connection_id TEXT NOT NULL REFERENCES connections(id) ON DELETE RESTRICT,
        PRIMARY KEY (token_id, connection_id)
      );
      CREATE TABLE IF NOT EXISTS oauth_rules (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        match_type TEXT NOT NULL CHECK (match_type IN ('user', 'email', 'domain')),
        match_value TEXT NOT NULL,
        default_connection_id TEXT REFERENCES connections(id) ON DELETE RESTRICT,
        include_personal INTEGER NOT NULL DEFAULT 1,
        read_only INTEGER NOT NULL DEFAULT 0,
        categories TEXT,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL,
        last_used_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS rule_connections (
        rule_id TEXT NOT NULL REFERENCES oauth_rules(id) ON DELETE CASCADE,
        connection_id TEXT NOT NULL REFERENCES connections(id) ON DELETE RESTRICT,
        PRIMARY KEY (rule_id, connection_id)
      );
      CREATE TABLE IF NOT EXISTS oauth_identities (
        sub TEXT PRIMARY KEY,
        email TEXT,
        email_verified INTEGER,
        name TEXT,
        last_seen_at INTEGER NOT NULL,
        rule_id TEXT
      );
    `);
  }

  close(): void {
    this.db.close();
  }

  // --- settings -------------------------------------------------------------

  getSetting<T>(key: string, fallback: T): T {
    const row = this.db.prepare("SELECT value FROM settings WHERE key = ?").get(key) as { value: string } | undefined;
    return row ? (JSON.parse(row.value) as T) : fallback;
  }

  setSetting(key: string, value: unknown): void {
    this.db
      .prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
      .run(key, JSON.stringify(value));
  }

  deleteSetting(key: string): void {
    this.db.prepare("DELETE FROM settings WHERE key = ?").run(key);
  }

  /** Settings holding secrets are sealed with the store key, like OpenStack credentials. */
  getSecretSetting(key: string): string | undefined {
    const sealed = this.getSetting<string | null>(key, null);
    return sealed ? this.sealer.open<{ value: string }>("secret-setting", sealed)?.value : undefined;
  }

  setSecretSetting(key: string, value: string): void {
    this.setSetting(key, this.sealer.seal("secret-setting", { value }));
  }

  disabledCategories(): string[] {
    return this.getSetting<string[]>("disabled_categories", []);
  }

  setDisabledCategories(categories: string[]): void {
    this.setSetting("disabled_categories", [...new Set(categories)].sort());
  }

  /**
   * Disables the categories listed in `disabledByDefault` the first time they show up in the catalog (also on existing
   * databases, when a catalog update brings them); afterwards the admin's choice is kept.
   */
  syncCategories(all: string[], disabledByDefault: string[]): void {
    const seen = new Set(this.getSetting<string[]>("categories_seen", []));
    const fresh = all.filter((c) => !seen.has(c));
    if (!fresh.length) return;
    const toDisable = fresh.filter((c) => disabledByDefault.includes(c));
    if (toDisable.length) this.setDisabledCategories([...this.disabledCategories(), ...toDisable]);
    this.setSetting("categories_seen", [...seen, ...fresh].sort());
  }

  // --- admin password -------------------------------------------------------

  hasAdminPassword(): boolean {
    return this.getSetting<string | null>("admin_password", null) !== null;
  }

  setAdminPassword(password: string): void {
    if (password.length < 12) throw new ValidationError("The admin password must be at least 12 characters long.");
    const salt = randomBytes(16);
    const hash = scryptSync(password, salt, 32);
    this.setSetting("admin_password", `scrypt:${salt.toString("hex")}:${hash.toString("hex")}`);
  }

  verifyAdminPassword(password: string): boolean {
    const stored = this.getSetting<string | null>("admin_password", null);
    if (!stored) return false;
    const [, salt, hash] = stored.split(":");
    const candidate = scryptSync(password, Buffer.from(salt, "hex"), 32);
    return timingSafeEqual(candidate, Buffer.from(hash, "hex"));
  }

  // --- connections ----------------------------------------------------------

  private openCredentials(sealed: string): CloudCredentials | undefined {
    return this.sealer.open<{ credentials: CloudCredentials }>("connection-credentials", sealed)?.credentials;
  }

  private toConnection(row: Record<string, any>): Connection {
    const credentials = this.openCredentials(row.credentials_enc);
    const auth = credentials?.auth;
    // The secret never leaves the store through this view.
    const publicAuth = auth
      ? (Object.fromEntries(
          Object.entries(auth).filter(([k]) => !["password", "secret", "accessToken"].includes(k)),
        ) as unknown as CloudCredentials["auth"])
      : ({ type: "password" } as CloudCredentials["auth"]);
    return {
      id: row.id,
      name: row.name,
      description: row.description,
      readOnly: Boolean(row.read_only),
      defaultProjectId: row.default_project_id ?? null,
      authUrl: credentials?.authUrl ?? "",
      authType: publicAuth.type,
      identity: auth ? describeIdentity(auth) : "(unreadable: was the secret key changed?)",
      credentials: { ...(credentials ?? { authUrl: "" }), auth: publicAuth },
      secretHint: row.secret_hint,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      ...(row.last_check_at
        ? { lastCheck: { at: row.last_check_at, ok: Boolean(row.last_check_ok), detail: row.last_check_detail ?? "" } }
        : {}),
    };
  }

  listConnections(): Connection[] {
    return this.db.prepare("SELECT * FROM connections ORDER BY name").all().map((r) => this.toConnection(r));
  }

  getConnection(id: string): Connection | undefined {
    const row = this.db.prepare("SELECT * FROM connections WHERE id = ?").get(id);
    return row ? this.toConnection(row) : undefined;
  }

  /** The full credentials of a connection, secret included. */
  connectionCredentials(id: string): CloudCredentials | undefined {
    const row = this.db.prepare("SELECT credentials_enc FROM connections WHERE id = ?").get(id) as { credentials_enc: string } | undefined;
    return row ? this.openCredentials(row.credentials_enc) : undefined;
  }

  private assertProjectId(value: unknown): void {
    if (value !== undefined && value !== null && !(typeof value === "string" && /^[\w-]{1,64}$/.test(value))) {
      throw new ValidationError("The default project must be a project id.");
    }
  }

  private assertUniqueName(name: string, exceptId?: string): void {
    const row = this.db.prepare("SELECT id FROM connections WHERE name = ?").get(name) as { id: string } | undefined;
    if (row && row.id !== exceptId) throw new ValidationError(`A connection named "${name}" already exists.`);
  }

  private validCredentials(input: CloudCredentials | undefined): CloudCredentials {
    if (!input) throw new ValidationError("The OpenStack credentials are required.");
    try {
      const credentials = normalizeCredentials(input);
      if (credentials.auth.type === "oidc_access_token") {
        throw new ValidationError("Federated access is configured in the OAuth settings, not as a connection.");
      }
      return credentials;
    } catch (err) {
      if (err instanceof CredentialsError) throw new ValidationError(err.message);
      throw err;
    }
  }

  createConnection(input: ConnectionInput): Connection {
    const name = input.name?.trim();
    if (!name) throw new ValidationError("Name is required.");
    const credentials = this.validCredentials(input.credentials);
    this.assertUniqueName(name);
    this.assertProjectId(input.defaultProjectId);
    const id = randomUUID();
    const ts = now();
    this.db
      .prepare(
        `INSERT INTO connections (id, name, description, credentials_enc, secret_hint, read_only, default_project_id, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        name,
        input.description?.trim() ?? "",
        this.sealer.seal("connection-credentials", { credentials }),
        secretOf(credentials.auth).slice(-4),
        input.readOnly ? 1 : 0,
        input.defaultProjectId || null,
        ts,
        ts,
      );
    return this.getConnection(id)!;
  }

  updateConnection(id: string, input: Partial<ConnectionInput>): Connection {
    const current = this.getConnection(id);
    if (!current) throw new ValidationError("Connection not found.");
    const name = input.name?.trim() ?? current.name;
    if (!name) throw new ValidationError("Name is required.");
    this.assertUniqueName(name, id);
    this.assertProjectId(input.defaultProjectId);

    let credentials: CloudCredentials | undefined;
    if (input.credentials) {
      // A blank secret keeps the stored one, as long as the authentication type is the same.
      const stored = this.connectionCredentials(id);
      const auth = { ...input.credentials.auth } as Record<string, unknown>;
      const secretKey = auth.type === "password" ? "password" : "secret";
      if (!auth[secretKey] && stored && stored.auth.type === auth.type) auth[secretKey] = secretOf(stored.auth);
      credentials = this.validCredentials({ ...input.credentials, auth: auth as unknown as CloudCredentials["auth"] });
    }
    // Changing the credentials makes the default project meaningless unless it is given again.
    const defaultProjectId =
      input.defaultProjectId !== undefined ? input.defaultProjectId || null : credentials ? null : current.defaultProjectId;
    this.db
      .prepare(
        `UPDATE connections SET name = ?, description = ?, read_only = ?, default_project_id = ?, updated_at = ?
           ${credentials ? ", credentials_enc = ?, secret_hint = ?, last_check_at = NULL" : ""}
         WHERE id = ?`,
      )
      .run(
        name,
        input.description?.trim() ?? current.description,
        (input.readOnly ?? current.readOnly) ? 1 : 0,
        defaultProjectId,
        now(),
        ...(credentials ? [this.sealer.seal("connection-credentials", { credentials }), secretOf(credentials.auth).slice(-4)] : []),
        id,
      );
    return this.getConnection(id)!;
  }

  deleteConnection(id: string): void {
    const used = this.db.prepare("SELECT COUNT(*) AS n FROM token_connections WHERE connection_id = ?").get(id) as { n: number };
    if (used.n) throw new ValidationError(`This connection is used by ${used.n} MCP token(s); delete them first.`);
    const rules = this.db
      .prepare("SELECT COUNT(DISTINCT rule_id) AS n FROM rule_connections WHERE connection_id = ?")
      .get(id) as { n: number };
    if (rules.n) throw new ValidationError(`This connection is used by ${rules.n} OAuth rule(s); update them first.`);
    this.db.prepare("DELETE FROM connections WHERE id = ?").run(id);
  }

  private grantedConnection(id: string): GrantedConnection | undefined {
    const connection = this.getConnection(id);
    const credentials = this.connectionCredentials(id);
    if (!connection || !credentials) return undefined;
    return { id, name: connection.name, credentials, readOnly: connection.readOnly, defaultProjectId: connection.defaultProjectId };
  }

  recordConnectionCheck(id: string, ok: boolean, detail: string): void {
    this.db
      .prepare("UPDATE connections SET last_check_at = ?, last_check_ok = ?, last_check_detail = ? WHERE id = ?")
      .run(now(), ok ? 1 : 0, detail, id);
  }

  // --- MCP tokens -----------------------------------------------------------

  private toToken(row: Record<string, any>): McpToken {
    return {
      id: row.id,
      name: row.name,
      tokenPrefix: row.token_prefix,
      connectionIds: this.tokenConnectionIds(row.id, row.connection_id),
      defaultConnectionId: row.connection_id,
      readOnly: Boolean(row.read_only),
      allowedIps: JSON.parse(row.allowed_ips),
      categories: row.categories === null ? null : JSON.parse(row.categories),
      expiresAt: row.expires_at,
      createdAt: row.created_at,
      lastUsedAt: row.last_used_at,
      lastUsedIp: row.last_used_ip,
      revokedAt: row.revoked_at,
    };
  }

  private tokenConnectionIds(tokenId: string, defaultId: string): string[] {
    const rows = this.db.prepare("SELECT connection_id FROM token_connections WHERE token_id = ?").all(tokenId) as {
      connection_id: string;
    }[];
    return [defaultId, ...rows.map((r) => r.connection_id).filter((id) => id !== defaultId)];
  }

  private setTokenConnections(tokenId: string, ids: string[]): void {
    this.db.prepare("DELETE FROM token_connections WHERE token_id = ?").run(tokenId);
    const insert = this.db.prepare("INSERT INTO token_connections (token_id, connection_id) VALUES (?, ?)");
    for (const id of ids) insert.run(tokenId, id);
  }

  listTokens(): McpToken[] {
    return this.db.prepare("SELECT * FROM mcp_tokens ORDER BY created_at DESC").all().map((r) => this.toToken(r));
  }

  getToken(id: string): McpToken | undefined {
    const row = this.db.prepare("SELECT * FROM mcp_tokens WHERE id = ?").get(id);
    return row ? this.toToken(row) : undefined;
  }

  private validateTokenInput(input: Partial<McpTokenInput>): void {
    if (input.name !== undefined && !input.name.trim()) throw new ValidationError("Name is required.");
    for (const id of [...(input.connectionIds ?? []), ...(input.defaultConnectionId ? [input.defaultConnectionId] : [])]) {
      if (!this.getConnection(id)) throw new ValidationError("Unknown connection.");
    }
    if (input.expiresAt && input.expiresAt < now()) throw new ValidationError("The expiry date is in the past.");
  }

  /** Allowed connections with the default first, checking the default is among them. */
  private resolveConnections(defaultId: string, ids: string[] | undefined): string[] {
    const list = [...new Set(ids?.length ? ids : [defaultId])];
    if (!list.includes(defaultId)) throw new ValidationError("The default connection must be one of the token's connections.");
    return [defaultId, ...list.filter((id) => id !== defaultId)];
  }

  /** Creates a token and returns its plaintext value, which is never stored nor shown again. */
  createToken(input: McpTokenInput): { token: McpToken; secret: string } {
    this.validateTokenInput(input);
    if (!input.defaultConnectionId) throw new ValidationError("A connection is required.");
    const connectionIds = this.resolveConnections(input.defaultConnectionId, input.connectionIds);
    const secret = MCP_TOKEN_PREFIX + randomBytes(32).toString("base64url");
    const id = randomUUID();
    this.db
      .prepare(
        `INSERT INTO mcp_tokens (id, name, token_prefix, token_hash, connection_id, read_only, allowed_ips, categories, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        input.name.trim(),
        secret.slice(0, MCP_TOKEN_PREFIX.length + 6),
        sha256(secret),
        input.defaultConnectionId,
        input.readOnly ? 1 : 0,
        JSON.stringify(normalizeIpRules(input.allowedIps ?? [])),
        input.categories ? JSON.stringify(input.categories) : null,
        input.expiresAt ?? null,
        now(),
      );
    this.setTokenConnections(id, connectionIds);
    return { token: this.getToken(id)!, secret };
  }

  updateToken(id: string, input: Partial<McpTokenInput>): McpToken {
    const current = this.getToken(id);
    if (!current) throw new ValidationError("Token not found.");
    this.validateTokenInput(input);
    const defaultId = input.defaultConnectionId ?? current.defaultConnectionId;
    const connectionIds = this.resolveConnections(defaultId, input.connectionIds ?? current.connectionIds);
    this.db
      .prepare(
        `UPDATE mcp_tokens SET name = ?, connection_id = ?, read_only = ?, allowed_ips = ?, categories = ?, expires_at = ?
         WHERE id = ?`,
      )
      .run(
        input.name?.trim() ?? current.name,
        defaultId,
        (input.readOnly ?? current.readOnly) ? 1 : 0,
        JSON.stringify(input.allowedIps ? normalizeIpRules(input.allowedIps) : current.allowedIps),
        (input.categories !== undefined ? input.categories : current.categories) === null
          ? null
          : JSON.stringify(input.categories ?? current.categories),
        input.expiresAt !== undefined ? input.expiresAt : current.expiresAt,
        id,
      );
    this.setTokenConnections(id, connectionIds);
    return this.getToken(id)!;
  }

  revokeToken(id: string): void {
    this.db.prepare("UPDATE mcp_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL").run(now(), id);
  }

  deleteToken(id: string): void {
    this.db.prepare("DELETE FROM mcp_tokens WHERE id = ?").run(id);
  }

  /** Authenticates an MCP request carrying a managed token. Throws with a client-safe message on refusal. */
  authenticateToken(secret: string, ip: string | undefined): McpGrant {
    const row = this.db.prepare("SELECT * FROM mcp_tokens WHERE token_hash = ?").get(sha256(secret));
    if (!row) throw new ValidationError("Unknown MCP token.");
    const token = this.toToken(row);
    if (token.revokedAt) throw new ValidationError("This MCP token has been revoked.");
    if (token.expiresAt && token.expiresAt < now()) throw new ValidationError("This MCP token has expired.");
    if (!ipAllowed(token.allowedIps, ip)) throw new ValidationError("This MCP token is not allowed from your IP address.");
    const connections = token.connectionIds.flatMap((id) => this.grantedConnection(id) ?? []);
    if (!connections.length) throw new ValidationError("The OpenStack connections of this token are unavailable.");
    // Avoid a write per request: last use is recorded at most once a minute.
    if (!token.lastUsedAt || now() - token.lastUsedAt > 60_000 || token.lastUsedIp !== (ip ?? null)) {
      this.db.prepare("UPDATE mcp_tokens SET last_used_at = ?, last_used_ip = ? WHERE id = ?").run(now(), ip ?? null, token.id);
    }
    return {
      tokenId: token.id,
      connections,
      readOnly: token.readOnly,
      categories: token.categories,
    };
  }

  // --- OAuth access rules ---------------------------------------------------

  oauthDefaultPolicy(): OAuthDefaultPolicy {
    return this.getSetting<OAuthDefaultPolicy>("oauth_default_policy", "personal");
  }

  setOAuthDefaultPolicy(policy: OAuthDefaultPolicy): void {
    if (policy !== "personal" && policy !== "deny") throw new ValidationError("The default policy must be personal or deny.");
    this.setSetting("oauth_default_policy", policy);
  }

  private toRule(row: Record<string, any>): OAuthRule {
    const ids = (this.db.prepare("SELECT connection_id FROM rule_connections WHERE rule_id = ?").all(row.id) as {
      connection_id: string;
    }[]).map((r) => r.connection_id);
    const defaultId: string | null = row.default_connection_id;
    return {
      id: row.id,
      name: row.name,
      matchType: row.match_type,
      matchValue: row.match_value,
      connectionIds: defaultId ? [defaultId, ...ids.filter((id) => id !== defaultId)] : ids,
      defaultConnectionId: defaultId,
      includePersonal: Boolean(row.include_personal),
      readOnly: Boolean(row.read_only),
      categories: row.categories === null ? null : JSON.parse(row.categories),
      enabled: Boolean(row.enabled),
      createdAt: row.created_at,
      lastUsedAt: row.last_used_at,
    };
  }

  listOAuthRules(): OAuthRule[] {
    return this.db.prepare("SELECT * FROM oauth_rules ORDER BY created_at").all().map((r) => this.toRule(r));
  }

  getOAuthRule(id: string): OAuthRule | undefined {
    const row = this.db.prepare("SELECT * FROM oauth_rules WHERE id = ?").get(id);
    return row ? this.toRule(row) : undefined;
  }

  private normalizeRule(input: OAuthRuleInput): Required<OAuthRuleInput> {
    const name = input.name?.trim();
    if (!name) throw new ValidationError("Name is required.");
    if (!["user", "email", "domain"].includes(input.matchType)) throw new ValidationError("Invalid match type.");
    let matchValue = input.matchValue?.trim().toLowerCase() ?? "";
    if (input.matchType === "domain") matchValue = matchValue.replace(/^@/, "");
    if (!matchValue) throw new ValidationError("The value to match is required.");
    if (input.matchType === "email" && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(matchValue)) throw new ValidationError("Invalid e-mail address.");
    if (input.matchType === "domain" && !/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(matchValue)) throw new ValidationError("Invalid domain.");

    const includePersonal = input.includePersonal ?? true;
    const connectionIds = [...new Set(input.connectionIds ?? [])];
    for (const id of connectionIds) if (!this.getConnection(id)) throw new ValidationError("Unknown connection.");
    let defaultConnectionId = input.defaultConnectionId ?? null;
    if (!connectionIds.length && !includePersonal) {
      throw new ValidationError("Grant at least one connection or the user's personal login.");
    }
    if (defaultConnectionId === null && !includePersonal) defaultConnectionId = connectionIds[0];
    if (defaultConnectionId !== null && !connectionIds.includes(defaultConnectionId)) {
      throw new ValidationError("The default connection must be one of the rule's connections.");
    }
    return {
      name,
      matchType: input.matchType,
      matchValue,
      connectionIds,
      defaultConnectionId,
      includePersonal,
      readOnly: input.readOnly ?? false,
      categories: input.categories ?? null,
      enabled: input.enabled ?? true,
    };
  }

  private saveRuleConnections(ruleId: string, ids: string[]): void {
    this.db.prepare("DELETE FROM rule_connections WHERE rule_id = ?").run(ruleId);
    const insert = this.db.prepare("INSERT INTO rule_connections (rule_id, connection_id) VALUES (?, ?)");
    for (const id of ids) insert.run(ruleId, id);
  }

  createOAuthRule(input: OAuthRuleInput): OAuthRule {
    const rule = this.normalizeRule(input);
    const id = randomUUID();
    this.db
      .prepare(
        `INSERT INTO oauth_rules (id, name, match_type, match_value, default_connection_id, include_personal, read_only, categories, enabled, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        rule.name,
        rule.matchType,
        rule.matchValue,
        rule.defaultConnectionId,
        rule.includePersonal ? 1 : 0,
        rule.readOnly ? 1 : 0,
        rule.categories ? JSON.stringify(rule.categories) : null,
        rule.enabled ? 1 : 0,
        now(),
      );
    this.saveRuleConnections(id, rule.connectionIds);
    return this.getOAuthRule(id)!;
  }

  updateOAuthRule(id: string, input: Partial<OAuthRuleInput>): OAuthRule {
    const current = this.getOAuthRule(id);
    if (!current) throw new ValidationError("Rule not found.");
    const rule = this.normalizeRule({ ...current, ...input });
    this.db
      .prepare(
        `UPDATE oauth_rules SET name = ?, match_type = ?, match_value = ?, default_connection_id = ?, include_personal = ?,
           read_only = ?, categories = ?, enabled = ? WHERE id = ?`,
      )
      .run(
        rule.name,
        rule.matchType,
        rule.matchValue,
        rule.defaultConnectionId,
        rule.includePersonal ? 1 : 0,
        rule.readOnly ? 1 : 0,
        rule.categories ? JSON.stringify(rule.categories) : null,
        rule.enabled ? 1 : 0,
        id,
      );
    this.saveRuleConnections(id, rule.connectionIds);
    return this.getOAuthRule(id)!;
  }

  deleteOAuthRule(id: string): void {
    this.db.prepare("DELETE FROM oauth_rules WHERE id = ?").run(id);
  }

  /**
   * The rule applying to an identity: user id first, then exact e-mail, then e-mail domain (oldest rule first).
   * E-mail based rules only consider addresses the identity provider reports as verified.
   */
  matchOAuthRule(identity: OAuthIdentity): OAuthRule | undefined {
    const rules = this.listOAuthRules().filter((r) => r.enabled);
    const email = identity.email && identity.emailVerified ? identity.email.toLowerCase() : undefined;
    return (
      rules.find((r) => r.matchType === "user" && r.matchValue === identity.sub.toLowerCase()) ??
      (email ? rules.find((r) => r.matchType === "email" && r.matchValue === email) : undefined) ??
      (email ? rules.find((r) => r.matchType === "domain" && email.endsWith(`@${r.matchValue}`)) : undefined)
    );
  }

  listOAuthIdentities(): OAuthSeenIdentity[] {
    return (this.db.prepare("SELECT * FROM oauth_identities ORDER BY last_seen_at DESC LIMIT 100").all() as Record<string, any>[]).map(
      (r) => ({
        sub: r.sub,
        email: r.email ?? undefined,
        emailVerified: r.email_verified === null ? undefined : Boolean(r.email_verified),
        name: r.name ?? undefined,
        lastSeenAt: r.last_seen_at,
        ruleId: r.rule_id,
      }),
    );
  }

  /**
   * Decides what an OAuth user may do, from the admin's rules. `personal` are the user's own credentials through
   * Keystone federation, when it is configured. Throws with a client-safe message when the user is not allowed.
   */
  authorizeOAuth(identity: OAuthIdentity | undefined, personal: CloudCredentials | undefined): McpGrant {
    const rule = identity ? this.matchOAuthRule(identity) : undefined;
    if (identity) this.recordIdentity(identity, rule?.id ?? null);
    const own: GrantedConnection[] = personal
      ? [{ id: "personal", name: PERSONAL_CONNECTION, credentials: personal, readOnly: false, defaultProjectId: null }]
      : [];

    if (!rule) {
      if (this.oauthDefaultPolicy() === "deny") throw new ValidationError(NOT_ALLOWED);
      if (!own.length) throw new ValidationError(NO_FEDERATION);
      return { tokenId: "oauth:personal", connections: own, readOnly: false, categories: null };
    }

    const shared = rule.connectionIds.flatMap((id) => this.grantedConnection(id) ?? []);
    const mine = rule.includePersonal ? own : [];
    const connections = rule.defaultConnectionId === null ? [...mine, ...shared] : [...shared, ...mine];
    if (!connections.length) {
      throw new ValidationError(rule.includePersonal && !personal ? NO_FEDERATION : "The OpenStack connections granted to you are unavailable.");
    }
    if (!rule.lastUsedAt || now() - rule.lastUsedAt > 60_000) {
      this.db.prepare("UPDATE oauth_rules SET last_used_at = ? WHERE id = ?").run(now(), rule.id);
    }
    return { tokenId: `oauth:${rule.id}`, connections, readOnly: rule.readOnly, categories: rule.categories };
  }

  /**
   * Checked right after the identity provider login: returns why the user is refused, if they are. The identity is
   * recorded either way, so that the admin sees who tried and can create a rule for them. `federation` tells whether
   * personal access through Keystone federation is available.
   */
  checkOAuthLogin(identity: OAuthIdentity | undefined, federation = true): string | undefined {
    const rule = identity ? this.matchOAuthRule(identity) : undefined;
    if (identity) this.recordIdentity(identity, rule?.id ?? null);
    if (!rule && this.oauthDefaultPolicy() === "deny") return NOT_ALLOWED;
    if (!federation && (!rule || !rule.connectionIds.length)) return NO_FEDERATION;
    return undefined;
  }

  private recordIdentity(identity: OAuthIdentity, ruleId: string | null): void {
    const row = this.db.prepare("SELECT last_seen_at, rule_id FROM oauth_identities WHERE sub = ?").get(identity.sub) as
      | { last_seen_at: number; rule_id: string | null }
      | undefined;
    // At most one write a minute per user, unless the matching rule changed.
    if (row && now() - row.last_seen_at < 60_000 && row.rule_id === ruleId) return;
    this.db
      .prepare(
        `INSERT INTO oauth_identities (sub, email, email_verified, name, last_seen_at, rule_id) VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(sub) DO UPDATE SET email = excluded.email, email_verified = excluded.email_verified,
           name = excluded.name, last_seen_at = excluded.last_seen_at, rule_id = excluded.rule_id`,
      )
      .run(
        identity.sub,
        identity.email ?? null,
        identity.emailVerified === undefined ? null : identity.emailVerified ? 1 : 0,
        identity.name ?? null,
        now(),
        ruleId,
      );
  }
}
