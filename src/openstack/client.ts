import { createHash } from "node:crypto";
import type { ServiceInfo } from "../services.js";
import type { CloudCredentials, EndpointInterface } from "./credentials.js";

export type HttpMethod = "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE";

const MAX_RETRY_WAIT_MS = 15_000;
/** Tokens are renewed this long before they expire. */
const TOKEN_MARGIN_MS = 2 * 60_000;
const PROJECTS_TTL_MS = 5 * 60_000;
const MAX_CACHE_ENTRIES = 1_000;
/** Response headers never shown to the model. */
const HIDDEN_HEADERS = new Set(["x-subject-token", "x-auth-token", "set-cookie", "x-storage-token"]);

export interface CatalogEndpoint {
  interface: string;
  region?: string;
  region_id?: string;
  url: string;
}

export interface CatalogService {
  type: string;
  name?: string;
  endpoints: CatalogEndpoint[];
}

export interface NamedRef {
  id: string;
  name?: string;
  domain?: { id?: string; name?: string };
}

/** A Keystone token and what came with it. */
export interface KeystoneToken {
  value: string;
  expiresAt: number;
  user?: NamedRef;
  project?: NamedRef;
  roles: string[];
  catalog: CatalogService[];
}

export interface Project {
  id: string;
  name: string;
  domainId?: string;
  enabled?: boolean;
}

export interface ApiRequest {
  credentials: CloudCredentials;
  /** Project to act on; the credentials' own scope when omitted. */
  projectId?: string;
  region?: string;
  service: ServiceInfo;
  method: HttpMethod;
  /** Concrete path as in the spec, e.g. /v2.1/servers/abc, joined to the service endpoint. */
  path: string;
  query?: Record<string, unknown>;
  body?: unknown;
  contentType?: string;
  headers?: Record<string, string>;
  microversion?: string;
  /** Media type to ask for, when the operation does not answer JSON (e.g. text/plain for Barbican payloads). */
  accept?: string;
}

export interface ApiResponse {
  status: number;
  ok: boolean;
  contentType: string;
  /** Parsed JSON, text, or a description of a binary payload. */
  data: unknown;
  url: string;
  /** Response headers worth showing (all of them for HEAD requests). */
  headers: Record<string, string>;
  projectId?: string;
  region?: string;
}

export class OpenStackError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
  }
}

export interface ClientOptions {
  timeoutMs?: number;
  fetch?: typeof fetch;
}

/** Identity v3 root from an auth URL given with or without /v3. */
export function identityV3(authUrl: string): string {
  const base = authUrl.replace(/\/+$/, "");
  return /\/v3$/.test(base) ? base : `${base}/v3`;
}

const VERSION_SEGMENT = /^v\d+(\.\d+)?$/i;

/**
 * Joins a service endpoint from the Keystone catalog and a path from the spec. Spec paths start with the API version
 * (/v2.1/servers), while endpoints may stop before it (https://neutron:9696), include it (https://nova/v2.1) or go
 * beyond it with the project id (https://cinder/v3/<project>, https://swift/v1/AUTH_<project>). The endpoint's version
 * wins, and what follows it is kept unless the path already starts with it.
 */
export function joinEndpoint(endpoint: string, path: string): string {
  const url = new URL(endpoint);
  const base = url.pathname.split("/").filter(Boolean);
  const segments = path.split("/").filter(Boolean);
  const pathVersion = segments.length && VERSION_SEGMENT.test(segments[0]) ? 1 : 0;
  let anchor = -1;
  for (let i = base.length - 1; i >= 0; i--) {
    if (VERSION_SEGMENT.test(base[i])) {
      anchor = i;
      break;
    }
  }
  let joined: string[];
  if (pathVersion && anchor >= 0) {
    const tail = base.slice(anchor + 1);
    const rest = segments.slice(1);
    const startsWithTail = tail.length > 0 && tail.every((t, i) => rest[i] === t);
    joined = [...base.slice(0, anchor + 1), ...(startsWithTail ? [] : tail), ...rest];
  } else {
    joined = [...base, ...segments];
  }
  url.pathname = `/${joined.join("/")}${path.endsWith("/") && joined.length ? "/" : ""}`;
  url.search = "";
  return url.href;
}

/** What follows the version in an endpoint URL, e.g. "AUTH_123" for Swift. */
export function endpointTail(endpoint: string): string | undefined {
  const base = new URL(endpoint).pathname.split("/").filter(Boolean);
  for (let i = base.length - 1; i >= 0; i--) {
    if (VERSION_SEGMENT.test(base[i])) return base[i + 1];
  }
  return undefined;
}

function buildQuery(url: string, query?: Record<string, unknown>): string {
  const u = new URL(url);
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value === undefined || value === null) continue;
    // OpenStack APIs expect repeated keys for lists (?status=ACTIVE&status=ERROR).
    if (Array.isArray(value)) for (const v of value) u.searchParams.append(key, String(v));
    else u.searchParams.set(key, String(value));
  }
  return u.href;
}

function hash(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function quote(value: unknown): string {
  return JSON.stringify(String(value ?? "").slice(0, 300));
}

/** Error message of an OpenStack JSON error body, whatever service it comes from. */
function errorMessage(data: unknown): string | undefined {
  if (!data || typeof data !== "object") return typeof data === "string" ? data.slice(0, 300) : undefined;
  const obj = data as Record<string, any>;
  const inner = obj.error ?? obj.NeutronError ?? Object.values(obj).find((v) => v && typeof v === "object" && "message" in v);
  return inner?.message ?? obj.message ?? obj.faultstring ?? obj.title;
}

class BoundedMap<V> extends Map<string, V> {
  override set(key: string, value: V): this {
    if (!this.has(key) && this.size >= MAX_CACHE_ENTRIES) this.delete(this.keys().next().value!);
    return super.set(key, value);
  }
}

/**
 * Talks to OpenStack: authenticates with Keystone (tokens are cached until shortly before they expire), finds the
 * service endpoints in the token's catalog and sends the API calls with the right token, region and microversion.
 */
export class OpenStackClient {
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly tokens = new BoundedMap<Promise<KeystoneToken>>();
  private readonly projects = new BoundedMap<{ at: number; value: Promise<Project[]> }>();

  constructor(options: ClientOptions = {}) {
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.fetchImpl = options.fetch ?? fetch;
  }

  private async send(url: string, init: RequestInit): Promise<Response> {
    let res = await this.fetchImpl(url, { ...init, signal: AbortSignal.timeout(this.timeoutMs) });
    if (res.status === 429 || res.status === 503) {
      const retryAfter = Number(res.headers.get("retry-after") ?? "NaN");
      const waitMs = Number.isFinite(retryAfter) ? retryAfter * 1000 : Number.POSITIVE_INFINITY;
      if (waitMs <= MAX_RETRY_WAIT_MS) {
        await new Promise((r) => setTimeout(r, waitMs));
        res = await this.fetchImpl(url, { ...init, signal: AbortSignal.timeout(this.timeoutMs) });
      }
    }
    return res;
  }

  // --- authentication -------------------------------------------------------

  private scopeOf(credentials: CloudCredentials, projectId?: string): Record<string, unknown> | undefined {
    if (projectId) return { project: { id: projectId } };
    const p = credentials.project;
    if (!p) return undefined;
    if (p.id) return { project: { id: p.id } };
    return { project: { name: p.name, domain: p.domainId ? { id: p.domainId } : { name: p.domainName } } };
  }

  private identityOf(credentials: CloudCredentials): Record<string, unknown> {
    const auth = credentials.auth;
    const domain = (name?: string, id?: string) => (id ? { id } : name ? { name } : undefined);
    switch (auth.type) {
      case "password":
        return {
          methods: ["password"],
          password: {
            user: auth.userId
              ? { id: auth.userId, password: auth.password }
              : { name: auth.username, domain: domain(auth.userDomainName, auth.userDomainId), password: auth.password },
          },
        };
      case "application_credential":
        return {
          methods: ["application_credential"],
          application_credential: auth.id
            ? { id: auth.id, secret: auth.secret }
            : { name: auth.name, secret: auth.secret, user: { name: auth.username, domain: domain(auth.userDomainName) } },
        };
      default:
        throw new OpenStackError("This authentication type is exchanged through federation.");
    }
  }

  private async issueToken(credentials: CloudCredentials, body: unknown, headers: Record<string, string> = {}, url?: string): Promise<KeystoneToken> {
    const target = url ?? `${identityV3(credentials.authUrl)}/auth/tokens`;
    let res: Response;
    try {
      res = await this.send(target, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json", ...headers },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (err) {
      throw new OpenStackError(`Keystone unreachable at ${new URL(target).origin}: ${(err as Error).message}`);
    }
    const text = await res.text();
    let data: any;
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = text;
    }
    const value = res.headers.get("x-subject-token");
    if (!res.ok || !value) {
      const detail = errorMessage(data);
      throw new OpenStackError(
        `Keystone refused the authentication: HTTP ${res.status}${detail ? ` ${quote(detail)}` : ""}`,
        res.status,
      );
    }
    const token = data?.token ?? {};
    return {
      value,
      expiresAt: token.expires_at ? Date.parse(token.expires_at) : Date.now() + 3600_000,
      user: token.user,
      project: token.project,
      roles: (token.roles ?? []).map((r: { name: string }) => r.name),
      catalog: token.catalog ?? [],
    };
  }

  private async authenticateFresh(credentials: CloudCredentials, projectId?: string): Promise<KeystoneToken> {
    const scope = this.scopeOf(credentials, projectId);
    const auth = credentials.auth;
    if (auth.type === "oidc_access_token") {
      // Federation: the identity provider's access token buys an unscoped token, which is then scoped.
      const v3 = identityV3(credentials.authUrl);
      const unscoped = await this.issueToken(
        credentials,
        undefined,
        { Authorization: `Bearer ${auth.accessToken}` },
        `${v3}/OS-FEDERATION/identity_providers/${encodeURIComponent(auth.identityProvider)}/protocols/${encodeURIComponent(auth.protocol)}/auth`,
      );
      if (!scope) return unscoped;
      return this.issueToken(credentials, { auth: { identity: { methods: ["token"], token: { id: unscoped.value } }, scope } });
    }
    if (auth.type === "application_credential" && projectId) {
      // Bound to one project: another project cannot be requested, only the same one.
      const token = await this.authenticate(credentials);
      if (token.project?.id !== projectId) {
        throw new OpenStackError(`This application credential is bound to project ${token.project?.name ?? token.project?.id}; it cannot act on another project.`);
      }
      return token;
    }
    return this.issueToken(credentials, {
      auth: { identity: this.identityOf(credentials), ...(scope && auth.type !== "application_credential" ? { scope } : {}) },
    });
  }

  /** A valid token for the credentials, scoped to `projectId` or to their default project. Cached. */
  async authenticate(credentials: CloudCredentials, projectId?: string): Promise<KeystoneToken> {
    const key = `${hash(credentials)}|${projectId ?? ""}`;
    const cached = this.tokens.get(key);
    if (cached) {
      try {
        const token = await cached;
        if (token.expiresAt - TOKEN_MARGIN_MS > Date.now()) return token;
      } catch {
        // A failed attempt is retried below.
      }
    }
    const pending = this.authenticateFresh(credentials, projectId);
    this.tokens.set(key, pending);
    pending.catch(() => {
      if (this.tokens.get(key) === pending) this.tokens.delete(key);
    });
    return pending;
  }

  /** Forgets the cached tokens of these credentials (after a 401, or when they change). */
  invalidate(credentials: CloudCredentials): void {
    const prefix = `${hash(credentials)}|`;
    for (const key of [...this.tokens.keys()]) if (key.startsWith(prefix)) this.tokens.delete(key);
    this.projects.delete(hash(credentials));
  }

  /** Projects the identity can scope to (GET /v3/auth/projects), cached for a few minutes. */
  async listProjects(credentials: CloudCredentials): Promise<Project[]> {
    const key = hash(credentials);
    const cached = this.projects.get(key);
    if (cached && Date.now() - cached.at < PROJECTS_TTL_MS) return cached.value;
    const value = (async () => {
      const token = await this.authenticate(credentials);
      if (credentials.auth.type === "application_credential") {
        return token.project ? [{ id: token.project.id, name: token.project.name ?? token.project.id, domainId: token.project.domain?.id }] : [];
      }
      const res = await this.send(`${identityV3(credentials.authUrl)}/auth/projects`, {
        headers: { "X-Auth-Token": token.value, Accept: "application/json" },
      });
      if (!res.ok) throw new OpenStackError(`Keystone answered HTTP ${res.status} listing the projects`, res.status);
      const data = (await res.json()) as { projects?: { id: string; name: string; domain_id?: string; enabled?: boolean }[] };
      return (data.projects ?? [])
        .map((p) => ({ id: p.id, name: p.name, domainId: p.domain_id, enabled: p.enabled }))
        .sort((a, b) => a.name.localeCompare(b.name));
    })();
    this.projects.set(key, { at: Date.now(), value });
    value.catch(() => {
      if (this.projects.get(key)?.value === value) this.projects.delete(key);
    });
    return value;
  }

  // --- endpoints ------------------------------------------------------------

  /** Regions offering at least one endpoint in the token's catalog. */
  static regions(token: KeystoneToken): string[] {
    const set = new Set<string>();
    for (const s of token.catalog) for (const e of s.endpoints) if (e.region_id ?? e.region) set.add((e.region_id ?? e.region)!);
    return [...set].sort();
  }

  /** Service types present in the token's catalog. */
  static serviceTypes(token: KeystoneToken): string[] {
    return [...new Set(token.catalog.map((s) => s.type))].sort();
  }

  static endpoint(token: KeystoneToken, service: ServiceInfo, region: string | undefined, iface: EndpointInterface): { url: string; region?: string } {
    if (!token.catalog.length) {
      throw new OpenStackError("The token has no service catalog: it is not scoped to a project. Pass `project`.");
    }
    for (const type of service.catalogTypes) {
      const entry = token.catalog.find((s) => s.type === type);
      if (!entry) continue;
      const candidates = entry.endpoints.filter((e) => e.interface === iface);
      const regionOf = (e: CatalogEndpoint) => e.region_id ?? e.region;
      const match = region ? candidates.find((e) => regionOf(e) === region) : candidates[0];
      if (match) return { url: match.url, region: regionOf(match) };
      if (region && candidates.length) {
        const available = [...new Set(candidates.map(regionOf))].join(", ");
        throw new OpenStackError(`${service.name} has no ${iface} endpoint in region "${region}". Available: ${available}.`);
      }
    }
    throw new OpenStackError(
      `${service.name} (${service.catalogTypes.join("/")}) is not in this cloud's service catalog` +
        ` with a ${iface} endpoint. Available services: ${OpenStackClient.serviceTypes(token).join(", ") || "none"}.`,
    );
  }

  // --- API calls ------------------------------------------------------------

  async request(req: ApiRequest): Promise<ApiResponse> {
    const attempt = async (): Promise<ApiResponse> => {
      const token = await this.authenticate(req.credentials, req.projectId);
      const { url: endpoint, region } = OpenStackClient.endpoint(token, req.service, req.region ?? req.credentials.region, req.credentials.interface ?? "public");
      const url = buildQuery(joinEndpoint(endpoint, req.path), req.query);
      const headers: Record<string, string> = { Accept: req.accept ?? "application/json", ...req.headers, "X-Auth-Token": token.value };
      if (req.microversion && req.service.microversion) {
        const { header, prefix } = req.service.microversion;
        headers[header] = prefix ? `${prefix} ${req.microversion}` : req.microversion;
        // Nova only reads the legacy header below 2.27.
        if (req.service.type === "compute") headers["X-OpenStack-Nova-API-Version"] = req.microversion;
      }
      let body: string | undefined;
      if (req.body !== undefined) {
        const json = !req.contentType || req.contentType.includes("json");
        body = json || typeof req.body !== "string" ? JSON.stringify(req.body) : req.body;
        headers["Content-Type"] = req.contentType && req.contentType !== "*" ? req.contentType : "application/json";
      }

      const res = await this.send(url, { method: req.method, headers, body });
      const contentType = res.headers.get("content-type") ?? "";
      let data: unknown;
      if (req.method === "HEAD" || res.status === 204) {
        data = null;
      } else if (contentType.includes("json")) {
        const text = await res.text();
        try {
          data = text ? JSON.parse(text) : null;
        } catch {
          data = text;
        }
      } else if (contentType.startsWith("text/") || contentType.includes("xml") || contentType.includes("yaml") || !contentType) {
        data = await res.text();
      } else {
        const size = (await res.arrayBuffer()).byteLength;
        data = { binary: true, contentType, bytes: size, note: "Binary payloads are not returned through MCP." };
      }
      const shown: Record<string, string> = {};
      res.headers.forEach((value, name) => {
        const lower = name.toLowerCase();
        if (HIDDEN_HEADERS.has(lower)) return;
        // HEAD answers live in their headers (Swift metadata); otherwise only the request id and location matter.
        if (req.method === "HEAD" || lower === "x-openstack-request-id" || lower === "location" || lower.startsWith("x-object-meta-") || lower.startsWith("x-container-") || lower.startsWith("x-account-") || lower.includes("api-version")) {
          shown[lower] = value;
        }
      });
      return { status: res.status, ok: res.ok, contentType, data, url, headers: shown, projectId: token.project?.id, region };
    };

    const first = await attempt();
    if (first.status !== 401) return first;
    // The token may have been revoked or the password changed: authenticate again once.
    this.invalidate(req.credentials);
    return attempt();
  }
}
