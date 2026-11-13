import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { HttpMethod } from "./openstack/client.js";
import { SERVICES } from "./services.js";

export type { HttpMethod } from "./openstack/client.js";

export interface OperationParam {
  name: string;
  in: "path" | "query" | "header";
  required?: boolean;
  type: string;
  values?: unknown[];
  description?: string;
  minVersion?: string;
  maxVersion?: string;
}

export interface OperationAction {
  name: string;
  /** Component schema of the action's body (without the service prefix). */
  schema: string;
  summary?: string;
}

export interface Operation {
  /** "<service type> <METHOD> <path>", e.g. "compute GET /v2.1/servers/{id}". */
  id: string;
  /** Service type, e.g. "compute". */
  service: string;
  method: HttpMethod;
  path: string;
  /** "<Service name> > <resource>", e.g. "Compute > servers". */
  tag: string;
  summary: string;
  description?: string;
  deprecated?: boolean;
  /** Explicitly flagged as dangerous; see isDangerous for the full rule. */
  dangerous?: boolean;
  /** "curated" for operations written by hand in spec/extensions (services without an upstream spec). */
  source?: string;
  /** Microversion range of the operation, when it does not exist in every version. */
  minVersion?: string;
  maxVersion?: string;
  params: OperationParam[];
  body?: { contentType: string; required?: boolean; schema: unknown };
  /** For POST …/action endpoints: the actions the body can carry, one key each ({"reboot": {...}}). */
  actions?: OperationAction[];
  responseType?: string;
}

interface CatalogFile {
  source: string;
  generatedAt: string;
  versions?: Record<string, string>;
  operations: Operation[];
  schemas: Record<string, unknown>;
}

/** Categories disabled by default the first time they appear: none for now, every call is subject to Keystone policies. */
export const SENSITIVE_CATEGORIES: string[] = [];

/**
 * Body keys of …/action requests that destroy data or bypass safety checks, across Nova, Cinder and Manila.
 * Matched case-insensitively, with or without the "os-" prefix.
 */
const DANGEROUS_ACTIONS = new Set(
  [
    "forceDelete", "force_delete", "evacuate", "rebuild", "restore", "resetState", "reset_status", "reset_task_state",
    "unmanage", "revert", "revertResize", "migrateLive", "migrate", "trigger_crash_dump", "changePassword", "reimage",
    "retype", "shrink", "force_detach", "deny_access", "resetNetwork", "rescue",
  ].map((a) => a.toLowerCase()),
);

function actionKey(name: string): string {
  return name.toLowerCase().replace(/^os-/, "");
}

/** Action names in a request body for an …/action endpoint. */
export function bodyActions(body: unknown): string[] {
  return body && typeof body === "object" && !Array.isArray(body) ? Object.keys(body) : [];
}

/**
 * Whether a call needs an explicit confirmation: operations flagged dangerous, every DELETE, and the …/action calls
 * whose action destroys data or bypasses safety checks (force delete, rebuild, evacuate, state resets, retype…).
 */
export function isDangerous(op: Operation, body?: unknown): boolean {
  if (op.dangerous) return true;
  if (op.method === "GET" || op.method === "HEAD") return false;
  if (op.method === "DELETE") return true;
  if (/\/action$/.test(op.path)) return bodyActions(body).some((a) => DANGEROUS_ACTIONS.has(actionKey(a)));
  return false;
}

/** The dangerous actions of an …/action endpoint, as listed by describe. */
export function dangerousActions(op: Operation): string[] {
  return (op.actions ?? []).map((a) => a.name).filter((a) => DANGEROUS_ACTIONS.has(actionKey(a)));
}

export interface SearchOptions {
  query?: string;
  service?: string;
  tag?: string;
  method?: HttpMethod;
  limit?: number;
}

/** Project code names and common wording mapped to the vocabulary used by the specs. */
const SYNONYMS: Record<string, string[]> = {
  vm: ["server"],
  vms: ["server"],
  instance: ["server"],
  instances: ["server"],
  ip: ["ip", "floatingip"],
  fip: ["floatingip"],
  floating: ["floating", "floatingip"],
  sg: ["security"],
  firewall: ["security", "firewall"],
  lb: ["loadbalancer", "load"],
  loadbalancer: ["loadbalancer", "load"],
  disk: ["volume"],
  disks: ["volume"],
  bucket: ["container"],
  buckets: ["container"],
  keypair: ["keypair", "key"],
  ssh: ["keypair"],
  record: ["recordset"],
  records: ["recordset"],
  tenant: ["project"],
  k8s: ["cluster"],
  kubernetes: ["cluster"],
  stack: ["stack"],
  secret: ["secret"],
  ...Object.fromEntries(SERVICES.map((s) => [s.project, s.type.split("-")])),
};

function stem(word: string): string {
  if (word.length > 4 && word.endsWith("ies")) return `${word.slice(0, -3)}y`;
  return word.length > 3 && word.endsWith("s") && !word.endsWith("ss") ? word.slice(0, -1) : word;
}

function words(text: string): string[] {
  return text
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length > 1)
    .map(stem);
}

/** Each query term becomes a group of alternatives; a term matches if any alternative does. */
function queryTerms(query: string): string[][] {
  return query
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length > 1)
    .map((w) => (SYNONYMS[w] ?? [w]).map(stem));
}

export class Catalog {
  readonly operations: Operation[];
  readonly generatedAt: string;
  readonly versions: Record<string, string>;
  private readonly file: CatalogFile;
  private readonly schemas: Record<string, unknown>;
  private readonly views = new Map<string, Catalog>();
  private readonly byId = new Map<string, Operation>();
  private readonly matchers: { op: Operation; regex: RegExp; names: string[] }[] = [];
  /** Version prefix of each service's paths (e.g. "/v2.1" for compute), when they all share one. */
  private readonly prefixes = new Map<string, string>();

  constructor(file: CatalogFile) {
    this.file = file;
    this.operations = file.operations;
    this.schemas = file.schemas;
    this.generatedAt = file.generatedAt;
    this.versions = file.versions ?? {};
    for (const op of this.operations) {
      this.byId.set(op.id, op);
      const names: string[] = [];
      const pattern = op.path
        .split(/(\{[^}]+\})/)
        .map((part) => {
          const m = part.match(/^\{([^}]+)\}$/);
          if (!m) return part.replace(/[.*+?^$()|[\]\\]/g, "\\$&");
          names.push(m[1]);
          // Swift object names may contain slashes.
          return m[1] === "object" ? "(.+)" : "([^/]+)";
        })
        .join("");
      this.matchers.push({ op, regex: new RegExp(`^${pattern}/?$`), names });
    }
    // Prefer literal paths over templated ones (e.g. /v2.1/servers/detail before /v2.1/servers/{id}).
    this.matchers.sort((a, b) => a.names.length - b.names.length);

    const firsts = new Map<string, Set<string>>();
    for (const op of this.operations) {
      const first = op.path.split("/")[1] ?? "";
      if (!firsts.has(op.service)) firsts.set(op.service, new Set());
      firsts.get(op.service)!.add(/^v[\d.]+$/.test(first) ? first : "");
    }
    for (const [service, set] of firsts) {
      if (set.size === 1 && [...set][0]) this.prefixes.set(service, `/${[...set][0]}`);
    }
  }

  static load(): Catalog {
    const here = dirname(fileURLToPath(import.meta.url));
    const raw = readFileSync(join(here, "catalog.json"), "utf8");
    return new Catalog(JSON.parse(raw) as CatalogFile);
  }

  /** Top-level category of an operation: its service name, e.g. "Compute". */
  static categoryOf(op: Operation): string {
    return op.tag.split(" > ")[0];
  }

  categories(): { name: string; count: number }[] {
    const counts = new Map<string, number>();
    for (const op of this.operations) {
      const name = Catalog.categoryOf(op);
      counts.set(name, (counts.get(name) ?? 0) + 1);
    }
    return [...counts.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => a.name.localeCompare(b.name));
  }

  /** Service types with at least one operation. */
  services(): string[] {
    return [...new Set(this.operations.map((op) => op.service))];
  }

  /** A catalog limited to the given categories (cached per combination). */
  restrict(categories: Iterable<string>): Catalog {
    const allowed = new Set(categories);
    const key = [...allowed].sort().join("\n");
    let view = this.views.get(key);
    if (!view) {
      view = new Catalog({
        ...this.file,
        operations: this.operations.filter((op) => allowed.has(Catalog.categoryOf(op))),
      });
      this.views.set(key, view);
    }
    return view;
  }

  get(id: string): Operation | undefined {
    return this.byId.get(id);
  }

  /** The version prefix of a service's paths, e.g. "/v2.1" for compute. */
  prefix(service: string): string | undefined {
    return this.prefixes.get(service);
  }

  /**
   * Resolves a concrete path such as /v2.1/servers/abc to its operation. The version prefix may be left out
   * (/servers/abc), it is then added.
   */
  match(
    service: string,
    method: HttpMethod,
    path: string,
  ): { op: Operation; path: string; pathParams: Record<string, string> } | undefined {
    const clean = path.split("?")[0];
    const prefix = this.prefixes.get(service);
    const candidates = [clean, ...(prefix && !clean.startsWith(`${prefix}/`) && clean !== prefix ? [`${prefix}${clean}`] : [])];
    for (const candidate of candidates) {
      for (const { op, regex, names } of this.matchers) {
        if (op.service !== service || op.method !== method) continue;
        const m = candidate.match(regex);
        if (!m) continue;
        const pathParams = Object.fromEntries(names.map((n, i) => [n, decodeURIComponent(m[i + 1])]));
        return { op, path: candidate, pathParams };
      }
    }
    return undefined;
  }

  tags(): { tag: string; count: number }[] {
    const counts = new Map<string, number>();
    for (const op of this.operations) counts.set(op.tag, (counts.get(op.tag) ?? 0) + 1);
    return [...counts.entries()].map(([tag, count]) => ({ tag, count })).sort((a, b) => a.tag.localeCompare(b.tag));
  }

  search({ query = "", service, tag, method, limit = 20 }: SearchOptions): Operation[] {
    const terms = queryTerms(query);
    const tagFilter = tag?.toLowerCase();
    const candidates = this.operations.filter(
      (op) =>
        (!method || op.method === method) &&
        (!service || op.service === service) &&
        (!tagFilter || op.tag.toLowerCase().includes(tagFilter)),
    );
    if (!terms.length) return candidates.slice(0, limit);

    const scored = candidates.map((op) => {
      const fields: [string[], number][] = [
        [words(op.summary), 4],
        [words(op.tag), 3],
        [words(`${op.service} ${op.path}`), 2],
        [words(`${op.description ?? ""} ${(op.actions ?? []).map((a) => a.name).join(" ")}`), 1],
      ];
      let score = 0;
      let matched = 0;
      for (const alternatives of terms) {
        let best = 0;
        for (const [fieldWords, weight] of fields) {
          if (fieldWords.some((w) => alternatives.some((a) => w.startsWith(a)))) best = Math.max(best, weight);
        }
        if (best) matched++;
        score += best;
      }
      if (op.deprecated) score -= 1;
      return { op, score, matched };
    });

    const all = scored.filter((s) => s.matched === terms.length);
    const pool = all.length ? all : scored.filter((s) => s.matched > 0);
    return pool
      .sort((a, b) => b.matched - a.matched || b.score - a.score || a.op.path.length - b.op.path.length)
      .slice(0, limit)
      .map((s) => s.op);
  }

  /** Inlines component $refs up to a fixed depth so the schema is self-contained. */
  resolveSchema(schema: unknown, depth = 0): unknown {
    if (Array.isArray(schema)) return schema.map((s) => this.resolveSchema(s, depth));
    if (!schema || typeof schema !== "object") return schema;
    const obj = schema as Record<string, unknown>;
    if (typeof obj.$ref === "string") {
      const name = obj.$ref.split("/").pop()!;
      if (depth >= 5 || !this.schemas[name]) return { $ref: name };
      return this.resolveSchema(this.schemas[name], depth + 1);
    }
    return Object.fromEntries(Object.entries(obj).map(([k, v]) => [k, this.resolveSchema(v, depth)]));
  }

  /** Schema of one action of an …/action endpoint. */
  actionSchema(op: Operation, action: string): unknown {
    const found = op.actions?.find((a) => a.name.toLowerCase() === action.toLowerCase());
    if (!found) return undefined;
    return this.resolveSchema({ $ref: `#/components/schemas/${op.service}:${found.schema}` });
  }
}
