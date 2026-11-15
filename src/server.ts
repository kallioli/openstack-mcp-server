import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult, Icon } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { type Catalog, type HttpMethod, type Operation, bodyActions, dangerousActions, isDangerous } from "./catalog.js";
import { OpenStackClient, type Project, endpointTail, unsafePathReason } from "./openstack/client.js";
import { type CloudCredentials, describeIdentity } from "./openstack/credentials.js";
import { loadProjects } from "./projects.js";
import { serviceInfo } from "./services.js";
import { VERSION } from "./version.js";

/** A set of OpenStack credentials the MCP client may act with. */
export interface ConnectionContext {
  name: string;
  credentials: CloudCredentials;
  readOnly?: boolean;
  /** Project used when the call does not name one (the credentials' own scope otherwise). */
  defaultProjectId?: string | null;
}

export interface ServerOptions {
  catalog: Catalog;
  client: OpenStackClient;
  /** Connections available to this request; the first one is the default. */
  connections: ConnectionContext[];
  /** Hides the write tool altogether. */
  readOnly?: boolean;
  maxResponseChars?: number;
  /**
   * Projects of each connection (by connection name), from loadProjects. When given, they are listed in the tool
   * schemas and projects can be named instead of given by id.
   */
  projects?: Map<string, Project[] | string>;
  /** Logo shown by clients next to the server (MCP Implementation.icons). */
  icons?: Icon[];
}

/** At most this many projects are spelled out in a tool schema; the rest are reachable by name or id. */
const MAX_LISTED_PROJECTS = 50;

/** Path placeholders standing for the project acted on, filled automatically when left open. */
const PROJECT_PARAMS = new Set(["project_id", "tenant_id"]);

/** Request headers a caller may set (Swift metadata, conditional requests, object content type). */
const ALLOWED_HEADER = /^(x-(object|container|account)-meta-[\w-]+|x-(container|account)-(read|write|sync-to|sync-key)|x-versions-location|x-history-location|x-delete-(at|after)|x-copy-from|x-object-manifest|x-symlink-target|content-type|content-disposition|if-match|if-none-match|if-modified-since|if-unmodified-since|range|destination)$/i;

const queryShape = z
  .record(z.string(), z.union([z.string(), z.number(), z.boolean(), z.array(z.union([z.string(), z.number()]))]))
  .optional()
  .describe("Query string parameters, e.g. {\"limit\": 50, \"marker\": \"<last id>\", \"status\": \"ACTIVE\"}.");

const pathParamsShape = z
  .record(z.string(), z.union([z.string(), z.number()]))
  .optional()
  .describe("Values for {placeholders} when `path` is given as a template, e.g. {\"id\": \"<server uuid>\"}.");

const microversionShape = z
  .string()
  .regex(/^(\d+\.\d+|latest)$/)
  .optional()
  .describe(
    "API microversion (compute, block-storage, placement, shared-file-system, container-infra), e.g. \"2.79\" or \"latest\". " +
      "Defaults to the service's base version, or to the operation's minimum version when it needs one.",
  );

function text(content: string, isError = false): CallToolResult {
  return { content: [{ type: "text", text: content }], ...(isError ? { isError: true } : {}) };
}

function formatOperationLine(op: Operation): string {
  const versions = op.minVersion || op.maxVersion ? ` (microversion ${op.minVersion ?? ""}-${op.maxVersion ?? ""})` : "";
  return `${op.service} ${op.method} ${op.path}: ${op.summary}${op.deprecated ? " (deprecated)" : ""}${versions}`;
}

function fillTemplate(path: string, params: Record<string, string | number> = {}): string {
  return path.replace(/\{([^}]+)\}/g, (whole, name: string) => {
    if (params[name] === undefined) return whole;
    // Swift object names keep their slashes.
    return name === "object" ? String(params[name]).split("/").map(encodeURIComponent).join("/") : encodeURIComponent(String(params[name]));
  });
}

function compareVersions(a: string, b: string): number {
  if (a === "latest") return b === "latest" ? 0 : 1;
  if (b === "latest") return -1;
  const [a1, a2] = a.split(".").map(Number);
  const [b1, b2] = b.split(".").map(Number);
  return a1 - b1 || (a2 ?? 0) - (b2 ?? 0);
}

export function createServer(options: ServerOptions): McpServer {
  const { catalog, client, connections, projects, maxResponseChars = 60_000 } = options;
  if (!connections.length) throw new Error("At least one connection is required.");
  // The write tool exists if at least one connection may write.
  const readOnly = options.readOnly || connections.every((c) => c.readOnly);
  const multiple = connections.length > 1;
  const projectsOf = (c: ConnectionContext) => {
    const value = projects?.get(c.name);
    return Array.isArray(value) ? value : [];
  };
  const services = catalog.services();
  const serviceShape = z
    .enum(services as [string, ...string[]])
    .describe("OpenStack service type, e.g. \"compute\" (Nova), \"network\" (Neutron), \"block-storage\" (Cinder), \"image\" (Glance).");

  // The choices this token has are spelled out in the schema itself, so no extra call is needed to pick one.
  const connectionShape = multiple
    ? z
        .enum(connections.map((c) => c.name) as [string, ...string[]])
        .optional()
        .describe(
          `OpenStack connection (cloud and credentials) to act with. Default: "${connections[0].name}". Available: ` +
            connections.map((c) => `"${c.name}"${c.readOnly ? " (read-only)" : ""}`).join(", ") +
            ".",
        )
    : undefined;

  const listed = connections.flatMap((c) =>
    projectsOf(c).map(
      (p) => `${p.name} (${p.id}${multiple ? `, connection "${c.name}"` : ""}${p.id === c.defaultProjectId ? ", default" : ""})`,
    ),
  );
  const projectShape = z
    .string()
    .optional()
    .describe(
      [
        "OpenStack project to act on, by name or id; the matching connection is picked automatically.",
        "Defaults to the connection's project.",
        listed.length
          ? `Known: ${listed.slice(0, MAX_LISTED_PROJECTS).join("; ")}${listed.length > MAX_LISTED_PROJECTS ? "; … (see openstack_list_clouds)" : ""}.`
          : "Use openstack_list_clouds to see them.",
      ].join(" "),
    );
  const regionShape = z.string().optional().describe("Region of the endpoint to call, e.g. \"RegionOne\". Defaults to the connection's region.");

  /** Picks the connection and project for a call from what the caller named, falling back to the defaults. */
  function resolveTarget(
    connectionName: string | undefined,
    project: string | undefined,
  ): { connection: ConnectionContext; projectId?: string } | { error: string } {
    let connection: ConnectionContext | undefined;
    if (connectionName) {
      connection = connections.find((c) => c.name.toLowerCase() === connectionName.trim().toLowerCase());
      if (!connection) {
        return { error: `Unknown connection "${connectionName}". Available: ${connections.map((c) => c.name).join(", ")}.` };
      }
    }
    if (project === undefined || project.trim() === "") {
      const chosen = connection ?? connections[0];
      return { connection: chosen, projectId: chosen.defaultProjectId ?? undefined };
    }

    const needle = project.trim().toLowerCase();
    const pool = connection ? [connection] : connections;
    const matches = (test: (p: Project) => boolean) =>
      pool.flatMap((c) => projectsOf(c).filter(test).map((p) => ({ connection: c, project: p })));
    let found = matches((p) => p.id.toLowerCase() === needle);
    if (!found.length) found = matches((p) => p.name.toLowerCase() === needle);
    if (!found.length) found = matches((p) => p.name.toLowerCase().includes(needle));

    const distinct = new Map(found.map((f) => [`${f.connection.name}/${f.project.id}`, f]));
    if (distinct.size === 1) {
      const [{ connection: c, project: p }] = distinct.values();
      return { connection: c, projectId: p.id };
    }
    if (distinct.size > 1) {
      const list = [...distinct.values()].map((f) => `${f.project.name} (${f.project.id}, connection "${f.connection.name}")`);
      return { error: `"${project}" matches several projects: ${list.join("; ")}. Pass the id or the connection.` };
    }
    // A project id the lists do not show (e.g. lists unavailable) is passed through: Keystone decides.
    if (/^[0-9a-f-]{32,36}$/i.test(project.trim())) return { connection: connection ?? connections[0], projectId: project.trim() };
    const known = pool.flatMap((c) => projectsOf(c).map((p) => p.name));
    return {
      error: known.length
        ? `Unknown project "${project}". Known: ${known.join(", ")}.`
        : `Project "${project}" cannot be resolved by name (project list unavailable); pass its id.`,
    };
  }

  const server = new McpServer(
    { name: "openstack-mcp-server", version: VERSION, ...(options.icons?.length ? { icons: options.icons } : {}) },
    {
      instructions: [
        "Gives access to the OpenStack APIs (compute/Nova, network/Neutron, block-storage/Cinder, image/Glance, identity/Keystone,",
        "object-store/Swift, load-balancer/Octavia, dns/Designate, shared-file-system/Manila, placement, container-infra/Magnum…).",
        "Workflow: 1) openstack_search_operations to find the endpoint, 2) openstack_describe_operation for its parameters and body,",
        "3) openstack_get for reads or openstack_request for writes, always with the `service` type.",
        "Resources live in projects and regions: call openstack_list_clouds first to see the connections, projects, regions and",
        "services you can use, then pass `project` (name or id), `region` and, if needed, `connection`.",
        "Lists paginate with `limit` and `marker` (id of the last item); most list endpoints accept field filters as query parameters.",
        "Compute, block-storage, placement, shared-file-system and container-infra use microversions (`microversion`).",
        "Deletions and destructive actions (rebuild, evacuate, force delete, state resets…) need the user's explicit confirmation.",
      ].join(" "),
    },
  );

  /**
   * Asks for confirmation of a dangerous call. When the client supports elicitation, the user is asked directly and
   * `confirm` is not enough; otherwise the assistant must have confirmed with the user and pass confirm: true.
   */
  async function confirmDangerous(op: Operation, what: string, confirm: boolean | undefined): Promise<CallToolResult | undefined> {
    if (server.server.getClientCapabilities()?.elicitation) {
      try {
        const answer = await server.server.elicitInput({
          message: `Confirm this OpenStack action, which may be irreversible: ${what}`,
          requestedSchema: {
            type: "object",
            properties: { confirm: { type: "boolean", title: "Confirm", description: "Run this action" } },
            required: ["confirm"],
          },
        });
        if (answer.action === "accept" && answer.content?.confirm === true) return undefined;
        return text(`Cancelled: the user did not confirm ${what}.`, true);
      } catch (err) {
        return text(`Could not ask the user to confirm ${what}: ${(err as Error).message}`, true);
      }
    }
    if (confirm === true) return undefined;
    return text(
      `${op.id} needs an explicit confirmation (irreversible action). Describe its exact effect to the user, ` +
        "get their confirmation, then retry with confirm: true.",
      true,
    );
  }

  interface CallTarget {
    connection?: string;
    project?: string;
    region?: string;
    microversion?: string;
    headers?: Record<string, string>;
    confirm?: boolean;
  }

  async function execute(
    serviceType: string,
    method: HttpMethod,
    rawPath: string,
    pathParams: Record<string, string | number> | undefined,
    query: Record<string, unknown> | undefined,
    body: unknown,
    target: CallTarget = {},
  ): Promise<CallToolResult> {
    const service = serviceInfo(serviceType);
    if (!service || !services.includes(service.type)) {
      return text(`Unknown or disabled service "${serviceType}". Available: ${services.join(", ")}.`, true);
    }
    const resolved = resolveTarget(target.connection, target.project);
    if ("error" in resolved) return text(resolved.error, true);
    const { connection } = resolved;
    if (method !== "GET" && method !== "HEAD" && connection.readOnly) {
      return text(`Connection "${connection.name}" is read-only: ${method} requests are not allowed.`, true);
    }
    for (const name of Object.keys(target.headers ?? {})) {
      if (!ALLOWED_HEADER.test(name)) return text(`Header "${name}" cannot be set (only Swift metadata and conditional headers).`, true);
    }

    let token;
    try {
      token = await client.authenticate(connection.credentials, resolved.projectId);
    } catch (err) {
      return text(`Authentication with connection "${connection.name}" failed: ${(err as Error).message}`, true);
    }
    const projectId = token.project?.id ?? resolved.projectId;

    // The project acted on fills the project placeholders the caller left open, and Swift's account comes from the
    // object-store endpoint (AUTH_<project>).
    const params = { ...pathParams };
    let path = rawPath.trim().startsWith("/") ? rawPath.trim() : `/${rawPath.trim()}`;
    if (projectId) {
      for (const name of PROJECT_PARAMS) if (params[name] === undefined && path.includes(`{${name}}`)) params[name] = projectId;
    }
    if (service.type === "object-store" && params.account === undefined && path.includes("{account}")) {
      try {
        const { url } = OpenStackClient.endpoint(token, service, target.region ?? connection.credentials.region, connection.credentials.interface ?? "public");
        const tail = endpointTail(url);
        if (tail) params.account = tail;
      } catch (err) {
        return text((err as Error).message, true);
      }
    }
    path = fillTemplate(path, params);
    if (/\{[^}]+\}/.test(path)) return text(`Unresolved placeholders in path ${path}. Provide them in path_params.`, true);
    // Refused before matching: the URL sent must be the path validated against the catalog, segment for segment.
    const unsafe = unsafePathReason(path);
    if (unsafe) return text(`Invalid path ${path}: ${unsafe}.`, true);

    const matched = catalog.match(service.type, method, path);
    if (!matched) {
      return text(
        `No ${service.name} operation matches ${method} ${path}, or its service is not enabled for this token. ` +
          "Use openstack_search_operations to find the right endpoint.",
        true,
      );
    }
    const { op } = matched;
    path = matched.path;
    const missing = op.params.filter((p) => p.in === "query" && p.required && query?.[p.name] === undefined).map((p) => p.name);
    if (missing.length) return text(`Missing required query parameter(s) for ${op.id}: ${missing.join(", ")}.`, true);
    if (body !== undefined && op.body && !op.body.contentType.includes("json") && typeof body !== "string") {
      return text(`${op.id} expects a ${op.body.contentType} body: pass it as a string.`, true);
    }
    if (op.actions?.length && body !== undefined) {
      const known = new Set(op.actions.map((a) => a.name));
      const unknown = bodyActions(body).filter((a) => !known.has(a));
      if (unknown.length) {
        return text(`Unknown action(s) ${unknown.join(", ")} for ${op.id}. See openstack_describe_operation for the list.`, true);
      }
    }

    let microversion = target.microversion;
    if (microversion && !service.microversion) {
      return text(`${service.name} has no microversions; leave \`microversion\` out.`, true);
    }
    // Operations added after the base version need at least their own version.
    if (!microversion && op.minVersion && service.microversion && compareVersions(op.minVersion, service.microversion.base) > 0) {
      microversion = op.minVersion;
    }
    if (microversion && op.maxVersion && compareVersions(microversion, op.maxVersion) > 0) {
      return text(`${op.id} was removed after microversion ${op.maxVersion}; pass microversion ≤ ${op.maxVersion}.`, true);
    }

    const projectName = token.project?.name;
    const where = [
      multiple ? `connection "${connection.name}"` : undefined,
      projectName || projectId ? `project ${projectName ?? ""}${projectId ? ` (${projectId})` : ""}`.trim() : undefined,
    ]
      .filter(Boolean)
      .join(", ");
    // Checked here, on the resolved path that is sent as is (no dot segments), so no spelling of the path can skip it.
    if (isDangerous(op, body)) {
      const actions = op.actions?.length ? ` [${bodyActions(body).join(", ")}]` : "";
      const what = `${service.type} ${method} ${path}${actions}${op.summary ? ` (${op.summary})` : ""}${where ? ` on ${where}` : ""}`;
      const refusal = await confirmDangerous(op, what, target.confirm);
      if (refusal) return refusal;
    }

    let res;
    try {
      res = await client.request({
        credentials: connection.credentials,
        projectId: resolved.projectId,
        region: target.region,
        service,
        method,
        path,
        query,
        body,
        contentType: body !== undefined ? (target.headers?.["content-type"] ?? target.headers?.["Content-Type"] ?? op.body?.contentType) : undefined,
        headers: target.headers,
        microversion,
        accept: op.responseType && !op.responseType.includes("json") && op.responseType !== "*" ? op.responseType : undefined,
      });
    } catch (err) {
      return text(`Request to OpenStack failed: ${(err as Error).message}`, true);
    }

    let output = res.data === null ? "" : typeof res.data === "string" ? res.data : JSON.stringify(res.data, null, 2);
    if (output.length > maxResponseChars) {
      output = `${output.slice(0, maxResponseChars)}\n… [truncated ${output.length - maxResponseChars} characters: narrow the request with filters, \`fields\` or pagination (limit/marker)]`;
    }
    const headerLines = Object.entries(res.headers).map(([k, v]) => `${k}: ${v}`);
    const via = [where, res.region ? `region ${res.region}` : undefined, microversion ? `microversion ${microversion}` : undefined]
      .filter(Boolean)
      .join(", ");
    return text(
      [`HTTP ${res.status} ${op.id}${via ? ` [${via}]` : ""}`, ...headerLines, ...(output ? ["", output] : [])].join("\n"),
      !res.ok,
    );
  }

  server.registerTool(
    "openstack_list_clouds",
    {
      title: "List OpenStack connections, projects and regions",
      description:
        "Lists the connections (OpenStack clouds and credentials) available to you and, for each, the identity, the " +
        "projects it can act on, the regions and the services of its catalog. Use the names with the `connection`, " +
        "`project` and `region` parameters of openstack_get / openstack_request.",
      inputSchema: {},
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async () => {
      const all = projects ?? (await loadProjects(client, connections));
      const blocks = await Promise.all(
        connections.map(async (c, index) => {
          const flags = [index === 0 ? "default" : undefined, c.readOnly ? "read-only" : "read/write"].filter(Boolean);
          const lines = [`Connection "${c.name}" (${flags.join(", ")})`, `  Keystone: ${c.credentials.authUrl}`];
          try {
            const token = await client.authenticate(c.credentials, c.defaultProjectId ?? undefined);
            const user = token.user ? `${token.user.name ?? token.user.id}${token.user.domain?.name ? `@${token.user.domain.name}` : ""}` : describeIdentity(c.credentials.auth);
            lines.push(`  Identity: ${user}${token.roles.length ? ` (roles: ${token.roles.join(", ")})` : ""}`);
            if (token.project) lines.push(`  Default project: ${token.project.name ?? ""} (${token.project.id})`);
            const regions = OpenStackClient.regions(token);
            if (regions.length) {
              lines.push(`  Regions: ${regions.map((r) => (r === c.credentials.region ? `${r} (default)` : r)).join(", ")}`);
            }
            const types = OpenStackClient.serviceTypes(token);
            if (types.length) lines.push(`  Services in the catalog: ${types.join(", ")}`);
          } catch (err) {
            lines.push(`  Authentication failed: ${(err as Error).message}`);
          }
          const list = all.get(c.name);
          if (typeof list === "string" || list === undefined) {
            lines.push(`  Projects: unavailable (${list ?? "not loaded"})`);
          } else if (!list.length) {
            lines.push("  Projects: none visible");
          } else {
            lines.push("  Projects:");
            for (const p of list) lines.push(`    - ${p.name}: ${p.id}${p.id === c.defaultProjectId ? " (default)" : ""}${p.enabled === false ? " (disabled)" : ""}`);
          }
          return lines.join("\n");
        }),
      );
      return text(blocks.join("\n\n"));
    },
  );

  server.registerTool(
    "openstack_list_services",
    {
      title: "List OpenStack API services",
      description:
        "Lists the OpenStack services (and their resource categories) covered by this server, with their number of " +
        "operations and API version. Useful to discover what the APIs cover.",
      inputSchema: {
        filter: z.string().optional().describe("Only return categories containing this text (case-insensitive), e.g. \"network\"."),
        detailed: z.boolean().optional().describe("Also list the resource categories of each service."),
      },
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ filter, detailed }) => {
      const needle = filter?.toLowerCase();
      const tags = catalog.tags();
      const lines = services.flatMap((type) => {
        const info = serviceInfo(type)!;
        const own = tags.filter((t) => t.tag.startsWith(`${info.name} > `));
        const count = own.reduce((n, t) => n + t.count, 0);
        const head = `${type} (${info.name}, ${info.project}${catalog.versions[type] ? `, API ${catalog.versions[type]}` : ""}${info.microversion ? ", microversions" : ""}): ${count} operations`;
        const matchesService = !needle || `${type} ${info.name} ${info.project}`.toLowerCase().includes(needle);
        const sub = own.filter((t) => matchesService || t.tag.toLowerCase().includes(needle!));
        if (!matchesService && !sub.length) return [];
        return [head, ...(detailed || (needle && !matchesService) ? sub.map((t) => `  - ${t.tag.split(" > ")[1]} (${t.count})`) : [])];
      });
      return text(lines.join("\n") || "No service matches.");
    },
  );

  server.registerTool(
    "openstack_search_operations",
    {
      title: "Search OpenStack API operations",
      description:
        `Full-text search over the ~${Math.round(catalog.operations.length / 100) * 100} OpenStack API operations (summary, resource, path, description, actions). ` +
        "Search in English, e.g. \"list servers\", \"floating ip\", \"security group rule\", \"volume snapshot\", \"reboot\".",
      inputSchema: {
        query: z.string().describe("Keywords in English."),
        service: serviceShape.optional(),
        method: z.enum(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]).optional(),
        limit: z.number().int().min(1).max(100).optional().describe("Max results (default 20)."),
      },
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ query, service, method, limit }) => {
      const results = catalog.search({ query, service, method, limit: limit ?? 20 });
      if (!results.length) return text("No operation found. Try other English keywords or openstack_list_services.");
      return text(results.map(formatOperationLine).join("\n"));
    },
  );

  server.registerTool(
    "openstack_describe_operation",
    {
      title: "Describe an OpenStack API operation",
      description:
        "Returns the parameters, request body schema and microversion range of one operation. `operation` is " +
        "\"<service> METHOD /path\" exactly as returned by openstack_search_operations; a concrete path also works. " +
        "For …/action endpoints, pass `action` to get the body of one action (e.g. \"reboot\").",
      inputSchema: {
        operation: z.string().describe("e.g. \"compute POST /v2.1/servers/{id}/action\""),
        action: z.string().optional().describe("For …/action endpoints: the action to describe, e.g. \"reboot\" or \"os-extend\"."),
      },
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ operation, action }) => {
      const [first, ...rest] = operation.trim().split(/\s+/);
      const service = serviceInfo(first ?? "");
      const [method, ...pathParts] = service ? rest : [first, ...rest];
      const path = pathParts.join("");
      const upper = method?.toUpperCase() as HttpMethod;
      const candidates = service ? [service.type] : services;
      let op: Operation | undefined;
      for (const s of candidates) {
        op = catalog.get(`${s} ${upper} ${path}`) ?? catalog.match(s, upper, path)?.op;
        if (op) break;
      }
      if (!op) return text(`Unknown operation "${operation}". Use openstack_search_operations first.`, true);

      if (action) {
        const schema = catalog.actionSchema(op, action);
        if (!schema) {
          return text(`No action "${action}" on ${op.id}. Actions: ${(op.actions ?? []).map((a) => a.name).join(", ") || "none"}.`, true);
        }
        const info = op.actions!.find((a) => a.name.toLowerCase() === action.toLowerCase())!;
        return text(
          JSON.stringify(
            { operation: op.id, action: info.name, summary: info.summary, needsConfirmation: dangerousActions(op).includes(info.name), body: schema },
            null,
            2,
          ),
        );
      }

      const details = {
        operation: op.id,
        service: op.service,
        category: op.tag,
        summary: op.summary,
        description: op.description,
        deprecated: op.deprecated,
        ...(op.source === "curated" ? { source: "curated (no upstream spec for this service; checked against the API reference)" } : {}),
        ...(op.minVersion || op.maxVersion ? { microversions: { min: op.minVersion, max: op.maxVersion } } : {}),
        needsConfirmation: op.actions?.length ? `for actions: ${dangerousActions(op).join(", ") || "none"}` : isDangerous(op),
        parameters: op.params,
        ...(op.actions?.length
          ? {
              actions: op.actions.map((a) => ({ name: a.name, summary: a.summary })),
              body: { contentType: op.body?.contentType, note: "One key per action, e.g. {\"<action>\": {...}}. Pass `action` to get its schema." },
            }
          : { body: op.body && { ...op.body, schema: catalog.resolveSchema(op.body.schema) } }),
        responseType: op.responseType ?? "application/json",
        tool: op.method === "GET" || op.method === "HEAD" ? "openstack_get" : "openstack_request",
      };
      return text(JSON.stringify(details, null, 2));
    },
  );

  server.registerTool(
    "openstack_get",
    {
      title: "Read from the OpenStack APIs",
      description:
        "Performs a GET (or HEAD) request on an OpenStack service. `path` may be concrete (/v2.1/servers/abc) or a " +
        "template (/v2.1/servers/{id}) combined with path_params; the version prefix may be left out (/servers/detail).",
      inputSchema: {
        service: serviceShape,
        path: z.string().describe("API path as in the catalog, e.g. /v2.0/networks"),
        path_params: pathParamsShape,
        query: queryShape,
        method: z.enum(["GET", "HEAD"]).optional().describe("HEAD returns the headers only (e.g. Swift metadata)."),
        microversion: microversionShape,
        confirm: z
          .boolean()
          .optional()
          .describe("Set to true only after the user explicitly asked for it, for the few reads needing confirmation (secret payloads)."),
        project: projectShape,
        region: regionShape,
        ...(connectionShape ? { connection: connectionShape } : {}),
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ service, path, path_params, query, method, microversion, confirm, project, region, connection }) =>
      execute(service, method ?? "GET", path, path_params, query, undefined, { connection, project, region, microversion, confirm }),
  );

  if (!readOnly) {
    server.registerTool(
      "openstack_request",
      {
        title: "Modify resources through the OpenStack APIs",
        description:
          "Performs a POST, PUT, PATCH or DELETE request on an OpenStack service. These calls change real resources " +
          "(and may incur costs): check the operation with openstack_describe_operation and confirm intent before calling.",
        inputSchema: {
          service: serviceShape,
          method: z.enum(["POST", "PUT", "PATCH", "DELETE"]),
          path: z.string().describe("API path, concrete or template, e.g. /v2.1/servers/{id}/action"),
          path_params: pathParamsShape,
          query: queryShape,
          body: z
            .unknown()
            .optional()
            .describe("JSON request body, as described by openstack_describe_operation (a string for Swift object content)."),
          headers: z
            .record(z.string(), z.string())
            .optional()
            .describe("Extra headers: Swift metadata (X-Object-Meta-*, X-Container-Meta-*…), Content-Type, If-Match…"),
          microversion: microversionShape,
          confirm: z
            .boolean()
            .optional()
            .describe(
              "Set to true only after the user explicitly confirmed, for operations needing confirmation (deletions, rebuild, evacuate, force delete, resets…; see needsConfirmation in openstack_describe_operation).",
            ),
          project: projectShape,
          region: regionShape,
          ...(connectionShape ? { connection: connectionShape } : {}),
        },
        annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
      },
      async ({ service, method, path, path_params, query, body, headers, microversion, confirm, project, region, connection }) =>
        execute(service, method, path, path_params, query, body, { connection, project, region, microversion, headers, confirm }),
    );
  }

  return server;
}
