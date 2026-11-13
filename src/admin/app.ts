import { timingSafeEqual } from "node:crypto";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import express, { type NextFunction, type Request, type Response } from "express";
import { type Catalog, SENSITIVE_CATEGORIES } from "../catalog.js";
import type { Config } from "../config.js";
import { OpenStackClient } from "../openstack/client.js";
import { CredentialsError, credentialsFromEnv, parseCloudsYaml, parseOpenrc } from "../openstack/credentials.js";
import { Sealer } from "../oauth/seal.js";
import { type McpToken, type OAuthRule, type OAuthRuleInput, type Store, ValidationError } from "../store/db.js";
import { Settings } from "../settings.js";
import { dynamicTrustProxy } from "../trust-proxy.js";
import { VERSION } from "../version.js";

const SESSION_COOKIE = "osmcp_admin";
const SESSION_TTL = 12 * 60 * 60;
const LOGIN_WINDOW_MS = 15 * 60_000;
const LOGIN_MAX_ATTEMPTS = 10;

export interface AdminAppOptions {
  config: Config;
  store: Store;
  catalog: Catalog;
  client: OpenStackClient;
  secretKey: string;
  /** Runtime settings edited from the portal; built from config and store when omitted. */
  settings?: Settings;
  /** One-time code unlocking the onboarding while no admin password exists (printed in the logs). */
  setupCode?: string;
  startedAt?: number;
}

function cookie(req: Request, name: string): string | undefined {
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const [key, ...value] = part.trim().split("=");
    if (key === name) return decodeURIComponent(value.join("="));
  }
  return undefined;
}

/** Locates the built SPA: dist/admin next to the compiled server, or ../dist/admin when running from src. */
function staticDir(): string | undefined {
  const here = dirname(fileURLToPath(import.meta.url));
  return [join(here, "..", "admin-ui"), join(here, "..", "..", "dist", "admin-ui")].find((d) =>
    existsSync(join(d, "index.html")),
  );
}

export function createAdminApp({
  config,
  store,
  catalog,
  client,
  secretKey,
  settings = new Settings(config, store),
  setupCode,
  startedAt = Date.now(),
}: AdminAppOptions) {
  const app = express();
  const sealer = new Sealer(secretKey);
  const loginAttempts = new Map<string, { count: number; resetAt: number }>();
  let pendingSetupCode = setupCode;
  store.syncCategories(
    catalog.categories().map((c) => c.name),
    SENSITIVE_CATEGORIES,
  );
  app.use(dynamicTrustProxy(app, () => settings.effective().trustProxy));
  app.disable("x-powered-by");
  app.use(express.json({ limit: "100kb" }));
  app.use((_req, res, next) => {
    res.set({
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
      "Content-Security-Policy":
        "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'",
    });
    next();
  });

  const api = express.Router();

  // --- authentication -------------------------------------------------------

  const isAuthenticated = (req: Request) => {
    const value = cookie(req, SESSION_COOKIE);
    return Boolean(value && sealer.open("admin-session", value));
  };

  /** Counts failed attempts per IP; returns false (and answers 429) once the limit is reached. */
  const underAttemptLimit = (req: Request, res: Response) => {
    const attempt = loginAttempts.get(req.ip ?? "unknown");
    if (attempt && attempt.resetAt > Date.now() && attempt.count >= LOGIN_MAX_ATTEMPTS) {
      res.status(429).json({ error: "Too many attempts, try again later." });
      return false;
    }
    return true;
  };
  const recordFailure = (req: Request) => {
    const key = req.ip ?? "unknown";
    const attempt = loginAttempts.get(key);
    const current = attempt && attempt.resetAt > Date.now() ? attempt : { count: 0, resetAt: Date.now() + LOGIN_WINDOW_MS };
    loginAttempts.set(key, { ...current, count: current.count + 1 });
  };
  const openSession = (req: Request, res: Response) => {
    loginAttempts.delete(req.ip ?? "unknown");
    res.cookie(SESSION_COOKIE, sealer.seal("admin-session", {}, SESSION_TTL), {
      httpOnly: true,
      sameSite: "strict",
      secure: req.secure,
      maxAge: SESSION_TTL * 1000,
      path: "/",
    });
  };

  api.post("/auth/login", (req, res) => {
    if (!underAttemptLimit(req, res)) return;
    const password = typeof req.body?.password === "string" ? req.body.password : "";
    if (!store.verifyAdminPassword(password)) {
      recordFailure(req);
      res.status(401).json({ error: "Invalid password." });
      return;
    }
    openSession(req, res);
    res.json({ ok: true });
  });

  // First launch: whoever holds the setup code from the logs chooses the admin password.
  api.post("/setup/admin", (req, res) => {
    if (store.hasAdminPassword() || !pendingSetupCode) {
      res.status(409).json({ error: "The admin account already exists." });
      return;
    }
    if (!underAttemptLimit(req, res)) return;
    const code = typeof req.body?.setupCode === "string" ? req.body.setupCode.trim().toLowerCase() : "";
    const expected = Buffer.from(pendingSetupCode);
    if (code.length !== expected.length || !timingSafeEqual(Buffer.from(code), expected)) {
      recordFailure(req);
      res.status(401).json({ error: "Invalid setup code." });
      return;
    }
    store.setAdminPassword(typeof req.body?.password === "string" ? req.body.password : "");
    pendingSetupCode = undefined;
    openSession(req, res);
    res.json({ ok: true });
  });

  api.post("/auth/logout", (_req, res) => {
    res.clearCookie(SESSION_COOKIE, { path: "/" });
    res.json({ ok: true });
  });

  api.get("/auth/me", (req, res) => {
    res.json({
      authenticated: isAuthenticated(req),
      needsSetup: !store.hasAdminPassword(),
      setupCompleted: settings.setupCompleted(),
    });
  });

  // Everything below requires a session. Mutations also require a custom header, which
  // cross-site forms cannot send (defence in depth on top of the SameSite cookie).
  api.use((req: Request, res: Response, next: NextFunction) => {
    if (!isAuthenticated(req)) {
      res.status(401).json({ error: "Not authenticated." });
      return;
    }
    if (req.method !== "GET" && req.headers["x-requested-with"] !== "openstack-mcp-admin") {
      res.status(403).json({ error: "Missing X-Requested-With header." });
      return;
    }
    next();
  });

  // --- dashboard ------------------------------------------------------------

  const tokenStatus = (t: McpToken) =>
    t.revokedAt ? "revoked" : t.expiresAt && t.expiresAt < Date.now() ? "expired" : "active";

  api.get("/dashboard", (_req, res) => {
    const effective = settings.effective();
    const tokens = store.listTokens();
    const disabled = new Set(store.disabledCategories());
    const categories = catalog.categories();
    const mcpUrl = effective.publicUrl
      ? new URL("/mcp", effective.publicUrl).href
      : `http://${config.host === "0.0.0.0" ? "localhost" : config.host}:${config.port}/mcp`;
    res.json({
      version: VERSION,
      uptimeSeconds: Math.round((Date.now() - startedAt) / 1000),
      mcpUrl,
      catalog: { operations: catalog.operations.length, generatedAt: catalog.generatedAt },
      categories: { total: categories.length, enabled: categories.filter((c) => !disabled.has(c.name)).length },
      connections: store.listConnections().map((c) => ({ id: c.id, name: c.name, lastCheck: c.lastCheck })),
      tokens: {
        active: tokens.filter((t) => tokenStatus(t) === "active").length,
        expired: tokens.filter((t) => tokenStatus(t) === "expired").length,
        revoked: tokens.filter((t) => tokenStatus(t) === "revoked").length,
      },
      auth: {
        managedTokens: true,
        oauth: Boolean(effective.oauth),
        federation: Boolean(effective.oauth && effective.federation),
        apiKeys: config.apiKeys.length > 0,
      },
      readOnly: effective.readOnly,
    });
  });

  // --- connections ----------------------------------------------------------

  api.get("/connections", (_req, res) => {
    const usage = new Map<string, number>();
    for (const t of store.listTokens()) for (const id of t.connectionIds) usage.set(id, (usage.get(id) ?? 0) + 1);
    res.json(store.listConnections().map((c) => ({ ...c, tokenCount: usage.get(c.id) ?? 0 })));
  });

  api.post("/connections", (req, res) => {
    res.status(201).json(store.createConnection(req.body ?? {}));
  });

  api.patch("/connections/:id", (req, res) => {
    res.json(store.updateConnection(String(req.params.id), req.body ?? {}));
  });

  api.delete("/connections/:id", (req, res) => {
    store.deleteConnection(String(req.params.id));
    res.status(204).end();
  });

  /** Fills the connection form from a pasted clouds.yaml or openrc file (nothing is stored). */
  api.post("/connections/parse", (req, res) => {
    const text = typeof req.body?.text === "string" ? req.body.text : "";
    if (!text.trim()) throw new ValidationError("Paste a clouds.yaml or an openrc file.");
    try {
      if (/^\s*clouds\s*:/m.test(text)) {
        const clouds = parseCloudsYaml(text, { allowMissingSecret: true });
        res.json({
          format: "clouds.yaml",
          clouds: Object.entries(clouds).map(([name, value]) =>
            typeof value === "string" ? { name, error: value } : { name, credentials: value },
          ),
        });
        return;
      }
      const vars = parseOpenrc(text);
      if (!vars.OS_AUTH_URL) throw new ValidationError("No clouds: section nor OS_AUTH_URL found.");
      // Interactive openrc files ask for the password: accept them without it, the form asks for it.
      const credentials = credentialsFromEnv({ OS_PASSWORD: "-", OS_APPLICATION_CREDENTIAL_SECRET: "-", ...vars })!;
      const auth = { ...credentials.auth } as Record<string, unknown>;
      for (const key of ["password", "secret"]) if (auth[key] === "-") auth[key] = "";
      res.json({ format: "openrc", clouds: [{ name: vars.OS_CLOUD ?? vars.OS_PROJECT_NAME ?? "openstack", credentials: { ...credentials, auth } }] });
    } catch (err) {
      if (err instanceof CredentialsError) throw new ValidationError(err.message);
      throw err;
    }
  });

  /** Projects the connection's identity can act on, to pick a default one. */
  api.get("/connections/:id/projects", async (req, res) => {
    const credentials = store.connectionCredentials(String(req.params.id));
    if (!credentials) {
      res.status(404).json({ error: "Connection not found." });
      return;
    }
    try {
      res.json(await client.listProjects(credentials));
    } catch (err) {
      res.status(502).json({ error: (err as Error).message });
    }
  });

  api.post("/connections/:id/test", async (req, res) => {
    const id = String(req.params.id);
    const credentials = store.connectionCredentials(id);
    if (!credentials) {
      res.status(404).json({ error: "Connection not found." });
      return;
    }
    const connection = store.getConnection(id)!;
    client.invalidate(credentials);
    let ok = false;
    let detail: string;
    try {
      const token = await client.authenticate(credentials, connection.defaultProjectId ?? undefined);
      ok = true;
      const user = token.user ? `${token.user.name ?? token.user.id}${token.user.domain?.name ? `@${token.user.domain.name}` : ""}` : "?";
      const parts = [`Authenticated as ${user}`];
      if (token.project) parts.push(`project ${token.project.name ?? token.project.id}`);
      else parts.push("unscoped (no default project)");
      const regions = OpenStackClient.regions(token);
      if (regions.length) parts.push(`region${regions.length > 1 ? "s" : ""} ${regions.join(", ")}`);
      if (token.catalog.length) parts.push(`${OpenStackClient.serviceTypes(token).length} services`);
      try {
        const count = (await client.listProjects(credentials)).length;
        parts.push(`${count} project${count > 1 ? "s" : ""}`);
      } catch {
        parts.push("projects not listable");
      }
      if (credentials.region && regions.length && !regions.includes(credentials.region)) {
        ok = false;
        parts.push(`region "${credentials.region}" not in the catalog`);
      }
      detail = parts.join(" · ");
    } catch (err) {
      detail = (err as Error).message;
    }
    store.recordConnectionCheck(id, ok, detail);
    res.json(store.getConnection(id));
  });

  // --- MCP tokens -----------------------------------------------------------

  const serializeToken = (t: McpToken, names: Map<string, string>) => ({
    ...t,
    connections: t.connectionIds.map((id) => ({ id, name: names.get(id) ?? null })),
    status: tokenStatus(t),
  });
  const connectionNames = () => new Map(store.listConnections().map((c) => [c.id, c.name]));

  const parseTokenBody = (body: Record<string, unknown>) => {
    const known = new Set(catalog.categories().map((c) => c.name));
    if (Array.isArray(body.categories)) {
      const unknown = body.categories.filter((c) => !known.has(String(c)));
      if (unknown.length) throw new ValidationError(`Unknown categories: ${unknown.join(", ")}`);
    }
    return {
      ...(body.name !== undefined ? { name: String(body.name) } : {}),
      ...(Array.isArray(body.connectionIds) ? { connectionIds: body.connectionIds.map(String) } : {}),
      // `connectionId` is accepted as a shorthand for a single-connection token.
      ...(body.defaultConnectionId !== undefined || body.connectionId !== undefined
        ? { defaultConnectionId: String(body.defaultConnectionId ?? body.connectionId) }
        : {}),
      ...(body.readOnly !== undefined ? { readOnly: Boolean(body.readOnly) } : {}),
      ...(Array.isArray(body.allowedIps) ? { allowedIps: body.allowedIps.map(String) } : {}),
      ...(body.categories !== undefined
        ? { categories: Array.isArray(body.categories) ? body.categories.map(String) : null }
        : {}),
      ...(body.expiresAt !== undefined ? { expiresAt: body.expiresAt === null ? null : Number(body.expiresAt) } : {}),
    };
  };

  api.get("/tokens", (_req, res) => {
    const names = connectionNames();
    res.json(store.listTokens().map((t) => serializeToken(t, names)));
  });

  api.post("/tokens", (req, res) => {
    const input = parseTokenBody(req.body ?? {});
    const { token, secret } = store.createToken({ name: "", defaultConnectionId: "", ...input });
    res.status(201).json({ token: serializeToken(token, connectionNames()), secret });
  });

  api.patch("/tokens/:id", (req, res) => {
    res.json(serializeToken(store.updateToken(String(req.params.id), parseTokenBody(req.body ?? {})), connectionNames()));
  });

  api.post("/tokens/:id/revoke", (req, res) => {
    store.revokeToken(String(req.params.id));
    const token = store.getToken(String(req.params.id));
    if (!token) {
      res.status(404).json({ error: "Token not found." });
      return;
    }
    res.json(serializeToken(token, connectionNames()));
  });

  api.delete("/tokens/:id", (req, res) => {
    store.deleteToken(String(req.params.id));
    res.status(204).end();
  });

  // --- OAuth access rules ---------------------------------------------------

  const serializeRule = (r: OAuthRule, names: Map<string, string>) => ({
    ...r,
    connections: r.connectionIds.map((id) => ({ id, name: names.get(id) ?? null })),
  });

  const parseRuleBody = (body: Record<string, unknown>): Partial<OAuthRuleInput> => {
    const known = new Set(catalog.categories().map((c) => c.name));
    if (Array.isArray(body.categories)) {
      const unknown = body.categories.filter((c) => !known.has(String(c)));
      if (unknown.length) throw new ValidationError(`Unknown categories: ${unknown.join(", ")}`);
    }
    return {
      ...(body.name !== undefined ? { name: String(body.name) } : {}),
      ...(body.matchType !== undefined ? { matchType: String(body.matchType) as OAuthRuleInput["matchType"] } : {}),
      ...(body.matchValue !== undefined ? { matchValue: String(body.matchValue) } : {}),
      ...(Array.isArray(body.connectionIds) ? { connectionIds: body.connectionIds.map(String) } : {}),
      ...(body.defaultConnectionId !== undefined
        ? { defaultConnectionId: body.defaultConnectionId === null ? null : String(body.defaultConnectionId) }
        : {}),
      ...(body.includePersonal !== undefined ? { includePersonal: Boolean(body.includePersonal) } : {}),
      ...(body.readOnly !== undefined ? { readOnly: Boolean(body.readOnly) } : {}),
      ...(body.categories !== undefined
        ? { categories: Array.isArray(body.categories) ? body.categories.map(String) : null }
        : {}),
      ...(body.enabled !== undefined ? { enabled: Boolean(body.enabled) } : {}),
    };
  };

  api.get("/oauth", (_req, res) => {
    const names = connectionNames();
    const rules = store.listOAuthRules();
    const ruleNames = new Map(rules.map((r) => [r.id, r.name]));
    res.json({
      enabled: Boolean(settings.effective().oauth),
      defaultPolicy: store.oauthDefaultPolicy(),
      rules: rules.map((r) => serializeRule(r, names)),
      identities: store.listOAuthIdentities().map((i) => ({ ...i, ruleName: i.ruleId ? (ruleNames.get(i.ruleId) ?? null) : null })),
    });
  });

  api.put("/oauth/policy", (req, res) => {
    store.setOAuthDefaultPolicy(req.body?.defaultPolicy);
    res.json({ defaultPolicy: store.oauthDefaultPolicy() });
  });

  api.post("/oauth/rules", (req, res) => {
    const input = parseRuleBody(req.body ?? {});
    const rule = store.createOAuthRule({ name: "", matchType: "email", matchValue: "", ...input });
    res.status(201).json(serializeRule(rule, connectionNames()));
  });

  api.patch("/oauth/rules/:id", (req, res) => {
    res.json(serializeRule(store.updateOAuthRule(String(req.params.id), parseRuleBody(req.body ?? {})), connectionNames()));
  });

  api.delete("/oauth/rules/:id", (req, res) => {
    store.deleteOAuthRule(String(req.params.id));
    res.status(204).end();
  });

  // --- settings & onboarding ------------------------------------------------

  api.get("/settings", (_req, res) => {
    res.json(settings.view());
  });

  api.put("/settings", (req, res) => {
    res.json(settings.update(req.body ?? {}));
  });

  api.post("/setup/complete", (_req, res) => {
    settings.completeSetup();
    res.json(settings.view());
  });

  // --- tool exposure --------------------------------------------------------

  api.get("/categories", (_req, res) => {
    const disabled = new Set(store.disabledCategories());
    const tags = catalog.tags();
    res.json(
      catalog.categories().map((c) => ({
        ...c,
        enabled: !disabled.has(c.name),
        tags: tags
          .filter((t) => t.tag === c.name || t.tag.startsWith(`${c.name} > `))
          .map((t) => ({ tag: t.tag, count: t.count })),
      })),
    );
  });

  api.put("/categories", (req, res) => {
    const disabled: unknown = req.body?.disabled;
    if (!Array.isArray(disabled)) throw new ValidationError("`disabled` must be an array of category names.");
    const known = new Set(catalog.categories().map((c) => c.name));
    const unknown = disabled.filter((c) => !known.has(String(c)));
    if (unknown.length) throw new ValidationError(`Unknown categories: ${unknown.join(", ")}`);
    store.setDisabledCategories(disabled.map(String));
    res.json({ disabled: store.disabledCategories() });
  });

  api.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof ValidationError) {
      res.status(400).json({ error: err.message });
      return;
    }
    console.error("Admin API error:", err);
    res.status(500).json({ error: "Internal server error." });
  });

  app.use("/api", api);
  app.use("/api", (_req, res) => {
    res.status(404).json({ error: "Not found." });
  });

  const ui = staticDir();
  if (ui) {
    // Built assets have content hashes and never change; index.html must always be revalidated so that an update of
    // the server is picked up by a simple reload.
    app.use("/assets", express.static(join(ui, "assets"), { immutable: true, maxAge: "1y" }));
    app.use(express.static(ui, { index: false, maxAge: "1h" }));
    app.get(/.*/, (_req, res) => res.set("Cache-Control", "no-cache").sendFile(join(ui, "index.html")));
  } else {
    app.get("/", (_req, res) => {
      res.type("text/plain").send("Admin UI not built. Run `npm run build:admin`.");
    });
  }

  return app;
}
