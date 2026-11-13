#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Catalog } from "./catalog.js";
import { loadConfig } from "./config.js";
import { createHttpApp } from "./http.js";
import { OpenStackClient } from "./openstack/client.js";
import { randomBytes } from "node:crypto";
import { oauthProviderFromSettings } from "./oauth/factory.js";
import { createAdminApp } from "./admin/app.js";
import { loadProjects } from "./projects.js";
import { createServer } from "./server.js";
import { Settings } from "./settings.js";
import { openStore } from "./store/bootstrap.js";

const config = loadConfig();
const catalog = Catalog.load();
const client = new OpenStackClient();
if (config.envCloudError) console.error(`Ignoring the OS_* variables: ${config.envCloudError}`);

if (process.argv.includes("--stdio")) {
  // Local mode: the cloud comes from the usual OS_* variables (source your openrc file first).
  if (!config.envCloud) {
    console.error("The OS_* variables (OS_AUTH_URL, OS_USERNAME, OS_PASSWORD…) are required in --stdio mode.");
    process.exit(1);
  }
  const connections = [{ name: "openstack", credentials: config.envCloud }];
  const server = createServer({
    catalog,
    client,
    connections,
    projects: await loadProjects(client, connections),
    readOnly: config.readOnly,
    maxResponseChars: config.maxResponseChars,
  });
  await server.connect(new StdioServerTransport());
} else {
  if (config.apiKeys.length && !config.envCloud) {
    console.error("MCP_API_KEYS requires an OpenStack cloud in the OS_* variables.");
    process.exit(1);
  }
  const { store, secretKey } = openStore(config);
  const settings = new Settings(config, store);
  const oauth = oauthProviderFromSettings(settings, store);
  const app = createHttpApp(config, catalog, client, { oauth, store, settings: () => settings.effective() });
  const httpServer = app.listen(config.port, config.host, () => {
    const effective = settings.effective();
    const mode = ["managed tokens", effective.oauth ? `oauth${effective.federation ? " + federation" : ""}` : undefined, config.apiKeys.length ? "api-key" : undefined]
      .filter(Boolean)
      .join(" + ");
    console.log(
      `openstack-mcp-server listening on http://${config.host}:${config.port}/mcp ` +
        `(${catalog.operations.length} operations, auth: ${mode}${effective.readOnly ? ", read-only" : ""})`,
    );
  });

  // Until an admin password exists, the portal runs the onboarding, unlocked by this one-time code.
  const setupCode = store.hasAdminPassword() ? undefined : randomBytes(6).toString("hex");
  const adminServer = config.admin.enabled
    ? createAdminApp({ config, store, catalog, client, secretKey, settings, setupCode }).listen(
        config.admin.port,
        config.admin.host,
        () => {
          const url = `http://${config.admin.host === "0.0.0.0" ? "localhost" : config.admin.host}:${config.admin.port}/`;
          console.log(`Admin portal listening on ${url}`);
          if (setupCode) console.log(`First launch: open ${url} to set the server up. Setup code: ${setupCode}`);
        },
      )
    : undefined;

  // As PID 1 in a container, Node gets no default signal handling: shut down explicitly.
  const shutdown = (signal: string) => {
    console.log(`${signal} received, shutting down`);
    adminServer?.close();
    adminServer?.closeIdleConnections();
    httpServer.close(() => {
      store.close();
      process.exit(0);
    });
    httpServer.closeIdleConnections();
    setTimeout(() => process.exit(0), 5_000).unref();
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}
