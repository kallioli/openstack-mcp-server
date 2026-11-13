import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { Catalog } from "../src/catalog.js";
import { loadConfig } from "../src/config.js";
import { createHttpApp } from "../src/http.js";
import { OpenStackClient } from "../src/openstack/client.js";
import { AUTH_URL, fakeCloud } from "./fake-openstack.js";

const catalog = Catalog.load();
const client = new OpenStackClient({ fetch: fakeCloud().fetch });
/** API key mode, the simplest way to get through /mcp. */
const CLOUD_ENV = {
  MCP_API_KEYS: "api-token",
  OS_AUTH_URL: AUTH_URL,
  OS_USERNAME: "alice",
  OS_PASSWORD: "s3cret",
  OS_USER_DOMAIN_NAME: "Default",
  OS_PROJECT_NAME: "prod",
  OS_PROJECT_DOMAIN_NAME: "Default",
};

async function withServer(env: Record<string, string>, run: (url: string) => Promise<void>) {
  const server = createHttpApp(loadConfig({ HOST: "127.0.0.1", ...CLOUD_ENV, ...env }), catalog, client).listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  try {
    await run(`http://127.0.0.1:${(server.address() as { port: number }).port}`);
  } finally {
    server.close();
  }
}

async function serverInfo(url: string) {
  const res = await fetch(`${url}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: "Bearer api-token" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } },
    }),
  });
  return (await res.json()).result.serverInfo;
}

describe("server icon", () => {
  it("is served without authentication on the MCP port", async () => {
    await withServer({}, async (url) => {
      const svg = await fetch(`${url}/favicon.svg`);
      expect(svg.status).toBe(200);
      expect(svg.headers.get("content-type")).toContain("image/svg+xml");
      expect(await svg.text()).toBe(readFileSync("assets/favicon.svg", "utf8"));

      const png = await fetch(`${url}/favicon.png`);
      expect(png.headers.get("content-type")).toBe("image/png");
      expect(Buffer.from(await png.arrayBuffer()).subarray(1, 4).toString()).toBe("PNG");

      const ico = await fetch(`${url}/favicon.ico`);
      expect(ico.headers.get("content-type")).toBe("image/x-icon");
      expect([...new Uint8Array(await ico.arrayBuffer()).subarray(0, 4)]).toEqual([0, 0, 1, 0]);

      const home = await (await fetch(url)).text();
      expect(home).toContain('<link rel="icon" href="/favicon.svg"');
    });
  });

  it("is declared in the initialize response, on the public URL when set", async () => {
    await withServer({}, async (url) => {
      const info = await serverInfo(url);
      expect(info.name).toBe("openstack-mcp-server");
      expect(info.icons).toEqual([
        { src: `${url}/favicon.svg`, mimeType: "image/svg+xml", sizes: ["any"] },
        { src: `${url}/favicon.png`, mimeType: "image/png", sizes: ["256x256"] },
      ]);
    });
    await withServer({ PUBLIC_URL: "https://mcp.example.com" }, async (url) => {
      expect((await serverInfo(url)).icons[0].src).toBe("https://mcp.example.com/favicon.svg");
    });
  });
});
