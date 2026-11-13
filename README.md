<p align="center"><img src="assets/favicon.svg" width="96" alt=""></p>

# openstack-mcp-server

A remote [Model Context Protocol](https://modelcontextprotocol.io) server that gives AI assistants (Claude, Cursor,
VS Code…) access to the **OpenStack APIs** of one or several clouds, with a web admin portal to manage who can do
what.

> **Unofficial project**, not affiliated with or endorsed by the OpenInfra Foundation. "OpenStack" is a trademark of
> the OpenInfra Foundation.

## Features

- **The OpenStack APIs, a handful of tools.** About 1,800 operations across 13 services, reachable through six tools
  instead of one tool per endpoint, every call validated against the catalog:
  Compute (Nova), Network (Neutron), Block Storage (Cinder), Image (Glance), Identity (Keystone), Object Storage
  (Swift), Load Balancer (Octavia), DNS (Designate), Placement, Shared File Systems (Manila), Container Infrastructure
  (Magnum), Orchestration (Heat) and Key Manager (Barbican).
- **Keystone done for you.** Password or application credential authentication, tokens cached until they expire,
  endpoints taken from the service catalog (region and interface), microversions, project switching per call.
- **Several clouds and projects.** One server, many clouds and identities ("connections"); the assistant picks the
  right one, the project and the region per call ("list the servers of the staging project").
- **Fine-grained access.** MCP tokens with read-only mode, allowed services, IP allow-list and expiry; "Sign in" with
  your OpenID Connect identity provider (OAuth) with rules per user, e-mail or domain, and optionally Keystone
  federation so that people act with their own OpenStack identity.
- **Safe by default.** Deletions and destructive actions (rebuild, evacuate, force delete, state resets, reading a
  secret payload…) need the user's explicit confirmation. Keystone policies apply on top of everything.
- **Admin portal.** Guided first-launch setup (paste your `clouds.yaml` or `openrc`), then everything is managed from
  a web UI (English / French), applied without restart.
- **Easy to run.** One container image (amd64 / arm64), a SQLite file for state, stateless MCP endpoint.

## Quick start

```bash
podman run -d --name openstack-mcp-server \
  -p 3000:3000 -p 127.0.0.1:9090:9090 \
  -v openstack-mcp-data:/data \
  ghcr.io/kallioli/openstack-mcp-server:latest

podman logs openstack-mcp-server | grep "Setup code"
```

Open <http://localhost:9090>, enter the setup code and follow the wizard:

1. **Admin account**: the one-time code from the logs proves you own the server.
2. **Access & security**: public URL, reverse proxy, global read-only mode.
3. **OpenStack connection**: paste a `clouds.yaml` or an `openrc` file, or fill in the Keystone URL and credentials
   (an [application credential](https://docs.openstack.org/keystone/latest/user/application_credentials.html) is
   recommended). It is tested live and you pick a default project.
4. **OAuth** (optional): enables "Sign in" through your identity provider, for claude.ai.
5. **MCP token**: generated with a ready-to-paste client command.

Docker works the same way (`docker run …` with the same options). If your cloud uses a private certificate
authority, mount it and set `NODE_EXTRA_CA_CERTS=/certs/ca.pem`.

## Connecting a client

The MCP endpoint is `http://<host>:3000/mcp` (or your public HTTPS URL).

**Claude Code**, with an MCP token from the portal:

```bash
claude mcp add --transport http openstack https://mcp.example.com/mcp \
  --header "Authorization: Bearer osmt_…"
```

**Claude Code with OAuth**: `claude mcp add --transport http openstack https://mcp.example.com/mcp`, then `/mcp` to
sign in.

**claude.ai**: Settings → Connectors → Add custom connector → `https://mcp.example.com/mcp`. claude.ai reaches the
server from the internet, so it needs a public HTTPS URL and OAuth enabled.

**Claude Desktop and other clients without custom headers** can go through
[`mcp-remote`](https://www.npmjs.com/package/mcp-remote):

```json
{
  "mcpServers": {
    "openstack": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://localhost:3000/mcp", "--header", "Authorization:${AUTH}"],
      "env": { "AUTH": "Bearer osmt_…" }
    }
  }
}
```

**Locally, without the server** (stdio): source your `openrc` file, then
`node dist/index.js --stdio` (or `npx tsx src/index.ts --stdio`) as the command of your MCP client.

## How it works

### Tools

| Tool | Purpose |
| --- | --- |
| `openstack_list_clouds` | Connections available, with identity, roles, projects, regions and services of each |
| `openstack_list_services` | Services covered, their resource categories and number of operations |
| `openstack_search_operations` | Full-text search of operations (English keywords, code names such as "nova" work) |
| `openstack_describe_operation` | Parameters, body schema, microversion range and safety flags of one operation; one action of `…/action` endpoints |
| `openstack_get` | GET and HEAD requests (read-only, safe to auto-approve) |
| `openstack_request` | POST / PUT / PATCH / DELETE (hidden in read-only mode) |

The assistant searches the catalog, reads the operation's description, then calls it with the `service` type
(`compute`, `network`, `block-storage`…) and the path as in the API reference. The version prefix may be left out
(`/servers/detail` for `/v2.1/servers/detail`). The server joins it to the endpoint of the Keystone catalog, whatever
its shape (`https://neutron:9696`, `https://nova/v2.1`, `https://cinder/v3/<project>`, `https://swift/v1/AUTH_<project>`).

### Connections, projects and regions

- **Connection**: a set of OpenStack credentials (Keystone URL, user or application credential, default project,
  region and interface). An MCP token is granted one or more connections, one being its default, and never sees the
  others. A read-only connection refuses writes.
- **Project**: the projects the identity can scope to (`GET /v3/auth/projects`). Each connection can have a default
  one. Application credentials are bound to their own project.
- **Region**: any region of the service catalog, the connection's region by default.

`openstack_get` and `openstack_request` take `project` (**name or id**), `region` and, when several connections are
available, `connection`. The token's projects are listed in the tool schema, so the assistant needs no extra call to
pick one; an ambiguous name is refused with the candidates. Path placeholders `{project_id}` / `{tenant_id}` default
to the project acted on, and Swift's `{account}` to the account of the object-store endpoint.

### Microversions

Compute, Block Storage, Placement, Shared File Systems and Container Infrastructure take a `microversion` argument
(`"2.79"`, `"latest"`). Operations introduced after the base version get their minimum version automatically, and
calls to operations removed in the requested version are refused before reaching the cloud.

### Confirmation of risky operations

Every `DELETE`, the destructive actions of `…/action` endpoints (rebuild, evacuate, force delete, reset state,
migrate, retype, unmanage, revert…), abandoning a Heat stack and reading a Barbican secret payload need the user's
explicit confirmation. When the client supports MCP elicitation, the server asks the user directly; otherwise the call
is refused until the assistant confirms with the user and retries with `confirm: true`.

### The catalog

`src/catalog.json` is compiled by `npm run catalog` from the OpenAPI specs generated by the OpenStack codegenerator and
shipped with the [OpenStack Rust SDK](https://github.com/gtema/openstack) (`openstack_types/data`, Apache-2.0),
downloaded at a pinned commit. Heat and Barbican have no upstream spec yet: their operations are written by hand in
`spec/extensions/` and shown as `source: curated`.

## Authentication

Modes can be combined:

| Mode | For | The client sends |
| --- | --- | --- |
| **MCP tokens** (recommended) | Teams; Claude Code, Cursor, VS Code… | `Authorization: Bearer osmt_…`, created in the portal |
| **OAuth** | claude.ai, Claude Desktop | Nothing: the user signs in with the identity provider |
| **Static API keys** | Legacy setups, GitOps | `Authorization: Bearer <key>` from `MCP_API_KEYS`; acts with the `OS_*` cloud |

### OAuth and Keystone federation

1. Create a confidential OpenID Connect client in your identity provider (Keycloak, Entra ID, Authentik…) with the
   redirect URI `https://<your-server>/oauth/callback`.
2. Enter the public URL, issuer URL, client id and client secret in the portal (wizard or **Settings**).
3. Add the server in your client with just its URL; the client handles the login.

The **OAuth access** page grants shared connections to the people who sign in, through rules matching them by user id
(`sub`), e-mail address or e-mail domain, with read-only mode and allowed services. E-mail and domain rules only match
addresses the identity provider reports as verified, and rules are re-evaluated on every request.

When **Keystone federation** is configured (Keystone URL, identity provider and protocol, as registered in Keystone),
users also get a `Personal` connection: their identity provider access token is exchanged at
`/v3/OS-FEDERATION/identity_providers/<idp>/protocols/<protocol>/auth` (like keystoneauth's `v3oidcaccesstoken`), so
they act with their own OpenStack identity and roles. Keystone must accept bearer tokens from that provider (for
instance mod_auth_openidc with `OIDCOAuthVerifyJwksUri` or token introspection). Without federation, people only get
the shared connections their rule grants. The policy for users no rule matches is either *personal access only* or
*deny*.

The server stores nothing for OAuth: clients, codes and tokens are AES-256-GCM sealed. Access tokens expire with the
identity provider token they wrap; changing the OAuth secret signs everyone out.

## Admin portal

Runs on its own port (default `9090`). **Keep it private**: publish only the MCP port through your reverse proxy and
reach the portal through a VPN, an SSH tunnel or a restricted virtual host.

| Page | What it does |
| --- | --- |
| Dashboard | Health, catalog size, exposed services, tokens, connection status, auth modes, MCP URL |
| OpenStack connections | Credentials the server acts with (encrypted at rest), import from `clouds.yaml` / `openrc`, live test, default project |
| MCP tokens | Tokens shown once and stored hashed: connections, read-only, services, IP allow-list, expiry, revocation |
| OAuth access | Rules for people who sign in, default policy, recent sign-ins |
| Tool exposure | Services visible to every client |
| Settings | Public URL, reverse proxy, read-only mode, response size, OpenID Connect client, Keystone federation |

## Configuration

Settings made in the portal are stored in the database and applied without restart. Environment variables take
precedence and lock the matching field in the portal, which suits GitOps deployments. See
[.env.example](.env.example) for details.

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT`, `HOST` | `3000`, `0.0.0.0` | MCP endpoint |
| `ADMIN_PORT`, `ADMIN_HOST`, `ADMIN_ENABLED` | `9090`, `HOST`, `true` | Admin portal |
| `ADMIN_PASSWORD` | | Sets the admin password at startup (skips the first wizard step) |
| `DATA_DIR` | `./data` (`/data` in the image) | SQLite database and generated secret key |
| `MCP_SECRET_KEY` | generated in `DATA_DIR/secret.key` | Encrypts stored OpenStack credentials: back it up |
| `PUBLIC_URL` | | Public HTTPS origin, required for OAuth |
| `TRUST_PROXY` | | Number of reverse proxies in front of the server (e.g. `1`) |
| `OPENSTACK_READ_ONLY` | `false` | Read-only for every client |
| `MAX_RESPONSE_CHARS` | `60000` | Longer API responses are truncated |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_SCOPES`, `OAUTH_SECRET` | | OpenID Connect client for OAuth |
| `OS_FEDERATION_AUTH_URL`, `OS_FEDERATION_IDP`, `OS_FEDERATION_PROTOCOL`, `OS_FEDERATION_REGION` | protocol `openid` | Keystone federation |
| `MCP_ALLOWED_HOSTS` | | Host header allow-list |
| `MCP_API_KEYS` and the `OS_*` variables | | Static API keys mode (and `--stdio` mode) |
| `NODE_EXTRA_CA_CERTS` | | Private certificate authority of the cloud |

Put the MCP endpoint behind HTTPS before exposing it: tokens travel in request headers.

## Development

```bash
npm install
npm run dev                  # MCP server and admin API in watch mode
npm run dev:admin            # admin UI with hot reload on :5173 (API proxied to :9090)
npm test                     # vitest
npm run typecheck
npm run build                # server and admin UI into dist/
npm run catalog              # rebuild src/catalog.json (add -- --specs <dir> to use local specs)
```

Build the image yourself with `podman build --format docker -t openstack-mcp-server .` (`--format docker` keeps the
health check) or `docker build -f Containerfile -t openstack-mcp-server .`. The CI publishes `latest` from `main` and
`X.Y.Z` / `X.Y` from version tags.

## License

[MIT](LICENSE). The catalog is derived from OpenAPI specs under the Apache License 2.0, see [NOTICE](NOTICE).
