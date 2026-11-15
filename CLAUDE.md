# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm run dev                  # MCP server (:3000) + admin API/portal (:9090) in watch mode (tsx)
npm run dev:admin            # admin UI with hot reload on :5173, /api proxied to :9090
npm test                     # vitest (all of test/**/*.test.ts)
npx vitest run test/server.test.ts          # one file
npx vitest run -t "read-only"               # tests whose name matches
npm run typecheck            # server (tsconfig.json) AND admin UI (admin-ui/tsconfig.json)
npm run build                # server -> dist/, admin UI -> dist/admin-ui/
npm run catalog              # regenerate src/catalog.json (-- --specs <dir> for local specs, -- --ref <commit>)
npx tsx src/index.ts --stdio # local stdio mode, needs OS_* variables (source an openrc)
```

CI (`.github/workflows/ci.yml`) runs `npm ci`, `typecheck`, `test`, `build` on Node 24, then builds the multi-arch
image from `Containerfile`. Node >= 22.13 is required (`node:sqlite` is used directly without a flag, no ORM or native deps).

## Architecture

TypeScript ESM (`NodeNext`: relative imports end in `.js`). Two processes-in-one started by `src/index.ts`:

- **MCP endpoint** (`src/http.ts`, Express via the MCP SDK): **stateless** — every `POST /mcp` authenticates,
  builds a fresh `McpServer` (`createServer` in `src/server.ts`) and a `StreamableHTTPServerTransport`, then
  discards them. GET/DELETE `/mcp` return 405. Per-request state must not live on the server object.
- **Admin portal** (`src/admin/app.ts`): separate port, JSON API under `/api` plus the React SPA built from
  `admin-ui/` (Vite root is `admin-ui/`, `publicDir` is `assets/`, shared with the MCP endpoint's icons).

### Request flow on `/mcp` (src/http.ts)

The bearer token decides the auth mode, in this order: `osmt_…` → admin-managed MCP token
(`store.authenticateToken`); OAuth access-token prefix → `OidcOAuthProvider.verifyAccessToken`, then
`store.authorizeOAuth` applies OAuth rules (optionally adding a `Personal` connection via Keystone federation);
otherwise static `MCP_API_KEYS` acting with the `OS_*` cloud. Each mode yields a list of `ConnectionContext`s, a
read-only flag and allowed categories; the catalog is narrowed with `catalog.restrict()` (globally disabled
categories ∩ token categories) before `createServer`.

### MCP tools (src/server.ts)

Six generic tools instead of one per endpoint: `openstack_list_clouds`, `openstack_list_services`,
`openstack_search_operations`, `openstack_describe_operation`, `openstack_get` (GET/HEAD) and `openstack_request`
(writes; not registered when read-only). Tool schemas are generated per request: connection names and the token's
projects are embedded as enums/descriptions so the model needs no discovery call. Every call is validated against
the catalog (operation exists, microversion range, path templating, allowed headers). `isDangerous()` in
`src/catalog.ts` (every DELETE, `dangerous: true` ops, and `…/action` bodies whose key is in `DANGEROUS_ACTIONS`)
triggers `confirmDangerous`: MCP elicitation if the client supports it, else refusal until `confirm: true`.

### Catalog

`src/catalog.json` is **generated** — do not edit by hand. `scripts/build-catalog.ts` compiles the OpenAPI specs from
`gtema/openstack` (`openstack_types/data`, pinned `DEFAULT_REF`) plus hand-written specs in `spec/extensions/*.json`
(Heat, Barbican; `source: "curated"`). Service metadata (type, code name, Keystone catalog types, spec file,
microversion header/base) lives in `SERVICES` in `src/services.ts`; adding a service means an entry there and then
`npm run catalog`. `build:server` copies the JSON into `dist/`.

### OpenStack client (src/openstack/)

`client.ts` handles Keystone auth (password, application credential, `oidc_access_token` for federation), caches
tokens (renewed 2 min before expiry) and project lists (5 min) keyed by a credentials hash, resolves endpoints from
the service catalog by region/interface, joins spec paths to endpoints of any shape (version prefix optional,
`{project_id}`/Swift `{account}` filled in), and hides auth headers from responses. `credentials.ts` normalizes and
parses `clouds.yaml`/`openrc` input. `OpenStackClient` accepts an injected `fetch` — tests rely on this.

### Persistence and settings

- `src/store/db.ts` (`Store`): single SQLite file in `DATA_DIR`. Schema is `CREATE TABLE IF NOT EXISTS` in the
  constructor. Connection credentials are encrypted with the secret key (`MCP_SECRET_KEY` or generated
  `DATA_DIR/secret.key`, see `store/bootstrap.ts`); MCP tokens are stored hashed. Throws `ValidationError` for user
  input errors (the admin API maps these to 4xx).
- `src/settings.ts`: runtime settings stored in the DB, read per request via `settings.effective()` so portal changes
  apply without restart. Each setting has an env var in `ENV_VARS` that overrides it and locks it in the portal.
  The OAuth provider and router are rebuilt when OAuth settings or the public URL change (`oauth/factory.ts`,
  `currentOAuth` in `http.ts`).
- OAuth (`src/oauth/`) is stateless server-side: client registrations, codes and access tokens are AES-256-GCM
  sealed blobs (`seal.ts`) wrapping the IdP token. `/authorize` renders a consent page (anyone can register a client,
  and the IdP only sees the server's static client); `POST /oauth/consent` and `/oauth/callback` check a browser
  nonce cookie bound into the sealed pending state.
- Paths reaching OpenStack must never contain dot segments or backslashes (`unsafePathReason` in
  `openstack/client.ts`): the URL parser would rewrite them after the catalog check.

### Admin UI (admin-ui/)

React 19 + Vite, no router/state library. i18n uses English source strings as keys: `t("Some text")`; every new
user-visible string needs a French entry in `admin-ui/src/locales/fr.ts` (missing keys warn in dev).

## Tests

Vitest with no real network: `test/fake-openstack.ts` is a fake Keystone + API recorder passed as `fetch` to
`OpenStackClient`; `test/fake-idp.ts` fakes the OIDC provider. MCP tools are tested end to end with the SDK `Client`
over `InMemoryTransport` (see `connect()` in `test/server.test.ts`); HTTP/admin tests drive the Express apps.

## Conventions

- Version is duplicated in `package.json` and `src/version.ts`; changes are recorded in `CHANGELOG.md`
  (Keep a Changelog, `[Unreleased]` section).
- New env vars belong in `src/config.ts`, `.env.example` and the README configuration table.
