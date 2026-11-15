# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

First version, built on the architecture of [infomaniak-mcp-server](https://github.com/kallioli/infomaniak-mcp-server).

### MCP server
- Remote MCP server over Streamable HTTP (stateless, horizontally scalable), plus a stdio mode using the `OS_*`
  variables.
- A catalog of about 1,800 operations compiled from the OpenStack OpenAPI specs (Nova, Neutron, Cinder, Glance,
  Keystone, Swift, Octavia, Designate, Placement, Manila, Magnum) and curated specs for Heat and Barbican.
- Tools: `openstack_list_clouds`, `openstack_list_services`, `openstack_search_operations`,
  `openstack_describe_operation`, `openstack_get` (GET/HEAD) and `openstack_request` (writes).
- Keystone authentication with passwords or application credentials, token cache, project switching, endpoint
  selection by region and interface from the service catalog, microversions.
- Confirmation (elicitation or `confirm: true`) for deletions, destructive server, volume and share actions, Heat stack
  abandon and Barbican secret payloads.
- Paths with dot segments (`..`, `%2e%2e`) or backslashes are refused, so the URL sent is always the operation checked
  against the catalog (service restrictions and confirmations); redirects from OpenStack are not followed.

### Access control and administration
- Admin portal (English / French) with onboarding, OpenStack connections (import from `clouds.yaml` or `openrc`,
  live test, default project), MCP tokens, OAuth rules, service exposure and settings.
- OAuth through any OpenID Connect identity provider, with optional Keystone federation for personal access. Users
  approve each client on a consent page naming where their access is sent, and the authorization is bound to their
  browser; refresh tokens expire after 30 days without use.
- Static API keys acting with the cloud of the `OS_*` variables.
