/**
 * OpenStack services covered by the catalog. Each one is a category of operations (shown in the admin portal and
 * selectable per token), reached through the endpoint Keystone lists for one of its service types.
 */
export interface ServiceInfo {
  /** Official service type (service-types-authority), used as the `service` argument of the tools. */
  type: string;
  /** Category name shown to users. */
  name: string;
  /** Project code name, to help searches ("nova", "neutron"...). */
  project: string;
  /** Service types under which a Keystone catalog may list this service, in order of preference. */
  catalogTypes: string[];
  /** File of the OpenAPI spec, relative to the spec source (see scripts/build-catalog.ts). */
  spec?: string;
  /** How a microversion is requested, for services that have them. */
  microversion?: { header: string; prefix?: string; /** Version served without header. */ base: string };
}

export const SERVICES: ServiceInfo[] = [
  {
    type: "compute",
    name: "Compute",
    project: "nova",
    catalogTypes: ["compute"],
    spec: "compute/v2.yaml",
    microversion: { header: "OpenStack-API-Version", prefix: "compute", base: "2.1" },
  },
  { type: "network", name: "Network", project: "neutron", catalogTypes: ["network"], spec: "network/v2.yaml" },
  {
    type: "block-storage",
    name: "Block Storage",
    project: "cinder",
    catalogTypes: ["block-storage", "volumev3", "volume", "block-store"],
    spec: "block-storage/v3.yaml",
    microversion: { header: "OpenStack-API-Version", prefix: "volume", base: "3.0" },
  },
  { type: "image", name: "Image", project: "glance", catalogTypes: ["image"], spec: "image/v2.yaml" },
  { type: "identity", name: "Identity", project: "keystone", catalogTypes: ["identity"], spec: "identity/v3.yaml" },
  { type: "object-store", name: "Object Storage", project: "swift", catalogTypes: ["object-store"], spec: "object-store/v1.yaml" },
  {
    type: "load-balancer",
    name: "Load Balancer",
    project: "octavia",
    catalogTypes: ["load-balancer"],
    spec: "load-balancer/v2.yaml",
  },
  { type: "dns", name: "DNS", project: "designate", catalogTypes: ["dns"], spec: "dns/v2.yaml" },
  {
    type: "placement",
    name: "Placement",
    project: "placement",
    catalogTypes: ["placement"],
    spec: "placement/v1.yaml",
    microversion: { header: "OpenStack-API-Version", prefix: "placement", base: "1.0" },
  },
  {
    type: "shared-file-system",
    name: "Shared File Systems",
    project: "manila",
    catalogTypes: ["shared-file-system", "sharev2", "share"],
    spec: "shared-file-system/v2.yaml",
    microversion: { header: "X-OpenStack-Manila-API-Version", base: "2.0" },
  },
  {
    type: "container-infrastructure-management",
    name: "Container Infrastructure",
    project: "magnum",
    catalogTypes: ["container-infrastructure-management", "container-infra", "container-infrastructure"],
    spec: "container-infrastructure-management/v1.yaml",
    microversion: { header: "OpenStack-API-Version", prefix: "container-infra", base: "1.1" },
  },
  // No upstream spec yet: their operations come from spec/extensions/.
  { type: "orchestration", name: "Orchestration", project: "heat", catalogTypes: ["orchestration"] },
  { type: "key-manager", name: "Key Manager", project: "barbican", catalogTypes: ["key-manager"] },
];

export const SERVICE_TYPES = SERVICES.map((s) => s.type);

export function serviceInfo(type: string): ServiceInfo | undefined {
  const needle = type.trim().toLowerCase();
  return SERVICES.find((s) => s.type === needle || s.catalogTypes.includes(needle) || s.project === needle);
}

export function serviceByName(name: string): ServiceInfo | undefined {
  return SERVICES.find((s) => s.name === name);
}
