import type { OpenStackClient, Project } from "./openstack/client.js";
import type { CloudCredentials } from "./openstack/credentials.js";

/**
 * Loads the projects of several connections, keyed by connection name (cached per credentials by the client). A
 * connection whose list cannot be fetched maps to the error message instead.
 */
export async function loadProjects(
  client: OpenStackClient,
  connections: { name: string; credentials: CloudCredentials }[],
): Promise<Map<string, Project[] | string>> {
  const entries = await Promise.all(
    connections.map(async (c) => {
      try {
        return [c.name, await client.listProjects(c.credentials)] as const;
      } catch (err) {
        return [c.name, (err as Error).message] as const;
      }
    }),
  );
  return new Map<string, Project[] | string>(entries);
}
