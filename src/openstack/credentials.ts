import { parse } from "yaml";

export type EndpointInterface = "public" | "internal" | "admin";

/** How the server authenticates to Keystone for a connection. */
export type AuthMethod =
  | {
      type: "password";
      username?: string;
      userId?: string;
      /** Domain of the user, by name (e.g. "Default") or id. */
      userDomainName?: string;
      userDomainId?: string;
      password: string;
    }
  | {
      type: "application_credential";
      /** Either the id, or the name together with the owner's user name and domain. */
      id?: string;
      name?: string;
      username?: string;
      userDomainName?: string;
      secret: string;
    }
  | {
      /** An OpenID Connect access token exchanged at Keystone's federation endpoint (keystoneauth v3oidcaccesstoken). */
      type: "oidc_access_token";
      identityProvider: string;
      protocol: string;
      accessToken: string;
    };

/** The project a token is scoped to by default. */
export interface ProjectScope {
  id?: string;
  name?: string;
  domainName?: string;
  domainId?: string;
}

/** Everything needed to reach one OpenStack cloud as one identity. */
export interface CloudCredentials {
  /** Keystone URL, with or without the trailing /v3. */
  authUrl: string;
  auth: AuthMethod;
  project?: ProjectScope;
  /** Region used when a call names none; the first region of the catalog otherwise. */
  region?: string;
  interface?: EndpointInterface;
}

export class CredentialsError extends Error {}

const INTERFACES = ["public", "internal", "admin"] as const;

function str(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined;
  const s = String(value).trim();
  return s || undefined;
}

function iface(value: unknown): EndpointInterface | undefined {
  const s = str(value)?.toLowerCase().replace(/url$/, "");
  if (!s) return undefined;
  if (!INTERFACES.includes(s as EndpointInterface)) throw new CredentialsError(`Invalid interface "${value}" (public, internal or admin).`);
  return s as EndpointInterface;
}

/** Checks and normalises credentials; throws a CredentialsError with a user-facing message. */
export function normalizeCredentials(input: CloudCredentials): CloudCredentials {
  const authUrl = str(input?.authUrl);
  if (!authUrl) throw new CredentialsError("The Keystone auth URL is required.");
  let url: URL;
  try {
    url = new URL(authUrl);
  } catch {
    throw new CredentialsError("The Keystone auth URL is not a valid URL.");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new CredentialsError("The Keystone auth URL must use http(s).");

  const a = input.auth as Record<string, unknown> | undefined;
  let auth: AuthMethod;
  switch (a?.type) {
    case "password": {
      const password = typeof a.password === "string" ? a.password : "";
      if (!str(a.username) && !str(a.userId)) throw new CredentialsError("A user name or user id is required.");
      if (!password) throw new CredentialsError("The password is required.");
      if (str(a.username) && !str(a.userId) && !str(a.userDomainName) && !str(a.userDomainId)) {
        throw new CredentialsError("The user domain is required with a user name (often \"Default\").");
      }
      auth = {
        type: "password",
        username: str(a.username),
        userId: str(a.userId),
        userDomainName: str(a.userDomainName),
        userDomainId: str(a.userDomainId),
        password,
      };
      break;
    }
    case "application_credential": {
      const secret = typeof a.secret === "string" ? a.secret : "";
      if (!secret) throw new CredentialsError("The application credential secret is required.");
      if (!str(a.id) && !(str(a.name) && str(a.username))) {
        throw new CredentialsError("The application credential id is required (or its name with the owner's user name).");
      }
      auth = {
        type: "application_credential",
        id: str(a.id),
        name: str(a.name),
        username: str(a.username),
        userDomainName: str(a.userDomainName),
        secret,
      };
      break;
    }
    case "oidc_access_token": {
      const accessToken = str(a.accessToken);
      if (!accessToken || !str(a.identityProvider)) throw new CredentialsError("Federated access needs an identity provider and a token.");
      auth = {
        type: "oidc_access_token",
        identityProvider: str(a.identityProvider)!,
        protocol: str(a.protocol) ?? "openid",
        accessToken,
      };
      break;
    }
    default:
      throw new CredentialsError("Unknown authentication type (password or application_credential).");
  }

  const p = input.project;
  const project: ProjectScope | undefined =
    p && (str(p.id) || str(p.name))
      ? { id: str(p.id), name: str(p.name), domainName: str(p.domainName), domainId: str(p.domainId) }
      : undefined;
  if (project?.name && !project.id && !project.domainName && !project.domainId) {
    throw new CredentialsError("The project domain is required with a project name (often \"Default\").");
  }
  if (auth.type === "application_credential" && project) {
    throw new CredentialsError("Application credentials are bound to their project: leave the project empty.");
  }
  return {
    authUrl: url.href.replace(/\/+$/, ""),
    auth,
    ...(project ? { project } : {}),
    ...(str(input.region) ? { region: str(input.region) } : {}),
    interface: iface(input.interface) ?? "public",
  };
}

/** A short, non-secret description of the identity, e.g. "alice@Default" or "app credential 1f3e…". */
export function describeIdentity(auth: AuthMethod): string {
  switch (auth.type) {
    case "password":
      return `${auth.username ?? auth.userId}${auth.userDomainName ? `@${auth.userDomainName}` : ""}`;
    case "application_credential":
      return `application credential ${auth.name ?? auth.id}`;
    case "oidc_access_token":
      return `federated user (${auth.identityProvider})`;
  }
}

/** The secret part of the credentials, whose last characters help recognise them. */
export function secretOf(auth: AuthMethod): string {
  return auth.type === "password" ? auth.password : auth.type === "application_credential" ? auth.secret : auth.accessToken;
}

/** Maps the usual OS_* variables (openrc file or environment) to credentials. */
export function credentialsFromEnv(env: Record<string, string | undefined>): CloudCredentials | undefined {
  if (!env.OS_AUTH_URL) return undefined;
  const appCred = env.OS_APPLICATION_CREDENTIAL_ID || env.OS_APPLICATION_CREDENTIAL_NAME || env.OS_AUTH_TYPE === "v3applicationcredential";
  const userDomain = env.OS_USER_DOMAIN_NAME ?? (env.OS_USER_DOMAIN_ID ? undefined : env.OS_DOMAIN_NAME ?? env.OS_PROJECT_DOMAIN_NAME);
  return normalizeCredentials({
    authUrl: env.OS_AUTH_URL,
    auth: appCred
      ? {
          type: "application_credential",
          id: env.OS_APPLICATION_CREDENTIAL_ID,
          name: env.OS_APPLICATION_CREDENTIAL_NAME,
          username: env.OS_USERNAME,
          userDomainName: userDomain,
          secret: env.OS_APPLICATION_CREDENTIAL_SECRET ?? "",
        }
      : {
          type: "password",
          username: env.OS_USERNAME,
          userId: env.OS_USER_ID,
          userDomainName: userDomain,
          userDomainId: env.OS_USER_DOMAIN_ID,
          password: env.OS_PASSWORD ?? "",
        },
    project: appCred
      ? undefined
      : {
          id: env.OS_PROJECT_ID ?? env.OS_TENANT_ID,
          name: env.OS_PROJECT_NAME ?? env.OS_TENANT_NAME,
          domainName: env.OS_PROJECT_DOMAIN_NAME ?? (env.OS_PROJECT_DOMAIN_ID ? undefined : env.OS_USER_DOMAIN_NAME),
          domainId: env.OS_PROJECT_DOMAIN_ID,
        },
    region: env.OS_REGION_NAME,
    interface: (env.OS_INTERFACE ?? env.OS_ENDPOINT_TYPE) as EndpointInterface | undefined,
  });
}

/** Parses the `export OS_…=…` lines of an openrc file. */
export function parseOpenrc(text: string): Record<string, string> {
  const vars: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^\s*(?:export\s+)?(OS_[A-Z_]+)=(.*)$/);
    if (!m) continue;
    let value = m[2].trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    // Interactive openrc files read the password from the terminal: leave it for the user to type.
    if (value.startsWith("$")) continue;
    vars[m[1]] = value;
  }
  return vars;
}

/**
 * Credentials from a clouds.yaml document (and optionally a secure.yaml merged into it). Returns every cloud it
 * defines, keyed by name; clouds that cannot be used are mapped to the reason.
 */
export function parseCloudsYaml(text: string, options: { allowMissingSecret?: boolean } = {}): Record<string, CloudCredentials | string> {
  let doc: any;
  try {
    doc = parse(text);
  } catch (err) {
    throw new CredentialsError(`Invalid YAML: ${(err as Error).message}`);
  }
  const clouds = doc?.clouds;
  if (!clouds || typeof clouds !== "object") throw new CredentialsError("No `clouds:` section found.");
  const out: Record<string, CloudCredentials | string> = {};
  for (const [name, cloud] of Object.entries<any>(clouds)) {
    const a = cloud?.auth ?? {};
    const type = String(cloud?.auth_type ?? (a.application_credential_secret ? "v3applicationcredential" : "password"));
    try {
      // The secret often lives in secure.yaml: the form can then ask for it.
      const placeholder = options.allowMissingSecret ? "\u0000" : "";
      const credentials = normalizeCredentials({
        authUrl: a.auth_url,
        auth: /applicationcredential/.test(type)
          ? {
              type: "application_credential",
              id: a.application_credential_id,
              name: a.application_credential_name,
              username: a.username,
              userDomainName: a.user_domain_name,
              secret: a.application_credential_secret ?? placeholder,
            }
          : {
              type: "password",
              username: a.username,
              userId: a.user_id,
              userDomainName: a.user_domain_name ?? (a.user_domain_id ? undefined : a.domain_name ?? a.project_domain_name),
              userDomainId: a.user_domain_id,
              password: a.password ?? placeholder,
            },
        project: /applicationcredential/.test(type)
          ? undefined
          : {
              id: a.project_id ?? a.tenant_id,
              name: a.project_name ?? a.tenant_name,
              domainName: a.project_domain_name ?? (a.project_domain_id ? undefined : a.user_domain_name),
              domainId: a.project_domain_id,
            },
        region: cloud?.region_name ?? (Array.isArray(cloud?.regions) ? (cloud.regions[0]?.name ?? cloud.regions[0]) : undefined),
        interface: cloud?.interface,
      });
      const auth = credentials.auth as Record<string, unknown>;
      for (const key of ["password", "secret"]) if (auth[key] === placeholder && placeholder) auth[key] = "";
      out[name] = credentials;
    } catch (err) {
      out[name] = (err as Error).message;
    }
  }
  return out;
}
