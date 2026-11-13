import { type FormEvent, useCallback, useEffect, useState } from "react";
import { api, type AuthType, type CloudCredentials, type Connection, type EndpointInterface, type ParsedClouds, type Project } from "../api";
import { useI18n } from "../i18n";
import { Badge, EmptyState, ErrorBanner, Modal, StatusDot, useFormat } from "../ui";

/** Credential fields as edited in the form; ids kept from an import or the stored connection are preserved. */
export interface CredentialsDraft {
  authUrl: string;
  authType: AuthType;
  username: string;
  userId: string;
  userDomainName: string;
  userDomainId: string;
  /** Password or application credential secret; empty keeps the stored one on edit. */
  secret: string;
  appCredId: string;
  appCredName: string;
  projectName: string;
  projectId: string;
  projectDomainName: string;
  projectDomainId: string;
  region: string;
  interface: EndpointInterface;
}

export function draftFromCredentials(c?: CloudCredentials): CredentialsDraft {
  const auth = c?.auth;
  const password = auth?.type === "password" ? auth : undefined;
  const appCred = auth?.type === "application_credential" ? auth : undefined;
  return {
    authUrl: c?.authUrl ?? "",
    authType: auth?.type ?? "password",
    username: auth?.username ?? "",
    userId: password?.userId ?? "",
    userDomainName: auth?.userDomainName ?? "",
    userDomainId: password?.userDomainId ?? "",
    secret: (password ? password.password : appCred?.secret) ?? "",
    appCredId: appCred?.id ?? "",
    appCredName: appCred?.name ?? "",
    projectName: c?.project?.name ?? "",
    projectId: c?.project?.id ?? "",
    projectDomainName: c?.project?.domainName ?? "",
    projectDomainId: c?.project?.domainId ?? "",
    region: c?.region ?? "",
    interface: c?.interface ?? "public",
  };
}

const opt = (value: string) => value.trim() || undefined;

/** The credentials sent to the API (an empty secret keeps the stored one on update). */
export function credentialsFromDraft(d: CredentialsDraft): CloudCredentials {
  const auth: CloudCredentials["auth"] =
    d.authType === "password"
      ? {
          type: "password",
          username: opt(d.username),
          userId: opt(d.userId),
          userDomainName: opt(d.userDomainName),
          userDomainId: opt(d.userDomainId),
          password: d.secret,
        }
      : {
          type: "application_credential",
          id: opt(d.appCredId),
          name: opt(d.appCredName),
          username: opt(d.username),
          userDomainName: opt(d.userDomainName),
          secret: d.secret,
        };
  // Application credentials are bound to their project: the API refuses a project with them.
  const project =
    d.authType === "password" && (opt(d.projectName) || opt(d.projectId))
      ? { id: opt(d.projectId), name: opt(d.projectName), domainName: opt(d.projectDomainName), domainId: opt(d.projectDomainId) }
      : undefined;
  return { authUrl: d.authUrl.trim(), auth, ...(project ? { project } : {}), region: opt(d.region), interface: d.interface };
}

/** Keystone credentials: auth URL, authentication method, project scope, region and interface. */
export function CredentialsFields({
  draft,
  onChange,
  stored,
}: {
  draft: CredentialsDraft;
  onChange: (draft: CredentialsDraft) => void;
  /** The connection being edited: its secret is kept when the field stays empty. */
  stored?: Connection;
}) {
  const { t } = useI18n();
  const set = (patch: Partial<CredentialsDraft>) => onChange({ ...draft, ...patch });
  const keepSecret = stored && stored.authType === draft.authType;
  const password = draft.authType === "password";
  return (
    <>
      <label className="field">
        <span>{t("Keystone auth URL")}</span>
        <input value={draft.authUrl} onChange={(e) => set({ authUrl: e.target.value })} placeholder="https://keystone.example.com:5000/v3" required />
        <small>{t("The identity endpoint (OS_AUTH_URL), with or without /v3.")}</small>
      </label>
      <label className="field">
        <span>{t("Authentication")}</span>
        <select value={draft.authType} onChange={(e) => set({ authType: e.target.value as AuthType, secret: "" })}>
          <option value="password">{t("User name and password")}</option>
          <option value="application_credential">{t("Application credential")}</option>
        </select>
        <small>
          {password
            ? t("A dedicated service user is recommended over a personal account.")
            : t("Recommended: created with “openstack application credential create”, revocable and limited to one project and its roles.")}
        </small>
      </label>

      {password ? (
        <>
          <div className="form-row">
            {draft.userId && !draft.username ? (
              <label className="field">
                <span>{t("User ID")}</span>
                <input value={draft.userId} onChange={(e) => set({ userId: e.target.value })} autoComplete="off" required />
              </label>
            ) : (
              <label className="field">
                <span>{t("User name")}</span>
                <input value={draft.username} onChange={(e) => set({ username: e.target.value })} autoComplete="off" required />
              </label>
            )}
            <label className="field">
              <span>{t("User domain")}</span>
              <input
                value={draft.userDomainName}
                onChange={(e) => set({ userDomainName: e.target.value })}
                placeholder={draft.userDomainId ? t("ID {id}", { id: draft.userDomainId }) : "Default"}
                required={!draft.userId && !draft.userDomainId}
              />
            </label>
          </div>
          <label className="field">
            <span>{t("Password")}</span>
            <input
              type="password"
              autoComplete="new-password"
              value={draft.secret}
              onChange={(e) => set({ secret: e.target.value })}
              placeholder={keepSecret ? t("Leave empty to keep the stored one (…{hint})", { hint: stored.secretHint }) : ""}
              required={!keepSecret}
            />
            <small>{t("Encrypted at rest, never shown again.")}</small>
          </label>
          <div className="form-row">
            <label className="field">
              <span>{t("Project name")}</span>
              <input value={draft.projectName} onChange={(e) => set({ projectName: e.target.value })} placeholder={t("Optional")} />
            </label>
            <label className="field">
              <span>{t("Project domain")}</span>
              <input
                value={draft.projectDomainName}
                onChange={(e) => set({ projectDomainName: e.target.value })}
                placeholder={draft.projectDomainId ? t("ID {id}", { id: draft.projectDomainId }) : "Default"}
                required={Boolean(draft.projectName.trim()) && !draft.projectId.trim() && !draft.projectDomainId}
              />
            </label>
            <label className="field">
              <span>{t("or project ID")}</span>
              <input value={draft.projectId} onChange={(e) => set({ projectId: e.target.value })} placeholder={t("Optional")} />
            </label>
          </div>
          <p className="hint">{t("Without a project, the login is unscoped: pick a default project afterwards among those the user can access.")}</p>
        </>
      ) : (
        <>
          <div className="form-row">
            {draft.appCredName && !draft.appCredId ? (
              <>
                <label className="field">
                  <span>{t("Application credential name")}</span>
                  <input value={draft.appCredName} onChange={(e) => set({ appCredName: e.target.value })} autoComplete="off" required />
                </label>
                <label className="field">
                  <span>{t("Owner's user name")}</span>
                  <input value={draft.username} onChange={(e) => set({ username: e.target.value })} autoComplete="off" required />
                </label>
              </>
            ) : (
              <label className="field">
                <span>{t("Application credential ID")}</span>
                <input value={draft.appCredId} onChange={(e) => set({ appCredId: e.target.value })} autoComplete="off" required />
              </label>
            )}
            <label className="field">
              <span>{t("Secret")}</span>
              <input
                type="password"
                autoComplete="new-password"
                value={draft.secret}
                onChange={(e) => set({ secret: e.target.value })}
                placeholder={keepSecret ? t("Leave empty to keep the stored one (…{hint})", { hint: stored.secretHint }) : ""}
                required={!keepSecret}
              />
            </label>
          </div>
          <p className="hint">{t("Application credentials are bound to the project they were created in: there is no project to set.")}</p>
        </>
      )}

      <div className="form-row">
        <label className="field">
          <span>{t("Region")}</span>
          <input value={draft.region} onChange={(e) => set({ region: e.target.value })} placeholder={t("Optional, e.g. RegionOne")} />
          <small>{t("Used when a call names none; the first region of the catalog otherwise.")}</small>
        </label>
        <label className="field">
          <span>{t("Endpoint interface")}</span>
          <select value={draft.interface} onChange={(e) => set({ interface: e.target.value as EndpointInterface })}>
            <option value="public">public</option>
            <option value="internal">internal</option>
            <option value="admin">admin</option>
          </select>
          <small>{t("Which catalog endpoints the server calls; public unless it runs inside the cloud's network.")}</small>
        </label>
      </div>
    </>
  );
}

/** Prefills the credentials from a pasted clouds.yaml or openrc file; nothing is stored by the parsing. */
export function ImportCredentials({ onImport }: { onImport: (name: string, credentials: CloudCredentials) => void }) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const [result, setResult] = useState<ParsedClouds | null>(null);
  const [imported, setImported] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const pick = (name: string, credentials: CloudCredentials) => {
    onImport(name, credentials);
    setImported(name);
  };

  const parse = async () => {
    setBusy(true);
    setError(null);
    setImported(null);
    try {
      const parsed = await api<ParsedClouds>("POST", "/connections/parse", { text });
      setResult(parsed);
      const usable = parsed.clouds.filter((c) => "credentials" in c);
      if (parsed.clouds.length === 1 && usable.length === 1 && "credentials" in usable[0]) pick(usable[0].name, usable[0].credentials);
    } catch (err) {
      setError((err as Error).message);
      setResult(null);
    } finally {
      setBusy(false);
    }
  };

  if (!open) {
    return (
      <div>
        <button type="button" className="button button-small" onClick={() => setOpen(true)}>
          {t("Import a clouds.yaml or openrc file…")}
        </button>
      </div>
    );
  }
  return (
    <div className="import-panel">
      <label className="field">
        <span>{t("Import clouds.yaml / openrc")}</span>
        <textarea
          rows={6}
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder={"clouds:\n  mycloud:\n    auth:\n      auth_url: https://…\n\nexport OS_AUTH_URL=https://…"}
          spellCheck={false}
        />
        <small>{t("Paste the file content: it fills the form below, nothing is saved before you confirm.")}</small>
      </label>
      <ErrorBanner error={error} />
      <div className="inline">
        <button type="button" className="button button-small button-primary" onClick={parse} disabled={busy || !text.trim()}>
          {busy ? t("Reading…") : t("Read")}
        </button>
        <button type="button" className="button button-small button-ghost" onClick={() => setOpen(false)}>
          {t("Close")}
        </button>
      </div>
      {result && (
        <>
          <p className="hint">{t("{format} file: pick the cloud to use.", { format: result.format })}</p>
          <ul className="status-list">
            {result.clouds.map((c) => (
              <li key={c.name}>
                <StatusDot ok={"credentials" in c} />
                <strong>{c.name}</strong>
                {"credentials" in c ? (
                  <>
                    <span className="muted">{c.credentials.authUrl}</span>
                    <button type="button" className="button button-small" onClick={() => pick(c.name, c.credentials)}>
                      {imported === c.name ? t("Imported ✓") : t("Use")}
                    </button>
                  </>
                ) : (
                  <span className="muted">{t(c.error)}</span>
                )}
              </li>
            ))}
          </ul>
          {imported && <p className="hint">{t("Type the password or secret if the file did not contain it.")}</p>}
        </>
      )}
    </div>
  );
}

/** Picks the project used when a call names none; options come live from Keystone. */
export function ProjectSelect({ connectionId, value, onChange }: { connectionId: string; value: string | null; onChange: (v: string | null) => void }) {
  const { t } = useI18n();
  const [projects, setProjects] = useState<Project[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api<Project[]>("GET", `/connections/${connectionId}/projects`).then(setProjects, (e) => setError(e.message));
  }, [connectionId]);

  const known = projects?.some((p) => p.id === value);
  return (
    <label className="field">
      <span>{t("Default project")}</span>
      <select value={value ?? ""} onChange={(e) => onChange(e.target.value || null)} disabled={!projects && !error}>
        <option value="">{t("None (the credentials' own scope)")}</option>
        {projects?.map((p) => (
          <option key={p.id} value={p.id}>
            {p.name} ({p.id}){p.enabled === false ? ` ${t("(disabled)")}` : ""}
          </option>
        ))}
        {value !== null && !known && <option value={value}>{t("Project {id}", { id: value })}</option>}
      </select>
      <small>
        {error
          ? t("List unavailable: {error}", { error: t(error) })
          : !projects
            ? t("Loading projects…")
            : t("Used by calls that do not name a project; the AI can still choose another one per call.")}
      </small>
    </label>
  );
}

/** Everything the connection form edits. */
export interface ConnectionDraft {
  name: string;
  description: string;
  readOnly: boolean;
  defaultProjectId: string | null;
  credentials: CredentialsDraft;
}

export function connectionDraft(initial?: Connection): ConnectionDraft {
  return {
    name: initial?.name ?? "",
    description: initial?.description ?? "",
    readOnly: initial?.readOnly ?? false,
    defaultProjectId: initial?.defaultProjectId ?? null,
    credentials: draftFromCredentials(initial?.credentials),
  };
}

/**
 * Body of POST /connections, or of PATCH /connections/:id with the credentials only when they changed (sending them
 * resets the last check). `credentialsChanged` tells the caller to test the connection again.
 */
export function connectionBody(form: ConnectionDraft, initial?: Connection): { body: Record<string, unknown>; credentialsChanged: boolean } {
  const credentials = credentialsFromDraft(form.credentials);
  const base = { name: form.name, description: form.description, readOnly: form.readOnly };
  if (!initial) return { body: { ...base, credentials }, credentialsChanged: true };
  const before = credentialsFromDraft(draftFromCredentials(initial.credentials));
  const changed = JSON.stringify(credentials) !== JSON.stringify(before);
  // Changing the credentials resets the default project on the server, unless it is sent again: keep it on the same cloud.
  const keepProject = !changed || credentials.authUrl.replace(/\/+$/, "") === initial.authUrl;
  return {
    body: { ...base, ...(changed ? { credentials } : {}), ...(keepProject ? { defaultProjectId: form.defaultProjectId } : {}) },
    credentialsChanged: changed,
  };
}

/** Name, description, import, credentials and read-only switch, shared by the connections page and the onboarding. */
export function ConnectionFields({ form, onChange, initial }: { form: ConnectionDraft; onChange: (form: ConnectionDraft) => void; initial?: Connection }) {
  const { t } = useI18n();
  return (
    <>
      <div className="form-row">
        <label className="field">
          <span>{t("Name")}</span>
          <input value={form.name} onChange={(e) => onChange({ ...form, name: e.target.value })} placeholder={t("Production, Customer A…")} required autoFocus />
        </label>
        <label className="field">
          <span>{t("Description")}</span>
          <input value={form.description} onChange={(e) => onChange({ ...form, description: e.target.value })} placeholder={t("Optional")} />
        </label>
      </div>
      <ImportCredentials
        onImport={(name, credentials) => onChange({ ...form, name: form.name || name, credentials: draftFromCredentials(credentials) })}
      />
      <CredentialsFields draft={form.credentials} onChange={(credentials) => onChange({ ...form, credentials })} stored={initial} />
      <label className="checkbox">
        <input type="checkbox" checked={form.readOnly} onChange={(e) => onChange({ ...form, readOnly: e.target.checked })} />
        <span>
          {t("Read-only")}
          <small>{t("All MCP tokens of this connection will only be able to make GET requests.")}</small>
        </span>
      </label>
    </>
  );
}

function ConnectionForm({ initial, onClose, onSaved }: { initial?: Connection; onClose: () => void; onSaved: () => void }) {
  const { t } = useI18n();
  const [form, setForm] = useState<ConnectionDraft>(() => connectionDraft(initial));
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { body, credentialsChanged } = connectionBody(form, initial);
      const saved = initial
        ? await api<Connection>("PATCH", `/connections/${initial.id}`, body)
        : await api<Connection>("POST", "/connections", body);
      if (credentialsChanged) await api("POST", `/connections/${saved.id}/test`);
      onSaved();
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };

  return (
    <Modal
      title={initial ? t("Edit “{name}”", { name: initial.name }) : t("New OpenStack connection")}
      onClose={onClose}
      footer={
        <>
          <button className="button" type="button" onClick={onClose}>
            {t("Cancel")}
          </button>
          <button className="button button-primary" form="connection-form" disabled={busy}>
            {busy ? t("Saving…") : initial ? t("Save") : t("Create and test")}
          </button>
        </>
      }
    >
      <form id="connection-form" className="form" onSubmit={submit}>
        <ErrorBanner error={error} />
        <ConnectionFields form={form} onChange={setForm} initial={initial} />
        {initial ? (
          <ProjectSelect connectionId={initial.id} value={form.defaultProjectId} onChange={(defaultProjectId) => setForm({ ...form, defaultProjectId })} />
        ) : (
          <p className="hint">{t("The default project can be chosen after creation, by editing the connection.")}</p>
        )}
      </form>
    </Modal>
  );
}

export function ConnectionsPage() {
  const { t } = useI18n();
  const { formatRelative } = useFormat();
  const [connections, setConnections] = useState<Connection[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<Connection | "new" | null>(null);
  const [testing, setTesting] = useState<string | null>(null);

  const load = useCallback(() => {
    api<Connection[]>("GET", "/connections").then(setConnections, (e) => setError(e.message));
  }, []);
  useEffect(load, [load]);

  const test = async (c: Connection) => {
    setTesting(c.id);
    try {
      await api("POST", `/connections/${c.id}/test`);
      load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setTesting(null);
    }
  };

  const remove = async (c: Connection) => {
    if (!window.confirm(t("Delete the connection “{name}”?", { name: c.name }))) return;
    try {
      await api("DELETE", `/connections/${c.id}`);
      load();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <>
      <header className="page-header">
        <div>
          <h1>{t("OpenStack connections")}</h1>
          <p>{t("OpenStack credentials the server uses on behalf of MCP tokens and OAuth access rules.")}</p>
        </div>
        <button className="button button-primary" onClick={() => setEditing("new")}>
          {t("+ New connection")}
        </button>
      </header>
      <ErrorBanner error={error} />

      {connections && !connections.length && (
        <EmptyState title={t("No connections")}>
          <p>{t("Add OpenStack credentials (one cloud, one identity) to be able to issue MCP tokens.")}</p>
          <button className="button button-primary" onClick={() => setEditing("new")}>
            {t("Add a connection")}
          </button>
        </EmptyState>
      )}

      {connections && connections.length > 0 && (
        <div className="card table-card">
          <table>
            <thead>
              <tr>
                <th>{t("Connection")}</th>
                <th>{t("Identity")}</th>
                <th>{t("Access")}</th>
                <th>{t("Default project")}</th>
                <th>{t("Last test")}</th>
                <th>{t("MCP tokens")}</th>
                <th aria-label={t("Actions")} />
              </tr>
            </thead>
            <tbody>
              {connections.map((c) => (
                <tr key={c.id}>
                  <td>
                    <strong>{c.name}</strong>
                    {c.description && <div className="muted">{c.description}</div>}
                    <div className="muted">
                      <code>{c.authUrl}</code>
                    </div>
                    {c.credentials.region && <div className="muted">{t("Region {region}", { region: c.credentials.region })}</div>}
                  </td>
                  <td>
                    <div>{c.identity}</div>
                    <code className="muted">…{c.secretHint}</code>
                  </td>
                  <td>{c.readOnly ? <Badge tone="info">{t("Read-only")}</Badge> : <Badge>{t("Read/write")}</Badge>}</td>
                  <td>
                    {c.defaultProjectId ? (
                      <code>{c.defaultProjectId}</code>
                    ) : c.credentials.project ? (
                      <span>{c.credentials.project.name ?? c.credentials.project.id}</span>
                    ) : (
                      <span className="muted">-</span>
                    )}
                  </td>
                  <td>
                    <div className="inline">
                      <StatusDot ok={c.lastCheck?.ok} />
                      <span>{c.lastCheck ? c.lastCheck.detail : t("Never tested")}</span>
                    </div>
                    {c.lastCheck && <div className="muted">{formatRelative(c.lastCheck.at)}</div>}
                  </td>
                  <td>{c.tokenCount}</td>
                  <td className="actions">
                    <button className="button button-small" onClick={() => test(c)} disabled={testing === c.id}>
                      {testing === c.id ? t("Testing…") : t("Test")}
                    </button>
                    <button className="button button-small" onClick={() => setEditing(c)}>
                      {t("Edit")}
                    </button>
                    <button className="button button-small button-danger" onClick={() => remove(c)} disabled={c.tokenCount > 0} title={c.tokenCount ? t("Delete its MCP tokens first") : undefined}>
                      {t("Delete")}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {editing && (
        <ConnectionForm
          initial={editing === "new" ? undefined : editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            load();
          }}
        />
      )}
    </>
  );
}
