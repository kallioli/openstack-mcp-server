import { type FormEvent, useCallback, useEffect, useState } from "react";
import { api, type Category, type Connection, type OAuthIdentity, type OAuthMatchType, type OAuthOverview, type OAuthRule, type SettingsView } from "../api";
import { CategoryPicker, ConnectionPicker } from "../pickers";
import { type Translate, useI18n } from "../i18n";
import { Badge, EmptyState, ErrorBanner, Modal, useFormat } from "../ui";

/** Stands for the signed-in user's own OpenStack identity (Keystone federation) in the connection picker. */
const PERSONAL = "__personal__";

const MATCH_LABELS: Record<OAuthMatchType, string> = {
  user: "Identity provider user",
  email: "Email address",
  domain: "Email domain",
};

const MATCH_PLACEHOLDERS: Record<OAuthMatchType, string> = {
  user: "Subject (sub) at the identity provider",
  email: "jane.doe@example.com",
  domain: "example.com",
};

interface Draft {
  name: string;
  matchType: OAuthMatchType;
  matchValue: string;
}

interface FormState extends Draft {
  /** Selected connections, PERSONAL included when the user's own login is granted. */
  connectionIds: string[];
  defaultId: string;
  readOnly: boolean;
  categories: string[] | null;
  enabled: boolean;
}

function RuleForm({
  initial,
  draft,
  connections,
  categories,
  federation,
  onClose,
  onSaved,
}: {
  initial?: OAuthRule;
  draft?: Draft;
  /** Whether Keystone federation is configured, which the personal access requires. */
  federation: boolean;
  connections: Connection[];
  categories: Category[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const { t } = useI18n();
  const [form, setForm] = useState<FormState>(() => {
    if (initial) {
      return {
        name: initial.name,
        matchType: initial.matchType,
        matchValue: initial.matchValue,
        connectionIds: [...(initial.includePersonal ? [PERSONAL] : []), ...initial.connectionIds],
        defaultId: initial.defaultConnectionId ?? PERSONAL,
        readOnly: initial.readOnly,
        categories: initial.categories,
        enabled: initial.enabled,
      };
    }
    // Without federation there is no personal access to grant: start from the first shared connection.
    const first = federation ? PERSONAL : (connections[0]?.id ?? PERSONAL);
    return { name: "", matchType: "domain", matchValue: "", ...draft, connectionIds: [first], defaultId: first, readOnly: false, categories: null, enabled: true };
  });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const choices = [
    { id: PERSONAL, name: t("The user's own OpenStack identity"), readOnly: false, identity: t("Keystone federation") } as Connection,
    ...connections,
  ];

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!form.connectionIds.length) {
      setError("Grant at least one connection or the personal access.");
      return;
    }
    if (form.categories && !form.categories.length) {
      setError("Select at least one service, or “All exposed services”.");
      return;
    }
    setBusy(true);
    setError(null);
    const body = {
      name: form.name,
      matchType: form.matchType,
      matchValue: form.matchValue,
      includePersonal: form.connectionIds.includes(PERSONAL),
      connectionIds: form.connectionIds.filter((id) => id !== PERSONAL),
      defaultConnectionId: form.defaultId === PERSONAL ? null : form.defaultId,
      readOnly: form.readOnly,
      categories: form.categories,
      enabled: form.enabled,
    };
    try {
      if (initial) await api("PATCH", `/oauth/rules/${initial.id}`, body);
      else await api("POST", "/oauth/rules", body);
      onSaved();
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };

  return (
    <Modal
      title={initial ? t("Edit “{name}”", { name: initial.name }) : t("New OAuth access rule")}
      onClose={onClose}
      footer={
        <>
          <button className="button" type="button" onClick={onClose}>
            {t("Cancel")}
          </button>
          <button className="button button-primary" form="rule-form" disabled={busy}>
            {busy ? t("Saving…") : t("Save")}
          </button>
        </>
      }
    >
      <form id="rule-form" className="form" onSubmit={submit}>
        <ErrorBanner error={error} />
        <label className="field">
          <span>{t("Name")}</span>
          <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder={t("Support team")} required autoFocus />
        </label>
        <div className="form-row">
          <label className="field">
            <span>{t("Applies to")}</span>
            <select value={form.matchType} onChange={(e) => setForm({ ...form, matchType: e.target.value as OAuthMatchType })}>
              {(Object.keys(MATCH_LABELS) as OAuthMatchType[]).map((type) => (
                <option key={type} value={type}>
                  {t(MATCH_LABELS[type])}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>{t("Value")}</span>
            <input value={form.matchValue} onChange={(e) => setForm({ ...form, matchValue: e.target.value })} placeholder={t(MATCH_PLACEHOLDERS[form.matchType])} required />
          </label>
        </div>
        <p className="hint">
          {t("Email and domain rules only apply to addresses verified by the identity provider. Priority: user, then email, then domain.")}
        </p>
        <fieldset className="field">
          <legend>{t("Granted connections")}</legend>
          <ConnectionPicker
            connections={choices}
            value={form.connectionIds}
            defaultId={form.defaultId}
            onChange={(connectionIds, defaultId) => setForm({ ...form, connectionIds, defaultId })}
          />
          <small>{t("The personal access is the OpenStack identity of the person signing in, with their own projects and roles, through Keystone federation.")}</small>
        </fieldset>
        {form.connectionIds.includes(PERSONAL) && !federation && (
          <div className="banner banner-warn">
            {t("Keystone federation is not configured (Settings): the personal access granted by this rule will not work until it is.")}
          </div>
        )}
        <label className="checkbox">
          <input type="checkbox" checked={form.readOnly} onChange={(e) => setForm({ ...form, readOnly: e.target.checked })} />
          <span>
            {t("Read-only")}
            <small>{t("The write tool is not exposed to these users.")}</small>
          </span>
        </label>
        <fieldset className="field">
          <legend>{t("Allowed OpenStack services")}</legend>
          <CategoryPicker categories={categories} value={form.categories} onChange={(c) => setForm({ ...form, categories: c })} />
        </fieldset>
        <label className="checkbox">
          <input type="checkbox" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />
          <span>
            {t("Rule enabled")}
            <small>{t("Disabling a rule cuts off the access it grants from the next request on.")}</small>
          </span>
        </label>
      </form>
    </Modal>
  );
}

function draftFor(identity: OAuthIdentity, t: Translate): Draft {
  if (identity.email && identity.emailVerified) {
    return { name: identity.name ?? identity.email, matchType: "email", matchValue: identity.email };
  }
  return { name: identity.name ?? t("User {sub}", { sub: identity.sub }), matchType: "user", matchValue: identity.sub };
}

export function OAuthPage() {
  const { t } = useI18n();
  const { formatRelative } = useFormat();
  const [data, setData] = useState<OAuthOverview | null>(null);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [categories, setCategories] = useState<Category[]>([]);
  const [federation, setFederation] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<{ rule?: OAuthRule; draft?: Draft } | null>(null);

  const load = useCallback(() => {
    Promise.all([
      api<OAuthOverview>("GET", "/oauth"),
      api<Connection[]>("GET", "/connections"),
      api<Category[]>("GET", "/categories"),
      api<SettingsView>("GET", "/settings"),
    ]).then(
      ([o, c, cat, settings]) => {
        setData(o);
        setConnections(c);
        setCategories(cat);
        setFederation(settings.federationActive);
      },
      (e) => setError(e.message),
    );
  }, []);
  useEffect(load, [load]);

  const act = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
      load();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  if (!data) return <ErrorBanner error={error} />;

  return (
    <>
      <header className="page-header">
        <div>
          <h1>{t("OAuth access")}</h1>
          <p>
            {t("What people get when they sign in with your identity provider (claude.ai, Claude Desktop…): shared connections, their own OpenStack identity, read-only mode, services.")}
          </p>
        </div>
        <button className="button button-primary" onClick={() => setEditing({})}>
          {t("+ New rule")}
        </button>
      </header>
      <ErrorBanner error={error} />
      {!data.enabled && (
        <div className="banner banner-warn">
          {t("OpenID Connect sign-in is not enabled on this server (issuer, client ID, client secret and public URL, in Settings). Rules will apply as soon as it is.")}
        </div>
      )}

      <section className="card">
        <h2>{t("Users without a rule")}</h2>
        <div className="radio-group">
          <label className="checkbox">
            <input type="radio" name="policy" checked={data.defaultPolicy === "personal"} onChange={() => act(() => api("PUT", "/oauth/policy", { defaultPolicy: "personal" }))} />
            <span>
              {t("Their own OpenStack identity only")}
              <small>
                {federation
                  ? t("They act with their own OpenStack identity through Keystone federation, without any shared connection.")
                  : t("Requires Keystone federation, which is not configured: until it is, people without a rule are refused.")}
              </small>
            </span>
          </label>
          <label className="checkbox">
            <input type="radio" name="policy" checked={data.defaultPolicy === "deny"} onChange={() => act(() => api("PUT", "/oauth/policy", { defaultPolicy: "deny" }))} />
            <span>
              {t("Deny")}
              <small>{t("Only people covered by a rule can use the server.")}</small>
            </span>
          </label>
        </div>
      </section>

      <h2>{t("Rules")}</h2>
      {!data.rules.length ? (
        <EmptyState title={t("No rules")}>
          <p>{t("For example, grant your connections to your whole company domain.")}</p>
          <button className="button button-primary" onClick={() => setEditing({})}>
            {t("Create a rule")}
          </button>
        </EmptyState>
      ) : (
        <div className="card table-card">
          <table>
            <thead>
              <tr>
                <th>{t("Rule")}</th>
                <th>{t("Connections")}</th>
                <th>{t("Permissions")}</th>
                <th>{t("Last used")}</th>
                <th aria-label={t("Actions")} />
              </tr>
            </thead>
            <tbody>
              {data.rules.map((r) => (
                <tr key={r.id} className={r.enabled ? "" : "row-muted"}>
                  <td>
                    <div className="inline">
                      <strong>{r.name}</strong>
                      {!r.enabled && <Badge tone="warn">{t("Disabled")}</Badge>}
                    </div>
                    <div className="muted">
                      {t(MATCH_LABELS[r.matchType])}: <code>{r.matchType === "domain" ? `@${r.matchValue}` : r.matchValue}</code>
                    </div>
                  </td>
                  <td>
                    {r.includePersonal && (
                      <div className={r.defaultConnectionId === null ? "" : "muted"}>
                        {t("Personal access")}
                        {r.defaultConnectionId === null && " ★"} {!federation && <Badge tone="warn">{t("needs federation")}</Badge>}
                      </div>
                    )}
                    {r.connections.map((c) => (
                      <div key={c.id} className={c.id === r.defaultConnectionId ? "" : "muted"}>
                        {c.name ?? "-"}
                        {c.id === r.defaultConnectionId && " ★"}
                      </div>
                    ))}
                  </td>
                  <td>
                    {r.readOnly ? <Badge tone="info">{t("Read-only")}</Badge> : <Badge>{t("Read/write")}</Badge>}
                    <div className="chips-inline">
                      {r.categories === null ? (
                        <span className="muted">{t("All services")}</span>
                      ) : (
                        r.categories.map((c) => (
                          <span key={c} className="chip chip-small">
                            {c}
                          </span>
                        ))
                      )}
                    </div>
                  </td>
                  <td className="muted">{formatRelative(r.lastUsedAt)}</td>
                  <td className="actions">
                    <button className="button button-small" onClick={() => act(() => api("PATCH", `/oauth/rules/${r.id}`, { enabled: !r.enabled }))}>
                      {r.enabled ? t("Disable") : t("Enable")}
                    </button>
                    <button className="button button-small" onClick={() => setEditing({ rule: r })}>
                      {t("Edit")}
                    </button>
                    <button className="button button-small button-danger" onClick={() => window.confirm(t("Delete the rule “{name}”?", { name: r.name })) && act(() => api("DELETE", `/oauth/rules/${r.id}`))}>
                      {t("Delete")}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h2>{t("Recent OAuth sign-ins")}</h2>
      {!data.identities.length ? (
        <p className="muted">{t("Nobody has signed in yet.")}</p>
      ) : (
        <div className="card table-card">
          <table>
            <thead>
              <tr>
                <th>{t("User")}</th>
                <th>{t("Applied access")}</th>
                <th>{t("Seen")}</th>
                <th aria-label={t("Actions")} />
              </tr>
            </thead>
            <tbody>
              {data.identities.map((i) => (
                <tr key={i.sub}>
                  <td>
                    <strong>{i.name ?? i.email ?? i.sub}</strong>
                    <div className="muted inline">
                      {i.email && <span>{i.email}</span>}
                      {i.email && (i.emailVerified ? <Badge tone="ok">{t("verified")}</Badge> : <Badge tone="warn">{t("unverified")}</Badge>)}
                      <code>{i.sub}</code>
                    </div>
                  </td>
                  <td>
                    {i.ruleName ? (
                      <Badge tone="ok">{i.ruleName}</Badge>
                    ) : data.defaultPolicy === "deny" || !federation ? (
                      <Badge tone="error">{t("Denied (no rule)")}</Badge>
                    ) : (
                      <span className="muted">{t("Personal access (no rule)")}</span>
                    )}
                  </td>
                  <td className="muted">{formatRelative(i.lastSeenAt)}</td>
                  <td className="actions">
                    {!i.ruleId && (
                      <button className="button button-small" onClick={() => setEditing({ draft: draftFor(i, t) })}>
                        {t("Create a rule")}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {editing && (
        <RuleForm
          initial={editing.rule}
          draft={editing.draft}
          connections={connections}
          categories={categories}
          federation={federation}
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
