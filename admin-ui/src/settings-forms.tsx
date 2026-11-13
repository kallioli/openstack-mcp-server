import { type ReactNode, useState } from "react";
import type { SettingKey, SettingsPatch, SettingsView } from "./api";
import { useI18n } from "./i18n";
import { CodeBlock } from "./ui";

/** Form state shared by the onboarding and the settings page; only changed fields are sent. */
export interface SettingsDraft {
  publicUrl: string;
  trustProxy: string;
  readOnly: boolean;
  maxResponseChars: string;
  oauthEnabled: boolean;
  oauthIssuer: string;
  oauthClientId: string;
  /** Empty keeps the stored secret. */
  oauthClientSecret: string;
  oauthScopes: string;
  federationEnabled: boolean;
  federationAuthUrl: string;
  federationIdentityProvider: string;
  federationProtocol: string;
  federationRegion: string;
}

export function draftFrom(view: SettingsView): SettingsDraft {
  const v = view.values;
  return {
    publicUrl: v.publicUrl ?? "",
    trustProxy: v.trustProxy ?? "",
    readOnly: v.readOnly,
    maxResponseChars: String(v.maxResponseChars),
    oauthEnabled: Boolean(v.oauthIssuer || v.oauthClientId),
    oauthIssuer: v.oauthIssuer ?? "",
    oauthClientId: v.oauthClientId ?? "",
    oauthClientSecret: "",
    oauthScopes: v.oauthScopes.join(" "),
    federationEnabled: Boolean(v.federationAuthUrl || v.federationIdentityProvider),
    federationAuthUrl: v.federationAuthUrl ?? "",
    federationIdentityProvider: v.federationIdentityProvider ?? "",
    federationProtocol: v.federationProtocol,
    federationRegion: v.federationRegion ?? "",
  };
}

/** The changes between a draft and the stored settings, leaving out settings fixed by the environment. */
export function patchFrom(draft: SettingsDraft, view: SettingsView, sections: ("access" | "security" | "oauth")[]): SettingsPatch {
  const v = view.values;
  const free = (key: SettingKey) => !view.locked[key];
  const patch: SettingsPatch = {};
  /** Sets a text setting when it changed; empty means unset (null). */
  const text = <K extends "publicUrl" | "trustProxy" | "oauthIssuer" | "oauthClientId" | "federationAuthUrl" | "federationIdentityProvider" | "federationRegion">(
    key: K,
    value: string,
  ) => {
    if (free(key) && value.trim() !== (v[key] ?? "")) patch[key] = value.trim() || null;
  };
  if (sections.includes("access")) {
    text("publicUrl", draft.publicUrl);
    text("trustProxy", draft.trustProxy);
  }
  if (sections.includes("security")) {
    if (free("readOnly") && draft.readOnly !== v.readOnly) patch.readOnly = draft.readOnly;
    if (free("maxResponseChars") && Number(draft.maxResponseChars) !== v.maxResponseChars) patch.maxResponseChars = Number(draft.maxResponseChars);
  }
  if (sections.includes("oauth")) {
    const oauth = draft.oauthEnabled;
    text("oauthIssuer", oauth ? draft.oauthIssuer : "");
    text("oauthClientId", oauth ? draft.oauthClientId : "");
    if (free("oauthClientSecret") && oauth && draft.oauthClientSecret.trim()) patch.oauthClientSecret = draft.oauthClientSecret.trim();
    const scopes = draft.oauthScopes.split(/[\s,]+/).filter(Boolean);
    if (free("oauthScopes") && oauth && scopes.join(" ") !== v.oauthScopes.join(" ")) {
      // Back to the defaults: clear the stored list.
      patch.oauthScopes = scopes.join(" ") === view.defaults.oauthScopes.join(" ") ? null : scopes;
    }
    const federation = oauth && draft.federationEnabled;
    text("federationAuthUrl", federation ? draft.federationAuthUrl : "");
    text("federationIdentityProvider", federation ? draft.federationIdentityProvider : "");
    text("federationRegion", federation ? draft.federationRegion : "");
    const protocol = (federation ? draft.federationProtocol.trim() : "") || view.defaults.federationProtocol;
    if (free("federationProtocol") && protocol !== v.federationProtocol) {
      patch.federationProtocol = protocol === view.defaults.federationProtocol ? null : protocol;
    }
  }
  return patch;
}

function Locked({ variable }: { variable?: string }) {
  const { t } = useI18n();
  if (!variable) return null;
  return <small className="locked">🔒 {t("Set by the environment variable {variable}", { variable })}</small>;
}

function Field({ label, hint, locked, children }: { label: string; hint?: ReactNode; locked?: string; children: ReactNode }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
      {locked ? <Locked variable={locked} /> : hint && <small>{hint}</small>}
    </label>
  );
}

interface SectionProps {
  view: SettingsView;
  draft: SettingsDraft;
  onChange: (draft: SettingsDraft) => void;
}

export function AccessFields({ view, draft, onChange }: SectionProps) {
  const { t } = useI18n();
  return (
    <div className="form-row">
      <Field
        label={t("Public URL of the MCP server")}
        locked={view.locked.publicUrl}
        hint={t("HTTPS origin through which clients reach the server, e.g. https://mcp.example.com. Required for OAuth and claude.ai; optional for local use.")}
      >
        <input value={draft.publicUrl} disabled={Boolean(view.locked.publicUrl)} onChange={(e) => onChange({ ...draft, publicUrl: e.target.value })} placeholder="https://mcp.example.com" />
      </Field>
      <TrustProxyField view={view} value={draft.trustProxy} onChange={(trustProxy) => onChange({ ...draft, trustProxy })} />
    </div>
  );
}

/** Common setups as presets; anything else (named ranges, CIDRs) goes through "Custom". */
const PROXY_PRESETS = [
  { value: "", label: "No reverse proxy" },
  { value: "1", label: "1 reverse proxy (Caddy, nginx, Traefik…)" },
  { value: "2", label: "2 proxies (e.g. CDN + reverse proxy)" },
];
const CUSTOM = "custom";

function TrustProxyField({ view, value, onChange }: { view: SettingsView; value: string; onChange: (value: string) => void }) {
  const { t } = useI18n();
  const [custom, setCustom] = useState(() => !PROXY_PRESETS.some((p) => p.value === value));
  const locked = Boolean(view.locked.trustProxy);
  return (
    <Field
      label={t("Trusted reverse proxy")}
      locked={view.locked.trustProxy}
      hint={
        custom
          ? t("Express “trust proxy” value: a hop count, loopback / uniquelocal, or IPs and CIDR ranges separated by commas.")
          : t("Lets the server see the real client IP behind the proxy (used by token IP restrictions).")
      }
    >
      <select
        value={custom ? CUSTOM : value}
        disabled={locked}
        onChange={(e) => {
          const next = e.target.value;
          setCustom(next === CUSTOM);
          if (next !== CUSTOM) onChange(next);
        }}
      >
        {PROXY_PRESETS.map((p) => (
          <option key={p.value} value={p.value}>
            {t(p.label)}
          </option>
        ))}
        <option value={CUSTOM}>{t("Custom…")}</option>
      </select>
      {custom && (
        <input value={value} disabled={locked} onChange={(e) => onChange(e.target.value)} placeholder="loopback, 10.0.0.0/8" autoFocus={!value} />
      )}
    </Field>
  );
}

export function SecurityFields({ view, draft, onChange }: SectionProps) {
  const { t } = useI18n();
  return (
    <div className="form">
      <label className="checkbox">
        <input type="checkbox" checked={draft.readOnly} disabled={Boolean(view.locked.readOnly)} onChange={(e) => onChange({ ...draft, readOnly: e.target.checked })} />
        <span>
          {t("Read-only for the whole server")}
          <small>{t("No client can modify any OpenStack resource, whatever its permissions. Recommended to start with.")}</small>
          <Locked variable={view.locked.readOnly} />
        </span>
      </label>
      <Field
        label={t("Maximum response size (characters)")}
        locked={view.locked.maxResponseChars}
        hint={t("Longer responses are truncated to preserve the AI's context.")}
      >
        <input
          type="number"
          min={1000}
          max={1000000}
          step={1000}
          value={draft.maxResponseChars}
          disabled={Boolean(view.locked.maxResponseChars)}
          onChange={(e) => onChange({ ...draft, maxResponseChars: e.target.value })}
        />
      </Field>
    </div>
  );
}

export function OAuthFields({ view, draft, onChange }: SectionProps) {
  const { t } = useI18n();
  const lockedOAuth = view.locked.oauthIssuer ?? view.locked.oauthClientId;
  const lockedFederation = view.locked.federationAuthUrl ?? view.locked.federationIdentityProvider;
  const callback = draft.publicUrl.trim() ? `${draft.publicUrl.trim().replace(/\/+$/, "")}/oauth/callback` : view.callbackUrl;
  const set = (patch: Partial<SettingsDraft>) => onChange({ ...draft, ...patch });
  return (
    <div className="form">
      <label className="checkbox">
        <input type="checkbox" checked={draft.oauthEnabled} disabled={Boolean(lockedOAuth)} onChange={(e) => set({ oauthEnabled: e.target.checked })} />
        <span>
          {t("Enable sign-in with an OpenID Connect identity provider")}
          <small>{t("For claude.ai, Claude Desktop and clients that discover authentication on their own: users sign in with your identity provider, with no token to copy.")}</small>
          <Locked variable={lockedOAuth} />
        </span>
      </label>
      {draft.oauthEnabled && (
        <>
          <div className="steps-hint">
            <p>{t("1. In your identity provider (Keycloak, Microsoft Entra ID, Okta, Google…), create a confidential OpenID Connect client with this redirect URI:")}</p>
            {callback ? <CodeBlock code={callback} /> : <p className="banner banner-warn">{t("Enter the server's public URL first.")}</p>}
            <p>{t("2. Paste the issuer URL, the client ID and the client secret here.")}</p>
          </div>
          <Field
            label={t("Issuer URL")}
            locked={view.locked.oauthIssuer}
            hint={t("The provider's issuer, whose /.well-known/openid-configuration is read, e.g. https://sso.example.com/realms/main.")}
          >
            <input
              value={draft.oauthIssuer}
              disabled={Boolean(view.locked.oauthIssuer)}
              onChange={(e) => set({ oauthIssuer: e.target.value })}
              placeholder="https://sso.example.com/realms/main"
              autoComplete="off"
            />
          </Field>
          <div className="form-row">
            <Field label={t("Client ID")} locked={view.locked.oauthClientId}>
              <input value={draft.oauthClientId} disabled={Boolean(view.locked.oauthClientId)} onChange={(e) => set({ oauthClientId: e.target.value })} autoComplete="off" />
            </Field>
            <Field
              label={t("Client secret")}
              locked={view.locked.oauthClientSecret}
              hint={view.oauthClientSecretSet ? t("Saved and encrypted. Leave empty to keep it.") : t("Encrypted in the database, never shown again.")}
            >
              <input
                type="password"
                value={draft.oauthClientSecret}
                disabled={Boolean(view.locked.oauthClientSecret)}
                onChange={(e) => set({ oauthClientSecret: e.target.value })}
                placeholder={view.oauthClientSecretSet ? "••••••••" : ""}
                autoComplete="off"
              />
            </Field>
          </div>
          <Field
            label={t("Scopes")}
            locked={view.locked.oauthScopes}
            hint={t("Space-separated. openid and email are required for OAuth access rules.")}
          >
            <textarea rows={2} value={draft.oauthScopes} disabled={Boolean(view.locked.oauthScopes)} onChange={(e) => set({ oauthScopes: e.target.value })} />
          </Field>

          <h3>{t("Keystone federation (optional)")}</h3>
          <p className="hint">
            {t(
              "When Keystone trusts the same identity provider (OS-FEDERATION), each person acts with their own OpenStack identity and roles: the server exchanges their access token at Keystone. Without federation, OAuth users only get the shared connections that the rules of “OAuth access” grant them.",
            )}
          </p>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={draft.federationEnabled}
              disabled={Boolean(lockedFederation)}
              onChange={(e) => set({ federationEnabled: e.target.checked })}
            />
            <span>
              {t("Give users their own OpenStack access through Keystone federation")}
              <Locked variable={lockedFederation} />
            </span>
          </label>
          {draft.federationEnabled && (
            <>
              <Field label={t("Keystone URL")} locked={view.locked.federationAuthUrl} hint={t("The Keystone auth URL of the cloud, with or without /v3.")}>
                <input
                  value={draft.federationAuthUrl}
                  disabled={Boolean(view.locked.federationAuthUrl)}
                  onChange={(e) => set({ federationAuthUrl: e.target.value })}
                  placeholder="https://keystone.example.com:5000/v3"
                  autoComplete="off"
                />
              </Field>
              <div className="form-row">
                <Field
                  label={t("Identity provider")}
                  locked={view.locked.federationIdentityProvider}
                  hint={t("Its name in Keystone (openstack identity provider list).")}
                >
                  <input
                    value={draft.federationIdentityProvider}
                    disabled={Boolean(view.locked.federationIdentityProvider)}
                    onChange={(e) => set({ federationIdentityProvider: e.target.value })}
                    placeholder="sso"
                    autoComplete="off"
                  />
                </Field>
                <Field label={t("Protocol")} locked={view.locked.federationProtocol} hint={t("Default: {protocol}.", { protocol: view.defaults.federationProtocol })}>
                  <input
                    value={draft.federationProtocol}
                    disabled={Boolean(view.locked.federationProtocol)}
                    onChange={(e) => set({ federationProtocol: e.target.value })}
                    placeholder={view.defaults.federationProtocol}
                    autoComplete="off"
                  />
                </Field>
                <Field label={t("Region")} locked={view.locked.federationRegion} hint={t("Optional; the first region of the catalog otherwise.")}>
                  <input
                    value={draft.federationRegion}
                    disabled={Boolean(view.locked.federationRegion)}
                    onChange={(e) => set({ federationRegion: e.target.value })}
                    placeholder="RegionOne"
                    autoComplete="off"
                  />
                </Field>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
