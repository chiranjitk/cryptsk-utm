"use client";

/**
 * #/identity/federation — Federation (SSO) (M23, spec 2.9). Three stacked
 * sections: Federated IdPs (SAML2/OIDC table + create/edit/delete + simulated
 * connectivity test), RADIUS CoA profiles (table + CRUD + simulated CoA packet
 * send) and the user activity timeline (paged table, 10s polling).
 * Theme (ADR-019): blue-600 enterprise accents, zinc neutrals, rose-600
 * danger, amber-500 warning. Secrets are write-only — the UI never renders a
 * stored client secret, only the "•••••••• (stored)" placeholder.
 */

import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { z } from "zod";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  coaProfileCreateSchema,
  coaSendSchema,
  idpCreateSchema,
} from "@/lib/validators/identity-advanced";
import {
  ACTIVITY_EVENTS,
  IDP_PROTOCOLS,
  dayGroupLabel,
  identityApi,
  fieldErrorsOf,
  fmtRelative,
  clockLabel,
  qs,
  type ActivityDTO,
  type ActivityEvent,
  type CoaAction,
  type CoaProfileDTO,
  type IdpDTO,
  type IdpProtocol,
  type IdpStatus,
} from "./identity-advanced-api";
import { ConfirmDialog, EmptyBlock, FieldLabel, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";

/** Long-list scroll wrapper with a slim custom scrollbar. */
const SCROLL =
  "max-h-96 overflow-y-auto [&::-webkit-scrollbar]:w-1.5 [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-zinc-300 dark:[&::-webkit-scrollbar-thumb]:bg-zinc-700";

const ROOT_KEY = ["identity-advanced"] as const;

function invalidateAll(queryClient: ReturnType<typeof useQueryClient>) {
  void queryClient.invalidateQueries({ queryKey: ROOT_KEY });
}

/** First message per field from server fieldErrors envelope details. */
function feToMap(fe: Record<string, string[]>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(fe)) if (v.length > 0) out[k] = v[0];
  return out;
}

/** Client-side zod issues → first message per field. */
function zodToMap(error: z.ZodError): Record<string, string> {
  const out: Record<string, string> = {};
  for (const issue of error.issues) {
    const k = issue.path.join(".") || "_";
    if (!out[k]) out[k] = issue.message;
  }
  return out;
}

function FieldError({ msg }: { msg?: string }) {
  if (!msg) return null;
  return <p className="mt-1 text-xs text-rose-600">{msg}</p>;
}

/** Debounce text filters so each keystroke does not fire a query. */
function useDebounced(value: string, ms = 400): string {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

// ── badge recipes (ADR-019 — blue/zinc/rose/amber only) ─────────────────────

const PROTOCOL_CLS: Record<IdpProtocol, string> = {
  saml2: "border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400",
  oidc: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
};

const STATUS_CLS: Record<IdpStatus, string> = {
  ok: "border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400",
  error: "border-rose-600/60 bg-transparent text-rose-500",
  untested: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
};

const EVENT_CLS: Record<ActivityEvent, string> = {
  login: "border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400",
  logout: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
  portal: "border-blue-500/40 bg-transparent text-blue-600 dark:text-blue-400",
  vpn: "border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400",
  coa: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  vlan_change: "border-rose-600/40 bg-transparent text-rose-500",
  nac_auth: "border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400",
  idp_sso: "border-transparent bg-blue-600 text-white",
};

function ProtocolBadge({ protocol }: { protocol: IdpProtocol }) {
  const Icon = protocol === "saml2" ? Icons.KeyRound : Icons.Fingerprint;
  return (
    <Badge variant="outline" className={`gap-1 font-mono text-[10px] uppercase ${PROTOCOL_CLS[protocol]}`}>
      <Icon className="h-3 w-3" />
      {protocol}
    </Badge>
  );
}

function IdpStatusBadge({ status }: { status: IdpStatus }) {
  const Icon = status === "ok" ? Icons.ShieldCheck : status === "error" ? Icons.ShieldAlert : Icons.Clock;
  return (
    <Badge variant="outline" className={`gap-1 font-medium ${STATUS_CLS[status]}`}>
      <Icon className="h-3 w-3" />
      {status}
    </Badge>
  );
}

function EventBadge({ event }: { event: string }) {
  const cls = EVENT_CLS[event as ActivityEvent] ?? EVENT_CLS.logout;
  return (
    <Badge variant="outline" className={`gap-1 font-mono text-[10px] ${cls}`}>
      {event}
    </Badge>
  );
}

/** Pre-parsed detail JSON rendered as compact k=v chips (max 3). */
function DetailChips({ detail }: { detail: Record<string, unknown> }) {
  const entries = Object.entries(detail).slice(0, 3);
  if (entries.length === 0) return <span className="text-xs text-zinc-400">—</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {entries.map(([k, v]) => (
        <Badge
          key={k}
          variant="outline"
          className="max-w-44 border-zinc-300 bg-transparent font-mono text-[10px] font-normal text-zinc-500 dark:border-zinc-700 dark:text-zinc-400"
        >
          <span className="truncate">
            {k}={String(v)}
          </span>
        </Badge>
      ))}
    </div>
  );
}

// ── IdP editor (create + edit, write-only secret) ───────────────────────────

function IdpEditor(props: { idp: IdpDTO | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = props.idp !== null;
  const [name, setName] = useState(props.idp?.name ?? "");
  const [protocol, setProtocol] = useState<IdpProtocol>(props.idp?.protocol ?? "saml2");
  const [entityId, setEntityId] = useState(props.idp?.entityId ?? "");
  const [metadataUrl, setMetadataUrl] = useState(props.idp?.metadataUrl ?? "");
  const [ssoUrl, setSsoUrl] = useState(props.idp?.ssoUrl ?? "");
  const [clientId, setClientId] = useState(props.idp?.clientId ?? "");
  const [secret, setSecret] = useState(""); // write-only — never prefilled
  const [redirectUri, setRedirectUri] = useState(props.idp?.redirectUri ?? "");
  const [certId, setCertId] = useState(props.idp?.idpCertId != null ? String(props.idp.idpCertId) : "");
  const [enabled, setEnabled] = useState(props.idp?.enabled ?? true);
  const [err, setErr] = useState<string | null>(null);
  const [fields, setFields] = useState<Record<string, string>>({});

  const certsQuery = useQuery({
    queryKey: [...ROOT_KEY, "cert-refs"],
    queryFn: identityApi.listIdpCertificates,
  });
  const certs = certsQuery.data ?? [];
  // keep a stored-but-inactive cert selectable so editing never wipes it silently
  const editing = props.idp;
  const staleCert =
    editing?.idpCertId != null && !certs.some((c) => c.id === editing.idpCertId)
      ? { id: editing.idpCertId, name: `Certificate #${editing.idpCertId}`, commonName: "unavailable" }
      : null;

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => {
      const id = props.idp?.id;
      if (isEdit && id !== undefined) return identityApi.updateIdp(id, body);
      return identityApi.createIdp(body);
    },
    onSuccess: (idp) => {
      toastOk(isEdit ? "IdP updated" : "IdP created", idp.name);
      invalidateAll(queryClient);
      props.onClose();
    },
    onError: (e) => {
      setErr(e instanceof Error ? e.message : "Save failed");
      setFields(feToMap(fieldErrorsOf(e)));
    },
  });

  const submit = () => {
    const payload: Record<string, unknown> = {
      name: name.trim(),
      protocol,
      entityId: entityId.trim() || null,
      metadataUrl: metadataUrl.trim() || null,
      ssoUrl: ssoUrl.trim() || null,
      clientId: clientId.trim() || null,
      idpCertId: certId === "" ? null : Number(certId),
      redirectUri: redirectUri.trim() || null,
      enabled,
    };
    // write-only secret rule: only include when the operator typed a new one
    if (secret.trim()) payload.clientSecret = secret.trim();

    const parsed = idpCreateSchema.safeParse(payload);
    if (!parsed.success) {
      setFields(zodToMap(parsed.error));
      setErr(null);
      return;
    }
    setFields({});
    setErr(null);
    save.mutate(payload);
  };

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-base">{isEdit ? `Edit ${props.idp?.name}` : "New federated IdP"}</DialogTitle>
          <DialogDescription>
            SAML2 requires an entityId or metadata URL; OIDC requires a clientId and an https redirect URI.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div>
            <FieldLabel>Name</FieldLabel>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Okta SAML" />
            <FieldError msg={fields.name} />
          </div>
          <div>
            <FieldLabel>Protocol</FieldLabel>
            <Select value={protocol} onValueChange={(v) => setProtocol(v as IdpProtocol)}>
              <SelectTrigger aria-label="IdP protocol">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {IDP_PROTOCOLS.map((p) => (
                  <SelectItem key={p} value={p}>
                    {p === "saml2" ? "SAML 2.0" : "OpenID Connect"}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <FieldError msg={fields.protocol} />
          </div>

          {protocol === "saml2" ? (
            <>
              <div>
                <FieldLabel hint="required unless metadata URL is set">Entity ID</FieldLabel>
                <Input
                  value={entityId}
                  onChange={(e) => setEntityId(e.target.value)}
                  placeholder="https://idp.example.com/sso"
                  className="font-mono text-xs"
                />
                <FieldError msg={fields.entityId} />
              </div>
              <div>
                <FieldLabel hint="http(s) URL">Metadata URL</FieldLabel>
                <Input
                  value={metadataUrl}
                  onChange={(e) => setMetadataUrl(e.target.value)}
                  placeholder="https://idp.example.com/.well-known/saml-metadata"
                  className="font-mono text-xs"
                />
                <FieldError msg={fields.metadataUrl} />
              </div>
              <div>
                <FieldLabel hint="signing certificate (PKI console)">IdP certificate</FieldLabel>
                <Select value={certId} onValueChange={setCertId}>
                  <SelectTrigger aria-label="IdP signing certificate">
                    <SelectValue placeholder="— none —" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">— none —</SelectItem>
                    {staleCert && (
                      <SelectItem value={String(staleCert.id)}>{staleCert.name} (inactive)</SelectItem>
                    )}
                    {certs.map((c) => (
                      <SelectItem key={c.id} value={String(c.id)}>
                        {c.name} ({c.commonName})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FieldError msg={fields.idpCertId} />
              </div>
            </>
          ) : (
            <>
              <div>
                <FieldLabel hint="required for OIDC">Client ID</FieldLabel>
                <Input
                  value={clientId}
                  onChange={(e) => setClientId(e.target.value)}
                  placeholder="cryptsk-console"
                  className="font-mono text-xs"
                />
                <FieldError msg={fields.clientId} />
              </div>
              <div>
                <FieldLabel hint={isEdit && props.idp?.hasSecret ? "stored — leave blank to keep" : "write-only"}>
                  Client secret
                </FieldLabel>
                <Input
                  type="password"
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                  placeholder={props.idp?.hasSecret ? "•••••••• (stored)" : "super-secret-value"}
                  autoComplete="new-password"
                />
                <FieldError msg={fields.clientSecret} />
              </div>
            </>
          )}

          <div>
            <FieldLabel hint={protocol === "oidc" ? "must be https" : "optional"}>Redirect URI</FieldLabel>
            <Input
              value={redirectUri}
              onChange={(e) => setRedirectUri(e.target.value)}
              placeholder="https://fw.cryptsk.local/api/v1/sso/callback"
              className="font-mono text-xs"
            />
            <FieldError msg={fields.redirectUri} />
          </div>
          {protocol === "saml2" && (
            <div>
              <FieldLabel hint="optional">SSO URL</FieldLabel>
              <Input
                value={ssoUrl}
                onChange={(e) => setSsoUrl(e.target.value)}
                placeholder="https://idp.example.com/sso/saml"
                className="font-mono text-xs"
              />
              <FieldError msg={fields.ssoUrl} />
            </div>
          )}

          <div className="flex items-center justify-between gap-4 rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
            <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">IdP enabled</span>
            <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="IdP enabled" />
          </div>

          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button className="bg-blue-600 text-white hover:bg-blue-700" disabled={save.isPending || !name.trim()} onClick={submit}>
            {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create IdP"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── CoA profile editor ──────────────────────────────────────────────────────

function CoaEditor(props: { profile: CoaProfileDTO | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = props.profile !== null;
  const [name, setName] = useState(props.profile?.name ?? "");
  const [radiusId, setRadiusId] = useState(
    props.profile?.radiusProfileId != null ? String(props.profile.radiusProfileId) : "",
  );
  const [coaEnabled, setCoaEnabled] = useState(props.profile?.coaEnabled ?? true);
  const [dynamicVlan, setDynamicVlan] = useState(props.profile?.dynamicVlan ?? true);
  const [vlanStart, setVlanStart] = useState(props.profile?.vlanPoolStart != null ? String(props.profile.vlanPoolStart) : "");
  const [vlanEnd, setVlanEnd] = useState(props.profile?.vlanPoolEnd != null ? String(props.profile.vlanPoolEnd) : "");
  const [timeout, setTimeout_] = useState(props.profile ? String(props.profile.sessionTimeoutMin) : "480");
  const [enabled, setEnabled] = useState(props.profile?.enabled ?? true);
  const [err, setErr] = useState<string | null>(null);
  const [fields, setFields] = useState<Record<string, string>>({});

  const radiusQuery = useQuery({
    queryKey: [...ROOT_KEY, "radius-refs"],
    queryFn: identityApi.listRadiusProfiles,
  });
  const radiusProfiles = radiusQuery.data ?? [];
  const editingProfile = props.profile;
  const staleRadius =
    editingProfile?.radiusProfileId != null && !radiusProfiles.some((r) => r.id === editingProfile.radiusProfileId)
      ? {
          id: editingProfile.radiusProfileId,
          name: editingProfile.radiusProfileName ?? `Profile #${editingProfile.radiusProfileId}`,
          serverIp: "unknown",
          authPort: 0,
        }
      : null;

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => {
      const id = props.profile?.id;
      if (isEdit && id !== undefined) return identityApi.updateCoaProfile(id, body);
      return identityApi.createCoaProfile(body);
    },
    onSuccess: (p) => {
      toastOk(isEdit ? "CoA profile updated" : "CoA profile created", p.name);
      invalidateAll(queryClient);
      props.onClose();
    },
    onError: (e) => {
      setErr(e instanceof Error ? e.message : "Save failed");
      setFields(feToMap(fieldErrorsOf(e)));
    },
  });

  const submit = () => {
    const payload = {
      name: name.trim(),
      radiusProfileId: radiusId === "" ? null : Number(radiusId),
      coaEnabled,
      dynamicVlan,
      vlanPoolStart: vlanStart.trim() === "" ? null : vlanStart,
      vlanPoolEnd: vlanEnd.trim() === "" ? null : vlanEnd,
      sessionTimeoutMin: timeout,
      enabled,
    };
    const parsed = coaProfileCreateSchema.safeParse(payload);
    if (!parsed.success) {
      setFields(zodToMap(parsed.error));
      setErr(null);
      return;
    }
    setFields({});
    setErr(null);
    save.mutate(payload);
  };

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-base">
            {isEdit ? `Edit ${props.profile?.name}` : "New RADIUS CoA profile"}
          </DialogTitle>
          <DialogDescription>
            Change-of-Authorization packets are sent through the linked RADIUS profile (shared secret is managed there and never displayed).
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div>
            <FieldLabel>Name</FieldLabel>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="corporate-coa" />
            <FieldError msg={fields.name} />
          </div>
          <div>
            <FieldLabel hint="RADIUS server (M07)">RADIUS profile</FieldLabel>
            <Select value={radiusId} onValueChange={setRadiusId}>
              <SelectTrigger aria-label="RADIUS profile">
                <SelectValue placeholder="— none —" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">— none —</SelectItem>
                {staleRadius && (
                  <SelectItem value={String(staleRadius.id)}>{staleRadius.name} (unavailable)</SelectItem>
                )}
                {radiusProfiles.map((r) => (
                  <SelectItem key={r.id} value={String(r.id)}>
                    {r.name} — {r.serverIp}:{r.authPort}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <FieldError msg={fields.radiusProfileId} />
          </div>
          <div>
            <FieldLabel hint="minutes (5–10080)">Session timeout</FieldLabel>
            <Input
              type="number"
              min={5}
              max={10080}
              value={timeout}
              onChange={(e) => setTimeout_(e.target.value)}
              className="font-mono text-xs"
            />
            <FieldError msg={fields.sessionTimeoutMin} />
          </div>

          <div className="grid gap-3 rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
            <div className="flex items-center justify-between gap-4">
              <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">CoA enabled</span>
              <Switch checked={coaEnabled} onCheckedChange={setCoaEnabled} aria-label="CoA enabled" />
            </div>
            <div className="flex items-center justify-between gap-4">
              <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Dynamic VLAN assignment</span>
              <Switch checked={dynamicVlan} onCheckedChange={setDynamicVlan} aria-label="Dynamic VLAN" />
            </div>
            {dynamicVlan && (
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <FieldLabel hint="1–4094">VLAN pool start</FieldLabel>
                  <Input
                    type="number"
                    min={1}
                    max={4094}
                    value={vlanStart}
                    onChange={(e) => setVlanStart(e.target.value)}
                    placeholder="100"
                    className="font-mono text-xs"
                  />
                  <FieldError msg={fields.vlanPoolStart} />
                </div>
                <div>
                  <FieldLabel hint="≥ start">VLAN pool end</FieldLabel>
                  <Input
                    type="number"
                    min={1}
                    max={4094}
                    value={vlanEnd}
                    onChange={(e) => setVlanEnd(e.target.value)}
                    placeholder="199"
                    className="font-mono text-xs"
                  />
                  <FieldError msg={fields.vlanPoolEnd} />
                </div>
              </div>
            )}
            <div className="flex items-center justify-between gap-4">
              <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Profile enabled</span>
              <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="Profile enabled" />
            </div>
          </div>

          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button className="bg-blue-600 text-white hover:bg-blue-700" disabled={save.isPending || !name.trim()} onClick={submit}>
            {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create profile"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── send CoA dialog (simulated packet) ──────────────────────────────────────

function SendCoaDialog(props: { profile: CoaProfileDTO; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [userName, setUserName] = useState("");
  const [action, setAction] = useState<CoaAction>("reauth");
  const [vlanId, setVlanId] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const send = useMutation({
    mutationFn: (body: { userName: string; action: CoaAction; vlanId?: number }) =>
      identityApi.sendCoa(props.profile.id, body),
    onSuccess: (r) => {
      toastOk("CoA packet sent", `${r.packet.code} → ${r.packet.attributes["User-Name"]}`);
      invalidateAll(queryClient);
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "CoA send failed"),
  });

  const submit = () => {
    const payload = { userName: userName.trim(), action, ...(action === "vlan" ? { vlanId } : {}) };
    const parsed = coaSendSchema.safeParse(payload);
    if (!parsed.success) {
      setErr(parsed.error.issues[0]?.message ?? "Invalid CoA request");
      return;
    }
    setErr(null);
    send.mutate(parsed.data);
  };

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-base">Send CoA packet — {props.profile.name}</DialogTitle>
          <DialogDescription>
            Simulated RADIUS Change-of-Authorization toward the NAS. The event is written to the activity timeline.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div>
            <FieldLabel hint="must be an existing user">User name</FieldLabel>
            <Input value={userName} onChange={(e) => setUserName(e.target.value)} placeholder="socuser" className="font-mono text-xs" />
          </div>
          <div>
            <FieldLabel>Action</FieldLabel>
            <Select value={action} onValueChange={(v) => setAction(v as CoaAction)}>
              <SelectTrigger aria-label="CoA action">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="reauth">reauth — force re-authentication</SelectItem>
                <SelectItem value="disconnect">disconnect — terminate session</SelectItem>
                <SelectItem value="vlan">vlan — push dynamic VLAN</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {action === "vlan" && (
            <div>
              <FieldLabel hint="1–4094">VLAN ID</FieldLabel>
              <Input
                type="number"
                min={1}
                max={4094}
                value={vlanId}
                onChange={(e) => setVlanId(e.target.value)}
                placeholder="100"
                className="font-mono text-xs"
              />
            </div>
          )}

          {err && <p className="text-xs text-rose-600">{err}</p>}

          {send.data && (
            <div className="rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
              <p className="mb-2 flex items-center gap-1.5 text-xs font-medium text-blue-600 dark:text-blue-400">
                <Icons.ShieldCheck className="h-3.5 w-3.5" />
                {send.data.packet.code} accepted
              </p>
              <div className="space-y-1">
                {Object.entries(send.data.packet.attributes).map(([k, v]) => (
                  <p key={k} className="font-mono text-[11px] text-zinc-600 dark:text-zinc-300">
                    <span className="text-zinc-400">{k}</span> = {String(v)}
                  </p>
                ))}
              </div>
            </div>
          )}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Close
          </Button>
          <Button
            className="bg-blue-600 text-white hover:bg-blue-700"
            disabled={send.isPending || !userName.trim()}
            onClick={submit}
          >
            {send.isPending ? <Icons.Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" /> : <Icons.Send className="mr-1 h-3.5 w-3.5" />}
            Send packet
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── IdPs section ────────────────────────────────────────────────────────────

function IdpsCard() {
  const queryClient = useQueryClient();
  const idpsQuery = useQuery({ queryKey: [...ROOT_KEY, "idps"], queryFn: identityApi.listIdps });
  const rows = idpsQuery.data ?? [];

  const [addOpen, setAddOpen] = useState(false);
  const [editing, setEditing] = useState<IdpDTO | null>(null);
  const [deleting, setDeleting] = useState<IdpDTO | null>(null);

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => identityApi.updateIdp(id, { enabled }),
    onSuccess: () => invalidateAll(queryClient),
    onError: (e) => toastErr(e, "Toggle failed"),
  });

  const del = useMutation({
    mutationFn: (id: number) => identityApi.deleteIdp(id),
    onSuccess: () => {
      toastOk("IdP deleted");
      setDeleting(null);
      invalidateAll(queryClient);
    },
    onError: (e) => toastErr(e, "Delete failed"),
  });

  const test = useMutation({
    mutationFn: (id: number) => identityApi.testIdp(id),
    onSuccess: (r, id) => {
      const name = rows.find((i) => i.id === id)?.name ?? `#${id}`;
      if (r.ok) toastOk(`IdP ${name} reachable`, `simulated handshake ${r.latencyMs}ms`);
      else toastErr(new Error(r.error ?? "handshake failed"), `IdP ${name} test failed`);
      invalidateAll(queryClient);
    },
    onError: (e) => toastErr(e, "IdP test failed"),
  });

  return (
    <Card>
      <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2 space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.KeyRound className="h-4 w-4 text-blue-600 dark:text-blue-400" />
          Identity Providers
          <span className="text-xs font-normal text-zinc-400">{rows.length} configured</span>
        </CardTitle>
        <Button size="sm" className="h-8 bg-blue-600 text-white hover:bg-blue-700" onClick={() => setAddOpen(true)}>
          <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add IdP
        </Button>
      </CardHeader>
      <CardContent className="p-0">
        {idpsQuery.isError ? (
          <div className="p-4">
            <QueryError error={idpsQuery.error} onRetry={() => void idpsQuery.refetch()} />
          </div>
        ) : idpsQuery.isLoading ? (
          <TableSkeleton rows={3} cols={5} />
        ) : rows.length === 0 ? (
          <EmptyBlock
            icon={<Icons.KeyRound className="h-6 w-6" />}
            title="No federated IdPs"
            description="Add a SAML 2.0 or OpenID Connect provider to enable single sign-on against the console and captive portal."
            action={
              <Button size="sm" className="bg-blue-600 text-white hover:bg-blue-700" onClick={() => setAddOpen(true)}>
                <Icons.Plus className="mr-1 h-3.5 w-3.5" /> New IdP
              </Button>
            }
          />
        ) : (
          <div className={SCROLL}>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Provider</TableHead>
                  <TableHead>Entity / endpoint</TableHead>
                  <TableHead className="w-40">Signing cert</TableHead>
                  <TableHead className="w-24">Enabled</TableHead>
                  <TableHead className="w-28 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((idp) => (
                  <TableRow key={idp.id} className={idp.enabled ? undefined : "opacity-70"}>
                    <TableCell>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-semibold">{idp.name}</span>
                        <ProtocolBadge protocol={idp.protocol} />
                        <IdpStatusBadge status={idp.status} />
                      </div>
                    </TableCell>
                    <TableCell className="max-w-72">
                      <span
                        className="block truncate font-mono text-xs text-zinc-600 dark:text-zinc-300"
                        title={idp.entityId ?? idp.metadataUrl ?? idp.ssoUrl ?? idp.clientId ?? undefined}
                      >
                        {idp.entityId ?? idp.metadataUrl ?? idp.ssoUrl ?? idp.clientId ?? "—"}
                      </span>
                      {idp.redirectUri && (
                        <span className="block truncate text-[10px] text-zinc-400" title={idp.redirectUri}>
                          redirect: {idp.redirectUri}
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="text-xs text-zinc-500">{idp.idpCertName ?? "—"}</TableCell>
                    <TableCell>
                      <Switch
                        checked={idp.enabled}
                        disabled={toggle.isPending && toggle.variables?.id === idp.id}
                        onCheckedChange={(enabled) => toggle.mutate({ id: idp.id, enabled })}
                        aria-label={`Toggle ${idp.name}`}
                      />
                    </TableCell>
                    <TableCell>
                      <div className="flex justify-end gap-0.5">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-zinc-400 hover:text-blue-600"
                          aria-label={`Test ${idp.name}`}
                          disabled={test.isPending && test.variables === idp.id}
                          onClick={() => test.mutate(idp.id)}
                        >
                          {test.isPending && test.variables === idp.id ? (
                            <Icons.Loader2 className="h-3.5 w-3.5 animate-spin" />
                          ) : (
                            <Icons.FlaskConical className="h-3.5 w-3.5" />
                          )}
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-zinc-400 hover:text-blue-600"
                          aria-label={`Edit ${idp.name}`}
                          onClick={() => setEditing(idp)}
                        >
                          <Icons.Pencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-rose-500 hover:text-rose-600"
                          aria-label={`Delete ${idp.name}`}
                          onClick={() => setDeleting(idp)}
                        >
                          <Icons.Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
        <p className="border-t border-zinc-200 px-4 py-2 text-[11px] text-zinc-400 dark:border-zinc-800">
          Client secrets are write-only — stored values are never returned or displayed.
        </p>
      </CardContent>

      {addOpen && <IdpEditor idp={null} onClose={() => setAddOpen(false)} />}
      {editing && <IdpEditor idp={editing} onClose={() => setEditing(null)} />}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete IdP “${deleting?.name ?? ""}”?`}
        description="Users authenticating through this provider will fall back to local login."
        loading={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting.id)}
      />
    </Card>
  );
}

// ── CoA profiles section ────────────────────────────────────────────────────

function CoaCard() {
  const queryClient = useQueryClient();
  const coaQuery = useQuery({ queryKey: [...ROOT_KEY, "coa-profiles"], queryFn: identityApi.listCoaProfiles });
  const radiusQuery = useQuery({ queryKey: [...ROOT_KEY, "radius-refs"], queryFn: identityApi.listRadiusProfiles });
  const rows = coaQuery.data ?? [];
  // endpoint sub-line per RADIUS profile name (server:port of the CoA target)
  const radiusEndpoint = new Map((radiusQuery.data ?? []).map((r) => [r.name, `${r.serverIp}:${r.authPort}` as const]));

  const [addOpen, setAddOpen] = useState(false);
  const [editing, setEditing] = useState<CoaProfileDTO | null>(null);
  const [deleting, setDeleting] = useState<CoaProfileDTO | null>(null);
  const [sending, setSending] = useState<CoaProfileDTO | null>(null);

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => identityApi.updateCoaProfile(id, { enabled }),
    onSuccess: () => invalidateAll(queryClient),
    onError: (e) => toastErr(e, "Toggle failed"),
  });

  const del = useMutation({
    mutationFn: (id: number) => identityApi.deleteCoaProfile(id),
    onSuccess: () => {
      toastOk("CoA profile deleted");
      setDeleting(null);
      invalidateAll(queryClient);
    },
    onError: (e) => toastErr(e, "Delete failed"),
  });

  return (
    <Card>
      <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2 space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.Radio className="h-4 w-4 text-blue-600 dark:text-blue-400" />
          RADIUS CoA Profiles
          <span className="text-xs font-normal text-zinc-400">{rows.length} configured</span>
        </CardTitle>
        <Button size="sm" className="h-8 bg-blue-600 text-white hover:bg-blue-700" onClick={() => setAddOpen(true)}>
          <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add profile
        </Button>
      </CardHeader>
      <CardContent className="p-0">
        {coaQuery.isError ? (
          <div className="p-4">
            <QueryError error={coaQuery.error} onRetry={() => void coaQuery.refetch()} />
          </div>
        ) : coaQuery.isLoading ? (
          <TableSkeleton rows={3} cols={5} />
        ) : rows.length === 0 ? (
          <EmptyBlock
            icon={<Icons.Radio className="h-6 w-6" />}
            title="No CoA profiles"
            description="RADIUS Change-of-Authorization profiles let the firewall push session updates (VLAN, re-auth, disconnect) to NAS devices."
            action={
              <Button size="sm" className="bg-blue-600 text-white hover:bg-blue-700" onClick={() => setAddOpen(true)}>
                <Icons.Plus className="mr-1 h-3.5 w-3.5" /> New profile
              </Button>
            }
          />
        ) : (
          <div className={SCROLL}>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Profile</TableHead>
                  <TableHead>RADIUS server</TableHead>
                  <TableHead className="w-44">Dynamic VLAN</TableHead>
                  <TableHead className="w-24">Timeout</TableHead>
                  <TableHead className="w-24">Enabled</TableHead>
                  <TableHead className="w-28 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((p) => (
                  <TableRow key={p.id} className={p.enabled ? undefined : "opacity-70"}>
                    <TableCell>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-semibold">{p.name}</span>
                        {p.coaEnabled ? (
                          <Badge variant="outline" className="border-blue-500/40 bg-blue-500/10 text-[10px] text-blue-600 dark:text-blue-400">
                            CoA on
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="border-zinc-300 text-[10px] text-zinc-500 dark:border-zinc-700">
                            CoA off
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      {p.radiusProfileName ? (
                        <>
                          <span className="block text-xs font-medium">{p.radiusProfileName}</span>
                          <span className="block text-[10px] text-zinc-400">
                            {radiusEndpoint.get(p.radiusProfileName) ?? "shared secret stored"}
                          </span>
                        </>
                      ) : (
                        <span className="text-xs text-zinc-400">—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {p.dynamicVlan ? (
                        <Badge
                          variant="outline"
                          className="border-blue-500/40 bg-blue-500/10 font-mono text-[10px] text-blue-600 dark:text-blue-400"
                        >
                          {p.vlanPoolStart != null && p.vlanPoolEnd != null ? `pool ${p.vlanPoolStart}–${p.vlanPoolEnd}` : "dynamic"}
                        </Badge>
                      ) : (
                        <span className="text-xs text-zinc-400">off</span>
                      )}
                    </TableCell>
                    <TableCell className="text-xs text-zinc-500">{p.sessionTimeoutMin} min</TableCell>
                    <TableCell>
                      <Switch
                        checked={p.enabled}
                        disabled={toggle.isPending && toggle.variables?.id === p.id}
                        onCheckedChange={(enabled) => toggle.mutate({ id: p.id, enabled })}
                        aria-label={`Toggle ${p.name}`}
                      />
                    </TableCell>
                    <TableCell>
                      <div className="flex justify-end gap-0.5">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-zinc-400 hover:text-blue-600"
                          aria-label={`Send CoA via ${p.name}`}
                          disabled={!p.enabled || !p.coaEnabled}
                          title={!p.enabled || !p.coaEnabled ? "Enable the profile and CoA first" : "Send CoA packet"}
                          onClick={() => setSending(p)}
                        >
                          <Icons.Send className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-zinc-400 hover:text-blue-600"
                          aria-label={`Edit ${p.name}`}
                          onClick={() => setEditing(p)}
                        >
                          <Icons.Pencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-rose-500 hover:text-rose-600"
                          aria-label={`Delete ${p.name}`}
                          onClick={() => setDeleting(p)}
                        >
                          <Icons.Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
        <p className="border-t border-zinc-200 px-4 py-2 text-[11px] text-zinc-400 dark:border-zinc-800">
          RADIUS shared secrets are write-only on the linked profiles (Identity → RADIUS) and never rendered here.
        </p>
      </CardContent>

      {addOpen && <CoaEditor profile={null} onClose={() => setAddOpen(false)} />}
      {editing && <CoaEditor profile={editing} onClose={() => setEditing(null)} />}
      {sending && <SendCoaDialog profile={sending} onClose={() => setSending(null)} />}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete CoA profile “${deleting?.name ?? ""}”?`}
        description="In-flight session authorizations keep their current VLAN until the next re-auth."
        loading={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting.id)}
      />
    </Card>
  );
}

// ── activity timeline section (paged, 10s polling) ──────────────────────────

const ACTIVITY_PAGE_SIZE = 10;

function ActivityCard() {
  const [event, setEvent] = useState<"all" | ActivityEvent>("all");
  const [userInput, setUserInput] = useState("");
  const user = useDebounced(userInput);

  const params = useMemo(
    () => qs({ event: event === "all" ? undefined : event, userName: user || undefined, limit: 200 }),
    [event, user],
  );

  const [page, setPage] = useState(1);
  const [pageKey, setPageKey] = useState(params);

  const activityQuery = useQuery({
    queryKey: [...ROOT_KEY, "activity", params],
    queryFn: () => identityApi.listActivity(params),
    refetchInterval: 10_000,
  });
  const rows = activityQuery.data ?? [];

  // reset to the first page whenever the filter signature changes (render-time
  // state adjustment — no effect needed)
  if (pageKey !== params) {
    setPageKey(params);
    setPage(1);
  }

  const totalPages = Math.max(1, Math.ceil(rows.length / ACTIVITY_PAGE_SIZE));
  const pageRows = rows.slice((page - 1) * ACTIVITY_PAGE_SIZE, page * ACTIVITY_PAGE_SIZE);

  return (
    <Card>
      <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2 space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.History className="h-4 w-4 text-blue-600 dark:text-blue-400" />
          User Activity Timeline
          <span className="flex items-center gap-1 text-xs font-normal text-zinc-400">
            <span className="relative flex h-1.5 w-1.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-blue-500 opacity-60" />
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-blue-600" />
            </span>
            live · 10s
          </span>
        </CardTitle>
        <div className="flex items-center gap-2">
          <Input
            value={userInput}
            onChange={(e) => setUserInput(e.target.value)}
            placeholder="Filter user…"
            aria-label="Filter activity by user"
            className="h-8 w-36 text-xs"
          />
          <Select
            value={event}
            onValueChange={(v) => setEvent(v as "all" | ActivityEvent)}
          >
            <SelectTrigger className="h-8 w-36" aria-label="Event filter">
              <SelectValue placeholder="All events" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All events</SelectItem>
              {ACTIVITY_EVENTS.map((e) => (
                <SelectItem key={e} value={e}>
                  {e}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button variant="ghost" size="icon" className="h-8 w-8" aria-label="Refresh activity" onClick={() => void activityQuery.refetch()}>
            <Icons.RefreshCw className={`h-3.5 w-3.5 ${activityQuery.isFetching ? "animate-spin" : ""}`} />
          </Button>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        {activityQuery.isError ? (
          <div className="p-4">
            <QueryError error={activityQuery.error} onRetry={() => void activityQuery.refetch()} />
          </div>
        ) : activityQuery.isLoading ? (
          <TableSkeleton rows={6} cols={5} />
        ) : rows.length === 0 ? (
          <EmptyBlock
            icon={<Icons.History className="h-6 w-6" />}
            title="No activity events"
            description="Logins, SSO, VPN, portal and NAC events appear here as users authenticate."
          />
        ) : (
          <div className={SCROLL}>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-40">User</TableHead>
                  <TableHead className="w-32">Event</TableHead>
                  <TableHead className="w-32">Source IP</TableHead>
                  <TableHead>Detail</TableHead>
                  <TableHead className="w-24 text-right">Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pageRows.map((row) => (
                  <ActivityRow key={row.id} row={row} />
                ))}
              </TableBody>
            </Table>
          </div>
        )}
        {rows.length > 0 && (
          <div className="flex items-center justify-between gap-2 border-t border-zinc-200 px-4 py-2 dark:border-zinc-800">
            <p className="text-[11px] text-zinc-400">
              Page {page} of {totalPages} · {rows.length} events (newest first)
            </p>
            <div className="flex items-center gap-1">
              <Button
                variant="outline"
                size="sm"
                className="h-8 gap-1 text-xs"
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                <Icons.ChevronLeft className="h-3.5 w-3.5" /> Prev
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="h-8 gap-1 text-xs"
                disabled={page >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              >
                Next <Icons.ChevronRight className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function ActivityRow({ row }: { row: ActivityDTO }) {
  return (
    <TableRow>
      <TableCell>
        <div className="flex items-center gap-2">
          <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-blue-500/10 text-[10px] font-semibold text-blue-600 dark:text-blue-400">
            {row.userName.slice(0, 2).toUpperCase()}
          </span>
          <span className="truncate font-mono text-xs font-medium" title={row.userName}>
            {row.userName}
          </span>
        </div>
      </TableCell>
      <TableCell>
        <EventBadge event={row.event} />
      </TableCell>
      <TableCell className="font-mono text-xs text-zinc-500">{row.sourceIp ?? "—"}</TableCell>
      <TableCell>
        <DetailChips detail={row.detail} />
      </TableCell>
      <TableCell className="whitespace-nowrap text-right">
        <span className="block text-xs tabular-nums text-zinc-600 dark:text-zinc-300" title={row.createdAt}>
          {clockLabel(row.createdAt)}
        </span>
        <span className="block text-[10px] text-zinc-400">
          {dayGroupLabel(row.createdAt)} · {fmtRelative(row.createdAt)}
        </span>
      </TableCell>
    </TableRow>
  );
}

// ── main view ───────────────────────────────────────────────────────────────

export function FederationView() {
  return (
    <div className="space-y-4">
      <IdpsCard />
      <CoaCard />
      <ActivityCard />
    </div>
  );
}
