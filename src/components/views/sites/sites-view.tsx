"use client";

/**
 * Multi-Site Central Manager view (Phase 4 §4.1) — the central console for a
 * fleet of UTM instances: fleet stats strip, site table with a selected-site
 * detail card (deploy from template, push firmware, connectivity probe —
 * each recorded as a SiteDeployment), deployment history with inline
 * transport errors, site-template manager (JSON bundle editor) and the
 * firmware catalog (checksummed per-channel releases).
 * Atoms reused from fw-ui (table states, toasts, ConfirmDialog, density);
 * palette per UI_DESIGN_SYSTEM §2 — no indigo/blue anywhere.
 */

import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import {
  ConfirmDialog,
  DensityToggle,
  EmptyBlock,
  QueryError,
  TableSkeleton,
  toastErr,
  toastOk,
  useTableDensity,
} from "../firewall/fw-ui";
import {
  CHANNELS,
  DEPLOY_STATUSES,
  KINDS,
  ROLES,
  SITE_STATUSES,
  fmtDateTime,
  qs,
  sitesApi,
  type DeploymentDTO,
  type DeploymentKind,
  type DeploymentStatus,
  type FirmwareChannel,
  type FirmwareDTO,
  type SiteDTO,
  type SiteRole,
  type SiteStatus,
  type TemplateDTO,
} from "./sites-api";

// ── local chips (colors only — palette per UI_DESIGN_SYSTEM §2) ─────────────

const STATUS_BADGE: Record<SiteStatus, { cls: string; icon: React.ComponentType<{ className?: string }> }> = {
  online: { cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400", icon: Icons.Wifi },
  offline: { cls: "border-zinc-400/60 bg-zinc-500/5 text-zinc-600 dark:text-zinc-300", icon: Icons.WifiOff },
  degraded: { cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400", icon: Icons.TriangleAlert },
  never_seen: { cls: "border-zinc-400/60 border-dashed bg-zinc-500/5 text-zinc-500 dark:text-zinc-400", icon: Icons.CircleDashed },
};

function StatusBadge({ status }: { status: SiteStatus }) {
  const def = STATUS_BADGE[status] ?? STATUS_BADGE.never_seen;
  const Icon = def.icon;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium capitalize", def.cls)}>
      <Icon className="h-3 w-3" />
      {status.replace("_", " ")}
    </Badge>
  );
}

const ROLE_BADGE: Record<SiteRole, { cls: string; icon: React.ComponentType<{ className?: string }>; hint: string }> = {
  hub: { cls: "border-teal-500/40 bg-teal-500/10 text-teal-600 dark:text-teal-400", icon: Icons.Landmark, hint: "central hub site" },
  spoke: { cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400", icon: Icons.Share2, hint: "spoke behind a hub" },
  standalone: { cls: "border-zinc-400/60 bg-zinc-500/5 text-zinc-600 dark:text-zinc-300", icon: Icons.Server, hint: "standalone instance" },
};

function RoleBadge({ role }: { role: SiteRole }) {
  const def = ROLE_BADGE[role] ?? ROLE_BADGE.standalone;
  const Icon = def.icon;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium capitalize", def.cls)} title={def.hint}>
      <Icon className="h-3 w-3" />
      {role}
    </Badge>
  );
}

const KIND_CHIP: Record<DeploymentKind, { cls: string; icon: React.ComponentType<{ className?: string }> }> = {
  policy: { cls: "border-zinc-400/60 bg-zinc-500/5 text-zinc-600 dark:text-zinc-300", icon: Icons.ShieldCheck },
  template: { cls: "border-teal-500/40 bg-teal-500/10 text-teal-600 dark:text-teal-400", icon: Icons.LayoutTemplate },
  firmware: { cls: "border-orange-500/40 bg-orange-500/10 text-orange-600 dark:text-orange-400", icon: Icons.Cpu },
};

function KindChip({ kind }: { kind: DeploymentKind }) {
  const def = KIND_CHIP[kind] ?? KIND_CHIP.policy;
  const Icon = def.icon;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium", def.cls)}>
      <Icon className="h-3 w-3" />
      {kind}
    </Badge>
  );
}

const DEPLOY_STATUS_BADGE: Record<DeploymentStatus, { cls: string; icon: React.ComponentType<{ className?: string }> }> = {
  pending: { cls: "border-zinc-400/60 bg-zinc-500/5 text-zinc-600 dark:text-zinc-300", icon: Icons.CircleDashed },
  pushing: { cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400", icon: Icons.Upload },
  applied: { cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400", icon: Icons.CircleCheck },
  failed: { cls: "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400", icon: Icons.CircleX },
};

function DeployStatusBadge({ status }: { status: DeploymentStatus }) {
  const def = DEPLOY_STATUS_BADGE[status] ?? DEPLOY_STATUS_BADGE.pending;
  const Icon = def.icon;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium", def.cls)}>
      <Icon className="h-3 w-3" />
      {status}
    </Badge>
  );
}

function ChannelBadge({ channel }: { channel: FirmwareChannel }) {
  const beta = channel === "beta";
  return (
    <Badge
      variant="outline"
      className={cn(
        "gap-1 font-medium",
        beta
          ? "border-orange-500/40 bg-orange-500/10 text-orange-600 dark:text-orange-400"
          : "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
      )}
      title={beta ? "beta channel — early releases" : "stable channel — production releases"}
    >
      {beta ? <Icons.FlaskConical className="h-3 w-3" /> : <Icons.ShieldCheck className="h-3 w-3" />}
      {channel}
    </Badge>
  );
}

// ── stats strip ─────────────────────────────────────────────────────────────

function StatCard(props: { label: string; value: React.ReactNode; icon?: React.ReactNode; hint?: string }) {
  return (
    <div className="min-w-0 rounded-lg border border-zinc-200 px-3 py-2 dark:border-zinc-800">
      <p className="flex items-center gap-1.5 truncate text-[11px] font-medium uppercase tracking-wide text-zinc-500">
        {props.icon}
        {props.label}
      </p>
      <p className="mt-0.5 text-lg font-semibold tabular-nums" title={props.hint}>
        {props.value}
      </p>
    </div>
  );
}

function StatsStrip() {
  const query = useQuery({ queryKey: ["sites", "stats"], queryFn: () => sitesApi.getStats() });
  const s = query.data;
  if (query.isLoading || !s) {
    return (
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="h-[58px] animate-pulse rounded-lg bg-zinc-500/10" />
        ))}
      </div>
    );
  }
  const byStatus: Array<{ status: SiteStatus; icon: React.ReactNode }> = [
    { status: "online", icon: <Icons.Wifi className="h-3 w-3 text-emerald-500" /> },
    { status: "offline", icon: <Icons.WifiOff className="h-3 w-3 text-zinc-400" /> },
    { status: "degraded", icon: <Icons.TriangleAlert className="h-3 w-3 text-amber-500" /> },
    { status: "never_seen", icon: <Icons.CircleDashed className="h-3 w-3 text-zinc-400" /> },
  ];
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
      <StatCard label="Sites" value={s.total} hint={`${s.byRole.hub} hub · ${s.byRole.spoke} spoke · ${s.byRole.standalone} standalone`} />
      {byStatus.map(({ status, icon }) => (
        <StatCard key={status} label={status.replace("_", " ")} value={s.byStatus[status]} icon={icon} />
      ))}
      <StatCard label="Deployments 7d" value={s.deployments7d} icon={<Icons.Upload className="h-3 w-3 text-zinc-400" />} />
    </div>
  );
}

// ── inline pager (server-side pagination — meta.totalPages drives it) ───────

function Pager(props: {
  page: number;
  totalPages: number;
  total: number;
  noun: string;
  onPage: (page: number) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-2 border-t border-zinc-200 px-3 py-2 text-xs text-zinc-500 dark:border-zinc-800">
      <span className="tabular-nums">
        page {props.page} / {props.totalPages} · {props.total.toLocaleString()} {props.noun}
        {props.total === 1 ? "" : "s"}
      </span>
      <div className="flex items-center gap-1">
        <Button variant="outline" size="sm" className="h-7 px-2" disabled={props.page <= 1} onClick={() => props.onPage(props.page - 1)}>
          <Icons.ChevronLeft className="h-3.5 w-3.5" />
        </Button>
        <Button variant="outline" size="sm" className="h-7 px-2" disabled={props.page >= props.totalPages} onClick={() => props.onPage(props.page + 1)}>
          <Icons.ChevronRight className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  );
}

// ── JSON textarea validation (template payload / resource limits) ───────────

function jsonPayloadError(text: string): string | null {
  const t = text.trim();
  if (!t) return "JSON payload is required";
  let parsed: unknown;
  try {
    parsed = JSON.parse(t);
  } catch (err) {
    return `Invalid JSON: ${err instanceof Error ? err.message : "parse error"}`;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return "Payload must be a JSON object";
  }
  return null;
}

// ── site create / edit dialog ───────────────────────────────────────────────

function SiteDialog(props: {
  mode: "create" | "edit";
  site?: SiteDTO;
  onClose: () => void;
}) {
  const editing = props.mode === "edit" && props.site;
  const [name, setName] = useState(props.site?.name ?? "");
  const [region, setRegion] = useState(props.site?.region ?? "");
  const [role, setRole] = useState<SiteRole>(props.site?.role ?? "standalone");
  const [endpoint, setEndpoint] = useState(props.site?.publicEndpoint ?? "");
  const [version, setVersion] = useState(props.site?.version ?? "");
  const [status, setStatus] = useState<SiteStatus>(props.site?.status ?? "never_seen");
  const [limitsText, setLimitsText] = useState(
    props.site ? JSON.stringify(props.site.resourceLimits ?? {}, null, 2) : "{}",
  );
  const [notes, setNotes] = useState(props.site?.notes ?? "");
  const [busy, setBusy] = useState(false);
  const queryClient = useQueryClient();

  const limitsError = useMemo(() => jsonPayloadError(limitsText), [limitsText]);
  const canSubmit = name.trim().length > 0 && (!editing || !limitsError);

  const submit = async () => {
    if (!name.trim()) return;
    setBusy(true);
    try {
      if (editing) {
        const updated = await sitesApi.update(props.site!.id, {
          name: name.trim(),
          region: region.trim(),
          role,
          publicEndpoint: endpoint.trim(),
          version: version.trim(),
          status,
          resourceLimits: JSON.parse(limitsText) as Record<string, unknown>,
          notes,
        });
        toastOk("Site updated", `${updated.name} saved (${updated.status.replace("_", " ")})`);
      } else {
        const created = await sitesApi.create({
          name: name.trim(),
          region: region.trim(),
          role,
          publicEndpoint: endpoint.trim(),
          notes,
        });
        toastOk("Site registered", `${created.name} (${created.role}) — awaiting first connection`);
      }
      await queryClient.invalidateQueries({ queryKey: ["sites"] });
      setBusy(false);
      props.onClose();
    } catch (err) {
      toastErr(err, editing ? "Update site failed" : "Register site failed");
      setBusy(false);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && props.onClose()}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-base">{editing ? `Edit site ${props.site!.name}` : "Register site"}</DialogTitle>
          <DialogDescription>
            {editing
              ? "Update the fleet record — status and version normally come from the site itself."
              : "Add a UTM instance to this central console. It stays 'never seen' until it first connects."}
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="site-name">Name</Label>
              <Input id="site-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="hq-berlin" autoFocus />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="site-region">Region</Label>
              <Input id="site-region" value={region} onChange={(e) => setRegion(e.target.value)} placeholder="eu-central" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="site-role">Role</Label>
              <Select value={role} onValueChange={(v) => setRole(v as SiteRole)}>
                <SelectTrigger id="site-role" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ROLES.map((r) => (
                    <SelectItem key={r} value={r}>
                      {r}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="site-endpoint">Public endpoint</Label>
              <Input
                id="site-endpoint"
                value={endpoint}
                onChange={(e) => setEndpoint(e.target.value)}
                placeholder="hq.corp.example:8443"
              />
            </div>
          </div>
          {editing && (
            <>
              <div className="grid grid-cols-2 gap-3">
                <div className="grid gap-1.5">
                  <Label htmlFor="site-version">Console version</Label>
                  <Input id="site-version" value={version} onChange={(e) => setVersion(e.target.value)} placeholder="3.1.4" />
                </div>
                <div className="grid gap-1.5">
                  <Label htmlFor="site-status">Status</Label>
                  <Select value={status} onValueChange={(v) => setStatus(v as SiteStatus)}>
                    <SelectTrigger id="site-status" className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {SITE_STATUSES.map((s) => (
                        <SelectItem key={s} value={s}>
                          {s.replace("_", " ")}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="site-limits">Resource limits (JSON)</Label>
                <Textarea
                  id="site-limits"
                  value={limitsText}
                  onChange={(e) => setLimitsText(e.target.value)}
                  rows={3}
                  className="font-mono text-xs"
                  placeholder='{"maxRules": 500, "maxCpuPct": 80}'
                />
                {limitsError && <p className="text-xs text-rose-600 dark:text-rose-400">{limitsError}</p>}
              </div>
            </>
          )}
          <div className="grid gap-1.5">
            <Label htmlFor="site-notes">Notes</Label>
            <Textarea id="site-notes" value={notes} onChange={(e) => setNotes(e.target.value)} rows={2} placeholder="Operator, escalation contact, hardware…" />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={props.onClose} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={busy || !canSubmit}>
            {busy ? "Saving…" : editing ? "Save changes" : "Register site"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── deploy-from-template dialog (creates a template SiteDeployment) ─────────

function DeployTemplateDialog(props: { site: SiteDTO; onClose: () => void }) {
  const [templateId, setTemplateId] = useState("");
  const [busy, setBusy] = useState(false);
  const queryClient = useQueryClient();

  const templatesQuery = useQuery({ queryKey: ["sites", "templates"], queryFn: () => sitesApi.listTemplates() });
  const templates = templatesQuery.data ?? [];
  const selected = templates.find((t) => String(t.id) === templateId) ?? null;

  const submit = async () => {
    if (!selected) return;
    setBusy(true);
    try {
      const dep = await sitesApi.push(props.site.id, { kind: "template", templateId: selected.id });
      if (dep.status === "failed") {
        toastErr(
          new Error(dep.result.errors.join("; ") || "push failed"),
          `Template push failed — ${props.site.name}`,
        );
      } else {
        toastOk("Template deployed", `${selected.name} v${selected.version} → ${props.site.name} (applied)`);
      }
      await queryClient.invalidateQueries({ queryKey: ["sites"] });
      setBusy(false);
      props.onClose();
    } catch (err) {
      toastErr(err, "Template push failed");
      setBusy(false);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && props.onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-base">Deploy template to {props.site.name}</DialogTitle>
          <DialogDescription>
            Pushes the template&apos;s config bundle to the site and records it as a deployment.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          <div className="grid gap-1.5">
            <Label htmlFor="deploy-template">Site template</Label>
            <Select value={templateId} onValueChange={setTemplateId}>
              <SelectTrigger id="deploy-template" className="w-full">
                <SelectValue placeholder="choose a template" />
              </SelectTrigger>
              <SelectContent>
                {templates.map((t) => (
                  <SelectItem key={t.id} value={String(t.id)}>
                    <span className="font-medium">{t.name}</span>
                    <span className="ml-2 text-xs text-zinc-500">v{t.version}</span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {selected && (
            <div className="rounded-lg border border-zinc-200 p-3 text-xs dark:border-zinc-800">
              <p className="text-zinc-500">{selected.description || "No description."}</p>
              <p className="mt-1 font-mono text-[11px] text-zinc-400">
                {Object.keys(selected.payload).length} top-level key(s) in the bundle
              </p>
            </div>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={props.onClose} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={busy || !selected}>
            <Icons.Upload className="mr-1 h-4 w-4" />
            {busy ? "Pushing…" : "Deploy"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── push-firmware dialog (creates a firmware SiteDeployment) ────────────────

function PushFirmwareDialog(props: { site: SiteDTO; onClose: () => void }) {
  const [version, setVersion] = useState("");
  const [busy, setBusy] = useState(false);
  const queryClient = useQueryClient();

  const firmwareQuery = useQuery({ queryKey: ["sites", "firmware"], queryFn: () => sitesApi.listFirmware() });
  const releases = firmwareQuery.data ?? [];
  const selected = releases.find((r) => r.version === version) ?? null;

  const submit = async () => {
    if (!selected) return;
    setBusy(true);
    try {
      const dep = await sitesApi.push(props.site.id, { kind: "firmware", firmwareVersion: selected.version });
      if (dep.status === "failed") {
        toastErr(
          new Error(dep.result.errors.join("; ") || "push failed"),
          `Firmware push failed — ${props.site.name}`,
        );
      } else {
        toastOk("Firmware pushed", `${props.site.name} → ${selected.version} (${selected.channel}, applied)`);
      }
      await queryClient.invalidateQueries({ queryKey: ["sites"] });
      setBusy(false);
      props.onClose();
    } catch (err) {
      toastErr(err, "Firmware push failed");
      setBusy(false);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && props.onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-base">Push firmware to {props.site.name}</DialogTitle>
          <DialogDescription>
            Currently on {props.site.version || "no reported version"}. The site updates its version after a successful apply.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          <div className="grid gap-1.5">
            <Label htmlFor="push-firmware">Catalog release</Label>
            <Select value={version} onValueChange={setVersion}>
              <SelectTrigger id="push-firmware" className="w-full">
                <SelectValue placeholder="choose a firmware release" />
              </SelectTrigger>
              <SelectContent>
                {releases.map((r) => (
                  <SelectItem key={r.id} value={r.version}>
                    <span className="font-mono text-xs">{r.version}</span>
                    <span className="ml-2 text-xs text-zinc-500">{r.channel}</span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {selected && (
            <div className="rounded-lg border border-zinc-200 p-3 text-xs dark:border-zinc-800">
              <div className="flex items-center justify-between gap-3">
                <span className="text-zinc-500">Checksum</span>
                <span className="font-mono text-[11px]" title={selected.sha256}>
                  {selected.sha256.slice(0, 16)}…
                </span>
              </div>
              <div className="mt-1 flex items-start justify-between gap-3">
                <span className="shrink-0 text-zinc-500">Notes</span>
                <span className="text-right text-zinc-600 dark:text-zinc-300">{selected.releaseNotes || "—"}</span>
              </div>
            </div>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={props.onClose} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={busy || !selected}>
            <Icons.Cpu className="mr-1 h-4 w-4" />
            {busy ? "Pushing…" : "Push firmware"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── template create / edit dialog (validated JSON payload textarea) ─────────

function TemplateDialog(props: {
  mode: "create" | "edit";
  template?: TemplateDTO;
  onClose: () => void;
}) {
  const editing = props.mode === "edit" && props.template;
  const [name, setName] = useState(props.template?.name ?? "");
  const [description, setDescription] = useState(props.template?.description ?? "");
  const [version, setVersion] = useState(props.template?.version ?? "1");
  const [payloadText, setPayloadText] = useState(
    props.template ? JSON.stringify(props.template.payload ?? {}, null, 2) : "{\n  \"firewallRules\": [],\n  \"natRules\": []\n}",
  );
  const [busy, setBusy] = useState(false);
  const queryClient = useQueryClient();

  const payloadError = useMemo(() => jsonPayloadError(payloadText), [payloadText]);
  const canSubmit = name.trim().length > 0 && !payloadError;

  const submit = async () => {
    if (!name.trim() || payloadError) return;
    setBusy(true);
    try {
      const payload = JSON.parse(payloadText) as Record<string, unknown>;
      if (editing) {
        const updated = await sitesApi.updateTemplate(props.template!.id, {
          name: name.trim(),
          description,
          version: version.trim() || "1",
          payload,
        });
        toastOk("Template updated", `${updated.name} v${updated.version} saved`);
      } else {
        const created = await sitesApi.createTemplate({
          name: name.trim(),
          description,
          version: version.trim() || "1",
          payload,
        });
        toastOk("Template created", `${created.name} v${created.version} ready to deploy`);
      }
      await queryClient.invalidateQueries({ queryKey: ["sites"] });
      setBusy(false);
      props.onClose();
    } catch (err) {
      toastErr(err, editing ? "Update template failed" : "Create template failed");
      setBusy(false);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && props.onClose()}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-xl">
        <DialogHeader>
          <DialogTitle className="text-base">{editing ? `Edit template ${props.template!.name}` : "New site template"}</DialogTitle>
          <DialogDescription>
            A reusable config bundle ({"{firewallRules[], natRules[], dnsPolicies[], …}"}) deployed to sites in one push.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          <div className="grid grid-cols-3 gap-3">
            <div className="col-span-2 grid gap-1.5">
              <Label htmlFor="tpl-name">Name</Label>
              <Input id="tpl-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="branch-office-baseline" autoFocus />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="tpl-version">Version</Label>
              <Input id="tpl-version" value={version} onChange={(e) => setVersion(e.target.value)} placeholder="1" />
            </div>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="tpl-description">Description</Label>
            <Input id="tpl-description" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Standard config for new branch sites" />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="tpl-payload">Payload (JSON object)</Label>
            <Textarea
              id="tpl-payload"
              value={payloadText}
              onChange={(e) => setPayloadText(e.target.value)}
              rows={10}
              className="font-mono text-xs"
            />
            {payloadError ? (
              <p className="text-xs text-rose-600 dark:text-rose-400">{payloadError}</p>
            ) : (
              <p className="text-xs text-emerald-600 dark:text-emerald-400">Valid JSON object.</p>
            )}
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={props.onClose} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={busy || !canSubmit}>
            {busy ? "Saving…" : editing ? "Save changes" : "Create template"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── add firmware release dialog (Switch picks the channel) ──────────────────

function FirmwareDialog(props: { onClose: () => void }) {
  const [version, setVersion] = useState("");
  const [beta, setBeta] = useState(false);
  const [sha, setSha] = useState("");
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState(false);
  const queryClient = useQueryClient();

  const shaError = useMemo(() => {
    if (!sha.trim()) return "sha256 is required";
    return /^[0-9a-fA-F]{64}$/.test(sha.trim()) ? null : "sha256 must be exactly 64 hex characters";
  }, [sha]);
  const canSubmit = version.trim().length > 0 && !shaError;

  const submit = async () => {
    if (!version.trim() || shaError) return;
    setBusy(true);
    try {
      const created = await sitesApi.createFirmware({
        version: version.trim(),
        channel: beta ? "beta" : "stable",
        sha256: sha.trim(),
        releaseNotes: notes,
      });
      toastOk("Release published", `${created.channel}@${created.version} added to the catalog`);
      await queryClient.invalidateQueries({ queryKey: ["sites"] });
      setBusy(false);
      props.onClose();
    } catch (err) {
      toastErr(err, "Add release failed");
      setBusy(false);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && props.onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-base">Add firmware release</DialogTitle>
          <DialogDescription>
            Catalog entry for a console release. The sha256 checksum is verified on the remote site before apply.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="fw-version">Version</Label>
              <Input id="fw-version" value={version} onChange={(e) => setVersion(e.target.value)} placeholder="3.2.0" autoFocus />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="fw-channel">Channel</Label>
              <div className="flex h-9 items-center gap-2">
                <Switch id="fw-channel" checked={beta} onCheckedChange={setBeta} aria-label="Publish on the beta channel" />
                <span className="text-sm text-zinc-600 dark:text-zinc-300">{beta ? "beta" : "stable"}</span>
              </div>
            </div>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="fw-sha">SHA-256</Label>
            <Input
              id="fw-sha"
              value={sha}
              onChange={(e) => setSha(e.target.value)}
              className="font-mono text-xs"
              placeholder="64 hex characters"
            />
            {shaError && <p className="text-xs text-rose-600 dark:text-rose-400">{shaError}</p>}
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="fw-notes">Release notes</Label>
            <Textarea id="fw-notes" value={notes} onChange={(e) => setNotes(e.target.value)} rows={3} placeholder="What changed in this release…" />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={props.onClose} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={busy || !canSubmit}>
            {busy ? "Publishing…" : "Add release"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── selected-site detail card (site detail + push actions) ──────────────────

function SiteDetailCard(props: {
  site: SiteDTO;
  onEdit: (site: SiteDTO) => void;
  onDeployTemplate: (site: SiteDTO) => void;
  onPushFirmware: (site: SiteDTO) => void;
  onProbe: (site: SiteDTO) => void;
}) {
  const s = props.site;
  const limits = Object.entries(s.resourceLimits ?? {});
  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex flex-wrap items-center gap-2 text-base">
          <span>{s.name}</span>
          <RoleBadge role={s.role} />
          <StatusBadge status={s.status} />
        </CardTitle>
        <CardDescription>
          {s.region || "no region"} · registered {fmtDateTime(s.createdAt)}
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3">
        <div className="grid gap-x-6 gap-y-1 text-xs sm:grid-cols-2 lg:grid-cols-4">
          <div className="flex items-start justify-between gap-3 sm:col-span-2">
            <span className="shrink-0 text-zinc-500">Endpoint</span>
            <span className="min-w-0 truncate font-mono">{s.publicEndpoint || "—"}</span>
          </div>
          <div className="flex items-start justify-between gap-3">
            <span className="shrink-0 text-zinc-500">Version</span>
            <span className="font-mono">{s.version || "—"}</span>
          </div>
          <div className="flex items-start justify-between gap-3">
            <span className="shrink-0 text-zinc-500">Last seen</span>
            <span>{fmtDateTime(s.lastSeenAt)}</span>
          </div>
        </div>
        {limits.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] uppercase tracking-wide text-zinc-400">Limits</span>
            {limits.map(([k, v]) => (
              <Badge key={k} variant="outline" className="border-zinc-300 bg-zinc-100 font-mono text-[11px] text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
                {k}: {String(v)}
              </Badge>
            ))}
          </div>
        )}
        {s.notes && <p className="text-xs text-zinc-600 dark:text-zinc-300">{s.notes}</p>}
        <TooltipProvider delayDuration={200}>
          <div className="flex flex-wrap items-center gap-1.5">
            <Button size="sm" variant="outline" className="h-8 gap-1.5 text-xs" onClick={() => props.onDeployTemplate(s)}>
              <Icons.LayoutTemplate className="h-3.5 w-3.5" />
              Deploy template
            </Button>
            <Button size="sm" variant="outline" className="h-8 gap-1.5 text-xs" onClick={() => props.onPushFirmware(s)}>
              <Icons.Cpu className="h-3.5 w-3.5" />
              Push firmware
            </Button>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  size="sm"
                  variant="outline"
                  className="h-8 gap-1.5 text-xs"
                  onClick={() => props.onProbe(s)}
                  aria-label={`Test connectivity to ${s.name}`}
                >
                  <Icons.Radio className="h-3.5 w-3.5" />
                  Test connectivity
                </Button>
              </TooltipTrigger>
              <TooltipContent>Sends a connectivity probe — recorded as a deployment</TooltipContent>
            </Tooltip>
            <Button size="sm" variant="ghost" className="h-8 gap-1.5 text-xs" onClick={() => props.onEdit(s)}>
              <Icons.Pencil className="h-3.5 w-3.5" />
              Edit
            </Button>
          </div>
        </TooltipProvider>
      </CardContent>
    </Card>
  );
}

// ── sites tab ───────────────────────────────────────────────────────────────

const EMPTY_SITE_FILTERS = { q: "", status: "", role: "" };
type SiteFilters = typeof EMPTY_SITE_FILTERS;
const SITE_LIMIT = 25;

function SitesTab() {
  const [inputs, setInputs] = useState<SiteFilters>(EMPTY_SITE_FILTERS);
  const [filters, setFilters] = useState<SiteFilters>(EMPTY_SITE_FILTERS); // applied
  const [page, setPage] = useState(1);
  const [density] = useTableDensity("sites");
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [dialog, setDialog] = useState<{ mode: "create" } | { mode: "edit"; site: SiteDTO } | null>(null);
  const [deployFor, setDeployFor] = useState<SiteDTO | null>(null);
  const [firmwareFor, setFirmwareFor] = useState<SiteDTO | null>(null);
  const [probeFor, setProbeFor] = useState<SiteDTO | null>(null);
  const [probeBusy, setProbeBusy] = useState(false);
  const [deleteFor, setDeleteFor] = useState<SiteDTO | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const queryClient = useQueryClient();

  const commitText = () => {
    setFilters((cur) => (cur.q === inputs.q ? cur : { ...cur, q: inputs.q }));
    setPage(1);
  };

  const applyFilter = (patch: Partial<SiteFilters>) => {
    setInputs({ ...inputs, ...patch });
    setFilters({ ...inputs, ...patch });
    setPage(1);
  };

  const params = useMemo(() => qs({ ...filters, page, limit: SITE_LIMIT }), [filters, page]);
  const query = useQuery({
    queryKey: ["sites", "list", filters, page],
    queryFn: () => sitesApi.list(params),
  });

  const rows = query.data?.data ?? [];
  const meta = query.data?.meta;
  const selected = rows.find((r) => r.id === selectedId) ?? null;

  const confirmProbe = async () => {
    if (!probeFor) return;
    setProbeBusy(true);
    try {
      const dep = await sitesApi.push(probeFor.id, { kind: "policy", payload: { probe: "connectivity" } });
      if (dep.status === "failed") {
        toastErr(new Error(dep.result.errors.join("; ") || "site unreachable"), `Probe failed — ${probeFor.name}`);
      } else {
        toastOk("Site reachable", `${probeFor.name} probe applied — transport OK`);
      }
      await queryClient.invalidateQueries({ queryKey: ["sites"] });
      setProbeBusy(false);
      setProbeFor(null);
    } catch (err) {
      toastErr(err, "Connectivity probe failed");
      setProbeBusy(false);
    }
  };

  const confirmDelete = async () => {
    if (!deleteFor) return;
    setDeleteBusy(true);
    try {
      await sitesApi.deleteSite(deleteFor.id);
      toastOk("Site removed", `${deleteFor.name} and its deployment history were deleted`);
      if (selectedId === deleteFor.id) setSelectedId(null);
      await queryClient.invalidateQueries({ queryKey: ["sites"] });
      setDeleteBusy(false);
      setDeleteFor(null);
    } catch (err) {
      toastErr(err, "Delete site failed");
      setDeleteBusy(false);
    }
  };

  return (
    <div className="grid gap-3">
      {selected && (
        <SiteDetailCard
          site={selected}
          onEdit={(s) => setDialog({ mode: "edit", site: s })}
          onDeployTemplate={setDeployFor}
          onPushFirmware={setFirmwareFor}
          onProbe={setProbeFor}
        />
      )}

      {/* filter bar */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative">
          <Icons.Search className="absolute left-2.5 top-3 lg:top-2.5 h-4 w-4 text-zinc-400" />
          <Input
            value={inputs.q}
            onChange={(e) => setInputs({ ...inputs, q: e.target.value })}
            onKeyDown={(e) => e.key === "Enter" && commitText()}
            onBlur={commitText}
            placeholder="Search name/region/endpoint…"
            className="h-11 w-60 pl-8 lg:h-9"
            aria-label="Search sites"
          />
        </div>
        <Select value={filters.status || "any"} onValueChange={(v) => applyFilter({ status: v === "any" ? "" : v })}>
          <SelectTrigger className="h-11 w-36 lg:h-9" aria-label="Status filter">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="any">any status</SelectItem>
            {SITE_STATUSES.map((s) => (
              <SelectItem key={s} value={s}>
                {s.replace("_", " ")}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={filters.role || "any"} onValueChange={(v) => applyFilter({ role: v === "any" ? "" : v })}>
          <SelectTrigger className="h-11 w-36 lg:h-9" aria-label="Role filter">
            <SelectValue placeholder="Role" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="any">any role</SelectItem>
            {ROLES.map((r) => (
              <SelectItem key={r} value={r}>
                {r}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <div className="ml-auto flex items-center gap-2">
          <Button className="h-11 gap-1.5 lg:h-9" onClick={() => setDialog({ mode: "create" })}>
            <Icons.Plus className="h-4 w-4" />
            Register site
          </Button>
          <DensityToggle storageKey="sites" label="Site table density" />
        </div>
      </div>

      {/* table */}
      <div className="min-w-0 rounded-lg border border-zinc-200 dark:border-zinc-800">
        {query.isLoading ? (
          <TableSkeleton rows={8} cols={8} />
        ) : query.isError ? (
          <QueryError error={query.error} onRetry={() => void query.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyBlock
            icon={<Icons.Server className="h-6 w-6" />}
            title="No sites match this filter"
            description="Register a UTM instance to manage it from this central console."
            action={
              <Button size="sm" className="mt-2 gap-1.5" onClick={() => setDialog({ mode: "create" })}>
                <Icons.Plus className="h-3.5 w-3.5" />
                Register site
              </Button>
            }
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <Table
                className={cn(
                  "min-w-[900px]",
                  density === "compact" && "[&_th]:h-9 [&_th]:px-1.5 [&_td]:px-1.5 [&_td]:py-1 [&_td]:text-xs",
                )}
              >
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Region</TableHead>
                    <TableHead>Role</TableHead>
                    <TableHead>Endpoint</TableHead>
                    <TableHead>Version</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Last seen</TableHead>
                    <TableHead className="w-24 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((r) => (
                    <TableRow
                      key={r.id}
                      className={cn("cursor-pointer", selectedId === r.id && "bg-zinc-500/5")}
                      onClick={() => setSelectedId(selectedId === r.id ? null : r.id)}
                    >
                      <TableCell className="whitespace-nowrap font-medium text-sm">{r.name}</TableCell>
                      <TableCell className="text-xs text-zinc-500">{r.region || "—"}</TableCell>
                      <TableCell>
                        <RoleBadge role={r.role} />
                      </TableCell>
                      <TableCell className="max-w-52 min-w-0 truncate font-mono text-xs" title={r.publicEndpoint}>
                        {r.publicEndpoint || <span className="text-zinc-400">—</span>}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{r.version || <span className="text-zinc-400">—</span>}</TableCell>
                      <TableCell>
                        <StatusBadge status={r.status} />
                      </TableCell>
                      <TableCell className="whitespace-nowrap text-xs tabular-nums">{fmtDateTime(r.lastSeenAt)}</TableCell>
                      <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="sm" className="h-7 px-2" aria-label={`Actions for ${r.name}`}>
                              <Icons.MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end" className="w-52">
                            <DropdownMenuLabel className="text-xs">{r.name}</DropdownMenuLabel>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem onClick={() => setDeployFor(r)}>
                              <Icons.LayoutTemplate className="mr-1.5 h-3.5 w-3.5" />
                              Deploy template…
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => setFirmwareFor(r)}>
                              <Icons.Cpu className="mr-1.5 h-3.5 w-3.5" />
                              Push firmware…
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => setProbeFor(r)}>
                              <Icons.Radio className="mr-1.5 h-3.5 w-3.5" />
                              Test connectivity
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem onClick={() => setDialog({ mode: "edit", site: r })}>
                              <Icons.Pencil className="mr-1.5 h-3.5 w-3.5" />
                              Edit
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              className="text-rose-600 dark:text-rose-400"
                              onClick={() => setDeleteFor(r)}
                            >
                              <Icons.Trash2 className="mr-1.5 h-3.5 w-3.5" />
                              Delete
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            {meta && <Pager page={meta.page} totalPages={meta.totalPages} total={meta.total} noun="site" onPage={setPage} />}
          </>
        )}
      </div>

      {/* dialogs + confirms */}
      {dialog?.mode === "create" && <SiteDialog mode="create" onClose={() => setDialog(null)} />}
      {dialog?.mode === "edit" && (
        <SiteDialog mode="edit" site={dialog.site} onClose={() => setDialog(null)} />
      )}
      {deployFor && <DeployTemplateDialog site={deployFor} onClose={() => setDeployFor(null)} />}
      {firmwareFor && <PushFirmwareDialog site={firmwareFor} onClose={() => setFirmwareFor(null)} />}
      {deleteFor && (
        <ConfirmDialog
          open
          onOpenChange={(open) => !open && !deleteBusy && setDeleteFor(null)}
          title={`Delete site ${deleteFor.name}?`}
          description="Removes the site from the fleet and its deployment history. Central audit log entries are kept."
          confirmLabel="Delete site"
          loading={deleteBusy}
          onConfirm={() => void confirmDelete()}
        />
      )}
      {probeFor && (
        <ConfirmDialog
          open
          onOpenChange={(open) => !open && !probeBusy && setProbeFor(null)}
          title={`Test connectivity to ${probeFor.name}?`}
          description={`Sends a connectivity probe to ${probeFor.publicEndpoint || "the site console"} and records it as a deployment. Sites that have never connected fail with "site has never connected".`}
          confirmLabel="Send probe"
          loading={probeBusy}
          onConfirm={() => void confirmProbe()}
        />
      )}
    </div>
  );
}

// ── deployments tab ─────────────────────────────────────────────────────────

const EMPTY_DEPLOY_FILTERS = { siteId: "", kind: "", status: "" };
type DeployFilters = typeof EMPTY_DEPLOY_FILTERS;
const DEPLOY_LIMIT = 25;

function DeploymentsTab() {
  const [filters, setFilters] = useState<DeployFilters>(EMPTY_DEPLOY_FILTERS);
  const [page, setPage] = useState(1);
  const [density] = useTableDensity("site-deployments");

  const sitesQuery = useQuery({
    queryKey: ["sites", "filter-options"],
    queryFn: () => sitesApi.list("limit=100&page=1"),
    staleTime: 30_000,
  });
  const sites = sitesQuery.data?.data ?? [];

  const params = useMemo(() => qs({ ...filters, page, limit: DEPLOY_LIMIT }), [filters, page]);
  const query = useQuery({
    queryKey: ["sites", "deployments", filters, page],
    queryFn: () => sitesApi.listDeployments(params),
  });

  const rows = query.data?.data ?? [];
  const meta = query.data?.meta;

  const applyFilter = (patch: Partial<DeployFilters>) => {
    setFilters({ ...filters, ...patch });
    setPage(1);
  };

  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <Select value={filters.siteId || "any"} onValueChange={(v) => applyFilter({ siteId: v === "any" ? "" : v })}>
          <SelectTrigger className="h-11 w-44 lg:h-9" aria-label="Site filter">
            <SelectValue placeholder="Site" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="any">any site</SelectItem>
            {sites.map((s) => (
              <SelectItem key={s.id} value={String(s.id)}>
                {s.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={filters.kind || "any"} onValueChange={(v) => applyFilter({ kind: v === "any" ? "" : v })}>
          <SelectTrigger className="h-11 w-36 lg:h-9" aria-label="Kind filter">
            <SelectValue placeholder="Kind" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="any">any kind</SelectItem>
            {KINDS.map((k) => (
              <SelectItem key={k} value={k}>
                {k}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={filters.status || "any"} onValueChange={(v) => applyFilter({ status: v === "any" ? "" : v })}>
          <SelectTrigger className="h-11 w-36 lg:h-9" aria-label="Deployment status filter">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="any">any status</SelectItem>
            {DEPLOY_STATUSES.map((s) => (
              <SelectItem key={s} value={s}>
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="min-w-0 rounded-lg border border-zinc-200 dark:border-zinc-800">
        {query.isLoading ? (
          <TableSkeleton rows={8} cols={7} />
        ) : query.isError ? (
          <QueryError error={query.error} onRetry={() => void query.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyBlock
            icon={<Icons.Upload className="h-6 w-6" />}
            title="No deployments match this filter"
            description="Pushes to sites (policies, templates, firmware, connectivity probes) appear here."
          />
        ) : (
          <>
            <div className="max-h-96 overflow-y-auto">
              <Table
                className={cn(
                  "min-w-[820px]",
                  density === "compact" && "[&_th]:h-9 [&_th]:px-1.5 [&_td]:px-1.5 [&_td]:py-1 [&_td]:text-xs",
                )}
              >
                <TableHeader>
                  <TableRow>
                    <TableHead>Site</TableHead>
                    <TableHead>Kind</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Pushed</TableHead>
                    <TableHead>Applied</TableHead>
                    <TableHead>Result</TableHead>
                    <TableHead className="w-16 text-right">#</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((d) => (
                    <TableRow key={d.id}>
                      <TableCell className="whitespace-nowrap font-medium text-sm">{d.siteName ?? `site#${d.siteId}`}</TableCell>
                      <TableCell>
                        <KindChip kind={d.kind} />
                      </TableCell>
                      <TableCell>
                        <DeployStatusBadge status={d.status} />
                      </TableCell>
                      <TableCell className="whitespace-nowrap text-xs tabular-nums">{fmtDateTime(d.pushedAt)}</TableCell>
                      <TableCell className="whitespace-nowrap text-xs tabular-nums">{fmtDateTime(d.appliedAt)}</TableCell>
                      <TableCell className="max-w-96 min-w-0">
                        {d.result.errors.length > 0 ? (
                          <div className="flex flex-col gap-0.5">
                            {d.result.errors.slice(0, 3).map((e, i) => (
                              <p key={i} className="truncate text-xs text-rose-600 dark:text-rose-400" title={e}>
                                <Icons.CircleX className="mr-1 inline h-3 w-3" />
                                {e}
                              </p>
                            ))}
                            {d.result.errors.length > 3 && (
                              <p className="text-[11px] text-zinc-400">+{d.result.errors.length - 3} more error(s)</p>
                            )}
                          </div>
                        ) : d.result.applied.length > 0 ? (
                          <p className="truncate text-xs text-emerald-600 dark:text-emerald-400" title={d.result.applied.join("; ")}>
                            <Icons.CircleCheck className="mr-1 inline h-3 w-3" />
                            {d.result.applied.join("; ")}
                          </p>
                        ) : (
                          <span className="text-xs text-zinc-400">—</span>
                        )}
                      </TableCell>
                      <TableCell className="text-right font-mono text-xs text-zinc-400">{d.id}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            {meta && <Pager page={meta.page} totalPages={meta.totalPages} total={meta.total} noun="deployment" onPage={setPage} />}
          </>
        )}
      </div>
    </div>
  );
}

// ── templates tab ───────────────────────────────────────────────────────────

function TemplatesTab() {
  const [density] = useTableDensity("site-templates");
  const [dialog, setDialog] = useState<{ mode: "create" } | { mode: "edit"; template: TemplateDTO } | null>(null);
  const [deleteFor, setDeleteFor] = useState<TemplateDTO | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const queryClient = useQueryClient();

  const query = useQuery({ queryKey: ["sites", "templates"], queryFn: () => sitesApi.listTemplates() });
  const rows = query.data ?? [];

  const confirmDelete = async () => {
    if (!deleteFor) return;
    setDeleteBusy(true);
    try {
      await sitesApi.deleteTemplate(deleteFor.id);
      toastOk("Template deleted", `${deleteFor.name} removed — pushed deployments keep their snapshot`);
      await queryClient.invalidateQueries({ queryKey: ["sites"] });
      setDeleteBusy(false);
      setDeleteFor(null);
    } catch (err) {
      toastErr(err, "Delete template failed");
      setDeleteBusy(false);
    }
  };

  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-sm text-zinc-500">
          Reusable config bundles — deploy one to any site from the Sites tab.
        </p>
        <div className="ml-auto">
          <Button className="h-11 gap-1.5 lg:h-9" onClick={() => setDialog({ mode: "create" })}>
            <Icons.Plus className="h-4 w-4" />
            New template
          </Button>
        </div>
      </div>

      <div className="min-w-0 rounded-lg border border-zinc-200 dark:border-zinc-800">
        {query.isLoading ? (
          <TableSkeleton rows={5} cols={6} />
        ) : query.isError ? (
          <QueryError error={query.error} onRetry={() => void query.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyBlock
            icon={<Icons.LayoutTemplate className="h-6 w-6" />}
            title="No site templates yet"
            description="Create a config bundle (firewall rules, NAT, DNS policies…) and deploy it to new sites in one push."
            action={
              <Button size="sm" className="mt-2 gap-1.5" onClick={() => setDialog({ mode: "create" })}>
                <Icons.Plus className="h-3.5 w-3.5" />
                New template
              </Button>
            }
          />
        ) : (
          <div className="max-h-96 overflow-y-auto">
            <Table
              className={cn(
                "min-w-[760px]",
                density === "compact" && "[&_th]:h-9 [&_th]:px-1.5 [&_td]:px-1.5 [&_td]:py-1 [&_td]:text-xs",
              )}
            >
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead>Payload keys</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="w-28 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((t) => (
                  <TableRow key={t.id}>
                    <TableCell className="whitespace-nowrap font-medium text-sm">{t.name}</TableCell>
                    <TableCell className="font-mono text-xs">{t.version}</TableCell>
                    <TableCell className="max-w-72 min-w-0 truncate text-xs text-zinc-500" title={t.description}>
                      {t.description || "—"}
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {Object.keys(t.payload).length === 0 ? (
                          <span className="text-xs text-zinc-400">empty</span>
                        ) : (
                          Object.keys(t.payload).slice(0, 3).map((k) => (
                            <Badge
                              key={k}
                              variant="outline"
                              className="border-zinc-300 bg-zinc-100 font-mono text-[11px] text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
                            >
                              {k}
                            </Badge>
                          ))
                        )}
                        {Object.keys(t.payload).length > 3 && (
                          <span className="text-[11px] text-zinc-400">+{Object.keys(t.payload).length - 3}</span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs tabular-nums">{fmtDateTime(t.createdAt)}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 px-2 text-xs"
                          onClick={() => setDialog({ mode: "edit", template: t })}
                          aria-label={`Edit ${t.name}`}
                        >
                          <Icons.Pencil className="h-3.5 w-3.5" />
                          Edit
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 px-2 text-xs text-rose-600 dark:text-rose-400"
                          onClick={() => setDeleteFor(t)}
                          aria-label={`Delete ${t.name}`}
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
      </div>

      {dialog?.mode === "create" && <TemplateDialog mode="create" onClose={() => setDialog(null)} />}
      {dialog?.mode === "edit" && (
        <TemplateDialog mode="edit" template={dialog.template} onClose={() => setDialog(null)} />
      )}
      {deleteFor && (
        <ConfirmDialog
          open
          onOpenChange={(open) => !open && !deleteBusy && setDeleteFor(null)}
          title={`Delete template ${deleteFor.name}?`}
          description="Deployments already pushed from this template keep their payload snapshot."
          confirmLabel="Delete template"
          loading={deleteBusy}
          onConfirm={() => void confirmDelete()}
        />
      )}
    </div>
  );
}

// ── firmware tab ────────────────────────────────────────────────────────────

function FirmwareTab() {
  const [density] = useTableDensity("site-firmware");
  const [dialogOpen, setDialogOpen] = useState(false);
  const query = useQuery({ queryKey: ["sites", "firmware"], queryFn: () => sitesApi.listFirmware() });
  const rows = query.data ?? [];

  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-sm text-zinc-500">
          Central firmware catalog — push any release to a site from the Sites tab.
        </p>
        <div className="ml-auto">
          <Button className="h-11 gap-1.5 lg:h-9" onClick={() => setDialogOpen(true)}>
            <Icons.Plus className="h-4 w-4" />
            Add release
          </Button>
        </div>
      </div>

      <div className="min-w-0 rounded-lg border border-zinc-200 dark:border-zinc-800">
        {query.isLoading ? (
          <TableSkeleton rows={5} cols={6} />
        ) : query.isError ? (
          <QueryError error={query.error} onRetry={() => void query.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyBlock
            icon={<Icons.Cpu className="h-6 w-6" />}
            title="Firmware catalog is empty"
            description="Add a checksummed release per channel (stable / beta) to make it available for site pushes."
            action={
              <Button size="sm" className="mt-2 gap-1.5" onClick={() => setDialogOpen(true)}>
                <Icons.Plus className="h-3.5 w-3.5" />
                Add release
              </Button>
            }
          />
        ) : (
          <div className="max-h-96 overflow-y-auto">
            <Table
              className={cn(
                "min-w-[760px]",
                density === "compact" && "[&_th]:h-9 [&_th]:px-1.5 [&_td]:px-1.5 [&_td]:py-1 [&_td]:text-xs",
              )}
            >
              <TableHeader>
                <TableRow>
                  <TableHead>Version</TableHead>
                  <TableHead>Channel</TableHead>
                  <TableHead>SHA-256</TableHead>
                  <TableHead>Release notes</TableHead>
                  <TableHead>Released</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((f) => (
                  <TableRow key={f.id}>
                    <TableCell className="whitespace-nowrap font-mono text-sm font-medium">{f.version}</TableCell>
                    <TableCell>
                      <ChannelBadge channel={f.channel} />
                    </TableCell>
                    <TableCell className="font-mono text-xs text-zinc-500" title={f.sha256}>
                      {f.sha256 ? `${f.sha256.slice(0, 12)}…${f.sha256.slice(-6)}` : "—"}
                    </TableCell>
                    <TableCell className="max-w-80 min-w-0 truncate text-xs text-zinc-500" title={f.releaseNotes}>
                      {f.releaseNotes || "—"}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs tabular-nums">{fmtDateTime(f.releasedAt ?? f.createdAt)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>

      {dialogOpen && <FirmwareDialog onClose={() => setDialogOpen(false)} />}
    </div>
  );
}

// ── main view ───────────────────────────────────────────────────────────────

export function SitesView() {
  const [tab, setTab] = useState("sites");
  return (
    <div className="flex flex-col gap-6">
      <header className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Multi-Site Manager</h1>
          <p className="text-sm text-zinc-500">
            Central console for the UTM fleet — sites, policy/template/firmware pushes, templates and the firmware catalog.
          </p>
        </div>
        <Badge variant="outline" className="border-zinc-500/30 bg-zinc-500/10 font-mono text-zinc-600 dark:text-zinc-300">
          spec 4.1
        </Badge>
      </header>

      <StatsStrip />

      <Tabs value={tab} onValueChange={setTab} className="gap-6">
        <TabsList className="h-auto w-full flex-wrap justify-start sm:w-auto">
          <TabsTrigger value="sites" className="gap-1.5">
            <Icons.Server className="h-4 w-4" />
            Sites
          </TabsTrigger>
          <TabsTrigger value="deployments" className="gap-1.5">
            <Icons.Upload className="h-4 w-4" />
            Deployments
          </TabsTrigger>
          <TabsTrigger value="templates" className="gap-1.5">
            <Icons.LayoutTemplate className="h-4 w-4" />
            Templates
          </TabsTrigger>
          <TabsTrigger value="firmware" className="gap-1.5">
            <Icons.Cpu className="h-4 w-4" />
            Firmware
          </TabsTrigger>
        </TabsList>

        <TabsContent value="sites">
          <SitesTab />
        </TabsContent>
        <TabsContent value="deployments">
          <DeploymentsTab />
        </TabsContent>
        <TabsContent value="templates">
          <TemplatesTab />
        </TabsContent>
        <TabsContent value="firmware">
          <FirmwareTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
