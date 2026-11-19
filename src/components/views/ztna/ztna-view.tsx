"use client";

/**
 * #/security/ztna — Zero Trust Network Access console (Phase 4 §4.4).
 * Tabs: Applications (protected resources CRUD), Access Policies
 * (user/group/device → app allow/deny rules with posture gate + schedule),
 * Device Posture (requirement profiles + per-device check snapshots with
 * inline failed/unknown checks) — plus an Access Simulator card that calls
 * /evaluate and shows the decision, matched policy and reason.
 * Style mirrors the DLP/incident views; palette per UI_DESIGN_SYSTEM §2
 * (allow = zinc soft, deny = rose solid, emerald only for compliant health).
 */

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";
import {
  CHECK_LABELS,
  SUBJECT_TYPES,
  fmtDateTime,
  ztnaApi,
  type CheckKey,
  type CreateAppBody,
  type CreatePolicyBody,
  type CreateProfileBody,
  type PostureProfileDTO,
  type PostureVerdict,
  type ZtnaAction,
  type ZtnaAppDTO,
  type ZtnaEvaluation,
  type ZtnaPolicyDTO,
  type ZtnaStats,
  type ZtnaSubjectType,
} from "./ztna-api";
import { ConfirmDialog, EmptyBlock, FieldLabel, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";

const ZTNA_KEY = ["ztna"] as const;

// ── badges ───────────────────────────────────────────────────────────────────

const VERDICT_CLS: Record<PostureVerdict, string> = {
  compliant: "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
  non_compliant: "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400",
  unknown: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
};

function VerdictBadge({ verdict }: { verdict: string }) {
  const label = verdict === "non_compliant" ? "non-compliant" : verdict;
  return (
    <Badge variant="outline" className={cn("font-medium", VERDICT_CLS[verdict as PostureVerdict] ?? VERDICT_CLS.unknown)}>
      {label}
    </Badge>
  );
}

const ACTION_CLS: Record<ZtnaAction, string> = {
  allow: "border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300",
  deny: "border-transparent bg-rose-600 text-white",
};

function ActionBadge({ action }: { action: string }) {
  const Icon = action === "deny" ? Icons.Ban : Icons.ShieldCheck;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium", ACTION_CLS[action as ZtnaAction] ?? ACTION_CLS.allow)}>
      <Icon className="h-3 w-3" />
      {action}
    </Badge>
  );
}

const SUBJECT_ICON: Record<ZtnaSubjectType, React.ComponentType<{ className?: string }>> = {
  user: Icons.User,
  group: Icons.Users,
  device: Icons.MonitorSmartphone,
};

function SubjectBadge({ policy }: { policy: Pick<ZtnaPolicyDTO, "subjectType" | "subjectRef"> }) {
  const Icon = SUBJECT_ICON[policy.subjectType] ?? Icons.User;
  return (
    <Badge variant="outline" className="max-w-56 gap-1 font-normal">
      <Icon className="h-3 w-3 shrink-0 text-zinc-400" />
      <span className="truncate font-medium">{policy.subjectRef}</span>
      <span className="ml-0.5 shrink-0 text-[10px] uppercase text-zinc-400">{policy.subjectType}</span>
    </Badge>
  );
}

function CheckChip({ check, state }: { check: CheckKey; state: "pass" | "fail" | "unknown" }) {
  const cls =
    state === "pass"
      ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400"
      : state === "fail"
        ? "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400"
        : "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400";
  return (
    <Badge variant="outline" className={cn("gap-1 text-[10px] font-normal", cls)}>
      {state === "pass" ? <Icons.Check className="h-2.5 w-2.5" /> : state === "fail" ? <Icons.X className="h-2.5 w-2.5" /> : <Icons.HelpCircle className="h-2.5 w-2.5" />}
      {CHECK_LABELS[check]}
    </Badge>
  );
}

/** Requirement chips for a posture profile (only what the profile requires). */
function Requirements({ checks }: { checks: PostureProfileDTO["checks"] }) {
  const chips: string[] = [];
  if (checks.osPatchMaxAgeDays) chips.push(`OS patch ≤ ${checks.osPatchMaxAgeDays}d`);
  if (checks.avRequired) chips.push("AV");
  if (checks.diskEncryptRequired) chips.push("Disk encrypt");
  if (checks.firewallRequired) chips.push("Firewall");
  if (chips.length === 0) return <span className="text-xs text-zinc-400">no requirements</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {chips.map((c) => (
        <Badge key={c} variant="outline" className="border-zinc-300 bg-zinc-100 text-[10px] font-normal text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
          {c}
        </Badge>
      ))}
    </div>
  );
}

// ── stats strip ──────────────────────────────────────────────────────────────

function StatsStrip({ stats }: { stats: ZtnaStats | undefined }) {
  const compliance = stats?.compliance ?? { compliant: 0, nonCompliant: 0, unknown: 0 };
  const total = compliance.compliant + compliance.nonCompliant + compliance.unknown;
  const pct = (n: number) => (total === 0 ? 0 : Math.round((n / total) * 100));
  const items: Array<{ label: string; value: number | string; icon: React.ReactNode }> = [
    { label: "Applications", value: stats?.apps ?? 0, icon: <Icons.AppWindow className="h-4 w-4 text-zinc-500 dark:text-zinc-400" /> },
    { label: "Access policies", value: `${stats?.enabledPolicies ?? 0}/${stats?.policies ?? 0}`, icon: <Icons.KeyRound className="h-4 w-4 text-zinc-500 dark:text-zinc-400" /> },
    { label: "Posture profiles", value: stats?.profiles ?? 0, icon: <Icons.ClipboardCheck className="h-4 w-4 text-zinc-500 dark:text-zinc-400" /> },
    { label: "Devices compliant", value: `${compliance.compliant}/${total}`, icon: <Icons.ShieldCheck className="h-4 w-4 text-emerald-500" /> },
    { label: "Stale re-checks", value: stats?.staleChecks ?? 0, icon: <Icons.TimerReset className="h-4 w-4 text-amber-500" /> },
  ];
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 lg:grid-cols-5">
        {items.map((it) => (
          <Card key={it.label}>
            <CardContent className="flex items-center gap-3 p-4">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-zinc-500/10">{it.icon}</div>
              <div className="min-w-0">
                <p className="truncate text-xs text-zinc-500 dark:text-zinc-400">{it.label}</p>
                <p className="text-lg font-semibold leading-tight">{it.value}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
      <div className="flex items-center gap-3">
        <div className="flex h-2.5 flex-1 overflow-hidden rounded-full bg-zinc-200 dark:bg-zinc-800" role="img" aria-label={`Posture compliance: ${pct(compliance.compliant)}% compliant`}>
          <div className="bg-emerald-500 transition-all" style={{ width: `${pct(compliance.compliant)}%` }} />
          <div className="bg-rose-500 transition-all" style={{ width: `${pct(compliance.nonCompliant)}%` }} />
          <div className="bg-zinc-400 transition-all" style={{ width: `${pct(compliance.unknown)}%` }} />
        </div>
        <span className="shrink-0 text-[11px] text-zinc-500 dark:text-zinc-400">
          {compliance.compliant} compliant · {compliance.nonCompliant} non-compliant · {compliance.unknown} unknown
        </span>
      </div>
    </div>
  );
}

// ── applications tab ─────────────────────────────────────────────────────────

const EMPTY_APP: CreateAppBody = { name: "", host: "", port: 443, protocol: "tcp", group: "" };

function AppDialog(props: { initial: ZtnaAppDTO | null; onClose: () => void; onSaved: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = props.initial !== null;
  // mounted only while open (dlp PatternEditor pattern) — state seeds at mount
  const [form, setForm] = useState<CreateAppBody>(
    props.initial
      ? { name: props.initial.name, host: props.initial.host, port: props.initial.port, protocol: props.initial.protocol, group: props.initial.group }
      : EMPTY_APP,
  );

  const save = useMutation({
    mutationFn: () => {
      const body: CreateAppBody = { ...form, name: form.name.trim(), host: form.host.trim(), group: form.group.trim() };
      return isEdit ? ztnaApi.updateApp(props.initial!.id, body) : ztnaApi.createApp(body);
    },
    onSuccess: (app) => {
      toastOk(isEdit ? "Application updated" : "Application created", `${app.name} → ${app.host}:${app.port}`);
      void queryClient.invalidateQueries({ queryKey: ZTNA_KEY });
      props.onClose();
    },
    onError: (err) => toastErr(err, isEdit ? "Could not update application" : "Could not create application"),
  });

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{isEdit ? "Edit application" : "New protected application"}</DialogTitle>
          <DialogDescription>The resource users reach through the ZTNA broker (hostname or IP).</DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div>
            <FieldLabel>Name</FieldLabel>
            <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="intranet-wiki" />
          </div>
          <div>
            <FieldLabel>Host</FieldLabel>
            <Input value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} placeholder="wiki.corp.internal" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <FieldLabel>Port</FieldLabel>
              <Input type="number" min={1} max={65535} value={form.port} onChange={(e) => setForm({ ...form, port: Number(e.target.value) || 443 })} />
            </div>
            <div>
              <FieldLabel>Protocol</FieldLabel>
              <Select value={form.protocol} onValueChange={(v) => setForm({ ...form, protocol: v as CreateAppBody["protocol"] })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="tcp">TCP</SelectItem>
                  <SelectItem value="udp">UDP</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div>
            <FieldLabel hint="optional">Business group</FieldLabel>
            <Input value={form.group} onChange={(e) => setForm({ ...form, group: e.target.value })} placeholder="engineering" />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={props.onClose}>Cancel</Button>
          <Button onClick={() => save.mutate()} disabled={save.isPending || !form.name.trim() || !form.host.trim()}>
            {save.isPending ? "Saving…" : "Save"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function AppsTab() {
  const queryClient = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<ZtnaAppDTO | null>(null);
  const [deleting, setDeleting] = useState<ZtnaAppDTO | null>(null);
  const appsQuery = useQuery({ queryKey: [...ZTNA_KEY, "apps"], queryFn: ztnaApi.listApps });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ZTNA_KEY });

  const remove = useMutation({
    mutationFn: (id: number) => ztnaApi.deleteApp(id),
    onSuccess: () => {
      toastOk("Application deleted");
      setDeleting(null);
      invalidate();
    },
    onError: (err) => {
      toastErr(err, "Could not delete application");
      setDeleting(null);
    },
  });

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs text-zinc-500 dark:text-zinc-400">Resources protected by the ZTNA broker — access is identity-based, never network-location-based.</p>
        <Button
          size="sm"
          onClick={() => {
            setEditing(null);
            setDialogOpen(true);
          }}
        >
          <Icons.Plus className="mr-1 h-4 w-4" /> New application
        </Button>
      </div>
      {appsQuery.isLoading ? (
        <TableSkeleton rows={5} cols={6} />
      ) : appsQuery.isError ? (
        <QueryError error={appsQuery.error} onRetry={() => appsQuery.refetch()} />
      ) : appsQuery.data.length === 0 ? (
        <EmptyBlock
          icon={<Icons.AppWindow className="h-6 w-6" />}
          title="No ZTNA applications yet"
          description="Register the first protected resource, then define who (user, group or device) may reach it."
          action={
            <Button size="sm" onClick={() => { setEditing(null); setDialogOpen(true); }}>
              <Icons.Plus className="mr-1 h-4 w-4" /> New application
            </Button>
          }
        />
      ) : (
        <div className="overflow-x-auto rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Application</TableHead>
                <TableHead>Endpoint</TableHead>
                <TableHead>Group</TableHead>
                <TableHead className="text-right">Policies</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="w-24 text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {appsQuery.data.map((app) => (
                <TableRow key={app.id}>
                  <TableCell className="font-medium">{app.name}</TableCell>
                  <TableCell>
                    <span className="font-mono text-xs">{app.host}:{app.port}</span>
                    <Badge variant="outline" className="ml-2 border-zinc-300 bg-zinc-100 text-[10px] uppercase text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-400">
                      {app.protocol}
                    </Badge>
                  </TableCell>
                  <TableCell>{app.group ? <span className="text-xs">{app.group}</span> : <span className="text-xs text-zinc-400">—</span>}</TableCell>
                  <TableCell className="text-right text-xs">{app.policyCount}</TableCell>
                  <TableCell className="text-xs text-zinc-500">{fmtDateTime(app.createdAt)}</TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7"
                      aria-label={`Edit ${app.name}`}
                      onClick={() => {
                        setEditing(app);
                        setDialogOpen(true);
                      }}
                    >
                      <Icons.Pencil className="h-3.5 w-3.5" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 text-rose-500 hover:text-rose-600"
                      aria-label={`Delete ${app.name}`}
                      onClick={() => setDeleting(app)}
                    >
                      <Icons.Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {dialogOpen && <AppDialog initial={editing} onClose={() => setDialogOpen(false)} />}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={`Delete application '${deleting?.name ?? ""}'?`}
        description="Applications with access policies cannot be deleted — remove their policies first."
        loading={remove.isPending}
        onConfirm={() => deleting && remove.mutate(deleting.id)}
      />
    </div>
  );
}

// ── access policies tab ──────────────────────────────────────────────────────

const EMPTY_POLICY = { appId: 0, subjectType: "user" as ZtnaSubjectType, subjectRef: "", action: "allow" as ZtnaAction, postureProfileId: null as number | null, schedule: "", enabled: true };
type PolicyForm = typeof EMPTY_POLICY;

function PolicyDialog(props: {
  initial: ZtnaPolicyDTO | null;
  apps: ZtnaAppDTO[];
  profiles: PostureProfileDTO[];
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const isEdit = props.initial !== null;
  const [form, setForm] = useState<PolicyForm>(
    props.initial
      ? {
          appId: props.initial.appId,
          subjectType: props.initial.subjectType,
          subjectRef: props.initial.subjectRef,
          action: props.initial.action,
          postureProfileId: props.initial.postureProfileId,
          schedule: props.initial.schedule,
          enabled: props.initial.enabled,
        }
      : EMPTY_POLICY,
  );

  const save = useMutation({
    mutationFn: () => {
      const body: CreatePolicyBody = { ...form, subjectRef: form.subjectRef.trim(), schedule: form.schedule.trim() };
      return isEdit ? ztnaApi.updatePolicy(props.initial!.id, body) : ztnaApi.createPolicy(body);
    },
    onSuccess: (policy) => {
      toastOk(isEdit ? "Access policy updated" : "Access policy created", `${policy.action} ${policy.subjectType}:${policy.subjectRef} → ${policy.appName}`);
      void queryClient.invalidateQueries({ queryKey: ZTNA_KEY });
      props.onClose();
    },
    onError: (err) => toastErr(err, isEdit ? "Could not update policy" : "Could not create policy"),
  });

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{isEdit ? "Edit access policy" : "New access policy"}</DialogTitle>
          <DialogDescription>Who may reach the application. Deny always wins over allow; device rules outrank user rules, which outrank group rules.</DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <FieldLabel>Application</FieldLabel>
              <Select value={form.appId ? String(form.appId) : undefined} onValueChange={(v) => setForm({ ...form, appId: Number(v) })}>
                <SelectTrigger aria-label="Application"><SelectValue placeholder="Select…" /></SelectTrigger>
                <SelectContent>
                  {props.apps.map((a) => (
                    <SelectItem key={a.id} value={String(a.id)}>{a.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel>Action</FieldLabel>
              <Select value={form.action} onValueChange={(v) => setForm({ ...form, action: v as ZtnaAction })}>
                <SelectTrigger aria-label="Action"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="allow">allow</SelectItem>
                  <SelectItem value="deny">deny</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <FieldLabel>Subject type</FieldLabel>
              <Select value={form.subjectType} onValueChange={(v) => setForm({ ...form, subjectType: v as ZtnaSubjectType })}>
                <SelectTrigger aria-label="Subject type"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {SUBJECT_TYPES.map((t) => (
                    <SelectItem key={t} value={t}>{t}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel hint={form.subjectType === "user" ? "username" : form.subjectType === "group" ? "group name" : "device id (MAC/agent id)"}>
                Subject
              </FieldLabel>
              <Input value={form.subjectRef} onChange={(e) => setForm({ ...form, subjectRef: e.target.value })} placeholder={form.subjectType === "device" ? "aa:bb:cc:dd:ee:ff" : "alice"} />
            </div>
          </div>
          <div>
            <FieldLabel hint="gate on device posture">Posture profile</FieldLabel>
            <Select
              value={form.postureProfileId === null ? "none" : String(form.postureProfileId)}
              onValueChange={(v) => setForm({ ...form, postureProfileId: v === "none" ? null : Number(v) })}
            >
              <SelectTrigger aria-label="Posture profile"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="none">none — no posture gate</SelectItem>
                {props.profiles.map((p) => (
                  <SelectItem key={p.id} value={String(p.id)}>{p.name}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <FieldLabel hint='e.g. "Mon-Fri 09:00-17:00", empty = always'>Schedule</FieldLabel>
            <Input value={form.schedule} onChange={(e) => setForm({ ...form, schedule: e.target.value })} placeholder="Mon-Fri 09:00-17:00" />
          </div>
          <div className="flex items-center justify-between rounded-lg border p-3">
            <Label htmlFor="policy-enabled" className="text-sm">Enabled</Label>
            <Switch id="policy-enabled" checked={form.enabled} onCheckedChange={(v) => setForm({ ...form, enabled: v })} />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={props.onClose}>Cancel</Button>
          <Button onClick={() => save.mutate()} disabled={save.isPending || !form.appId || !form.subjectRef.trim()}>
            {save.isPending ? "Saving…" : "Save"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function PoliciesTab({ apps, profiles }: { apps: ZtnaAppDTO[]; profiles: PostureProfileDTO[] }) {
  const queryClient = useQueryClient();
  const [appFilter, setAppFilter] = useState<string>("all");
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<ZtnaPolicyDTO | null>(null);
  const [deleting, setDeleting] = useState<ZtnaPolicyDTO | null>(null);

  const appId = appFilter === "all" ? undefined : Number(appFilter);
  const policiesQuery = useQuery({
    queryKey: [...ZTNA_KEY, "policies", appFilter],
    queryFn: () => ztnaApi.listPolicies(appId),
  });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ZTNA_KEY });

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => ztnaApi.updatePolicy(id, { enabled }),
    onSuccess: (policy) => {
      toastOk(policy.enabled ? "Policy enabled" : "Policy disabled", `${policy.action} ${policy.subjectType}:${policy.subjectRef}`);
      invalidate();
    },
    onError: (err) => toastErr(err, "Could not toggle policy"),
  });

  const remove = useMutation({
    mutationFn: (id: number) => ztnaApi.deletePolicy(id),
    onSuccess: () => {
      toastOk("Access policy deleted");
      setDeleting(null);
      invalidate();
    },
    onError: (err) => {
      toastErr(err, "Could not delete policy");
      setDeleting(null);
    },
  });

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-xs text-zinc-500 dark:text-zinc-400">Application</span>
          <Select value={appFilter} onValueChange={setAppFilter}>
            <SelectTrigger className="h-8 w-48" aria-label="Filter by application"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All applications</SelectItem>
              {apps.map((a) => (
                <SelectItem key={a.id} value={String(a.id)}>{a.name}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <Button size="sm" disabled={apps.length === 0} onClick={() => { setEditing(null); setDialogOpen(true); }}>
          <Icons.Plus className="mr-1 h-4 w-4" /> New policy
        </Button>
      </div>
      {policiesQuery.isLoading ? (
        <TableSkeleton rows={5} cols={7} />
      ) : policiesQuery.isError ? (
        <QueryError error={policiesQuery.error} onRetry={() => policiesQuery.refetch()} />
      ) : policiesQuery.data.length === 0 ? (
        <EmptyBlock
          icon={<Icons.KeyRound className="h-6 w-6" />}
          title={apps.length === 0 ? "Register an application first" : "No access policies yet"}
          description={apps.length === 0 ? "Access rules are scoped to registered ZTNA applications." : "Define who may reach an application — everything unmatched is denied by default."}
          action={
            apps.length === 0 ? undefined : (
              <Button size="sm" onClick={() => { setEditing(null); setDialogOpen(true); }}>
                <Icons.Plus className="mr-1 h-4 w-4" /> New policy
              </Button>
            )
          }
        />
      ) : (
        <div className="overflow-x-auto rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Application</TableHead>
                <TableHead>Subject</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Posture profile</TableHead>
                <TableHead>Schedule</TableHead>
                <TableHead>Enabled</TableHead>
                <TableHead className="w-20 text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {policiesQuery.data.map((p) => (
                <TableRow key={p.id}>
                  <TableCell className="font-medium">{p.appName}</TableCell>
                  <TableCell><SubjectBadge policy={p} /></TableCell>
                  <TableCell><ActionBadge action={p.action} /></TableCell>
                  <TableCell>
                    {p.postureProfileName ? (
                      <Badge variant="outline" className="gap-1 font-normal">
                        <Icons.ClipboardCheck className="h-3 w-3 text-zinc-400" />
                        {p.postureProfileName}
                      </Badge>
                    ) : (
                      <span className="text-xs text-zinc-400">—</span>
                    )}
                  </TableCell>
                  <TableCell>{p.schedule ? <span className="font-mono text-xs">{p.schedule}</span> : <span className="text-xs text-zinc-400">always</span>}</TableCell>
                  <TableCell>
                    <Switch
                      checked={p.enabled}
                      aria-label={`Toggle policy ${p.subjectRef}`}
                      disabled={toggle.isPending}
                      onCheckedChange={(v) => toggle.mutate({ id: p.id, enabled: v })}
                    />
                  </TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="icon" className="h-7 w-7" aria-label={`Edit policy for ${p.subjectRef}`} onClick={() => { setEditing(p); setDialogOpen(true); }}>
                      <Icons.Pencil className="h-3.5 w-3.5" />
                    </Button>
                    <Button variant="ghost" size="icon" className="h-7 w-7 text-rose-500 hover:text-rose-600" aria-label={`Delete policy for ${p.subjectRef}`} onClick={() => setDeleting(p)}>
                      <Icons.Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {dialogOpen && <PolicyDialog initial={editing} apps={apps} profiles={profiles} onClose={() => setDialogOpen(false)} />}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={`Delete ${deleting?.action ?? ""} policy for '${deleting?.subjectRef ?? ""}'?`}
        description="The subject falls back to the default deny for this application."
        loading={remove.isPending}
        onConfirm={() => deleting && remove.mutate(deleting.id)}
      />
    </div>
  );
}

// ── device posture tab ───────────────────────────────────────────────────────

const EMPTY_PROFILE = { name: "", checks: { osPatchMaxAgeDays: undefined as number | undefined, avRequired: false, diskEncryptRequired: false, firewallRequired: false } };
type ProfileForm = typeof EMPTY_PROFILE;

function ProfileDialog(props: {
  initial: PostureProfileDTO | null;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const isEdit = props.initial !== null;
  const [form, setForm] = useState<ProfileForm>(
    props.initial
      ? {
          name: props.initial.name,
          checks: {
            osPatchMaxAgeDays: props.initial.checks.osPatchMaxAgeDays,
            avRequired: props.initial.checks.avRequired === true,
            diskEncryptRequired: props.initial.checks.diskEncryptRequired === true,
            firewallRequired: props.initial.checks.firewallRequired === true,
          },
        }
      : EMPTY_PROFILE,
  );

  const save = useMutation({
    mutationFn: () => {
      const body: CreateProfileBody = { name: form.name.trim(), checks: form.checks };
      return isEdit ? ztnaApi.updateProfile(props.initial!.id, body) : ztnaApi.createProfile(body);
    },
    onSuccess: (profile) => {
      toastOk(isEdit ? "Posture profile updated" : "Posture profile created", profile.name);
      void queryClient.invalidateQueries({ queryKey: ZTNA_KEY });
      props.onClose();
    },
    onError: (err) => toastErr(err, isEdit ? "Could not update profile" : "Could not create profile"),
  });

  const noChecks = !form.checks.osPatchMaxAgeDays && !form.checks.avRequired && !form.checks.diskEncryptRequired && !form.checks.firewallRequired;
  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{isEdit ? "Edit posture profile" : "New posture profile"}</DialogTitle>
          <DialogDescription>Basic device checks (spec §4.4): OS patch age, antivirus, disk encryption, host firewall.</DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div>
            <FieldLabel>Name</FieldLabel>
            <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="corporate-laptop" />
          </div>
          <div className="rounded-lg border p-3">
            <div>
              <FieldLabel hint="days">Max OS patch age</FieldLabel>
              <Input
                type="number"
                min={1}
                max={365}
                placeholder="e.g. 30"
                value={form.checks.osPatchMaxAgeDays ?? ""}
                onChange={(e) => {
                  const v = e.target.value === "" ? undefined : Number(e.target.value);
                  setForm({ ...form, checks: { ...form.checks, osPatchMaxAgeDays: v && v > 0 ? v : undefined } });
                }}
              />
            </div>
            <div className="mt-3 space-y-2">
              {([
                ["avRequired", "Antivirus required"],
                ["diskEncryptRequired", "Disk encryption required"],
                ["firewallRequired", "Host firewall required"],
              ] as Array<[keyof ProfileForm["checks"], string]>).map(([key, label]) => (
                <div key={key} className="flex items-center justify-between">
                  <Label htmlFor={`chk-${key}`} className="text-sm">{label}</Label>
                  <Switch
                    id={`chk-${key}`}
                    checked={form.checks[key] === true}
                    onCheckedChange={(v) => setForm({ ...form, checks: { ...form.checks, [key]: v } })}
                  />
                </div>
              ))}
            </div>
          </div>
          {noChecks && <p className="text-xs text-amber-600 dark:text-amber-400">A profile with no requirements marks every device compliant — enable at least one check.</p>}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={props.onClose}>Cancel</Button>
          <Button onClick={() => save.mutate()} disabled={save.isPending || !form.name.trim()}>
            {save.isPending ? "Saving…" : "Save"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function RecordCheckDialog(props: { profiles: PostureProfileDTO[]; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [deviceId, setDeviceId] = useState("");
  const [profileId, setProfileId] = useState<number>(props.profiles[0]?.id ?? 0);
  const [results, setResults] = useState<Record<CheckKey, "pass" | "fail" | "unknown">>({
    osPatch: "unknown",
    av: "unknown",
    diskEncrypt: "unknown",
    firewall: "unknown",
  });

  const save = useMutation({
    mutationFn: () => ztnaApi.recordCheck({ deviceId: deviceId.trim(), profileId, results }),
    onSuccess: (check) => {
      toastOk("Posture check recorded", `${check.deviceId} → ${check.verdict}`);
      void queryClient.invalidateQueries({ queryKey: ZTNA_KEY });
      props.onClose();
    },
    onError: (err) => toastErr(err, "Could not record posture check"),
  });

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Record posture check</DialogTitle>
          <DialogDescription>Manual/agent check — the console's continuous validation re-evaluates it every 60 minutes.</DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div>
            <FieldLabel hint="MAC or agent id">Device id</FieldLabel>
            <Input value={deviceId} onChange={(e) => setDeviceId(e.target.value)} placeholder="aa:bb:cc:dd:ee:ff" />
          </div>
          <div>
            <FieldLabel>Posture profile</FieldLabel>
            <Select value={profileId ? String(profileId) : undefined} onValueChange={(v) => setProfileId(Number(v))}>
              <SelectTrigger aria-label="Posture profile"><SelectValue placeholder="Select…" /></SelectTrigger>
              <SelectContent>
                {props.profiles.map((p) => (
                  <SelectItem key={p.id} value={String(p.id)}>{p.name}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2 rounded-lg border p-3">
            <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">Observed results</p>
            {(Object.keys(CHECK_LABELS) as CheckKey[]).map((key) => (
              <div key={key} className="flex items-center justify-between gap-2">
                <span className="text-sm">{CHECK_LABELS[key]}</span>
                <Select value={results[key]} onValueChange={(v) => setResults({ ...results, [key]: v as "pass" | "fail" | "unknown" })}>
                  <SelectTrigger className="h-8 w-28" aria-label={`${CHECK_LABELS[key]} result`}><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="pass">pass</SelectItem>
                    <SelectItem value="fail">fail</SelectItem>
                    <SelectItem value="unknown">unknown</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            ))}
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={props.onClose}>Cancel</Button>
          <Button onClick={() => save.mutate()} disabled={save.isPending || !deviceId.trim() || !profileId}>
            {save.isPending ? "Recording…" : "Record check"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ProfileCards(props: {
  profiles: PostureProfileDTO[];
  onEdit: (p: PostureProfileDTO) => void;
  onDelete: (p: PostureProfileDTO) => void;
  onNew: () => void;
}) {
  if (props.profiles.length === 0) {
    return (
      <EmptyBlock
        icon={<Icons.ClipboardCheck className="h-6 w-6" />}
        title="No posture profiles"
        description="A profile sets the device requirements (OS patches, AV, disk encryption, firewall) an access policy can gate on."
        action={
          <Button size="sm" onClick={props.onNew}>
            <Icons.Plus className="mr-1 h-4 w-4" /> New profile
          </Button>
        }
      />
    );
  }
  return (
    <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
      {props.profiles.map((p) => (
        <Card key={p.id}>
          <CardContent className="space-y-2 p-4">
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <p className="truncate text-sm font-semibold">{p.name}</p>
                <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
                  {p.policyCount} attached polic{p.policyCount === 1 ? "y" : "ies"}
                </p>
              </div>
              <div className="flex shrink-0">
                <Button variant="ghost" size="icon" className="h-7 w-7" aria-label={`Edit profile ${p.name}`} onClick={() => props.onEdit(p)}>
                  <Icons.Pencil className="h-3.5 w-3.5" />
                </Button>
                <Button variant="ghost" size="icon" className="h-7 w-7 text-rose-500 hover:text-rose-600" aria-label={`Delete profile ${p.name}`} onClick={() => props.onDelete(p)}>
                  <Icons.Trash2 className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
            <Requirements checks={p.checks} />
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function PostureTab({ profiles }: { profiles: PostureProfileDTO[] }) {
  const queryClient = useQueryClient();
  const [profileDialog, setProfileDialog] = useState(false);
  const [editingProfile, setEditingProfile] = useState<PostureProfileDTO | null>(null);
  const [deletingProfile, setDeletingProfile] = useState<PostureProfileDTO | null>(null);
  const [checkDialog, setCheckDialog] = useState(false);
  const [page, setPage] = useState(1);

  const checksQuery = useQuery({
    queryKey: [...ZTNA_KEY, "checks", page],
    queryFn: () => ztnaApi.listChecks(page, 25),
  });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ZTNA_KEY });

  // Explicit continuous-validation sweep (audit fix F-d — GET /posture-checks
  // no longer mutates; the console advances due re-checks via this button).
  const runValidation = useMutation({
    mutationFn: () => ztnaApi.runValidation(),
    onSuccess: (res) => {
      toastOk(
        res.changed > 0 ? "Validation run — verdicts changed" : "Validation run — nothing changed",
        `${res.rechecked} device${res.rechecked === 1 ? "" : "s"} re-checked, ${res.changed} verdict flip${res.changed === 1 ? "" : "s"}`,
      );
      invalidate();
    },
    onError: (err) => toastErr(err, "Could not run validation"),
  });

  const removeProfile = useMutation({
    mutationFn: (id: number) => ztnaApi.deleteProfile(id),
    onSuccess: () => {
      toastOk("Posture profile deleted");
      setDeletingProfile(null);
      invalidate();
    },
    onError: (err) => {
      toastErr(err, "Could not delete profile");
      setDeletingProfile(null);
    },
  });

  const meta = checksQuery.data?.meta;
  const totalPages = meta ? Math.max(1, meta.totalPages) : 1;

  return (
    <div className="space-y-5">
      <section className="space-y-3">
        <div className="flex items-center justify-between gap-2">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-zinc-500">Posture profiles</h3>
          <Button size="sm" variant="outline" onClick={() => { setEditingProfile(null); setProfileDialog(true); }}>
            <Icons.Plus className="mr-1 h-4 w-4" /> New profile
          </Button>
        </div>
        <ProfileCards
          profiles={profiles}
          onEdit={(p) => { setEditingProfile(p); setProfileDialog(true); }}
          onDelete={(p) => setDeletingProfile(p)}
          onNew={() => { setEditingProfile(null); setProfileDialog(true); }}
        />
      </section>

      <section className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wide text-zinc-500">Device checks</h3>
            <p className="mt-0.5 text-[11px] text-zinc-400">
              Latest check per device — continuous validation re-runs stored results every 60 min (endpoint agent / WMI / SSH probe transport out of console scope).
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              disabled={runValidation.isPending}
              onClick={() => runValidation.mutate()}
            >
              <Icons.RefreshCw className={cn("mr-1 h-4 w-4", runValidation.isPending && "animate-spin")} />
              Run validation
            </Button>
            <Button size="sm" disabled={profiles.length === 0} onClick={() => setCheckDialog(true)}>
              <Icons.Stethoscope className="mr-1 h-4 w-4" /> Record check
            </Button>
          </div>
        </div>
        {checksQuery.isLoading ? (
          <TableSkeleton rows={4} cols={5} />
        ) : checksQuery.isError ? (
          <QueryError error={checksQuery.error} onRetry={() => checksQuery.refetch()} />
        ) : checksQuery.data.data.length === 0 ? (
          <EmptyBlock
            icon={<Icons.Stethoscope className="h-6 w-6" />}
            title="No device posture checks recorded"
            description="Record a manual check or wait for agent results — verdicts feed the posture gate on access policies."
            action={
              profiles.length === 0 ? undefined : (
                <Button size="sm" onClick={() => setCheckDialog(true)}>
                  <Icons.Stethoscope className="mr-1 h-4 w-4" /> Record check
                </Button>
              )
            }
          />
        ) : (
          <div className="max-h-96 overflow-y-auto rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Device</TableHead>
                  <TableHead>Profile</TableHead>
                  <TableHead>Verdict</TableHead>
                  <TableHead>Failed checks</TableHead>
                  <TableHead>Checked</TableHead>
                  <TableHead>Next re-check</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {checksQuery.data.data.map((c) => (
                  <TableRow key={c.id}>
                    <TableCell className="font-mono text-xs">{c.deviceId}</TableCell>
                    <TableCell className="text-xs">{c.profileName}</TableCell>
                    <TableCell><VerdictBadge verdict={c.verdict} /></TableCell>
                    <TableCell>
                      {c.failedChecks.length === 0 && c.unknownChecks.length === 0 ? (
                        <span className="text-xs text-zinc-400">—</span>
                      ) : (
                        <div className="flex flex-wrap gap-1">
                          {c.failedChecks.map((k) => (
                            <CheckChip key={`f-${k}`} check={k} state="fail" />
                          ))}
                          {c.unknownChecks.map((k) => (
                            <CheckChip key={`u-${k}`} check={k} state="unknown" />
                          ))}
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="text-xs text-zinc-500">{fmtDateTime(c.checkedAt)}</TableCell>
                    <TableCell className="text-xs text-zinc-500">{fmtDateTime(c.nextCheckAt)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
        {meta && meta.total > 0 ? (
          <div className="flex items-center justify-between text-xs text-zinc-500 dark:text-zinc-400">
            <span>
              {meta.total} device{meta.total === 1 ? "" : "s"} · page {meta.page}/{totalPages}
            </span>
            <div className="flex gap-1">
              <Button variant="outline" size="sm" className="h-7" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>
                <Icons.ChevronLeft className="h-3.5 w-3.5" /> Prev
              </Button>
              <Button variant="outline" size="sm" className="h-7" disabled={page >= totalPages} onClick={() => setPage((p) => Math.min(totalPages, p + 1))}>
                Next <Icons.ChevronRight className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>
        ) : null}
      </section>

      {profileDialog && <ProfileDialog initial={editingProfile} onClose={() => setProfileDialog(false)} />}
      {checkDialog && <RecordCheckDialog profiles={profiles} onClose={() => setCheckDialog(false)} />}
      <ConfirmDialog
        open={deletingProfile !== null}
        onOpenChange={(o) => !o && setDeletingProfile(null)}
        title={`Delete posture profile '${deletingProfile?.name ?? ""}'?`}
        description="Profiles attached to access policies cannot be deleted — detach them first."
        loading={removeProfile.isPending}
        onConfirm={() => deletingProfile && removeProfile.mutate(deletingProfile.id)}
      />
    </div>
  );
}

// ── access simulator ─────────────────────────────────────────────────────────

function SimulatorCard({ apps }: { apps: ZtnaAppDTO[] }) {
  const [appId, setAppId] = useState<number>(0);
  const [user, setUser] = useState("");
  const [groups, setGroups] = useState("");
  const [deviceId, setDeviceId] = useState("");
  const [result, setResult] = useState<ZtnaEvaluation | null>(null);

  const run = useMutation({
    mutationFn: () =>
      ztnaApi.evaluate({
        appId,
        subject: {
          user: user.trim() || undefined,
          groups: groups.split(",").map((g) => g.trim()).filter(Boolean),
          deviceId: deviceId.trim() || undefined,
        },
      }),
    onSuccess: (r) => setResult(r),
    onError: (err) => toastErr(err, "Evaluation failed"),
  });

  if (apps.length === 0) return null;
  return (
    <Card>
      <CardContent className="space-y-3 p-4">
        <div className="flex items-center gap-2">
          <Icons.FlaskConical className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
          <h3 className="text-sm font-semibold">Access Simulator</h3>
          <Badge variant="outline" className="border-zinc-300 bg-zinc-100 text-[10px] font-normal text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-400">
            POST /api/v1/ztna/evaluate
          </Badge>
        </div>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-5">
          <div>
            <FieldLabel>Application</FieldLabel>
            <Select value={appId ? String(appId) : undefined} onValueChange={(v) => { setAppId(Number(v)); setResult(null); }}>
              <SelectTrigger aria-label="Simulator application"><SelectValue placeholder="Select…" /></SelectTrigger>
              <SelectContent>
                {apps.map((a) => (
                  <SelectItem key={a.id} value={String(a.id)}>{a.name}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <FieldLabel hint="optional">User</FieldLabel>
            <Input value={user} onChange={(e) => setUser(e.target.value)} placeholder="alice" />
          </div>
          <div>
            <FieldLabel hint="comma-separated">Groups</FieldLabel>
            <Input value={groups} onChange={(e) => setGroups(e.target.value)} placeholder="engineering, oncall" />
          </div>
          <div>
            <FieldLabel hint="optional">Device id</FieldLabel>
            <Input value={deviceId} onChange={(e) => setDeviceId(e.target.value)} placeholder="aa:bb:cc:dd:ee:ff" />
          </div>
          <div className="flex items-end">
            <Button className="w-full" disabled={!appId || run.isPending} onClick={() => run.mutate()}>
              {run.isPending ? <Icons.Loader2 className="mr-1 h-4 w-4 animate-spin" /> : <Icons.Play className="mr-1 h-4 w-4" />}
              Simulate
            </Button>
          </div>
        </div>
        {result ? (
          <div className={cn("space-y-2 rounded-lg border p-3", result.decision === "allow" ? "border-emerald-500/40 bg-emerald-500/5" : "border-rose-500/40 bg-rose-500/5")}>
            <div className="flex flex-wrap items-center gap-2">
              <ActionBadge action={result.decision} />
              <span className="text-sm font-medium">{result.appName}</span>
              <VerdictBadge verdict={result.postureVerdict} />
              <span className="ml-auto text-[11px] text-zinc-400">
                {result.matchedPolicyId !== null ? `matched policy #${result.matchedPolicyId}${result.matchedPolicyRef ? ` (${result.matchedPolicyRef})` : ""}` : "no matching policy"}
              </span>
            </div>
            <p className="text-xs text-zinc-600 dark:text-zinc-300">{result.reason}</p>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

// ── view root ────────────────────────────────────────────────────────────────

export function ZtnaView() {
  const appsQuery = useQuery({ queryKey: [...ZTNA_KEY, "apps"], queryFn: ztnaApi.listApps });
  const profilesQuery = useQuery({ queryKey: [...ZTNA_KEY, "profiles"], queryFn: ztnaApi.listProfiles });
  const statsQuery = useQuery({ queryKey: [...ZTNA_KEY, "stats"], queryFn: ztnaApi.getStats, refetchInterval: 30_000 });

  const apps = appsQuery.data ?? [];
  const profiles = profilesQuery.data ?? [];

  return (
    <div className="mx-auto w-full max-w-7xl space-y-6 p-4 lg:p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Zero Trust Network Access</h1>
          <p className="mt-1 text-sm text-zinc-500 dark:text-zinc-400">
            Identity-based user-to-resource access with device posture gating and periodic re-validation (spec §4.4). No match → default deny.
          </p>
        </div>
        <Badge variant="outline" className="gap-1 border-zinc-500/30 bg-zinc-500/10 font-normal text-zinc-600 dark:text-zinc-300">
          <Icons.Fingerprint className="h-3 w-3" /> ZTNA basic
        </Badge>
      </div>

      {statsQuery.data ? <StatsStrip stats={statsQuery.data} /> : null}

      <Tabs defaultValue="applications">
        <TabsList>
          <TabsTrigger value="applications">
            <Icons.AppWindow className="mr-1.5 h-3.5 w-3.5" /> Applications
          </TabsTrigger>
          <TabsTrigger value="policies">
            <Icons.KeyRound className="mr-1.5 h-3.5 w-3.5" /> Access Policies
          </TabsTrigger>
          <TabsTrigger value="posture">
            <Icons.Stethoscope className="mr-1.5 h-3.5 w-3.5" /> Device Posture
          </TabsTrigger>
        </TabsList>
        <TabsContent value="applications" className="mt-4">
          <AppsTab />
        </TabsContent>
        <TabsContent value="policies" className="mt-4">
          <PoliciesTab apps={apps} profiles={profiles} />
        </TabsContent>
        <TabsContent value="posture" className="mt-4">
          <PostureTab profiles={profiles} />
        </TabsContent>
      </Tabs>

      <SimulatorCard apps={apps} />
    </div>
  );
}
