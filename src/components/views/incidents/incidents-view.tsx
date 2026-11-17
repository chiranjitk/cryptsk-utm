"use client";

/**
 * Incident Response view (Phase 3 §3.5) — SOC console for the incident
 * workflow: stats strip (open by severity / created 7d / MTTR), filterable
 * incident table with the full action palette (timeline sheet, transition
 * dropdown bound to the allowed status graph, assign dialog, confirm-first
 * block-source that materializes a firewall deny rule), and a create dialog
 * with a "from last IPS event" convenience picker that prefills
 * title/severity/srcIps and the sourceRef pointer for dedupe.
 * Atoms reused from fw-ui (table states, toasts, ConfirmDialog, density),
 * ips-ui (severity recipes) — no new design language. Palette per UI_DESIGN_SYSTEM §2.
 */

import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
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
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
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
import { SeverityBadge, SEVERITY_TONE } from "../ips/ips-ui";
import { ipsApi } from "../ips/ips-api";
import {
  allowedNext,
  fmtDateTime,
  incidentsApi,
  qs,
  SEVERITIES,
  SOURCES,
  STATUSES,
  type IncidentDTO,
  type IncidentSeverity,
  type IncidentSource,
  type IncidentStatus,
  type TimelineAction,
} from "./incidents-api";

const LIMIT = 25;

const EMPTY_FILTERS = { q: "", status: "", severity: "", source: "" };
type Filters = typeof EMPTY_FILTERS;

// ── local chips (colors only — palette per UI_DESIGN_SYSTEM §2) ─────────────

const STATUS_BADGE: Record<IncidentStatus, { cls: string; icon: React.ComponentType<{ className?: string }> }> = {
  new: { cls: "border-zinc-400/60 bg-zinc-500/5 text-zinc-600 dark:text-zinc-300", icon: Icons.CircleDashed },
  investigating: { cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400", icon: Icons.Search },
  contained: { cls: "border-orange-500/40 bg-orange-500/10 text-orange-600 dark:text-orange-400", icon: Icons.ShieldHalf },
  resolved: { cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400", icon: Icons.CircleCheck },
};

function StatusBadge({ status }: { status: IncidentStatus }) {
  const def = STATUS_BADGE[status] ?? STATUS_BADGE.new;
  const Icon = def.icon;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium capitalize", def.cls)}>
      <Icon className="h-3 w-3" />
      {status}
    </Badge>
  );
}

const SOURCE_CHIP: Record<IncidentSource, { icon: React.ComponentType<{ className?: string }>; label: string }> = {
  manual: { icon: Icons.User, label: "manual" },
  ips_event: { icon: Icons.Siren, label: "ips" },
  dlp_incident: { icon: Icons.FileSearch, label: "dlp" },
  dns_tunnel: { icon: Icons.Network, label: "dns" },
  threat_intel: { icon: Icons.Radar, label: "ti" },
  ai: { icon: Icons.Sparkles, label: "ai" },
};

function SourceChip({ source }: { source: IncidentSource }) {
  const def = SOURCE_CHIP[source] ?? SOURCE_CHIP.manual;
  const Icon = def.icon;
  return (
    <Badge
      variant="outline"
      className="gap-1 border-zinc-300 bg-zinc-100 font-medium text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
      title={`source: ${source}`}
    >
      <Icon className="h-3 w-3" />
      {def.label}
    </Badge>
  );
}

const ACTION_CHIP: Record<TimelineAction, { cls: string; icon: React.ComponentType<{ className?: string }> }> = {
  created: { cls: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300", icon: Icons.Flag },
  status_change: { cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400", icon: Icons.ArrowRight },
  assigned: { cls: "border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300", icon: Icons.UserPlus },
  blocked: { cls: "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400", icon: Icons.Ban },
  quarantine: { cls: "border-orange-500/40 bg-orange-500/10 text-orange-600 dark:text-orange-400", icon: Icons.ShieldAlert },
  note: { cls: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300", icon: Icons.StickyNote },
  resolved: { cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400", icon: Icons.CircleCheck },
};

function TimelineActionChip({ action }: { action: TimelineAction }) {
  const def = ACTION_CHIP[action] ?? ACTION_CHIP.note;
  const Icon = def.icon;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium", def.cls)}>
      <Icon className="h-3 w-3" />
      {action.replace("_", " ")}
    </Badge>
  );
}

// ── stats strip ─────────────────────────────────────────────────────────────

function StatCard(props: { label: string; value: React.ReactNode; hint?: string; className?: string }) {
  return (
    <div className={cn("min-w-0 rounded-lg border border-zinc-200 px-3 py-2 dark:border-zinc-800", props.className)}>
      <p className="truncate text-[11px] font-medium uppercase tracking-wide text-zinc-500">{props.label}</p>
      <p className="mt-0.5 text-lg font-semibold tabular-nums" title={props.hint}>
        {props.value}
      </p>
    </div>
  );
}

function StatsStrip() {
  const query = useQuery({ queryKey: ["incidents", "stats"], queryFn: () => incidentsApi.getStats() });
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
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
      <StatCard label="Open incidents" value={s.openTotal} />
      {SEVERITIES.map((sev) => (
        <div key={sev} className="min-w-0 rounded-lg border border-zinc-200 px-3 py-2 dark:border-zinc-800">
          <p className="flex items-center gap-1.5 truncate text-[11px] font-medium uppercase tracking-wide text-zinc-500">
            <span className={cn("inline-block h-2 w-2 shrink-0 rounded-full", SEVERITY_TONE[sev].dot)} />
            {sev}
          </p>
          <p className="mt-0.5 text-lg font-semibold tabular-nums">{s.openBySeverity[sev]}</p>
        </div>
      ))}
      <StatCard label="Created 7d" value={s.created7d} />
      <StatCard
        label="Mean time to resolve"
        value={s.mttrHours === null ? "—" : `${s.mttrHours} h`}
        hint={`${s.resolvedTotal} resolved incident${s.resolvedTotal === 1 ? "" : "s"}`}
      />
    </div>
  );
}

// ── inline pager (server-side pagination — meta.totalPages drives it) ───────

function Pager(props: {
  page: number;
  totalPages: number;
  total: number;
  onPage: (page: number) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-2 border-t border-zinc-200 px-3 py-2 text-xs text-zinc-500 dark:border-zinc-800">
      <span className="tabular-nums">
        page {props.page} / {props.totalPages} · {props.total.toLocaleString()} incident
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

// ── dialogs ─────────────────────────────────────────────────────────────────

function AssignDialog(props: {
  incident: IncidentDTO;
  onClose: () => void;
  onDone: () => void;
}) {
  const [value, setValue] = useState(props.incident.assignedTo ?? "");
  const [busy, setBusy] = useState(false);
  const queryClient = useQueryClient();

  const submit = async () => {
    setBusy(true);
    try {
      await incidentsApi.assign(props.incident.id, value.trim() || null);
      toastOk(
        value.trim() ? "Incident assigned" : "Assignment cleared",
        `${props.incident.ref} ${value.trim() ? `assigned to ${value.trim()}` : "is now unassigned"}`,
      );
      await queryClient.invalidateQueries({ queryKey: ["incidents"] });
      setBusy(false);
      props.onClose();
      props.onDone();
    } catch (err) {
      toastErr(err, "Assign failed");
      setBusy(false);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && props.onClose()}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle className="text-base">Assign incident {props.incident.ref}</DialogTitle>
          <DialogDescription>Set the analyst responsible for this incident. Clear the field to unassign.</DialogDescription>
        </DialogHeader>
        <div className="space-y-2">
          <Label htmlFor="incident-assignee">Assignee</Label>
          <Input
            id="incident-assignee"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="username"
            autoFocus
            onKeyDown={(e) => e.key === "Enter" && !busy && void submit()}
          />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={props.onClose} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={busy}>
            {busy ? "Saving…" : "Save"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** JSON sourceRef pointer for an IPS alert — stable key for fromAlert dedupe. */
function ipsEventSourceRef(eventId: number, sid: string | null): string {
  return JSON.stringify({ kind: "ips_event", id: eventId, sid: sid ?? null });
}

function CreateIncidentDialog(props: { onClose: () => void; onDone: () => void }) {
  const [fromEvent, setFromEvent] = useState("any");
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState<IncidentSeverity>("medium");
  const [description, setDescription] = useState("");
  const [assignee, setAssignee] = useState("");
  const [busy, setBusy] = useState(false);
  const queryClient = useQueryClient();

  // recent IPS events — the convenience picker (read-only ips area)
  const eventsQuery = useQuery({
    queryKey: ["incidents", "create", "ips-events"],
    queryFn: () => ipsApi.listEvents("limit=20&page=1"),
  });
  const events = eventsQuery.data?.data ?? [];
  const selectedEvent = events.find((e) => String(e.id) === fromEvent) ?? null;

  const applyEventPrefill = (eventId: string) => {
    setFromEvent(eventId);
    const ev = events.find((e) => String(e.id) === eventId);
    if (!ev) return;
    setTitle(`IPS event sid ${ev.sid ?? `#${ev.id}`}: ${ev.message ?? "signature alert"}`.slice(0, 200));
    setSeverity(ev.severity);
    setDescription(ev.message ? `${ev.category ?? "ips"} — ${ev.message}` : `${ev.category ?? "ips"} alert`);
  };

  const reset = () => {
    setFromEvent("any");
    setTitle("");
    setSeverity("medium");
    setDescription("");
    setAssignee("");
  };

  const submit = async () => {
    if (!title.trim()) return;
    setBusy(true);
    try {
      const detail: Record<string, unknown> = { description: description.trim() || null };
      const srcIp = selectedEvent?.srcIp ?? null;
      if (srcIp) detail.srcIps = [srcIp];
      const res = await incidentsApi.create({
        title: title.trim(),
        source: selectedEvent ? "ips_event" : "manual",
        sourceRef: selectedEvent ? ipsEventSourceRef(selectedEvent.id, selectedEvent.sid) : null,
        severity,
        assignedTo: assignee.trim() || null,
        detail,
      });
      if (res.deduped) {
        toastOk("Existing open incident", `${res.incident.ref} already tracks this alert — returned unchanged`);
      } else {
        toastOk("Incident created", `${res.incident.ref} opened (${selectedEvent ? "ips_event" : "manual"})`);
      }
      await queryClient.invalidateQueries({ queryKey: ["incidents"] });
      setBusy(false);
      reset();
      props.onClose();
      props.onDone();
    } catch (err) {
      toastErr(err, "Create incident failed");
      setBusy(false);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && props.onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-base">Create incident</DialogTitle>
          <DialogDescription>
            Open a case manually or prefill from a recent IPS alert. Alert-derived incidents dedupe against open cases.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          <div className="grid gap-1.5">
            <Label htmlFor="incident-from-event">From last IPS event (optional)</Label>
            <Select value={fromEvent} onValueChange={applyEventPrefill}>
              <SelectTrigger id="incident-from-event" className="w-full">
                <SelectValue placeholder="manual incident" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="any">manual incident (no prefill)</SelectItem>
                {events.map((e) => (
                  <SelectItem key={e.id} value={String(e.id)}>
                    <span className="font-mono text-xs">sid {e.sid ?? `#${e.id}`}</span>
                    <span className="ml-2 text-xs text-zinc-500">{e.message ?? e.category ?? "alert"}</span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {selectedEvent?.srcIp && (
              <p className="text-[11px] text-zinc-500">
                source <span className="font-mono">{selectedEvent.srcIp}</span> becomes a blockable srcIp on the incident.
              </p>
            )}
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="incident-title">Title</Label>
            <Input
              id="incident-title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Short summary of what happened"
              autoFocus
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="incident-severity">Severity</Label>
              <Select value={severity} onValueChange={(v) => setSeverity(v as IncidentSeverity)}>
                <SelectTrigger id="incident-severity" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SEVERITIES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {s}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="incident-assignee">Assignee (optional)</Label>
              <Input id="incident-assignee" value={assignee} onChange={(e) => setAssignee(e.target.value)} placeholder="username" />
            </div>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="incident-description">Description</Label>
            <Textarea
              id="incident-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Context, affected hosts, first observations…"
              rows={3}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={props.onClose} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={busy || !title.trim()}>
            {busy ? "Creating…" : "Create incident"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── timeline sheet ──────────────────────────────────────────────────────────

function TimelineSheet(props: {
  incident: IncidentDTO;
  onClose: () => void;
}) {
  const [note, setNote] = useState("");
  const [busyNote, setBusyNote] = useState(false);
  const queryClient = useQueryClient();

  const detailQuery = useQuery({
    queryKey: ["incidents", "detail", props.incident.id],
    queryFn: () => incidentsApi.get(props.incident.id),
  });
  const incident = detailQuery.data ?? props.incident;
  const timeline = incident.timeline ?? [];

  const submitNote = async () => {
    if (!note.trim()) return;
    setBusyNote(true);
    try {
      await incidentsApi.addNote(props.incident.id, note.trim());
      toastOk("Note added", `${props.incident.ref} timeline updated`);
      setNote("");
      await queryClient.invalidateQueries({ queryKey: ["incidents"] });
      setBusyNote(false);
    } catch (err) {
      toastErr(err, "Add note failed");
      setBusyNote(false);
    }
  };

  return (
    <Sheet open onOpenChange={(open) => !open && props.onClose()}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-md">
        <SheetHeader>
          <SheetTitle className="flex flex-wrap items-center gap-2 text-base">
            <span className="font-mono">{incident.ref}</span>
            <SeverityBadge severity={incident.severity} />
            <StatusBadge status={incident.status} />
          </SheetTitle>
          <SheetDescription className="text-sm text-zinc-600 dark:text-zinc-300">{incident.title}</SheetDescription>
        </SheetHeader>
        <div className="px-4 pb-6">
          <div className="mb-4 rounded-lg border border-zinc-200 p-3 text-xs dark:border-zinc-800">
            <div className="flex items-start justify-between gap-3 py-0.5">
              <span className="shrink-0 text-zinc-500">Source</span>
              <span className="font-mono">{incident.sourceRef ?? incident.source}</span>
            </div>
            <div className="flex items-start justify-between gap-3 py-0.5">
              <span className="shrink-0 text-zinc-500">Source IPs</span>
              <span className="font-mono">{incident.detail.srcIps?.length ? incident.detail.srcIps.join(", ") : "—"}</span>
            </div>
            <div className="flex items-start justify-between gap-3 py-0.5">
              <span className="shrink-0 text-zinc-500">Created</span>
              <span>{fmtDateTime(incident.createdAt)}</span>
            </div>
            <div className="flex items-start justify-between gap-3 py-0.5">
              <span className="shrink-0 text-zinc-500">Resolved</span>
              <span>{fmtDateTime(incident.resolvedAt)}</span>
            </div>
            {incident.detail.description && (
              <p className="mt-2 border-t border-zinc-100 pt-2 text-zinc-600 dark:border-zinc-800 dark:text-zinc-300">
                {incident.detail.description}
              </p>
            )}
            {incident.detail.blockedRuleId && (
              <p className="mt-2 flex items-center gap-1.5 border-t border-zinc-100 pt-2 text-rose-600 dark:border-zinc-800 dark:text-rose-400">
                <Icons.Ban className="h-3.5 w-3.5" />
                source blocked — rule #{incident.detail.blockedRuleId}, object #{incident.detail.blockedAddressId ?? "—"}
              </p>
            )}
          </div>

          <p className="mb-2 text-xs font-medium uppercase tracking-wide text-zinc-500">Timeline</p>
          {detailQuery.isLoading ? (
            <p className="py-4 text-xs text-zinc-400">Loading timeline…</p>
          ) : timeline.length === 0 ? (
            <p className="py-4 text-xs text-zinc-400">No timeline entries.</p>
          ) : (
            <ol className="relative space-y-3 border-l border-zinc-200 pl-5 dark:border-zinc-800">
              {timeline.map((t) => (
                <li key={t.id} className="relative">
                  <span className="absolute -left-[26px] top-1 flex h-3 w-3 items-center justify-center rounded-full border border-zinc-300 bg-white dark:border-zinc-600 dark:bg-zinc-900">
                    <span className={cn("h-1.5 w-1.5 rounded-full", SEVERITY_TONE.info.dot)} />
                  </span>
                  <div className="flex flex-wrap items-center gap-1.5">
                    <TimelineActionChip action={t.action} />
                    <span className="text-xs font-medium">{t.actor}</span>
                    <span className="text-[11px] text-zinc-400">{fmtDateTime(t.createdAt)}</span>
                  </div>
                  {t.detail && <p className="mt-0.5 whitespace-pre-wrap text-xs text-zinc-600 dark:text-zinc-300">{t.detail}</p>}
                </li>
              ))}
            </ol>
          )}

          <div className="mt-4 grid gap-1.5 border-t border-zinc-200 pt-4 dark:border-zinc-800">
            <Label htmlFor="incident-note">Add note</Label>
            <Textarea
              id="incident-note"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              rows={2}
              placeholder="Observation, containment step, follow-up…"
            />
            <div className="flex justify-end">
              <Button size="sm" onClick={() => void submitNote()} disabled={busyNote || !note.trim()}>
                {busyNote ? "Adding…" : "Add note"}
              </Button>
            </div>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
}

// ── row actions ─────────────────────────────────────────────────────────────

function RowActions(props: {
  incident: IncidentDTO;
  onTimeline: (incident: IncidentDTO) => void;
  onAssign: (incident: IncidentDTO) => void;
  onBlockConfirm: (incident: IncidentDTO) => void;
}) {
  const r = props.incident;
  const next = allowedNext(r.status);
  const srcIp = r.detail.srcIps?.[0];
  const blockDisabled = !srcIp || Boolean(r.detail.blockedRuleId);

  return (
    <div className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
      <TooltipProvider delayDuration={200}>
        <Tooltip>
          <TooltipTrigger asChild>
            <Button variant="ghost" size="sm" className="h-7 px-2 text-xs" onClick={() => props.onTimeline(r)} aria-label={`Timeline for ${r.ref}`}>
              <Icons.History className="h-3.5 w-3.5" />
              Timeline
            </Button>
          </TooltipTrigger>
          <TooltipContent>Workflow timeline</TooltipContent>
        </Tooltip>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              className="h-7 gap-1 px-2 text-xs"
              disabled={next.length === 0}
              aria-label={`Transition ${r.ref}`}
            >
              <Icons.ArrowRight className="h-3.5 w-3.5" />
              Move
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-44">
            <DropdownMenuLabel className="text-xs">Workflow transition</DropdownMenuLabel>
            <DropdownMenuSeparator />
            {next.map((s) => (
              <TransitionItem key={s} incident={r} target={s} />
            ))}
          </DropdownMenuContent>
        </DropdownMenu>

        <Button variant="ghost" size="sm" className="h-7 px-2 text-xs" onClick={() => props.onAssign(r)} aria-label={`Assign ${r.ref}`}>
          <Icons.UserPlus className="h-3.5 w-3.5" />
          Assign
        </Button>

        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              className="h-7 gap-1 px-2 text-xs text-rose-600 dark:text-rose-400"
              disabled={blockDisabled}
              onClick={() => props.onBlockConfirm(r)}
              aria-label={`Block source of ${r.ref}`}
            >
              <Icons.Ban className="h-3.5 w-3.5" />
              Block
            </Button>
          </TooltipTrigger>
          <TooltipContent>
            {r.detail.blockedRuleId
              ? `Source already blocked (rule #${r.detail.blockedRuleId})`
              : srcIp
                ? `Create deny rule for ${srcIp}`
                : "Incident detail has no srcIps to block"}
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    </div>
  );
}

function TransitionItem(props: { incident: IncidentDTO; target: IncidentStatus }) {
  const [busy, setBusy] = useState(false);
  const queryClient = useQueryClient();
  const go = async () => {
    setBusy(true);
    try {
      await incidentsApi.transition(props.incident.id, props.target);
      toastOk("Incident updated", `${props.incident.ref} moved to ${props.target}`);
      await queryClient.invalidateQueries({ queryKey: ["incidents"] });
    } catch (err) {
      toastErr(err, "Transition failed");
    } finally {
      setBusy(false);
    }
  };
  return (
    <DropdownMenuItem disabled={busy} onClick={() => void go()}>
      <Icons.ArrowRight className="mr-1.5 h-3.5 w-3.5" />
      {props.target === "resolved" ? "Mark resolved" : `Move to ${props.target}`}
    </DropdownMenuItem>
  );
}

// ── main view ───────────────────────────────────────────────────────────────

export function IncidentsView() {
  const [inputs, setInputs] = useState<Filters>(EMPTY_FILTERS);
  const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS); // applied
  const [page, setPage] = useState(1);
  const [density] = useTableDensity("incidents");
  const [createOpen, setCreateOpen] = useState(false);
  const [timelineFor, setTimelineFor] = useState<IncidentDTO | null>(null);
  const [assignFor, setAssignFor] = useState<IncidentDTO | null>(null);
  const [blockFor, setBlockFor] = useState<IncidentDTO | null>(null);
  const [blockBusy, setBlockBusy] = useState(false);
  const queryClient = useQueryClient();

  const commitText = () => {
    setFilters((cur) => (cur.q === inputs.q ? cur : { ...cur, q: inputs.q }));
    setPage(1);
  };

  const applyFilter = (patch: Partial<Filters>) => {
    setInputs({ ...inputs, ...patch });
    setFilters({ ...inputs, ...patch });
    setPage(1);
  };

  const params = useMemo(() => qs({ ...filters, page, limit: LIMIT }), [filters, page]);
  const query = useQuery({
    queryKey: ["incidents", "list", filters, page],
    queryFn: () => incidentsApi.list(params),
  });

  const rows = query.data?.data ?? [];
  const meta = query.data?.meta;

  const confirmBlock = async () => {
    if (!blockFor) return;
    setBlockBusy(true);
    try {
      const res = await incidentsApi.blockSource(blockFor.id);
      toastOk(
        "Source blocked",
        `${res.incident.ref}: deny rule #${res.firewallRuleId} for ${res.incident.detail.srcIps?.[0] ?? "source"} created`,
      );
      await queryClient.invalidateQueries({ queryKey: ["incidents"] });
      setBlockBusy(false);
      setBlockFor(null);
    } catch (err) {
      toastErr(err, "Block source failed");
      setBlockBusy(false);
    }
  };

  return (
    <div className="grid gap-3">
      <StatsStrip />

      {/* filter bar */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative">
          <Icons.Search className="absolute left-2.5 top-3 lg:top-2.5 h-4 w-4 text-zinc-400" />
          <Input
            value={inputs.q}
            onChange={(e) => setInputs({ ...inputs, q: e.target.value })}
            onKeyDown={(e) => e.key === "Enter" && commitText()}
            onBlur={commitText}
            placeholder="Search ref/title/assignee…"
            className="h-11 w-60 pl-8 lg:h-9"
            aria-label="Search incidents"
          />
        </div>
        <Select value={filters.status || "any"} onValueChange={(v) => applyFilter({ status: v === "any" ? "" : v })}>
          <SelectTrigger className="h-11 w-36 lg:h-9" aria-label="Status filter">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="any">any status</SelectItem>
            {STATUSES.map((s) => (
              <SelectItem key={s} value={s}>
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={filters.severity || "any"} onValueChange={(v) => applyFilter({ severity: v === "any" ? "" : v })}>
          <SelectTrigger className="h-11 w-36 lg:h-9" aria-label="Severity filter">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="any">any severity</SelectItem>
            {SEVERITIES.map((s) => (
              <SelectItem key={s} value={s}>
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={filters.source || "any"} onValueChange={(v) => applyFilter({ source: v === "any" ? "" : v })}>
          <SelectTrigger className="h-11 w-40 lg:h-9" aria-label="Source filter">
            <SelectValue placeholder="Source" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="any">any source</SelectItem>
            {SOURCES.map((s) => (
              <SelectItem key={s} value={s}>
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <div className="ml-auto flex items-center gap-2">
          <Button className="h-11 gap-1.5 lg:h-9" onClick={() => setCreateOpen(true)}>
            <Icons.Flag className="h-4 w-4" />
            New incident
          </Button>
          <DensityToggle storageKey="incidents" label="Incident table density" />
        </div>
      </div>

      {/* table */}
      <div className="min-w-0 rounded-lg border border-zinc-200 dark:border-zinc-800">
        {query.isLoading ? (
          <TableSkeleton rows={8} cols={7} />
        ) : query.isError ? (
          <QueryError error={query.error} onRetry={() => void query.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyBlock
            icon={<Icons.Flag className="h-6 w-6" />}
            title="No incidents match this filter"
            description="Open one from an IPS alert or create a manual case."
            action={
              <Button size="sm" className="mt-2 gap-1.5" onClick={() => setCreateOpen(true)}>
                <Icons.Flag className="h-3.5 w-3.5" />
                New incident
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
                    <TableHead>Ref</TableHead>
                    <TableHead>Title</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Assignee</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead className="w-56 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((r) => (
                    <TableRow key={r.id} className="cursor-pointer" onClick={() => setTimelineFor(r)}>
                      <TableCell className="whitespace-nowrap font-mono text-xs">{r.ref}</TableCell>
                      <TableCell
                        className="max-w-64 min-w-0 truncate text-sm"
                        title={r.detail.description ?? r.title}
                      >
                        {r.title}
                      </TableCell>
                      <TableCell>
                        <SourceChip source={r.source} />
                      </TableCell>
                      <TableCell>
                        <SeverityBadge severity={r.severity} />
                      </TableCell>
                      <TableCell>
                        <StatusBadge status={r.status} />
                      </TableCell>
                      <TableCell className="text-xs">{r.assignedTo ?? <span className="text-zinc-400">unassigned</span>}</TableCell>
                      <TableCell className="whitespace-nowrap text-xs tabular-nums">{fmtDateTime(r.createdAt)}</TableCell>
                      <TableCell className="text-right">
                        <RowActions
                          incident={r}
                          onTimeline={setTimelineFor}
                          onAssign={setAssignFor}
                          onBlockConfirm={setBlockFor}
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            {meta && <Pager page={meta.page} totalPages={meta.totalPages} total={meta.total} onPage={setPage} />}
          </>
        )}
      </div>

      {/* dialogs + sheet */}
      {createOpen && <CreateIncidentDialog onClose={() => setCreateOpen(false)} onDone={() => undefined} />}
      {assignFor && <AssignDialog incident={assignFor} onClose={() => setAssignFor(null)} onDone={() => undefined} />}
      {timelineFor && <TimelineSheet incident={timelineFor} onClose={() => setTimelineFor(null)} />}
      {blockFor && (
        <ConfirmDialog
          open
          onOpenChange={(open) => !open && !blockBusy && setBlockFor(null)}
          title={`Block source of ${blockFor.ref}?`}
          description={`Creates an ip address object for ${
            blockFor.detail.srcIps?.[0] ?? "the source"
          } plus a top-priority deny firewall rule ('INC ${blockFor.ref} auto-block'). The rule is logged in the incident timeline and can be reviewed under Firewall → Rules.`}
          confirmLabel="Block source"
          loading={blockBusy}
          onConfirm={() => void confirmBlock()}
        />
      )}
    </div>
  );
}
