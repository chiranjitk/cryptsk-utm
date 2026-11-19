"use client";

/**
 * SOAR view (Phase 4 §4.6) — automated response playbook console: stats chips
 * strip, Playbooks tab (table with live enabled switch, run-now, edit and
 * delete + a create/edit dialog with a dynamic ordered action builder) and a
 * Playbook Runs tab (run ledger with status filter, expandable per-step
 * results). Atoms reused from fw-ui (table states, toasts, ConfirmDialog);
 * palette per UI_DESIGN_SYSTEM §2 — no indigo/blue.
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import { ConfirmDialog, EmptyBlock, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";
import {
  ACTION_KINDS,
  BLOCK_DIRECTIONS,
  fmtDateTime,
  fmtDuration,
  qs,
  SEVERITIES,
  soarApi,
  SOURCES,
  TRIGGER_KINDS,
  RUN_STATUSES,
  type BlockDirection,
  type SoarAction,
  type SoarActionKind,
  type SoarPlaybookDTO,
  type SoarRunDTO,
  type SoarRunStatus,
  type SoarSeverity,
  type SoarTriggerKind,
} from "./soar-api";

const RUNS_LIMIT = 25;

// ── badge recipes (colors only — palette per UI_DESIGN_SYSTEM §2) ───────────

const TRIGGER_BADGE: Record<SoarTriggerKind, { cls: string; icon: React.ComponentType<{ className?: string }>; label: string }> = {
  incident_created: { cls: "border-zinc-400/60 bg-zinc-500/5 text-zinc-600 dark:text-zinc-300", icon: Icons.Flag, label: "incident created" },
  incident_severity: { cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400", icon: Icons.TriangleAlert, label: "incident severity" },
  dlp_incident: { cls: "border-orange-500/40 bg-orange-500/10 text-orange-600 dark:text-orange-400", icon: Icons.FileSearch, label: "dlp incident" },
  dns_tunnel: { cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400", icon: Icons.Network, label: "dns tunnel" },
  ioc_hit: { cls: "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400", icon: Icons.Radar, label: "ioc hit" },
};

function TriggerBadge({ kind }: { kind: SoarTriggerKind }) {
  const def = TRIGGER_BADGE[kind] ?? TRIGGER_BADGE.incident_created;
  const Icon = def.icon;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium", def.cls)}>
      <Icon className="h-3 w-3" />
      {def.label}
    </Badge>
  );
}

const RUN_BADGE: Record<SoarRunStatus, { cls: string; icon: React.ComponentType<{ className?: string }> }> = {
  running: { cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400", icon: Icons.Loader },
  success: { cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400", icon: Icons.CircleCheck },
  failed: { cls: "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400", icon: Icons.CircleX },
  skipped: { cls: "border-zinc-400/60 bg-zinc-500/5 text-zinc-600 dark:text-zinc-300", icon: Icons.SkipForward },
};

function RunStatusBadge({ status }: { status: string }) {
  const def = RUN_BADGE[status as SoarRunStatus] ?? RUN_BADGE.skipped;
  const Icon = def.icon;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium capitalize", def.cls)}>
      <Icon className="h-3 w-3" />
      {status}
    </Badge>
  );
}

function StepStatusIcon({ status }: { status: string }) {
  if (status === "success") return <Icons.CircleCheck className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />;
  if (status === "failed") return <Icons.CircleX className="h-3.5 w-3.5 text-rose-600 dark:text-rose-400" />;
  return <Icons.SkipForward className="h-3.5 w-3.5 text-zinc-400" />;
}

const ACTION_LABEL: Record<SoarActionKind, { icon: React.ComponentType<{ className?: string }>; label: string }> = {
  block_ip: { icon: Icons.Ban, label: "Block IP" },
  notify: { icon: Icons.Bell, label: "Notify" },
  create_incident: { icon: Icons.Flag, label: "Create incident" },
  delay: { icon: Icons.Hourglass, label: "Delay" },
  webhook: { icon: Icons.Webhook, label: "Webhook" },
};

function ActionChip({ kind }: { kind: string }) {
  const def = ACTION_LABEL[kind as SoarActionKind] ?? { icon: Icons.Zap, label: kind };
  const Icon = def.icon;
  return (
    <Badge variant="outline" className="gap-1 border-zinc-300 bg-zinc-100 font-medium text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
      <Icon className="h-3 w-3" />
      {def.label}
    </Badge>
  );
}

// ── stats strip ─────────────────────────────────────────────────────────────

function StatChip(props: { label: string; value: React.ReactNode; hint?: string; className?: string }) {
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
  const query = useQuery({ queryKey: ["soar", "stats"], queryFn: () => soarApi.getStats() });
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
      <StatChip label="Playbooks" value={s.playbooks.total} hint={`${s.playbooks.enabled} enabled`} />
      <StatChip label="Runs total" value={s.runs.total} />
      <StatChip label="Runs 7d" value={s.runs.last7d} />
      <StatChip
        label="Success rate"
        value={s.runs.successRate === null ? "—" : `${s.runs.successRate}%`}
        hint={`${s.runs.success} success / ${s.runs.failed} failed (terminal runs)`}
      />
      <StatChip label="Failed" value={s.runs.failed} />
      <StatChip label="Skipped (dedupe)" value={s.runs.skipped} hint={`${s.runs.running} currently running`} />
    </div>
  );
}

// ── pager (server-side pagination — meta.totalPages drives it) ──────────────

function Pager(props: { page: number; totalPages: number; total: number; onPage: (page: number) => void; noun: string }) {
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

// ── action builder (ordered rows — kind select + minimal params) ────────────

interface ActionRow {
  kind: SoarActionKind;
  ip: string;
  direction: BlockDirection;
  title: string;
  message: string;
  incidentSeverity: SoarSeverity;
  seconds: string;
  payload: string; // JSON text for webhook
}

const EMPTY_ROW: ActionRow = {
  kind: "notify",
  ip: "",
  direction: "both",
  title: "",
  message: "",
  incidentSeverity: "high",
  seconds: "30",
  payload: "{}",
};

function rowsFromActions(actions: SoarAction[]): ActionRow[] {
  return actions.map((a) => {
    const p = (a.params ?? {}) as Record<string, unknown>;
    return {
      kind: a.kind,
      ip: typeof p.ip === "string" ? p.ip : "",
      direction: (p.direction === "in" || p.direction === "out" ? p.direction : "both") as BlockDirection,
      title: typeof p.title === "string" ? p.title : "",
      message: typeof p.message === "string" ? p.message : "",
      incidentSeverity: (SEVERITIES.includes(p.severity as SoarSeverity) ? p.severity : "high") as SoarSeverity,
      seconds: typeof p.seconds === "number" ? String(p.seconds) : "30",
      payload: p.payload !== undefined ? JSON.stringify(p.payload, null, 2) : "{}",
    };
  });
}

function buildActions(rows: ActionRow[]): SoarAction[] {
  if (rows.length === 0) throw new Error("A playbook needs at least one action");
  return rows.map((row, i) => {
    const at = `action #${i + 1} (${ACTION_LABEL[row.kind].label})`;
    switch (row.kind) {
      case "block_ip": {
        if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(row.ip.trim()) || row.ip.split(".").some((o) => Number(o) > 255)) {
          throw new Error(`${at}: enter a valid IPv4 address`);
        }
        return { kind: "block_ip", params: { ip: row.ip.trim(), direction: row.direction } };
      }
      case "notify": {
        if (!row.title.trim() || !row.message.trim()) throw new Error(`${at}: title and message are required`);
        return { kind: "notify", params: { title: row.title.trim(), message: row.message.trim() } };
      }
      case "create_incident": {
        if (!row.title.trim()) throw new Error(`${at}: incident title is required`);
        return { kind: "create_incident", params: { title: row.title.trim(), severity: row.incidentSeverity } };
      }
      case "delay": {
        const n = Number(row.seconds);
        if (!Number.isInteger(n) || n < 1 || n > 300) throw new Error(`${at}: seconds must be 1-300`);
        return { kind: "delay", params: { seconds: n } };
      }
      case "webhook": {
        let payload: unknown;
        try {
          payload = JSON.parse(row.payload || "{}");
        } catch {
          throw new Error(`${at}: payload must be valid JSON`);
        }
        if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
          throw new Error(`${at}: payload must be a JSON object`);
        }
        return { kind: "webhook", params: { payload } };
      }
      default:
        throw new Error(`${at}: unknown kind`);
    }
  });
}

function ActionRowEditor(props: {
  row: ActionRow;
  index: number;
  total: number;
  onChange: (patch: Partial<ActionRow>) => void;
  onMove: (dir: -1 | 1) => void;
  onRemove: () => void;
}) {
  const { row, index, total } = props;
  return (
    <div className="rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
      <div className="mb-2 flex items-center gap-2">
        <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-zinc-500/10 text-[11px] font-semibold text-zinc-600 dark:text-zinc-300">
          {index + 1}
        </span>
        <Select value={row.kind} onValueChange={(v) => props.onChange({ kind: v as SoarActionKind })}>
          <SelectTrigger className="h-8 w-44" aria-label={`Action ${index + 1} kind`}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {ACTION_KINDS.map((k) => (
              <SelectItem key={k} value={k}>
                {ACTION_LABEL[k].label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <div className="ml-auto flex items-center gap-0.5">
          <Button variant="ghost" size="sm" className="h-7 w-7 p-0" disabled={index === 0} onClick={() => props.onMove(-1)} aria-label="Move action up">
            <Icons.ChevronUp className="h-3.5 w-3.5" />
          </Button>
          <Button variant="ghost" size="sm" className="h-7 w-7 p-0" disabled={index === total - 1} onClick={() => props.onMove(1)} aria-label="Move action down">
            <Icons.ChevronDown className="h-3.5 w-3.5" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="h-7 w-7 p-0 text-rose-600 hover:text-rose-700 dark:text-rose-400"
            disabled={total <= 1}
            onClick={props.onRemove}
            aria-label="Remove action"
          >
            <Icons.Trash2 className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>

      {row.kind === "block_ip" && (
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-[1fr_9rem]">
          <div className="grid gap-1">
            <Label className="text-xs text-zinc-500">IPv4 address</Label>
            <Input value={row.ip} onChange={(e) => props.onChange({ ip: e.target.value })} placeholder="203.0.113.9" className="h-8 font-mono text-xs" />
          </div>
          <div className="grid gap-1">
            <Label className="text-xs text-zinc-500">Direction</Label>
            <Select value={row.direction} onValueChange={(v) => props.onChange({ direction: v as BlockDirection })}>
              <SelectTrigger className="h-8 w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {BLOCK_DIRECTIONS.map((d) => (
                  <SelectItem key={d} value={d}>
                    {d}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
      )}

      {row.kind === "notify" && (
        <div className="grid gap-2">
          <div className="grid gap-1">
            <Label className="text-xs text-zinc-500">Title</Label>
            <Input value={row.title} onChange={(e) => props.onChange({ title: e.target.value })} placeholder="Suspicious login detected" className="h-8 text-xs" />
          </div>
          <div className="grid gap-1">
            <Label className="text-xs text-zinc-500">Message</Label>
            <Textarea value={row.message} onChange={(e) => props.onChange({ message: e.target.value })} placeholder="What happened and what to do…" rows={2} className="text-xs" />
          </div>
        </div>
      )}

      {row.kind === "create_incident" && (
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-[1fr_9rem]">
          <div className="grid gap-1">
            <Label className="text-xs text-zinc-500">Incident title</Label>
            <Input value={row.title} onChange={(e) => props.onChange({ title: e.target.value })} placeholder="Auto-opened by playbook" className="h-8 text-xs" />
          </div>
          <div className="grid gap-1">
            <Label className="text-xs text-zinc-500">Severity</Label>
            <Select value={row.incidentSeverity} onValueChange={(v) => props.onChange({ incidentSeverity: v as SoarSeverity })}>
              <SelectTrigger className="h-8 w-full">
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
        </div>
      )}

      {row.kind === "delay" && (
        <div className="grid gap-1 sm:w-40">
          <Label className="text-xs text-zinc-500">Seconds (1-300)</Label>
          <Input
            type="number"
            min={1}
            max={300}
            value={row.seconds}
            onChange={(e) => props.onChange({ seconds: e.target.value })}
            className="h-8 text-xs tabular-nums"
          />
        </div>
      )}

      {row.kind === "webhook" && (
        <div className="grid gap-1">
          <Label className="text-xs text-zinc-500">Payload (JSON object)</Label>
          <Textarea value={row.payload} onChange={(e) => props.onChange({ payload: e.target.value })} rows={3} className="font-mono text-xs" />
        </div>
      )}
    </div>
  );
}

// ── playbook create/edit dialog ─────────────────────────────────────────────

const EMPTY_FILTER = { severities: [] as SoarSeverity[], sources: [] as string[], kinds: [] as string[] };

function toggle<T>(list: T[], value: T): T[] {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
}

function PlaybookDialog(props: { playbook: SoarPlaybookDTO | null; onClose: () => void }) {
  const editing = props.playbook !== null;
  const [name, setName] = useState(props.playbook?.name ?? "");
  const [enabled, setEnabled] = useState(props.playbook?.enabled ?? true);
  const [triggerKind, setTriggerKind] = useState<SoarTriggerKind>(props.playbook?.triggerKind ?? "incident_created");
  const [filter, setFilter] = useState(() => {
    const f = props.playbook?.triggerFilter;
    return {
      severities: (f?.severities ?? []).filter((s): s is SoarSeverity => SEVERITIES.includes(s as SoarSeverity)),
      sources: f?.sources ?? [],
      kinds: f?.kinds ?? [],
    };
  });
  const [kindsText, setKindsText] = useState((props.playbook?.triggerFilter?.kinds ?? []).join(", "));
  const [dedupeKey, setDedupeKey] = useState(props.playbook?.dedupeKey ?? "");
  const [rows, setRows] = useState<ActionRow[]>(() => rowsFromActions(props.playbook?.actions ?? [{ kind: "notify", params: { title: "", message: "" } }]));
  const [busy, setBusy] = useState(false);
  const queryClient = useQueryClient();

  const save = async () => {
    let actions: SoarAction[];
    try {
      actions = buildActions(rows);
    } catch (err) {
      toastErr(err, "Check the action list");
      return;
    }
    const kinds = kindsText.split(",").map((k) => k.trim()).filter(Boolean);
    const body = {
      name: name.trim(),
      enabled,
      triggerKind,
      triggerFilter: { severities: filter.severities, sources: filter.sources, kinds },
      actions,
      dedupeKey: dedupeKey.trim(),
    };
    if (!body.name) {
      toastErr(new Error("Playbook name is required"), "Validation");
      return;
    }
    setBusy(true);
    try {
      if (editing && props.playbook) {
        await soarApi.updatePlaybook(props.playbook.id, body);
        toastOk("Playbook updated", `${body.name} saved`);
      } else {
        await soarApi.createPlaybook(body);
        toastOk("Playbook created", `${body.name} (${body.triggerKind})`);
      }
      await queryClient.invalidateQueries({ queryKey: ["soar"] });
      setBusy(false);
      props.onClose();
    } catch (err) {
      toastErr(err, editing ? "Update failed" : "Create failed");
      setBusy(false);
    }
  };

  const patchRow = (index: number, patch: Partial<ActionRow>) =>
    setRows((cur) => cur.map((r, i) => (i === index ? { ...r, ...patch } : r)));
  const moveRow = (index: number, dir: -1 | 1) =>
    setRows((cur) => {
      const next = [...cur];
      const [row] = next.splice(index, 1);
      next.splice(index + dir, 0, row);
      return next;
    });

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && props.onClose()}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle className="text-base">{editing ? `Edit playbook ${props.playbook?.name}` : "New playbook"}</DialogTitle>
          <DialogDescription>
            A playbook runs its actions in order when a matching trigger fires. Empty filter lists match everything within the trigger kind.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-[1fr_auto]">
            <div className="grid gap-1.5">
              <Label htmlFor="soar-pb-name">Name</Label>
              <Input id="soar-pb-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Auto-block critical IPS sources" autoFocus />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="soar-pb-enabled" className="text-zinc-500">Enabled</Label>
              <div className="flex h-9 items-center">
                <Switch id="soar-pb-enabled" checked={enabled} onCheckedChange={setEnabled} />
              </div>
            </div>
          </div>

          <div className="grid gap-1.5">
            <Label htmlFor="soar-pb-trigger">Trigger kind</Label>
            <Select value={triggerKind} onValueChange={(v) => setTriggerKind(v as SoarTriggerKind)}>
              <SelectTrigger id="soar-pb-trigger" className="w-full sm:w-72">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {TRIGGER_KINDS.map((k) => (
                  <SelectItem key={k} value={k}>
                    {TRIGGER_BADGE[k].label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="grid gap-2 rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
            <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">Trigger filter (empty = match all)</p>
            <div className="grid gap-1.5">
              <Label className="text-xs text-zinc-500">Severities</Label>
              <div className="flex flex-wrap gap-1.5">
                {SEVERITIES.map((s) => (
                  <button key={s} type="button" onClick={() => setFilter((f) => ({ ...f, severities: toggle(f.severities, s) }))} aria-pressed={filter.severities.includes(s)}>
                    <Badge
                      variant="outline"
                      className={cn(
                        "cursor-pointer capitalize",
                        filter.severities.includes(s)
                          ? "border-amber-500/50 bg-amber-500/10 text-amber-600 dark:text-amber-400"
                          : "border-zinc-300 bg-zinc-100 text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-400",
                      )}
                    >
                      {s}
                    </Badge>
                  </button>
                ))}
              </div>
            </div>
            <div className="grid gap-1.5">
              <Label className="text-xs text-zinc-500">Sources</Label>
              <div className="flex flex-wrap gap-1.5">
                {SOURCES.map((s) => (
                  <button key={s} type="button" onClick={() => setFilter((f) => ({ ...f, sources: toggle(f.sources, s) }))} aria-pressed={filter.sources.includes(s)}>
                    <Badge
                      variant="outline"
                      className={cn(
                        "cursor-pointer",
                        filter.sources.includes(s)
                          ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                          : "border-zinc-300 bg-zinc-100 text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-400",
                      )}
                    >
                      {s}
                    </Badge>
                  </button>
                ))}
              </div>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="soar-pb-kinds" className="text-xs text-zinc-500">Kinds (comma-separated)</Label>
              <Input id="soar-pb-kinds" value={kindsText} onChange={(e) => setKindsText(e.target.value)} placeholder="e.g. pii, credentials" className="h-8 text-xs" />
            </div>
          </div>

          <div className="grid gap-2">
            <div className="flex items-center justify-between">
              <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">Actions (run in order)</p>
              <Button variant="outline" size="sm" className="h-7 gap-1 text-xs" disabled={rows.length >= 10} onClick={() => setRows((cur) => [...cur, { ...EMPTY_ROW }])}>
                <Icons.Plus className="h-3.5 w-3.5" />
                Add action
              </Button>
            </div>
            <div className="grid max-h-72 gap-2 overflow-y-auto pr-1">
              {rows.map((row, i) => (
                <ActionRowEditor
                  key={i}
                  row={row}
                  index={i}
                  total={rows.length}
                  onChange={(patch) => patchRow(i, patch)}
                  onMove={(dir) => moveRow(i, dir)}
                  onRemove={() => setRows((cur) => cur.filter((_, j) => j !== i))}
                />
              ))}
            </div>
          </div>

          <div className="grid gap-1.5">
            <Label htmlFor="soar-pb-dedupe">Dedupe key (optional)</Label>
            <Input id="soar-pb-dedupe" value={dedupeKey} onChange={(e) => setDedupeKey(e.target.value)} placeholder="e.g. block-c2 — skips re-fires for the same triggerRef" className="h-8 text-xs" />
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={props.onClose} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void save()} disabled={busy || !name.trim()}>
            {busy ? "Saving…" : editing ? "Save changes" : "Create playbook"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── run-now dialog ──────────────────────────────────────────────────────────

function RunDialog(props: { playbook: SoarPlaybookDTO; onClose: () => void }) {
  const [triggerRef, setTriggerRef] = useState(`manual:${new Date().toISOString().slice(0, 19)}`);
  const [payloadText, setPayloadText] = useState("{}");
  const [busy, setBusy] = useState(false);
  const queryClient = useQueryClient();

  const fire = async () => {
    let payload: Record<string, unknown> = {};
    try {
      const parsed: unknown = JSON.parse(payloadText || "{}");
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Payload must be a JSON object");
      payload = parsed as Record<string, unknown>;
    } catch (err) {
      toastErr(err, "Payload must be valid JSON");
      return;
    }
    if (!triggerRef.trim()) {
      toastErr(new Error("triggerRef is required"), "Validation");
      return;
    }
    setBusy(true);
    try {
      const run = await soarApi.runPlaybook(props.playbook.id, triggerRef.trim(), payload);
      if (run.status === "skipped") {
        toastOk("Run skipped (dedupe)", `${props.playbook.name}: open run with dedupeKey '${props.playbook.dedupeKey}' already handled ${run.triggerRef}`);
      } else if (run.status === "success") {
        toastOk("Playbook fired", `${props.playbook.name}: ${run.steps.length} step${run.steps.length === 1 ? "" : "s"} completed`);
      } else {
        toastErr(new Error(run.steps.find((s) => s.status === "failed")?.detail ?? "step failed"), `Playbook ${run.status} — ${props.playbook.name}`);
      }
      await queryClient.invalidateQueries({ queryKey: ["soar"] });
      setBusy(false);
      props.onClose();
    } catch (err) {
      toastErr(err, "Run failed");
      setBusy(false);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && props.onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-base">Run playbook “{props.playbook.name}”</DialogTitle>
          <DialogDescription>
            Fires the playbook now for the given trigger reference — bypasses enabled/filter, dedupe still applies.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          <div className="grid gap-1.5">
            <Label htmlFor="soar-run-ref">Trigger ref</Label>
            <Input id="soar-run-ref" value={triggerRef} onChange={(e) => setTriggerRef(e.target.value)} className="h-9 font-mono text-xs" autoFocus />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="soar-run-payload">Payload (JSON object — severity/source/kind feed the filter)</Label>
            <Textarea id="soar-run-payload" value={payloadText} onChange={(e) => setPayloadText(e.target.value)} rows={4} className="font-mono text-xs" />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={props.onClose} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void fire()} disabled={busy || !triggerRef.trim()}>
            {busy ? "Running…" : "Run now"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── playbooks tab ───────────────────────────────────────────────────────────

function filterSummary(pb: SoarPlaybookDTO): string {
  const f = pb.triggerFilter ?? { severities: [], sources: [], kinds: [] };
  const parts: string[] = [];
  if (f.severities?.length) parts.push(`sev: ${f.severities.join("/")}`);
  if (f.sources?.length) parts.push(`src: ${f.sources.join("/")}`);
  if (f.kinds?.length) parts.push(`kinds: ${f.kinds.join("/")}`);
  return parts.length ? parts.join(" · ") : "match all";
}

function EnabledSwitch(props: { playbook: SoarPlaybookDTO }) {
  const [busy, setBusy] = useState(false);
  const queryClient = useQueryClient();
  const flip = async (checked: boolean) => {
    setBusy(true);
    try {
      await soarApi.updatePlaybook(props.playbook.id, { enabled: checked });
      toastOk(checked ? "Playbook enabled" : "Playbook disabled", props.playbook.name);
      await queryClient.invalidateQueries({ queryKey: ["soar"] });
    } catch (err) {
      toastErr(err, "Toggle failed");
    } finally {
      setBusy(false);
    }
  };
  return <Switch checked={props.playbook.enabled} onCheckedChange={(v) => void flip(v)} disabled={busy} aria-label={`Toggle ${props.playbook.name}`} />;
}

function PlaybooksTab(props: { onCreate: () => void }) {
  const [editFor, setEditFor] = useState<SoarPlaybookDTO | null>(null);
  const [runFor, setRunFor] = useState<SoarPlaybookDTO | null>(null);
  const [deleteFor, setDeleteFor] = useState<SoarPlaybookDTO | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const queryClient = useQueryClient();

  const query = useQuery({ queryKey: ["soar", "playbooks"], queryFn: () => soarApi.listPlaybooks() });
  const rows = query.data?.data ?? [];

  const confirmDelete = async () => {
    if (!deleteFor) return;
    setDeleteBusy(true);
    try {
      await soarApi.deletePlaybook(deleteFor.id);
      toastOk("Playbook deleted", `${deleteFor.name} and its run history removed`);
      await queryClient.invalidateQueries({ queryKey: ["soar"] });
      setDeleteBusy(false);
      setDeleteFor(null);
    } catch (err) {
      toastErr(err, "Delete failed");
      setDeleteBusy(false);
    }
  };

  return (
    <div className="min-w-0 rounded-lg border border-zinc-200 dark:border-zinc-800">
      {query.isLoading ? (
        <TableSkeleton rows={6} cols={6} />
      ) : query.isError ? (
        <QueryError error={query.error} onRetry={() => void query.refetch()} />
      ) : rows.length === 0 ? (
        <EmptyBlock
          icon={<Icons.Route className="h-6 w-6" />}
          title="No playbooks yet"
          description="Automated responses run ordered actions (block IP, notify, open a case…) when their trigger fires."
          action={
            <Button size="sm" className="mt-2 gap-1.5" onClick={props.onCreate}>
              <Icons.Plus className="h-3.5 w-3.5" />
              New playbook
            </Button>
          }
        />
      ) : (
        <div className="overflow-x-auto">
          <Table className="min-w-[860px]">
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Trigger</TableHead>
                <TableHead>Filter</TableHead>
                <TableHead>Actions</TableHead>
                <TableHead>Enabled</TableHead>
                <TableHead>Last run</TableHead>
                <TableHead className="w-44 text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((pb) => (
                <TableRow key={pb.id}>
                  <TableCell className="max-w-56 min-w-0 truncate text-sm font-medium" title={pb.name}>
                    {pb.name}
                  </TableCell>
                  <TableCell>
                    <TriggerBadge kind={pb.triggerKind} />
                  </TableCell>
                  <TableCell className="max-w-56 min-w-0 truncate text-xs text-zinc-500" title={filterSummary(pb)}>
                    {filterSummary(pb)}
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap items-center gap-1">
                      {pb.actions.slice(0, 3).map((a, i) => (
                        <ActionChip key={i} kind={a.kind} />
                      ))}
                      {pb.actions.length > 3 && <span className="text-[11px] text-zinc-400">+{pb.actions.length - 3}</span>}
                    </div>
                  </TableCell>
                  <TableCell>
                    <EnabledSwitch playbook={pb} />
                  </TableCell>
                  <TableCell className="whitespace-nowrap text-xs tabular-nums">{fmtDateTime(pb.lastRunAt)}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-1">
                      <Button variant="ghost" size="sm" className="h-7 gap-1 px-2 text-xs" onClick={() => setRunFor(pb)} aria-label={`Run ${pb.name}`}>
                        <Icons.Play className="h-3.5 w-3.5" />
                        Run
                      </Button>
                      <Button variant="ghost" size="sm" className="h-7 gap-1 px-2 text-xs" onClick={() => setEditFor(pb)} aria-label={`Edit ${pb.name}`}>
                        <Icons.Pencil className="h-3.5 w-3.5" />
                        Edit
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 w-7 p-0 text-rose-600 hover:text-rose-700 dark:text-rose-400"
                        onClick={() => setDeleteFor(pb)}
                        aria-label={`Delete ${pb.name}`}
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

      {editFor && <PlaybookDialog playbook={editFor} onClose={() => setEditFor(null)} />}
      {runFor && <RunDialog playbook={runFor} onClose={() => setRunFor(null)} />}
      {deleteFor && (
        <ConfirmDialog
          open
          onOpenChange={(open) => !open && !deleteBusy && setDeleteFor(null)}
          title={`Delete playbook “${deleteFor.name}”?`}
          description="The playbook and its run history are removed permanently. Firewall rules, incidents and notifications already created by past runs stay in place."
          confirmLabel="Delete playbook"
          loading={deleteBusy}
          onConfirm={() => void confirmDelete()}
        />
      )}
    </div>
  );
}

// ── runs tab (steps expandable via description list) ────────────────────────

function StepsList({ run }: { run: SoarRunDTO }) {
  return (
    <div className="max-h-96 overflow-y-auto rounded-lg border border-zinc-200 bg-zinc-500/[0.03] p-3 dark:border-zinc-800">
      <dl className="grid gap-2">
        {run.steps.map((step, i) => (
          <div key={i} className="grid grid-cols-[auto_auto_1fr] items-start gap-2 text-xs">
            <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-zinc-500/10 font-semibold text-zinc-600 dark:text-zinc-300">
              {i + 1}
            </span>
            <span className="flex items-center gap-1.5 whitespace-nowrap pt-0.5">
              <StepStatusIcon status={step.status} />
              <ActionChip kind={step.kind} />
            </span>
            <dd className="min-w-0 break-words pt-0.5 text-zinc-600 dark:text-zinc-300">{step.detail}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function RunsTab() {
  const [status, setStatus] = useState<SoarRunStatus | "">("");
  const [playbookId, setPlaybookId] = useState("");
  const [page, setPage] = useState(1);
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const playbooksQuery = useQuery({ queryKey: ["soar", "playbooks"], queryFn: () => soarApi.listPlaybooks() });
  const params = useMemo(() => qs({ status, playbookId: playbookId || undefined, page, limit: RUNS_LIMIT }), [status, playbookId, page]);
  const query = useQuery({
    queryKey: ["soar", "runs", { status, playbookId, page }],
    queryFn: () => soarApi.listRuns(params),
  });
  const rows = query.data?.data ?? [];
  const meta = query.data?.meta;

  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <Select
          value={status || "any"}
          onValueChange={(v) => {
            setStatus(v === "any" ? "" : (v as SoarRunStatus));
            setPage(1);
          }}
        >
          <SelectTrigger className="h-11 w-40 lg:h-9" aria-label="Status filter">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="any">any status</SelectItem>
            {RUN_STATUSES.map((s) => (
              <SelectItem key={s} value={s}>
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select
          value={playbookId || "any"}
          onValueChange={(v) => {
            setPlaybookId(v === "any" ? "" : v);
            setPage(1);
          }}
        >
          <SelectTrigger className="h-11 w-56 lg:h-9" aria-label="Playbook filter">
            <SelectValue placeholder="Playbook" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="any">any playbook</SelectItem>
            {(playbooksQuery.data?.data ?? []).map((pb) => (
              <SelectItem key={pb.id} value={String(pb.id)}>
                {pb.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="min-w-0 rounded-lg border border-zinc-200 dark:border-zinc-800">
        {query.isLoading ? (
          <TableSkeleton rows={6} cols={6} />
        ) : query.isError ? (
          <QueryError error={query.error} onRetry={() => void query.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyBlock
            icon={<Icons.History className="h-6 w-6" />}
            title="No playbook runs"
            description="Runs appear here when a trigger fires a playbook or you use Run now on the Playbooks tab."
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <Table className="min-w-[820px]">
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-8" />
                    <TableHead>Playbook</TableHead>
                    <TableHead>Trigger ref</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Steps</TableHead>
                    <TableHead>Duration</TableHead>
                    <TableHead>Started</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((run) => (
                    <TableRow
                      key={run.id}
                      className={cn("cursor-pointer", expandedId === run.id && "bg-zinc-500/[0.04]")}
                      onClick={() => setExpandedId((cur) => (cur === run.id ? null : run.id))}
                    >
                      <TableCell>
                        <Icons.ChevronRight className={cn("h-3.5 w-3.5 text-zinc-400 transition-transform", expandedId === run.id && "rotate-90")} />
                      </TableCell>
                      <TableCell className="max-w-56 min-w-0 truncate text-sm font-medium" title={run.playbookName}>
                        {run.playbookName}
                      </TableCell>
                      <TableCell className="max-w-56 min-w-0 truncate font-mono text-xs" title={run.triggerRef}>
                        {run.triggerRef}
                      </TableCell>
                      <TableCell>
                        <RunStatusBadge status={run.status} />
                      </TableCell>
                      <TableCell className="text-xs tabular-nums">{run.steps.length}</TableCell>
                      <TableCell className="text-xs tabular-nums">{fmtDuration(run.durationMs)}</TableCell>
                      <TableCell className="whitespace-nowrap text-xs tabular-nums">{fmtDateTime(run.startedAt)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            {meta && <Pager page={meta.page} totalPages={meta.totalPages} total={meta.total} onPage={setPage} noun="run" />}
          </>
        )}
      </div>

      {expandedId !== null &&
        (() => {
          const run = rows.find((r) => r.id === expandedId);
          if (!run) return null;
          return (
            <div className="grid gap-2 rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
              <div className="flex flex-wrap items-center gap-2">
                <Icons.ListOrdered className="h-4 w-4 text-zinc-400" />
                <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                  Steps — {run.playbookName} · <span className="font-mono normal-case">{run.triggerRef}</span>
                </p>
                <RunStatusBadge status={run.status} />
                <Button variant="ghost" size="sm" className="ml-auto h-7 px-2 text-xs" onClick={() => setExpandedId(null)}>
                  <Icons.ChevronUp className="h-3.5 w-3.5" />
                  Close
                </Button>
              </div>
              <StepsList run={run} />
            </div>
          );
        })()}
    </div>
  );
}

// ── main view ───────────────────────────────────────────────────────────────

export function SoarView() {
  const [createOpen, setCreateOpen] = useState(false);

  return (
    <div className="grid gap-3">
      <StatsStrip />

      <Tabs defaultValue="playbooks" className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <TabsList>
            <TabsTrigger value="playbooks" className="gap-1.5">
              <Icons.Route className="h-3.5 w-3.5" />
              Playbooks
            </TabsTrigger>
            <TabsTrigger value="runs" className="gap-1.5">
              <Icons.History className="h-3.5 w-3.5" />
              Playbook runs
            </TabsTrigger>
          </TabsList>
          <div className="ml-auto">
            <Button className="h-11 gap-1.5 lg:h-9" onClick={() => setCreateOpen(true)}>
              <Icons.Plus className="h-4 w-4" />
              New playbook
            </Button>
          </div>
        </div>

        <TabsContent value="playbooks" className="mt-3">
          <PlaybooksTab onCreate={() => setCreateOpen(true)} />
        </TabsContent>
        <TabsContent value="runs" className="mt-3">
          <RunsTab />
        </TabsContent>
      </Tabs>

      {createOpen && <PlaybookDialog playbook={null} onClose={() => setCreateOpen(false)} />}
    </div>
  );
}
