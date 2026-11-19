"use client";

/**
 * Config anomaly view (spec §4.5 rule-based pass) — console for firewall
 * misconfiguration findings: stats chips (open by severity + last scan),
 * Run Scan trigger over /api/v1/config-anomaly/scan, and a scrollable
 * findings table (kind badge, severity badge, subjectRef, message,
 * suggestion, status, detected) with Resolve / Ignore row actions.
 * Atoms reused from fw-ui (table states, toasts) — palette per
 * UI_DESIGN_SYSTEM §2 (zinc/amber/rose/emerald — no indigo/blue).
 */

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { EmptyBlock, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";
import {
  configAnomalyApi,
  fmtDateTime,
  KIND_LABEL,
  KINDS,
  qs,
  SEVERITIES,
  SEVERITY_TONE,
  STATUSES,
  STATUS_TONE,
  type ConfigAnomalyFindingDTO,
  type ConfigAnomalyKind,
  type ConfigAnomalySeverity,
  type ConfigAnomalyStatus,
} from "./config-anomaly-api";

const LIMIT = 50;

const EMPTY_FILTERS = { kind: "", severity: "", status: "" };
type Filters = typeof EMPTY_FILTERS;

// ── badges ──────────────────────────────────────────────────────────────────

const KIND_ICON: Record<ConfigAnomalyKind, React.ComponentType<{ className?: string }>> = {
  any_any_rule: Icons.ShieldOff,
  wan_permissive: Icons.Globe,
  unused_object: Icons.Boxes,
  shadowed_rule: Icons.Layers,
  log_disabled: Icons.ScrollText,
  duplicate_rule: Icons.Copy,
};

function KindBadge({ kind }: { kind: ConfigAnomalyKind }) {
  const Icon = KIND_ICON[kind] ?? Icons.ShieldAlert;
  return (
    <Badge
      variant="outline"
      className="gap-1 border-zinc-300 bg-zinc-100 font-medium text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
      title={`kind: ${kind}`}
    >
      <Icon className="h-3 w-3" />
      {KIND_LABEL[kind] ?? kind}
    </Badge>
  );
}

function SeverityBadge({ severity }: { severity: ConfigAnomalySeverity }) {
  const tone = SEVERITY_TONE[severity] ?? SEVERITY_TONE.low;
  return (
    <Badge variant="outline" className={cn("gap-1.5 font-medium capitalize", tone.chip)}>
      <span className={cn("inline-block h-1.5 w-1.5 rounded-full", tone.dot)} />
      {severity}
    </Badge>
  );
}

function StatusBadge({ status }: { status: ConfigAnomalyStatus }) {
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium capitalize", STATUS_TONE[status] ?? STATUS_TONE.ignored)}>
      {status === "open" ? <Icons.CircleDashed className="h-3 w-3" /> : status === "resolved" ? <Icons.CircleCheck className="h-3 w-3" /> : <Icons.EyeOff className="h-3 w-3" />}
      {status}
    </Badge>
  );
}

// ── stats chips row ─────────────────────────────────────────────────────────

function StatsChips(props: { onScan: () => void; scanning: boolean; lastScanAt: string | null }) {
  const query = useQuery({ queryKey: ["config-anomaly", "stats"], queryFn: () => configAnomalyApi.getStats() });
  const s = query.data;
  const openTotal = s?.openTotal ?? 0;
  return (
    <div className="flex flex-wrap items-stretch gap-2">
      <div className="min-w-0 rounded-lg border border-zinc-200 px-3 py-2 dark:border-zinc-800">
        <p className="truncate text-[11px] font-medium uppercase tracking-wide text-zinc-500">Open findings</p>
        <p className="mt-0.5 text-lg font-semibold tabular-nums">{query.isLoading ? "—" : openTotal}</p>
      </div>
      {SEVERITIES.map((sev) => (
        <div key={sev} className="min-w-0 rounded-lg border border-zinc-200 px-3 py-2 dark:border-zinc-800">
          <p className="flex items-center gap-1.5 truncate text-[11px] font-medium uppercase tracking-wide text-zinc-500">
            <span className={cn("inline-block h-2 w-2 shrink-0 rounded-full", SEVERITY_TONE[sev].dot)} />
            {sev}
          </p>
          <p className="mt-0.5 text-lg font-semibold tabular-nums">{query.isLoading ? "—" : s?.openBySeverity[sev] ?? 0}</p>
        </div>
      ))}
      <div className="min-w-0 rounded-lg border border-zinc-200 px-3 py-2 dark:border-zinc-800">
        <p className="truncate text-[11px] font-medium uppercase tracking-wide text-zinc-500">Last scan</p>
        <p className="mt-0.5 text-sm font-semibold leading-7">{props.lastScanAt ? fmtDateTime(props.lastScanAt) : "never"}</p>
      </div>
      <Button className="gap-1.5 self-center" onClick={props.onScan} disabled={props.scanning}>
        {props.scanning ? <Icons.Loader2 className="h-4 w-4 animate-spin" /> : <Icons.ScanSearch className="h-4 w-4" />}
        {props.scanning ? "Scanning…" : "Run Scan"}
      </Button>
    </div>
  );
}

// ── row actions (Resolve / Ignore — open rows only) ─────────────────────────

function RowActions(props: { finding: ConfigAnomalyFindingDTO }) {
  const [busy, setBusy] = useState<"resolve" | "ignore" | null>(null);
  const queryClient = useQueryClient();
  const open = props.finding.status === "open";

  const triage = async (status: "resolved" | "ignored") => {
    setBusy(status === "resolved" ? "resolve" : "ignore");
    try {
      await configAnomalyApi.triage(props.finding.id, status);
      toastOk(
        status === "resolved" ? "Finding resolved" : "Finding ignored",
        `${props.finding.subjectRef} marked ${status}`,
      );
      await queryClient.invalidateQueries({ queryKey: ["config-anomaly"] });
    } catch (err) {
      toastErr(err, "Triage failed");
    } finally {
      setBusy(null);
    }
  };

  if (!open) return <span className="text-xs text-zinc-400">—</span>;
  return (
    <TooltipProvider>
      <div className="flex items-center justify-end gap-1">
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              className="h-7 gap-1 px-2 text-xs text-emerald-600 dark:text-emerald-400"
              disabled={busy !== null}
              onClick={() => void triage("resolved")}
              aria-label={`Resolve ${props.finding.subjectRef}`}
            >
              {busy === "resolve" ? <Icons.Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Icons.CircleCheck className="h-3.5 w-3.5" />}
              Resolve
            </Button>
          </TooltipTrigger>
          <TooltipContent>Mark resolved — suppresses re-alerting for this subject</TooltipContent>
        </Tooltip>
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              className="h-7 gap-1 px-2 text-xs"
              disabled={busy !== null}
              onClick={() => void triage("ignored")}
              aria-label={`Ignore ${props.finding.subjectRef}`}
            >
              {busy === "ignore" ? <Icons.Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Icons.EyeOff className="h-3.5 w-3.5" />}
              Ignore
            </Button>
          </TooltipTrigger>
          <TooltipContent>Accept as-is — ignores future detections of this subject</TooltipContent>
        </Tooltip>
      </div>
    </TooltipProvider>
  );
}

// ── main view ───────────────────────────────────────────────────────────────

export function ConfigAnomalyView() {
  const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS);
  const [page, setPage] = useState(1);
  const queryClient = useQueryClient();

  const params = useMemo(() => qs({ ...filters, page, limit: LIMIT }), [filters, page]);
  const query = useQuery({
    queryKey: ["config-anomaly", "list", filters, page],
    queryFn: () => configAnomalyApi.list(params),
  });
  const statsQuery = useQuery({ queryKey: ["config-anomaly", "stats"], queryFn: () => configAnomalyApi.getStats() });

  const rows = query.data?.data ?? [];
  const meta = query.data?.meta;

  const scan = useMutation({
    mutationFn: () => configAnomalyApi.scan(),
    onSuccess: (summary) => {
      toastOk(
        "Scan complete",
        `${summary.detected} finding${summary.detected === 1 ? "" : "s"} detected · ${summary.newOpen} new · ${summary.autoResolved} auto-resolved`,
      );
      void queryClient.invalidateQueries({ queryKey: ["config-anomaly"] });
    },
    onError: (err) => toastErr(err, "Scan failed"),
  });

  const applyFilter = (patch: Partial<Filters>) => {
    setFilters({ ...filters, ...patch });
    setPage(1);
  };

  return (
    <div className="grid gap-3">
      {/* stats chips row + Run Scan */}
      <StatsChips
        onScan={() => scan.mutate()}
        scanning={scan.isPending}
        lastScanAt={statsQuery.data?.lastScanAt ?? null}
      />

      {/* filter bar */}
      <div className="flex flex-wrap items-center gap-2">
        <Select value={filters.kind || "any"} onValueChange={(v) => applyFilter({ kind: v === "any" ? "" : v })}>
          <SelectTrigger className="h-11 w-44 lg:h-9" aria-label="Kind filter">
            <SelectValue placeholder="Kind" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="any">any kind</SelectItem>
            {KINDS.map((k) => (
              <SelectItem key={k} value={k}>
                {KIND_LABEL[k]}
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
        <span className="ml-auto text-xs text-zinc-500">
          Rule-based pass — ML scoring arrives later per spec §4.5
        </span>
      </div>

      {/* findings table — scrollable pane */}
      <div className="min-w-0 rounded-lg border border-zinc-200 dark:border-zinc-800">
        {query.isLoading ? (
          <TableSkeleton rows={6} cols={8} />
        ) : query.isError ? (
          <QueryError error={query.error} onRetry={() => void query.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyBlock
            icon={<Icons.ShieldCheck className="h-6 w-6" />}
            title="No anomalies — configuration looks clean"
            description={
              filters.kind || filters.severity || filters.status
                ? "Nothing matches the current filter — clear it or run a fresh scan."
                : "Run a scan to check the enabled firewall rules for any-any allows, WAN permissiveness, shadowing, missing logs, duplicates and dead objects."
            }
            action={
              <Button size="sm" variant="outline" className="mt-2 gap-1.5" onClick={() => scan.mutate()} disabled={scan.isPending}>
                <Icons.ScanSearch className="h-3.5 w-3.5" />
                Run Scan
              </Button>
            }
          />
        ) : (
          <div className="max-h-96 overflow-y-auto">
            <Table className="min-w-[960px]">
              <TableHeader>
                <TableRow>
                  <TableHead>Kind</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Subject</TableHead>
                  <TableHead>Message</TableHead>
                  <TableHead>Suggestion</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Detected</TableHead>
                  <TableHead className="w-44 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell>
                      <KindBadge kind={r.kind} />
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={r.severity} />
                    </TableCell>
                    <TableCell className="whitespace-nowrap font-mono text-xs">{r.subjectRef}</TableCell>
                    <TableCell className="max-w-72 min-w-0 text-sm" title={r.detail.message}>
                      <span className="line-clamp-2">{r.detail.message}</span>
                    </TableCell>
                    <TableCell className="max-w-72 min-w-0 text-xs text-zinc-500" title={r.detail.suggestion}>
                      <span className="line-clamp-2">{r.detail.suggestion}</span>
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={r.status} />
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs tabular-nums">{fmtDateTime(r.detectedAt)}</TableCell>
                    <TableCell className="text-right">
                      <RowActions finding={r} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
        {meta && meta.total > 0 ? (
          <div className="flex items-center justify-between gap-2 border-t border-zinc-200 px-3 py-2 text-xs text-zinc-500 dark:border-zinc-800">
            <span className="tabular-nums">
              page {meta.page} / {meta.totalPages} · {meta.total.toLocaleString()} finding{meta.total === 1 ? "" : "s"}
            </span>
            <div className="flex items-center gap-1">
              <Button variant="outline" size="sm" className="h-7 px-2" disabled={meta.page <= 1} onClick={() => setPage(meta.page - 1)}>
                <Icons.ChevronLeft className="h-3.5 w-3.5" />
              </Button>
              <Button variant="outline" size="sm" className="h-7 px-2" disabled={meta.page >= meta.totalPages} onClick={() => setPage(meta.page + 1)}>
                <Icons.ChevronRight className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
