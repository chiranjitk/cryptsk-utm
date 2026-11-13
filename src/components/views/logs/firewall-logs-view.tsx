"use client";

/**
 * #/logs/firewall (M09 §4) — filterable, server-paginated firewall flow log.
 * Every filter is part of the TanStack Query key and resets page to 1;
 * `until < since` is blocked client-side with an inline error (§5.1).
 * Row click opens the detail Sheet; Export CSV downloads the current filter
 * via the locked /logs/firewall/export endpoint (10 000-row cap, §3).
 */

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { cn } from "@/lib/utils";
import { DensityToggle, EmptyBlock, QueryError, TableSkeleton, toastErr, toastOk, useTableDensity } from "../firewall/fw-ui";
import { logsApi, qs, type FirewallLogDTO } from "./logs-api";
import { ActionBadge, Paginator, ProtocolBadge, fmtTs, humanizeBytes, localInputToIso } from "./logs-ui";

const LIMIT = 25;
const ACTIONS = ["allow", "deny", "drop", "reject"] as const;

interface Filters {
  q: string;
  action: string;
  src: string;
  dst: string;
  since: string; // datetime-local raw value
  until: string;
}

const EMPTY_FILTERS: Filters = { q: "", action: "", src: "", dst: "", since: "", until: "" };

function rangeInvalid(f: Pick<Filters, "since" | "until">): boolean {
  return Boolean(f.since && f.until && new Date(f.until).getTime() < new Date(f.since).getTime());
}

function DetailRow({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-zinc-100 py-1.5 text-sm dark:border-zinc-800/60">
      <span className="shrink-0 text-xs text-zinc-500">{label}</span>
      <span className={`text-right ${mono ? "font-mono text-xs" : ""}`}>{value ?? "—"}</span>
    </div>
  );
}

export function FirewallLogsView() {
  const [inputs, setInputs] = useState<Filters>(EMPTY_FILTERS);
  const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS); // applied
  const [page, setPage] = useState(1);
  const [rangeError, setRangeError] = useState<string | null>(null);
  const [selected, setSelected] = useState<FirewallLogDTO | null>(null);
  const [exporting, setExporting] = useState(false);
  const [density] = useTableDensity("logs-firewall");

  // 24h per-action counts for the filter chips — LOCKED /logs/stats payload (same key/cache as the reports tab)
  const stats = useQuery({ queryKey: ["logs", "stats", "24h"], queryFn: () => logsApi.getStats("24h") });
  const actionCounts = useMemo(() => {
    const out: Record<string, number> = {};
    for (const s of stats.data?.series ?? []) out[s.key] = s.points.reduce((a, p) => a + p.count, 0);
    return out;
  }, [stats.data]);

  const apply = (next: Filters) => {
    if (rangeInvalid(next)) {
      setRangeError("‘Until’ must not be earlier than ‘Since’.");
      return; // block the change (§5.1 client-side validation)
    }
    setRangeError(null);
    setInputs(next);
    setFilters(next);
    setPage(1);
  };

  /** Text inputs commit on Enter/blur; selects + datetimes commit immediately. */
  const commitText = () => {
    if (inputs !== filters && !rangeInvalid(inputs)) apply(inputs);
  };

  const isoFilters = useMemo(
    () => ({
      q: filters.q,
      action: filters.action,
      src: filters.src,
      dst: filters.dst,
      since: localInputToIso(filters.since),
      until: localInputToIso(filters.until),
    }),
    [filters],
  );

  const params = qs({ ...isoFilters, page, limit: LIMIT });
  const query = useQuery({
    queryKey: ["logs", "firewall", filters, page],
    queryFn: () => logsApi.listFirewall(params),
  });

  const activeCount = Object.values(isoFilters).filter((v) => v !== "").length;

  const onExport = async () => {
    setExporting(true);
    try {
      const { rows } = await logsApi.exportFirewallCsv(qs(isoFilters));
      toastOk(
        "CSV exported",
        rows >= 10000
          ? `${rows.toLocaleString()} rows written — export cap (10 000) hit; narrow the filter for older rows.`
          : `${rows.toLocaleString()} rows written`,
      );
    } catch (err) {
      toastErr(err, "Export failed");
    } finally {
      setExporting(false);
    }
  };

  const rows = query.data?.data ?? [];
  const meta = query.data?.meta;

  return (
    <div className="grid gap-3">
      {/* filter bar */}
      <div className="no-print flex flex-wrap items-center gap-2">
        <div className="relative">
          <Icons.Search className="absolute left-2.5 top-3 lg:top-2.5 h-4 w-4 text-zinc-400" />
          <Input
            value={inputs.q}
            onChange={(e) => setInputs({ ...inputs, q: e.target.value })}
            onKeyDown={(e) => e.key === "Enter" && commitText()}
            onBlur={commitText}
            placeholder="Search src/dst/user/rule/app…"
            className="h-11 w-64 pl-8 lg:h-9"
          />
        </div>
        <Input
          value={inputs.src}
          onChange={(e) => setInputs({ ...inputs, src: e.target.value })}
          onKeyDown={(e) => e.key === "Enter" && commitText()}
          onBlur={commitText}
          placeholder="src prefix"
          className="h-11 w-36 font-mono text-xs lg:h-9"
        />
        <Input
          value={inputs.dst}
          onChange={(e) => setInputs({ ...inputs, dst: e.target.value })}
          onKeyDown={(e) => e.key === "Enter" && commitText()}
          onBlur={commitText}
          placeholder="dst prefix"
          className="h-11 w-36 font-mono text-xs lg:h-9"
        />
        <Input
          type="datetime-local"
          value={inputs.since}
          onChange={(e) => apply({ ...inputs, since: e.target.value })}
          className="h-11 w-56 text-xs lg:h-9"
          aria-label="Since"
        />
        <Input
          type="datetime-local"
          value={inputs.until}
          onChange={(e) => apply({ ...inputs, until: e.target.value })}
          className="h-11 w-56 text-xs lg:h-9"
          aria-label="Until"
        />
        <Badge variant="outline" className="border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300">
          <Icons.Filter className="mr-0.5 h-3 w-3" />
          {activeCount} active
        </Badge>
        {activeCount > 0 && (
          <Button variant="ghost" size="sm" className="h-11 gap-1 text-zinc-500 lg:h-8" onClick={() => apply(EMPTY_FILTERS)}>
            <Icons.X className="h-3.5 w-3.5" />
            Clear
          </Button>
        )}
        <div className="ml-auto flex items-center gap-2">
          <DensityToggle storageKey="logs-firewall" label="Firewall log table density" />
          <Tooltip>
            <TooltipTrigger asChild>
              <Button size="sm" className="h-11 gap-1.5 lg:h-8" onClick={onExport} disabled={exporting} aria-label="Export CSV">
                {exporting ? <Icons.Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Icons.Download className="h-3.5 w-3.5" />}
                Export CSV
              </Button>
            </TooltipTrigger>
            <TooltipContent side="left" className="max-w-72">
              <p className="font-medium">CSV columns</p>
              <p className="font-mono text-[11px] leading-relaxed">
                timestamp, src_ip, src_port, dst_ip, dst_port, protocol, action, rule_name, app_name, bytes, packets, user_name, id
              </p>
              <p className="mt-1 text-[11px]">Applies the current filter · 10 000-row export cap.</p>
            </TooltipContent>
          </Tooltip>
        </div>
      </div>

      {/* action filter chips — 24h counts from the LOCKED stats payload (window-level, not filter-scoped) */}
      <div className="no-print flex flex-wrap items-center gap-1.5">
        <span className="mr-1 text-xs font-medium text-zinc-500">Action</span>
        {ACTIONS.map((a) => {
          const active = filters.action === a;
          const count = actionCounts[a];
          return (
            <button
              key={a}
              type="button"
              aria-pressed={active}
              onClick={() => apply({ ...inputs, action: active ? "" : a })}
              className={cn(
                "inline-flex h-11 items-center gap-1.5 rounded-full border px-2.5 text-xs transition-colors lg:h-7",
                active
                  ? "border-zinc-500/30 bg-zinc-500/10 font-medium text-zinc-600 dark:text-zinc-300"
                  : "border-zinc-200 text-zinc-500 hover:bg-zinc-100 dark:border-zinc-800 dark:text-zinc-400 dark:hover:bg-zinc-800",
              )}
            >
              {a}
              {count !== undefined && <span className="font-mono tabular-nums text-zinc-400">{count.toLocaleString()}</span>}
            </button>
          );
        })}
        {!filters.action && <span className="text-xs text-zinc-400">(any)</span>}
        {stats.isFetching && !stats.data && <span className="text-xs text-zinc-400">counts…</span>}
      </div>

      {rangeError && (
        <Alert className="border-amber-500/40 bg-amber-500/5 text-amber-600 dark:text-amber-400">
          <Icons.TriangleAlert className="h-4 w-4" />
          <AlertDescription>{rangeError}</AlertDescription>
        </Alert>
      )}

      {/* retention banner */}
      <Alert className="border-zinc-500/20 bg-zinc-500/5">
        <Icons.Database className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
        <AlertDescription className="text-xs text-zinc-600 dark:text-zinc-400">
          Rolling 50 000-row window — oldest flows are pruned by the retention job (DATA_LIFECYCLE §4). Exports cap at 10 000 rows.
        </AlertDescription>
      </Alert>

      {/* table — card is the grid item: min-w-0 stops the min-w table's min-content from widening the page; the table scrolls inside, paginator stays put */}
      <div className="min-w-0 rounded-lg border border-zinc-200 dark:border-zinc-800">
        {query.isLoading ? (
          <TableSkeleton rows={8} cols={9} />
        ) : query.isError ? (
          <QueryError error={query.error} onRetry={() => void query.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyBlock
            icon={<Icons.Waves className="h-6 w-6" />}
            title="No flows match this filter"
            description="Loosen the filters or widen the time range."
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <Table className={cn("min-w-[960px]", density === "compact" && "[&_th]:h-9 [&_th]:px-1.5 [&_td]:px-1.5 [&_td]:py-1 [&_td]:text-xs")}>
                <TableHeader>
                  <TableRow>
                    <TableHead>Timestamp</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Destination</TableHead>
                    <TableHead>Proto</TableHead>
                    <TableHead>Action</TableHead>
                    <TableHead>App</TableHead>
                    <TableHead>Rule</TableHead>
                    <TableHead className="text-right">Bytes</TableHead>
                    <TableHead>User</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((r) => (
                    <TableRow key={r.id} className="cursor-pointer" onClick={() => setSelected(r)}>
                      <TableCell className="whitespace-nowrap font-mono text-xs tabular-nums">{fmtTs(r.timestamp)}</TableCell>
                      <TableCell className="max-w-36 min-w-0 truncate font-mono text-xs" title={r.srcIp ?? undefined}>
                        {r.srcIp ?? "—"}
                        {r.srcPort ? <span className="text-zinc-400">:{r.srcPort}</span> : null}
                      </TableCell>
                      <TableCell className="max-w-36 min-w-0 truncate font-mono text-xs" title={r.dstIp ?? undefined}>
                        {r.dstIp ?? "—"}
                        {r.dstPort ? <span className="text-zinc-400">:{r.dstPort}</span> : null}
                      </TableCell>
                      <TableCell>
                        <ProtocolBadge protocol={r.protocol} />
                      </TableCell>
                      <TableCell>
                        <ActionBadge action={r.action} />
                      </TableCell>
                      <TableCell className="max-w-36 truncate text-xs">{r.appName ?? "—"}</TableCell>
                      <TableCell className="max-w-36 truncate text-xs">{r.ruleName ?? "—"}</TableCell>
                      <TableCell className="text-right font-mono text-xs tabular-nums">{humanizeBytes(r.bytes)}</TableCell>
                      <TableCell className="max-w-28 truncate text-xs">{r.userName ?? "—"}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            {meta && (
              <Paginator
                page={meta.page}
                totalPages={meta.totalPages}
                total={meta.total}
                limit={meta.limit}
                onPage={setPage}
                className="border-t border-zinc-200 dark:border-zinc-800"
              />
            )}
          </>
        )}
      </div>

      {/* detail drawer */}
      <Sheet open={selected !== null} onOpenChange={(open) => !open && setSelected(null)}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-md">
          <SheetHeader>
            <SheetTitle className="flex items-center gap-2 text-base">
              Flow detail
              <ActionBadge action={selected?.action ?? null} />
            </SheetTitle>
            <SheetDescription className="font-mono text-xs">raw id {selected?.id ?? "—"}</SheetDescription>
          </SheetHeader>
          {selected && (
            <div className="px-4 pb-6">
              <DetailRow label="Timestamp" value={fmtTs(selected.timestamp)} />
              <DetailRow label="Source" value={`${selected.srcIp ?? "—"}${selected.srcPort ? `:${selected.srcPort}` : ""}`} mono />
              <DetailRow label="Destination" value={`${selected.dstIp ?? "—"}${selected.dstPort ? `:${selected.dstPort}` : ""}`} mono />
              <DetailRow label="Protocol" value={selected.protocol ?? "—"} mono />
              <DetailRow label="Action" value={<ActionBadge action={selected.action} />} />
              <DetailRow label="Bytes" value={humanizeBytes(selected.bytes)} />
              <DetailRow label="Packets" value={selected.packets.toLocaleString()} />
              <DetailRow label="App (nDPI)" value={selected.appName ?? "—"} />
              <DetailRow label="Rule" value={selected.ruleName ?? "—"} />
              <DetailRow label="User" value={selected.userName ?? "—"} />
              {/* cross-view pivot — deep-link the flow's IPs into Log Search (R6 pass 3) */}
              {(selected.srcIp || selected.dstIp) && (
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {selected.srcIp && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-11 gap-1.5 lg:h-8"
                      aria-label={`Search source IP ${selected.srcIp} in Log Search`}
                      onClick={() => {
                        setSelected(null);
                        window.location.hash = `#/logs/search?q=${encodeURIComponent(selected.srcIp ?? "")}`;
                      }}
                    >
                      <Icons.Search className="h-3.5 w-3.5" />
                      src in Log Search
                    </Button>
                  )}
                  {selected.dstIp && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-11 gap-1.5 lg:h-8"
                      aria-label={`Search destination IP ${selected.dstIp} in Log Search`}
                      onClick={() => {
                        setSelected(null);
                        window.location.hash = `#/logs/search?q=${encodeURIComponent(selected.dstIp ?? "")}`;
                      }}
                    >
                      <Icons.Search className="h-3.5 w-3.5" />
                      dst in Log Search
                    </Button>
                  )}
                </div>
              )}
            </div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
