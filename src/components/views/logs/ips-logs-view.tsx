"use client";

/**
 * #/logs/ips (M09 §4) — IPS event page: severity multi-chips (SEVERITY_TONE
 * parity with #/ips/events), category/q/since/until filters, suppressed badge,
 * and a "Suppress" row action that REUSES M04's confirm-first SuppressMenu
 * (ips-ui — dropdown → confirm dialog → POST /api/v1/ips/events/{id}/suppress).
 * The mutated row is patched into the current page cache — no full reload.
 * Detail sheet also pivots: "Open sid in IPS triage" deep-links `#/ips/events?sid=`.
 */

import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
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
import { cn } from "@/lib/utils";
import { DensityToggle, EmptyBlock, QueryError, TableSkeleton, useTableDensity } from "../firewall/fw-ui";
import { SEVERITY_TONE, SuppressMenu, type SuppressContext } from "../ips/ips-ui";
import { logsApi, qs, type IpsEventDTO, type Paged } from "./logs-api";
import { IpsActionBadge, Paginator, SeverityBadge, fmtTs, localInputToIso } from "./logs-ui";

const LIMIT = 25;

/** Categories the generator emits (M09 §4) — static list keeps the Select stable. */
const CATEGORIES = ["scan", "trojan", "web_attack", "policy", "exploit", "botnet", "dos", "info"] as const;
const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

interface Filters {
  severities: string[];
  category: string;
  q: string;
  since: string;
  until: string;
}

const EMPTY_FILTERS: Filters = { severities: [], category: "", q: "", since: "", until: "" };

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

export function IpsLogsView() {
  const [inputs, setInputs] = useState<Filters>(EMPTY_FILTERS);
  const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS); // applied
  const [page, setPage] = useState(1);
  const [rangeError, setRangeError] = useState<string | null>(null);
  const [selected, setSelected] = useState<IpsEventDTO | null>(null);
  const queryClient = useQueryClient();
  const [density] = useTableDensity("logs-ips");

  // row-key → patch map survives SuppressMenu's async POST without a page reload
  const queryKey = useMemo(() => ["logs", "ips", filters, page] as const, [filters, page]);

  const apply = (next: Filters) => {
    if (rangeInvalid(next)) {
      setRangeError("‘Until’ must not be earlier than ‘Since’.");
      return;
    }
    setRangeError(null);
    setInputs(next);
    setFilters(next);
    setPage(1);
  };
  const commitText = () => {
    if (inputs !== filters && !rangeInvalid(inputs)) apply(inputs);
  };

  const isoFilters = useMemo(
    () => ({
      severity: filters.severities.join(","),
      category: filters.category,
      q: filters.q,
      since: localInputToIso(filters.since),
      until: localInputToIso(filters.until),
    }),
    [filters],
  );

  const params = qs({ ...isoFilters, page, limit: LIMIT });
  const query = useQuery({
    queryKey,
    queryFn: () => logsApi.listIps(params),
  });

  /** SuppressMenu already POSTs + toasts — this patches the page cache (M09 acceptance: no full reload). */
  const patchSuppressed = (id: number, duration: "24h" | "7d" | "forever") => {
    const suppressedUntil = duration === "24h" ? new Date(Date.now() + 24 * 3600_000).toISOString() : duration === "7d" ? new Date(Date.now() + 7 * 24 * 3600_000).toISOString() : null;
    queryClient.setQueryData<Paged<IpsEventDTO>>(queryKey, (old) =>
      old ? { ...old, data: old.data.map((r) => (r.id === id ? { ...r, action: "suppressed", suppressedUntil } : r)) } : old,
    );
  };

  const suppressContextOf = (r: IpsEventDTO): SuppressContext => ({
    id: r.id,
    severity: (r.severity as SuppressContext["severity"]) ?? "info",
    sid: r.sid,
    category: r.category,
    message: r.message,
    action: r.action,
  });

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
            placeholder="Search message/sid/ip…"
            className="h-11 w-60 pl-8 lg:h-9"
          />
        </div>
        <Select value={filters.category || "any"} onValueChange={(v) => apply({ ...inputs, category: v === "any" ? "" : v })}>
          <SelectTrigger className="h-11 w-40 lg:h-9">
            <SelectValue placeholder="Category" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="any">any category</SelectItem>
            {CATEGORIES.map((c) => (
              <SelectItem key={c} value={c}>
                {c}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
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
        <div className="ml-auto">
          <DensityToggle storageKey="logs-ips" label="IPS event table density" />
        </div>
      </div>

      {/* severity multi-chips — empty selection = any; active chips take the M04 SEVERITY_TONE recipe (parity with #/ips/events) */}
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="mr-1 text-xs font-medium text-zinc-500">Severity</span>
        {SEVERITIES.map((s) => {
          const active = inputs.severities.includes(s);
          return (
            <button
              key={s}
              type="button"
              aria-pressed={active}
              onClick={() =>
                apply({
                  ...inputs,
                  severities: active ? inputs.severities.filter((x) => x !== s) : [...inputs.severities, s],
                })
              }
              className={cn(
                "inline-flex h-11 items-center rounded-full border px-2.5 text-xs transition-colors lg:h-7 lg:py-1",
                active ? cn("font-medium", SEVERITY_TONE[s].chip) : "border-zinc-200 text-zinc-500 hover:bg-zinc-100 dark:border-zinc-800 dark:text-zinc-400 dark:hover:bg-zinc-800",
              )}
            >
              {s}
            </button>
          );
        })}
        {filters.severities.length === 0 && <span className="text-xs text-zinc-400">(any)</span>}
        {(filters.severities.length > 0 || filters.category || filters.q || filters.since || filters.until) && (
          <Button variant="ghost" size="sm" className="ml-2 h-11 gap-1 text-zinc-500 lg:h-7" onClick={() => apply(EMPTY_FILTERS)}>
            <Icons.X className="h-3.5 w-3.5" />
            Clear
          </Button>
        )}
      </div>

      {rangeError && (
        <div className="rounded-md border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-xs text-amber-600 dark:text-amber-400">
          {rangeError}
        </div>
      )}

      {/* table — card is the grid item: min-w-0 stops the min-w table's min-content from widening the page */}
      <div className="min-w-0 rounded-lg border border-zinc-200 dark:border-zinc-800">
        {query.isLoading ? (
          <TableSkeleton rows={8} cols={8} />
        ) : query.isError ? (
          <QueryError error={query.error} onRetry={() => void query.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyBlock icon={<Icons.Siren className="h-6 w-6" />} title="No IPS events match this filter" description="Loosen the severity/category filters or widen the time range." />
        ) : (
          <>
            <div className="overflow-x-auto">
              <Table className={cn("min-w-[880px]", density === "compact" && "[&_th]:h-9 [&_th]:px-1.5 [&_td]:px-1.5 [&_td]:py-1 [&_td]:text-xs")}>
                <TableHeader>
                  <TableRow>
                    <TableHead>Timestamp</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Action</TableHead>
                    <TableHead>SID</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead>Message</TableHead>
                    <TableHead>Src → Dst</TableHead>
                    <TableHead className="w-24 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((r) => (
                    <TableRow key={r.id} className="cursor-pointer" onClick={() => setSelected(r)}>
                      <TableCell className="whitespace-nowrap font-mono text-xs tabular-nums">{fmtTs(r.timestamp)}</TableCell>
                      <TableCell>
                        <SeverityBadge severity={r.severity} />
                      </TableCell>
                      <TableCell>
                        <IpsActionBadge action={r.action} />
                      </TableCell>
                      <TableCell className="font-mono text-xs">{r.sid ?? "—"}</TableCell>
                      <TableCell className="text-xs">{r.category ?? "—"}</TableCell>
                      <TableCell className="max-w-64 min-w-0 truncate text-xs text-zinc-600 dark:text-zinc-300" title={r.message ?? undefined}>{r.message ?? "—"}</TableCell>
                      <TableCell className="whitespace-nowrap font-mono text-xs">
                        {r.srcIp ?? "—"} → {r.dstIp ?? "—"}
                      </TableCell>
                      <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                        {r.action !== "suppressed" && (
                          <SuppressMenu
                            eventId={r.id}
                            event={suppressContextOf(r)}
                            onSuppressed={(d) => patchSuppressed(r.id, d)}
                            triggerLabel={`Suppress event ${r.sid ?? `#${r.id}`}`}
                          />
                        )}
                      </TableCell>
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
              IPS event
              <SeverityBadge severity={selected?.severity ?? "info"} />
              {selected && <IpsActionBadge action={selected.action} />}
            </SheetTitle>
            <SheetDescription className="font-mono text-xs">raw id {selected?.id ?? "—"}</SheetDescription>
          </SheetHeader>
          {selected && (
            <div className="px-4 pb-6">
              <DetailRow label="Timestamp" value={fmtTs(selected.timestamp)} />
              <DetailRow label="Severity" value={<SeverityBadge severity={selected.severity} />} />
              <DetailRow label="Action" value={<IpsActionBadge action={selected.action} />} />
              <DetailRow label="SID" value={selected.sid ?? "—"} mono />
              <DetailRow label="Category" value={selected.category ?? "—"} />
              <DetailRow label="Message" value={selected.message ?? "—"} />
              <DetailRow label="Source" value={`${selected.srcIp ?? "—"}${selected.srcPort ? `:${selected.srcPort}` : ""}`} mono />
              <DetailRow label="Destination" value={`${selected.dstIp ?? "—"}${selected.dstPort ? `:${selected.dstPort}` : ""}`} mono />
              <DetailRow label="Suppressed until" value={selected.suppressedUntil ? fmtTs(selected.suppressedUntil) : "—"} />
              {/* cross-view pivot — deep-link the sid into M04's triage view (R6 pass 3;
                  events-view reads ?sid= one-shot at mount) */}
              {selected.sid && (
                <div className="mt-3">
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-11 w-full gap-1.5 lg:h-8 lg:w-auto"
                    aria-label={`Open sid ${selected.sid} in IPS triage`}
                    onClick={() => {
                      setSelected(null);
                      window.location.hash = `#/ips/events?sid=${encodeURIComponent(selected.sid ?? "")}`;
                    }}
                  >
                    <Icons.ExternalLink className="h-3.5 w-3.5" />
                    Open sid in IPS triage
                  </Button>
                </div>
              )}
              {selected.action !== "suppressed" && (
                <div className="mt-3">
                  <SuppressMenu
                    eventId={selected.id}
                    event={suppressContextOf(selected)}
                    onSuppressed={(d) => {
                      patchSuppressed(selected.id, d);
                      setSelected(null);
                    }}
                    triggerLabel="Suppress…"
                  />
                </div>
              )}
            </div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
