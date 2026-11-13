"use client";

/**
 * #/logs/ips (M09 §4) — IPS event page: severity multi-chips, category/q/
 * since/until filters, suppressed badge, and a "Suppress" row action that
 * REUSES M04's POST /api/v1/ips/events/{id}/suppress (do not duplicate).
 * The mutated row is patched into the current page cache — no full reload.
 */

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
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
import { EmptyBlock, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";
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
  const [suppressTarget, setSuppressTarget] = useState<IpsEventDTO | null>(null);
  const queryClient = useQueryClient();

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
  const queryKey = useMemo(() => ["logs", "ips", filters, page] as const, [filters, page]);
  const query = useQuery({
    queryKey,
    queryFn: () => logsApi.listIps(params),
  });

  const suppress = useMutation({
    mutationFn: ({ id, duration }: { id: number; duration: "24h" | "7d" | "forever" }) =>
      logsApi.suppressIpsEvent(id, duration),
    onSuccess: (updated) => {
      // patch the row into the current page cache (M09 acceptance: no full reload)
      queryClient.setQueryData<Paged<IpsEventDTO>>(queryKey, (old) =>
        old
          ? { ...old, data: old.data.map((r) => (r.id === updated.id ? { ...r, ...updated } : r)) }
          : old,
      );
      setSuppressTarget(null);
      toastOk("Event suppressed", updated.suppressedUntil ? `Until ${fmtTs(updated.suppressedUntil)}` : "Suppressed forever");
    },
    onError: (err) => toastErr(err, "Suppress failed"),
  });

  const rows = query.data?.data ?? [];
  const meta = query.data?.meta;

  return (
    <div className="grid gap-3">
      {/* filter bar */}
      <div className="no-print flex flex-wrap items-center gap-2">
        <div className="relative">
          <Icons.Search className="absolute left-2.5 top-2.5 h-4 w-4 text-zinc-400" />
          <Input
            value={inputs.q}
            onChange={(e) => setInputs({ ...inputs, q: e.target.value })}
            onKeyDown={(e) => e.key === "Enter" && commitText()}
            onBlur={commitText}
            placeholder="Search message/sid/ip…"
            className="w-60 pl-8"
          />
        </div>
        <Select value={filters.category || "any"} onValueChange={(v) => apply({ ...inputs, category: v === "any" ? "" : v })}>
          <SelectTrigger className="w-40">
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
          className="w-56 text-xs"
          aria-label="Since"
        />
        <Input
          type="datetime-local"
          value={inputs.until}
          onChange={(e) => apply({ ...inputs, until: e.target.value })}
          className="w-56 text-xs"
          aria-label="Until"
        />
      </div>

      {/* severity multi-chips — empty selection = any */}
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
                "rounded-full border px-2.5 py-1 text-xs transition-colors",
                active
                  ? "border-zinc-500/30 bg-zinc-500/10 font-medium text-zinc-600 dark:text-zinc-300"
                  : "border-zinc-200 text-zinc-500 hover:bg-zinc-100 dark:border-zinc-800 dark:text-zinc-400 dark:hover:bg-zinc-800",
              )}
            >
              {s}
            </button>
          );
        })}
        {filters.severities.length === 0 && <span className="text-xs text-zinc-400">(any)</span>}
        {(filters.severities.length > 0 || filters.category || filters.q || filters.since || filters.until) && (
          <Button variant="ghost" size="sm" className="ml-2 h-7 gap-1 text-zinc-500" onClick={() => apply(EMPTY_FILTERS)}>
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

      {/* table */}
      <div className="rounded-lg border border-zinc-200 dark:border-zinc-800">
        {query.isLoading ? (
          <TableSkeleton rows={8} cols={8} />
        ) : query.isError ? (
          <QueryError error={query.error} onRetry={() => void query.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyBlock icon={<Icons.Siren className="h-6 w-6" />} title="No IPS events match this filter" description="Loosen the severity/category filters or widen the time range." />
        ) : (
          <>
            <Table>
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
                    <TableCell className="max-w-64 truncate text-xs text-zinc-600 dark:text-zinc-300">{r.message ?? "—"}</TableCell>
                    <TableCell className="whitespace-nowrap font-mono text-xs">
                      {r.srcIp ?? "—"} → {r.dstIp ?? "—"}
                    </TableCell>
                    <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                      {r.action !== "suppressed" && (
                        <Button variant="outline" size="sm" className="h-7 gap-1 px-2 text-xs" onClick={() => setSuppressTarget(r)}>
                          <Icons.BellOff className="h-3 w-3" />
                          Suppress
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
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

      {/* suppress duration dialog — M04 endpoint reuse */}
      <Dialog open={suppressTarget !== null} onOpenChange={(open) => !open && setSuppressTarget(null)}>
        <DialogContent className="sm:max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base">
              <Icons.BellOff className="h-4 w-4" />
              Suppress event {suppressTarget?.sid ?? `#${suppressTarget?.id ?? ""}`}
            </DialogTitle>
            <DialogDescription>
              Matching events are muted for the chosen duration (M04 exceptions). The rule itself is not changed.
            </DialogDescription>
          </DialogHeader>
          <div className="grid grid-cols-3 gap-2">
            {(["24h", "7d", "forever"] as const).map((d) => (
              <Button
                key={d}
                variant="outline"
                disabled={suppress.isPending}
                onClick={() => suppressTarget && suppress.mutate({ id: suppressTarget.id, duration: d })}
              >
                {d === "forever" ? "forever" : d}
              </Button>
            ))}
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setSuppressTarget(null)}>
              Cancel
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

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
              {selected.action !== "suppressed" && (
                <Button
                  variant="outline"
                  size="sm"
                  className="mt-3 gap-1.5"
                  onClick={() => {
                    setSuppressTarget(selected);
                    setSelected(null);
                  }}
                >
                  <Icons.BellOff className="h-3.5 w-3.5" />
                  Suppress…
                </Button>
              )}
            </div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
