"use client";

/**
 * #/logs/audit (M09 §4) — append-only audit trail (ADR-011): filters by user
 * (from /api/v1/users), objectType (distinct via groupBy facets), result
 * chips + q/since/until. Detail Sheet renders beforeState/afterState
 * side-by-side through a defensive local JsonFieldViewer. Rows for deleted
 * users keep the stored username string (null userId never crashes).
 */

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
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
import { EmptyBlock, QueryError, TableSkeleton } from "../firewall/fw-ui";
import { logsApi, qs, type AuditLogDTO } from "./logs-api";
import { Paginator, ResultBadge, fmtTs, localInputToIso } from "./logs-ui";

const LIMIT = 25;
const RESULTS = ["success", "failure", "denied"] as const;

interface Filters {
  user: string;
  objectType: string;
  result: string;
  q: string;
  since: string;
  until: string;
}

const EMPTY_FILTERS: Filters = { user: "", objectType: "", result: "", q: "", since: "", until: "" };

function rangeInvalid(f: Pick<Filters, "since" | "until">): boolean {
  return Boolean(f.since && f.until && new Date(f.until).getTime() < new Date(f.since).getTime());
}

function initialsOf(username: string | null): string {
  if (!username) return "?";
  const parts = username.split(/[\s._-]+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return username.slice(0, 2).toUpperCase();
}

/** Monospace, collapsible JSON viewer — parses stored JSON strings defensively. */
function JsonFieldViewer({ raw, label, tone }: { raw: string | null; label: string; tone: "before" | "after" }) {
  const [open, setOpen] = useState(true);
  const text = useMemo(() => {
    if (!raw) return null;
    try {
      const parsed = JSON.parse(raw);
      return JSON.stringify(parsed, null, 2);
    } catch {
      return raw; // not JSON — render as-is
    }
  }, [raw]);
  return (
    <div className="min-w-0 rounded-lg border border-zinc-200 dark:border-zinc-800">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-1.5 border-b border-zinc-200 px-2.5 py-1.5 text-left text-[11px] font-semibold uppercase tracking-wide text-zinc-500 dark:border-zinc-800"
      >
        <Icons.ChevronDown className={cn("h-3.5 w-3.5 transition-transform", !open && "-rotate-90")} />
        {label}
        {tone === "after" && text !== null && (
          <Badge variant="outline" className="ml-auto border-emerald-500/40 bg-emerald-500/10 px-1.5 text-[10px] text-emerald-600 dark:text-emerald-400">
            new
          </Badge>
        )}
        {tone === "before" && text !== null && (
          <Badge variant="outline" className="ml-auto border-zinc-300 px-1.5 text-[10px] text-zinc-500 dark:border-zinc-700">
            previous
          </Badge>
        )}
      </button>
      {open && (
        <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words px-2.5 py-2 font-mono text-[11px] leading-relaxed text-zinc-700 dark:text-zinc-300">
          {text ?? "—"}
        </pre>
      )}
    </div>
  );
}

function DetailRow({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-zinc-100 py-1.5 text-sm dark:border-zinc-800/60">
      <span className="shrink-0 text-xs text-zinc-500">{label}</span>
      <span className={`text-right ${mono ? "font-mono text-xs" : ""}`}>{value ?? "—"}</span>
    </div>
  );
}

export function AuditView() {
  const [inputs, setInputs] = useState<Filters>(EMPTY_FILTERS);
  const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS); // applied
  const [page, setPage] = useState(1);
  const [rangeError, setRangeError] = useState<string | null>(null);
  const [selected, setSelected] = useState<AuditLogDTO | null>(null);

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
      user: filters.user,
      objectType: filters.objectType,
      result: filters.result,
      q: filters.q,
      since: localInputToIso(filters.since),
      until: localInputToIso(filters.until),
    }),
    [filters],
  );

  const params = qs({ ...isoFilters, page, limit: LIMIT });
  const query = useQuery({
    queryKey: ["logs", "audit", filters, page],
    queryFn: () => logsApi.listAudit(params),
  });

  // Distinct objectTypes via groupBy facets (service: distinctAuditObjectTypes).
  const facets = useQuery({
    queryKey: ["logs", "audit", "facets", "objectTypes"],
    queryFn: () => logsApi.auditObjectTypes(),
  });
  // Users list needs identity read — degrades to a plain text input on 403.
  const users = useQuery({
    queryKey: ["logs", "audit", "users"],
    queryFn: () => logsApi.listUsers(100),
    retry: false,
  });

  const rows = query.data?.data ?? [];
  const meta = query.data?.meta;

  return (
    <div className="grid gap-3">
      {/* filter bar */}
      <div className="no-print flex flex-wrap items-center gap-2">
        {users.data ? (
          <Select value={filters.user || "any"} onValueChange={(v) => apply({ ...inputs, user: v === "any" ? "" : v })}>
            <SelectTrigger className="w-44">
              <SelectValue placeholder="User" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="any">any user</SelectItem>
              {users.data.map((u) => (
                <SelectItem key={u.id} value={u.username}>
                  {u.username}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        ) : (
          <Input
            value={inputs.user}
            onChange={(e) => setInputs({ ...inputs, user: e.target.value })}
            onKeyDown={(e) => e.key === "Enter" && commitText()}
            onBlur={commitText}
            placeholder="username"
            className="w-40 text-xs"
          />
        )}
        <Select value={filters.objectType || "any"} onValueChange={(v) => apply({ ...inputs, objectType: v === "any" ? "" : v })}>
          <SelectTrigger className="w-44">
            <SelectValue placeholder="Object type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="any">any object type</SelectItem>
            {(facets.data ?? []).map((t) => (
              <SelectItem key={t} value={t}>
                {t}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <div className="relative">
          <Icons.Search className="absolute left-2.5 top-2.5 h-4 w-4 text-zinc-400" />
          <Input
            value={inputs.q}
            onChange={(e) => setInputs({ ...inputs, q: e.target.value })}
            onKeyDown={(e) => e.key === "Enter" && commitText()}
            onBlur={commitText}
            placeholder="Search action/object/user…"
            className="w-56 pl-8"
          />
        </div>
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
        <div className="flex items-center gap-1.5">
          {RESULTS.map((r) => {
            const active = filters.result === r;
            return (
              <button
                key={r}
                type="button"
                aria-pressed={active}
                onClick={() => apply({ ...inputs, result: active ? "" : r })}
                className={cn(
                  "rounded-full border px-2.5 py-1 text-xs transition-colors",
                  active
                    ? "border-red-600/40 bg-red-600/10 font-medium text-red-700 dark:text-red-500"
                    : "border-zinc-200 text-zinc-500 hover:bg-zinc-100 dark:border-zinc-800 dark:text-zinc-400 dark:hover:bg-zinc-800",
                )}
              >
                {r}
              </button>
            );
          })}
          {(Object.values(filters).some(Boolean)) && (
            <Button variant="ghost" size="sm" className="h-7 gap-1 text-zinc-500" onClick={() => apply(EMPTY_FILTERS)}>
              <Icons.X className="h-3.5 w-3.5" />
              Clear
            </Button>
          )}
        </div>
      </div>

      {rangeError && (
        <div className="rounded-md border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-xs text-amber-600 dark:text-amber-400">
          {rangeError}
        </div>
      )}

      {/* table */}
      <div className="rounded-lg border border-zinc-200 dark:border-zinc-800">
        {query.isLoading ? (
          <TableSkeleton rows={8} cols={7} />
        ) : query.isError ? (
          <QueryError error={query.error} onRetry={() => void query.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyBlock icon={<Icons.ScrollText className="h-6 w-6" />} title="No audit entries match this filter" description="Audit rows are append-only (ADR-011) — try a wider time range." />
        ) : (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Timestamp</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Object type</TableHead>
                  <TableHead>Object name</TableHead>
                  <TableHead>Result</TableHead>
                  <TableHead>Source IP</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((r) => (
                  <TableRow key={r.id} className="cursor-pointer" onClick={() => setSelected(r)}>
                    <TableCell className="whitespace-nowrap font-mono text-xs tabular-nums">{fmtTs(r.createdAt)}</TableCell>
                    <TableCell>
                      <span className="flex items-center gap-2">
                        <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-red-600/10 text-[10px] font-semibold text-red-700 dark:text-red-500">
                          {initialsOf(r.username)}
                        </span>
                        <span className="text-xs">{r.username ?? "(deleted user)"}</span>
                      </span>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="border-zinc-300 bg-zinc-50 font-mono text-[11px] text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300">
                        {r.action}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs">{r.objectType}</TableCell>
                    <TableCell className="max-w-40 truncate text-xs">{r.objectName ?? "—"}</TableCell>
                    <TableCell>
                      <ResultBadge result={r.result} />
                    </TableCell>
                    <TableCell className="font-mono text-xs">{r.sourceIp ?? "—"}</TableCell>
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

      {/* detail drawer */}
      <Sheet open={selected !== null} onOpenChange={(open) => !open && setSelected(null)}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-lg">
          <SheetHeader>
            <SheetTitle className="flex items-center gap-2 text-base">
              Audit entry
              {selected && <ResultBadge result={selected.result} />}
            </SheetTitle>
            <SheetDescription className="font-mono text-xs">raw id {selected?.id ?? "—"}</SheetDescription>
          </SheetHeader>
          {selected && (
            <div className="px-4 pb-6">
              <DetailRow label="Timestamp" value={fmtTs(selected.createdAt)} />
              <DetailRow label="User" value={selected.username ?? "(deleted user)"} />
              <DetailRow label="User id" value={selected.userId ?? "null"} mono />
              <DetailRow label="Action" value={selected.action} mono />
              <DetailRow label="Object" value={`${selected.objectType}${selected.objectId ? ` #${selected.objectId}` : ""}${selected.objectName ? ` — ${selected.objectName}` : ""}`} />
              <DetailRow label="Source IP" value={selected.sourceIp ?? "—"} mono />

              <div className="mt-3 grid gap-2 sm:grid-cols-2">
                <JsonFieldViewer label="Before state" raw={selected.beforeState} tone="before" />
                <JsonFieldViewer label="After state" raw={selected.afterState} tone="after" />
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
