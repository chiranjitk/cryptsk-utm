"use client";

/**
 * Log Search view (M12 spec 2.13) — hash #/logs/search.
 * Toolbar: dataset segmented buttons (Firewall/IPS/Audit), debounced
 * free-text query, per-dataset severity/action selects, since/until date
 * inputs, page size, CEF/LEEF export (firewall only) and "Save search".
 * Left rail (lg+) lists saved searches (click applies, trash deletes).
 * Results table with server pagination + "N total".
 * Theme per ADR-019: white & enterprise blue.
 */

import { useEffect, useMemo, useState } from "react";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  ConfirmDialog,
  EmptyBlock,
  FieldLabel,
  QueryError,
  TableSkeleton,
  toastErr,
  toastOk,
} from "../firewall/fw-ui";
import { cn } from "@/lib/utils";
import {
  fieldErrorsOf,
  qs,
  searchApi,
  type SavedSearchDTO,
  type SearchDataset,
  type SearchRow,
} from "./search-api";

// ── constants ───────────────────────────────────────────────────────────────

const DATASETS: Array<{ id: SearchDataset; label: string; icon: React.ComponentType<{ className?: string }> }> = [
  { id: "firewall", label: "Firewall", icon: Icons.Shield },
  { id: "ips", label: "IPS", icon: Icons.Bug },
  { id: "audit", label: "Audit", icon: Icons.ScrollText },
];

const FW_ACTIONS = ["allow", "deny", "drop", "reject"] as const;
const IPS_ACTIONS = ["alert", "drop", "reject", "bypass", "suppressed"] as const;
const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;

const DATASET_BADGE: Record<SearchDataset, string> = {
  firewall: "border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400",
  ips: "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400",
  audit: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
};

const SEVERITY_BADGE: Record<string, string> = {
  critical: "border-transparent bg-rose-600 text-white",
  high: "border-orange-500/40 bg-orange-500/10 text-orange-600 dark:text-orange-400",
  medium: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  low: "border-zinc-300 text-zinc-500 dark:border-zinc-700",
  info: "border-zinc-300 text-zinc-500 dark:border-zinc-700",
};

function fmtTs(ts: string): string {
  return new Date(ts).toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function toDayInput(iso: string | undefined): string {
  return iso ? iso.slice(0, 10) : "";
}

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <Badge variant="outline" className={cn("font-medium capitalize", SEVERITY_BADGE[severity] ?? SEVERITY_BADGE.info)}>
      {severity}
    </Badge>
  );
}

// ── view ────────────────────────────────────────────────────────────────────

export function SearchView() {
  const queryClient = useQueryClient();
  const invalidateSaved = () => void queryClient.invalidateQueries({ queryKey: ["m12", "saved"] });

  // ── filter state ──
  const [dataset, setDataset] = useState<SearchDataset>("firewall");
  const [qInput, setQInput] = useState("");
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("");
  const [action, setAction] = useState("");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState<10 | 25 | 50 | 100>(25);

  // debounced free-text (300 ms)
  useEffect(() => {
    const t = setTimeout(() => {
      setQ(qInput.trim());
      setPage(1);
    }, 300);
    return () => clearTimeout(t);
  }, [qInput]);

  const switchDataset = (d: SearchDataset) => {
    setDataset(d);
    setSeverity("");
    setAction("");
    setPage(1);
  };

  const sinceIso = since ? `${since}T00:00:00.000Z` : "";
  const untilIso = until ? `${until}T23:59:59.999Z` : "";
  const params = qs({
    dataset,
    q,
    severity: dataset === "ips" ? severity : "",
    action: dataset === "audit" ? "" : action,
    since: sinceIso,
    until: untilIso,
    page,
    limit,
  });

  const searchQuery = useQuery({
    queryKey: ["m12", "search", params],
    queryFn: () => searchApi.search(params),
    placeholderData: keepPreviousData,
  });
  const savedQuery = useQuery({ queryKey: ["m12", "saved"], queryFn: searchApi.listSaved });

  const activeFilterCount = [q, severity, action, since, until].filter(Boolean).length;
  const clearFilters = () => {
    setQInput("");
    setQ("");
    setSeverity("");
    setAction("");
    setSince("");
    setUntil("");
    setPage(1);
  };

  // ── export CEF/LEEF (firewall only per spec) ──
  const doExport = async (format: "cef" | "leef") => {
    try {
      const r = await searchApi.exportLogs("firewall", format, 100);
      toastOk(`${format.toUpperCase()} export downloaded`, `${r.lines} events → ${r.filename}`);
    } catch (err) {
      toastErr(err, `${format.toUpperCase()} export failed`);
    }
  };

  // ── save search dialog ──
  const [saveOpen, setSaveOpen] = useState(false);
  const [saveName, setSaveName] = useState("");
  const [saveErr, setSaveErr] = useState<Record<string, string[]>>({});
  const saveMut = useMutation({
    mutationFn: () =>
      searchApi.createSaved({
        name: saveName.trim(),
        dataset,
        queryText: q,
        filters: {
          ...(action ? { action } : {}),
          ...(severity ? { severity } : {}),
          ...(sinceIso ? { since: sinceIso } : {}),
          ...(untilIso ? { until: untilIso } : {}),
        },
      }),
    onSuccess: (s) => {
      toastOk("Search saved", `"${s.name}" is pinned to the left rail`);
      setSaveOpen(false);
      setSaveName("");
      setSaveErr({});
      invalidateSaved();
    },
    onError: (err) => {
      const fe = fieldErrorsOf(err);
      setSaveErr(fe);
      if (!fe.name) toastErr(err, "Save failed");
    },
  });

  // ── apply + delete saved searches ──
  const applySaved = (s: SavedSearchDTO) => {
    setDataset(s.dataset);
    setQInput(s.queryText);
    setQ(s.queryText.trim());
    setSeverity(s.filters.severity ?? "");
    setAction(s.filters.action ?? "");
    const sinceDays = Number(s.filters.sinceDays);
    setSince(sinceDays > 0 ? new Date(Date.now() - sinceDays * 86_400_000).toISOString().slice(0, 10) : toDayInput(s.filters.since));
    setUntil(toDayInput(s.filters.until));
    setPage(1);
  };

  const [deletingSaved, setDeletingSaved] = useState<SavedSearchDTO | null>(null);
  const delSavedMut = useMutation({
    mutationFn: (id: number) => searchApi.deleteSaved(id),
    onSuccess: () => {
      toastOk("Saved search deleted");
      setDeletingSaved(null);
      invalidateSaved();
    },
    onError: (err) => toastErr(err, "Delete failed"),
  });

  const rows: SearchRow[] = searchQuery.data?.data ?? [];
  const meta = searchQuery.data?.meta;
  const savedRows = useMemo(() => savedQuery.data ?? [], [savedQuery.data]);

  return (
    <div className="space-y-3">
      <p className="text-xs text-zinc-500">
        One search across firewall flows, IPS events and the audit trail — save frequent filter sets, export firewall events as CEF or LEEF for your SIEM.
      </p>

      {/* ── toolbar ── */}
      <div className="flex flex-wrap items-end gap-2">
        <div className="inline-flex h-9 overflow-hidden rounded-md border border-zinc-200 dark:border-zinc-800" role="group" aria-label="Dataset">
          {DATASETS.map((d, i) => {
            const Icon = d.icon;
            const active = dataset === d.id;
            return (
              <button
                key={d.id}
                type="button"
                aria-pressed={active}
                onClick={() => switchDataset(d.id)}
                className={cn(
                  "flex min-h-9 items-center gap-1.5 px-3 text-xs font-medium transition-colors",
                  i > 0 && "border-l border-zinc-200 dark:border-zinc-800",
                  active
                    ? "bg-blue-600 text-white hover:bg-blue-700"
                    : "bg-white text-zinc-600 hover:bg-blue-500/10 dark:bg-zinc-950 dark:text-zinc-300 dark:hover:bg-blue-500/10",
                )}
              >
                <Icon className="h-3.5 w-3.5" />
                {d.label}
              </button>
            );
          })}
        </div>

        <div className="min-w-52 flex-1">
          <Input
            value={qInput}
            onChange={(e) => setQInput(e.target.value)}
            placeholder={dataset === "firewall" ? "Search src, dst, action, rule…" : dataset === "ips" ? "Search message, sid, src…" : "Search user, action, object…"}
            className="h-9 text-xs"
            aria-label="Free-text query"
          />
        </div>

        {dataset === "ips" && (
          <Select
            value={severity || "any"}
            onValueChange={(v) => {
              setSeverity(v === "any" ? "" : v);
              setPage(1);
            }}
          >
            <SelectTrigger className="h-9 w-32 text-xs" aria-label="Severity">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="any">any severity</SelectItem>
              {SEVERITIES.map((s) => (
                <SelectItem key={s} value={s} className="capitalize">
                  {s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}

        {dataset !== "audit" && (
          <Select
            value={action || "any"}
            onValueChange={(v) => {
              setAction(v === "any" ? "" : v);
              setPage(1);
            }}
          >
            <SelectTrigger className="h-9 w-32 text-xs" aria-label="Action">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="any">any action</SelectItem>
              {(dataset === "firewall" ? FW_ACTIONS : IPS_ACTIONS).map((a) => (
                <SelectItem key={a} value={a}>
                  {a}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}

        <Input
          type="date"
          value={since}
          onChange={(e) => {
            setSince(e.target.value);
            setPage(1);
          }}
          className="h-9 w-36 text-xs"
          aria-label="Since"
        />
        <Input
          type="date"
          value={until}
          onChange={(e) => {
            setUntil(e.target.value);
            setPage(1);
          }}
          className="h-9 w-36 text-xs"
          aria-label="Until"
        />

        <Select
          value={String(limit)}
          onValueChange={(v) => {
            setLimit(Number(v) as 10 | 25 | 50 | 100);
            setPage(1);
          }}
        >
          <SelectTrigger className="h-9 w-24 text-xs" aria-label="Page size">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {[10, 25, 50, 100].map((n) => (
              <SelectItem key={n} value={String(n)}>
                {n} / page
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        {activeFilterCount > 0 && (
          <Button variant="ghost" size="sm" className="h-9 gap-1 text-zinc-500" onClick={clearFilters}>
            <Icons.X className="h-3.5 w-3.5" />
            Clear
          </Button>
        )}

        {dataset === "firewall" && (
          <div className="ml-auto flex items-center gap-1.5">
            <Button variant="outline" size="sm" className="h-9 gap-1.5" onClick={() => void doExport("cef")}>
              <Icons.Download className="h-3.5 w-3.5" />
              CEF
            </Button>
            <Button variant="outline" size="sm" className="h-9 gap-1.5" onClick={() => void doExport("leef")}>
              <Icons.Download className="h-3.5 w-3.5" />
              LEEF
            </Button>
          </div>
        )}

        <Button
          size="sm"
          className={cn("h-9 gap-1.5 bg-blue-600 text-white hover:bg-blue-700", dataset === "firewall" && "ml-0")}
          onClick={() => {
            setSaveName("");
            setSaveErr({});
            setSaveOpen(true);
          }}
        >
          <Icons.BookmarkPlus className="h-3.5 w-3.5" />
          Save search
        </Button>
      </div>

      {/* ── body: saved rail + results ── */}
      <div className="grid items-start gap-4 lg:grid-cols-[260px_1fr]">
        {/* left rail — saved searches */}
        <Card className="hidden lg:block">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-1.5 text-sm">
              <Icons.Bookmark className="h-4 w-4 text-blue-600 dark:text-blue-400" />
              Saved searches
              <Badge variant="outline" className="ml-auto border-blue-500/40 bg-blue-500/10 px-1.5 text-[10px] text-blue-600 dark:text-blue-400">
                {savedRows.length}
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="max-h-96 space-y-1 overflow-y-auto p-2 pt-0">
            {savedQuery.isLoading ? (
              <div className="space-y-1.5 p-1">
                {[...Array(3)].map((_, i) => (
                  <div key={i} className="h-9 animate-pulse rounded bg-zinc-100 dark:bg-zinc-800" />
                ))}
              </div>
            ) : savedRows.length === 0 ? (
              <p className="px-2 py-6 text-center text-xs text-zinc-400">
                Nothing saved yet — tune the filters and press “Save search”.
              </p>
            ) : (
              savedRows.map((s) => (
                <div
                  key={s.id}
                  className={cn(
                    "group flex items-center gap-1 rounded-md border px-2 py-1.5 transition-colors hover:bg-blue-500/10",
                    "border-zinc-200 dark:border-zinc-800",
                  )}
                >
                  <button
                    type="button"
                    onClick={() => applySaved(s)}
                    className="flex min-w-0 flex-1 flex-col items-start gap-0.5 text-left"
                  >
                    <span className="w-full truncate text-xs font-medium">{s.name}</span>
                    <span className="flex items-center gap-1 text-[10px] text-zinc-400">
                      <span className="uppercase">{s.dataset}</span>
                      {s.queryText ? <span className="truncate font-mono">· {s.queryText}</span> : null}
                    </span>
                  </button>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7 shrink-0 text-zinc-400 opacity-0 transition-opacity hover:text-rose-600 group-hover:opacity-100"
                    aria-label={`Delete ${s.name}`}
                    onClick={() => setDeletingSaved(s)}
                  >
                    <Icons.Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              ))
            )}
          </CardContent>
        </Card>

        {/* results */}
        <div className="min-w-0 space-y-2">
          <div className="rounded-lg border border-zinc-200 dark:border-zinc-800">
            {searchQuery.isLoading ? (
              <TableSkeleton rows={8} cols={5} />
            ) : searchQuery.isError ? (
              <QueryError error={searchQuery.error} onRetry={() => void searchQuery.refetch()} />
            ) : rows.length === 0 ? (
              <EmptyBlock
                icon={<Icons.FileSearch className="h-6 w-6" />}
                title="No events match this filter"
                description="Loosen the filters, widen the time range, or switch dataset."
              />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-24">Dataset</TableHead>
                    <TableHead className="w-36">Time</TableHead>
                    <TableHead>Event</TableHead>
                    <TableHead className="hidden md:table-cell">Details</TableHead>
                    <TableHead className="w-24">Severity</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((r) => (
                    <TableRow key={`${r.dataset}-${r.id}`}>
                      <TableCell>
                        <Badge variant="outline" className={cn("font-medium capitalize", DATASET_BADGE[r.dataset])}>
                          {r.dataset}
                        </Badge>
                      </TableCell>
                      <TableCell className="whitespace-nowrap font-mono text-xs tabular-nums">{fmtTs(r.ts)}</TableCell>
                      <TableCell className="max-w-72 truncate text-xs font-medium">{r.headline}</TableCell>
                      <TableCell className="hidden max-w-72 truncate font-mono text-[11px] text-zinc-500 md:table-cell">
                        {r.detail || "—"}
                      </TableCell>
                      <TableCell>{r.severity ? <SeverityBadge severity={r.severity} /> : <span className="text-xs text-zinc-400">—</span>}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </div>

          {/* pagination */}
          <div className="flex flex-wrap items-center justify-between gap-2 px-1">
            <p className="text-xs text-zinc-500">
              {meta ? (
                <>
                  Page <span className="font-medium text-zinc-700 dark:text-zinc-300">{meta.page}</span> of{" "}
                  <span className="font-medium text-zinc-700 dark:text-zinc-300">{meta.totalPages}</span> ·{" "}
                  <span className="font-medium text-zinc-700 dark:text-zinc-300">{meta.total}</span> events total
                </>
              ) : (
                "…"
              )}
            </p>
            <div className="flex gap-1.5">
              <Button
                variant="outline"
                size="sm"
                className="h-8 gap-1"
                disabled={page <= 1 || searchQuery.isFetching}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                <Icons.ChevronLeft className="h-3.5 w-3.5" />
                Prev
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="h-8 gap-1"
                disabled={!meta || page >= meta.totalPages || searchQuery.isFetching}
                onClick={() => setPage((p) => p + 1)}
              >
                Next
                <Icons.ChevronRight className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>
        </div>
      </div>

      {/* ── save search dialog ── */}
      <Dialog open={saveOpen} onOpenChange={setSaveOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Save current search</DialogTitle>
            <DialogDescription>
              Pins dataset, query text and filters ({dataset}) to the left rail — click a saved search to re-apply it.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-1">
            <FieldLabel hint="required · unique">Name</FieldLabel>
            <Input
              value={saveName}
              onChange={(e) => setSaveName(e.target.value)}
              placeholder="e.g. Blocked inbound last 7d"
              autoFocus
            />
            {saveErr.name?.[0] ? <p className="text-xs text-rose-600">{saveErr.name[0]}</p> : null}
          </div>
          <div className="rounded-md border border-zinc-200 p-3 text-xs text-zinc-500 dark:border-zinc-800">
            <p>
              <span className="font-medium text-zinc-700 dark:text-zinc-300">Dataset:</span> {dataset}
            </p>
            <p>
              <span className="font-medium text-zinc-700 dark:text-zinc-300">Query:</span> {q || "(empty)"}
            </p>
            <p>
              <span className="font-medium text-zinc-700 dark:text-zinc-300">Filters:</span>{" "}
              {[severity, action, sinceIso && `since ${since}`, untilIso && `until ${until}`].filter(Boolean).join(", ") || "none"}
            </p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setSaveOpen(false)}>
              Cancel
            </Button>
            <Button
              className="bg-blue-600 text-white hover:bg-blue-700"
              disabled={saveMut.isPending || saveName.trim().length === 0}
              onClick={() => saveMut.mutate()}
            >
              {saveMut.isPending ? <Icons.Loader2 className="mr-1 h-4 w-4 animate-spin" /> : <Icons.BookmarkPlus className="mr-1 h-4 w-4" />}
              Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={deletingSaved != null}
        onOpenChange={(open) => !open && setDeletingSaved(null)}
        title={`Delete saved search "${deletingSaved?.name ?? ""}"?`}
        description="The saved filter set is removed. This cannot be undone."
        confirmLabel="Delete"
        loading={delSavedMut.isPending}
        onConfirm={() => deletingSaved && delSavedMut.mutate(deletingSaved.id)}
      />
    </div>
  );
}
