"use client";

/**
 * #/threat-intel/iocs — IOC store (M13 §2.11 tab 2). Server-paged table with
 * severity/category/type/feed/q filters, confidence + reputation meters,
 * manual "Add IOC" dialog, soft-disable switch and delete. R3: per-row
 * selection with bulk disable (sequential calls to the existing per-IOC
 * disable endpoint, progress in the button) and copy-to-clipboard values.
 */

import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
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
import {
  CATEGORIES,
  IOC_TYPES,
  SEVERITIES,
  fmtRelative,
  qs,
  threatIntelApi,
  type IocDTO,
  type IocType,
  type ThreatCategory,
  type ThreatSeverity,
} from "./threat-intel-api";
import { CategoryChip, Meter, SeverityBadge, TypeBadge } from "./ti-ui";
import { ConfirmDialog, EmptyBlock, FieldLabel, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";

const IOCS_KEY = ["threat-intel", "iocs"] as const;
const FEEDS_KEY = ["threat-intel", "feeds"] as const;

// ── add-IOC dialog ──────────────────────────────────────────────────────────

function IocEditor(props: { onClose: () => void }) {
  const queryClient = useQueryClient();
  const [type, setType] = useState<IocType>("ip");
  const [value, setValue] = useState("");
  const [category, setCategory] = useState<ThreatCategory>("malware");
  const [severity, setSeverity] = useState<ThreatSeverity>("warning");
  const [confidence, setConfidence] = useState("70");
  const [description, setDescription] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => threatIntelApi.createIoc(body),
    onSuccess: (created) => {
      toastOk(`IOC added`, `${created.type}:${created.value}`);
      void queryClient.invalidateQueries({ queryKey: ["threat-intel"] });
      props.onClose();
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Save failed"),
  });

  const confidenceNum = Number(confidence);

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-base">Add IOC</DialogTitle>
          <DialogDescription>Manually curated indicator — source is recorded as &quot;manual&quot;.</DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div className="grid grid-cols-[110px_1fr] gap-4">
            <div>
              <FieldLabel>Type</FieldLabel>
              <Select value={type} onValueChange={(v) => setType(v as IocType)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {IOC_TYPES.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel>Value</FieldLabel>
              <Input
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder={type === "cidr" ? "185.222.57.0/24" : type === "hash" ? "e6e5c4a1b0d29f3f…" : "45.155.205.233"}
                className="font-mono text-xs"
              />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel>Category</FieldLabel>
              <Select value={category} onValueChange={(v) => setCategory(v as ThreatCategory)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CATEGORIES.map((c) => (
                    <SelectItem key={c} value={c}>
                      {c}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel>Severity</FieldLabel>
              <Select value={severity} onValueChange={(v) => setSeverity(v as ThreatSeverity)}>
                <SelectTrigger>
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
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel hint="0–100">Confidence</FieldLabel>
              <Input type="number" min={0} max={100} value={confidence} onChange={(e) => setConfidence(e.target.value)} />
            </div>
            <div>
              <FieldLabel hint="optional">Expires at</FieldLabel>
              <Input type="date" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} />
            </div>
          </div>
          <div>
            <FieldLabel hint="optional">Description</FieldLabel>
            <Input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Why this indicator is blocked…" />
          </div>
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button
            className="bg-zinc-700 text-white hover:bg-zinc-800"
            disabled={save.isPending || !value.trim() || !Number.isFinite(confidenceNum) || confidenceNum < 0 || confidenceNum > 100}
            onClick={() =>
              save.mutate({
                type,
                value: value.trim(),
                category,
                severity,
                confidence: confidenceNum,
                description: description.trim() || null,
                expiresAt: expiresAt || null,
              })
            }
          >
            {save.isPending ? "Saving…" : "Add IOC"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── main view ───────────────────────────────────────────────────────────────

export function IocsView() {
  const queryClient = useQueryClient();

  const [severity, setSeverity] = useState<"all" | ThreatSeverity>("all");
  const [category, setCategory] = useState<"all" | ThreatCategory>("all");
  const [type, setType] = useState<"all" | IocType>("all");
  const [feedId, setFeedId] = useState<string>("all");
  const [qInput, setQInput] = useState("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const [addOpen, setAddOpen] = useState(false);
  const [deleting, setDeleting] = useState<IocDTO | null>(null);
  /** id → DTO as selected; kept across pages so bulk disable matches intent */
  const [selected, setSelected] = useState<Map<number, IocDTO>>(new Map());
  const [bulkBusy, setBulkBusy] = useState<{ done: number; total: number } | null>(null);

  // debounce free-text search
  useEffect(() => {
    const t = setTimeout(() => {
      setQ(qInput.trim());
      setPage(1);
    }, 350);
    return () => clearTimeout(t);
  }, [qInput]);

  const feedsQuery = useQuery({ queryKey: FEEDS_KEY, queryFn: threatIntelApi.listFeeds });
  const feeds = feedsQuery.data ?? [];

  const params = useMemo(
    () =>
      qs({
        severity: severity === "all" ? undefined : severity,
        category: category === "all" ? undefined : category,
        type: type === "all" ? undefined : type,
        feedId: feedId === "all" ? undefined : feedId,
        q,
        page,
        limit: 25,
      }),
    [severity, category, type, feedId, q, page],
  );

  const iocsQuery = useQuery({
    queryKey: [...IOCS_KEY, params],
    queryFn: () => threatIntelApi.listIocs(params),
  });
  const meta = iocsQuery.data?.meta;
  const rows = iocsQuery.data?.data ?? [];
  const hasFilters = severity !== "all" || category !== "all" || type !== "all" || feedId !== "all" || q !== "";

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => threatIntelApi.setIocEnabled(id, enabled),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: IOCS_KEY }),
    onError: (e) => toastErr(e, "Toggle failed"),
  });

  // sequential calls to the existing POST /iocs/{id}/disable — no bulk endpoint,
  // progress reported in the button (mission rule: do not change the API)
  const bulkDisable = async () => {
    if (bulkBusy) return;
    const targets = [...selected.values()].filter((r) => r.enabled);
    const alreadyOff = selected.size - targets.length;
    if (targets.length === 0) {
      toastOk("Nothing to disable", alreadyOff > 0 ? `${alreadyOff} selected IOC${alreadyOff === 1 ? " is" : "s are"} already disabled` : undefined);
      setSelected(new Map());
      return;
    }
    setBulkBusy({ done: 0, total: targets.length });
    let ok = 0;
    let failed = 0;
    for (const t of targets) {
      try {
        await threatIntelApi.setIocEnabled(t.id, false);
        ok += 1;
      } catch {
        failed += 1;
      }
      setBulkBusy((b) => (b ? { ...b, done: b.done + 1 } : b));
    }
    setBulkBusy(null);
    setSelected(new Map());
    void queryClient.invalidateQueries({ queryKey: IOCS_KEY });
    if (failed === 0) {
      toastOk(
        `Disabled ${ok} IOC${ok === 1 ? "" : "s"}`,
        alreadyOff > 0 ? `${alreadyOff} selected were already disabled` : "Matching stops for disabled indicators",
      );
    } else {
      toastErr(new Error(`${failed} of ${targets.length} disable calls failed`), `Disabled ${ok}, failed ${failed}`);
    }
  };

  const pageAllSelected = rows.length > 0 && rows.every((r) => selected.has(r.id));
  const someSelected = selected.size > 0;
  const disableableCount = [...selected.values()].filter((r) => r.enabled).length;

  const del = useMutation({
    mutationFn: (id: number) => threatIntelApi.deleteIoc(id),
    onSuccess: () => {
      toastOk("IOC deleted");
      setDeleting(null);
      void queryClient.invalidateQueries({ queryKey: ["threat-intel"] });
    },
    onError: (e) => toastErr(e, "Delete failed"),
  });

  return (
    <div className="space-y-4">
      {/* ── filter bar ─────────────────────────────────────────────────── */}
      <Card>
        <CardContent className="flex flex-wrap items-center gap-2 p-4">
          <Select
            value={severity}
            onValueChange={(v) => {
              setPage(1);
              setSeverity(v as "all" | ThreatSeverity);
            }}
          >
            <SelectTrigger className="h-8 w-36" aria-label="Severity filter">
              <SelectValue placeholder="All severities" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All severities</SelectItem>
              {SEVERITIES.map((s) => (
                <SelectItem key={s} value={s}>
                  {s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select
            value={category}
            onValueChange={(v) => {
              setPage(1);
              setCategory(v as "all" | ThreatCategory);
            }}
          >
            <SelectTrigger className="h-8 w-36" aria-label="Category filter">
              <SelectValue placeholder="All categories" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All categories</SelectItem>
              {CATEGORIES.map((c) => (
                <SelectItem key={c} value={c}>
                  {c}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select
            value={type}
            onValueChange={(v) => {
              setPage(1);
              setType(v as "all" | IocType);
            }}
          >
            <SelectTrigger className="h-8 w-32" aria-label="Type filter">
              <SelectValue placeholder="All types" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All types</SelectItem>
              {IOC_TYPES.map((t) => (
                <SelectItem key={t} value={t}>
                  {t}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select
            value={feedId}
            onValueChange={(v) => {
              setPage(1);
              setFeedId(v);
            }}
          >
            <SelectTrigger className="h-8 w-44" aria-label="Feed filter">
              <SelectValue placeholder="All sources" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All sources</SelectItem>
              <SelectItem value="manual">Manual only</SelectItem>
              {feeds.map((f) => (
                <SelectItem key={f.id} value={String(f.id)}>
                  {f.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <div className="relative">
            <Icons.Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-400" />
            <Input
              value={qInput}
              onChange={(e) => setQInput(e.target.value)}
              placeholder="Search value / description…"
              className="h-8 w-56 pl-8 text-xs"
              aria-label="Search IOCs"
            />
          </div>

          <div className="ml-auto flex items-center gap-2">
            {hasFilters && (
              <Button
                variant="ghost"
                size="sm"
                className="h-8 gap-1 text-xs"
                onClick={() => {
                  setSeverity("all");
                  setCategory("all");
                  setType("all");
                  setFeedId("all");
                  setQInput("");
                  setPage(1);
                }}
              >
                <Icons.X className="h-3.5 w-3.5" /> Clear
              </Button>
            )}
            <Button size="sm" className="h-8 bg-zinc-700 text-white hover:bg-zinc-800" onClick={() => setAddOpen(true)}>
              <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add IOC
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* ── bulk selection bar (appears when rows are selected) ────────── */}
      {someSelected && (
        <div
          role="toolbar"
          aria-label="Bulk selection actions"
          className="flex flex-wrap items-center gap-2 rounded-lg border border-zinc-300 bg-zinc-50 px-3 py-2 text-xs dark:border-zinc-700 dark:bg-zinc-800/60"
        >
          <span className="font-medium text-zinc-600 dark:text-zinc-300">{selected.size} selected</span>
          <span className="text-zinc-400">{disableableCount} will be disabled</span>
          <div className="ml-auto flex items-center gap-2">
            <Button variant="outline" size="sm" className="h-8" disabled={bulkBusy !== null} onClick={() => setSelected(new Map())}>
              Clear
            </Button>
            <Button
              size="sm"
              className="h-8 bg-zinc-700 text-white hover:bg-zinc-800"
              disabled={bulkBusy !== null}
              onClick={() => void bulkDisable()}
            >
              {bulkBusy ? (
                <>
                  <Icons.Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" aria-hidden />
                  Disabling {bulkBusy.done}/{bulkBusy.total}…
                </>
              ) : (
                <>
                  <Icons.Ban className="mr-1 h-3.5 w-3.5" aria-hidden />
                  Disable selected
                </>
              )}
            </Button>
          </div>
        </div>
      )}

      {/* ── IOCs table ─────────────────────────────────────────────────── */}
      <Card>
        <CardContent className="p-0">
          {iocsQuery.isError ? (
            <div className="p-4">
              <QueryError error={iocsQuery.error} onRetry={() => void iocsQuery.refetch()} />
            </div>
          ) : iocsQuery.isLoading ? (
            <TableSkeleton rows={8} cols={10} />
          ) : rows.length === 0 ? (
            <EmptyBlock
              icon={<Icons.Bug className="h-6 w-6" />}
              title={hasFilters ? "No IOCs match the current filters" : "No indicators yet"}
              description={
                hasFilters
                  ? "Clear filters or sync a threat feed to ingest indicators."
                  : "Sync a threat feed or add a manual IOC to populate the store."
              }
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-10">
                    <Checkbox
                      aria-label="Select all IOCs on this page"
                      checked={pageAllSelected ? true : someSelected ? "indeterminate" : false}
                      disabled={bulkBusy !== null}
                      onCheckedChange={(v) => {
                        setSelected((prev) => {
                          const next = new Map(prev);
                          if (v === true) rows.forEach((r) => next.set(r.id, r));
                          else rows.forEach((r) => next.delete(r.id));
                          return next;
                        });
                      }}
                    />
                  </TableHead>
                  <TableHead>Value</TableHead>
                  <TableHead className="w-16">Type</TableHead>
                  <TableHead className="w-24">Category</TableHead>
                  <TableHead className="w-24">Severity</TableHead>
                  <TableHead className="w-28">Confidence</TableHead>
                  <TableHead className="w-28">Reputation</TableHead>
                  <TableHead className="w-32">Source</TableHead>
                  <TableHead className="w-24">Last seen</TableHead>
                  <TableHead className="w-24 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((ioc) => (
                  <TableRow key={ioc.id} className={ioc.enabled ? undefined : "opacity-60"}>
                    <TableCell className="w-10 pr-0">
                      <Checkbox
                        aria-label={`Select IOC ${ioc.value}`}
                        checked={selected.has(ioc.id)}
                        disabled={bulkBusy !== null}
                        onCheckedChange={(v) => {
                          setSelected((prev) => {
                            const next = new Map(prev);
                            if (v === true) next.set(ioc.id, ioc);
                            else next.delete(ioc.id);
                            return next;
                          });
                        }}
                      />
                    </TableCell>
                    <TableCell className="max-w-64">
                      <div className="flex items-center gap-1">
                        <span className="min-w-0 flex-1">
                          <span className="block truncate font-mono text-xs" title={ioc.value}>
                            {ioc.value}
                          </span>
                          {ioc.description && (
                            <span className="block truncate text-[10px] text-zinc-400" title={ioc.description}>
                              {ioc.description}
                            </span>
                          )}
                        </span>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 shrink-0 text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-300"
                          aria-label={`Copy IOC value ${ioc.value}`}
                          onClick={() => {
                            void navigator.clipboard
                              .writeText(ioc.value)
                              .then(() => toastOk("Copied to clipboard", ioc.value))
                              .catch((err) => toastErr(err, "Copy failed"));
                          }}
                        >
                          <Icons.Copy className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                    <TableCell>
                      <TypeBadge type={ioc.type} />
                    </TableCell>
                    <TableCell>
                      <CategoryChip category={ioc.category} />
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={ioc.severity} />
                    </TableCell>
                    <TableCell>
                      <Meter value={ioc.confidence} label="confidence" tone="blue" />
                    </TableCell>
                    <TableCell>
                      <Meter value={ioc.reputation} label="reputation" tone={ioc.reputation <= 10 ? "red" : "blue"} />
                    </TableCell>
                    <TableCell className="max-w-32">
                      <span className="block truncate text-xs text-zinc-500" title={ioc.source}>
                        {ioc.source}
                      </span>
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs text-zinc-500">{fmtRelative(ioc.lastSeen)}</TableCell>
                    <TableCell>
                      <div className="flex items-center justify-end gap-1">
                        <Switch
                          checked={ioc.enabled}
                          onCheckedChange={(enabled) => toggle.mutate({ id: ioc.id, enabled })}
                          aria-label={`Toggle IOC ${ioc.value}`}
                        />
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-rose-500 hover:text-rose-600"
                          aria-label={`Delete IOC ${ioc.value}`}
                          onClick={() => setDeleting(ioc)}
                        >
                          <Icons.Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}

          {/* pagination + row summary — server-side */}
          {meta && meta.total > 0 && (
            <div className="flex flex-wrap items-center justify-between gap-2 border-t border-zinc-200 px-4 py-2.5 text-xs text-zinc-500 dark:border-zinc-800">
              <span>
                page {meta.page} of {meta.totalPages} · {meta.total} IOC{meta.total === 1 ? "" : "s"}
              </span>
              <div className="flex items-center gap-1.5">
                <Button variant="outline" size="sm" className="h-7" disabled={meta.page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>
                  <Icons.ChevronLeft className="h-3.5 w-3.5" /> Prev
                </Button>
                <Button variant="outline" size="sm" className="h-7" disabled={meta.page >= meta.totalPages} onClick={() => setPage((p) => p + 1)}>
                  Next <Icons.ChevronRight className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {addOpen && <IocEditor onClose={() => setAddOpen(false)} />}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete IOC ${deleting?.value ?? ""}?`}
        description="The indicator is removed from matching. Related auto-block rules keep working until deleted separately."
        loading={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting.id)}
      />
    </div>
  );
}
