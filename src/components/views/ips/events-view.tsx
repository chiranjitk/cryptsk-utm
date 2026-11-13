"use client";

/**
 * #/ips/events — triage workflow for the ips_events stream (M04 §4).
 * Server-paginated query + 50-row live tail (logs:tail, filtered), severity
 * chips, category/time-range/q/sid filters, suppress menu (24h/7d/forever)
 * and "Create firewall block rule" → prefilled M03 RuleEditor via
 * sessionStorage handoff.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { useRealtime } from "@/lib/realtime";
import {
  ipsApi,
  ipsFetch,
  fmtDateTime,
  fmtRelative,
  SEVERITIES,
  type IpsEventDto,
  type IpsSeverity,
} from "./ips-api";
import { CategoryChip, IpsActionBadge, SeverityBadge, SuppressMenu, useIpsConfigInvalidation } from "./ips-ui";
import { EmptyBlock, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";
import type { FwRule } from "../firewall/fw-api";

const EVENTS_KEY = ["ips", "events"] as const;
const CATEGORIES_KEY = ["ips", "rule-categories"] as const;
const LIVE_CAP = 50; // M04 §6 in-memory live buffer
const PREFILL_STORAGE_KEY = "ips:prefill-rule";

type RangeKey = "1h" | "24h" | "7d" | "all";

const RANGE_MS: Record<Exclude<RangeKey, "all">, number> = {
  "1h": 3600_000,
  "24h": 24 * 3600_000,
  "7d": 7 * 24 * 3600_000,
};

export function EventsView() {
  useIpsConfigInvalidation();
  const queryClient = useQueryClient();

  const [severities, setSeverities] = useState<IpsSeverity[]>([]);
  const [category, setCategory] = useState<string>("all");
  const [range, setRange] = useState<RangeKey>("24h");
  const [qInput, setQInput] = useState("");
  const [sidInput, setSidInput] = useState("");
  const [q, setQ] = useState("");
  const [sid, setSid] = useState("");
  const [page, setPage] = useState(1);
  const [liveEnabled, setLiveEnabled] = useState(true);
  const [liveRows, setLiveRows] = useState<IpsEventDto[]>([]);
  const [selected, setSelected] = useState<IpsEventDto | null>(null);
  const [blocking, setBlocking] = useState(false);

  // debounce free-text + sid inputs
  useEffect(() => {
    const t = setTimeout(() => {
      setQ(qInput.trim());
      setSid(sidInput.trim());
      setPage(1);
    }, 350);
    return () => clearTimeout(t);
  }, [qInput, sidInput]);

  const params = useMemo(() => {
    const sp = new URLSearchParams();
    if (severities.length > 0) sp.set("severity", severities.join(","));
    if (category !== "all") sp.set("category", category);
    if (range !== "all") sp.set("since", new Date(Date.now() - RANGE_MS[range]).toISOString());
    if (q) sp.set("q", q);
    if (sid) sp.set("sid", sid);
    sp.set("page", String(page));
    sp.set("limit", "25");
    return sp.toString();
  }, [severities, category, range, q, sid, page]);

  const eventsQuery = useQuery({
    queryKey: [...EVENTS_KEY, params],
    queryFn: () => ipsApi.listEvents(params),
  });

  const categoriesQuery = useQuery({
    queryKey: CATEGORIES_KEY,
    queryFn: ipsApi.listCategories,
    staleTime: 5 * 60_000,
  });
  const categories = categoriesQuery.data?.categories ?? [];

  // ── live tail (logs:tail kind=ips, filtered, 50-row cap) ──────────────────
  const filterRef = useRef({ severities, category, range, q, sid });
  filterRef.current = { severities, category, range, q, sid };

  useRealtime(["logs"], {
    onLogsTail: (l) => {
      if (l.kind !== "ips") return;
      const f = filterRef.current;
      const entry = l.entry as {
        ts: string; srcIp?: string | null; srcPort?: number | null; dstIp?: string | null; dstPort?: number | null;
        action: string; sid?: string | null; severity: string; category?: string | null; message?: string | null;
      };
      const sev = entry.severity as IpsSeverity;
      if (f.severities.length > 0 && !f.severities.includes(sev)) return;
      if (f.category !== "all" && entry.category !== f.category) return;
      if (f.sid && entry.sid !== f.sid) return;
      if (f.q) {
        const hay = `${entry.message ?? ""} ${entry.srcIp ?? ""} ${entry.dstIp ?? ""} ${entry.category ?? ""}`.toLowerCase();
        if (!hay.includes(f.q.toLowerCase())) return;
      }
      if (f.range !== "all" && Date.parse(entry.ts) < Date.now() - RANGE_MS[f.range]) return;
      setLiveRows((prev) =>
        [
          {
            id: -Date.now(), // synthetic — deduped against persisted rows below
            timestamp: entry.ts,
            srcIp: entry.srcIp ?? null,
            srcPort: entry.srcPort ?? null,
            dstIp: entry.dstIp ?? null,
            dstPort: entry.dstPort ?? null,
            action: entry.action as IpsEventDto["action"],
            sid: entry.sid ?? null,
            severity: sev,
            category: entry.category ?? null,
            message: entry.message ?? null,
            suppressedUntil: null,
          },
          ...prev,
        ].slice(0, LIVE_CAP),
      );
    },
  });

  const persisted = eventsQuery.data?.data ?? [];
  const persistedKeys = useMemo(() => new Set(persisted.map((e) => `${e.sid}|${e.timestamp}`)), [persisted]);
  const rows = useMemo(() => {
    if (!liveEnabled || page !== 1) return persisted;
    const fresh = liveRows.filter((r) => !persistedKeys.has(`${r.sid}|${r.timestamp}`));
    return [...fresh, ...persisted];
  }, [liveRows, persisted, persistedKeys, liveEnabled, page]);

  const meta = eventsQuery.data?.meta;
  const hasFilters = severities.length > 0 || category !== "all" || range !== "all" || q || sid;

  const invalidateEvents = () => void queryClient.invalidateQueries({ queryKey: EVENTS_KEY });

  // ── "Create firewall block rule" handoff to M03 (M04 §5) ──────────────────
  const blockSource = async (ev: IpsEventDto) => {
    if (!ev.srcIp || blocking) return;
    setBlocking(true);
    try {
      const baseName = `ips-src-${ev.sid ?? ev.id}`.slice(0, 64);
      let addrId: number | null = null;
      try {
        const created = await ipsFetch<{ id: number }>("/api/v1/address-objects", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: baseName,
            type: "ip",
            value: ev.srcIp,
            description: `IPS block source (sid ${ev.sid}) — event #${ev.id}`,
          }),
        });
        addrId = created.id;
      } catch (err) {
        // duplicate name → reuse the existing object
        const list = await ipsFetch<Array<{ id: number; name: string; value: string }>>("/api/v1/address-objects?limit=200");
        const found = list.find((a) => a.name === baseName || a.value === ev.srcIp);
        if (found) addrId = found.id;
        else throw err;
      }
      if (addrId == null) throw new Error("Could not resolve address object");

      const draft: FwRule = {
        id: -1,
        tenantId: 1,
        name: `IPS block sid ${ev.sid ?? "unknown"}`.slice(0, 64),
        description: `Auto-prefilled from IPS event #${ev.id} (${ev.category ?? "uncategorized"})`,
        enabled: true,
        position: 0,
        srcZoneIds: [],
        dstZoneIds: [],
        srcAddrIds: [addrId],
        dstAddrIds: [],
        serviceIds: [],
        applicationIds: [],
        userIds: [],
        srcMacs: [],
        scheduleId: null,
        action: "drop",
        logging: "summary",
        connLimit: null,
        rateLimit: null,
        synProtection: false,
        synThreshold: null,
        ipsPolicyId: null,
        qosPolicyId: null,
        tags: ["ips"],
        comment: `IPS event #${ev.id} — sid ${ev.sid} — ${ev.message ?? ""}`.slice(0, 240),
        hitCount: 0,
        lastHitAt: null,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      sessionStorage.setItem(PREFILL_STORAGE_KEY, JSON.stringify(draft));
      toastOk("Opening rule editor", "Firewall rule prefilled from the event — review and save");
      setSelected(null);
      window.location.hash = "#/firewall/rules?prefill=1";
    } catch (err) {
      toastErr(err, "Could not prefill block rule");
    } finally {
      setBlocking(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* ── filter bar ─────────────────────────────────────────────────── */}
      <Card>
        <CardContent className="space-y-3 p-4">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="mr-1 text-xs font-medium text-zinc-500">Severity</span>
            {SEVERITIES.map((s) => {
              const active = severities.includes(s);
              return (
                <button
                  key={s}
                  type="button"
                  aria-pressed={active}
                  onClick={() => {
                    setPage(1);
                    setSeverities((prev) => (prev.includes(s) ? prev.filter((x) => x !== s) : [...prev, s]));
                  }}
                  className={cn(
                    "rounded-full border px-2.5 py-1 text-xs transition-colors",
                    active
                      ? "border-zinc-600/40 bg-zinc-600/10 font-medium text-zinc-700 dark:text-zinc-500"
                      : "border-zinc-200 text-zinc-500 hover:bg-zinc-100 dark:border-zinc-800 dark:text-zinc-400 dark:hover:bg-zinc-800",
                  )}
                >
                  {s}
                </button>
              );
            })}

            <Separator orientation="vertical" className="mx-1.5 hidden h-5 sm:block" />

            {(["1h", "24h", "7d", "all"] as RangeKey[]).map((r) => (
              <button
                key={r}
                type="button"
                aria-pressed={range === r}
                onClick={() => {
                  setPage(1);
                  setRange(r);
                }}
                className={cn(
                  "rounded-full border px-2.5 py-1 text-xs transition-colors",
                  range === r
                    ? "border-zinc-600/40 bg-zinc-600/10 font-medium text-zinc-700 dark:text-zinc-500"
                    : "border-zinc-200 text-zinc-500 hover:bg-zinc-100 dark:border-zinc-800 dark:text-zinc-400 dark:hover:bg-zinc-800",
                )}
              >
                {r === "all" ? "all time" : r}
              </button>
            ))}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Select
              value={category}
              onValueChange={(v) => {
                setPage(1);
                setCategory(v);
              }}
            >
              <SelectTrigger className="h-8 w-44" aria-label="Category filter">
                <SelectValue placeholder="All categories" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All categories</SelectItem>
                {categories.map((c) => (
                  <SelectItem key={c.name} value={c.name}>
                    {c.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <div className="relative">
              <Icons.Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-400" />
              <Input
                value={qInput}
                onChange={(e) => setQInput(e.target.value)}
                placeholder="Search message / IP…"
                className="h-8 w-52 pl-8 text-xs"
                aria-label="Search events"
              />
            </div>
            <div className="relative">
              <Icons.Hash className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-400" />
              <Input
                value={sidInput}
                onChange={(e) => setSidInput(e.target.value)}
                placeholder="sid…"
                className="h-8 w-36 pl-8 font-mono text-xs"
                aria-label="Search by sid"
              />
            </div>

            <div className="ml-auto flex items-center gap-2">
              <div className="flex items-center gap-1.5">
                <Switch id="live-tail" checked={liveEnabled} onCheckedChange={setLiveEnabled} aria-label="Toggle live tail" />
                <Label htmlFor="live-tail" className="cursor-pointer text-xs text-zinc-500">
                  Live tail
                </Label>
                {liveEnabled && (
                  <span className="relative flex h-2 w-2">
                    <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                    <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
                  </span>
                )}
              </div>
              {hasFilters && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-8 gap-1 text-xs"
                  onClick={() => {
                    setSeverities([]);
                    setCategory("all");
                    setRange("24h");
                    setQInput("");
                    setSidInput("");
                    setPage(1);
                  }}
                >
                  <Icons.X className="h-3.5 w-3.5" /> Clear
                </Button>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* ── events table ───────────────────────────────────────────────── */}
      <Card>
        <CardContent className="p-0">
          {eventsQuery.isError ? (
            <div className="p-4">
              <QueryError error={eventsQuery.error} onRetry={() => void eventsQuery.refetch()} />
            </div>
          ) : eventsQuery.isLoading ? (
            <TableSkeleton rows={8} cols={8} />
          ) : rows.length === 0 ? (
            <EmptyBlock
              icon={<Icons.Siren className="h-6 w-6" />}
              title="No events match the current filters"
              description="Widen the time range or clear severity filters to see more of the stream."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-36">Time</TableHead>
                  <TableHead className="w-24">Severity</TableHead>
                  <TableHead className="w-32">Category</TableHead>
                  <TableHead className="w-28">sid</TableHead>
                  <TableHead className="w-24">Action</TableHead>
                  <TableHead>Source → Destination</TableHead>
                  <TableHead className="min-w-40">Message</TableHead>
                  <TableHead className="w-40 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((ev) => {
                  const live = ev.id < 0;
                  return (
                    <TableRow
                      key={`${ev.id}-${ev.timestamp}`}
                      className={cn("cursor-pointer", live && "bg-zinc-600/5")}
                      onClick={() => setSelected(ev)}
                    >
                      <TableCell className="whitespace-nowrap font-mono text-xs tabular-nums text-zinc-500">
                        {live && (
                          <TooltipProvider delayDuration={100}>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <span className="mr-1 inline-block h-1.5 w-1.5 rounded-full bg-emerald-500 align-middle" aria-label="live" />
                              </TooltipTrigger>
                              <TooltipContent className="text-xs">Live tail row</TooltipContent>
                            </Tooltip>
                          </TooltipProvider>
                        )}
                        {fmtDateTime(ev.timestamp)}
                      </TableCell>
                      <TableCell>
                        <SeverityBadge severity={ev.severity} />
                      </TableCell>
                      <TableCell>
                        <CategoryChip category={ev.category} />
                      </TableCell>
                      <TableCell className="font-mono text-xs text-zinc-500">{ev.sid ?? "—"}</TableCell>
                      <TableCell>
                        <IpsActionBadge action={ev.action} />
                      </TableCell>
                      <TableCell className="whitespace-nowrap font-mono text-xs">
                        {ev.srcIp ?? "?"}
                        {ev.srcPort ? `:${ev.srcPort}` : ""}
                        <span className="text-zinc-400"> → </span>
                        {ev.dstIp ?? "?"}
                        {ev.dstPort ? `:${ev.dstPort}` : ""}
                      </TableCell>
                      <TableCell className="max-w-56">
                        <span className="block truncate text-xs text-zinc-600 dark:text-zinc-300" title={ev.message ?? undefined}>
                          {ev.message ?? "—"}
                        </span>
                      </TableCell>
                      <TableCell onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1">
                          {ev.suppressedUntil && (
                            <TooltipProvider delayDuration={100}>
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <Badge variant="outline" className="border-zinc-300 px-1 py-0 text-[9px] text-zinc-500 dark:border-zinc-700">
                                    until {fmtDateTime(ev.suppressedUntil)}
                                  </Badge>
                                </TooltipTrigger>
                                <TooltipContent className="text-xs">Suppressed until {fmtDateTime(ev.suppressedUntil)}</TooltipContent>
                              </Tooltip>
                            </TooltipProvider>
                          )}
                          <SuppressMenu eventId={ev.id} onSuppressed={invalidateEvents} />
                          <TooltipProvider delayDuration={100}>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="h-7 gap-1 px-2 text-xs"
                                  disabled={blocking || !ev.srcIp}
                                  onClick={() => void blockSource(ev)}
                                >
                                  <Icons.ShieldBan className="h-3.5 w-3.5" /> Block
                                </Button>
                              </TooltipTrigger>
                              <TooltipContent className="text-xs">Create firewall block rule for {ev.srcIp ?? "source"}</TooltipContent>
                            </Tooltip>
                          </TooltipProvider>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}

          {/* pagination — server-side (M04 §7: no client filtering of pages) */}
          {meta && meta.total > 0 && (
            <div className="flex flex-wrap items-center justify-between gap-2 border-t border-zinc-200 px-4 py-2.5 text-xs text-zinc-500 dark:border-zinc-800">
              <span>
                {liveEnabled && page === 1 && liveRows.length > 0 ? `+${liveRows.length} live · ` : ""}
                page {meta.page} of {meta.totalPages} · {meta.total} event{meta.total === 1 ? "" : "s"}
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

      {/* ── detail side panel ──────────────────────────────────────────── */}
      <Sheet open={selected != null} onOpenChange={(open) => !open && setSelected(null)}>
        <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-md">
          {selected && (
            <>
              <SheetHeader>
                <SheetTitle className="flex items-center gap-2">
                  Event #{selected.id < 0 ? "live" : selected.id}
                  <SeverityBadge severity={selected.severity} />
                </SheetTitle>
                <SheetDescription className="font-mono text-xs">sid {selected.sid ?? "—"} · {selected.category ?? "uncategorized"}</SheetDescription>
              </SheetHeader>

              <div className="mt-2 space-y-4 px-4 pb-8">
                <div className="grid grid-cols-[92px_1fr] gap-x-3 gap-y-2 text-xs">
                  <span className="text-zinc-400">timestamp</span>
                  <span className="font-mono">{selected.timestamp}</span>
                  <span className="text-zinc-400">action</span>
                  <span><IpsActionBadge action={selected.action} /></span>
                  <span className="text-zinc-400">source</span>
                  <span className="font-mono">{selected.srcIp ?? "—"}{selected.srcPort ? `:${selected.srcPort}` : ""}</span>
                  <span className="text-zinc-400">destination</span>
                  <span className="font-mono">{selected.dstIp ?? "—"}{selected.dstPort ? `:${selected.dstPort}` : ""}</span>
                  {selected.suppressedUntil && (
                    <>
                      <span className="text-zinc-400">suppressed</span>
                      <span className="font-mono">until {selected.suppressedUntil} ({fmtRelative(selected.suppressedUntil)})</span>
                    </>
                  )}
                </div>

                <div>
                  <p className="mb-1 text-xs font-medium text-zinc-500">Raw message</p>
                  <pre className="overflow-x-auto whitespace-pre-wrap rounded-md bg-zinc-50 p-2.5 font-mono text-[11px] text-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300">
                    {selected.message ?? "—"}
                  </pre>
                </div>

                <Separator />

                <div className="flex flex-col gap-2">
                  <p className="text-xs font-medium text-zinc-500">Related actions</p>
                  <div className="flex flex-wrap items-center gap-2">
                    <SuppressMenu
                      eventId={selected.id}
                      triggerLabel="Suppress signature"
                      size="default"
                      onSuppressed={(d) => {
                        setSelected(null);
                        invalidateEvents();
                      }}
                    />
                    <Button
                      variant="destructive"
                      size="sm"
                      className="gap-1.5"
                      disabled={blocking || !selected.srcIp}
                      onClick={() => void blockSource(selected)}
                    >
                      <Icons.ShieldBan className="h-3.5 w-3.5" />
                      {blocking ? "Preparing…" : "Create firewall block rule"}
                    </Button>
                  </div>
                  <p className="text-[11px] leading-snug text-zinc-400">
                    Creates a temp address object for <span className="font-mono">{selected.srcIp ?? "—"}</span>/32 and prefills the M03
                    RuleEditor (name <span className="font-mono">IPS block sid {selected.sid ?? "…"}</span>, action drop).
                  </p>
                </div>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
