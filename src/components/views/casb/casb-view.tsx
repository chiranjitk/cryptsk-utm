"use client";

/**
 * CASB view (Phase 4 §4.3) — SaaS visibility console: discovery table of
 * observed per-client SaaS usage (sanctioned/shadow/unknown verdict chips),
 * the tenant SaaS catalog CRUD and the vendor connector config shell
 * (Google Workspace, Microsoft 365, Salesforce, Dropbox, Slack — shape-only
 * validation, no live vendor calls). "Run Scan" aggregates the nDPI-derived
 * app-control logs into discoveries with a summary toast.
 * Atoms reused from fw-ui (table states, toasts, ConfirmDialog, density) —
 * no new design language. Palette per UI_DESIGN_SYSTEM §2 (no indigo/blue).
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
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
import {
  CATEGORIES,
  VENDORS,
  VERDICTS,
  casbApi,
  fmtDateTime,
  humanizeBytes,
  qs,
  vendorLabel,
  type CasbConnectorDTO,
  type CasbVendor,
  type ConnectorStatus,
  type SaasAppCategory,
  type SaasAppDTO,
  type SaasVerdict,
} from "./casb-api";

const DISCOVERY_LIMIT = 25;
const CATALOG_LIMIT = 25;

const SCAN_WINDOWS = [
  { value: 60, label: "last hour" },
  { value: 1440, label: "last 24 hours" },
  { value: 10080, label: "last 7 days" },
];

// ── local chips (colors only — palette per UI_DESIGN_SYSTEM §2) ─────────────

const VERDICT_BADGE: Record<SaasVerdict, { cls: string; icon: React.ComponentType<{ className?: string }> }> = {
  sanctioned: { cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400", icon: Icons.ShieldCheck },
  shadow: { cls: "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400", icon: Icons.EyeOff },
  unknown: { cls: "border-zinc-400/60 bg-zinc-500/5 text-zinc-600 dark:text-zinc-300", icon: Icons.CircleHelp },
};

function VerdictBadge({ verdict }: { verdict: SaasVerdict }) {
  const def = VERDICT_BADGE[verdict] ?? VERDICT_BADGE.unknown;
  const Icon = def.icon;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium capitalize", def.cls)}>
      <Icon className="h-3 w-3" />
      {verdict}
    </Badge>
  );
}

const CONNECTOR_STATUS_BADGE: Record<ConnectorStatus, { cls: string; icon: React.ComponentType<{ className?: string }>; label: string }> = {
  connected: { cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400", icon: Icons.Link2, label: "connected" },
  disconnected: { cls: "border-zinc-400/60 bg-zinc-500/5 text-zinc-600 dark:text-zinc-300", icon: Icons.Unlink, label: "disconnected" },
  error: { cls: "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400", icon: Icons.TriangleAlert, label: "error" },
};

function ConnectorStatusBadge({ status }: { status: ConnectorStatus }) {
  const def = CONNECTOR_STATUS_BADGE[status] ?? CONNECTOR_STATUS_BADGE.disconnected;
  const Icon = def.icon;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium capitalize", def.cls)}>
      <Icon className="h-3 w-3" />
      {def.label}
    </Badge>
  );
}

function CategoryChip({ category }: { category: SaasAppCategory | null }) {
  if (!category) {
    return <span className="text-xs text-zinc-400">—</span>;
  }
  return (
    <Badge
      variant="outline"
      className="border-zinc-300 bg-zinc-100 font-medium capitalize text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
    >
      {category}
    </Badge>
  );
}

function RiskBadge({ score }: { score: number | null }) {
  if (score === null) return <span className="text-xs text-zinc-400">—</span>;
  const cls =
    score > 60
      ? "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400"
      : score > 30
        ? "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400"
        : "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400";
  return (
    <Badge variant="outline" className={cn("gap-1 tabular-nums", cls)}>
      <Icons.Gauge className="h-3 w-3" />
      {score}
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
  const query = useQuery({ queryKey: ["casb", "stats"], queryFn: () => casbApi.getStats() });
  const s = query.data;
  if (query.isLoading || !s) {
    return (
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="h-[58px] animate-pulse rounded-lg bg-zinc-500/10" />
        ))}
      </div>
    );
  }
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
      <StatCard label="Discovered pairs" value={s.total} hint="client × app observations" />
      <StatCard label="Sanctioned" value={s.byVerdict.sanctioned} hint="cataloged, low risk" />
      <StatCard
        label="Shadow"
        value={s.byVerdict.shadow}
        hint={s.topShadowApps[0] ? `top: ${s.topShadowApps[0].appHint}` : "cataloged, high risk"}
      />
      <StatCard label="Unknown" value={s.byVerdict.unknown} hint="no catalog attribution — triage" />
    </div>
  );
}

// ── inline pager (server-side pagination — meta.totalPages drives it) ───────

function Pager(props: {
  page: number;
  totalPages: number;
  total: number;
  noun: string;
  onPage: (page: number) => void;
}) {
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

// ── filter chips (verdict) ──────────────────────────────────────────────────

function VerdictChips(props: { value: string; onChange: (v: string) => void }) {
  return (
    <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Verdict filter">
      {(["", ...VERDICTS] as string[]).map((v) => {
        const active = props.value === v;
        const label = v === "" ? "all" : v;
        const Icon = v === "" ? Icons.ListFilter : VERDICT_BADGE[v as SaasVerdict].icon;
        return (
          <button
            key={v || "all"}
            type="button"
            onClick={() => props.onChange(v)}
            aria-pressed={active}
            className={cn(
              "inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-medium capitalize transition-colors",
              active
                ? "border-zinc-700 bg-zinc-700 text-white dark:border-zinc-300 dark:bg-zinc-300 dark:text-zinc-900"
                : "border-zinc-300 bg-transparent text-zinc-600 hover:bg-zinc-100 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800",
            )}
          >
            <Icon className="h-3 w-3" />
            {label}
          </button>
        );
      })}
    </div>
  );
}

// ── discoveries tab ─────────────────────────────────────────────────────────

function DiscoveriesTab() {
  const [verdict, setVerdict] = useState("");
  const [category, setCategory] = useState("");
  const [qInput, setQInput] = useState("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const [density] = useTableDensity("casb-discoveries");

  const commitText = () => {
    setQ((cur) => (cur === qInput ? cur : qInput));
    setPage(1);
  };

  const params = useMemo(() => qs({ verdict, category, q, page, limit: DISCOVERY_LIMIT }), [verdict, category, q, page]);
  const query = useQuery({
    queryKey: ["casb", "discoveries", { verdict, category, q }, page],
    queryFn: () => casbApi.listDiscoveries(params),
  });

  const rows = query.data?.data ?? [];
  const meta = query.data?.meta;
  const hasFilters = Boolean(verdict || category || q);

  return (
    <div className="grid gap-3">
      {/* filter chips */}
      <div className="flex flex-wrap items-center gap-2">
        <VerdictChips value={verdict} onChange={(v) => { setVerdict(v); setPage(1); }} />
        <Select
          value={category || "any"}
          onValueChange={(v) => {
            setCategory(v === "any" ? "" : v);
            setPage(1);
          }}
        >
          <SelectTrigger className="h-9 w-40" aria-label="Category filter">
            <SelectValue placeholder="Category" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="any">any category</SelectItem>
            {CATEGORIES.map((c) => (
              <SelectItem key={c} value={c} className="capitalize">
                {c}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <div className="relative">
          <Icons.Search className="absolute left-2.5 top-2.5 h-4 w-4 text-zinc-400" />
          <Input
            value={qInput}
            onChange={(e) => setQInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && commitText()}
            onBlur={commitText}
            placeholder="Search IP or app hint…"
            className="h-9 w-60 pl-8"
            aria-label="Search discoveries"
          />
        </div>
        {hasFilters && (
          <Button
            variant="ghost"
            size="sm"
            className="h-9 px-2 text-xs"
            onClick={() => {
              setVerdict("");
              setCategory("");
              setQInput("");
              setQ("");
              setPage(1);
            }}
          >
            <Icons.X className="h-3.5 w-3.5" />
            Clear
          </Button>
        )}
      </div>

      {/* table (fixed viewport — sticky header, scrolls inside) */}
      <div className="min-w-0 rounded-lg border border-zinc-200 dark:border-zinc-800">
        {query.isLoading ? (
          <TableSkeleton rows={8} cols={7} />
        ) : query.isError ? (
          <QueryError error={query.error} onRetry={() => void query.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyBlock
            icon={<Icons.CloudOff className="h-6 w-6" />}
            title={hasFilters ? "No discoveries match this filter" : "No SaaS usage discovered yet"}
            description={
              hasFilters
                ? "Loosen the verdict/category filters or clear the search."
                : "Run a scan to aggregate the nDPI app-control logs into per-client SaaS discoveries."
            }
          />
        ) : (
          <>
            <div className="max-h-96 overflow-y-auto">
              <div className="overflow-x-auto">
                <Table
                  className={cn(
                    "min-w-[860px] [&_thead]:sticky [&_thead]:top-0 [&_thead]:z-10 [&_thead]:bg-zinc-50 dark:[&_thead]:bg-zinc-900",
                    density === "compact" && "[&_th]:h-9 [&_th]:px-1.5 [&_td]:px-1.5 [&_td]:py-1 [&_td]:text-xs",
                  )}
                >
                  <TableHeader>
                    <TableRow>
                      <TableHead>Client IP</TableHead>
                      <TableHead>App hint</TableHead>
                      <TableHead>Verdict</TableHead>
                      <TableHead>Category</TableHead>
                      <TableHead className="text-right">Sessions</TableHead>
                      <TableHead className="text-right">Bytes</TableHead>
                      <TableHead className="text-right">Last seen</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rows.map((r) => (
                      <TableRow key={r.id}>
                        <TableCell className="whitespace-nowrap font-mono text-xs">{r.clientIp}</TableCell>
                        <TableCell className="max-w-56 min-w-0 truncate text-sm" title={`${r.appHint}${r.appName && r.appName !== r.appHint ? ` → ${r.appName}` : ""}`}>
                          {r.appHint}
                          {r.appName && (
                            <span className="ml-1.5 text-[11px] text-zinc-400">→ {r.appName}</span>
                          )}
                        </TableCell>
                        <TableCell>
                          <VerdictBadge verdict={r.verdict} />
                        </TableCell>
                        <TableCell>
                          <CategoryChip category={r.category} />
                        </TableCell>
                        <TableCell className="text-right tabular-nums">{r.sessions.toLocaleString()}</TableCell>
                        <TableCell className="whitespace-nowrap text-right tabular-nums" title={`${(r.bytesIn + r.bytesOut).toLocaleString()} B`}>
                          {humanizeBytes(r.bytesIn + r.bytesOut)}
                        </TableCell>
                        <TableCell className="whitespace-nowrap text-right text-xs tabular-nums">{fmtDateTime(r.lastSeenAt)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </div>
            {meta && <Pager page={meta.page} totalPages={meta.totalPages} total={meta.total} noun="discovery" onPage={setPage} />}
          </>
        )}
      </div>
    </div>
  );
}

// ── catalog tab ─────────────────────────────────────────────────────────────

function parseDomainList(text: string): string[] {
  return text
    .split(/[\n,]/)
    .map((d) => d.trim().toLowerCase())
    .filter((d) => d.length > 0);
}

function AppDialog(props: { app: SaasAppDTO | null; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState(props.app?.name ?? "");
  const [vendor, setVendor] = useState(props.app?.vendor ?? "");
  const [category, setCategory] = useState<SaasAppCategory>(props.app?.category ?? "collaboration");
  const [domainsText, setDomainsText] = useState((props.app?.domains ?? []).join("\n"));
  const [riskText, setRiskText] = useState(String(props.app?.riskScore ?? 20));
  const [busy, setBusy] = useState(false);
  const queryClient = useQueryClient();

  const editing = props.app !== null;
  const risk = Number(riskText);
  const domains = parseDomainList(domainsText);
  const valid = name.trim().length > 0 && domains.length > 0 && Number.isInteger(risk) && risk >= 0 && risk <= 100;

  const submit = async () => {
    if (!valid) return;
    setBusy(true);
    try {
      if (editing && props.app) {
        await casbApi.updateApp(props.app.id, {
          name: name.trim(),
          vendor: vendor.trim(),
          category,
          domains,
          riskScore: risk,
        });
        toastOk("Catalog updated", `${name.trim()} saved`);
      } else {
        await casbApi.createApp({
          name: name.trim(),
          vendor: vendor.trim(),
          category,
          domains,
          riskScore: risk,
        });
        toastOk("App added", `${name.trim()} is now classified by the scanner`);
      }
      await queryClient.invalidateQueries({ queryKey: ["casb"] });
      setBusy(false);
      props.onClose();
      props.onDone();
    } catch (err) {
      toastErr(err, editing ? "Update failed" : "Create failed");
      setBusy(false);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && props.onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-base">{editing ? `Edit ${props.app?.name}` : "Add SaaS app"}</DialogTitle>
          <DialogDescription>
            Domains drive attribution: plain entries match subdomains too ("box.com" matches "app.box.com"); "*." entries match
            deeper hosts only.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="casb-app-name">Name</Label>
              <Input id="casb-app-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Cloud" autoFocus />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="casb-app-vendor">Vendor</Label>
              <Input id="casb-app-vendor" value={vendor} onChange={(e) => setVendor(e.target.value)} placeholder="Acme Inc." />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="casb-app-category">Category</Label>
              <Select value={category} onValueChange={(v) => setCategory(v as SaasAppCategory)}>
                <SelectTrigger id="casb-app-category" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CATEGORIES.map((c) => (
                    <SelectItem key={c} value={c} className="capitalize">
                      {c}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="casb-app-risk">Risk score (0–100)</Label>
              <Input
                id="casb-app-risk"
                type="number"
                min={0}
                max={100}
                value={riskText}
                onChange={(e) => setRiskText(e.target.value)}
              />
              <p className="text-[11px] text-zinc-500">Above 50 the app is classed as shadow IT.</p>
            </div>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="casb-app-domains">Domains (one per line)</Label>
            <Textarea
              id="casb-app-domains"
              value={domainsText}
              onChange={(e) => setDomainsText(e.target.value)}
              placeholder={"acmecloud.com\n*.acmecloud.com"}
              rows={4}
              className="font-mono text-xs"
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={props.onClose} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={busy || !valid}>
            {busy ? "Saving…" : editing ? "Save changes" : "Add app"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function CatalogTab() {
  const [page, setPage] = useState(1);
  const [addOpen, setAddOpen] = useState(false);
  const [editFor, setEditFor] = useState<SaasAppDTO | null>(null);
  const [deleteFor, setDeleteFor] = useState<SaasAppDTO | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [seedBusy, setSeedBusy] = useState(false);
  const [density] = useTableDensity("casb-catalog");
  const queryClient = useQueryClient();

  const params = useMemo(() => qs({ page, limit: CATALOG_LIMIT }), [page]);
  const query = useQuery({
    queryKey: ["casb", "catalog", page],
    queryFn: () => casbApi.listCatalog(params),
  });

  const rows = query.data?.data ?? [];
  const meta = query.data?.meta;

  const seedDefaults = async () => {
    setSeedBusy(true);
    try {
      const res = await casbApi.seed();
      toastOk(
        "Defaults loaded",
        res.created === 0
          ? `Catalog already seeded (${res.total} apps)`
          : `Added ${res.created} default app${res.created === 1 ? "" : "s"} — ${res.total} total`,
      );
      await queryClient.invalidateQueries({ queryKey: ["casb"] });
    } catch (err) {
      toastErr(err, "Seed failed");
    } finally {
      setSeedBusy(false);
    }
  };

  const confirmDelete = async () => {
    if (!deleteFor) return;
    setDeleteBusy(true);
    try {
      await casbApi.deleteApp(deleteFor.id);
      toastOk("App removed", `${deleteFor.name} deleted — its discoveries re-classify on the next scan`);
      await queryClient.invalidateQueries({ queryKey: ["casb"] });
      setDeleteFor(null);
    } catch (err) {
      toastErr(err, "Delete failed");
    } finally {
      setDeleteBusy(false);
    }
  };

  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <Button className="h-9 gap-1.5" onClick={() => setAddOpen(true)}>
          <Icons.Plus className="h-4 w-4" />
          Add app
        </Button>
        <Button variant="outline" className="h-9 gap-1.5" onClick={() => void seedDefaults()} disabled={seedBusy}>
          <Icons.Download className="h-4 w-4" />
          {seedBusy ? "Loading…" : "Load defaults"}
        </Button>
        <div className="ml-auto">
          <DensityToggle storageKey="casb-catalog" label="Catalog table density" />
        </div>
      </div>

      <div className="min-w-0 rounded-lg border border-zinc-200 dark:border-zinc-800">
        {query.isLoading ? (
          <TableSkeleton rows={6} cols={6} />
        ) : query.isError ? (
          <QueryError error={query.error} onRetry={() => void query.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyBlock
            icon={<Icons.Layers className="h-6 w-6" />}
            title="Catalog is empty"
            description="Seed the shipped defaults (Google Workspace, Microsoft 365, Salesforce, Dropbox, Slack, …) or add custom apps."
            action={
              <Button size="sm" className="mt-2 gap-1.5" onClick={() => void seedDefaults()} disabled={seedBusy}>
                <Icons.Download className="h-3.5 w-3.5" />
                Load defaults
              </Button>
            }
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <Table
                className={cn(
                  "min-w-[760px]",
                  density === "compact" && "[&_th]:h-9 [&_th]:px-1.5 [&_td]:px-1.5 [&_td]:py-1 [&_td]:text-xs",
                )}
              >
                <TableHeader>
                  <TableRow>
                    <TableHead>App</TableHead>
                    <TableHead>Vendor</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead>Domains</TableHead>
                    <TableHead>Risk</TableHead>
                    <TableHead className="w-28 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((r) => (
                    <TableRow key={r.id}>
                      <TableCell className="text-sm font-medium">{r.name}</TableCell>
                      <TableCell className="text-xs text-zinc-500">{r.vendor || "—"}</TableCell>
                      <TableCell>
                        <CategoryChip category={r.category} />
                      </TableCell>
                      <TableCell className="max-w-72 min-w-0 truncate font-mono text-xs text-zinc-500" title={r.domains.join(", ")}>
                        {r.domains.join(", ")}
                      </TableCell>
                      <TableCell>
                        <RiskBadge score={r.riskScore} />
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="inline-flex items-center gap-1">
                          <Button variant="ghost" size="sm" className="h-7 px-2 text-xs" onClick={() => setEditFor(r)} aria-label={`Edit ${r.name}`}>
                            <Icons.Pencil className="h-3.5 w-3.5" />
                            Edit
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 px-2 text-xs text-rose-600 dark:text-rose-400"
                            onClick={() => setDeleteFor(r)}
                            aria-label={`Delete ${r.name}`}
                          >
                            <Icons.Trash2 className="h-3.5 w-3.5" />
                            Delete
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            {meta && <Pager page={meta.page} totalPages={meta.totalPages} total={meta.total} noun="app" onPage={setPage} />}
          </>
        )}
      </div>

      {addOpen && <AppDialog app={null} onClose={() => setAddOpen(false)} onDone={() => undefined} />}
      {editFor && <AppDialog app={editFor} onClose={() => setEditFor(null)} onDone={() => undefined} />}
      {deleteFor && (
        <ConfirmDialog
          open
          onOpenChange={(open) => !open && !deleteBusy && setDeleteFor(null)}
          title={`Delete ${deleteFor.name}?`}
          description={`Removes the catalog entry. Existing discovery rows keep their raw hint but lose the attribution; the next scan re-classifies them (likely as unknown).`}
          confirmLabel="Delete app"
          loading={deleteBusy}
          onConfirm={() => void confirmDelete()}
        />
      )}
    </div>
  );
}

// ── connectors tab ──────────────────────────────────────────────────────────

function ConnectorConfigDialog(props: {
  vendor: CasbVendor;
  connector: CasbConnectorDTO | null;
  onClose: () => void;
  onDone: () => void;
}) {
  const [text, setText] = useState(JSON.stringify(props.connector?.config ?? {}, null, 2));
  const [busy, setBusy] = useState(false);
  const queryClient = useQueryClient();
  const editing = props.connector !== null;

  const submit = async () => {
    let config: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(text || "{}");
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("config must be a JSON object");
      }
      config = parsed as Record<string, unknown>;
    } catch (err) {
      toastErr(err, "Invalid JSON");
      return;
    }
    setBusy(true);
    try {
      if (editing && props.connector) {
        await casbApi.updateConnector(props.connector.id, { config });
        toastOk("Connector saved", `${vendorLabel(props.vendor)} config updated — run Test to validate`);
      } else {
        await casbApi.createConnector({ vendor: props.vendor, config });
        toastOk("Connector created", `${vendorLabel(props.vendor)} added — run Test to validate`);
      }
      await queryClient.invalidateQueries({ queryKey: ["casb"] });
      setBusy(false);
      props.onClose();
      props.onDone();
    } catch (err) {
      toastErr(err, "Save failed");
      setBusy(false);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && props.onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-base">
            {editing ? `${vendorLabel(props.vendor)} config` : `Set up ${vendorLabel(props.vendor)}`}
          </DialogTitle>
          <DialogDescription>
            Config is a JSON object; secrets must be secret-store refs (keys ending <span className="font-mono">SecretRef</span>/
            <span className="font-mono">TokenRef</span>) — never plaintext. Test validates the shape only: live vendor sync is
            deferred.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-1.5">
          <Label htmlFor="casb-connector-config">Config JSON</Label>
          <Textarea
            id="casb-connector-config"
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={8}
            className="font-mono text-xs"
            spellCheck={false}
          />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={props.onClose} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={busy}>
            {busy ? "Saving…" : editing ? "Save config" : "Create connector"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ConnectorCard(props: {
  vendor: CasbVendor;
  connector: CasbConnectorDTO | null;
  onConfigure: () => void;
  onDelete: () => void;
}) {
  const [testBusy, setTestBusy] = useState(false);
  const queryClient = useQueryClient();
  const c = props.connector;

  const runTest = async () => {
    if (!c) return;
    setTestBusy(true);
    try {
      const res = await casbApi.testConnector(c.id);
      if (res.ok) {
        toastOk("Connector validated", res.message);
      } else {
        toastErr(new Error(res.message), `${vendorLabel(props.vendor)} test failed`);
      }
      await queryClient.invalidateQueries({ queryKey: ["casb"] });
    } catch (err) {
      toastErr(err, "Connector test failed");
    } finally {
      setTestBusy(false);
    }
  };

  return (
    <div className="flex min-w-0 flex-col gap-3 rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
      <div className="flex items-start justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2.5">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-zinc-500/10 text-zinc-600 dark:text-zinc-400">
            <Icons.CloudCog className="h-4.5 w-4.5" />
          </div>
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold">{vendorLabel(props.vendor)}</p>
            <p className="truncate font-mono text-[11px] text-zinc-500">{props.vendor}</p>
          </div>
        </div>
        {c ? (
          <ConnectorStatusBadge status={c.status as ConnectorStatus} />
        ) : (
          <Badge variant="outline" className="border-zinc-300 bg-zinc-100 text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800">
            not configured
          </Badge>
        )}
      </div>

      {c ? (
        <div className="grid gap-1 text-xs text-zinc-500">
          <p>
            Last sync:{" "}
            <span className="tabular-nums">{c.lastSyncAt ? fmtDateTime(c.lastSyncAt) : "never"}</span>
          </p>
          {c.missingKeys.length > 0 ? (
            <p className="text-amber-600 dark:text-amber-400">
              Missing keys: <span className="font-mono">{c.missingKeys.join(", ")}</span>
            </p>
          ) : (
            <p className="text-emerald-600 dark:text-emerald-400">Config shape valid · secret ref present</p>
          )}
        </div>
      ) : (
        <p className="text-xs text-zinc-500">
          Connects audit/API controls for this vendor via a config shell — no live vendor calls in this build.
        </p>
      )}

      <div className="mt-auto flex flex-wrap items-center gap-1.5">
        <Button variant="outline" size="sm" className="h-8 gap-1.5 px-2.5 text-xs" onClick={props.onConfigure}>
          <Icons.Settings2 className="h-3.5 w-3.5" />
          {c ? "Config" : "Set up"}
        </Button>
        {c && (
          <>
            <Button size="sm" className="h-8 gap-1.5 px-2.5 text-xs" onClick={() => void runTest()} disabled={testBusy}>
              <Icons.PlugZap className={cn("h-3.5 w-3.5", testBusy && "animate-pulse")} />
              {testBusy ? "Testing…" : "Test"}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="h-8 gap-1.5 px-2.5 text-xs text-rose-600 dark:text-rose-400"
              onClick={props.onDelete}
              aria-label={`Delete ${vendorLabel(props.vendor)} connector`}
            >
              <Icons.Trash2 className="h-3.5 w-3.5" />
              Delete
            </Button>
          </>
        )}
      </div>
    </div>
  );
}

function ConnectorsTab() {
  const query = useQuery({
    queryKey: ["casb", "connectors"],
    queryFn: () => casbApi.listConnectors(),
  });
  const queryClient = useQueryClient();
  const [configFor, setConfigFor] = useState<CasbVendor | null>(null);
  const [deleteFor, setDeleteFor] = useState<CasbConnectorDTO | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);

  const connectors = query.data ?? [];
  const byVendor = new Map(connectors.map((c) => [c.vendor, c]));

  const confirmDelete = async () => {
    if (!deleteFor) return;
    setDeleteBusy(true);
    try {
      await casbApi.deleteConnector(deleteFor.id);
      toastOk("Connector removed", `${deleteFor.vendorLabel} disconnected from the CASB shell`);
      await queryClient.invalidateQueries({ queryKey: ["casb"] });
      setDeleteFor(null);
    } catch (err) {
      toastErr(err, "Delete failed");
    } finally {
      setDeleteBusy(false);
    }
  };

  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs text-zinc-500">
          One connector per vendor. Test validates the config shape against the vendor key map — no network calls (live vendor
          sync deferred per spec §4.3).
        </p>
        <Button
          variant="outline"
          size="sm"
          className="h-8 gap-1.5 text-xs"
          onClick={() => void query.refetch()}
          disabled={query.isLoading}
        >
          <Icons.RefreshCw className="h-3.5 w-3.5" />
          Refresh
        </Button>
      </div>

      {query.isLoading ? (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="h-40 animate-pulse rounded-lg bg-zinc-500/10" />
          ))}
        </div>
      ) : query.isError ? (
        <QueryError error={query.error} onRetry={() => void query.refetch()} />
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {VENDORS.map((v) => (
            <ConnectorCard
              key={v.value}
              vendor={v.value}
              connector={byVendor.get(v.value) ?? null}
              onConfigure={() => setConfigFor(v.value)}
              onDelete={() => setDeleteFor(byVendor.get(v.value) ?? null)}
            />
          ))}
        </div>
      )}

      {configFor && (
        <ConnectorConfigDialog
          vendor={configFor}
          connector={byVendor.get(configFor) ?? null}
          onClose={() => setConfigFor(null)}
          onDone={() => undefined}
        />
      )}
      {deleteFor && (
        <ConfirmDialog
          open
          onOpenChange={(open) => !open && !deleteBusy && setDeleteFor(null)}
          title={`Remove the ${deleteFor.vendorLabel} connector?`}
          description="Deletes the connector shell and its stored config refs. Observations and catalog entries are unaffected."
          confirmLabel="Remove connector"
          loading={deleteBusy}
          onConfirm={() => void confirmDelete()}
        />
      )}
    </div>
  );
}

// ── main view ───────────────────────────────────────────────────────────────

export function CasbView() {
  const [scanWindow, setScanWindow] = useState(1440);
  const [scanBusy, setScanBusy] = useState(false);
  const queryClient = useQueryClient();

  const runScan = async () => {
    setScanBusy(true);
    try {
      const s = await casbApi.scan(scanWindow);
      toastOk(
        "Scan complete",
        `${s.scanned} log row${s.scanned === 1 ? "" : "s"} scanned — ${s.upserted} client/app pair${
          s.upserted === 1 ? "" : "s"
        }: ${s.sanctioned} sanctioned, ${s.shadow} shadow, ${s.unknown} unknown`,
      );
      await queryClient.invalidateQueries({ queryKey: ["casb"] });
    } catch (err) {
      toastErr(err, "Scan failed");
    } finally {
      setScanBusy(false);
    }
  };

  return (
    <div className="grid gap-3">
      <StatsStrip />

      {/* action bar */}
      <div className="flex flex-wrap items-center gap-2">
        <Button className="h-11 gap-1.5 lg:h-9" onClick={() => void runScan()} disabled={scanBusy}>
          <Icons.ScanSearch className={cn("h-4 w-4", scanBusy && "animate-pulse")} />
          {scanBusy ? "Scanning…" : "Run Scan"}
        </Button>
        <Select value={String(scanWindow)} onValueChange={(v) => setScanWindow(Number(v))}>
          <SelectTrigger className="h-11 w-44 lg:h-9" aria-label="Scan window">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {SCAN_WINDOWS.map((w) => (
              <SelectItem key={w.value} value={String(w.value)}>
                {w.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <span className="text-xs text-zinc-500">Aggregates the app-control log ring into per-client SaaS discoveries.</span>
      </div>

      <Tabs defaultValue="discoveries" className="min-w-0">
        <TabsList className="h-auto w-full flex-wrap justify-start sm:w-auto">
          <TabsTrigger value="discoveries" className="gap-1.5">
            <Icons.EyeOff className="h-3.5 w-3.5" />
            Discoveries
          </TabsTrigger>
          <TabsTrigger value="catalog" className="gap-1.5">
            <Icons.Layers className="h-3.5 w-3.5" />
            Catalog
          </TabsTrigger>
          <TabsTrigger value="connectors" className="gap-1.5">
            <Icons.CloudCog className="h-3.5 w-3.5" />
            Connectors
          </TabsTrigger>
        </TabsList>
        <TabsContent value="discoveries" className="mt-3">
          <DiscoveriesTab />
        </TabsContent>
        <TabsContent value="catalog" className="mt-3">
          <CatalogTab />
        </TabsContent>
        <TabsContent value="connectors" className="mt-3">
          <ConnectorsTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
