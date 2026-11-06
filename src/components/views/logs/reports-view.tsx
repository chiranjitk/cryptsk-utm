"use client";

/**
 * #/logs/reports (M09 §4) — 3 tabs: Reports | Scheduled | Forwarding.
 * Reports tab builds cards + charts from the LOCKED /logs/stats payload
 * (range 1h|24h/7d; series + ipsBySeverity — ENDPOINTS §11), uses the ADR-019
 * chart palette (blue/teal/emerald/amber/rose/zinc — never indigo), a print
 * stylesheet rendered inline (browser print = the Phase-1 PDF path), and
 * CSV/JSON downloads via /logs/reports/export. Scheduled + Forwarding tabs
 * CRUD report schedules and syslog/NetFlow targets (audited, section system).
 */

import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
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
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart";
import { Area, AreaChart, Cell, Pie, PieChart, XAxis, YAxis } from "recharts";
import { cn } from "@/lib/utils";
import { ConfirmDialog, EmptyBlock, FieldLabel, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";
import { logsApi, type LogStats, type NetflowTargetDTO, type ReportScheduleDTO, type StatsRange, type SyslogTargetDTO } from "./logs-api";
import { fmtTs } from "./logs-ui";

// ADR-019 chart series palette (locked: blue, teal, emerald, amber, rose, zinc — no indigo)
const CHART = { blue: "#2563eb", teal: "#14b8a6", emerald: "#10b981", amber: "#f59e0b", rose: "#f43f5e", zinc: "#71717a" } as const;
const ACTION_COLOR: Record<string, string> = { allow: CHART.blue, deny: CHART.rose, drop: CHART.amber, reject: CHART.zinc };
const SEV_COLOR: Record<string, string> = { critical: CHART.rose, high: CHART.amber, medium: CHART.blue, low: CHART.teal, info: CHART.zinc };

const RANGES: StatsRange[] = ["1h", "24h", "7d"];

function bucketLabel(ts: string, range: StatsRange): string {
  const d = new Date(ts);
  const hm = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  if (range === "1h") return hm;
  return `${d.toLocaleDateString(undefined, { month: "short", day: "2-digit" })} ${hm}`;
}

function actionTotals(stats: LogStats): Record<string, number> {
  const out: Record<string, number> = {};
  for (const s of stats.series) out[s.key] = s.points.reduce((a, p) => a + p.count, 0);
  return out;
}

// ── inline print stylesheet (component-scoped rules, M09 §4 tab 1) ─────────

const PRINT_CSS = `
@media print {
  .no-print { display: none !important; }
  body, main, aside { background: #fff !important; }
  body aside { display: none !important; }
  [data-slot="card"] { border: 1px solid #e4e4e7 !important; box-shadow: none !important; break-inside: avoid; }
  * { color: #18181b !important; }
  [data-slot="chart"] { background: #fff !important; }
}
`;

// ── Reports tab ─────────────────────────────────────────────────────────────

const trendConfig = {
  allow: { label: "allow", color: ACTION_COLOR.allow },
  deny: { label: "deny", color: ACTION_COLOR.deny },
  drop: { label: "drop", color: ACTION_COLOR.drop },
  reject: { label: "reject", color: ACTION_COLOR.reject },
} satisfies ChartConfig;

function StatCard(props: { label: string; value: string; sub: string; icon: React.ReactNode; tone: string }) {
  return (
    <Card>
      <CardContent className="flex items-center gap-3 p-4">
        <div className={cn("flex h-10 w-10 shrink-0 items-center justify-center rounded-lg", props.tone)}>{props.icon}</div>
        <div className="min-w-0">
          <p className="truncate text-xs text-zinc-500">{props.label}</p>
          <p className="text-lg font-semibold leading-tight tabular-nums">{props.value}</p>
          <p className="truncate text-[11px] text-zinc-400">{props.sub}</p>
        </div>
      </CardContent>
    </Card>
  );
}

function EmptyChart({ title }: { title: string }) {
  return (
    <div className="flex h-56 items-center justify-center rounded-lg border border-dashed border-zinc-200 dark:border-zinc-800">
      <EmptyBlock icon={<Icons.BarChart3 className="h-6 w-6" />} title="No events in this window" description={`${title} has nothing to plot for the selected range.`} />
    </div>
  );
}

function ReportsTab() {
  const [range, setRange] = useState<StatsRange>("24h");
  const [exporting, setExporting] = useState<string | null>(null);
  const stats = useQuery({
    queryKey: ["logs", "stats", range],
    queryFn: () => logsApi.getStats(range),
  });

  const derived = useMemo(() => {
    const s = stats.data;
    if (!s) return null;
    const totals = actionTotals(s);
    const total = Object.values(totals).reduce((a, b) => a + b, 0);
    const blocked = total > 0 ? ((totals.deny + totals.drop + totals.reject) / total) * 100 : 0;
    const critHigh = s.ipsBySeverity
      .filter((e) => e.key === "critical" || e.key === "high")
      .reduce((a, e) => a + e.count, 0);
    let peak = { label: "—", count: 0 };
    if (s.series.length > 0) {
      const buckets = s.series[0].points.length;
      for (let i = 0; i < buckets; i++) {
        const sum = s.series.reduce((a, serie) => a + (serie.points[i]?.count ?? 0), 0);
        if (sum > peak.count) peak = { label: bucketLabel(s.series[0].points[i].ts, range), count: sum };
      }
    }
    const trend = (s.series[0]?.points ?? []).map((p, i) => {
      const row: Record<string, string | number> = { label: bucketLabel(p.ts, range) };
      for (const serie of s.series) row[serie.key] = serie.points[i]?.count ?? 0;
      return row;
    });
    return { s, totals, total, blocked, critHigh, peak, trend };
  }, [stats.data, range]);

  const onExport = async (format: "csv" | "json") => {
    setExporting(format);
    try {
      await logsApi.exportReport(range, format);
      toastOk(`Report ${format.toUpperCase()} downloaded`, `Range: ${range}`);
    } catch (err) {
      toastErr(err, "Report export failed");
    } finally {
      setExporting(null);
    }
  };

  return (
    <div className="grid gap-4">
      <style dangerouslySetInnerHTML={{ __html: PRINT_CSS }} />

      {/* range picker + actions */}
      <div className="no-print flex flex-wrap items-center gap-2">
        <div className="flex overflow-hidden rounded-lg border border-zinc-200 dark:border-zinc-800">
          {RANGES.map((r) => (
            <button
              key={r}
              type="button"
              onClick={() => setRange(r)}
              className={cn(
                "px-3 py-1.5 text-xs font-medium transition-colors",
                range === r
                  ? "bg-blue-600 text-white"
                  : "bg-transparent text-zinc-500 hover:bg-zinc-100 dark:hover:bg-zinc-800",
              )}
            >
              {r}
            </button>
          ))}
        </div>
        <Badge variant="outline" className="border-zinc-300 text-[11px] text-zinc-500 dark:border-zinc-700">
          <Icons.Clock className="mr-1 h-3 w-3" />
          {stats.data ? `${fmtTs(stats.data.from)} → ${fmtTs(stats.data.to)} · ${stats.data.bucketMinutes}m buckets` : "loading…"}
        </Badge>
        <div className="ml-auto flex items-center gap-1.5">
          <Button size="sm" variant="outline" className="h-8 gap-1.5" onClick={() => window.print()}>
            <Icons.Printer className="h-3.5 w-3.5" />
            Print
          </Button>
          <Button size="sm" variant="outline" className="h-8 gap-1.5" disabled={exporting !== null} onClick={() => void onExport("csv")}>
            {exporting === "csv" ? <Icons.Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Icons.FileSpreadsheet className="h-3.5 w-3.5" />}
            Download CSV
          </Button>
          <Button size="sm" variant="outline" className="h-8 gap-1.5" disabled={exporting !== null} onClick={() => void onExport("json")}>
            {exporting === "json" ? <Icons.Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Icons.FileJson className="h-3.5 w-3.5" />}
            Download JSON
          </Button>
        </div>
      </div>

      {stats.isLoading ? (
        <div className="grid gap-4 md:grid-cols-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <Card key={i}>
              <div className="h-16 animate-pulse rounded-lg bg-zinc-100 dark:bg-zinc-800" />
            </Card>
          ))}
        </div>
      ) : stats.isError ? (
        <QueryError error={stats.error} onRetry={() => void stats.refetch()} />
      ) : derived ? (
        <>
          {/* cards row */}
          <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
            <StatCard
              label="Total flows"
              value={derived.total.toLocaleString()}
              sub={`window ${range}`}
              icon={<Icons.Waves className="h-5 w-5" />}
              tone="bg-blue-500/10 text-blue-600 dark:text-blue-400"
            />
            <StatCard
              label="Blocked"
              value={`${derived.blocked.toFixed(1)}%`}
              sub="deny + drop + reject"
              icon={<Icons.ShieldBan className="h-5 w-5" />}
              tone="bg-rose-500/10 text-rose-600 dark:text-rose-400"
            />
            <StatCard
              label="Critical + high"
              value={derived.critHigh.toLocaleString()}
              sub="IPS events in window"
              icon={<Icons.Siren className="h-5 w-5" />}
              tone="bg-amber-500/10 text-amber-600 dark:text-amber-400"
            />
            <StatCard
              label="Peak bucket"
              value={derived.peak.count.toLocaleString()}
              sub={derived.peak.count > 0 ? `at ${derived.peak.label}` : "no activity"}
              icon={<Icons.TrendingUp className="h-5 w-5" />}
              tone="bg-teal-500/10 text-teal-600 dark:text-teal-400"
            />
          </div>

          {/* charts */}
          <div className="grid gap-4 lg:grid-cols-3">
            <Card className="lg:col-span-2">
              <CardHeader className="p-4 pb-2 md:p-6 md:pb-2">
                <CardTitle className="text-sm font-medium">Action trend (stacked)</CardTitle>
              </CardHeader>
              <CardContent className="p-4 pt-0 md:p-6 md:pt-0">
                {derived.total === 0 ? (
                  <EmptyChart title="Action trend" />
                ) : (
                  <ChartContainer config={trendConfig} className="h-64 w-full">
                    <AreaChart data={derived.trend} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
                      <XAxis dataKey="label" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} minTickGap={40} />
                      <YAxis tick={{ fontSize: 10 }} tickLine={false} axisLine={false} width={44} />
                      <ChartTooltip content={<ChartTooltipContent />} />
                      {(["allow", "deny", "drop", "reject"] as const).map((k) => (
                        <Area
                          key={k}
                          type="monotone"
                          dataKey={k}
                          stackId="1"
                          stroke={`var(--color-${k})`}
                          fill={`var(--color-${k})`}
                          fillOpacity={0.55}
                          strokeWidth={1.5}
                          isAnimationActive={false}
                        />
                      ))}
                    </AreaChart>
                  </ChartContainer>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="p-4 pb-2 md:p-6 md:pb-2">
                <CardTitle className="text-sm font-medium">Action mix</CardTitle>
              </CardHeader>
              <CardContent className="p-4 pt-0 md:p-6 md:pt-0">
                {derived.total === 0 ? (
                  <EmptyChart title="Action mix" />
                ) : (
                  <ChartContainer config={{}} className="h-64 w-full">
                    <PieChart>
                      <ChartTooltip content={<ChartTooltipContent hideLabel />} />
                      <Pie
                        data={Object.entries(derived.totals).map(([key, count]) => ({ key, count }))}
                        dataKey="count"
                        nameKey="key"
                        innerRadius="55%"
                        outerRadius="85%"
                        paddingAngle={2}
                        strokeWidth={0}
                      >
                        {Object.entries(derived.totals).map(([key]) => (
                          <Cell key={key} fill={ACTION_COLOR[key] ?? CHART.zinc} />
                        ))}
                      </Pie>
                    </PieChart>
                  </ChartContainer>
                )}
                <ul className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                  {Object.entries(derived.totals).map(([key, count]) => (
                    <li key={key} className="flex items-center gap-1.5">
                      <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: ACTION_COLOR[key] }} />
                      <span className="text-zinc-600 dark:text-zinc-300">{key}</span>
                      <span className="ml-auto tabular-nums text-zinc-400">{count.toLocaleString()}</span>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>

            <Card className="lg:col-span-3">
              <CardHeader className="p-4 pb-2 md:p-6 md:pb-2">
                <CardTitle className="text-sm font-medium">Threat mix (IPS by severity)</CardTitle>
              </CardHeader>
              <CardContent className="p-4 pt-0 md:p-6 md:pt-0">
                {derived.critHigh === 0 && derived.s.ipsBySeverity.every((e) => e.count === 0) ? (
                  <EmptyChart title="Threat mix" />
                ) : (
                  <div className="flex flex-col items-center gap-3 sm:flex-row sm:items-start">
                    <ChartContainer config={{}} className="h-56 w-full sm:w-72">
                      <PieChart>
                        <ChartTooltip content={<ChartTooltipContent hideLabel />} />
                        <Pie
                          data={derived.s.ipsBySeverity.filter((e) => e.count > 0)}
                          dataKey="count"
                          nameKey="key"
                          innerRadius="55%"
                          outerRadius="85%"
                          paddingAngle={2}
                          strokeWidth={0}
                        >
                          {derived.s.ipsBySeverity.filter((e) => e.count > 0).map((e) => (
                            <Cell key={e.key} fill={SEV_COLOR[e.key] ?? CHART.zinc} />
                          ))}
                        </Pie>
                      </PieChart>
                    </ChartContainer>
                    <ul className="grid flex-1 grid-cols-2 gap-x-6 gap-y-1.5 text-xs">
                      {derived.s.ipsBySeverity.map((e) => (
                        <li key={e.key} className="flex items-center gap-1.5 border-b border-zinc-100 pb-1 dark:border-zinc-800/60">
                          <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: SEV_COLOR[e.key] ?? CHART.zinc }} />
                          <span className="uppercase text-zinc-600 dark:text-zinc-300">{e.key}</span>
                          <span className="ml-auto font-mono tabular-nums text-zinc-400">{e.count.toLocaleString()}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </>
      ) : null}
    </div>
  );
}

// ── Scheduled reports tab ───────────────────────────────────────────────────

const FORMAT_NOTE: Record<string, string> = {
  pdf: "rendered via print in sandbox",
  html: "rendered via print in sandbox",
  csv: "download on run",
  json: "download on run",
};

const SECTION_LABELS: Record<string, string> = { traffic: "Traffic", threats: "Threats", audit: "Audit" };

function ScheduleEditor(props: {
  onClose: () => void;
  initial: ReportScheduleDTO | null;
  onSaved: (msg: string) => void;
}) {
  const isEdit = props.initial !== null;
  // state initialized from props at mount — parent conditionally mounts with a key per target row
  const [name, setName] = useState(props.initial?.name ?? "");
  const [range, setRange] = useState<"daily" | "weekly" | "monthly">((props.initial?.range as "daily" | "weekly" | "monthly") ?? "daily");
  const [format, setFormat] = useState<"pdf" | "html" | "csv" | "json">((props.initial?.format as "pdf" | "html" | "csv" | "json") ?? "pdf");
  const [sections, setSections] = useState<string[]>(props.initial?.sections?.length ? props.initial.sections : ["traffic", "threats"]);
  const [recipients, setRecipients] = useState(props.initial?.recipients ?? "");
  const [enabled, setEnabled] = useState(props.initial?.enabled ?? true);
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      isEdit ? logsApi.updateSchedule(props.initial!.id, body) : logsApi.createSchedule(body),
    onSuccess: (saved) => {
      props.onSaved(`${isEdit ? "Updated" : "Created"} schedule "${saved.name}"`);
      props.onClose();
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Save failed"),
  });

  const toggleSection = (s: string, on: boolean) =>
    setSections((prev) => (on ? [...prev, s] : prev.filter((x) => x !== s)));

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-base">{isEdit ? "Edit schedule" : "New schedule"}</DialogTitle>
          <DialogDescription>Delivery is display-only in the sandbox (no mailer) — recipients are recorded for the appliance.</DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div>
            <FieldLabel>Name</FieldLabel>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Daily threat digest" />
          </div>
          <div>
            <FieldLabel>Range</FieldLabel>
            <RadioGroup value={range} onValueChange={(v) => setRange(v as "daily" | "weekly" | "monthly")} className="flex gap-4">
              {(["daily", "weekly", "monthly"] as const).map((r) => (
                <div key={r} className="flex items-center gap-1.5">
                  <RadioGroupItem value={r} id={`range-${r}`} />
                  <Label htmlFor={`range-${r}`} className="text-xs capitalize">
                    {r}
                  </Label>
                </div>
              ))}
            </RadioGroup>
          </div>
          <div>
            <FieldLabel hint={FORMAT_NOTE[format]}>Format</FieldLabel>
            <Select value={format} onValueChange={(v) => setFormat(v as "pdf" | "html" | "csv" | "json")}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(["pdf", "html", "csv", "json"] as const).map((f) => (
                  <SelectItem key={f} value={f}>
                    {f.toUpperCase()}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="mt-1 text-[11px] text-zinc-400">{FORMAT_NOTE[format]}</p>
          </div>
          <div>
            <FieldLabel hint="at least one">Sections</FieldLabel>
            <div className="flex flex-wrap gap-4">
              {Object.entries(SECTION_LABELS).map(([key, label]) => (
                <label key={key} className="flex items-center gap-1.5 text-xs">
                  <Checkbox checked={sections.includes(key)} onCheckedChange={(c) => toggleSection(key, c === true)} />
                  {label}
                </label>
              ))}
            </div>
          </div>
          <div>
            <FieldLabel hint="comma-separated">Recipients</FieldLabel>
            <Input value={recipients} onChange={(e) => setRecipients(e.target.value)} placeholder="ops@example.com, soc@example.com" />
          </div>
          <div className="flex items-center gap-2">
            <Switch checked={enabled} onCheckedChange={setEnabled} id="sched-enabled" />
            <Label htmlFor="sched-enabled" className="text-xs">
              Enabled
            </Label>
          </div>
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button
            disabled={save.isPending || !name.trim() || sections.length === 0}
            onClick={() => save.mutate({ name: name.trim(), range, format, sections, recipients: recipients.trim() || null, enabled })}
          >
            {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create schedule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ScheduledTab() {
  const queryClient = useQueryClient();
  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<ReportScheduleDTO | null>(null);
  const [deleting, setDeleting] = useState<ReportScheduleDTO | null>(null);
  const query = useQuery({ queryKey: ["logs", "schedules"], queryFn: () => logsApi.listSchedules() });

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ["logs", "schedules"] });

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => logsApi.updateSchedule(id, { enabled }),
    onSuccess: invalidate,
    onError: (e) => toastErr(e, "Toggle failed"),
  });
  const run = useMutation({
    mutationFn: (id: number) => logsApi.runSchedule(id),
    onSuccess: (r) => {
      invalidate();
      toastOk("Report generated", `lastRunAt ${fmtTs(r.lastRunAt)} — open the Reports tab for the live view, or export CSV/JSON`);
    },
    onError: (e) => toastErr(e, "Run failed"),
  });
  const del = useMutation({
    mutationFn: (id: number) => logsApi.deleteSchedule(id),
    onSuccess: () => {
      invalidate();
      setDeleting(null);
      toastOk("Schedule deleted");
    },
    onError: (e) => toastErr(e, "Delete failed"),
  });

  const rows = query.data ?? [];

  return (
    <div className="grid gap-3">
      <div className="no-print flex items-center justify-between">
        <p className="text-xs text-zinc-500">Engine-driven schedules bump <span className="font-mono">lastRunAt</span> on their window; Run now generates immediately.</p>
        <Button
          size="sm"
          className="h-8 gap-1.5"
          onClick={() => {
            setEditing(null);
            setEditorOpen(true);
          }}
        >
          <Icons.Plus className="h-3.5 w-3.5" />
          New schedule
        </Button>
      </div>

      <div className="rounded-lg border border-zinc-200 dark:border-zinc-800">
        {query.isLoading ? (
          <TableSkeleton rows={4} cols={7} />
        ) : query.isError ? (
          <QueryError error={query.error} onRetry={() => void query.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyBlock icon={<Icons.CalendarClock className="h-6 w-6" />} title="No schedules yet" description="Create a daily/weekly/monthly report schedule." />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Range</TableHead>
                <TableHead>Format</TableHead>
                <TableHead>Sections</TableHead>
                <TableHead>Recipients</TableHead>
                <TableHead>Last run</TableHead>
                <TableHead>Enabled</TableHead>
                <TableHead className="w-28 text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((s) => (
                <TableRow key={s.id}>
                  <TableCell className="text-sm font-medium">{s.name}</TableCell>
                  <TableCell>
                    <Badge variant="outline" className="border-blue-500/40 bg-blue-500/10 text-[11px] capitalize text-blue-600 dark:text-blue-400">
                      <Icons.CalendarClock className="mr-1 h-3 w-3" />
                      {s.range}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="border-zinc-300 font-mono text-[11px] uppercase text-zinc-600 dark:border-zinc-700 dark:text-zinc-300">
                      {s.format}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <span className="flex flex-wrap gap-1">
                      {s.sections.map((sec) => (
                        <Badge key={sec} variant="outline" className="border-zinc-300 text-[10px] capitalize text-zinc-500 dark:border-zinc-700">
                          {sec}
                        </Badge>
                      ))}
                    </span>
                  </TableCell>
                  <TableCell className="max-w-40 truncate text-xs">{s.recipients ?? "—"}</TableCell>
                  <TableCell className="whitespace-nowrap text-xs tabular-nums">{s.lastRunAt ? fmtTs(s.lastRunAt) : <span className="text-zinc-400">never</span>}</TableCell>
                  <TableCell>
                    <Switch checked={s.enabled} onCheckedChange={(enabled) => toggle.mutate({ id: s.id, enabled })} aria-label={`Toggle ${s.name}`} />
                  </TableCell>
                  <TableCell className="text-right">
                    <span className="inline-flex gap-1" onClick={(e) => e.stopPropagation()}>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 px-2"
                        title="Run now"
                        disabled={run.isPending}
                        onClick={() => run.mutate(s.id)}
                      >
                        <Icons.Play className="h-3.5 w-3.5" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 px-2"
                        title="Edit"
                        onClick={() => {
                          setEditing(s);
                          setEditorOpen(true);
                        }}
                      >
                        <Icons.Pencil className="h-3.5 w-3.5" />
                      </Button>
                      <Button variant="ghost" size="sm" className="h-7 px-2 text-rose-600" title="Delete" onClick={() => setDeleting(s)}>
                        <Icons.Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </span>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>

      {editorOpen && (
        <ScheduleEditor
          key={editing?.id ?? "new"}
          onClose={() => setEditorOpen(false)}
          initial={editing}
          onSaved={(msg) => {
            invalidate();
            toastOk(msg);
          }}
        />
      )}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={`Delete schedule "${deleting?.name ?? ""}"?`}
        description="The schedule stops generating reports. This cannot be undone."
        loading={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting.id)}
      />
    </div>
  );
}

// ── Forwarding tab (syslog + NetFlow) ───────────────────────────────────────

function SyslogEditor(props: { onClose: () => void; initial: SyslogTargetDTO | null; onSaved: () => void }) {
  const isEdit = props.initial !== null;
  // state initialized from props at mount — parent conditionally mounts with a key per target row
  const [name, setName] = useState(props.initial?.name ?? "");
  const [host, setHost] = useState(props.initial?.host ?? "");
  const [port, setPort] = useState(String(props.initial?.port ?? 514));
  const [protocol, setProtocol] = useState<"udp" | "tcp" | "tls">((props.initial?.protocol as "udp" | "tcp" | "tls") ?? "udp");
  const [minSeverity, setMinSeverity] = useState(props.initial?.minSeverity ?? "info");
  const [enabled, setEnabled] = useState(props.initial?.enabled ?? true);
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      isEdit ? logsApi.updateSyslogTarget(props.initial!.id, body) : logsApi.createSyslogTarget(body),
    onSuccess: () => {
      props.onSaved();
      props.onClose();
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Save failed"),
  });

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-base">{isEdit ? "Edit syslog target" : "New syslog target"}</DialogTitle>
          <DialogDescription>rsyslog queue semantics: unreachable targets buffer rows until reachable (appliance-side).</DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div>
            <FieldLabel>Name</FieldLabel>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="SIEM collector" />
          </div>
          <div className="grid grid-cols-[1fr_96px] gap-2">
            <div>
              <FieldLabel>Host</FieldLabel>
              <Input value={host} onChange={(e) => setHost(e.target.value)} placeholder="10.0.0.50" className="font-mono text-xs" />
            </div>
            <div>
              <FieldLabel>Port</FieldLabel>
              <Input type="number" min={1} max={65535} value={port} onChange={(e) => setPort(e.target.value)} className="font-mono text-xs" />
            </div>
          </div>
          <div>
            <FieldLabel>Protocol</FieldLabel>
            <RadioGroup value={protocol} onValueChange={(v) => setProtocol(v as "udp" | "tcp" | "tls")} className="flex gap-4">
              {(["udp", "tcp", "tls"] as const).map((p) => (
                <div key={p} className="flex items-center gap-1.5">
                  <RadioGroupItem value={p} id={`syslog-${p}`} />
                  <Label htmlFor={`syslog-${p}`} className="text-xs uppercase">
                    {p}
                  </Label>
                </div>
              ))}
            </RadioGroup>
          </div>
          <div>
            <FieldLabel>Minimum severity</FieldLabel>
            <Select value={minSeverity} onValueChange={setMinSeverity}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {["info", "low", "medium", "high", "critical"].map((s) => (
                  <SelectItem key={s} value={s}>
                    {s}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex items-center gap-2">
            <Switch checked={enabled} onCheckedChange={setEnabled} id="syslog-enabled" />
            <Label htmlFor="syslog-enabled" className="text-xs">
              Enabled
            </Label>
          </div>
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button
            disabled={save.isPending || !name.trim() || !host.trim()}
            onClick={() =>
              save.mutate({
                name: name.trim(),
                host: host.trim(),
                port: Number(port) || 514,
                protocol,
                minSeverity,
                enabled,
              })
            }
          >
            {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create target"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function NetflowEditor(props: { onClose: () => void; initial: NetflowTargetDTO | null; onSaved: () => void }) {
  const isEdit = props.initial !== null;
  // state initialized from props at mount — parent conditionally mounts with a key per target row
  const [name, setName] = useState(props.initial?.name ?? "");
  const [host, setHost] = useState(props.initial?.host ?? "");
  const [port, setPort] = useState(String(props.initial?.port ?? 2055));
  const [version, setVersion] = useState<"v5" | "v9" | "ipfix">((props.initial?.version as "v5" | "v9" | "ipfix") ?? "ipfix");
  const [samplingRate, setSamplingRate] = useState(String(props.initial?.samplingRate ?? 100));
  const [enabled, setEnabled] = useState(props.initial?.enabled ?? true);
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      isEdit ? logsApi.updateNetflowTarget(props.initial!.id, body) : logsApi.createNetflowTarget(body),
    onSuccess: () => {
      props.onSaved();
      props.onClose();
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Save failed"),
  });

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-base">{isEdit ? "Edit NetFlow target" : "New NetFlow target"}</DialogTitle>
          <DialogDescription>Appliance-side exporters: softflowd/nfdump per spec §1.12.</DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div>
            <FieldLabel>Name</FieldLabel>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Flow collector" />
          </div>
          <div className="grid grid-cols-[1fr_96px] gap-2">
            <div>
              <FieldLabel>Host</FieldLabel>
              <Input value={host} onChange={(e) => setHost(e.target.value)} placeholder="10.0.0.60" className="font-mono text-xs" />
            </div>
            <div>
              <FieldLabel>Port</FieldLabel>
              <Input type="number" min={1} max={65535} value={port} onChange={(e) => setPort(e.target.value)} className="font-mono text-xs" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div>
              <FieldLabel>Version</FieldLabel>
              <Select value={version} onValueChange={(v) => setVersion(v as "v5" | "v9" | "ipfix")}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {(["v5", "v9", "ipfix"] as const).map((v) => (
                    <SelectItem key={v} value={v}>
                      {v}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel hint="1-in-N">Sampling rate</FieldLabel>
              <Input type="number" min={1} max={65536} value={samplingRate} onChange={(e) => setSamplingRate(e.target.value)} className="font-mono text-xs" />
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Switch checked={enabled} onCheckedChange={setEnabled} id="netflow-enabled" />
            <Label htmlFor="netflow-enabled" className="text-xs">
              Enabled
            </Label>
          </div>
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button
            disabled={save.isPending || !name.trim() || !host.trim()}
            onClick={() =>
              save.mutate({
                name: name.trim(),
                host: host.trim(),
                port: Number(port) || 2055,
                version,
                samplingRate: Number(samplingRate) || 100,
                enabled,
              })
            }
          >
            {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create target"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ForwardingTab() {
  const queryClient = useQueryClient();
  const [syslogEditor, setSyslogEditor] = useState<{ open: boolean; initial: SyslogTargetDTO | null }>({ open: false, initial: null });
  const [netflowEditor, setNetflowEditor] = useState<{ open: boolean; initial: NetflowTargetDTO | null }>({ open: false, initial: null });
  const [deleting, setDeleting] = useState<{ kind: "syslog" | "netflow"; row: SyslogTargetDTO | NetflowTargetDTO } | null>(null);

  const syslog = useQuery({ queryKey: ["logs", "syslog-targets"], queryFn: () => logsApi.listSyslogTargets() });
  const netflow = useQuery({ queryKey: ["logs", "netflow-targets"], queryFn: () => logsApi.listNetflowTargets() });

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["logs", "syslog-targets"] });
    void queryClient.invalidateQueries({ queryKey: ["logs", "netflow-targets"] });
  };

  const toggleSyslog = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => logsApi.updateSyslogTarget(id, { enabled }),
    onSuccess: invalidate,
    onError: (e) => toastErr(e, "Toggle failed"),
  });
  const toggleNetflow = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => logsApi.updateNetflowTarget(id, { enabled }),
    onSuccess: invalidate,
    onError: (e) => toastErr(e, "Toggle failed"),
  });
  const del = useMutation({
    mutationFn: ({ kind, id }: { kind: "syslog" | "netflow"; id: number }) =>
      kind === "syslog" ? logsApi.deleteSyslogTarget(id) : logsApi.deleteNetflowTarget(id),
    onSuccess: () => {
      invalidate();
      setDeleting(null);
      toastOk("Target deleted");
    },
    onError: (e) => toastErr(e, "Delete failed"),
  });

  const syslogRows = syslog.data ?? [];
  const netflowRows = netflow.data ?? [];

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      {/* syslog card */}
      <Card>
        <CardHeader className="flex-row items-center justify-between space-y-0 p-4 md:p-6">
          <CardTitle className="flex items-center gap-2 text-sm font-medium">
            <Icons.FileText className="h-4 w-4 text-blue-600 dark:text-blue-400" />
            Syslog targets
          </CardTitle>
          <Button
            size="sm"
            variant="outline"
            className="h-8 gap-1.5"
            onClick={() => setSyslogEditor({ open: true, initial: null })}
          >
            <Icons.Plus className="h-3.5 w-3.5" />
            Add
          </Button>
        </CardHeader>
        <CardContent className="p-4 pt-0 md:p-6 md:pt-0">
          {syslog.isLoading ? (
            <TableSkeleton rows={2} cols={5} />
          ) : syslog.isError ? (
            <QueryError error={syslog.error} onRetry={() => void syslog.refetch()} />
          ) : syslogRows.length === 0 ? (
            <EmptyBlock icon={<Icons.FileText className="h-6 w-6" />} title="No syslog targets" description="Forward logs to a SIEM collector (udp/tcp/tls)." />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Host:port</TableHead>
                  <TableHead>Proto</TableHead>
                  <TableHead>Min sev</TableHead>
                  <TableHead className="text-right">Buffered</TableHead>
                  <TableHead>On</TableHead>
                  <TableHead className="w-20 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {syslogRows.map((t) => (
                  <TableRow key={t.id}>
                    <TableCell className="text-sm font-medium">{t.name}</TableCell>
                    <TableCell className="whitespace-nowrap font-mono text-xs">
                      {t.host}:{t.port}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="border-blue-500/40 bg-blue-500/10 text-[11px] uppercase text-blue-600 dark:text-blue-400">
                        {t.protocol}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs capitalize">{t.minSeverity}</TableCell>
                    <TableCell className="text-right">
                      <span
                        className={cn(
                          "inline-flex items-center gap-1 font-mono text-xs tabular-nums",
                          t.bufferedRows > 0 && "rounded bg-amber-500/15 px-1.5 py-0.5 text-amber-600 dark:text-amber-400",
                        )}
                        title={t.bufferedRows > 0 ? "Target unreachable — rows buffering" : undefined}
                      >
                        {t.bufferedRows > 0 && <span className="h-1.5 w-1.5 rounded-full bg-amber-500" />}
                        {t.bufferedRows}
                      </span>
                    </TableCell>
                    <TableCell>
                      <Switch checked={t.enabled} onCheckedChange={(enabled) => toggleSyslog.mutate({ id: t.id, enabled })} aria-label={`Toggle ${t.name}`} />
                    </TableCell>
                    <TableCell className="text-right">
                      <span className="inline-flex gap-1">
                        <Button variant="ghost" size="sm" className="h-7 px-2" title="Edit" onClick={() => setSyslogEditor({ open: true, initial: t })}>
                          <Icons.Pencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button variant="ghost" size="sm" className="h-7 px-2 text-rose-600" title="Delete" onClick={() => setDeleting({ kind: "syslog", row: t })}>
                          <Icons.Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* netflow card */}
      <Card>
        <CardHeader className="flex-row items-center justify-between space-y-0 p-4 md:p-6">
          <CardTitle className="flex items-center gap-2 text-sm font-medium">
            <Icons.Network className="h-4 w-4 text-blue-600 dark:text-blue-400" />
            NetFlow / IPFIX targets
          </CardTitle>
          <Button
            size="sm"
            variant="outline"
            className="h-8 gap-1.5"
            onClick={() => setNetflowEditor({ open: true, initial: null })}
          >
            <Icons.Plus className="h-3.5 w-3.5" />
            Add
          </Button>
        </CardHeader>
        <CardContent className="p-4 pt-0 md:p-6 md:pt-0">
          {netflow.isLoading ? (
            <TableSkeleton rows={2} cols={5} />
          ) : netflow.isError ? (
            <QueryError error={netflow.error} onRetry={() => void netflow.refetch()} />
          ) : netflowRows.length === 0 ? (
            <EmptyBlock icon={<Icons.Network className="h-6 w-6" />} title="No NetFlow targets" description="Export flows to a collector (v5/v9/ipfix, 1-in-N sampling)." />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Host:port</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead>Sampling</TableHead>
                  <TableHead>On</TableHead>
                  <TableHead className="w-20 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {netflowRows.map((t) => (
                  <TableRow key={t.id}>
                    <TableCell className="text-sm font-medium">{t.name}</TableCell>
                    <TableCell className="whitespace-nowrap font-mono text-xs">
                      {t.host}:{t.port}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="border-teal-500/40 bg-teal-500/10 text-[11px] text-teal-600 dark:text-teal-400">
                        {t.version}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs">1-in-{t.samplingRate}</TableCell>
                    <TableCell>
                      <Switch checked={t.enabled} onCheckedChange={(enabled) => toggleNetflow.mutate({ id: t.id, enabled })} aria-label={`Toggle ${t.name}`} />
                    </TableCell>
                    <TableCell className="text-right">
                      <span className="inline-flex gap-1">
                        <Button variant="ghost" size="sm" className="h-7 px-2" title="Edit" onClick={() => setNetflowEditor({ open: true, initial: t })}>
                          <Icons.Pencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button variant="ghost" size="sm" className="h-7 px-2 text-rose-600" title="Delete" onClick={() => setDeleting({ kind: "netflow", row: t })}>
                          <Icons.Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {syslogEditor.open && (
        <SyslogEditor
          key={syslogEditor.initial?.id ?? "new"}
          initial={syslogEditor.initial}
          onClose={() => setSyslogEditor({ open: false, initial: null })}
          onSaved={() => {
            invalidate();
            toastOk(syslogEditor.initial ? "Syslog target updated" : "Syslog target created");
          }}
        />
      )}
      {netflowEditor.open && (
        <NetflowEditor
          key={netflowEditor.initial?.id ?? "new"}
          initial={netflowEditor.initial}
          onClose={() => setNetflowEditor({ open: false, initial: null })}
          onSaved={() => {
            invalidate();
            toastOk(netflowEditor.initial ? "NetFlow target updated" : "NetFlow target created");
          }}
        />
      )}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={`Delete ${deleting?.kind === "netflow" ? "NetFlow" : "syslog"} target "${deleting?.row.name ?? ""}"?`}
        description="Log forwarding to this collector stops immediately."
        loading={del.isPending}
        onConfirm={() => deleting && del.mutate({ kind: deleting.kind, id: deleting.row.id })}
      />
    </div>
  );
}

// ── root view ───────────────────────────────────────────────────────────────

export function ReportsView() {
  return (
    <Tabs defaultValue="reports" className="grid gap-4">
      <TabsList className="no-print w-fit">
        <TabsTrigger value="reports" className="gap-1.5">
          <Icons.BarChart3 className="h-3.5 w-3.5" />
          Reports
        </TabsTrigger>
        <TabsTrigger value="scheduled" className="gap-1.5">
          <Icons.CalendarClock className="h-3.5 w-3.5" />
          Scheduled
        </TabsTrigger>
        <TabsTrigger value="forwarding" className="gap-1.5">
          <Icons.Send className="h-3.5 w-3.5" />
          Forwarding
        </TabsTrigger>
      </TabsList>
      <TabsContent value="reports">
        <ReportsTab />
      </TabsContent>
      <TabsContent value="scheduled">
        <ScheduledTab />
      </TabsContent>
      <TabsContent value="forwarding">
        <ForwardingTab />
      </TabsContent>
    </Tabs>
  );
}
