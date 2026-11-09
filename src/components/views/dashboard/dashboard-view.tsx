"use client";

/**
 * #/dashboard — M01-DASHBOARD.md. 30-second answer to "is the network healthy,
 * what is happening right now, what needs attention?". Live via metrics:tick +
 * wan:status + alerts:new; backfill from GET /api/v1/dashboard/summary.
 *
 * v2 (informative edition): status banner with overall verdict + KPI chips +
 * 24 h severity bar, live RX/TX speeds and traffic-window totals, top-talker
 * traffic bars, dedicated VPN tunnel panel, PKI expiring-certificates feed
 * and a system panel.
 */

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { AppsDonut, ThroughputAreaChart } from "@/components/charts/palette";
import { fetchApi, useRealtime, type MetricsTickPayload, type WanStatusPayload, type AlertNewPayload } from "@/lib/realtime";
import { cn } from "@/lib/utils";

type Summary = {
  health: { cpuPct: number; memPct: number; diskPct: number; tempC: number; uptimeSec: number };
  throughput: MetricsTickPayload;
  throughputHistory: MetricsTickPayload[];
  sessions: { active: number; conntrackCount: number };
  alerts24h: { total: number; bySeverity: Record<string, number> };
  topApps: Array<{ app: string; bytes: number }>;
  topTalkers: Array<{ ip: string; userName: string | null; bytes: number }>;
  wanStatus: Array<{ iface: string; state: string; rxKbps: number; txKbps: number }>;
  vpnStatus: Array<{ id: number; name: string; type: string; status: string; statusMessage?: string | null; activeSessions: number }>;
  recentThreats: Array<{ id?: number; ts: string; severity: string; category: string; message: string; srcIp: string; action: string }>;
};

type CertLite = { commonName: string; daysUntilExpiry: number | null; notAfter: string | null; status: string };

type Point = { ts: string; label: string; rx: number; tx: number };

const timeLabel = (ts: string) => new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const fmtBytes = (v: number) => (v >= 1e9 ? `${(v / 1e9).toFixed(1)} GB` : v >= 1e6 ? `${(v / 1e6).toFixed(0)} MB` : `${(v / 1e3).toFixed(0)} KB`);
const fmtUptime = (s: number) => `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
const fmtSpeed = (kbps: number) => (kbps >= 1000 ? `${(kbps / 1000).toFixed(1)} Mbps` : `${Math.round(kbps)} kbps`);

function tickToPoints(ticks: MetricsTickPayload[]): Point[] {
  const sum = (t: MetricsTickPayload, dir: "rxKbps" | "txKbps") => t.ifaces.reduce((s, i) => s + (i[dir] ?? 0), 0);
  return ticks.map((t) => ({ ts: t.ts, label: timeLabel(t.ts), rx: sum(t, "rxKbps"), tx: sum(t, "txKbps") }));
}

const SEV_STYLES: Record<string, string> = {
  critical: "bg-rose-500/15 text-rose-600 dark:text-rose-400 border-rose-500/30",
  high: "bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20",
  medium: "bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/30",
  low: "bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/20",
  info: "bg-zinc-500/10 text-zinc-600 dark:text-zinc-300 border-zinc-500/20",
};

const SEV_BAR: Record<string, string> = {
  critical: "bg-rose-600",
  high: "bg-rose-500",
  medium: "bg-amber-500",
  low: "bg-orange-400",
  info: "bg-zinc-400 dark:bg-zinc-500",
};
const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;

function GaugeCard({ label, value, unit, pct, icon, tone }: { label: string; value: string; unit?: string; pct: number; icon: React.ReactNode; tone: string }) {
  return (
    <Card>
      <CardContent className="flex items-center gap-3 p-4">
        <div className={cn("flex h-10 w-10 shrink-0 items-center justify-center rounded-lg", tone)}>{icon}</div>
        <div className="min-w-0 flex-1">
          <p className="truncate text-xs text-zinc-500">{label}</p>
          <p className="text-lg font-semibold leading-tight tabular-nums">
            {value}
            {unit ? <span className="ml-0.5 text-xs font-normal text-zinc-400">{unit}</span> : null}
          </p>
          <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800">
            <div
              className={cn("h-full rounded-full transition-all", pct > 85 ? "bg-rose-500" : pct > 65 ? "bg-amber-500" : "bg-emerald-500")}
              style={{ width: `${Math.min(100, Math.max(2, pct))}%` }}
            />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function StatChip({ icon: Icon, label, value, valueTone }: { icon: Icons.LucideIcon; label: string; value: string; valueTone?: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-200 bg-white/70 px-2.5 py-1.5 text-xs dark:border-zinc-800 dark:bg-zinc-900/70">
      <Icon className="h-3.5 w-3.5 text-zinc-400" />
      <span className="text-zinc-500 dark:text-zinc-400">{label}</span>
      <span className={cn("font-semibold tabular-nums text-zinc-800 dark:text-zinc-100", valueTone)}>{value}</span>
    </span>
  );
}

function vpnTone(status: string) {
  if (status === "up" || status === "active") return "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400";
  if (status === "down" || status === "error") return "border-rose-500/30 bg-rose-500/10 text-rose-600 dark:text-rose-400";
  return "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400";
}

export function DashboardView() {
  const summaryQuery = useQuery<Summary>({
    queryKey: ["dashboard", "summary"],
    queryFn: () => fetchApi<Summary>("/api/v1/dashboard/summary"),
    refetchInterval: 30_000,
  });

  const certsQuery = useQuery<CertLite[]>({
    queryKey: ["dashboard", "expiring-certs"],
    queryFn: () => fetchApi<CertLite[]>("/api/v1/pki/certificates/expiring?days=30"),
    refetchInterval: 300_000,
    retry: 1,
  });

  const [points, setPoints] = useState<Point[] | null>(null);
  const [wanOverride, setWanOverride] = useState<Record<string, string>>({});
  const [liveThreats, setLiveThreats] = useState<Summary["recentThreats"]>([]);
  const [conntrack, setConntrack] = useState<number | null>(null);
  const [lastTick, setLastTick] = useState<string | null>(null);

  useRealtime(["metrics", "alerts"], {
    onMetricsTick: (t) => {
      setConntrack(t.conntrackCount);
      setLastTick(t.ts);
      setPoints((prev) => {
        const sum = (dir: "rxKbps" | "txKbps") => t.ifaces.reduce((s, i) => s + (i[dir] ?? 0), 0);
        const next: Point = { ts: t.ts, label: timeLabel(t.ts), rx: sum("rxKbps"), tx: sum("txKbps") };
        const base = prev ?? [];
        return [...base.slice(-59), next];
      });
    },
    onWanStatus: (w) => setWanOverride((prev) => ({ ...prev, [w.iface]: w.state })),
    onAlertsNew: (a) => {
      if (a.type !== "threat") return;
      setLiveThreats((prev) =>
        [
          { id: a.id, ts: new Date().toISOString(), severity: a.severity, category: "threat", message: a.title, srcIp: "—", action: "alert" },
          ...prev,
        ].slice(0, 20),
      );
    },
  });

  const backfilled = useMemo(() => {
    if (!summaryQuery.data) return [];
    return tickToPoints(summaryQuery.data.throughputHistory ?? []);
  }, [summaryQuery.data]);

  const chartData = points ?? backfilled;

  if (summaryQuery.isLoading) {
    return (
      <div className="grid gap-4">
        <Skeleton className="h-28 rounded-xl" />
        <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-20 rounded-xl" />
          ))}
        </div>
        <div className="grid gap-4 lg:grid-cols-3">
          <Skeleton className="h-72 rounded-xl lg:col-span-2" />
          <Skeleton className="h-72 rounded-xl" />
        </div>
        <div className="grid gap-4 lg:grid-cols-2">
          <Skeleton className="h-64 rounded-xl" />
          <Skeleton className="h-64 rounded-xl" />
        </div>
      </div>
    );
  }

  const s = summaryQuery.data;
  if (!s) return <p className="text-sm text-rose-600">Failed to load dashboard summary.</p>;

  const wanRows = s.wanStatus.map((w) => ({ ...w, state: wanOverride[w.iface] ?? w.state }));
  const threats = [...liveThreats, ...(s.recentThreats ?? [])].slice(0, 12);
  const activeSessions = conntrack ?? s.sessions.conntrackCount;

  // ── verdict + KPI math ────────────────────────────────────────────────
  const sev = s.alerts24h.bySeverity ?? {};
  const critAlerts = sev.critical ?? 0;
  const highAlerts = sev.high ?? 0;
  const wanUp = wanRows.filter((w) => w.state === "up").length;
  const wanDown = wanRows.filter((w) => w.state === "down").length;
  const vpnUp = s.vpnStatus.filter((v) => v.status === "up" || v.status === "active").length;
  const h = s.health;
  const verdict: "critical" | "attention" | "ok" =
    critAlerts > 0 || wanDown > 0 || h.cpuPct > 90 || h.memPct > 90 || h.diskPct > 90 || h.tempC > 85
      ? "critical"
      : highAlerts > 0 || wanRows.some((w) => w.state === "degraded") || h.cpuPct > 75 || h.memPct > 75 || h.diskPct > 80 || h.tempC > 72
        ? "attention"
        : "ok";

  const VERDICTS = {
    ok: { label: "All systems operational", icon: Icons.ShieldCheck, dot: "bg-emerald-500", tone: "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400" },
    attention: { label: "Attention required", icon: Icons.AlertTriangle, dot: "bg-amber-500", tone: "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400" },
    critical: { label: "Critical events detected", icon: Icons.ShieldAlert, dot: "bg-rose-500", tone: "border-rose-500/30 bg-rose-500/10 text-rose-600 dark:text-rose-400" },
  } as const;
  const v = VERDICTS[verdict];

  const sevTotal = Object.values(sev).reduce((a, b) => a + (b ?? 0), 0) || 1;

  // ── throughput math ───────────────────────────────────────────────────
  const latest = chartData.length ? chartData[chartData.length - 1] : null;
  const curRx = latest?.rx ?? 0;
  const curTx = latest?.tx ?? 0;
  // each tick covers 2 s → kbps × 2 s × 1000 / 8 ≈ bytes
  const windowBytes = (dir: "rx" | "tx") => (chartData.reduce((acc, p) => acc + p[dir], 0) * 2 * 1000) / 8;

  // ── talkers bar scale ─────────────────────────────────────────────────
  const maxTalkerBytes = Math.max(...s.topTalkers.map((t) => t.bytes), 1);

  const certs = certsQuery.data ?? [];
  const expiringSoon = certs.filter((c) => (c.daysUntilExpiry ?? 999) <= 30);

  const quickActions = [
    { label: "Firewall Rules", hash: "#/firewall/rules", icon: Icons.ShieldCheck },
    { label: "IPS Events", hash: "#/ips/events", icon: Icons.Siren },
    { label: "VPN", hash: "#/vpn/configs", icon: Icons.Lock },
    { label: "Live Logs", hash: "#/logs/live", icon: Icons.Activity },
    { label: "Certificates", hash: "#/pki/certificates", icon: Icons.FileKey },
    { label: "Auto-Block", hash: "#/threat-intel/auto-block", icon: Icons.ShieldBan },
  ];

  return (
    <div className="grid gap-4">
      {/* ── status banner ─────────────────────────────────────────────── */}
      <Card className={cn("overflow-hidden", verdict === "critical" && "border-rose-500/30", verdict === "attention" && "border-amber-500/30", verdict === "ok" && "border-emerald-500/25")}>
        <CardContent className="flex flex-col gap-4 p-4 md:p-5">
          <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
            <div className="flex items-center gap-3">
              <span className={cn("relative flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border", v.tone)}>
                <v.icon className="h-5 w-5" />
                <span className={cn("absolute right-1 top-1 h-1.5 w-1.5 rounded-full", v.dot, verdict !== "ok" && "animate-pulse")} />
              </span>
              <div className="min-w-0">
                <p className="text-sm font-semibold">{v.label}</p>
                <p className="truncate text-xs text-zinc-500">
                  {wanUp}/{wanRows.length || 0} WAN links up · {vpnUp}/{s.vpnStatus.length} tunnels up · last tick {lastTick ? timeLabel(lastTick) : "—"}
                </p>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <StatChip icon={Icons.Network} label="Sessions" value={activeSessions.toLocaleString()} />
              <StatChip
                icon={Icons.Siren}
                label="Alerts 24 h"
                value={String(s.alerts24h.total)}
                valueTone={critAlerts > 0 ? "text-rose-600 dark:text-rose-400" : undefined}
              />
              <StatChip icon={Icons.Globe} label="WAN" value={`${wanUp}/${wanRows.length || 0}`} />
              <StatChip icon={Icons.Lock} label="VPN" value={`${vpnUp}/${s.vpnStatus.length}`} />
              <StatChip icon={Icons.Clock} label="Uptime" value={fmtUptime(h.uptimeSec)} />
            </div>
          </div>

          {/* 24 h severity bar + legend */}
          <div className="space-y-1.5">
            <div className="flex h-1.5 w-full overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800">
              {SEV_ORDER.map((k) =>
                (sev[k] ?? 0) > 0 ? <div key={k} className={cn("h-full", SEV_BAR[k])} style={{ width: `${((sev[k] ?? 0) / sevTotal) * 100}%` }} /> : null,
              )}
            </div>
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-zinc-500">
              <span className="text-zinc-400">last 24 h by severity:</span>
              {SEV_ORDER.map((k) =>
                (sev[k] ?? 0) > 0 ? (
                  <span key={k} className="flex items-center gap-1">
                    <span className={cn("h-1.5 w-1.5 rounded-full", SEV_BAR[k])} /> {sev[k]} {k}
                  </span>
                ) : null,
              )}
              {sevTotal === 1 && s.alerts24h.total === 0 && <span>no alerts recorded</span>}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* ── health gauges ─────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <GaugeCard label="CPU" value={String(h.cpuPct)} unit="%" pct={h.cpuPct} icon={<Icons.Cpu className="h-5 w-5" />} tone="bg-zinc-500/10 text-zinc-600 dark:text-zinc-400" />
        <GaugeCard label="Memory" value={String(h.memPct)} unit="%" pct={h.memPct} icon={<Icons.MemoryStick className="h-5 w-5" />} tone="bg-zinc-500/10 text-zinc-600 dark:text-zinc-400" />
        <GaugeCard label="Disk" value={String(h.diskPct)} unit="%" pct={h.diskPct} icon={<Icons.HardDrive className="h-5 w-5" />} tone="bg-zinc-500/10 text-zinc-600 dark:text-zinc-400" />
        <GaugeCard label="Temperature" value={String(h.tempC)} unit="°C" pct={h.tempC} icon={<Icons.Thermometer className="h-5 w-5" />} tone="bg-zinc-500/10 text-zinc-600 dark:text-zinc-400" />
      </div>

      {/* ── throughput + sessions/WAN ─────────────────────────────────── */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader className="flex-row items-center justify-between space-y-0 p-4 md:p-6">
            <CardTitle className="text-sm font-medium">Throughput (live)</CardTitle>
            <div className="flex items-center gap-3 text-xs">
              <span className="flex items-center gap-1.5 tabular-nums font-semibold text-zinc-700 dark:text-zinc-500">↓ {fmtSpeed(curRx)}</span>
              <span className="flex items-center gap-1.5 tabular-nums font-semibold text-zinc-500 dark:text-zinc-400">↑ {fmtSpeed(curTx)}</span>
            </div>
          </CardHeader>
          <CardContent className="p-4 pt-0 md:p-6 md:pt-0">
            <ThroughputAreaChart data={chartData.length ? chartData : backfilled} />
            <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-[11px] text-zinc-400">
              <p>2 s ticks via realtime stream · backfilled {backfilled.length} ticks on load</p>
              <p className="tabular-nums">
                window ≈ {fmtBytes(windowBytes("rx"))} ↓ · {fmtBytes(windowBytes("tx"))} ↑
              </p>
            </div>
          </CardContent>
        </Card>

        <div className="grid gap-4">
          <Card>
            <CardContent className="p-4 md:p-6">
              <p className="text-xs text-zinc-500">Active sessions</p>
              <p className="mt-1 text-3xl font-semibold tabular-nums">{activeSessions.toLocaleString()}</p>
              <p className="mt-1 text-[11px] text-zinc-400">conntrack · live counter</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex-row items-center justify-between space-y-0 p-4 pb-2 md:p-6 md:pb-2">
              <CardTitle className="text-sm font-medium">WAN status</CardTitle>
              <Badge
                variant="outline"
                className={cn(
                  "border",
                  wanDown > 0 && "border-rose-500/30 bg-rose-500/10 text-rose-600 dark:text-rose-400",
                  wanDown === 0 && wanRows.some((w) => w.state === "degraded") && "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400",
                  wanRows.length > 0 && wanDown === 0 && !wanRows.some((w) => w.state === "degraded") && "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
                )}
              >
                {wanUp}/{wanRows.length || 0} up
              </Badge>
            </CardHeader>
            <CardContent className="space-y-2 p-4 pt-0 md:p-6 md:pt-0">
              {wanRows.length === 0 ? (
                <p className="text-sm text-zinc-400">No WAN policies configured.</p>
              ) : (
                wanRows.map((w) => (
                  <div key={w.iface} className="flex items-center justify-between rounded-lg border border-zinc-200 px-3 py-2 dark:border-zinc-800">
                    <span className="font-mono text-sm">{w.iface}</span>
                    <span className="flex items-center gap-2 tabular-nums text-xs text-zinc-500">
                      ↓{Math.round(w.rxKbps / 1000)}M ↑{Math.round(w.txKbps / 1000)}M
                      <Badge
                        variant="outline"
                        className={cn(
                          "border",
                          w.state === "up" && "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
                          w.state === "degraded" && "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400",
                          w.state === "down" && "border-rose-500/30 bg-rose-500/10 text-rose-600 dark:text-rose-400",
                        )}
                      >
                        {w.state}
                      </Badge>
                    </span>
                  </div>
                ))
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* ── threats + apps ────────────────────────────────────────────── */}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="flex-row items-center justify-between space-y-0 p-4 md:p-6">
            <CardTitle className="text-sm font-medium">Threat feed (24 h)</CardTitle>
            <div className="flex items-center gap-2">
              {critAlerts > 0 && (
                <Badge variant="outline" className={cn("border", SEV_STYLES.critical)}>
                  {critAlerts} critical
                </Badge>
              )}
              {highAlerts > 0 && (
                <Badge variant="outline" className={cn("border", SEV_STYLES.high)}>
                  {highAlerts} high
                </Badge>
              )}
              {s.alerts24h.total === 0 ? (
                <Badge variant="outline" className="border-zinc-500/20 bg-zinc-500/10 text-zinc-500 dark:text-zinc-400">0 alerts</Badge>
              ) : (
                <Badge variant="outline" className="border-rose-500/30 bg-rose-500/10 text-rose-600 dark:text-rose-400">{s.alerts24h.total} alerts</Badge>
              )}
            </div>
          </CardHeader>
          <CardContent className="max-h-72 space-y-2 overflow-y-auto p-4 pt-0 md:p-6 md:pt-0">
            {threats.length === 0 ? (
              <p className="text-sm text-zinc-400">No high/critical events in the last 24 h.</p>
            ) : (
              threats.map((t, i) => (
                <div key={`${t.id ?? "live"}-${i}`} className="flex items-start gap-2 rounded-lg border border-zinc-200 p-2.5 dark:border-zinc-800">
                  <Badge variant="outline" className={cn("shrink-0 border capitalize", SEV_STYLES[t.severity] ?? SEV_STYLES.info)}>
                    {t.severity}
                  </Badge>
                  <div className="min-w-0">
                    <p className="truncate text-sm">{t.message}</p>
                    <p className="text-[11px] text-zinc-400">
                      {t.category} · {t.srcIp} · {timeLabel(t.ts)} · {t.action}
                    </p>
                  </div>
                </div>
              ))
            )}
          </CardContent>
        </Card>

        <div className="grid gap-4">
          <Card>
            <CardHeader className="p-4 pb-2 md:p-6 md:pb-2">
              <CardTitle className="text-sm font-medium">Top applications (24 h)</CardTitle>
            </CardHeader>
            <CardContent className="p-4 pt-0 md:p-6 md:pt-0">
              {s.topApps.length ? <AppsDonut data={s.topApps.slice(0, 6)} /> : <p className="text-sm text-zinc-400">No app data yet.</p>}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* ── talkers + VPN tunnels ─────────────────────────────────────── */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader className="p-4 pb-2 md:p-6 md:pb-2">
            <CardTitle className="text-sm font-medium">Top talkers (24 h)</CardTitle>
          </CardHeader>
          <CardContent className="p-4 pt-0 md:p-6 md:pt-0">
            {s.topTalkers.length === 0 ? (
              <p className="text-sm text-zinc-400">No traffic recorded yet.</p>
            ) : (
              <div className="max-h-64 space-y-3 overflow-y-auto pr-1">
                {s.topTalkers.map((t) => (
                  <div key={t.ip}>
                    <div className="flex items-baseline justify-between gap-2 text-xs">
                      <span className="truncate">
                        <span className="font-mono">{t.ip}</span>
                        {t.userName ? <span className="ml-2 text-zinc-500">{t.userName}</span> : null}
                      </span>
                      <span className="shrink-0 tabular-nums text-zinc-600 dark:text-zinc-300">{fmtBytes(t.bytes)}</span>
                    </div>
                    <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800">
                      <div
                        className="h-full rounded-full bg-zinc-400 transition-all dark:bg-zinc-500"
                        style={{ width: `${Math.max(2, (t.bytes / maxTalkerBytes) * 100)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex-row items-center justify-between space-y-0 p-4 pb-2 md:p-6 md:pb-2">
            <CardTitle className="text-sm font-medium">VPN tunnels</CardTitle>
            <Badge
              variant="outline"
              className={cn(
                "border",
                s.vpnStatus.length === 0
                  ? "border-zinc-500/20 bg-zinc-500/10 text-zinc-500"
                  : vpnUp === s.vpnStatus.length
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                    : "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400",
              )}
            >
              {vpnUp}/{s.vpnStatus.length} up
            </Badge>
          </CardHeader>
          <CardContent className="max-h-52 space-y-2 overflow-y-auto p-4 pt-0 md:p-6 md:pt-0">
            {s.vpnStatus.length === 0 ? (
              <p className="text-sm text-zinc-400">No VPN tunnels configured.</p>
            ) : (
              s.vpnStatus.map((tunnel) => (
                <div key={tunnel.id} className="flex items-center justify-between gap-2 rounded-lg border border-zinc-200 px-3 py-2 dark:border-zinc-800">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium">{tunnel.name}</p>
                    <p className="text-[11px] uppercase text-zinc-400">
                      {tunnel.type} · {tunnel.activeSessions} session{tunnel.activeSessions === 1 ? "" : "s"}
                    </p>
                  </div>
                  <Badge variant="outline" className={cn("shrink-0 border", vpnTone(tunnel.status))}>
                    {tunnel.status}
                  </Badge>
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>

      {/* ── attention / actions / system ──────────────────────────────── */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader className="flex-row items-center justify-between space-y-0 p-4 pb-2 md:p-6 md:pb-2">
            <CardTitle className="text-sm font-medium">Needs attention</CardTitle>
            <Badge
              variant="outline"
              className={cn(
                "border",
                certsQuery.isError && "border-zinc-500/20 bg-zinc-500/10 text-zinc-500",
                !certsQuery.isError && expiringSoon.length === 0 && "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
                !certsQuery.isError && expiringSoon.length > 0 && "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400",
              )}
            >
              {certsQuery.isError ? "—" : `${expiringSoon.length} item${expiringSoon.length === 1 ? "" : "s"}`}
            </Badge>
          </CardHeader>
          <CardContent className="p-4 pt-0 md:p-6 md:pt-0">
            {certsQuery.isError ? (
              <p className="text-sm text-zinc-400">Certificate expiry feed unavailable.</p>
            ) : certsQuery.isLoading ? (
              <div className="space-y-2">
                <Skeleton className="h-10 rounded-lg" />
                <Skeleton className="h-10 rounded-lg" />
              </div>
            ) : expiringSoon.length === 0 ? (
              <p className="text-sm text-zinc-400">No certificates expiring within 30 days.</p>
            ) : (
              <div className="space-y-2">
                {expiringSoon.slice(0, 5).map((c) => {
                  const d = c.daysUntilExpiry ?? 0;
                  const expired = d < 0;
                  return (
                    <div key={c.commonName} className="flex items-center justify-between gap-2 rounded-lg border border-zinc-200 px-3 py-2 dark:border-zinc-800">
                      <div className="min-w-0">
                        <p className="truncate font-mono text-xs font-medium">{c.commonName}</p>
                        <p className="text-[11px] text-zinc-400">{c.notAfter ? new Date(c.notAfter).toLocaleDateString() : "no expiry"}</p>
                      </div>
                      <Badge
                        variant="outline"
                        className={cn(
                          "shrink-0 border",
                          expired
                            ? "border-rose-500/30 bg-rose-500/10 text-rose-600 dark:text-rose-400"
                            : d <= 7
                              ? "border-rose-500/30 bg-rose-500/10 text-rose-600 dark:text-rose-400"
                              : "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400",
                        )}
                      >
                        {expired ? "expired" : d === 0 ? "expires today" : `in ${d} d`}
                      </Badge>
                    </div>
                  );
                })}
                <Button asChild variant="ghost" size="sm" className="h-8 w-full justify-center text-xs text-zinc-700 hover:text-zinc-800 dark:text-zinc-500 dark:hover:text-zinc-400">
                  <a href="#/pki/certificates">View all certificates →</a>
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="p-4 pb-2 md:p-6 md:pb-2">
            <CardTitle className="text-sm font-medium">Quick actions</CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-2 gap-2 p-4 pt-0 md:p-6 md:pt-0">
            {quickActions.map((a) => (
              <Button key={a.hash} asChild variant="outline" className="h-auto justify-start gap-2 py-2.5">
                <a href={a.hash}>
                  <a.icon className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
                  <span className="text-xs">{a.label}</span>
                </a>
              </Button>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardContent className="flex h-full flex-col gap-3 p-4 md:p-6">
            <div>
              <p className="text-xs text-zinc-500">Appliance uptime</p>
              <p className="mt-1 flex items-center gap-2 text-lg font-semibold tabular-nums">
                <Icons.Clock className="h-4 w-4 text-zinc-400" /> {fmtUptime(h.uptimeSec)}
              </p>
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="rounded-lg border border-zinc-200 p-2.5 dark:border-zinc-800">
                <p className="text-zinc-400">Local time</p>
                <p className="mt-0.5 font-semibold tabular-nums">{lastTick ? timeLabel(lastTick) : "—"}</p>
              </div>
              <div className="rounded-lg border border-zinc-200 p-2.5 dark:border-zinc-800">
                <p className="text-zinc-400">Telemetry</p>
                <p className="mt-0.5 font-semibold">2 s realtime ticks</p>
              </div>
              <div className="rounded-lg border border-zinc-200 p-2.5 dark:border-zinc-800">
                <p className="text-zinc-400">Alert sources</p>
                <p className="mt-0.5 font-semibold">IPS + engine</p>
              </div>
              <div className="rounded-lg border border-zinc-200 p-2.5 dark:border-zinc-800">
                <p className="text-zinc-400">Session count</p>
                <p className="mt-0.5 font-semibold tabular-nums">conntrack</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
