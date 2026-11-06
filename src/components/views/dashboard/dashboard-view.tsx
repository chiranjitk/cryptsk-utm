"use client";

/**
 * #/dashboard — M01-DASHBOARD.md. 30-second answer to "is the network healthy,
 * what is happening right now, what needs attention?". Live via metrics:tick +
 * wan:status + alerts:new; backfill from GET /api/v1/dashboard/summary.
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

type Point = { ts: string; label: string; rx: number; tx: number };

const timeLabel = (ts: string) => new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const fmtBytes = (v: number) => (v >= 1e9 ? `${(v / 1e9).toFixed(1)} GB` : v >= 1e6 ? `${(v / 1e6).toFixed(0)} MB` : `${(v / 1e3).toFixed(0)} KB`);
const fmtUptime = (s: number) => `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h ${Math.floor((s % 3600) / 60)}m`;

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
              className={cn("h-full rounded-full transition-all", pct > 85 ? "bg-rose-500" : pct > 65 ? "bg-amber-500" : "bg-blue-500")}
              style={{ width: `${Math.min(100, Math.max(2, pct))}%` }}
            />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export function DashboardView() {
  const summaryQuery = useQuery<Summary>({
    queryKey: ["dashboard", "summary"],
    queryFn: () => fetchApi<Summary>("/api/v1/dashboard/summary"),
    refetchInterval: 30_000,
  });

  const [points, setPoints] = useState<Point[] | null>(null);
  const [wanOverride, setWanOverride] = useState<Record<string, string>>({});
  const [liveThreats, setLiveThreats] = useState<Summary["recentThreats"]>([]);
  const [conntrack, setConntrack] = useState<number | null>(null);

  useRealtime(["metrics", "alerts"], {
    onMetricsTick: (t) => {
      setConntrack(t.conntrackCount);
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
        <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-20 rounded-xl" />
          ))}
        </div>
        <Skeleton className="h-72 rounded-xl" />
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

  const quickActions = [
    { label: "Firewall Rules", hash: "#/firewall/rules", icon: Icons.ShieldCheck },
    { label: "IPS Events", hash: "#/ips/events", icon: Icons.Siren },
    { label: "VPN", hash: "#/vpn/configs", icon: Icons.Lock },
    { label: "Live Logs", hash: "#/logs/live", icon: Icons.Activity },
  ];

  return (
    <div className="grid gap-4">
      {/* health row */}
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <GaugeCard label="CPU" value={String(s.health.cpuPct)} unit="%" pct={s.health.cpuPct} icon={<Icons.Cpu className="h-5 w-5" />} tone="bg-blue-500/10 text-blue-600 dark:text-blue-400" />
        <GaugeCard label="Memory" value={String(s.health.memPct)} unit="%" pct={s.health.memPct} icon={<Icons.MemoryStick className="h-5 w-5" />} tone="bg-sky-500/10 text-sky-600 dark:text-sky-400" />
        <GaugeCard label="Disk" value={String(s.health.diskPct)} unit="%" pct={s.health.diskPct} icon={<Icons.HardDrive className="h-5 w-5" />} tone="bg-violet-500/10 text-violet-600 dark:text-violet-400" />
        <GaugeCard label="Temperature" value={String(s.health.tempC)} unit="°C" pct={s.health.tempC} icon={<Icons.Thermometer className="h-5 w-5" />} tone="bg-amber-500/10 text-amber-600 dark:text-amber-400" />
      </div>

      {/* throughput + sessions */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader className="flex-row items-center justify-between space-y-0 p-4 md:p-6">
            <CardTitle className="text-sm font-medium">Throughput (live)</CardTitle>
            <div className="flex items-center gap-3 text-xs text-zinc-500">
              <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-blue-500" /> download</span>
              <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-sky-500" /> upload</span>
            </div>
          </CardHeader>
          <CardContent className="p-4 pt-0 md:p-6 md:pt-0">
            <ThroughputAreaChart data={chartData.length ? chartData : backfilled} />
            <p className="mt-2 text-[11px] text-zinc-400">
              2 s ticks via realtime stream · backfilled {backfilled.length} ticks on load
            </p>
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
            <CardHeader className="p-4 pb-2 md:p-6 md:pb-2">
              <CardTitle className="text-sm font-medium">WAN status</CardTitle>
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

      {/* threats + apps */}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="flex-row items-center justify-between space-y-0 p-4 md:p-6">
            <CardTitle className="text-sm font-medium">Threat feed (24 h)</CardTitle>
            <Badge variant="outline" className="border-rose-500/30 bg-rose-500/10 text-rose-600 dark:text-rose-400">
              {s.alerts24h.total} alerts
            </Badge>
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

      {/* talkers + quick actions */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader className="p-4 pb-2 md:p-6 md:pb-2">
            <CardTitle className="text-sm font-medium">Top talkers (24 h)</CardTitle>
          </CardHeader>
          <CardContent className="p-4 pt-0 md:p-6 md:pt-0">
            <div className="max-h-64 overflow-y-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-zinc-200 text-left text-xs text-zinc-500 dark:border-zinc-800">
                    <th className="py-2 font-medium">Host</th>
                    <th className="py-2 font-medium">User</th>
                    <th className="py-2 text-right font-medium">Traffic</th>
                  </tr>
                </thead>
                <tbody>
                  {s.topTalkers.map((t) => (
                    <tr key={t.ip} className="border-b border-zinc-100 last:border-0 dark:border-zinc-800/60">
                      <td className="py-2 font-mono text-xs">{t.ip}</td>
                      <td className="py-2 text-xs text-zinc-500">{t.userName ?? "—"}</td>
                      <td className="py-2 text-right tabular-nums">{fmtBytes(t.bytes)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>

        <div className="grid content-start gap-4">
          <Card>
            <CardHeader className="p-4 pb-2 md:p-6 md:pb-2">
              <CardTitle className="text-sm font-medium">Quick actions</CardTitle>
            </CardHeader>
            <CardContent className="grid grid-cols-2 gap-2 p-4 pt-0 md:p-6 md:pt-0">
              {quickActions.map((a) => (
                <Button key={a.hash} asChild variant="outline" className="h-auto justify-start gap-2 py-2.5">
                  <a href={a.hash}>
                    <a.icon className="h-4 w-4 text-blue-600 dark:text-blue-400" />
                    <span className="text-xs">{a.label}</span>
                  </a>
                </Button>
              ))}
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4 md:p-6">
              <p className="text-xs text-zinc-500">Appliance uptime</p>
              <p className="mt-1 flex items-center gap-2 text-lg font-semibold tabular-nums">
                <Icons.Clock className="h-4 w-4 text-zinc-400" /> {fmtUptime(s.health.uptimeSec)}
              </p>
              <p className="mt-2 text-[11px] text-zinc-400">VPN tunnels up: {s.vpnStatus.filter((v) => v.status === "up").length}/{s.vpnStatus.length}</p>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
