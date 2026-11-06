"use client";

/**
 * Chart wrappers — ADR-019 (supersedes ADR-013 palette): all charts go through
 * components/charts/ using the LOCKED enterprise palette (blue, sky, amber, rose,
 * orange, violet, slate). Owner-directed white & blue theme, 2026-11-06.
 */

import {
  Area,
  AreaChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

export const PALETTE = {
  blue: "#2563eb",
  sky: "#0ea5e9",
  amber: "#f59e0b",
  rose: "#f43f5e",
  orange: "#f97316",
  violet: "#8b5cf6",
  slate: "#64748b",
} as const;

const fmtKbps = (v: number) => (v >= 1000 ? `${(v / 1000).toFixed(1)}M` : `${Math.round(v)}K`);

export function ThroughputAreaChart({
  data,
  height = 240,
}: {
  data: Array<{ ts: string; label: string; rx: number; tx: number }>;
  height?: number;
}) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
        <defs>
          <linearGradient id="gradRx" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={PALETTE.blue} stopOpacity={0.35} />
            <stop offset="100%" stopColor={PALETTE.blue} stopOpacity={0.02} />
          </linearGradient>
          <linearGradient id="gradTx" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={PALETTE.sky} stopOpacity={0.3} />
            <stop offset="100%" stopColor={PALETTE.sky} stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <XAxis dataKey="label" tick={{ fontSize: 10 }} stroke={PALETTE.slate} tickLine={false} axisLine={false} minTickGap={48} />
        <YAxis tickFormatter={fmtKbps} tick={{ fontSize: 10 }} stroke={PALETTE.slate} tickLine={false} axisLine={false} width={52} />
        <Tooltip
          formatter={(value: number, name) => [`${fmtKbps(value)} kbps`, name === "rx" ? "Download" : "Upload"]}
          labelFormatter={(l) => `at ${l}`}
          contentStyle={{ borderRadius: 8, fontSize: 12 }}
        />
        <Area type="monotone" dataKey="rx" stroke={PALETTE.blue} strokeWidth={2} fill="url(#gradRx)" isAnimationActive={false} />
        <Area type="monotone" dataKey="tx" stroke={PALETTE.sky} strokeWidth={2} fill="url(#gradTx)" isAnimationActive={false} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

const DONUT_COLORS = [PALETTE.blue, PALETTE.sky, PALETTE.amber, PALETTE.rose, PALETTE.orange, PALETTE.violet, PALETTE.slate];

export function AppsDonut({ data, height = 220 }: { data: Array<{ app: string; bytes: number }>; height?: number }) {
  const total = data.reduce((s, d) => s + d.bytes, 0) || 1;
  const fmt = (v: number) => (v >= 1e9 ? `${(v / 1e9).toFixed(1)} GB` : v >= 1e6 ? `${(v / 1e6).toFixed(0)} MB` : `${(v / 1e3).toFixed(0)} KB`);
  return (
    <div className="flex flex-col items-center gap-2">
      <ResponsiveContainer width="100%" height={height}>
        <PieChart>
          <Pie data={data} dataKey="bytes" nameKey="app" innerRadius="62%" outerRadius="88%" paddingAngle={2} strokeWidth={0}>
            {data.map((_, i) => (
              <Cell key={i} fill={DONUT_COLORS[i % DONUT_COLORS.length]} />
            ))}
          </Pie>
          <Tooltip formatter={(value: number, name) => [fmt(value), String(name)]} contentStyle={{ borderRadius: 8, fontSize: 12 }} />
        </PieChart>
      </ResponsiveContainer>
      <ul className="grid w-full grid-cols-2 gap-x-4 gap-y-1 text-xs">
        {data.slice(0, 6).map((d, i) => (
          <li key={d.app} className="flex items-center gap-1.5">
            <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: DONUT_COLORS[i % DONUT_COLORS.length] }} />
            <span className="truncate text-zinc-600 dark:text-zinc-300">{d.app}</span>
            <span className="ml-auto shrink-0 tabular-nums text-zinc-400">{fmt(d.bytes)}</span>
          </li>
        ))}
      </ul>
      <p className="text-[11px] text-zinc-400">total 24 h: {fmt(total)}</p>
    </div>
  );
}
