"use client";

/**
 * Shared UI atoms for the M02 network views — composed only from
 * src/components/ui primitives. Blue theme per UI_DESIGN_SYSTEM §2 (ADR-019):
 * emerald is reserved for TRUE health semantics only (WAN up, link up, BFD up);
 * amber = degraded/warn, rose = down/critical, zinc = neutral/unknown.
 * Role chips are configuration labels, never health — so no emerald there.
 */

import { useRef, useState, useSyncExternalStore } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import * as Icons from "lucide-react";
import { cn } from "@/lib/utils";
import { toastErr, toastOk } from "@/components/views/firewall/fw-ui";
import {
  cfgBool,
  cfgNumber,
  cfgString,
  cfgStringArray,
  type Iface,
  type IfaceMode,
  type IfaceRole,
  type IfaceType,
  type MirrorDirection,
  type WanState,
} from "./net-api";

// ── interface type badge (zinc outline + glyph — type is neutral metadata) ──

const TYPE_ICON: Record<IfaceType, React.ComponentType<{ className?: string }>> = {
  physical: Icons.Cable,
  vlan: Icons.Layers,
  bridge: Icons.Network,
  bond: Icons.Link2,
  loopback: Icons.RotateCw,
  gre: Icons.Waypoints,
  ipip: Icons.ArrowRightLeft,
};

export function TypeBadge({ type, className }: { type: IfaceType; className?: string }) {
  const Icon = TYPE_ICON[type] ?? Icons.Cable;
  return (
    <Badge
      variant="outline"
      className={cn(
        "gap-1 border-zinc-300 bg-transparent font-normal text-zinc-600 dark:border-zinc-700 dark:text-zinc-300",
        className,
      )}
    >
      <Icon className="h-3 w-3" />
      {type}
    </Badge>
  );
}

// ── role badge (config label — blue for WAN, zinc otherwise, amber DMZ) ─────

const ROLE_CLS: Record<IfaceRole, string> = {
  wan: "border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300",
  lan: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
  dmz: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  vpn: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
  mgmt: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
  unused: "border-zinc-300 bg-transparent text-zinc-400 dark:border-zinc-700 dark:text-zinc-500",
};

export function RoleBadge({ role, className }: { role: IfaceRole; className?: string }) {
  return (
    <Badge variant="outline" className={cn("text-[10px] font-semibold uppercase tracking-wide", ROLE_CLS[role], className)}>
      {role}
    </Badge>
  );
}

// ── WAN state badge (health semantics — emerald allowed for `up`) ───────────

const WAN_STATE_BADGE: Record<WanState, { cls: string; icon: React.ComponentType<{ className?: string }>; label: string }> = {
  up: {
    cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
    icon: Icons.CircleCheck,
    label: "up",
  },
  degraded: {
    cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
    icon: Icons.CircleAlert,
    label: "degraded",
  },
  down: {
    cls: "border-transparent bg-rose-600 text-white",
    icon: Icons.CircleX,
    label: "down",
  },
  unknown: {
    cls: "border-zinc-300 bg-transparent text-zinc-500 dark:border-zinc-700 dark:text-zinc-400",
    icon: Icons.CircleDashed,
    label: "unknown",
  },
};

export function StateBadge({ state, className }: { state: WanState; className?: string }) {
  const def = WAN_STATE_BADGE[state] ?? WAN_STATE_BADGE.unknown;
  const Icon = def.icon;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium", def.cls, className)}>
      <Icon className="h-3 w-3" />
      {def.label}
    </Badge>
  );
}

// ── link dot (up = emerald, degraded = amber, down = rose, neutral = zinc) ──

export function LinkDot({
  up,
  degraded = false,
  neutral = false,
  className,
}: {
  up: boolean;
  degraded?: boolean;
  /** operator-disabled / unknown — zinc, not an incident */
  neutral?: boolean;
  className?: string;
}) {
  const cls = neutral
    ? "bg-zinc-300 dark:bg-zinc-700"
    : degraded
      ? "bg-amber-500"
      : up
        ? "bg-emerald-500"
        : "bg-rose-500";
  return <span aria-hidden="true" className={cn("inline-block h-2 w-2 shrink-0 rounded-full", cls, className)} />;
}

// ── generic zinc chips ──────────────────────────────────────────────────────

export function DirectionChip({ direction, className }: { direction: MirrorDirection; className?: string }) {
  return (
    <Badge
      variant="outline"
      className={cn(
        "border-zinc-300 bg-zinc-100 text-[10px] font-semibold uppercase text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
        className,
      )}
    >
      {direction}
    </Badge>
  );
}

export function ModeChip({ mode, className }: { mode: IfaceMode; className?: string }) {
  return (
    <Badge
      variant="outline"
      className={cn(
        "border-zinc-300 bg-zinc-100 text-[10px] font-semibold uppercase text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
        className,
      )}
    >
      {mode}
    </Badge>
  );
}

// ── BFD chip (REAL ping-based next-hop reachability, 30 s cache) ─────────────

export function BfdChip({ state, className }: { state: "up" | "down" | "unknown" | null; className?: string }) {
  if (state === "up") {
    return (
      <Badge
        variant="outline"
        className={cn("gap-1 border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400", className)}
      >
        <Icons.CircleCheck className="h-3 w-3" />
        Next-hop up
      </Badge>
    );
  }
  if (state === "down") {
    return (
      <Badge variant="outline" className={cn("gap-1 border-rose-600/60 bg-transparent text-rose-500", className)}>
        <Icons.CircleX className="h-3 w-3" />
        Next-hop down
      </Badge>
    );
  }
  if (state === "unknown") {
    return (
      <Badge
        variant="outline"
        className={cn("gap-1 border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400", className)}
      >
        <Icons.CircleDashed className="h-3 w-3" />
        Next-hop ?
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className={cn("border-zinc-300 bg-transparent text-zinc-500 dark:border-zinc-700 dark:text-zinc-400", className)}>
      Probe off
    </Badge>
  );
}

// ── kernel-sync badges (routing — vendor Status column parity) ───────────────

export function RouteOsBadge({ state }: { state: "in-kernel" | "drifted" | "missing" | "disabled" | null | undefined }) {
  if (state === null || state === undefined) {
    return <Badge variant="outline" className="border-zinc-300 bg-transparent text-zinc-400 dark:border-zinc-700">kernel n/a</Badge>;
  }
  if (state === "in-kernel") {
    return (
      <Badge variant="outline" className="gap-1 border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
        <Icons.CircleCheck className="h-3 w-3" />
        in kernel
      </Badge>
    );
  }
  if (state === "drifted") {
    return (
      <Badge variant="outline" className="gap-1 border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400">
        <Icons.AlertTriangle className="h-3 w-3" />
        drifted
      </Badge>
    );
  }
  if (state === "missing") {
    return (
      <Badge variant="outline" className="gap-1 border-rose-600/50 bg-transparent text-rose-500">
        <Icons.CircleX className="h-3 w-3" />
        not installed
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="border-zinc-300 bg-transparent text-zinc-500 dark:border-zinc-700 dark:text-zinc-400">
      off
    </Badge>
  );
}

export function PbrKernelBadge({ state }: { state: "in-kernel" | "missing" | "config-only" | "disabled" | null | undefined }) {
  if (state === null || state === undefined) {
    return <Badge variant="outline" className="border-zinc-300 bg-transparent text-zinc-400 dark:border-zinc-700">kernel n/a</Badge>;
  }
  if (state === "in-kernel") {
    return (
      <Badge variant="outline" className="gap-1 border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
        <Icons.CircleCheck className="h-3 w-3" />
        in kernel
      </Badge>
    );
  }
  if (state === "config-only") {
    return (
      <Badge variant="outline" className="gap-1 border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400">
        <Icons.Info className="h-3 w-3" />
        config-only
      </Badge>
    );
  }
  if (state === "missing") {
    return (
      <Badge variant="outline" className="gap-1 border-rose-600/50 bg-transparent text-rose-500">
        <Icons.CircleX className="h-3 w-3" />
        not installed
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="border-zinc-300 bg-transparent text-zinc-500 dark:border-zinc-700 dark:text-zinc-400">
      off
    </Badge>
  );
}

// ── sparkline (inline SVG — no chart lib; rx blue / tx sky) ─────────────────

export function Sparkline({
  points,
  className,
}: {
  points: Array<{ rxKbps: number; txKbps: number }>;
  className?: string;
}) {
  const W = 90;
  const H = 24;
  const max = Math.max(1, ...points.map((p) => Math.max(p.rxKbps, p.txKbps)));
  const step = points.length > 1 ? W / (points.length - 1) : W;
  const toPoints = (pick: (p: { rxKbps: number; txKbps: number }) => number) =>
    points
      .map((p, i) => `${(i * step).toFixed(1)},${(H - 2 - (pick(p) / max) * (H - 4)).toFixed(1)}`)
      .join(" ");

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      preserveAspectRatio="none"
      aria-hidden="true"
      className={cn("h-6 w-[90px] shrink-0", className)}
    >
      {points.length === 0 ? (
        <line x1={0} y1={H - 2} x2={W} y2={H - 2} strokeWidth={1.5} vectorEffect="non-scaling-stroke" className="stroke-zinc-300 dark:stroke-zinc-700" />
      ) : (
        <>
          <polyline points={toPoints((p) => p.rxKbps)} fill="none" strokeWidth={1.5} vectorEffect="non-scaling-stroke" className="stroke-zinc-700 dark:stroke-zinc-500" />
          <polyline points={toPoints((p) => p.txKbps)} fill="none" strokeWidth={1.5} vectorEffect="non-scaling-stroke" className="stroke-zinc-500 dark:stroke-zinc-400" />
        </>
      )}
    </svg>
  );
}

// ── per-type config summary (address / structural details) ──────────────────

const L3_TYPES: IfaceType[] = ["physical", "loopback", "gre", "ipip"];

function secondaryCount(c: Record<string, unknown>): number {
  const v = c["secondaryIps"];
  return Array.isArray(v) ? v.length : 0;
}

export function IfaceConfigSummary({ iface, className }: { iface: Iface; className?: string }) {
  const c = iface.config ?? {};
  let text: string;

  if (iface.mode === "l2" && L3_TYPES.includes(iface.type)) {
    // L2 = switching only: the addressing summary is hidden (M02 §4)
    text = "—";
  } else {
    switch (iface.type) {
      case "physical": {
        const wanType = cfgString(c, "wanType") ?? "static";
        if (wanType === "dhcp") text = "DHCP";
        else if (wanType === "pppoe") text = "PPPoE";
        else {
          const ip = cfgString(c, "ip");
          const prefix = cfgNumber(c, "cidrPrefix");
          text = ip ? `${ip}${prefix != null ? `/${prefix}` : ""}` : "static";
        }
        const gw = cfgString(c, "gateway");
        if (gw) text += ` · gw ${gw}`;
        break;
      }
      case "vlan": {
        const parent = iface.parentName ?? cfgString(c, "parent") ?? "—";
        text = `VLAN ${iface.vlanId ?? "—"} on ${parent}`;
        const ip = cfgString(c, "ip");
        const prefix = cfgNumber(c, "cidrPrefix");
        if (ip) text += ` · ${ip}${prefix != null ? `/${prefix}` : ""}`;
        const gw = cfgString(c, "gateway");
        if (gw) text += ` · gw ${gw}`;
        break;
      }
      case "bridge": {
        const members = cfgStringArray(c, "members");
        text = `bridge · ${members.length > 0 ? members.join(",") : "no members"}`;
        if (cfgBool(c, "stp")) text += ` · ${cfgString(c, "stpMode") ?? "stp"}`;
        if (cfgBool(c, "igmpSnooping")) text += " · igmp";
        const ip = cfgString(c, "ip");
        const prefix = cfgNumber(c, "cidrPrefix");
        if (ip) text += ` · ${ip}${prefix != null ? `/${prefix}` : ""}`;
        const gw = cfgString(c, "gateway");
        if (gw) text += ` · gw ${gw}`;
        break;
      }
      case "bond": {
        text = `bond · ${cfgString(c, "mode") ?? "—"}${cfgStringArray(c, "members").length > 0 ? ` · ${cfgStringArray(c, "members").join(",")}` : ""}`;
        const ip = cfgString(c, "ip");
        const prefix = cfgNumber(c, "cidrPrefix");
        if (ip) text += ` · ${ip}${prefix != null ? `/${prefix}` : ""}`;
        const gw = cfgString(c, "gateway");
        if (gw) text += ` · gw ${gw}`;
        break;
      }
      case "gre": {
        text = `GRE → ${cfgString(c, "remote") ?? "—"}`;
        break;
      }
      case "ipip": {
        text = `IPIP → ${cfgString(c, "remote") ?? "—"}`;
        break;
      }
      case "loopback": {
        const ip = cfgString(c, "ip");
        const prefix = cfgNumber(c, "cidrPrefix");
        text = ip ? `${ip}${prefix != null ? `/${prefix}` : ""}` : "loopback";
        break;
      }
      default:
        text = "—";
    }
  }

  const aliases = secondaryCount(c);
  if (aliases > 0) text += ` · +${aliases} alias${aliases === 1 ? "" : "es"}`;

  return <span className={cn("font-mono text-xs text-zinc-600 dark:text-zinc-300", className)}>{text}</span>;
}

/** Kernel SPAN state badge — in kernel / missing / disabled / n/a (tc missing). */
export function MirrorKernelBadge({
  state,
  className,
}: {
  state: "in-kernel" | "missing" | "disabled" | null | undefined;
  className?: string;
}) {
  if (state === null || state === undefined) {
    return <Badge variant="outline" className={cn("border-zinc-300 bg-transparent text-zinc-400 dark:border-zinc-700", className)}>kernel n/a</Badge>;
  }
  if (state === "in-kernel") {
    return (
      <Badge variant="outline" className={cn("gap-1 border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400", className)}>
        <Icons.CircleCheck className="h-3 w-3" />
        in kernel
      </Badge>
    );
  }
  if (state === "missing") {
    return (
      <Badge variant="outline" className={cn("gap-1 border-rose-600/50 bg-transparent text-rose-500", className)}>
        <Icons.CircleX className="h-3 w-3" />
        not installed
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className={cn("border-zinc-300 bg-transparent text-zinc-500 dark:border-zinc-700 dark:text-zinc-400", className)}>
      off
    </Badge>
  );
}

// ── R5 QA-round atoms: diagnostics output, recent targets, freshness, validation ──

/** Clipboard helper with toast feedback (shared by MAC copy + diag output). */
export async function copyText(text: string, okTitle = "Copied"): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    toastOk(okTitle);
  } catch {
    toastErr(new Error("Clipboard unavailable in this browser context"), "Copy failed");
  }
}

/** Live "second" ticker (10 s heartbeat) for relative updated-at labels.
 *  useSyncExternalStore keeps SSR/hydration safe (server snapshot = 0). */
const tickListeners = new Set<() => void>();
let tickTimer: ReturnType<typeof setInterval> | null = null;
function subscribeTick(cb: () => void): () => void {
  tickListeners.add(cb);
  if (tickTimer == null) {
    tickTimer = setInterval(() => tickListeners.forEach((l) => l()), 10_000);
  }
  return () => {
    tickListeners.delete(cb);
    if (tickListeners.size === 0 && tickTimer != null) {
      clearInterval(tickTimer);
      tickTimer = null;
    }
  };
}
export function useNowTick(): number {
  return useSyncExternalStore(
    subscribeTick,
    () => Date.now(),
    () => 0,
  );
}

/** Relative "updated Ns ago" stamp for derived-table refresh rows — reads the
 *  TanStack Query `dataUpdatedAt`; renders nothing before the first fetch. */
export function LastUpdatedLabel({ dataUpdatedAt, className }: { dataUpdatedAt?: number; className?: string }) {
  const now = useNowTick();
  if (!dataUpdatedAt) return null;
  const sec = Math.max(0, Math.round(((now || dataUpdatedAt) - dataUpdatedAt) / 1000));
  return (
    <span
      className={cn("inline-flex items-center gap-1 text-[11px] text-zinc-400 dark:text-zinc-500", className)}
      title={`Snapshot taken ${new Date(dataUpdatedAt).toLocaleTimeString()}`}
    >
      <Icons.Clock className="h-3 w-3" />
      {sec < 3 ? "updated just now" : `updated ${sec < 60 ? `${sec}s` : `${Math.floor(sec / 60)}m`} ago`}
    </span>
  );
}

// ── recent-target chips (localStorage-backed, hydration-safe) ────────────────

const RECENT_CAP = 4;
const recentCache = new Map<string, string[]>();
const recentListeners = new Set<() => void>();
const EMPTY_RECENT: string[] = [];

function readRecent(key: string): string[] {
  try {
    const raw = window.localStorage.getItem(`net-diag-recent:${key}`);
    const arr: unknown = raw ? JSON.parse(raw) : [];
    return Array.isArray(arr)
      ? arr.filter((x): x is string => typeof x === "string").slice(0, RECENT_CAP)
      : [];
  } catch {
    return [];
  }
}

function recentSnapshot(key: string): string[] {
  let v = recentCache.get(key);
  if (v == null) {
    v = readRecent(key);
    recentCache.set(key, v);
  }
  return v;
}

function pushRecent(key: string, value: string): void {
  const v = value.trim();
  if (!v) return;
  const prev = recentSnapshot(key);
  const next = [v, ...prev.filter((x) => x !== v)].slice(0, RECENT_CAP);
  if (next.length === prev.length && next.every((x, i) => x === prev[i])) return;
  recentCache.set(key, next);
  try {
    window.localStorage.setItem(`net-diag-recent:${key}`, JSON.stringify(next));
  } catch {
    // storage unavailable (private mode) — chips stay session-only
  }
  recentListeners.forEach((l) => l());
}

/** Most-recent diagnostic targets per tool (`net-diag-recent:<key>`).
 *  Call the setter from a mutation's onSuccess so only completed runs count. */
export function useRecentTargets(key: string): [string[], (value: string) => void] {
  const targets = useSyncExternalStore(
    (cb) => {
      recentListeners.add(cb);
      return () => {
        recentListeners.delete(cb);
      };
    },
    () => recentSnapshot(key),
    () => EMPTY_RECENT,
  );
  return [targets, pushRecent];
}

/** Direct store write (stable module fn — React-Compiler-safe to call from
 *  mutation onSuccess closures). */
export const pushRecentTarget = pushRecent;

/** Chip row for `useRecentTargets` — nothing rendered while empty. */
export function RecentTargetChips(props: {
  targets: string[];
  label: string;
  onPick: (value: string) => void;
  className?: string;
}) {
  if (props.targets.length === 0) return null;
  return (
    <div role="group" aria-label={`Recent ${props.label} targets`} className={cn("flex flex-wrap items-center gap-1.5", props.className)}>
      <span className="text-[10px] font-medium uppercase tracking-wide text-zinc-400 dark:text-zinc-500">recent:</span>
      {props.targets.map((t) => (
        <Button
          key={t}
          type="button"
          variant="outline"
          size="sm"
          className="h-11 max-w-44 px-2 font-mono text-[11px] normal-case lg:h-7"
          title={`Use ${t}`}
          aria-label={`Use recent ${props.label} target ${t}`}
          onClick={() => props.onPick(t)}
        >
          <span className="block min-w-0 truncate">{t}</span>
        </Button>
      ))}
    </div>
  );
}

// ── diagnostics output block (scrollable mono output + copy + size summary) ──

/** Vendor-style diagnostics output: summary chips row, a line/char count with a
 *  Copy button, then the raw tool output in a scrollable mono block. */
export function DiagOutputBlock(props: {
  label: string;
  output: string;
  summary?: React.ReactNode;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);
  const copyTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const text = props.output ?? "";
  const lineCount = text.length === 0 ? 0 : text.split("\n").length;

  const onCopy = () => {
    void copyText(text, `${props.label} output copied`).then(() => {
      setCopied(true);
      if (copyTimer.current) clearTimeout(copyTimer.current);
      copyTimer.current = setTimeout(() => setCopied(false), 1500);
    });
  };

  return (
    <div className={cn("space-y-1.5", props.className)}>
      {props.summary ? (
        <div className="flex flex-wrap items-center gap-2" role="status" aria-label={`${props.label} result summary`}>
          {props.summary}
        </div>
      ) : null}
      <div className="flex items-center justify-between gap-2">
        <p className="text-[10px] uppercase tracking-wide text-zinc-400 dark:text-zinc-500">
          {lineCount} {lineCount === 1 ? "line" : "lines"} · {text.length} chars
        </p>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="h-11 px-2.5 lg:h-7"
          disabled={text.length === 0}
          onClick={onCopy}
          aria-label={`Copy ${props.label} output`}
        >
          {copied ? <Icons.Check className="mr-1 h-3.5 w-3.5 text-emerald-500" /> : <Icons.Copy className="mr-1 h-3.5 w-3.5 text-zinc-500 dark:text-zinc-400" />}
          <span className="hidden sm:inline">{copied ? "Copied" : "Copy"}</span>
        </Button>
      </div>
      <pre
        role="region"
        aria-label={`${props.label} raw output`}
        className="max-h-56 overflow-auto rounded-lg border border-zinc-200 bg-zinc-50 p-3 font-mono text-[11px] leading-snug whitespace-pre-wrap break-words dark:border-zinc-800 dark:bg-zinc-900"
      >
        {text || "no output"}
      </pre>
    </div>
  );
}

// ── editor validation atoms (R2/R4 parity, UI_DESIGN_SYSTEM §5.16/§5.17) ────

/** Rose ring applied to an invalid input/select (same recipe as rule-editor). */
export const INVALID_CLS = "border-rose-500 ring-1 ring-rose-500/40 focus-visible:ring-rose-500";

/** Per-field error text under an invalid control (rule-editor recipe). */
export function FieldErrorText(props: { id: string; msg?: string }) {
  if (!props.msg) return null;
  return (
    <p id={props.id} role="alert" className="mt-1 text-[11px] text-rose-600 dark:text-rose-400">
      {props.msg}
    </p>
  );
}

/** Data-origin badge for derived tables — live kernel reads vs engine simulation. */
export function DataSourceBadge({ source, className }: { source: string | undefined; className?: string }) {
  if (source === "live") {
    return (
      <Badge variant="outline" className={cn("gap-1 border-emerald-500/40 bg-emerald-500/10 text-[10px] font-medium text-emerald-600 dark:text-emerald-400", className)}>
        <Icons.RadioTower className="h-3 w-3" /> live
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className={cn("border-zinc-300 text-[10px] font-normal text-zinc-500 dark:border-zinc-700 dark:text-zinc-400", className)}>
      simulated
    </Badge>
  );
}

