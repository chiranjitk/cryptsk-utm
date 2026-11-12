"use client";

/**
 * Shared UI atoms for the M02 network views — composed only from
 * src/components/ui primitives. Blue theme per UI_DESIGN_SYSTEM §2 (ADR-019):
 * emerald is reserved for TRUE health semantics only (WAN up, link up, BFD up);
 * amber = degraded/warn, rose = down/critical, zinc = neutral/unknown.
 * Role chips are configuration labels, never health — so no emerald there.
 */

import { Badge } from "@/components/ui/badge";
import * as Icons from "lucide-react";
import { cn } from "@/lib/utils";
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

// ── BFD chip (engine-simulated reachability state) ──────────────────────────

export function BfdChip({ state, className }: { state: "up" | "down" | null; className?: string }) {
  if (state === "up") {
    return (
      <Badge
        variant="outline"
        className={cn("gap-1 border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400", className)}
      >
        <Icons.CircleCheck className="h-3 w-3" />
        BFD up
      </Badge>
    );
  }
  if (state === "down") {
    return (
      <Badge variant="outline" className={cn("gap-1 border-rose-600/60 bg-transparent text-rose-500", className)}>
        <Icons.CircleX className="h-3 w-3" />
        BFD down
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className={cn("border-zinc-300 bg-transparent text-zinc-500 dark:border-zinc-700 dark:text-zinc-400", className)}>
      BFD off
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
