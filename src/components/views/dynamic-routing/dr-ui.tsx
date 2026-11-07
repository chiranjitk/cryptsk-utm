"use client";

/**
 * Shared atoms for the M19 dynamic-routing view — state/protocol badges on
 * the enterprise blue palette (UI_DESIGN_SYSTEM §2, ADR-019). Amber is a
 * transitional state, zinc neutral, rose only for "active" (failed) BGP.
 */

import { Badge } from "@/components/ui/badge";
import * as Icons from "lucide-react";
import { cn } from "@/lib/utils";

// ── BGP session state badge (established=blue, connect=amber, idle=zinc, active=red) ──

const BGP_STATE_CLS: Record<string, string> = {
  established: "border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400",
  connect: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  opensent: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  openconfirm: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  idle: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
  active: "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400",
};

export function BgpStateBadge({ state, className }: { state: string; className?: string }) {
  const cls = BGP_STATE_CLS[state] ?? BGP_STATE_CLS.idle;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium capitalize", cls, className)}>
      {state === "established" ? <Icons.CircleCheck className="h-3 w-3" /> : <Icons.CircleDashed className="h-3 w-3" />}
      {state}
    </Badge>
  );
}

// ── OSPF neighbor state badge (full=blue, others zinc) ───────────────────────

export function OspfStateBadge({ state, className }: { state: string; className?: string }) {
  const full = state === "full";
  return (
    <Badge
      variant="outline"
      className={cn(
        "gap-1 font-medium",
        full
          ? "border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400"
          : "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
        className,
      )}
    >
      {full ? <Icons.CircleCheck className="h-3 w-3" /> : <Icons.CircleDashed className="h-3 w-3" />}
      {state}
    </Badge>
  );
}

// ── protocol badge (bgp=blue, ospf=amber, static=zinc, connected=outline) ────

const RIB_PROTO_CLS: Record<string, string> = {
  bgp: "border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400",
  ospf: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  static: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
};

export function RibProtocolBadge({ protocol, className }: { protocol: string; className?: string }) {
  const cls = RIB_PROTO_CLS[protocol];
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium", cls, className)}>
      {protocol}
    </Badge>
  );
}

// ── small chips ──────────────────────────────────────────────────────────────

export function NetTypeChip({ type }: { type: string }) {
  return (
    <Badge
      variant="outline"
      className="border-zinc-300 bg-zinc-100 text-zinc-600 uppercase dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
    >
      {type}
    </Badge>
  );
}

export function FamilyBadge({ family }: { family: "ipv4" | "ipv6" }) {
  return (
    <Badge variant="outline" className="border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400">
      {family}
    </Badge>
  );
}

export function ListTypeBadge({ type }: { type: "standard" | "expanded" }) {
  return (
    <Badge variant="outline" className="border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
      {type}
    </Badge>
  );
}

export function PassiveChip({ passive }: { passive: boolean }) {
  if (!passive) return <span className="text-xs text-zinc-400">—</span>;
  return (
    <Badge variant="outline" className="gap-1 border-zinc-300 text-zinc-500 dark:border-zinc-700 dark:text-zinc-400">
      <Icons.EyeOff className="h-3 w-3" />
      passive
    </Badge>
  );
}

export function BfdFlagChip({ enabled, profileName }: { enabled: boolean; profileName?: string | null }) {
  if (!enabled) return <span className="text-xs text-zinc-400">—</span>;
  return (
    <Badge variant="outline" className="gap-1 border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400">
      <Icons.Activity className="h-3 w-3" />
      BFD{profileName ? ` · ${profileName}` : ""}
    </Badge>
  );
}

/** Inline zod field error text under an input (VALIDATION_ERROR details). */
export function FieldError({ errors, field }: { errors: Record<string, string[]>; field: string }) {
  const msgs = errors[field];
  if (!msgs || msgs.length === 0) return null;
  return <p className="mt-1 text-[11px] font-medium text-rose-600 dark:text-rose-400">{msgs[0]}</p>;
}
