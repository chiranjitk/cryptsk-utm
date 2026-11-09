"use client";

/**
 * Shared UI atoms for the M13 threat-intel views — composed only from
 * src/components/ui primitives. Blue theme per UI_DESIGN_SYSTEM §2:
 * severity critical = red, warning = amber, info = zinc; action chips
 * drop = red, reject = amber, quarantine_vlan = blue; "ok" sync state
 * = blue (emerald is reserved and FORBIDDEN in this module).
 */

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import * as Icons from "lucide-react";

// ── severity (M13 scale: info | warning | critical) ─────────────────────────

const SEVERITY_CLS: Record<string, string> = {
  critical: "border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400",
  warning: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  info: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
};

export function SeverityBadge({ severity, className }: { severity: string; className?: string }) {
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium capitalize", SEVERITY_CLS[severity] ?? SEVERITY_CLS.info, className)}>
      {severity}
    </Badge>
  );
}

/** Severity dot used in the compact "Recent matches" list. */
export function SeverityDot({ severity }: { severity: string }) {
  const cls =
    severity === "critical"
      ? "bg-red-500"
      : severity === "warning"
        ? "bg-amber-500"
        : "bg-zinc-400";
  return <span className={cn("inline-block h-2 w-2 shrink-0 rounded-full", cls)} aria-label={severity} />;
}

// ── auto-block action chips ─────────────────────────────────────────────────

const ACTION_CLS: Record<string, string> = {
  drop: "border-red-500/50 bg-transparent text-red-500",
  reject: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  quarantine_vlan: "border-red-600/40 bg-red-600/10 text-red-700 dark:text-red-500",
};

export function ActionChip({ action, className }: { action: string; className?: string }) {
  const Icon = action === "drop" ? Icons.Ban : action === "reject" ? Icons.CircleMinus : Icons.ShieldAlert;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium", ACTION_CLS[action] ?? ACTION_CLS.drop, className)}>
      <Icon className="h-3 w-3" />
      {action === "quarantine_vlan" ? "quarantine" : action}
    </Badge>
  );
}

/** Hit action in the recent-matches feed. */
export function HitActionChip({ action }: { action: string }) {
  const cls =
    action === "blocked"
      ? "border-red-500/50 bg-transparent text-red-500"
      : action === "quarantined"
        ? "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400"
        : "border-zinc-300 bg-zinc-100 text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800";
  return (
    <Badge variant="outline" className={cn("font-medium", cls)}>
      {action}
    </Badge>
  );
}

// ── small identity chips ────────────────────────────────────────────────────

export function TypeBadge({ type }: { type: string }) {
  return (
    <Badge
      variant="outline"
      className="border-zinc-300 bg-zinc-100 font-mono text-[10px] uppercase text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
    >
      {type}
    </Badge>
  );
}

export function DirectionChip({ direction }: { direction: string }) {
  return (
    <Badge variant="outline" className="border-zinc-300 bg-zinc-100 text-zinc-600 uppercase dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
      {direction}
    </Badge>
  );
}

/** manual | auto-feed source badge on auto-block rules. */
export function SourceBadge({ source }: { source: string }) {
  const isAuto = source === "auto-feed";
  return (
    <Badge
      variant="outline"
      className={cn(
        "gap-1 font-medium",
        isAuto
          ? "border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300"
          : "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
      )}
    >
      {isAuto ? <Icons.Radar className="h-3 w-3" /> : <Icons.User className="h-3 w-3" />}
      {source}
    </Badge>
  );
}

export function CategoryChip({ category }: { category: string }) {
  return (
    <Badge variant="outline" className="border-zinc-500/30 bg-zinc-500/5 text-xs font-normal capitalize text-zinc-600 dark:text-zinc-300">
      {category}
    </Badge>
  );
}

// ── meters (thin blue bars — confidence 0-100, reputation 0-100) ─────────────

export function Meter({ value, label, tone = "blue" }: { value: number; label: string; tone?: "blue" | "red" }) {
  const clamped = Math.max(0, Math.min(100, value));
  return (
    <div className="flex items-center gap-2" title={`${label}: ${clamped}%`}>
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-zinc-200 dark:bg-zinc-700">
        <div
          className={cn("h-full rounded-full transition-[width]", tone === "blue" ? "bg-zinc-500" : "bg-red-500")}
          style={{ width: `${clamped}%` }}
        />
      </div>
      <span className="w-7 shrink-0 text-right font-mono text-[10px] tabular-nums text-zinc-500">{clamped}</span>
    </div>
  );
}
