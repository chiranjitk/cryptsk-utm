"use client";

/**
 * Shared UI atoms for the M13 threat-intel views — composed only from
 * src/components/ui primitives. Palette per UI_DESIGN_SYSTEM §2 (rev 2):
 * severity critical = rose, warning = amber, info = zinc; action chips
 * drop = rose, reject = amber, quarantine_vlan = zinc; neutral sync state
 * = zinc. Emerald appears ONLY for true-health states (§2 health-only
 * rule) — the feed freshness badge uses it for "fresh" (<24 h sync), and
 * nowhere else in this module.
 */

import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import * as Icons from "lucide-react";

// ── severity (M13 scale: info | warning | critical) ─────────────────────────

const SEVERITY_CLS: Record<string, string> = {
  critical: "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400",
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
      ? "bg-zinc-500"
      : severity === "warning"
        ? "bg-amber-500"
        : "bg-zinc-400";
  return <span className={cn("inline-block h-2 w-2 shrink-0 rounded-full", cls)} aria-label={severity} />;
}

// ── auto-block action chips ─────────────────────────────────────────────────

const ACTION_CLS: Record<string, string> = {
  drop: "border-rose-500/50 bg-transparent text-rose-500",
  reject: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  quarantine_vlan: "border-rose-600/40 bg-rose-600/10 text-rose-700 dark:text-rose-500",
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
      ? "border-zinc-500/50 bg-transparent text-zinc-500"
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

// ── feed freshness (recency of last sync — health-only emerald per §2) ──────

/**
 * Data-recency badge for a threat feed: fresh (<24 h, emerald — true health),
 * aging (<7 d, amber), stale (≥7 d, rose), never synced (rose). Sync OUTCOME
 * (ok/error) stays on FeedsView's SyncStatusPill; this badge is only about
 * how old the ingested data is.
 */
export function FreshnessBadge({ lastSyncAt, lastStatus }: { lastSyncAt: string | null; lastStatus: string }) {
  let tone = "border-zinc-300 bg-zinc-100 text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-400";
  let dot = "bg-zinc-400";
  let label = "never synced";
  let tip = "Feed has never synced — run Sync now to ingest indicators";

  if (lastStatus === "error") {
    tone = "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400";
    dot = "bg-rose-500";
    label = "sync error";
    tip = "Last sync attempt failed — feed data may be outdated";
  } else if (lastSyncAt) {
    const ageMs = Date.now() - Date.parse(lastSyncAt);
    const ageH = Number.isNaN(ageMs) ? Infinity : ageMs / 3600_000;
    if (ageH < 24) {
      tone = "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400";
      dot = "bg-emerald-500";
      label = "fresh";
      tip = "Synced within the last 24 h";
    } else if (ageH < 24 * 7) {
      tone = "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400";
      dot = "bg-amber-500";
      label = "aging";
      tip = "Last sync was more than 24 h ago — consider syncing";
    } else {
      tone = "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400";
      dot = "bg-rose-500";
      label = "stale";
      tip = "Last sync was more than 7 days ago";
    }
  }

  return (
    <TooltipProvider delayDuration={100}>
      <Tooltip>
        <TooltipTrigger asChild>
          <Badge variant="outline" className={cn("gap-1.5 font-medium", tone)} aria-label={`Feed freshness: ${label}`}>
            <span className={cn("inline-block h-1.5 w-1.5 rounded-full", dot)} />
            {label}
          </Badge>
        </TooltipTrigger>
        <TooltipContent className="text-xs">{tip}</TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

// ── meters (thin neutral bars — confidence 0-100, reputation 0-100) ─────────

export function Meter({ value, label, tone = "blue" }: { value: number; label: string; tone?: "blue" | "red" }) {
  const clamped = Math.max(0, Math.min(100, value));
  return (
    <div className="flex items-center gap-2" title={`${label}: ${clamped}%`}>
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-zinc-200 dark:bg-zinc-700">
        <div
          className={cn("h-full rounded-full transition-[width]", tone === "blue" ? "bg-zinc-500" : "bg-zinc-500")}
          style={{ width: `${clamped}%` }}
        />
      </div>
      <span className="w-7 shrink-0 text-right font-mono text-[10px] tabular-nums text-zinc-500">{clamped}</span>
    </div>
  );
}
