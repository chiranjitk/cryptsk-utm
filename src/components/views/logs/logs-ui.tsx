"use client";

/**
 * Shared UI atoms for the M09 log views — LOCKED badge color map (M09 §5.4):
 * critical rose-600 solid · high rose-500 outline · medium orange-500 ·
 * low amber-500 · info violet-500 (violet ONLY here) · allow/success
 * emerald-500 · deny/drop rose-600 · reject orange-500 · failure rose-600
 * solid · denied rose-600 outline · suppressed zinc. Every badge pairs a
 * glyph + text (color is never the sole signal). No indigo anywhere.
 */

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import * as Icons from "lucide-react";

// ── manual paginator (server-side pagination — meta.totalPages drives it) ──

export function Paginator(props: {
  page: number;
  totalPages: number;
  total: number;
  limit: number;
  onPage: (page: number) => void;
  className?: string;
}) {
  const from = props.total === 0 ? 0 : (props.page - 1) * props.limit + 1;
  const to = Math.min(props.total, props.page * props.limit);
  return (
    <div className={cn("flex items-center justify-between gap-2 px-1 py-2 text-xs text-zinc-500", props.className)}>
      <span className="tabular-nums">
        {from}–{to} of {props.total.toLocaleString()}
      </span>
      <div className="flex items-center gap-1">
        <Button variant="outline" size="sm" className="h-7 gap-1 px-2" disabled={props.page <= 1} onClick={() => props.onPage(1)}>
          <Icons.ChevronsLeft className="h-3.5 w-3.5" />
        </Button>
        <Button variant="outline" size="sm" className="h-7 gap-1 px-2" disabled={props.page <= 1} onClick={() => props.onPage(props.page - 1)}>
          <Icons.ChevronLeft className="h-3.5 w-3.5" />
        </Button>
        <span className="px-2 font-medium tabular-nums text-zinc-600 dark:text-zinc-300">
          {props.page} / {props.totalPages}
        </span>
        <Button variant="outline" size="sm" className="h-7 gap-1 px-2" disabled={props.page >= props.totalPages} onClick={() => props.onPage(props.page + 1)}>
          <Icons.ChevronRight className="h-3.5 w-3.5" />
        </Button>
        <Button variant="outline" size="sm" className="h-7 gap-1 px-2" disabled={props.page >= props.totalPages} onClick={() => props.onPage(props.totalPages)}>
          <Icons.ChevronsRight className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  );
}

// ── severity badges (IPS events + live tail) ───────────────────────────────

const SEVERITY_BADGE: Record<string, { cls: string; icon: React.ComponentType<{ className?: string }> }> = {
  critical: { cls: "border-transparent bg-rose-600 text-white", icon: Icons.OctagonX },
  high: { cls: "border-rose-500/60 bg-transparent text-rose-600 dark:text-rose-400", icon: Icons.TriangleAlert },
  medium: { cls: "border-orange-500/40 bg-orange-500/10 text-orange-600 dark:text-orange-400", icon: Icons.CircleAlert },
  low: { cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400", icon: Icons.Info },
  info: { cls: "border-violet-500/40 bg-violet-500/10 text-violet-600 dark:text-violet-400", icon: Icons.Info },
};

export function SeverityBadge({ severity, className }: { severity: string; className?: string }) {
  const def = SEVERITY_BADGE[severity] ?? SEVERITY_BADGE.info;
  const Icon = def.icon;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium uppercase", def.cls, className)}>
      <Icon className="h-3 w-3" />
      {severity}
    </Badge>
  );
}

// ── firewall action badges ──────────────────────────────────────────────────

const FW_ACTION_BADGE: Record<string, { cls: string; icon: React.ComponentType<{ className?: string }> }> = {
  allow: { cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400", icon: Icons.ShieldCheck },
  deny: { cls: "border-transparent bg-rose-600 text-white", icon: Icons.Ban },
  drop: { cls: "border-rose-600/60 bg-transparent text-rose-600 dark:text-rose-400", icon: Icons.CircleX },
  reject: { cls: "border-orange-500/40 bg-orange-500/10 text-orange-600 dark:text-orange-400", icon: Icons.CircleMinus },
};

export function ActionBadge({ action, className }: { action: string | null; className?: string }) {
  const key = action ?? "";
  const def = FW_ACTION_BADGE[key] ?? { cls: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300", icon: Icons.HelpCircle };
  const Icon = def.icon;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium", def.cls, className)}>
      <Icon className="h-3 w-3" />
      {key || "—"}
    </Badge>
  );
}

// ── IPS action badges (alert/drop/reject/bypass/suppressed) ────────────────

const IPS_ACTION_BADGE: Record<string, { cls: string; icon: React.ComponentType<{ className?: string }> }> = {
  alert: { cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400", icon: Icons.Bell },
  drop: { cls: "border-transparent bg-rose-600 text-white", icon: Icons.CircleX },
  reject: { cls: "border-transparent bg-rose-600 text-white", icon: Icons.Ban },
  bypass: { cls: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300", icon: Icons.SkipForward },
  suppressed: { cls: "border-zinc-300 bg-transparent text-zinc-500 dark:border-zinc-700 dark:text-zinc-400", icon: Icons.BellOff },
};

export function IpsActionBadge({ action, className }: { action: string; className?: string }) {
  const def = IPS_ACTION_BADGE[action] ?? IPS_ACTION_BADGE.alert;
  const Icon = def.icon;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium", def.cls, className)}>
      <Icon className="h-3 w-3" />
      {action}
    </Badge>
  );
}

// ── audit result badges ─────────────────────────────────────────────────────

const RESULT_BADGE: Record<string, { cls: string; icon: React.ComponentType<{ className?: string }> }> = {
  success: { cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400", icon: Icons.CircleCheck },
  failure: { cls: "border-transparent bg-rose-600 text-white", icon: Icons.CircleX },
  denied: { cls: "border-rose-600/60 bg-transparent text-rose-600 dark:text-rose-400", icon: Icons.Ban },
};

export function ResultBadge({ result, className }: { result: string; className?: string }) {
  const def = RESULT_BADGE[result] ?? RESULT_BADGE.success;
  const Icon = def.icon;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium", def.cls, className)}>
      <Icon className="h-3 w-3" />
      {result}
    </Badge>
  );
}

// ── protocol chip ───────────────────────────────────────────────────────────

export function ProtocolBadge({ protocol, className }: { protocol: string | null; className?: string }) {
  if (!protocol) return <span className="text-xs text-zinc-400">—</span>;
  return (
    <Badge
      variant="outline"
      className={cn(
        "border-zinc-300 bg-zinc-50 font-mono text-[11px] uppercase text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300",
        className,
      )}
    >
      {protocol}
    </Badge>
  );
}

// ── formatters ──────────────────────────────────────────────────────────────

/** 1536 → "1.5 KB", 5_242_880 → "5.0 MB" (M09 §4 firewall table). */
export function humanizeBytes(v: number | null | undefined): string {
  if (v === null || v === undefined) return "—";
  if (v < 1024) return `${v} B`;
  if (v < 1024 ** 2) return `${(v / 1024).toFixed(1)} KB`;
  if (v < 1024 ** 3) return `${(v / 1024 ** 2).toFixed(1)} MB`;
  return `${(v / 1024 ** 3).toFixed(2)} GB`;
}

/** ISO → locale datetime with seconds ("Nov 06, 14:32:07"). */
export function fmtTs(ts: string | null | undefined): string {
  if (!ts) return "—";
  return new Date(ts).toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

/** datetime-local input value → ISO (user's locale → UTC, M09 §5.1). */
export function localInputToIso(value: string): string {
  if (!value) return "";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString();
}
