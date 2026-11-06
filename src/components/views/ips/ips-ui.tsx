"use client";

/**
 * Shared UI atoms for the M04 IPS views — canonical badge recipes per
 * M04 §4 (severity: info/low zinc, medium amber, high rose, critical rose
 * bold; action: alert amber, drop/reject rose, bypass zinc, suppressed muted).
 */

import { useQueryClient } from "@tanstack/react-query";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import * as Icons from "lucide-react";
import { cn } from "@/lib/utils";
import { useRealtime } from "@/lib/realtime";
import { toastErr, toastOk } from "@/components/views/firewall/fw-ui";
import { ipsApi, type IpsAction, type IpsMode, type IpsSeverity } from "./ips-api";

// ── realtime invalidation (scoped per-view, config channel) ─────────────────

export function useIpsConfigInvalidation(): void {
  const queryClient = useQueryClient();
  useRealtime(["config"], {
    onConfigUpdated: (c) => {
      if (c.section === "ips") void queryClient.invalidateQueries({ queryKey: ["ips"] });
    },
  });
}

// ── severity badge (M04 §4 recipes) ─────────────────────────────────────────

const SEVERITY_BADGE: Record<IpsSeverity, { cls: string; label: string }> = {
  info: { cls: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300", label: "info" },
  low: { cls: "border-zinc-400/60 bg-transparent text-zinc-500 dark:border-zinc-600 dark:text-zinc-400", label: "low" },
  medium: { cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400", label: "medium" },
  high: { cls: "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400", label: "high" },
  critical: { cls: "border-transparent bg-rose-600 font-bold text-white", label: "critical" },
};

export function SeverityBadge({ severity, className }: { severity: IpsSeverity; className?: string }) {
  const def = SEVERITY_BADGE[severity] ?? SEVERITY_BADGE.info;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium uppercase", def.cls, className)}>
      {def.label}
    </Badge>
  );
}

// ── action badge ────────────────────────────────────────────────────────────

const ACTION_BADGE: Record<IpsAction, { cls: string; icon: React.ComponentType<{ className?: string }>; label: string }> = {
  alert: { cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400", icon: Icons.Bell, label: "alert" },
  drop: { cls: "border-transparent bg-rose-600 text-white", icon: Icons.CircleX, label: "drop" },
  reject: { cls: "border-transparent bg-rose-600 text-white", icon: Icons.Ban, label: "reject" },
  bypass: { cls: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300", icon: Icons.SkipForward, label: "bypass" },
  suppressed: { cls: "border-zinc-300 bg-transparent text-zinc-500 dark:border-zinc-700 dark:text-zinc-400", icon: Icons.BellOff, label: "suppressed" },
};

export function IpsActionBadge({ action, className }: { action: IpsAction; className?: string }) {
  const def = ACTION_BADGE[action] ?? ACTION_BADGE.alert;
  const Icon = def.icon;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium", def.cls, className)}>
      <Icon className="h-3 w-3" />
      {def.label}
    </Badge>
  );
}

// ── mode badge ──────────────────────────────────────────────────────────────

const MODE_BADGE: Record<IpsMode, { cls: string; label: string; hint: string }> = {
  inline_drop: { cls: "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400", label: "inline drop", hint: "Inline — matching traffic is dropped (blocking)" },
  inline_tap: { cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400", label: "inline tap", hint: "Inline copy — detect-only (alerts, no blocking)" },
  passive: { cls: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300", label: "passive IDS", hint: "Off-path IDS on a mirror/SPAN tap — detect-only" },
};

export function ModeBadge({ mode, className }: { mode: IpsMode; className?: string }) {
  const def = MODE_BADGE[mode] ?? MODE_BADGE.inline_drop;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium", def.cls, className)}>
      {def.label}
    </Badge>
  );
}

export function modeHint(mode: IpsMode): string {
  return MODE_BADGE[mode]?.hint ?? "";
}

// ── category chip ───────────────────────────────────────────────────────────

export function CategoryChip({ category }: { category: string | null }) {
  if (!category) return <span className="text-xs text-zinc-400">—</span>;
  return (
    <Badge variant="outline" className="border-zinc-300 bg-zinc-50 font-mono text-[11px] text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300">
      {category}
    </Badge>
  );
}

// ── suppress menu (row + detail panel action) ───────────────────────────────

export function SuppressMenu(props: {
  eventId: number;
  onSuppressed: (duration: "24h" | "7d" | "forever") => void;
  size?: "sm" | "default";
  triggerLabel?: string;
}) {
  const apply = async (duration: "24h" | "7d" | "forever") => {
    try {
      await ipsApi.suppressEvent(props.eventId, duration);
      toastOk("Event suppressed", `Suppressed for ${duration === "forever" ? "forever" : duration}`);
      props.onSuppressed(duration);
    } catch (err) {
      toastErr(err, "Suppress failed");
    }
  };
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size={props.size ?? "sm"} className="h-7 gap-1 px-2 text-xs">
          <Icons.BellOff className="h-3.5 w-3.5" />
          {props.triggerLabel ?? "Suppress"}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-44">
        <DropdownMenuLabel className="text-xs">Suppress this signature</DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem onClick={() => void apply("24h")}>24 hours</DropdownMenuItem>
        <DropdownMenuItem onClick={() => void apply("7d")}>7 days</DropdownMenuItem>
        <DropdownMenuItem onClick={() => void apply("forever")}>Forever</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
