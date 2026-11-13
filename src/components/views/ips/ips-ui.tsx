"use client";

/**
 * Shared UI atoms for the M04 IPS views — canonical badge recipes per
 * M04 §4 (severity: info/low zinc, medium amber, high rose, critical rose
 * bold; action: alert amber, drop/reject rose, bypass zinc, suppressed muted).
 * Suppression is confirm-first (R3): the dropdown duration opens a dialog
 * that restates the signature + window before POSTing.
 */

import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import * as Icons from "lucide-react";
import { cn } from "@/lib/utils";
import { useRealtime } from "@/lib/realtime";
import { toastErr, toastOk } from "@/components/views/firewall/fw-ui";
import { ipsApi, fmtDateTime, type IpsAction, type IpsMode, type IpsSeverity } from "./ips-api";

export type SuppressDuration = "24h" | "7d" | "forever";

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

// ── severity chip/legend tones (filter chips + chart series swatches) ───────

/** Active-chip classes + legend dot class per severity (M04 §4 recipes). */
export const SEVERITY_TONE: Record<IpsSeverity, { chip: string; dot: string }> = {
  info: { chip: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300", dot: "bg-zinc-300 dark:bg-zinc-600" },
  low: { chip: "border-zinc-400/60 bg-zinc-500/5 text-zinc-500 dark:border-zinc-600 dark:text-zinc-400", dot: "bg-zinc-400" },
  medium: { chip: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400", dot: "bg-amber-500" },
  high: { chip: "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400", dot: "bg-rose-500" },
  critical: { chip: "border-rose-600 bg-rose-600 text-white", dot: "bg-rose-600" },
};

// ── suppress menu (row + detail panel action) — confirm-first ───────────────

/** Minimal event context the confirm dialog restates before POSTing. */
export interface SuppressContext {
  id: number;
  severity: IpsSeverity;
  sid: string | null;
  category: string | null;
  message: string | null;
  action: string;
}

export function SuppressMenu(props: {
  eventId: number;
  event?: SuppressContext;
  onSuppressed: (duration: SuppressDuration) => void;
  size?: "sm" | "default";
  triggerLabel?: string;
}) {
  const [pending, setPending] = useState<SuppressDuration | null>(null);
  const live = props.eventId < 0; // synthetic live-tail rows have no persisted id
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="ghost"
            size={props.size ?? "sm"}
            className="h-7 gap-1 px-2 text-xs"
            disabled={live}
            aria-label={props.triggerLabel ?? `Suppress event ${props.eventId}`}
          >
            <Icons.BellOff className="h-3.5 w-3.5" />
            {props.triggerLabel ?? "Suppress"}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-44">
          <DropdownMenuLabel className="text-xs">Suppress this signature</DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={() => setPending("24h")}>24 hours…</DropdownMenuItem>
          <DropdownMenuItem onClick={() => setPending("7d")}>7 days…</DropdownMenuItem>
          <DropdownMenuItem onClick={() => setPending("forever")}>Forever…</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      {pending !== null && (
        <SuppressConfirmDialog
          eventId={props.eventId}
          event={props.event}
          initialDuration={pending}
          onClose={() => setPending(null)}
          onSuppressed={(d) => {
            setPending(null);
            props.onSuppressed(d);
          }}
        />
      )}
    </>
  );
}

function SuppressConfirmDialog(props: {
  eventId: number;
  event?: SuppressContext;
  initialDuration: SuppressDuration;
  onClose: () => void;
  onSuppressed: (duration: SuppressDuration) => void;
}) {
  const [duration, setDuration] = useState<SuppressDuration>(props.initialDuration);
  const [busy, setBusy] = useState(false);
  const ev = props.event;
  const untilPreview =
    duration === "24h"
      ? `until ${fmtDateTime(new Date(Date.now() + 24 * 3600_000).toISOString())}`
      : duration === "7d"
        ? `until ${fmtDateTime(new Date(Date.now() + 7 * 24 * 3600_000).toISOString())}`
        : "permanently (no expiry)";

  const confirm = async () => {
    setBusy(true);
    try {
      await ipsApi.suppressEvent(props.eventId, duration);
      toastOk("Event suppressed", `sid ${ev?.sid ?? props.eventId} suppressed ${duration === "forever" ? "forever" : `for ${duration}`}`);
      props.onSuppressed(duration);
    } catch (err) {
      toastErr(err, "Suppress failed");
      setBusy(false);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && props.onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-base">
            <Icons.BellOff className="h-4 w-4 text-zinc-500" /> Suppress signature
            {ev && <SeverityBadge severity={ev.severity} />}
          </DialogTitle>
          <DialogDescription>
            Future hits for this signature will be recorded with action “suppressed” instead of alerting.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          <div className="rounded-lg border border-zinc-200 p-3 text-xs dark:border-zinc-800">
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[11px] text-zinc-500">
              <span>sid {ev?.sid ?? "—"}</span>
              {ev?.category && <span>{ev.category}</span>}
              {ev?.action === "suppressed" && <span className="text-amber-600 dark:text-amber-400">already suppressed</span>}
            </div>
            <p className="mt-1 line-clamp-2 text-zinc-600 dark:text-zinc-300">{ev?.message ?? "Signature message unavailable"}</p>
          </div>

          <RadioGroup
            value={duration}
            onValueChange={(v) => setDuration(v as SuppressDuration)}
            className="grid grid-cols-3 gap-2"
          >
            {([
              { v: "24h", label: "24 hours" },
              { v: "7d", label: "7 days" },
              { v: "forever", label: "Forever" },
            ] as Array<{ v: SuppressDuration; label: string }>).map((d) => (
              <Label
                key={d.v}
                htmlFor={`suppress-${d.v}`}
                className={cn(
                  "flex min-h-11 cursor-pointer items-center justify-center gap-2 rounded-lg border p-2.5 text-xs sm:min-h-0",
                  duration === d.v && "border-zinc-600/60 bg-zinc-600/5",
                )}
              >
                <RadioGroupItem id={`suppress-${d.v}`} value={d.v} className="sr-only" />
                {d.label}
              </Label>
            ))}
          </RadioGroup>
          <p className="text-[11px] text-zinc-400">
            Window: <span className="font-mono">{untilPreview}</span>. The audit log records the duration; a reason
            note is not persisted by the suppress endpoint (locked request shape, M04 §3).
          </p>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={props.onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="destructive" onClick={() => void confirm()} disabled={busy}>
            {busy ? "Suppressing…" : "Suppress signature"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
