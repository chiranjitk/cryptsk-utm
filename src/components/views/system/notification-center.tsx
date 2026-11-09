"use client";

/**
 * Notification center (M10 §4 — topbar bell, part of this module):
 * Bell trigger + unread badge (count from ?unread=true; increments live on
 * alerts:new; badge colors: critical rose / warning amber / else zinc),
 * popover list (type icon, 3-level severity badge, title, message,
 * sourceModule, relative time, unread tint), row click = mark read + deep
 * link per type, "Mark all read", footer notes the 500-row cap.
 * Exported: NotificationCenter (popover) + useUnreadCount (topbar badge).
 */

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { cn } from "@/lib/utils";
import { useRealtime, type AlertNewPayload } from "@/lib/realtime";
import { EmptyBlock, toastErr, toastOk } from "../firewall/fw-ui";
import { SeverityBadge, TypeIcon, deepLinkForType, fmtRelative } from "./system-ui";
import { systemApi, type NotificationDTO } from "./system-api";

// ── live unread count (also usable directly in a topbar badge) ──────────────

export function useUnreadCount(): { count: number; hasCritical: boolean; hasWarning: boolean } {
  const queryClient = useQueryClient();
  const unread = useQuery({
    queryKey: ["notifications", "unread-count"],
    queryFn: async () => {
      const { data, meta } = await systemApi.listNotifications("unread=true&limit=100");
      return { total: meta.total, rows: data };
    },
    refetchInterval: 30_000, // safety net — live updates ride alerts:new
  });

  useRealtime(["alerts"], {
    onAlertsNew: (a: AlertNewPayload) => {
      void queryClient.invalidateQueries({ queryKey: ["notifications"] });
      if (a.severity === "critical") {
        toastOk(a.title, a.message ?? undefined);
      }
    },
  });

  const rows = unread.data?.rows ?? [];
  return {
    count: unread.data?.total ?? 0,
    hasCritical: rows.some((r) => r.severity === "critical"),
    hasWarning: rows.some((r) => r.severity === "warning"),
  };
}

// ── popover ─────────────────────────────────────────────────────────────────

const UNREAD_TINT = "bg-red-600/5";

export function NotificationCenter() {
  const [open, setOpen] = useState(false);
  const queryClient = useQueryClient();
  const unread = useUnreadCount();
  const list = useQuery({
    enabled: open,
    queryKey: ["notifications", "list", "open"],
    queryFn: () => systemApi.listNotifications("page=1&limit=15"),
  });

  const markRead = useMutation({
    mutationFn: (n: NotificationDTO) => systemApi.markNotificationRead(n.id),
    onSuccess: (_d, n) => {
      void queryClient.invalidateQueries({ queryKey: ["notifications"] });
      window.location.hash = deepLinkForType(n.type);
      setOpen(false);
    },
    onError: (err) => toastErr(err, "Mark all failed"),
  });

  const readAll = useMutation({
    mutationFn: () => systemApi.markAllNotificationsRead(),
    onSuccess: (r) => {
      toastOk("All notifications marked read", `${r.marked} row${r.marked === 1 ? "" : "s"} updated (audited).`);
      void queryClient.invalidateQueries({ queryKey: ["notifications"] });
    },
    onError: (err) => toastErr(err, "Mark all failed"),
  });

  const badgeTone = unread.hasCritical
    ? "bg-rose-600 text-white" // critical unread → rose (§4 badge map)
    : unread.hasWarning
      ? "bg-amber-500 text-white"
      : "bg-zinc-500 text-white";

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button variant="ghost" size="icon" aria-label={`Notifications (${unread.count} unread)`} className="relative">
          <Icons.Bell className="h-4.5 w-4.5" />
          {unread.count > 0 ? (
            <span
              className={cn(
                "absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full px-1 text-[10px] font-semibold tabular-nums",
                badgeTone,
              )}
            >
              {unread.count > 99 ? "99+" : unread.count}
            </span>
          ) : null}
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-96 p-0">
        <div className="flex items-center justify-between px-3 py-2.5">
          <p className="text-sm font-semibold">Notifications</p>
          <Button
            size="sm"
            variant="ghost"
            className="h-7 gap-1 text-xs"
            disabled={unread.count === 0 || readAll.isPending}
            onClick={() => readAll.mutate()}
          >
            <Icons.CheckCheck className="h-3.5 w-3.5" /> Mark all read
          </Button>
        </div>
        <Separator />
        <ScrollArea className="h-96">
          {list.isLoading ? (
            <div className="space-y-2 p-3">
              {Array.from({ length: 4 }).map((_, i) => (
                <div key={i} className="h-14 animate-pulse rounded-lg bg-zinc-100 dark:bg-zinc-800" />
              ))}
            </div>
          ) : (list.data?.data.length ?? 0) === 0 ? (
            <EmptyBlock
              icon={<Icons.BellOff className="h-6 w-6" />}
              title="You're all caught up"
              description="New alerts appear here in realtime (threats, resource thresholds, HA, config events)."
            />
          ) : (
            <ul className="divide-y divide-zinc-100 dark:divide-zinc-800">
              {list.data!.data.map((n) => (
                <li key={n.id}>
                  <button
                    type="button"
                    className={cn(
                      "flex w-full items-start gap-2.5 px-3 py-2.5 text-left transition-colors hover:bg-zinc-50 dark:hover:bg-zinc-800/60",
                      !n.isRead && UNREAD_TINT,
                    )}
                    onClick={() => markRead.mutate(n)}
                  >
                    <span
                      className={cn(
                        "mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full",
                        n.severity === "critical"
                          ? "bg-rose-600/10 text-rose-600 dark:text-rose-400"
                          : n.severity === "warning"
                            ? "bg-amber-500/10 text-amber-600 dark:text-amber-400"
                            : "bg-zinc-100 text-zinc-500 dark:bg-zinc-800 dark:text-zinc-400",
                      )}
                    >
                      <TypeIcon type={n.type} />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="flex items-center gap-1.5">
                        <span className={cn("truncate text-sm", n.isRead ? "font-normal text-zinc-600 dark:text-zinc-300" : "font-medium")}>
                          {n.title}
                        </span>
                        <SeverityBadge severity={n.severity} />
                      </span>
                      {n.message ? <span className="mt-0.5 line-clamp-2 block text-xs text-zinc-500">{n.message}</span> : null}
                      <span className="mt-0.5 flex items-center gap-1.5 text-[10px] text-zinc-400">
                        {n.sourceModule ? <span className="rounded bg-zinc-100 px-1 py-0.5 dark:bg-zinc-800">{n.sourceModule}</span> : null}
                        {fmtRelative(n.createdAt)}
                        {!n.isRead ? <span className="h-1.5 w-1.5 rounded-full bg-red-700" aria-label="unread" /> : null}
                      </span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </ScrollArea>
        <Separator />
        <p className="px-3 py-2 text-[10px] text-zinc-400">
          Read notifications are pruned automatically beyond a 500-row window · click a row to mark read and jump to its view
        </p>
      </PopoverContent>
    </Popover>
  );
}
