"use client";

/**
 * Shared UI atoms for the QoS view (M08 §4) — template/priority/DSCP/hard-limit
 * badges, matcher chips and the per-section realtime invalidation hook.
 * Theme per ADR-019 (white & blue): blue = precedence/active, teal = AF classes,
 * amber = low precedence, rose-600 = hard limit, zinc neutrals.
 */

import * as Icons from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { toast as showToast } from "@/hooks/use-toast";
import { useRealtime } from "@/lib/realtime";
import { cn } from "@/lib/utils";
import { DSCP_WELL_KNOWN, QOS_TEMPLATES, dscpName, type QosTemplateName } from "@/lib/qos/templates";

// ── realtime invalidation (config:updated {section:"qos"} → refetch + toast) ─

export function useQosConfigInvalidation(): void {
  const queryClient = useQueryClient();
  useRealtime(["config"], {
    onConfigUpdated: (c) => {
      if (c.section === "qos") {
        void queryClient.invalidateQueries({ queryKey: ["qos"] });
        showToast({ title: "QoS applied", description: "Shaper configuration changed — policies refetched" });
      }
    },
  });
}

// ── badges ──────────────────────────────────────────────────────────────────

const TEMPLATE_CLS: Record<QosTemplateName, string> = {
  voip: "border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400",
  video: "border-teal-500/40 bg-teal-500/10 text-teal-600 dark:text-teal-400",
  gaming: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  bulk: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
  custom: "border-zinc-300 border-dashed bg-transparent text-zinc-500 dark:border-zinc-700 dark:text-zinc-400",
};

export function TemplateBadge({ template }: { template: string | null }) {
  if (!template) {
    return (
      <Badge variant="outline" className="border-dashed px-1.5 py-0 text-[10px] text-zinc-400">
        no template
      </Badge>
    );
  }
  const cls = TEMPLATE_CLS[template as QosTemplateName] ?? TEMPLATE_CLS.custom;
  return (
    <Badge variant="outline" className={cn("px-1.5 py-0 text-[10px]", cls)}>
      {QOS_TEMPLATES[template as QosTemplateName]?.label ?? template}
    </Badge>
  );
}

/** Priority 0–7: 0–1 high precedence (blue), 2–5 standard (zinc), 6–7 lowest (amber). */
export function PriorityBadge({ priority }: { priority: number }) {
  const cls =
    priority <= 1
      ? "border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400"
      : priority >= 6
        ? "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400"
        : "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300";
  return (
    <Badge variant="outline" className={cn("w-8 justify-center px-1.5 py-0 font-mono text-[10px]", cls)}>
      {priority}
    </Badge>
  );
}

const DSCP_CLS: Record<string, string> = {
  blue: "border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400",
  teal: "border-teal-500/40 bg-teal-500/10 text-teal-600 dark:text-teal-400",
  amber: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  zinc: "border-zinc-300 bg-zinc-50 px-1.5 py-0 font-mono text-[10px] text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300",
};

/** DSCP badge rendering e.g. "EF 46" (M08 §4); class colors: EF blue, AF teal, CS amber, BE/CS1 zinc. */
export function DscpBadge({ mark }: { mark: number | null }) {
  if (mark == null) return <span className="text-[11px] text-zinc-400">—</span>;
  const name = dscpName(mark);
  const cls =
    mark === 46
      ? DSCP_CLS.blue
      : [34, 26, 18].includes(mark)
        ? DSCP_CLS.teal
        : [32, 24].includes(mark)
          ? DSCP_CLS.amber
          : DSCP_CLS.zinc;
  return (
    <Badge variant="outline" className={cn("gap-1 px-1.5 py-0 font-mono text-[10px]", cls)}>
      {name ? <span className="font-sans font-medium">{name}</span> : null}
      {mark}
    </Badge>
  );
}

/** Per-user / per-app hard limit chip — rose-600 solid (M08 §5.2). */
export function HardLimitBadge() {
  return (
    <Badge variant="outline" className="gap-1 border-transparent bg-rose-600 px-1.5 py-0 text-[10px] text-white">
      <Icons.Gauge className="h-3 w-3" />
      limit
    </Badge>
  );
}

// ── matcher chips ───────────────────────────────────────────────────────────

function initialsOf(userName: string): string {
  const parts = userName.split(/[.\s_-]+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return userName.slice(0, 2).toUpperCase();
}

/** Matchers: apps as blue chips / users as avatar-initials / addresses mono. */
export function MatcherChips({
  apps,
  users,
  addresses,
  usersById,
}: {
  apps: string[];
  users: string[];
  addresses: string[];
  usersById?: Map<string, string>;
}) {
  if (apps.length === 0 && users.length === 0 && addresses.length === 0) {
    return <span className="text-[11px] italic text-zinc-400">Any traffic (catch-all)</span>;
  }
  return (
    <span className="flex flex-wrap items-center gap-1">
      {apps.map((a) => (
        <Badge key={`app-${a}`} variant="outline" className="border-blue-500/40 bg-blue-500/10 px-1.5 py-0 text-[10px] text-blue-600 dark:text-blue-400">
          {a}
        </Badge>
      ))}
      {users.map((u) => (
        <Badge
          key={`user-${u}`}
          variant="outline"
          className="gap-1 border-zinc-300 bg-zinc-50 px-1.5 py-0 text-[10px] text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300"
        >
          <span className="flex h-3.5 w-3.5 items-center justify-center rounded-full bg-zinc-200 text-[7px] font-semibold text-zinc-600 dark:bg-zinc-700 dark:text-zinc-200">
            {initialsOf(usersById?.get(u) ?? `user ${u}`)}
          </span>
          {usersById?.get(u) ?? `#${u}`}
        </Badge>
      ))}
      {addresses.map((a) => (
        <Badge key={`addr-${a}`} variant="outline" className="px-1.5 py-0 font-mono text-[10px] text-zinc-600 dark:text-zinc-300">
          {a}
        </Badge>
      ))}
    </span>
  );
}

// ── template explanation table (policy dialog, M08 §4) ──────────────────────

export function TemplateExplanationTable({ template, bandwidthKbps }: { template: QosTemplateName | null; bandwidthKbps: number }) {
  if (!template) return null;
  const def = QOS_TEMPLATES[template];
  return (
    <div className="rounded-md border border-zinc-200 dark:border-zinc-800">
      <div className="flex items-baseline justify-between gap-2 border-b border-zinc-200 px-2.5 py-1.5 dark:border-zinc-800">
        <p className="text-[11px] font-semibold text-zinc-600 dark:text-zinc-300">
          Starter rules seeded on create — {def.label.toLowerCase()} template
        </p>
        <p className="text-[10px] text-zinc-400">{def.intent}</p>
      </div>
      {def.rules.length === 0 ? (
        <p className="px-2.5 py-2 text-[11px] text-zinc-400">No starter rules — you add classes yourself.</p>
      ) : (
        <table className="w-full text-[11px]">
          <thead className="text-left text-[10px] uppercase tracking-wide text-zinc-400">
            <tr>
              <th className="px-2.5 py-1 font-medium">Rule</th>
              <th className="px-2.5 py-1 font-medium">Prio</th>
              <th className="px-2.5 py-1 font-medium">Guaranteed</th>
              <th className="px-2.5 py-1 font-medium">Max</th>
              <th className="px-2.5 py-1 font-medium">DSCP</th>
              <th className="px-2.5 py-1 font-medium">Apps</th>
            </tr>
          </thead>
          <tbody>
            {def.rules.map((r) => (
              <tr key={r.name} className="border-t border-zinc-100 dark:border-zinc-800/60">
                <td className="px-2.5 py-1 font-medium">{r.name}</td>
                <td className="px-2.5 py-1 font-mono">{r.priority}</td>
                <td className="px-2.5 py-1 font-mono tabular-nums">
                  {r.guaranteedPct == null ? "—" : `${Math.round((bandwidthKbps * r.guaranteedPct) / 100)} kbps`}
                </td>
                <td className="px-2.5 py-1 font-mono tabular-nums">
                  {r.maxPct == null ? "—" : `${Math.round((bandwidthKbps * r.maxPct) / 100)} kbps`}
                </td>
                <td className="px-2.5 py-1">
                  <DscpBadge mark={r.dscpMark} />
                </td>
                <td className="px-2.5 py-1 text-zinc-500">{r.matchApps.length ? r.matchApps.join(", ") : "any"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export { DSCP_WELL_KNOWN };
