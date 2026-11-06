"use client";

/**
 * Shared UI atoms + helpers for the M10 system surfaces (ADR-019 theme):
 * type badges (config teal / full violet — violet reserved for `full`),
 * notification severity map (info zinc / warning amber / critical rose),
 * deep links per notification type, byte humanizer, relative time, JSON
 * side-by-side diff lines + JsonFieldViewer, and the auth/permission hook.
 */

import { useQuery } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

// ── permissions (query key matches the app-shell ["auth","me"] cache) ───────

export interface MePayload {
  kind: "user" | "key";
  username: string;
  role?: string;
  permissions: { read: string[]; write: string[]; admin: string[] };
}

export function usePermissions(): {
  isAdmin: (area: string) => boolean;
  canWrite: (area: string) => boolean;
  username: string;
} {
  const me = useQuery<MePayload>({
    queryKey: ["auth", "me"],
    queryFn: async () => {
      const res = await fetch("/api/v1/auth/me", { credentials: "same-origin" });
      const json = (await res.json()) as { data: MePayload };
      return json.data;
    },
    staleTime: 60_000,
  });
  return {
    isAdmin: (area) => me.data?.permissions.admin.includes(area) ?? false,
    canWrite: (area) => me.data?.permissions.write.includes(area) ?? false,
    username: me.data?.username ?? "",
  };
}

// ── badges ──────────────────────────────────────────────────────────────────

/** Backup type badge: config teal, full violet (violet reserved for `full`). */
export function BackupTypeBadge({ type }: { type: string }) {
  if (type === "full") {
    return (
      <Badge className="border-transparent bg-violet-600 text-white">
        <Icons.DatabaseBackup className="mr-1 h-3 w-3" /> full
      </Badge>
    );
  }
  return (
    <Badge className="border-teal-500/40 bg-teal-500/10 text-teal-600 dark:text-teal-400">
      <Icons.FileJson className="mr-1 h-3 w-3" /> config
    </Badge>
  );
}

/** 3-level notification severity map (M09 §5.4 map — 5-level scale is ips_events-only). */
export const NOTIF_SEVERITY: Record<string, { cls: string; label: string }> = {
  info: { cls: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300", label: "info" },
  warning: { cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400", label: "warning" },
  critical: { cls: "border-rose-600/40 bg-rose-600/10 text-rose-600 dark:text-rose-400", label: "critical" },
};

export function SeverityBadge({ severity }: { severity: string }) {
  const def = NOTIF_SEVERITY[severity] ?? NOTIF_SEVERITY.info;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium", def.cls)}>
      {def.label}
    </Badge>
  );
}

/** Notification type icon (lucide per type). */
export function TypeIcon({ type, className }: { type: string; className?: string }) {
  const C =
    type === "threat"
      ? Icons.ShieldAlert
      : type === "vpn"
        ? Icons.LockKeyhole
        : type === "ha"
          ? Icons.Network
          : type === "config"
            ? Icons.FileJson
            : Icons.Server;
  return <C className={cn("h-4 w-4", className)} />;
}

/** Deep link per notification type (M10 §4 notification center). */
export function deepLinkForType(type: string): string {
  switch (type) {
    case "threat":
      return "#/ips/events";
    case "vpn":
      return "#/vpn/configs";
    case "config":
      return "#/system/backups";
    case "ha":
      return "#/ha";
    default:
      return "#/system/settings";
  }
}

// ── formatters ──────────────────────────────────────────────────────────────

export function humanizeBytes(v: number | null | undefined): string {
  if (v == null) return "—";
  if (v < 1024) return `${v} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let n = v / 1024;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i += 1;
  }
  return `${n.toFixed(n >= 10 ? 0 : 1)} ${units[i]}`;
}

export function fmtDateTime(ts: string | null | undefined): string {
  if (!ts) return "—";
  return new Date(ts).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** "just now" / "Ns ago" / "Nm ago" / "Nh ago" / "Nd ago" for notification rows. */
export function fmtRelative(ts: string): string {
  const sec = Math.max(0, Math.floor((Date.now() - Date.parse(ts)) / 1000));
  if (sec < 15) return "just now";
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  return `${Math.floor(hr / 24)}d ago`;
}

export function humanUptime(sec: number): string {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

/** Masked-literal sentinel (same rule as M07 RADIUS sharedSecret). */
export const MASK = "••••••••";

// ── JSON diff (config history card) ─────────────────────────────────────────

export type DiffLine = { kind: "same" | "added" | "removed"; text: string };

/**
 * Unified-ish JSON diff: both snapshots are pretty-printed to sorted-key
 * lines; LCS alignment marks lines only in `newerJson` as added (emerald) and
 * lines only in `olderJson` as removed (rose). Small inputs only — snapshots
 * are single-section JSON blobs.
 */
export function diffJson(olderJson: string, newerJson: string): DiffLine[] {
  const a = stableLines(olderJson);
  const b = stableLines(newerJson);
  // LCS DP (O(n·m) — snapshots are small)
  const n = a.length;
  const m = b.length;
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ kind: "same", text: a[i] });
      i += 1;
      j += 1;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      out.push({ kind: "removed", text: a[i] });
      i += 1;
    } else {
      out.push({ kind: "added", text: b[j] });
      j += 1;
    }
  }
  while (i < n) out.push({ kind: "removed", text: a[i++] });
  while (j < m) out.push({ kind: "added", text: b[j++] });
  return out;
}

function stableLines(json: string): string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return json.split("\n");
  }
  const lines: string[] = [];
  const walk = (v: unknown, indent: number, path: string): void => {
    const pad = "  ".repeat(indent);
    if (v === null || typeof v !== "object") {
      lines.push(`${pad}${path ? `${path}: ` : ""}${JSON.stringify(v)}`);
      return;
    }
    if (Array.isArray(v)) {
      lines.push(`${pad}${path ? `${path}: ` : ""}[${v.length} item${v.length === 1 ? "" : "s"}]`);
      v.forEach((item, idx) => walk(item, indent + 1, `[${idx}]`));
      return;
    }
    const entries = Object.entries(v as Record<string, unknown>).sort(([x], [y]) => x.localeCompare(y));
    lines.push(`${pad}${path ? `${path}: ` : ""}{${entries.length} key${entries.length === 1 ? "" : "s"}}`);
    for (const [k, val] of entries) walk(val, indent + 1, k);
  };
  walk(parsed, 0, "");
  return lines;
}

/** Parse a configSnapshot JSON string defensively (viewer fallback). */
export function parseSnapshot(json: string): unknown {
  try {
    return JSON.parse(json);
  } catch {
    return { unparseable: json.slice(0, 2000) };
  }
}

/** Single-snapshot JSON inspector (fallback pane of the diff viewer). */
export function JsonViewer({ json, maxHeight = "18rem" }: { json: string; maxHeight?: string }) {
  let pretty = json;
  try {
    pretty = JSON.stringify(JSON.parse(json), null, 2);
  } catch {
    // keep raw
  }
  return (
    <pre
      className="overflow-auto rounded-lg border border-zinc-200 bg-zinc-50 p-3 font-mono text-[11px] leading-relaxed text-zinc-700 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300"
      style={{ maxHeight }}
    >
      {pretty}
    </pre>
  );
}

/** Side-by-side snapshot panes with unified diff tinting. */
export function DiffViewer({ olderJson, newerJson, maxHeight = "22rem" }: { olderJson: string; newerJson: string; maxHeight?: string }) {
  const lines = diffJson(olderJson, newerJson);
  const left = lines.filter((l) => l.kind !== "added");
  const right = lines.filter((l) => l.kind !== "removed");
  return (
    <div className="grid gap-2 md:grid-cols-2">
      {[
        { title: "Older", rows: left },
        { title: "Newer", rows: right },
      ].map((pane) => (
        <div key={pane.title} className="overflow-hidden rounded-lg border border-zinc-200 dark:border-zinc-800">
          <p className="border-b border-zinc-200 bg-zinc-50 px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wide text-zinc-500 dark:border-zinc-800 dark:bg-zinc-900">
            {pane.title}
          </p>
          <pre className="overflow-auto p-2 font-mono text-[11px] leading-relaxed" style={{ maxHeight }}>
            {pane.rows.map((l, idx) => (
              <div
                key={idx}
                className={cn(
                  "rounded px-1",
                  l.kind === "added" && "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
                  l.kind === "removed" && "bg-rose-500/10 text-rose-700 dark:text-rose-400",
                  l.kind === "same" && "text-zinc-600 dark:text-zinc-400",
                )}
              >
                <span className="mr-1 inline-block w-3 select-none text-zinc-400">
                  {l.kind === "added" ? "+" : l.kind === "removed" ? "−" : " "}
                </span>
                {l.text}
              </div>
            ))}
          </pre>
        </div>
      ))}
    </div>
  );
}
