"use client";

/**
 * Shared UI atoms for the DNS & DHCP views (M06 §4) — Record-driven badges
 * using the canonical class recipes from vpn-ui/fw-ui, per-section realtime
 * invalidation hooks, and small editors (IP list, option key/value rows).
 */

import * as Icons from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useRealtime } from "@/lib/realtime";
import { cn } from "@/lib/utils";

// ── realtime invalidation (config:updated {section} gates) ──────────────────

export function useDnsConfigInvalidation(): void {
  const queryClient = useQueryClient();
  useRealtime(["config"], {
    onConfigUpdated: (c) => {
      if (c.section === "dns") void queryClient.invalidateQueries({ queryKey: ["dns"] });
    },
  });
}

export function useDhcpConfigInvalidation(): void {
  const queryClient = useQueryClient();
  useRealtime(["config"], {
    onConfigUpdated: (c) => {
      if (c.section === "dhcp") void queryClient.invalidateQueries({ queryKey: ["dhcp"] });
    },
  });
}

// ── badges & chips (canonical class recipes) ────────────────────────────────

/** DNS query result: allowed (zinc) / sinkhole (amber) / nxdomain (rose). */
export function ResultBadge({ action }: { action: string }) {
  const map: Record<string, { cls: string; label: string }> = {
    allowed: {
      cls: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
      label: "allowed",
    },
    sinkhole: { cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400", label: "sinkhole" },
    nxdomain: { cls: "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400", label: "nxdomain" },
  };
  const it = map[action] ?? map.allowed!;
  return (
    <Badge variant="outline" className={cn("px-1.5 py-0 text-[10px]", it.cls)}>
      {it.label}
    </Badge>
  );
}

/** Blocked marker — rose-600 solid (M06 §4). */
export function BlockedBadge() {
  return (
    <Badge variant="outline" className="border-transparent bg-rose-600 px-1.5 py-0 text-[10px] text-white">
      blocked
    </Badge>
  );
}

/** Lease state: active emerald / expired amber / released zinc (M06 §4). */
export function LeaseStateBadge({ state }: { state: string }) {
  const map: Record<string, { cls: string; label: string }> = {
    active: { cls: "border-transparent bg-emerald-600 text-white", label: "active" },
    expired: { cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400", label: "expired" },
    released: {
      cls: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
      label: "released",
    },
  };
  const it = map[state] ?? map.released!;
  return (
    <Badge variant="outline" className={cn("px-1.5 py-0 text-[10px]", it.cls)}>
      {it.label}
    </Badge>
  );
}

/** Subnet family chip: v4 blue / v6 violet (basic DHCPv6, M06 §4). */
export function FamilyChip({ family }: { family: string }) {
  const v6 = family === "ipv6";
  return (
    <Badge
      variant="outline"
      className={cn(
        "px-1.5 py-0 text-[10px] uppercase tracking-wide",
        v6
          ? "border-zinc-500/40 bg-zinc-500/10 text-zinc-600 dark:text-zinc-400"
          : "border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400",
      )}
    >
      {v6 ? "v6" : "v4"}
    </Badge>
  );
}

/** DNS record type chip (zinc mono). */
export function RecordTypeChip({ type }: { type: string }) {
  return (
    <Badge variant="outline" className="border-zinc-300 bg-zinc-50 px-1.5 py-0 font-mono text-[10px] text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300">
      {type}
    </Badge>
  );
}

/** Block categories as small chips. */
export function CategoryChips({ categories }: { categories: string[] }) {
  if (categories.length === 0) return <span className="text-[11px] text-zinc-400">none</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {categories.map((c) => (
        <Badge key={c} variant="outline" className="border-red-600/40 bg-red-600/10 px-1.5 py-0 text-[10px] text-red-700 dark:text-red-500">
          {c}
        </Badge>
      ))}
    </span>
  );
}

/** Inline info note (zinc panel with Info icon — policies-view flavor). */
export function InfoNote({ children }: { children: React.ReactNode }) {
  return (
    <p className="flex items-start gap-1.5 rounded-md bg-zinc-50 px-2.5 py-2 text-[11px] text-zinc-500 dark:bg-zinc-800/60">
      <Icons.Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
      <span>{children}</span>
    </p>
  );
}

// ── small editors ───────────────────────────────────────────────────────────

/** Editable list of IP strings (forwarders, dns servers, relay targets). */
export function IpListEditor({
  values,
  onChange,
  placeholder = "e.g. 1.1.1.1",
  addLabel = "Add",
}: {
  values: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  addLabel?: string;
}) {
  return (
    <div className="space-y-1.5">
      {values.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {values.map((v, i) => (
            <Badge key={`${v}-${i}`} variant="outline" className="gap-1 border-zinc-300 bg-zinc-50 px-2 py-0.5 font-mono text-[11px] text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300">
              {v}
              <button
                type="button"
                aria-label={`Remove ${v}`}
                className="ml-0.5 text-zinc-400 hover:text-rose-500"
                onClick={() => onChange(values.filter((_, idx) => idx !== i))}
              >
                <Icons.X className="h-3 w-3" />
              </button>
            </Badge>
          ))}
        </div>
      )}
      <Input
        className="h-9 font-mono text-xs"
        placeholder={placeholder}
        onKeyDown={(e) => {
          const el = e.currentTarget;
          if (e.key === "Enter") {
            e.preventDefault();
            const v = el.value.trim();
            if (v && !values.includes(v)) onChange([...values, v]);
            el.value = "";
          }
        }}
        onBlur={(e) => {
          const v = e.currentTarget.value.trim();
          if (v && !values.includes(v)) {
            onChange([...values, v]);
            e.currentTarget.value = "";
          }
        }}
      />
      <p className="text-[11px] text-zinc-400">{addLabel}: press Enter or leave the field</p>
    </div>
  );
}

/** Key/value rows editor for DHCP custom options ({ optionCode: value }). */
export function OptionsEditor({
  value,
  onChange,
}: {
  value: Record<string, string>;
  onChange: (next: Record<string, string>) => void;
}) {
  const entries = Object.entries(value);
  const setEntry = (oldKey: string, newKey: string, v: string) => {
    const next: Record<string, string> = {};
    for (const [k, val] of entries) {
      next[k === oldKey ? newKey || k : k] = k === oldKey ? v : val;
    }
    onChange(next);
  };
  return (
    <div className="space-y-1.5">
      {entries.map(([k, v]) => (
        <div key={k} className="flex items-center gap-1.5">
          <Input
            className="h-8 w-20 font-mono text-xs"
            defaultValue={k}
            aria-label="Option code"
            onBlur={(e) => setEntry(k, e.currentTarget.value.trim(), v)}
          />
          <Input
            className="h-8 flex-1 font-mono text-xs"
            defaultValue={v}
            aria-label="Option value"
            onBlur={(e) => setEntry(k, k, e.currentTarget.value.trim())}
          />
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="h-8 w-8 text-zinc-400 hover:text-rose-500"
            aria-label={`Remove option ${k}`}
            onClick={() => {
              const next = { ...value };
              delete next[k];
              onChange(next);
            }}
          >
            <Icons.Trash2 className="h-3.5 w-3.5" />
          </Button>
        </div>
      ))}
      <Button
        type="button"
        variant="outline"
        size="sm"
        className="h-7 text-[11px]"
        onClick={() => onChange({ ...value, "": "" })}
      >
        <Icons.Plus className="mr-1 h-3 w-3" /> Add option
      </Button>
    </div>
  );
}
