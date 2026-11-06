"use client";

/**
 * Shared UI atoms for the Identity views (M07 §4) — role/method/voucher/state
 * badges using the canonical class recipes from vpn-ui/dns-dhcp-ui, plus the
 * section-scoped realtime invalidation hook.
 */

import * as Icons from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { useRealtime } from "@/lib/realtime";
import { roleLabel, type Role } from "@/lib/auth/rbac";
import { cn } from "@/lib/utils";

// ── realtime invalidation (config:updated {section:"identity"}) ─────────────

export function useIdentityConfigInvalidation(): void {
  const queryClient = useQueryClient();
  useRealtime(["config"], {
    onConfigUpdated: (c) => {
      if (c.section === "identity") {
        void queryClient.invalidateQueries({ queryKey: ["identity"] });
        void queryClient.invalidateQueries({ queryKey: ["users"] });
        void queryClient.invalidateQueries({ queryKey: ["groups"] });
        void queryClient.invalidateQueries({ queryKey: ["radius"] });
        void queryClient.invalidateQueries({ queryKey: ["directory"] });
        void queryClient.invalidateQueries({ queryKey: ["portal"] });
        void queryClient.invalidateQueries({ queryKey: ["auth-settings"] });
      }
    },
  });
}

// ── badges & chips (canonical class recipes) ────────────────────────────────

const ROLE_STYLES: Record<string, string> = {
  super_admin: "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400",
  tenant_admin: "border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400",
  security_admin: "border-violet-500/40 bg-violet-500/10 text-violet-600 dark:text-violet-400",
  network_admin: "border-teal-500/40 bg-teal-500/10 text-teal-600 dark:text-teal-400",
  soc_analyst: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  helpdesk: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
  auditor: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
  api_service: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
};

export function RoleBadge({ role }: { role: string }) {
  return (
    <Badge variant="outline" className={cn("px-1.5 py-0 text-[10px]", ROLE_STYLES[role] ?? ROLE_STYLES.helpdesk)}>
      {roleLabel(role as Role) ?? role}
    </Badge>
  );
}

/** Identity session method — local emerald / radius teal / captive amber / vpn violet (M07 §4). */
export function MethodBadge({ method }: { method: string }) {
  const map: Record<string, { cls: string; label: string }> = {
    local: { cls: "border-transparent bg-emerald-600 text-white", label: "local" },
    radius: { cls: "border-teal-500/40 bg-teal-500/10 text-teal-600 dark:text-teal-400", label: "radius" },
    captive_portal: { cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400", label: "captive_portal" },
    vpn: { cls: "border-violet-500/40 bg-violet-500/10 text-violet-600 dark:text-violet-400", label: "vpn" },
  };
  const it = map[method] ?? map.local!;
  return (
    <Badge variant="outline" className={cn("px-1.5 py-0 text-[10px]", it.cls)}>
      {it.label}
    </Badge>
  );
}

/** Session state: active emerald / expired zinc (M07 §4). */
export function SessionStateBadge({ state }: { state: string }) {
  const active = state === "active";
  return (
    <Badge
      variant="outline"
      className={cn(
        "px-1.5 py-0 text-[10px]",
        active
          ? "border-transparent bg-emerald-600 text-white"
          : "border-zinc-300 bg-zinc-100 text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-400",
      )}
    >
      {state}
    </Badge>
  );
}

/** Voucher state: unused emerald / used zinc / expired amber (M07 §4). */
export function VoucherStateBadge({ state }: { state: string }) {
  const map: Record<string, string> = {
    unused: "border-transparent bg-emerald-600 text-white",
    used: "border-zinc-300 bg-zinc-100 text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-400",
    expired: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  };
  return (
    <Badge variant="outline" className={cn("px-1.5 py-0 text-[10px]", map[state] ?? map.used)}>
      {state}
    </Badge>
  );
}

/** Directory source type chip: ldap zinc / ad violet (M07 §4). */
export function DirectoryTypeChip({ type }: { type: string }) {
  const ad = type === "ad";
  return (
    <Badge
      variant="outline"
      className={cn(
        "px-1.5 py-0 text-[10px] uppercase tracking-wide",
        ad
          ? "border-violet-500/40 bg-violet-500/10 text-violet-600 dark:text-violet-400"
          : "border-zinc-300 bg-zinc-50 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300",
      )}
    >
      {type}
    </Badge>
  );
}

/** Inline info note (zinc panel — dns-dhcp-ui flavor). */
export function InfoNote({ children }: { children: React.ReactNode }) {
  return (
    <p className="flex items-start gap-1.5 rounded-md bg-zinc-50 px-2.5 py-2 text-[11px] text-zinc-500 dark:bg-zinc-800/60">
      <Icons.Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
      <span>{children}</span>
    </p>
  );
}

/** Test-result pill for simulated connectivity checks (emerald/rose per §7). */
export function TestResultPill({ ok, label }: { ok: boolean; label: string }) {
  return (
    <Badge
      variant="outline"
      className={cn(
        "gap-1 px-1.5 py-0 text-[10px]",
        ok
          ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
          : "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400",
      )}
    >
      {ok ? <Icons.CheckCircle2 className="h-3 w-3" /> : <Icons.XCircle className="h-3 w-3" />}
      {label}
    </Badge>
  );
}
