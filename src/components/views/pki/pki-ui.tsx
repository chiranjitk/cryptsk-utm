"use client";

/**
 * Shared PKI atoms (M14) — badges/pills composed from shadcn primitives.
 * Blue & enterprise theme (ADR-019 style): root CA = solid blue, subordinate
 * = outline, active = blue soft, revoked = rose solid, expired = rose
 * outline. Expiry pills: blue >90d, amber 31–90d, red ≤30d / expired.
 */

import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import * as Icons from "lucide-react";
import { cn } from "@/lib/utils";
import { fmtDate } from "./pki-api";

// ── status / type badges ────────────────────────────────────────────────────

export function PkiStatusBadge({ status, className }: { status: "active" | "revoked" | "expired"; className?: string }) {
  if (status === "active") {
    return (
      <Badge variant="outline" className={cn("gap-1 border-red-600/40 bg-red-600/10 text-red-700 dark:text-red-500", className)}>
        <Icons.ShieldCheck className="h-3 w-3" /> active
      </Badge>
    );
  }
  if (status === "revoked") {
    return (
      <Badge variant="outline" className={cn("gap-1 border-transparent bg-rose-600 text-white", className)}>
        <Icons.Ban className="h-3 w-3" /> revoked
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className={cn("gap-1 border-rose-600/60 bg-transparent text-rose-500", className)}>
      <Icons.CalendarX2 className="h-3 w-3" /> expired
    </Badge>
  );
}

export function CaTypeBadge({ type }: { type: "root" | "subordinate" }) {
  return type === "root" ? (
    <Badge className="bg-red-700 text-white hover:bg-red-700">
      <Icons.Landmark className="mr-1 h-3 w-3" /> root
    </Badge>
  ) : (
    <Badge variant="outline" className="border-zinc-300 text-zinc-600 dark:border-zinc-700 dark:text-zinc-300">
      <Icons.Network className="mr-1 h-3 w-3" /> subordinate
    </Badge>
  );
}

const CERT_TYPE_CLS: Record<string, string> = {
  server: "border-red-600/40 bg-red-600/10 text-red-700 dark:text-red-500",
  client: "border-zinc-300 bg-transparent text-zinc-600 dark:border-zinc-700 dark:text-zinc-300",
  device: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  user: "border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400",
};

export function CertTypeBadge({ type }: { type: string }) {
  return (
    <Badge variant="outline" className={cn("font-medium capitalize", CERT_TYPE_CLS[type] ?? CERT_TYPE_CLS.client)}>
      {type}
    </Badge>
  );
}

export function IssuedForChip({ issuedFor }: { issuedFor: string }) {
  return (
    <Badge
      variant="outline"
      className="border-zinc-300 bg-zinc-100 text-[10px] uppercase tracking-wide text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
    >
      {issuedFor.replace(/_/g, " ")}
    </Badge>
  );
}

// ── expiry pill ─────────────────────────────────────────────────────────────

export function ExpiryPill({
  notAfter,
  daysUntilExpiry,
  status,
}: {
  notAfter: string | null;
  daysUntilExpiry: number | null;
  status: "active" | "revoked" | "expired";
}) {
  const expired = status === "expired";
  const tone =
    expired || daysUntilExpiry === null || daysUntilExpiry <= 30
      ? "border-rose-600/40 bg-rose-600/10 text-rose-600 dark:text-rose-400"
      : daysUntilExpiry <= 90
        ? "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400"
        : "border-red-600/40 bg-red-600/10 text-red-700 dark:text-red-500";
  const label = expired ? "expired" : daysUntilExpiry === null ? "no expiry" : `${daysUntilExpiry}d left`;
  return (
    <TooltipProvider delayDuration={150}>
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="inline-flex cursor-default flex-col items-start">
            <span className="text-xs font-medium">{fmtDate(notAfter)}</span>
            <Badge variant="outline" className={cn("mt-0.5 gap-1 text-[10px]", tone)}>
              <Icons.Clock className="h-3 w-3" />
              {label}
            </Badge>
          </span>
        </TooltipTrigger>
        <TooltipContent className="text-xs">
          {expired ? "Validity ended" : daysUntilExpiry === null ? "No validity window set" : `${daysUntilExpiry} day(s) until expiry`}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

// ── SAN chips (max 2 + "+N") ────────────────────────────────────────────────

export function SansChips({ sans, max = 2 }: { sans: string[]; max?: number }) {
  if (sans.length === 0) return <span className="text-xs text-zinc-400">—</span>;
  const shown = sans.slice(0, max);
  const rest = sans.length - shown.length;
  return (
    <div className="flex flex-wrap items-center gap-1">
      {shown.map((s) => (
        <Badge key={s} variant="outline" className="max-w-40 truncate border-red-600/40 bg-red-600/10 font-mono text-[10px] font-normal text-red-700 dark:text-red-500">
          {s}
        </Badge>
      ))}
      {rest > 0 && (
        <TooltipProvider delayDuration={150}>
          <Tooltip>
            <TooltipTrigger asChild>
              <Badge variant="outline" className="border-zinc-300 text-[10px] text-zinc-500 dark:border-zinc-700">
                +{rest}
              </Badge>
            </TooltipTrigger>
            <TooltipContent className="max-w-64 break-all text-xs">{sans.slice(max).join(", ")}</TooltipContent>
          </Tooltip>
        </TooltipProvider>
      )}
    </div>
  );
}
