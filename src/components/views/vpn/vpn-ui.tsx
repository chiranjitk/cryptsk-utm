"use client";

/**
 * Shared UI atoms for the M05 VPN views — canonical badge recipes per M05 §4
 * (tunnel status: up=emerald health, connecting=amber, down=zinc, error=rose;
 * session status: active=emerald, idle=amber, disconnected=zinc).
 * Secrets (privateKey / PSK) render masked with a reveal-eye + generate helper
 * — never printed as plain text by default (M05 §4).
 */

import { useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import * as Icons from "lucide-react";
import { cn } from "@/lib/utils";
import { useRealtime } from "@/lib/realtime";
import type { VpnSessionStatus, VpnStatus, VpnType } from "./vpn-api";

// ── realtime invalidation (scoped per-view, config channel) ─────────────────

const VPN_STATUS_THROTTLE_MS = 2000;

export function useVpnConfigInvalidation(): void {
  const queryClient = useQueryClient();
  const lastStatusAt = useRef(0);
  useRealtime(["config"], {
    onConfigUpdated: (c) => {
      if (c.section === "vpn") void queryClient.invalidateQueries({ queryKey: ["vpn"] });
    },
    // M05 §6: vpn:status drives the tunnel status badges live (throttled)
    onVpnStatus: () => {
      const now = Date.now();
      if (now - lastStatusAt.current < VPN_STATUS_THROTTLE_MS) return;
      lastStatusAt.current = now;
      void queryClient.invalidateQueries({ queryKey: ["vpn", "configs"] });
    },
  });
}

// ── tunnel status badge (M05 §4 recipes) ────────────────────────────────────

const TUNNEL_BADGE: Record<VpnStatus, { cls: string; icon: React.ComponentType<{ className?: string }>; label: string }> = {
  up: { cls: "border-transparent bg-emerald-600 text-white", icon: Icons.ArrowUpRight, label: "up" },
  connecting: { cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400", icon: Icons.LoaderCircle, label: "connecting" },
  down: { cls: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300", icon: Icons.ArrowDownRight, label: "down" },
  error: { cls: "border-transparent bg-rose-600 text-white", icon: Icons.TriangleAlert, label: "error" },
};

export function TunnelStatusBadge({ status, statusMessage, className }: { status: VpnStatus; statusMessage?: string | null; className?: string }) {
  const def = TUNNEL_BADGE[status] ?? TUNNEL_BADGE.down;
  const Icon = def.icon;
  const badge = (
    <Badge variant="outline" className={cn("gap-1 font-medium capitalize", def.cls, className)}>
      <Icon className={cn("h-3 w-3", status === "connecting" && "animate-spin")} />
      {def.label}
    </Badge>
  );
  if (!statusMessage) return badge;
  return (
    <TooltipProvider delayDuration={150}>
      <Tooltip>
        <TooltipTrigger asChild>{badge}</TooltipTrigger>
        <TooltipContent className="max-w-64 text-xs">{statusMessage}</TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

// ── session status badge ────────────────────────────────────────────────────

const SESSION_BADGE: Record<VpnSessionStatus, string> = {
  active: "border-transparent bg-emerald-600 text-white",
  idle: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  disconnected: "border-zinc-300 bg-zinc-100 text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-400",
};

export function SessionStatusBadge({ status, className }: { status: VpnSessionStatus; className?: string }) {
  return (
    <Badge variant="outline" className={cn("font-medium capitalize", SESSION_BADGE[status] ?? SESSION_BADGE.disconnected, className)}>
      {status}
    </Badge>
  );
}

// ── type / subtype chips ────────────────────────────────────────────────────

const TYPE_CHIP: Record<VpnType, { label: string; cls: string }> = {
  wireguard_s2s: { label: "WireGuard s2s", cls: "border-zinc-300 bg-zinc-50 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300" },
  wireguard_remote: { label: "WireGuard remote", cls: "border-zinc-300 bg-zinc-50 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300" },
  ipsec_s2s: { label: "IPSec s2s", cls: "border-zinc-300 bg-zinc-50 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300" },
  ipsec_remote: { label: "IPSec remote", cls: "border-zinc-300 bg-zinc-50 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300" },
  openvpn: { label: "OpenVPN", cls: "border-zinc-300 bg-zinc-50 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300" },
};

export function VpnTypeChip({ type, className }: { type: VpnType; className?: string }) {
  const def = TYPE_CHIP[type] ?? TYPE_CHIP.openvpn;
  return (
    <Badge variant="outline" className={cn("text-[11px]", def.cls, className)}>
      {def.label}
    </Badge>
  );
}

export function SubtypeChip({ type }: { type: VpnType }) {
  const remote = type.endsWith("_remote") || type === "openvpn";
  return (
    <Badge
      variant="outline"
      className={cn(
        "text-[10px] uppercase tracking-wide",
        remote
          ? "border-zinc-500/40 bg-zinc-500/10 text-zinc-600 dark:text-zinc-400"
          : "border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400",
      )}
    >
      {remote ? "remote access" : "site-to-site"}
    </Badge>
  );
}

// ── masked secret field (privateKey / PSK) ──────────────────────────────────

/** Random placeholder key material — SIMULATION_LAYER §9: no real crypto. */
export function generateSecret(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let out = "";
  for (let i = 0; i < 44; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return `${out}==`;
}

export function SecretField(props: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  generate?: boolean;
  id?: string;
}) {
  const [show, setShow] = useState(false);
  return (
    <div className="flex items-center gap-1.5">
      <Input
        id={props.id}
        type={show ? "text" : "password"}
        value={props.value}
        placeholder={props.placeholder ?? "secret"}
        autoComplete="off"
        onChange={(e) => props.onChange(e.target.value)}
        className="font-mono text-xs"
      />
      <Button
        type="button"
        variant="outline"
        size="icon"
        className="h-9 w-9 shrink-0"
        aria-label={show ? "Hide secret" : "Reveal secret"}
        onClick={() => setShow((s) => !s)}
      >
        {show ? <Icons.EyeOff className="h-4 w-4" /> : <Icons.Eye className="h-4 w-4" />}
      </Button>
      {props.generate ? (
        <Button
          type="button"
          variant="outline"
          size="icon"
          className="h-9 w-9 shrink-0"
          aria-label="Generate secret"
          title="Generate placeholder key (simulated)"
          onClick={() => props.onChange(generateSecret())}
        >
          <Icons.Wand2 className="h-4 w-4" />
        </Button>
      ) : null}
    </div>
  );
}

// ── CIDR list editor (allowedIps / *Subnets) ────────────────────────────────

export function CidrListEditor(props: {
  values: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  addLabel?: string;
}) {
  const [draft, setDraft] = useState("");
  const add = () => {
    const v = draft.trim();
    if (!v || props.values.includes(v)) {
      setDraft("");
      return;
    }
    props.onChange([...props.values, v]);
    setDraft("");
  };
  return (
    <div className="space-y-1.5">
      <div className="flex items-center gap-1.5">
        <Input
          value={draft}
          placeholder={props.placeholder ?? "10.20.0.0/16"}
          className="h-9 font-mono text-xs"
          onChange={(e) => setDraft(e.target.value)}
          onBlur={() => {
            // commit a typed-but-unconfirmed entry so save never silently drops it
            if (draft.trim()) add();
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              add();
            }
          }}
        />
        <Button type="button" variant="outline" size="sm" className="h-9 shrink-0 gap-1" onClick={add}>
          <Icons.Plus className="h-3.5 w-3.5" /> {props.addLabel ?? "Add"}
        </Button>
      </div>
      {props.values.length > 0 ? (
        <div className="flex flex-wrap gap-1">
          {props.values.map((v) => (
            <Badge key={v} variant="outline" className="gap-1 border-zinc-300 pr-1 font-mono text-[11px] dark:border-zinc-700">
              {v}
              <button
                type="button"
                aria-label={`Remove ${v}`}
                className="ml-0.5 rounded-sm p-0.5 hover:bg-zinc-200 dark:hover:bg-zinc-700"
                onClick={() => props.onChange(props.values.filter((x) => x !== v))}
              >
                <Icons.X className="h-3 w-3" />
              </button>
            </Badge>
          ))}
        </div>
      ) : (
        <p className="text-[11px] text-zinc-400">No entries yet.</p>
      )}
    </div>
  );
}

// ── member tag input (VpnUserGroup.memberUsernames) ─────────────────────────

export function TagInput(props: {
  values: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  suggestions?: string[];
}) {
  const [draft, setDraft] = useState("");
  const add = (raw: string) => {
    const v = raw.trim();
    if (!v || props.values.includes(v)) return;
    props.onChange([...props.values, v]);
  };
  const pendingSuggestions = (props.suggestions ?? []).filter((s) => !props.values.includes(s)).slice(0, 6);
  return (
    <div className="space-y-1.5">
      <div className="flex flex-wrap items-center gap-1.5 rounded-md border border-zinc-200 p-2 dark:border-zinc-800">
        {props.values.map((v) => (
          <Badge key={v} variant="outline" className="gap-1 border-red-600/40 bg-red-600/10 pr-1 text-red-700 dark:text-red-500">
            {v}
            <button
              type="button"
              aria-label={`Remove ${v}`}
              className="ml-0.5 rounded-sm p-0.5 hover:bg-red-600/20"
              onClick={() => props.onChange(props.values.filter((x) => x !== v))}
            >
              <Icons.X className="h-3 w-3" />
            </button>
          </Badge>
        ))}
        <Input
          value={draft}
          placeholder={props.placeholder ?? "username + Enter"}
          className="h-7 min-w-32 flex-1 border-0 bg-transparent p-0 text-xs shadow-none focus-visible:ring-0 dark:bg-transparent"
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              add(draft);
              setDraft("");
            }
          }}
          onBlur={() => {
            if (draft.trim()) {
              add(draft);
              setDraft("");
            }
          }}
        />
      </div>
      {pendingSuggestions.length > 0 ? (
        <div className="flex flex-wrap items-center gap-1">
          <span className="text-[11px] text-zinc-400">Seen on live sessions:</span>
          {pendingSuggestions.map((s) => (
            <button
              key={s}
              type="button"
              className="rounded-full border border-zinc-200 px-2 py-0.5 text-[11px] text-zinc-500 hover:bg-zinc-100 dark:border-zinc-800 dark:hover:bg-zinc-800"
              onClick={() => add(s)}
            >
              + {s}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}
