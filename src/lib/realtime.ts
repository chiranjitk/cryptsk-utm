"use client";

/**
 * Realtime client — ADR-008 (socket.io mini-service, port 3003 behind the gateway).
 * LOCKED event set (PROJECT_MEMORY §7.3): metrics:tick, logs:tail, alerts:new,
 * sessions:update, wan:status, vpn:status, config:updated.
 * Connect via relative path + XTransformPort — never an absolute URL or explicit port.
 */

import { io, type Socket } from "socket.io-client";
import { useEffect, useRef } from "react";

let socket: Socket | null = null;

export type RealtimeChannels = Array<"metrics" | "logs" | "alerts" | "sessions" | "config">;

export function getSocket(): Socket {
  if (!socket) {
    socket = io("/", {
      transports: ["websocket", "polling"],
      query: { XTransformPort: "3003" },
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
    });
  }
  return socket;
}

export type MetricsTickPayload = {
  ts: string;
  ifaces: Array<{ name: string; rxKbps: number; txKbps: number }>;
  cpuPct: number;
  memPct: number;
  conntrackCount: number;
};

export type WanStatusPayload = { iface: string; state: string };
export type AlertNewPayload = { id: number; type: string; severity: string; title: string; message?: string | null };
export type VpnStatusPayload = { vpnId: number; status: string; statusMessage?: string | null };
export type ConfigUpdatedPayload = { section: string };
export type LogTailPayload = { kind: "firewall" | "ips"; entry: Record<string, unknown> };
export type SessionsUpdatePayload = { kind: "vpn" | "identity"; count: number };

/**
 * Subscribe to a set of realtime channels while a component is mounted.
 * Handlers are kept in a ref so re-renders never resubscribe.
 */
export function useRealtime(
  channels: RealtimeChannels,
  handlers: {
    onMetricsTick?: (t: MetricsTickPayload) => void;
    onLogsTail?: (l: LogTailPayload) => void;
    onAlertsNew?: (a: AlertNewPayload) => void;
    onSessionsUpdate?: (s: SessionsUpdatePayload) => void;
    onWanStatus?: (w: WanStatusPayload) => void;
    onVpnStatus?: (v: VpnStatusPayload) => void;
    onConfigUpdated?: (c: ConfigUpdatedPayload) => void;
  },
): void {
  const ref = useRef(handlers);
  useEffect(() => {
    ref.current = handlers;
  });
  const key = channels.join(",");

  useEffect(() => {
    const s = getSocket();
    const set = new Set(channels);
    const on = (ev: string, fn: (...args: unknown[]) => void) => s.on(ev, fn);
    const off = (ev: string) => s.off(ev);

    // channel gating (realtime-service): join rooms for channel events;
    // config/status events ride the default room. Re-subscribe on reconnect.
    const join = () => s.emit("subscribe", { channels: [...set] });
    if (s.connected) join();
    s.on("connect", join);

    if (set.has("metrics")) on("metrics:tick", (t) => ref.current.onMetricsTick?.(t as MetricsTickPayload));
    if (set.has("logs")) on("logs:tail", (l) => ref.current.onLogsTail?.(l as LogTailPayload));
    if (set.has("alerts")) on("alerts:new", (a) => ref.current.onAlertsNew?.(a as AlertNewPayload));
    if (set.has("sessions")) on("sessions:update", (x) => ref.current.onSessionsUpdate?.(x as SessionsUpdatePayload));
    if (set.has("config")) on("config:updated", (c) => ref.current.onConfigUpdated?.(c as ConfigUpdatedPayload));
    // status events ride along with their owning channels
    on("wan:status", (w) => ref.current.onWanStatus?.(w as WanStatusPayload));
    on("vpn:status", (v) => ref.current.onVpnStatus?.(v as VpnStatusPayload));

    return () => {
      s.emit("unsubscribe", { channels: [...set] });
      off("connect");
      for (const ev of [
        "metrics:tick", "logs:tail", "alerts:new", "sessions:update",
        "config:updated", "wan:status", "vpn:status",
      ]) off(ev);
    };
  }, [key]);
}

export async function fetchApi<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { ...init, credentials: "same-origin" });
  const json = (await res.json().catch(() => ({}))) as
    | { data: T; meta?: unknown }
    | { error: { code: string; message: string; details?: unknown; requestId?: string } };
  if ("error" in json) throw new Error(json.error.message || json.error.code);
  return json.data;
}
