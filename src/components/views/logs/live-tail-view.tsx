"use client";

/**
 * #/logs/live (M09 §4/§6) — realtime tail over the LOCKED `logs:tail` socket
 * event. Client-side ring buffer capped at 500 (newest top); Pause freezes
 * rendering while the buffer keeps counting (Resume flush-renders); amber
 * "reconnecting" banner tracks the shared socket's connect/disconnect state.
 * Live rows may not exist in the paginated listings yet — expected (M09 §5.5).
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";
import { getSocket, useRealtime, type LogTailPayload } from "@/lib/realtime";
import { ActionBadge, IpsActionBadge, SeverityBadge, fmtTs } from "./logs-ui";

const BUFFER_CAP = 500;

type TailEntry = {
  key: string;
  kind: "firewall" | "ips";
  ts: string;
  action: string | null;
  severity: string | null;
  srcIp: string | null;
  dstIp: string | null;
  app: string | null;
  sid: string | null;
  message: string | null;
};

function toEntry(payload: LogTailPayload, seq: number): TailEntry {
  const e = (payload.entry ?? {}) as Record<string, unknown>;
  const str = (k: string) => (typeof e[k] === "string" ? (e[k] as string) : null);
  const num = (k: string) => (typeof e[k] === "number" ? (e[k] as number) : null);
  return {
    key: `${payload.kind}-${String(e.id ?? "na")}-${seq}`,
    kind: payload.kind,
    ts: str("timestamp") ?? new Date().toISOString(),
    action: str("action"),
    severity: str("severity"),
    srcIp: str("srcIp") ?? str("src_ip"),
    dstIp: str("dstIp") ?? str("dst_ip"),
    app: str("appName"),
    sid: str("sid"),
    message: str("message"),
  };
}

export function LiveTailView() {
  const bufRef = useRef<TailEntry[]>([]);
  const seqRef = useRef(0);
  const pausedRef = useRef(false);
  const missedRef = useRef(0);

  const [rendered, setRendered] = useState<TailEntry[]>([]);
  const [paused, setPaused] = useState(false);
  const [missed, setMissed] = useState(0);
  const [bufCount, setBufCount] = useState(0); // render-safe mirror of bufRef.current.length
  const [kind, setKind] = useState<"all" | "firewall" | "ips">("all");
  const [autoscroll, setAutoscroll] = useState(true);
  const [connected, setConnected] = useState<boolean | null>(null);

  const scrollRef = useRef<HTMLDivElement | null>(null);

  const push = useCallback((payload: LogTailPayload) => {
    seqRef.current += 1;
    const entry = toEntry(payload, seqRef.current);
    bufRef.current = [entry, ...bufRef.current].slice(0, BUFFER_CAP); // ring buffer, newest top
    setBufCount(bufRef.current.length);
    if (pausedRef.current) {
      missedRef.current += 1;
      setMissed(missedRef.current); // buffer keeps counting while paused
    } else {
      setRendered(bufRef.current);
    }
  }, []);

  useRealtime(["logs"], { onLogsTail: push });

  // socket connect/disconnect state (own effect — banner + recovery)
  useEffect(() => {
    const s = getSocket();
    let active = true;
    // initial snapshot deferred off the effect body (setState-in-effect guard)
    const t = setTimeout(() => {
      if (active) setConnected(s.connected);
    }, 0);
    const onConnect = () => setConnected(true);
    const onDisconnect = () => setConnected(false);
    s.on("connect", onConnect);
    s.on("disconnect", onDisconnect);
    return () => {
      active = false;
      clearTimeout(t);
      s.off("connect", onConnect);
      s.off("disconnect", onDisconnect);
    };
  }, []);

  // autoscroll: newest-top, so keep pinned to the top while enabled
  useEffect(() => {
    if (autoscroll && scrollRef.current) scrollRef.current.scrollTop = 0;
  }, [rendered, autoscroll]);

  const togglePause = () => {
    if (paused) {
      // Resume flush-renders everything buffered while paused
      pausedRef.current = false;
      setPaused(false);
      setRendered(bufRef.current);
      missedRef.current = 0;
      setMissed(0);
    } else {
      pausedRef.current = true;
      setPaused(true);
    }
  };

  const clear = () => {
    bufRef.current = [];
    missedRef.current = 0;
    setMissed(0);
    setBufCount(0);
    setRendered([]);
  };

  const visible = useMemo(
    () => rendered.filter((e) => (kind === "all" ? true : e.kind === kind)),
    [rendered, kind],
  );

  return (
    <div className="grid gap-3">
      {/* controls */}
      <div className="no-print flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1.5">
          {(["all", "firewall", "ips"] as const).map((k) => (
            <button
              key={k}
              type="button"
              aria-pressed={kind === k}
              onClick={() => setKind(k)}
              className={cn(
                "rounded-full border px-2.5 py-1 text-xs transition-colors",
                kind === k
                  ? "border-red-600/40 bg-red-600/10 font-medium text-red-700 dark:text-red-500"
                  : "border-zinc-200 text-zinc-500 hover:bg-zinc-100 dark:border-zinc-800 dark:text-zinc-400 dark:hover:bg-zinc-800",
              )}
            >
              {k}
            </button>
          ))}
        </div>
        <Button size="sm" variant={paused ? "default" : "outline"} className="h-8 gap-1.5" onClick={togglePause}>
          {paused ? <Icons.Play className="h-3.5 w-3.5" /> : <Icons.Pause className="h-3.5 w-3.5" />}
          {paused ? `Resume${missed > 0 ? ` (+${missed} missed)` : ""}` : "Pause"}
        </Button>
        <Button size="sm" variant="outline" className="h-8 gap-1.5" onClick={clear}>
          <Icons.Trash2 className="h-3.5 w-3.5" />
          Clear
        </Button>
        <div className="flex items-center gap-2 text-xs text-zinc-500">
          <Switch checked={autoscroll} onCheckedChange={setAutoscroll} aria-label="Autoscroll" />
          autoscroll
        </div>
        <Badge variant="outline" className="border-zinc-300 font-mono text-[11px] text-zinc-500 dark:border-zinc-700">
          {bufCount} / {BUFFER_CAP}
        </Badge>
        <span className="ml-auto flex items-center gap-1.5 text-xs text-zinc-400">
          <span className={cn("h-2 w-2 rounded-full", connected === false ? "bg-rose-500" : connected ? "bg-emerald-500 animate-pulse" : "bg-zinc-400")} />
          {connected === false ? "disconnected" : connected ? "streaming" : "connecting…"}
        </span>
      </div>

      {connected === false && (
        <div className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs font-medium text-amber-600 dark:text-amber-400">
          Live updates paused — reconnecting…
        </div>
      )}

      {/* stream */}
      <div ref={scrollRef} className="h-[calc(100vh-16rem)] min-h-80 overflow-auto rounded-lg border border-zinc-200 bg-white dark:border-zinc-800 dark:bg-zinc-950">
        {visible.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-2 text-center">
            <Icons.Radio className="h-8 w-8 text-zinc-300 dark:text-zinc-700" />
            <p className="text-sm font-medium text-zinc-500">Waiting for events…</p>
            <p className="text-xs text-zinc-400">The engine pushes ~1–3 rows/s over `logs:tail`.</p>
          </div>
        ) : (
          <ul className="divide-y divide-zinc-100 dark:divide-zinc-800/60">
            {visible.map((e) => (
              <li key={e.key} className="flex items-center gap-2 px-3 py-1.5 text-xs hover:bg-red-600/5">
                <span className="w-36 shrink-0 font-mono tabular-nums text-zinc-400">{fmtTs(e.ts)}</span>
                <Badge
                  variant="outline"
                  className={cn(
                    "w-16 justify-center shrink-0 text-[10px] uppercase",
                    e.kind === "firewall"
                      ? "border-red-600/40 bg-red-600/10 text-red-700 dark:text-red-500"
                      : "border-zinc-300 bg-zinc-100 text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800",
                  )}
                >
                  {e.kind === "firewall" ? "fw" : "ips"}
                </Badge>
                {e.kind === "ips" ? (
                  e.action === "suppressed" ? <IpsActionBadge action="suppressed" className="shrink-0" /> : <SeverityBadge severity={e.severity ?? "info"} className="shrink-0" />
                ) : (
                  <ActionBadge action={e.action} className="shrink-0" />
                )}
                <span className="w-56 shrink-0 truncate font-mono text-zinc-600 dark:text-zinc-300">
                  {e.srcIp ?? "—"} → {e.dstIp ?? "—"}
                </span>
                <span className="w-28 shrink-0 truncate text-zinc-500">{e.kind === "ips" ? (e.sid ?? "—") : (e.app ?? "—")}</span>
                <span className="min-w-0 flex-1 truncate text-zinc-600 dark:text-zinc-400">{e.message ?? ""}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
