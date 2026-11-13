/**
 * Engine event bus — in-memory ring of realtime events that the
 * realtime-service polls via GET /api/internal/events?cursor=N
 * (single-writer to SQLite; SIMULATION_LAYER §7).
 * Event names/payloads are LOCKED: PROJECT_MEMORY §7.3.
 */

export interface IfaceTick {
  name: string;
  rxKbps: number;
  txKbps: number;
}

export interface MetricsTick {
  ts: string;
  ifaces: IfaceTick[];
  cpuPct: number;
  memPct: number;
  conntrackCount: number;
}

export interface FirewallLogEntry {
  id?: number;
  ts: string;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: string;
  action: string;
  ruleName: string | null;
  appName: string | null;
  bytes: number;
  packets: number;
  userName: string | null;
}

export interface IpsEventEntry {
  id?: number;
  ts: string;
  srcIp: string | null;
  srcPort: number | null;
  dstIp: string | null;
  dstPort: number | null;
  action: string;
  sid: string | null;
  severity: string;
  category: string | null;
  message: string | null;
}

export interface NotificationEntry {
  id: number;
  type: string;
  severity: string;
  title: string;
  message: string | null;
  sourceModule: string | null;
  createdAt: string;
  isRead: boolean;
}

export type EngineEvent =
  | { seq: number; type: "metrics:tick"; payload: MetricsTick }
  | { seq: number; type: "logs:tail"; payload: { kind: "firewall" | "ips"; entry: FirewallLogEntry | IpsEventEntry } }
  | { seq: number; type: "alerts:new"; payload: { notification: NotificationEntry } }
  | {
      seq: number;
      type: "sessions:update";
      payload: {
        kind: "vpn" | "identity";
        diff: Array<{ id: number; userName?: string | null; status?: string; bytesIn?: number; bytesOut?: number; lastActivity?: string }>;
      };
    }
  | { seq: number; type: "wan:status"; payload: { iface: string; state: "up" | "down" | "degraded"; latencyMs?: number | null } }
  | { seq: number; type: "vpn:status"; payload: { vpnId: number; status: "up" | "down" | "connecting" | "error"; statusMessage?: string } }
  | { seq: number; type: "config:updated"; payload: { section: string } };

const MAX_EVENTS = 1000;

/**
 * Ring state lives on globalThis (same trick as the MockEngine singleton):
 * Next/Turbopack evaluates this module once per bundle graph (instrumentation
 * vs route chunks), and the engine must emit into the SAME ring the
 * /api/internal/events route reads — otherwise the realtime cursor stalls.
 */
const g = globalThis as unknown as {
  __cryptskEventRing?: { events: EngineEvent[]; cursor: number };
};

const state = g.__cryptskEventRing ?? { events: [] as EngineEvent[], cursor: 0 };
g.__cryptskEventRing = state;

export function emitEvent(evt: Omit<EngineEvent, "seq">): EngineEvent {
  state.cursor += 1;
  const full = { ...evt, seq: state.cursor } as EngineEvent;
  state.events.push(full);
  if (state.events.length > MAX_EVENTS) state.events.splice(0, state.events.length - MAX_EVENTS);
  return full;
}

export function eventsSince(cursor: number): { events: EngineEvent[]; cursor: number } {
  if (cursor < 0) cursor = 0;
  const events = state.events.filter((e) => e.seq > cursor);
  return { events, cursor: state.cursor };
}

export function currentCursor(): number {
  return state.cursor;
}
