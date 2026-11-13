/**
 * realtime-service — socket.io hub, port 3003 (ADR-008, DEVELOPMENT_GUIDE §10).
 *
 * - Own bun project; binds 0.0.0.0; prints its listening line at boot.
 * - NO database connection: polls the Next internal route
 *   GET /api/internal/events?cursor=N every 1 s (single-writer to SQLite).
 * - Emits ONLY the locked 7 events (PROJECT_MEMORY §7.3):
 *     metrics:tick · logs:tail · alerts:new · sessions:update · wan:status · vpn:status · config:updated
 * - Channel control (STATE_AND_DATA_FLOW §4):
 *     client → `subscribe { channels: ["metrics","logs","alerts"] }` / `unsubscribe`
 *     channel-gated: metrics/logs/alerts · default room: sessions/wan/vpn/config events.
 */

import { Server } from "socket.io";

const PORT = 3003;
const INTERNAL_BASE = process.env.INTERNAL_BASE ?? "http://127.0.0.1:3000";
const INTERNAL_TOKEN = process.env.INTERNAL_TOKEN ?? "cryptsk-internal";

const CHANNEL_EVENTS: Record<string, string> = {
  metrics: "metrics:tick",
  logs: "logs:tail",
  alerts: "alerts:new",
};

const io = new Server(PORT, {
  host: "0.0.0.0",
  cors: { origin: true, credentials: true },
  serveClient: false,
});

console.log(`realtime-service listening on 3003`);

io.on("connection", (socket) => {
  socket.on("subscribe", (msg: { channels?: string[] }) => {
    for (const ch of msg?.channels ?? []) {
      if (ch in CHANNEL_EVENTS) void socket.join(ch);
    }
  });
  socket.on("unsubscribe", (msg: { channels?: string[] }) => {
    for (const ch of msg?.channels ?? []) {
      if (ch in CHANNEL_EVENTS) void socket.leave(ch);
    }
  });
});

// ── poll loop (1 s) ─────────────────────────────────────────────────────────
let cursor = 0;
let backoff = 1000;

async function poll() {
  try {
    const res = await fetch(`${INTERNAL_BASE}/api/internal/events?cursor=${cursor}`, {
      headers: { "x-internal-token": INTERNAL_TOKEN },
    });
    if (!res.ok) throw new Error(`internal events ${res.status}`);
    const body = (await res.json()) as {
      data?: { events?: Array<{ seq: number; type: string; payload: unknown }>; cursor?: number };
    };
    const events = body?.data?.events ?? [];
    cursor = body?.data?.cursor ?? cursor;
    for (const evt of events) {
      if (evt.type === "metrics:tick") {
        io.to("metrics").emit("metrics:tick", evt.payload);
      } else if (evt.type === "logs:tail") {
        io.to("logs").emit("logs:tail", evt.payload);
      } else if (evt.type === "alerts:new") {
        io.to("alerts").emit("alerts:new", evt.payload);
      } else if (
        evt.type === "sessions:update" ||
        evt.type === "wan:status" ||
        evt.type === "vpn:status" ||
        evt.type === "config:updated"
      ) {
        io.emit(evt.type, evt.payload); // default room for an authenticated session
      }
    }
    backoff = 1000;
  } catch {
    // Next dev server may be restarting — retry with capped backoff
    backoff = Math.min(backoff * 2, 10_000);
  }
}

setInterval(() => void poll(), 1000);
void poll();
