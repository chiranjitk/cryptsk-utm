/**
 * GET /api/v1/interfaces/{id}/stats — per-iface diagnostics (M02 §4 stats
 * dialog): live rates from the latest REAL metrics tick, windowed totals,
 * REAL error/drop/packet counters from /proc/net/dev deltas in host mode
 * (ADR-021; hash-seeded simulated counters only in ADAPTER_MODE=simulated),
 * and a last-60-ticks sparkline. 404 on unknown id.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { getEngine, getDataPlaneMode } from "@/lib/engine";
import { getHostCollector } from "@/lib/engine/host-collector";
import { hash32 } from "@/lib/network/derived";
import { idParamSchema } from "@/lib/validators/network";

export const dynamic = "force-dynamic";

const WINDOW_TICKS = 300; // ~10 min of the 2 s tick loop
const SPARK_TICKS = 60; // "last 60 ticks" sparkline (M02 §4)
const BYTES_PER_KBPS_PER_TICK = 2 * 125; // kbps → bytes per 2 s tick

export const GET = route({ area: "network" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  const row = await db.networkInterface.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!row) throw ApiError.notFound(`Interface ${id} not found`);

  const engine = getEngine();
  const ring = engine.metricsRing;
  const entryOf = (tick: { ifaces: Array<{ name: string; rxKbps: number; txKbps: number }> }) =>
    tick.ifaces.find((i) => i.name === row.name);

  // rates — latest tick entry for the iface (zeros when the ring is cold)
  const latest = ring.length ? ring[ring.length - 1] : undefined;
  const live = latest ? entryOf(latest) : undefined;

  // sparkline — last 60 ticks, zero-filled when the iface is absent
  const sparkline = ring.slice(-SPARK_TICKS).map((t) => {
    const e = entryOf(t);
    return { ts: t.ts, rxKbps: e?.rxKbps ?? 0, txKbps: e?.txKbps ?? 0 };
  });

  // windowed totals — kbps*125 bytes/s accumulated over the 2 s ticks
  const window = ring.slice(-WINDOW_TICKS);
  const rxBytes = Math.floor(window.reduce((acc, t) => acc + (entryOf(t)?.rxKbps ?? 0) * BYTES_PER_KBPS_PER_TICK, 0));
  const txBytes = Math.floor(window.reduce((acc, t) => acc + (entryOf(t)?.txKbps ?? 0) * BYTES_PER_KBPS_PER_TICK, 0));

  if (getDataPlaneMode() === "host") {
    // REAL counters — /proc/net/dev deltas since collector start (ADR-021)
    const c = getHostCollector().ifaceCounters(row.name);
    return {
      data: {
        id: row.id,
        name: row.name,
        rates: { rxKbps: live?.rxKbps ?? 0, txKbps: live?.txKbps ?? 0 },
        totals: {
          rxBytes,
          txBytes,
          rxPackets: c?.rxPackets ?? Math.floor(rxBytes / 1200),
          txPackets: c?.txPackets ?? Math.floor(txBytes / 1200),
          errors: c?.errors ?? 0,
          drops: c?.drops ?? 0,
        },
        sparkline,
        uptimeSec: engine.uptimeSec,
      },
    };
  }

  // simulated mode — deterministic hash-seeded counters (demo plane only)
  const hash = hash32(row.name);
  const hash2 = hash32(`${row.name}:drops`);

  return {
    data: {
      id: row.id,
      name: row.name,
      rates: { rxKbps: live?.rxKbps ?? 0, txKbps: live?.txKbps ?? 0 },
      totals: {
        rxBytes,
        txBytes,
        rxPackets: Math.floor(rxBytes / 1200),
        txPackets: Math.floor(txBytes / 1200),
        errors: (hash % 40) + Math.floor(window.length / 25),
        drops: (hash2 % 15) + Math.floor(window.length / 40),
      },
      sparkline,
      uptimeSec: engine.uptimeSec,
    },
  };
});
