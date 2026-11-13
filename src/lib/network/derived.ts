/**
 * Derived engine views (M02 §4 tabs 2–3) — LLDP neighbor table + MAC/FDB.
 * Not persisted: computed per request from a deterministic, time-bucketed
 * PRNG (SIMULATION_LAYER §6) so responses are stable within a churn window
 * (30 s for LLDP, 60 s for the FDB) and re-churn when the bucket rolls.
 */

import { db } from "@/lib/db";
import { parseJson } from "@/lib/json";

/** FNV-1a 32-bit string hash — deterministic seed helper for engine views. */
export function hash32(str: string): number {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function mulberry32(seed: number) {
  let a = seed >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Locally-administered, unicast MAC from the PRNG stream. */
function macLike(rand: () => number): string {
  const bytes = Array.from({ length: 6 }, () => Math.floor(rand() * 256));
  bytes[0] = (bytes[0] & 0xfe) | 0x02;
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join(":");
}

// ── LLDP neighbors (churn window: 30 s) ─────────────────────────────────────

export interface LldpNeighbor {
  localIface: string;
  chassisId: string;
  systemName: string;
  portId: string;
  portDesc: string;
  capabilities: string[];
  lastSeenSec: number;
}

const LLDP_SYSTEM_NAMES = ["core-sw-01", "edge-rtr-02", "uplink-modem", "lab-switch"];
const LLDP_PORT_DESCS = ["Uplink to core", "Server access port", "WAN handoff", "Lab access trunk"];
const LLDP_CAPABILITIES = ["Router", "Switch", "WLAN", "Station", "Bridge"];

export async function lldpNeighbors(tenantId: number, engineTickSeed = 0): Promise<LldpNeighbor[]> {
  const rows = await db.networkInterface.findMany({ where: { tenantId } });
  const tickBucket = Math.floor(Date.now() / 30000); // churn window: 30 s
  const out: LldpNeighbor[] = [];

  for (const row of rows) {
    // lldpd runs on physical ifaces unless config.lldp is off (M02 §4/§5)
    if (row.type !== "physical" || !row.enabled) continue;
    const cfg = parseJson<unknown>(row.config, {});
    if (!cfg || typeof cfg !== "object" || (cfg as Record<string, unknown>).lldp === false) continue;

    const rand = mulberry32(((tickBucket * 2654435761) ^ hash32(row.name) ^ engineTickSeed) >>> 0);
    const count = Math.floor(rand() * 3); // 0–2 neighbors per eligible iface
    for (let i = 0; i < count; i++) {
      const systemName = LLDP_SYSTEM_NAMES[Math.floor(rand() * LLDP_SYSTEM_NAMES.length)];
      const portId = rand() < 0.5 ? `Gi0/${1 + Math.floor(rand() * 24)}` : `eth${Math.floor(rand() * 8)}`;
      const portDesc = LLDP_PORT_DESCS[Math.floor(rand() * LLDP_PORT_DESCS.length)];
      const caps = LLDP_CAPABILITIES.filter(() => rand() < 0.4);
      out.push({
        localIface: row.name,
        chassisId: macLike(rand),
        systemName,
        portId,
        portDesc,
        capabilities: caps.length ? caps : ["Bridge"],
        lastSeenSec: 5 + Math.floor(rand() * 24), // 5–28 s ago
      });
    }
  }
  return out;
}

// ── MAC/FDB table (churn window: 60 s) ──────────────────────────────────────

export interface MacEntry {
  mac: string;
  vlan: number;
  iface: string;
  type: "dynamic" | "static";
  ageSec: number;
}

/** Deterministic member MAC — used for static bridge-membership FDB rows. */
export function derivedMac(name: string): string {
  const h = hash32(name);
  const bytes = [
    h & 0xff,
    (h >>> 8) & 0xff,
    (h >>> 16) & 0xff,
    (h >>> 24) & 0xff,
    (h ^ 0x9e3779b9) & 0xff,
    ((h >>> 8) ^ 0x85ebca6b) & 0xff,
  ];
  bytes[0] = (bytes[0] & 0xfe) | 0x02;
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join(":");
}

export async function macTable(tenantId: number): Promise<MacEntry[]> {
  const [ifaces, subnets] = await Promise.all([
    db.networkInterface.findMany({ where: { tenantId } }),
    db.dhcpSubnet.findMany({ where: { tenantId }, include: { reservations: true } }),
  ]);
  const byName = new Map(ifaces.map((i) => [i.name, i]));
  const out: MacEntry[] = [];

  // static — DHCP reservations surface on the owning subnet iface (M02 §4 tab 3)
  for (const s of subnets) {
    for (const r of s.reservations) {
      const iface = byName.get(s.interfaceName);
      const vlan = iface?.type === "vlan" && iface.vlanId ? iface.vlanId : 1;
      out.push({ mac: r.mac, vlan, iface: s.interfaceName, type: "static", ageSec: 0 });
    }
  }

  // static — bridge membership (member ifaces learned on every bridge)
  for (const b of ifaces) {
    if (b.type !== "bridge") continue;
    const cfg = parseJson<unknown>(b.config, {});
    const members =
      cfg && typeof cfg === "object" && Array.isArray((cfg as Record<string, unknown>).members)
        ? ((cfg as Record<string, unknown>).members as unknown[]).filter(
            (m): m is string => typeof m === "string",
          )
        : [];
    for (const m of members) {
      out.push({ mac: derivedMac(m), vlan: 1, iface: m, type: "static", ageSec: 0 });
    }
  }

  // dynamic — LAN-carrying ifaces learn hosts (60 s churn bucket)
  const bucket = Math.floor(Date.now() / 60000);
  for (const row of ifaces) {
    if (row.type !== "physical" && row.type !== "vlan") continue;
    if (!row.enabled || !["lan", "dmz", "mgmt"].includes(row.role)) continue;
    const vlan = row.type === "vlan" && row.vlanId ? row.vlanId : 1;
    const rand = mulberry32(((bucket * 2654435761) ^ hash32(row.name)) >>> 0);
    const count = 3 + Math.floor(rand() * 10); // 3–12 entries per iface
    for (let i = 0; i < count; i++) {
      out.push({
        mac: macLike(rand),
        vlan,
        iface: row.name,
        type: "dynamic",
        ageSec: 10 + Math.floor(rand() * 291), // 10–300 s
      });
    }
  }

  // static first, then by MAC (M02 §4 tab 3)
  out.sort((a, b) => (a.type === b.type ? a.mac.localeCompare(b.mac) : a.type === "static" ? -1 : 1));
  return out;
}
