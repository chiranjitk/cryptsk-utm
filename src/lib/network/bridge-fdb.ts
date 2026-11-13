/**
 * Real bridge FDB reads via `bridge fdb show` (iproute2). The M02 §4 MAC tab
 * merges: (1) static config-plane entries (DHCP reservations + bridge
 * membership, from the DB) with (2) dynamic entries — REAL learned FDB rows
 * when the kernel reports them, else the deterministic churn simulator.
 * meta.source: "live" | "simulated" keeps the data origin honest.
 *
 * `bridge fdb show` line shapes:
 *   00:11:22:33:44:55 dev ens34 vlan 1 master br-lan dynamic
 *   33:33:00:00:00:01 dev ens32 vlan 0 self permanent   (own NIC — skipped)
 */

import { hasTool, runTool } from "@/lib/host/tools";

export interface BridgeFdbEntry {
  mac: string;
  vlan: number;
  iface: string;
  type: "dynamic" | "static";
}

/** Parse `bridge fdb show` output → learned entries (master-backed only). */
export function parseBridgeFdb(out: string): BridgeFdbEntry[] {
  const rows: BridgeFdbEntry[] = [];
  for (const raw of out.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    const f = line.split(/\s+/);
    const mac = f[0];
    if (!/^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/.test(mac)) continue;
    let dev: string | null = null;
    let vlan = 1;
    let master: string | null = null;
    let permanent = false;
    let staticFlag = false;
    for (let i = 1; i < f.length; i++) {
      if (f[i] === "dev" && f[i + 1]) dev = f[++i];
      else if (f[i] === "vlan" && f[i + 1]) vlan = Number(f[++i]) || 1;
      else if (f[i] === "vid" && f[i + 1]) vlan = Number(f[++i]) || 1;
      else if (f[i] === "master" && f[i + 1]) master = f[++i];
      else if (f[i] === "permanent") permanent = true;
      else if (f[i] === "static") staticFlag = true;
    }
    if (!dev) continue;
    // entries with a master belong to a bridge FDB; bare `self permanent`
    // entries are the host's own NIC addresses — not learned stations
    if (!master) continue;
    rows.push({
      mac,
      vlan: vlan === 0 ? 1 : vlan, // untagged → default VLAN (engine convention)
      iface: dev,
      type: permanent || staticFlag ? "static" : "dynamic",
    });
  }
  return rows;
}

/** Real kernel FDB dump (available=false when `bridge` is missing). */
export async function readBridgeFdb(): Promise<{ available: boolean; rows: BridgeFdbEntry[] }> {
  if (!(await hasTool("bridge"))) return { available: false, rows: [] };
  const r = await runTool("bridge fdb show 2>/dev/null", 6000);
  if (!r.ok) return { available: true, rows: [] };
  return { available: true, rows: parseBridgeFdb(r.stdout) };
}
