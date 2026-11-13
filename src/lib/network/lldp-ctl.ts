/**
 * Real LLDP neighbor collection via `lldpctl` (lldpd). The M02 §4 LLDP tab
 * falls back to the deterministic churn simulator when lldpd is not installed
 * on the host — the route layer marks the data source honestly
 * (meta.source: "live" | "simulated").
 *
 * lldpctl -f keyvalue emits `lldp.<localIf>.<path>=<value>` lines:
 *   lldp.eth0.chassis.name=core-sw-01
 *   lldp.eth0.chassis.id.MAC=00:11:22:33:44:55
 *   lldp.eth0.port.ifname=Gi0/1
 *   lldp.eth0.port.desc=Uplink to core
 *   lldp.eth0.chassis.cap.available=Router,Switch
 */

import { hasTool, runTool } from "@/lib/host/tools";

export interface LldpCtlNeighbor {
  localIface: string;
  chassisId: string;
  systemName: string;
  portId: string;
  portDesc: string | null;
  capabilities: string[];
  lastSeenSec: number;
}

/** Parse `lldpctl -f keyvalue` output into per-neighbor rows. */
export function parseLldpKeyValue(out: string): LldpCtlNeighbor[] {
  // group key/value pairs by local interface
  const byIface = new Map<string, Map<string, string>>();
  for (const raw of out.split("\n")) {
    const line = raw.trim();
    if (!line.startsWith("lldp.")) continue;
    const eq = line.indexOf("=");
    if (eq < 0) continue;
    const keyPath = line.slice(5, eq); // strip "lldp."
    const value = line.slice(eq + 1);
    // first segment = local iface
    const dot = keyPath.indexOf(".");
    if (dot < 0) continue;
    const iface = keyPath.slice(0, dot);
    const path = keyPath.slice(dot + 1);
    if (!byIface.has(iface)) byIface.set(iface, new Map());
    byIface.get(iface)!.set(path, value);
  }

  const rows: LldpCtlNeighbor[] = [];
  for (const [iface, kv] of byIface) {
    // chassis.id.<type> (MAC/ifname/local/…) — value is the chassis id
    let chassisId: string | null = null;
    for (const [k, v] of kv) {
      if (k.startsWith("chassis.id.") && v) {
        chassisId = v;
        break;
      }
    }
    const systemName = kv.get("chassis.name") ?? null;
    const portId = kv.get("port.ifname") ?? kv.get("port.id") ?? null;
    // a neighbor without chassis id AND without system name is unusable
    if (!chassisId && !systemName) continue;

    const capsRaw = kv.get("chassis.cap.enabled") ?? kv.get("chassis.cap.available") ?? "";
    const capabilities = capsRaw
      .split(",")
      .map((c) => c.trim())
      .filter(Boolean);

    rows.push({
      localIface: iface,
      chassisId: chassisId ?? "(unknown)",
      systemName: systemName ?? "(unnamed)",
      portId: portId ?? "(unknown)",
      portDesc: kv.get("port.desc") ?? null,
      capabilities,
      lastSeenSec: 0, // lldpctl reports current state — neighbor is fresh now
    });
  }
  return rows;
}

/** Real neighbor dump (null rows / available=false when lldpctl is missing). */
export async function readLldpNeighborsReal(): Promise<{ available: boolean; rows: LldpCtlNeighbor[] }> {
  if (!(await hasTool("lldpctl"))) return { available: false, rows: [] };
  const r = await runTool("lldpctl -f keyvalue 2>/dev/null", 6000);
  if (!r.ok) return { available: true, rows: [] };
  return { available: true, rows: parseLldpKeyValue(r.stdout) };
}
