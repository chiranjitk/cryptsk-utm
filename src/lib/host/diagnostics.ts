/**
 * Host diagnostics — vendor-style interface diagnostics read straight from
 * /proc (arp, routes, counters) plus a hard-capped ping tool (pfSense
 * Diagnostics > Ping parity). All reads are unprivileged; ping is gated by
 * hasTool and audited at the route layer.
 */

import { readFile } from "fs/promises";
import { hasTool, runTool } from "./tools";

// ── ARP / neighbor cache (/proc/net/arp) ────────────────────────────────────

export interface ArpEntry {
  ip: string;
  mac: string | null;
  device: string;
  /** 0x2 = complete, 0x0 = incomplete (pending/resolving) */
  complete: boolean;
}

export async function readArp(): Promise<ArpEntry[]> {
  const raw = await readFile("/proc/net/arp", "utf8").catch(() => "");
  const out: ArpEntry[] = [];
  for (const line of raw.split("\n").slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 6 || !/^(\d{1,3}\.){3}\d{1,3}$/.test(f[0])) continue;
    const flags = f[2];
    out.push({
      ip: f[0],
      mac: /^[0-9a-fA-F:]{17}$/.test(f[3]) ? f[3] : null,
      device: f[5],
      complete: flags !== "0x0",
    });
  }
  return out;
}

// ── IPv4 route table (/proc/net/route — hex little-endian fields) ───────────

export interface RouteEntry {
  iface: string;
  destination: string;
  gateway: string;
  mask: string;
  metric: number;
  isDefault: boolean;
}

function hexToIp(hex: string): string {
  const n = parseInt(hex, 16);
  if (!Number.isFinite(n)) return "—";
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join(".");
}

export async function readRoutes(): Promise<RouteEntry[]> {
  const raw = await readFile("/proc/net/route", "utf8").catch(() => "");
  const out: RouteEntry[] = [];
  for (const line of raw.split("\n").slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 8) continue;
    const destination = hexToIp(f[1]);
    const gateway = hexToIp(f[2]);
    const mask = hexToIp(f[7]);
    out.push({
      iface: f[0],
      destination,
      gateway: f[2] === "00000000" ? "—" : gateway,
      mask: f[7] === "00000000" ? "0.0.0.0" : mask,
      metric: Number(f[6] ?? 0) || 0,
      isDefault: f[1] === "00000000" && f[7] === "00000000",
    });
  }
  return out;
}

// ── per-interface counters snapshot (/proc/net/dev via proc.ts) ─────────────

export { readNetDev } from "./proc";
export type { NetDevSample } from "./proc";

// ── scoped ping (pfSense Diagnostics > Ping parity) ─────────────────────────

const HOSTNAME_RE = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

export interface PingResult {
  ok: boolean;
  output: string;
  lossPct: number | null;
  avgMs: number | null;
  error?: string;
}

/** Run a bounded ping: count<=4, 1s per-packet wait, optional source interface. */
export async function runDiagPing(host: string, iface?: string, count = 3): Promise<PingResult> {
  const h = host.trim();
  const n = Math.min(Math.max(1, Math.floor(count)), 4);
  if (!/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(h) && !HOSTNAME_RE.test(h)) {
    return { ok: false, output: "", lossPct: null, avgMs: null, error: "Invalid host (use an IPv4 or hostname)" };
  }
  if (iface && !/^[a-z0-9.-]{1,15}$/i.test(iface)) {
    return { ok: false, output: "", lossPct: null, avgMs: null, error: "Invalid interface name" };
  }
  if (!(await hasTool("ping"))) {
    return { ok: false, output: "", lossPct: null, avgMs: null, error: "'ping' is not available on this host" };
  }
  const cmd = `ping -c ${n} -W 1${iface ? ` -I ${JSON.stringify(iface)}` : ""} ${JSON.stringify(h)} 2>&1`;
  const r = await runTool(cmd, 9000);
  // parse "X packets transmitted, Y received, Z% packet loss" + "min/avg/max"
  let lossPct: number | null = null;
  let avgMs: number | null = null;
  const lossMatch = r.stdout.match(/([\d.]+)% packet loss/);
  if (lossMatch) lossPct = Number(lossMatch[1]);
  const avgMatch = r.stdout.match(/= [\d./]+\/([\d.]+)\//);
  if (avgMatch) avgMs = Number(avgMatch[1]);
  return {
    ok: r.ok && lossPct !== 100,
    output: (r.stdout || r.stderr || r.error || "").slice(-4000),
    lossPct,
    avgMs,
  };
}
