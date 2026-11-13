/**
 * Host diagnostics — vendor-style interface diagnostics read straight from
 * /proc (arp, routes, counters) plus a hard-capped ping tool (pfSense
 * Diagnostics > Ping parity). All reads are unprivileged; ping is gated by
 * hasTool and audited at the route layer.
 */

import { readFile } from "fs/promises";
import net from "net";
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

/**
 * Run a bounded ping: count<=4, 1s per-packet wait, optional source interface.
 * `size` (payload bytes) + `df` enable path-MTU discovery (ping -M do -s N) —
 * enterprise MTU diagnostics parity.
 */
export async function runDiagPing(host: string, iface?: string, count = 3, size?: number, df?: boolean): Promise<PingResult> {
  const h = host.trim();
  const n = Math.min(Math.max(1, Math.floor(count)), 4);
  if (!/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(h) && !HOSTNAME_RE.test(h)) {
    return { ok: false, output: "", lossPct: null, avgMs: null, error: "Invalid host (use an IPv4 or hostname)" };
  }
  if (iface && !/^[a-z0-9.-]{1,15}$/i.test(iface)) {
    return { ok: false, output: "", lossPct: null, avgMs: null, error: "Invalid interface name" };
  }
  const sz = size != null && Number.isFinite(size) ? Math.min(Math.max(0, Math.floor(size)), 1472) : null;
  const dfOn = df === true || (sz != null && sz > 0 && df === undefined);
  if (!(await hasTool("ping"))) {
    return { ok: false, output: "", lossPct: null, avgMs: null, error: "'ping' is not available on this host" };
  }
  const dfFlags = dfOn && sz != null && sz > 0 ? ` -M do -s ${sz}` : "";
  const cmd = `ping -c ${n} -W 1${iface ? ` -I ${JSON.stringify(iface)}` : ""}${dfFlags} ${JSON.stringify(h)} 2>&1`;
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

// ── traceroute (pfSense Diagnostics > Traceroute parity) ────────────────────

export interface TracerouteHop {
  hop: number;
  ip: string | null;
  /** best rtt of the probe set, ms (null = timeout/star) */
  ms: number | null;
}

export interface TracerouteResult {
  ok: boolean;
  hops: TracerouteHop[];
  output: string;
  tool: "traceroute" | "tracepath" | null;
  error?: string;
}

function parseTracerouteHops(out: string): TracerouteHop[] {
  const hops: TracerouteHop[] = [];
  for (const line of out.split("\n")) {
    const m = /^\s*(\d{1,2})[:.\s]+(.*)$/.exec(line);
    if (!m) continue;
    const hop = Number(m[1]);
    const rest = m[2];
    // numeric probes: "10.0.0.1  0.4 ms 0.3 ms 0.3 ms" | stars: "* * *"
    const ipMatch = /(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{2,39})/.exec(rest);
    const rttMatch = /([\d.]+)\s*ms/.exec(rest);
    const star = /^\s*\*\s*(\*\s*)*$/.test(rest);
    hops.push({
      hop,
      ip: star || !ipMatch ? null : ipMatch[1],
      ms: rttMatch ? Number(rttMatch[1]) : null,
    });
  }
  return hops;
}

/** Parse tracepath -n output ("1: gw 0.3ms" / "2: 10.9.9.9 4.1ms reached"). */
function parseTracepathHops(out: string): TracerouteHop[] {
  const hops: TracerouteHop[] = [];
  for (const line of out.split("\n")) {
    const m = /^\s*(\d{1,2}):\s+(\S+)\s+([\d.]+)?\s*ms?/i.exec(line);
    if (!m) continue;
    const ipLike = /^(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{2,39})$/.test(m[2]);
    hops.push({ hop: Number(m[1]), ip: ipLike ? m[2] : null, ms: m[3] ? Number(m[3]) : null });
  }
  return hops;
}

/**
 * Bounded traceroute: numeric output (-n), 1 probe per hop, maxHops<=15,
 * 9 s ceiling. Prefers `traceroute`, falls back to `tracepath` (no iface
 * binding on tracepath — surfaced honestly via `tool`).
 */
export async function runDiagTraceroute(host: string, iface?: string, maxHops = 10): Promise<TracerouteResult> {
  const h = host.trim();
  if (!/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(h) && !HOSTNAME_RE.test(h)) {
    return { ok: false, hops: [], output: "", tool: null, error: "Invalid host (use an IPv4 or hostname)" };
  }
  if (iface && !/^[a-z0-9.-]{1,15}$/i.test(iface)) {
    return { ok: false, hops: [], output: "", tool: null, error: "Invalid interface name" };
  }
  const hops = Math.min(Math.max(1, Math.floor(maxHops)), 15);

  if (await hasTool("traceroute")) {
    const cmd = `traceroute -n -q 1 -w 2 -m ${hops}${iface ? ` -i ${JSON.stringify(iface)}` : ""} ${JSON.stringify(h)} 2>&1`;
    const r = await runTool(cmd, 9000);
    return {
      ok: r.ok,
      hops: parseTracerouteHops(r.stdout),
      output: (r.stdout || r.stderr || r.error || "").slice(-4000),
      tool: "traceroute",
    };
  }
  if (await hasTool("tracepath")) {
    const cmd = `tracepath -n -m ${hops} ${JSON.stringify(h)} 2>&1`;
    const r = await runTool(cmd, 9000);
    return {
      ok: r.ok,
      hops: parseTracepathHops(r.stdout),
      output: (r.stdout || r.stderr || r.error || "").slice(-4000),
      tool: "tracepath",
    };
  }
  return { ok: false, hops: [], output: "", tool: null, error: "neither 'traceroute' nor 'tracepath' is available on this host" };
}

// ── DNS lookup (pfSense Diagnostics > DNS Lookup parity) ────────────────────

export interface DnsLookupResult {
  ok: boolean;
  /** A/AAAA answers (IPv4 + IPv6) */
  addresses: string[];
  server: string | null;
  tool: "dig" | "host" | "nslookup" | null;
  output: string;
  error?: string;
}

function parseDigAddresses(out: string): string[] {
  return out
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => /^(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{6,39})$/.test(l));
}

/** `host` fallback output — "name has address 1.2.3.4" / "has IPv6 address ::1". */
function parseHostAddresses(out: string): string[] {
  return [...out.matchAll(/has (?:IPv6 |address )(\S+)/g)].map((m) => m[1]).filter((a) => /^(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{6,39})$/.test(a));
}

/** nslookup fallback — "Address: 1.2.3.4" (skip the resolver banner line). */
function parseNslookupAddresses(out: string): string[] {
  const out2: string[] = [];
  let first = true;
  for (const line of out.split("\n")) {
    const m = /^\s*Address:\s*(\S+)/.exec(line);
    if (!m) continue;
    if (first) {
      first = false; // nslookup prints the resolver's own address first
      continue;
    }
    if (/^(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{6,39})$/.test(m[1])) out2.push(m[1]);
  }
  return out2;
}

/** Resolve a name via dig → host → nslookup (first available binary wins). */
export async function runDiagDnsLookup(name: string, server?: string): Promise<DnsLookupResult> {
  const n = name.trim().replace(/\.$/, "");
  if (!HOSTNAME_RE.test(n) || n.length > 253) {
    return { ok: false, addresses: [], server: server ?? null, tool: null, output: "", error: "Invalid hostname" };
  }
  let srv: string | null = null;
  if (server && server.trim() !== "") {
    const s = server.trim();
    if (!/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(s)) {
      return { ok: false, addresses: [], server: null, tool: null, output: "", error: "DNS server must be an IPv4 address" };
    }
    srv = s;
  }

  if (await hasTool("dig")) {
    // some dig builds reject two type args with +short — query A then AAAA
    const serverArg = srv ? ` @${JSON.stringify(srv)}` : "";
    const a = await runTool(`dig +short +time=2 +tries=1${serverArg} ${JSON.stringify(n)} A 2>&1`, 6000);
    const aaaa = await runTool(`dig +short +time=2 +tries=1${serverArg} ${JSON.stringify(n)} AAAA 2>&1`, 6000);
    const addresses = [...parseDigAddresses(a.stdout), ...parseDigAddresses(aaaa.stdout)];
    return {
      ok: addresses.length > 0,
      addresses,
      server: srv,
      tool: "dig",
      output: `${a.stdout}${aaaa.stdout}${a.error || aaaa.error || ""}`.slice(-4000),
    };
  }
  if (await hasTool("host")) {
    const cmd = `host -W 2${srv ? ` ${JSON.stringify(srv)}` : ""} ${JSON.stringify(n)} 2>&1`;
    const r = await runTool(cmd, 6000);
    const addresses = parseHostAddresses(r.stdout);
    return {
      ok: r.ok && addresses.length > 0,
      addresses,
      server: srv,
      tool: "host",
      output: (r.stdout || r.stderr || r.error || "").slice(-4000),
    };
  }
  if (await hasTool("nslookup")) {
    const cmd = `nslookup${srv ? ` ${JSON.stringify(n)} ${JSON.stringify(srv)}` : ` ${JSON.stringify(n)}`} 2>&1`;
    const r = await runTool(cmd, 6000);
    const addresses = parseNslookupAddresses(r.stdout);
    return {
      ok: addresses.length > 0,
      addresses,
      server: srv,
      tool: "nslookup",
      output: (r.stdout || r.stderr || r.error || "").slice(-4000),
    };
  }
  return { ok: false, addresses: [], server: srv, tool: null, output: "", error: "no DNS client (dig/host/nslookup) on this host" };
}

// ── TCP port probe (node net — no binary dependency) ────────────────────────

export interface TcpCheckResult {
  ok: boolean;
  connected: boolean;
  latencyMs: number | null;
  /** source address used for the bind (null = routing table chose) */
  boundTo: string | null;
  output: string;
  error?: string;
}

/** First global IPv4 of an interface via `ip -4 -o addr` (null if unavailable). */
async function firstIfaceIpv4(iface: string): Promise<string | null> {
  const { hasTool: has, runTool: run } = { hasTool, runTool };
  if (!(await has("ip"))) return null;
  const r = await run(`ip -4 -o addr show dev ${JSON.stringify(iface)} scope global`, 3000);
  const m = /inet (\d{1,3}(?:\.\d{1,3}){3})/.exec(r.stdout);
  return m ? m[1] : null;
}

/**
 * REAL TCP connect test from the appliance (pfSense Diagnostics > Test Port
 * parity). Optional source-interface bind (uses the iface's first global
 * IPv4 when iproute2 is present). 3 s hard ceiling.
 */
export async function runDiagTcpCheck(host: string, port: number, iface?: string): Promise<TcpCheckResult> {
  const h = host.trim();
  if (!/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(h) && !HOSTNAME_RE.test(h)) {
    return { ok: false, connected: false, latencyMs: null, boundTo: null, output: "", error: "Invalid host (use an IPv4 or hostname)" };
  }
  const p = Math.floor(port);
  if (!Number.isInteger(p) || p < 1 || p > 65535) {
    return { ok: false, connected: false, latencyMs: null, boundTo: null, output: "", error: "Port must be 1-65535" };
  }
  if (iface && !/^[a-z0-9.-]{1,15}$/i.test(iface)) {
    return { ok: false, connected: false, latencyMs: null, boundTo: null, output: "", error: "Invalid interface name" };
  }

  const boundTo = iface ? await firstIfaceIpv4(iface) : null;
  const bindNote = iface ? (boundTo ? ` (bound to ${boundTo} via ${iface})` : ` (iface ${iface} has no global IPv4 — used the routing table)`) : "";
  return await new Promise<TcpCheckResult>((resolve) => {
    const sock = new net.Socket();
    let settled = false;
    const started = Date.now();
    const done = (connected: boolean, error?: string) => {
      if (settled) return;
      settled = true;
      sock.destroy();
      const latencyMs = connected ? Date.now() - started : null;
      resolve({
        ok: connected,
        connected,
        latencyMs,
        boundTo,
        output: `${connected ? "TCP connect" : "TCP connect FAILED"} ${h}:${p}${bindNote}${latencyMs != null ? ` — ${latencyMs} ms` : ""}${error ? `\n${error}` : ""}`,
        error,
      });
    };
    sock.setTimeout(3000);
    sock.once("connect", () => done(true));
    sock.once("timeout", () => done(false, `no answer from ${h}:${p} within 3 s`));
    sock.once("error", (err: Error) => done(false, err.message));
    try {
      if (boundTo) sock.connect({ port: p, host: h, localAddress: boundTo });
      else sock.connect(p, h);
    } catch (err) {
      done(false, err instanceof Error ? err.message : "connect failed");
    }
  });
}
