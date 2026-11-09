/**
 * procfs/sysfs readers — REAL host data, no simulation (ADR-021).
 * Every function reads the actual Linux kernel interfaces that are also
 * present on the Debian 13 appliance. In the sandbox the same files are
 * readable, so the console shows the sandbox host's real metrics.
 * All readers fail soft (null / zeros) — never throw into the tick loop.
 */

import { promises as fs } from "fs";
import { readFile } from "fs/promises";
import os from "os";
import path from "path";

export interface NetDevSample {
  name: string;
  rxBytes: number;
  rxPackets: number;
  rxErrors: number;
  rxDrops: number;
  txBytes: number;
  txPackets: number;
  txErrors: number;
  txDrops: number;
}

export interface CpuTimes {
  idle: number;
  total: number;
}

export interface MemInfo {
  totalBytes: number;
  availableBytes: number;
}

export interface DiskUsage {
  totalBytes: number;
  freeBytes: number;
  usedPct: number;
}

const INT_RE = /^(\d+)$/;

function num(s: string | undefined): number {
  return s && INT_RE.test(s) ? Number(s) : 0;
}

/** One sample of /proc/net/dev — real per-interface counters. */
export async function readNetDev(): Promise<NetDevSample[]> {
  try {
    const raw = await readFile("/proc/net/dev", "utf8");
    const out: NetDevSample[] = [];
    for (const line of raw.split("\n").slice(2)) {
      const [namePart, rest] = line.split(":");
      if (!rest) continue;
      const name = namePart.trim();
      if (!name) continue;
      const f = rest.trim().split(/\s+/);
      // rx: bytes packets errs drop fifo frame compressed multicast
      // tx: bytes packets errs drop fifo colls carrier compressed
      out.push({
        name,
        rxBytes: num(f[0]),
        rxPackets: num(f[1]),
        rxErrors: num(f[2]),
        rxDrops: num(f[3]),
        txBytes: num(f[8]),
        txPackets: num(f[9]),
        txErrors: num(f[10]),
        txDrops: num(f[11]),
      });
    }
    return out;
  } catch {
    return [];
  }
}

/** Cumulative CPU jiffies from /proc/stat — diff two samples for a % value. */
export async function readCpuTimes(): Promise<CpuTimes | null> {
  try {
    const raw = await readFile("/proc/stat", "utf8");
    const line = raw.split("\n").find((l) => l.startsWith("cpu "));
    if (!line) return null;
    const f = line.trim().split(/\s+/).slice(1).map(num);
    // user nice system idle iowait irq softirq steal guest guest_nice
    const idle = f[3] + f[4];
    const total = f.reduce((s, v) => s + v, 0);
    return { idle, total };
  } catch {
    return null;
  }
}

export async function readMemInfo(): Promise<MemInfo | null> {
  try {
    const raw = await readFile("/proc/meminfo", "utf8");
    const get = (key: string): number => {
      const m = raw.match(new RegExp(`^${key}:\\s+(\\d+) kB`, "m"));
      return m ? Number(m[1]) * 1024 : 0;
    };
    const total = get("MemTotal");
    const available = get("MemAvailable") || get("MemFree");
    if (!total) return null;
    return { totalBytes: total, availableBytes: available };
  } catch {
    return null;
  }
}

export async function memPct(): Promise<number> {
  const m = await readMemInfo();
  if (!m || !m.totalBytes) return 0;
  return Math.round((1 - m.availableBytes / m.totalBytes) * 1000) / 10;
}

export function readUptimeSec(): number {
  return Math.floor(os.uptime());
}

export function readHostname(): string {
  return os.hostname();
}

export function readLoadavg(): [number, number, number] {
  const [a, b, c] = os.loadavg();
  return [a, b, c];
}

/**
 * Real disk usage for a path. Node fs.statfs when available, `df -kP` fallback.
 */
export async function readDiskUsage(target = "/"): Promise<DiskUsage | null> {
  try {
    const mod = (fs as unknown as { statfs?: (p: string) => Promise<{ blocks: number; bsize: number; bavail: number }> });
    if (typeof mod.statfs === "function") {
      const s = await mod.statfs.call(fs, target);
      const total = s.blocks * s.bsize;
      const free = s.bavail * s.bsize;
      if (!total) return null;
      return { totalBytes: total, freeBytes: free, usedPct: Math.round((1 - free / total) * 1000) / 10 };
    }
  } catch {
    // fall through to df
  }
  try {
    const { execFile } = await import("child_process");
    const { promisify } = await import("util");
    const out = await promisify(execFile)("df", ["-kP", target], { timeout: 4000 });
    const line = out.stdout.split("\n")[1];
    if (!line) return null;
    const f = line.trim().split(/\s+/);
    const total = num(f[1]) * 1024;
    const avail = num(f[3]) * 1024;
    if (!total) return null;
    return { totalBytes: total, freeBytes: avail, usedPct: Math.round((1 - avail / total) * 1000) / 10 };
  } catch {
    return null;
  }
}

/** First readable thermal zone (milli°C → °C); null on VMs/containers without sensors. */
export async function readThermalC(): Promise<number | null> {
  try {
    const base = "/sys/class/thermal";
    const zones = await fs.readdir(base).catch(() => []);
    for (const z of zones.filter((n) => n.startsWith("thermal_zone"))) {
      const raw = await readFile(path.join(base, z, "temp"), "utf8").catch(() => "");
      const milli = num(raw.trim());
      if (milli > 0) return Math.round((milli / 1000) * 10) / 10;
    }
  } catch {
    // no thermal info
  }
  return null;
}

/** Real conntrack count; null when the nf_conntrack proc entry is absent. */
export async function readConntrackCount(): Promise<number | null> {
  try {
    const raw = await readFile("/proc/sys/net/netfilter/nf_conntrack_count", "utf8");
    const v = num(raw.trim());
    if (v > 0) return v;
  } catch {
    // fall through
  }
  return null;
}

const TCP_ESTABLISHED = 0x01;

/** Real TCP session table (/proc/net/tcp + tcp6). */
export async function readTcpSessions(): Promise<{ total: number; established: number }> {
  let total = 0;
  let established = 0;
  for (const file of ["/proc/net/tcp", "/proc/net/tcp6"]) {
    try {
      const raw = await readFile(file, "utf8");
      for (const line of raw.split("\n").slice(1)) {
        const f = line.trim().split(/\s+/);
        if (f.length < 4) continue;
        total += 1;
        if (parseInt(f[3], 16) === TCP_ESTABLISHED) established += 1;
      }
    } catch {
      // unavailable
    }
  }
  return { total, established };
}

/** UDP endpoints (/proc/net/udp + udp6). */
export async function readUdpEndpoints(): Promise<number> {
  let total = 0;
  for (const file of ["/proc/net/udp", "/proc/net/udp6"]) {
    try {
      const raw = await readFile(file, "utf8");
      total += Math.max(0, raw.split("\n").length - 1);
    } catch {
      // unavailable
    }
  }
  return total;
}

export interface RealInterface {
  name: string;
  operState: string;
  mtu: number | null;
  mac: string | null;
  ipv4: string[];
  ipv6: string[];
  carrier: boolean | null;
  /** default-route egress interface (first hit) */
  isDefaultRoute: boolean;
}

/** Real interface state from sysfs + os.networkInterfaces (no `ip` dependency). */
export async function readInterfaces(): Promise<RealInterface[]> {
  const out: RealInterface[] = [];
  const base = "/sys/class/net";
  const names = await fs.readdir(base).catch(() => []);

  // default route: /proc/net/route destination 00000000
  let defaultIface: string | null = null;
  try {
    const raw = await readFile("/proc/net/route", "utf8");
    for (const line of raw.split("\n").slice(1)) {
      const f = line.trim().split(/\s+/);
      if (f.length >= 8 && f[1] === "00000000") {
        defaultIface = f[0];
        break;
      }
    }
  } catch {
    // no route table
  }

  const ifAddrs = new Map<string, { ipv4: string[]; ipv6: string[] }>();
  try {
    const ni = os.networkInterfaces();
    for (const [name, addrs] of Object.entries(ni)) {
      const v4: string[] = [];
      const v6: string[] = [];
      for (const a of addrs ?? []) {
        if (a.family === "IPv4") v4.push(a.address);
        else if (a.family === "IPv6") v6.push(a.address.split("%")[0]);
      }
      ifAddrs.set(name, { ipv4: v4, ipv6: v6 });
    }
  } catch {
    // keep empty maps
  }

  for (const name of names) {
    const dir = path.join(base, name);
    const operState = (await readFile(path.join(dir, "operstate"), "utf8").catch(() => "unknown")).trim();
    const mtuRaw = await readFile(path.join(dir, "mtu"), "utf8").catch(() => "");
    const mac = (await readFile(path.join(dir, "address"), "utf8").catch(() => "")).trim() || null;
    const carrierRaw = await readFile(path.join(dir, "carrier"), "utf8").catch(() => "");
    const addrs = ifAddrs.get(name) ?? { ipv4: [], ipv6: [] };
    out.push({
      name,
      operState,
      mtu: num(mtuRaw.trim()) || null,
      mac,
      ipv4: addrs.ipv4,
      ipv6: addrs.ipv6,
      carrier: carrierRaw.trim() === "1" ? true : carrierRaw.trim() === "0" ? false : null,
      isDefaultRoute: name === defaultIface,
    });
  }
  return out;
}
