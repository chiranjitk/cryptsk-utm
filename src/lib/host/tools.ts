/**
 * Host tool wrappers (ADR-021) — thin, fail-soft exec shells around the
 * appliance binaries: nft, wg, tc, systemctl, journalctl, suricata.
 * On the Debian 13 appliance (root) these return REAL state; in the sandbox
 * without the binary or privileges they return `null` and the console shows
 * honest "not available" data instead of simulated rows.
 */

import { exec as execCb } from "child_process";
import { promisify } from "util";
import net from "net";

const exec = promisify(execCb);

const EXEC_TIMEOUT_MS = 5000;

/**
 * Cached binary availability (per process).
 * Positives are cached for the process lifetime; negatives are retried after
 * WHICH_NEG_TTL_MS — a single transient failure at boot (fork hiccup, cgroup
 * stall) must not permanently black-hole a tool.
 */
const whichCache = new Map<string, boolean>();
const whichCacheAt = new Map<string, number>();
const WHICH_NEG_TTL_MS = 60_000;

export async function hasTool(bin: string): Promise<boolean> {
  const cached = whichCache.get(bin);
  if (cached === true) return true;
  if (cached === false) {
    const at = whichCacheAt.get(bin) ?? 0;
    if (Date.now() - at < WHICH_NEG_TTL_MS) return false;
  }
  let ok = false;
  try {
    await exec(`command -v ${JSON.stringify(bin)} >/dev/null 2>&1`, { timeout: 2000, shell: "/bin/sh" });
    ok = true;
  } catch {
    ok = false;
  }
  whichCache.set(bin, ok);
  whichCacheAt.set(bin, Date.now());
  return ok;
}

export function clearToolCache(): void {
  whichCache.clear();
  whichCacheAt.clear();
}

export interface ToolResult {
  ok: boolean;
  stdout: string;
  stderr: string;
  /** e.g. EPERM / ETIMEDOUT — surfaced verbatim to the API layer */
  error?: string;
}

/** Run a tool; never throws — returns { ok:false, error } on failure. */
export async function runTool(cmd: string, timeoutMs = EXEC_TIMEOUT_MS): Promise<ToolResult> {
  try {
    const { stdout, stderr } = await exec(cmd, { timeout: timeoutMs, shell: "/bin/sh" });
    return { ok: true, stdout, stderr };
  } catch (err) {
    const e = err as { message?: string; stdout?: string; stderr?: string; killed?: boolean };
    return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? "", error: e.message ?? "exec failed" };
  }
}

// ── nftables ────────────────────────────────────────────────────────────────

export interface NftRuleset {
  available: boolean;
  /** empty when nft is missing or permission denied (sandbox without CAP_NET_ADMIN) */
  ruleset: string;
  permissionDenied: boolean;
}

export async function readNftRuleset(): Promise<NftRuleset> {
  if (!(await hasTool("nft"))) return { available: false, ruleset: "", permissionDenied: false };
  const res = await runTool("nft list ruleset", 6000);
  const denied = !res.ok && (/Operation not permitted/i.test(res.stderr) || /Operation not permitted/i.test(res.error ?? ""));
  return { available: res.ok, ruleset: res.ok ? res.stdout : "", permissionDenied: denied };
}

/** Apply a generated nftables ruleset file (root on the appliance). */
export async function applyNftFile(file: string): Promise<ToolResult> {
  if (!(await hasTool("nft"))) return { ok: false, stdout: "", stderr: "nft not installed", error: "nftables not installed on this host" };
  return runTool(`nft -f ${JSON.stringify(file)}`, 10000);
}

// ── WireGuard ───────────────────────────────────────────────────────────────

export interface WgPeerDump {
  iface: string;
  publicKey: string;
  endpoint: string | null;
  allowedIps: string[];
  /** seconds since last handshake; null = never */
  handshakeAgeSec: number | null;
  rxBytes: number;
  txBytes: number;
}

/**
 * `wg show all dump` — tab-separated: iface pubkey privateKey? endpoint
 * allowed-ips latest-handshake rx tx (fields vary per dump layout; the
 * all-dump format is: iface, public-key, private-key, endpoint, allowed-ips,
 * latest-handshake, rx, tx, persistent-keepalive).
 */
export async function readWgPeers(): Promise<WgPeerDump[] | null> {
  if (!(await hasTool("wg"))) return null;
  const res = await runTool("wg show all dump", 6000);
  if (!res.ok) return null;
  const peers: WgPeerDump[] = [];
  for (const line of res.stdout.split("\n")) {
    const f = line.trim().split("\t");
    if (f.length < 8) continue;
    const [, pub, , endpoint, allowed, handshake, rx, tx] = f;
    if (!pub) continue;
    peers.push({
      iface: f[0],
      publicKey: pub,
      endpoint: endpoint === "(none)" || !endpoint ? null : endpoint,
      allowedIps: allowed.split(",").filter(Boolean),
      handshakeAgeSec: handshake && handshake !== "0" ? Math.max(0, Math.floor(Date.now() / 1000 - Number(handshake))) : null,
      rxBytes: Number(rx) || 0,
      txBytes: Number(tx) || 0,
    });
  }
  return peers;
}

// ── systemd ─────────────────────────────────────────────────────────────────

/** Rate-limited warning so a persistent tool failure is VISIBLE in logs. */
let lastServiceWarn = 0;
function warnServiceRead(reason: string): void {
  const now = Date.now();
  if (now - lastServiceWarn < 300_000) return;
  lastServiceWarn = now;
  console.warn(`[host-tools] service states unreadable — ${reason}`);
}

/** Batch `systemctl is-active` — returns a map; null when systemctl is absent or the call failed outright. */
export async function readServiceStates(units: string[]): Promise<Record<string, string> | null> {
  if (!(await hasTool("systemctl"))) {
    warnServiceRead('`systemctl` binary not found (re-probed every 60 s)');
    return null;
  }
  const res = await runTool(`systemctl is-active -- ${units.map((u) => JSON.stringify(u)).join(" ")}`, 6000);
  if (!res.ok && !res.stdout.trim()) {
    // exec failed outright (spawn error / timeout) with nothing to parse
    warnServiceRead(`systemctl is-active failed: ${res.error ?? "unknown"}${res.stderr ? ` · stderr: ${res.stderr.slice(0, 200)}` : ""}`);
    return null;
  }
  const lines = res.stdout.split("\n").map((l) => l.trim()).filter(Boolean);
  if (lines.length !== units.length) {
    warnServiceRead(`systemctl is-active returned ${lines.length} lines for ${units.length} units — suffix units read as "unknown"`);
  }
  const map: Record<string, string> = {};
  units.forEach((u, i) => {
    map[u] = lines[i] ?? "unknown";
  });
  return map;
}

/** Real service restart (root on the appliance). */
export async function restartUnit(unit: string): Promise<ToolResult> {
  if (!(await hasTool("systemctl"))) return { ok: false, stdout: "", stderr: "systemctl not available", error: "systemd not available on this host" };
  return runTool(`systemctl restart ${JSON.stringify(unit)}`, 15000);
}

// ── Suricata ────────────────────────────────────────────────────────────────

export const SURICATA_EVE_CANDIDATES = [
  "/var/log/suricata/eve.json",
  "/var/log/suricata/eve-2.json",
];

export async function detectSuricataEve(): Promise<string | null> {
  const { access } = await import("fs/promises");
  const { constants } = await import("fs");
  for (const p of SURICATA_EVE_CANDIDATES) {
    try {
      await access(p, constants.R_OK);
      return p;
    } catch {
      // next candidate
    }
  }
  return null;
}

// ── Kea DHCP leases ─────────────────────────────────────────────────────────

export const KEA_LEASES_CANDIDATES = [
  "/var/lib/kea/kea-leases4.csv",
  "/var/lib/kea/kea-leases4.csv.1",
  "/var/lib/kea/dhcp4.leases",
];

export async function detectKeaLeases(): Promise<string | null> {
  const { access } = await import("fs/promises");
  const { constants } = await import("fs");
  for (const p of KEA_LEASES_CANDIDATES) {
    try {
      await access(p, constants.R_OK);
      return p;
    } catch {
      // next candidate
    }
  }
  return null;
}

// ── Unbound query log ───────────────────────────────────────────────────────

export const UNBOUND_LOG_CANDIDATES = [
  "/var/log/unbound/unbound.log",
  "/var/log/unbound.log",
];

export async function detectUnboundLog(): Promise<string | null> {
  const { access } = await import("fs/promises");
  const { constants } = await import("fs");
  for (const p of UNBOUND_LOG_CANDIDATES) {
    try {
      await access(p, constants.R_OK);
      return p;
    } catch {
      // next candidate
    }
  }
  return null;
}

// ── WAN gateway probe (real TCP connect) ────────────────────────────────────

/**
 * REAL ICMP ping via the system `ping` binary (setuid on Debian — works
 * unprivileged). Returns null when `ping` is unavailable.
 */
export async function pingHost(ip: string, timeoutSec = 2): Promise<boolean | null> {
  if (!(await hasTool("ping"))) return null;
  const res = await runTool(`ping -c 1 -W ${timeoutSec} ${JSON.stringify(ip)} >/dev/null 2>&1`, (timeoutSec + 1) * 1000);
  return res.ok;
}

/** Default gateway for an interface from /proc/net/route (little-endian hex). */
export async function readGatewayFor(iface: string): Promise<string | null> {
  const { readFile } = await import("fs/promises");
  try {
    const raw = await readFile("/proc/net/route", "utf8");
    for (const line of raw.split("\n").slice(1)) {
      const f = line.trim().split(/\s+/);
      if (f.length >= 3 && f[0] === iface && f[2] !== "00000000") {
        const hex = f[2];
        const bytes = [0, 2, 4, 6].map((i) => parseInt(hex.slice(i, i + 2), 16));
        return bytes.join(".");
      }
    }
  } catch {
    // no route table
  }
  return null;
}

export interface GatewayProbeResult {
  state: "up" | "degraded" | "down" | "unknown";
  latencyMs: number | null;
  detail: string;
}

/**
 * REAL probe: TCP connect to the interface's default gateway on port 53
 * (DNS fallback works even where ICMP is filtered), 2.5 s budget.
 */
export async function probeGateway(iface: string): Promise<GatewayProbeResult> {
  const { readFile } = await import("fs/promises");
  const carrierRaw = await readFile(`/sys/class/net/${iface}/carrier`, "utf8").catch(() => "");
  if (carrierRaw.trim() === "0") {
    return { state: "down", latencyMs: null, detail: "carrier lost (link down)" };
  }
  const gw = await readGatewayFor(iface);
  if (!gw) {
    return { state: "down", latencyMs: null, detail: "no default gateway on interface" };
  }
  return new Promise((resolve) => {
    const started = Date.now();
    const sock = new net.Socket();
    let settled = false;
    const done = (state: GatewayProbeResult["state"], detail: string) => {
      if (settled) return;
      settled = true;
      const latencyMs = Date.now() - started;
      sock.destroy();
      resolve({ state, latencyMs, detail });
    };
    sock.setTimeout(2500);
    sock.once("connect", () => done(Date.now() - started < 250 ? "up" : "degraded", `TCP ${gw}:53 reachable`));
    sock.once("timeout", () => done("degraded", `no TCP answer from ${gw}:53 within 2.5 s`));
    sock.once("error", (err: Error) => done("down", `probe error: ${err.message}`));
    sock.connect(53, gw);
  });
}
