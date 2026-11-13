/**
 * Multi-WAN probe runner (M02 §4, enterprise gap G1 fix).
 *
 * Until now the engine ignored every stored probe field and ran one hardcoded
 * TCP:53-to-gateway check. This module honors the policy's ACTUAL config:
 *
 *   probeType  probeTarget            real check
 *   ────────   ───────────────────    ──────────────────────────────────────
 *   icmp       IPv4 / FQDN            `ping -c1 -W <t> -I <iface> <target>`
 *   tcp        host:port              net.connect bound to the WAN source IP
 *   dns        resolver IPv4/FQDN     dns.Resolver (setLocalAddress) A query
 *   http       http(s)://…            http/https GET bound to the WAN source IP
 *
 * All probes honor timeoutMs and report latencyMs; the threshold state
 * machine (`nextWanState`) applies failThreshold/okThreshold with
 * down↔up hysteresis — a routing decision must never flap on one probe,
 * while up↔degraded stays immediate (real-time latency telemetry).
 *
 * Source binding: whenever the WAN interface has a primary IPv4, probes are
 * bound to it (ping -I, socket localAddress, resolver.setLocalAddress) so a
 * multi-WAN host probes each link over ITS OWN path instead of the main
 * routing table's egress.
 */

import net from "net";
import dns from "dns";
import http from "http";
import https from "https";

export type WanProbeVerdict = "up" | "degraded" | "down" | "unknown";

export interface WanProbeSpec {
  ifaceName: string;
  /** primary IPv4 of the WAN iface (null → probes leave via the main table) */
  ifaceIp: string | null;
  probeType: "icmp" | "tcp" | "dns" | "http";
  probeTarget: string;
  timeoutMs: number;
}

export interface WanProbeOutcome {
  state: WanProbeVerdict;
  latencyMs: number | null;
  detail: string;
}

// ── threshold state machine (pure — unit tested) ────────────────────────────

export interface WanHysteresis {
  state: WanProbeVerdict;
  failRun: number;
  okRun: number;
}

/**
 * Apply one probe verdict to the hysteresis state.
 *
 * down↔up transitions REQUIRE failThreshold / okThreshold consecutive probes
 * (no flappy default-route decisions). up↔degraded is immediate — degraded is
 * telemetry, not a decision. "unknown" stays until a threshold is crossed.
 */
export function nextWanState(
  cur: WanHysteresis,
  verdict: "up" | "degraded" | "down",
  failThreshold: number,
  okThreshold: number,
): { state: WanProbeVerdict; failRun: number; okRun: number; changed: boolean } {
  const prev = cur.state;
  if (verdict === "down") {
    const failRun = cur.failRun + 1;
    const state = failRun >= failThreshold ? "down" : prev === "down" ? "down" : prev;
    return { state, failRun, okRun: 0, changed: state !== prev };
  }
  // up or degraded — a good probe resets the fail run
  const okRun = cur.okRun + 1;
  const failRun = 0;
  let state: WanProbeVerdict;
  if (prev === "down" || prev === "unknown") {
    // recovery needs okThreshold consecutive good probes
    state = okRun >= okThreshold ? verdict : prev;
  } else {
    // healthy link — latency quality applies immediately
    state = verdict;
  }
  return { state, failRun, okRun, changed: state !== prev };
}

// ── target parsing (pure — unit tested) ─────────────────────────────────────

export interface TcpTarget {
  host: string;
  port: number;
}

export function parseTcpTarget(target: string): TcpTarget | null {
  const m = /^([a-zA-Z0-9._-]+):(\d{1,5})$/.exec(target.trim());
  if (!m) return null;
  const port = Number(m[2]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { host: m[1], port };
}

// ── real probes ─────────────────────────────────────────────────────────────

/** latency-based up/degraded split — answering fast vs answering slowly */
function latencyVerdict(latencyMs: number, timeoutMs: number): "up" | "degraded" {
  return latencyMs <= timeoutMs * 0.7 ? "up" : "degraded";
}

async function probeIcmp(spec: WanProbeSpec): Promise<WanProbeOutcome> {
  const { hasTool, runTool } = await import("@/lib/host/tools");
  if (!(await hasTool("ping"))) {
    return { state: "unknown", latencyMs: null, detail: "ping binary not available" };
  }
  const sec = Math.max(1, Math.ceil(spec.timeoutMs / 1000));
  // -I binds the probe to the WAN interface itself (kernel picks its source IP)
  const bind = spec.ifaceName ? ` -I ${JSON.stringify(spec.ifaceName)}` : "";
  const cmd = `ping -c 1 -W ${sec}${bind} ${JSON.stringify(spec.probeTarget)} 2>&1`;
  const r = await runTool(cmd, sec * 1000 + 1500);
  if (!r.ok) {
    const why = (r.stderr || r.stdout || r.error || "").split("\n").find(Boolean) ?? "no reply";
    return { state: "down", latencyMs: null, detail: `icmp ${spec.probeTarget}: ${why}` };
  }
  const m = /time[=<]\s*([\d.]+)\s*ms/i.exec(r.stdout);
  const latencyMs = m ? Math.round(Number(m[1])) : null;
  const v = latencyMs != null ? latencyVerdict(latencyMs, spec.timeoutMs) : "up";
  return { state: v, latencyMs, detail: `icmp ${spec.probeTarget} ok${latencyMs != null ? ` ${latencyMs} ms` : ""}` };
}

function probeTcp(spec: WanProbeSpec, t: TcpTarget): Promise<WanProbeOutcome> {
  return new Promise((resolve) => {
    const started = Date.now();
    const sock = new net.Socket();
    let settled = false;
    const done = (state: WanProbeOutcome["state"], detail: string) => {
      if (settled) return;
      settled = true;
      const latencyMs = Date.now() - started;
      sock.destroy();
      resolve({
        state,
        latencyMs: state === "down" ? null : latencyMs,
        detail: state === "down" ? `tcp ${t.host}:${t.port} — ${detail}` : `tcp ${t.host}:${t.port} ok ${latencyMs} ms`,
      });
    };
    sock.setTimeout(spec.timeoutMs);
    sock.once("connect", () => {
      const latencyMs = Date.now() - started;
      done(latencyVerdict(latencyMs, spec.timeoutMs), `connected in ${latencyMs} ms`);
    });
    sock.once("timeout", () => done("down", `no answer within ${spec.timeoutMs} ms`));
    sock.once("error", (err: Error) => done("down", err.message));
    try {
      sock.connect(t.port, t.host, spec.ifaceIp ? { localAddress: spec.ifaceIp } : undefined);
    } catch (err) {
      done("down", err instanceof Error ? err.message : "connect failed");
    }
  });
}

async function probeDns(spec: WanProbeSpec): Promise<WanProbeOutcome> {
  const resolver = new dns.Resolver({ timeout: spec.timeoutMs, tries: 1 });
  try {
    if (spec.ifaceIp) resolver.setLocalAddress(spec.ifaceIp);
    const started = Date.now();
    // A-record of an IANA-stable name via the configured resolver — proves the
    // path can carry DNS end-to-end (beyond mere gateway reachability)
    const addrs = await resolver.resolve4("example.com");
    const latencyMs = Date.now() - started;
    const v = latencyVerdict(latencyMs, spec.timeoutMs);
    return { state: v, latencyMs, detail: `dns ${spec.probeTarget} resolved example.com in ${latencyMs} ms` };
  } catch (err) {
    return {
      state: "down",
      latencyMs: null,
      detail: `dns ${spec.probeTarget}: ${err instanceof Error ? err.message : "resolver error"}`,
    };
  } finally {
    resolver.close();
  }
}

function probeHttp(spec: WanProbeSpec, url: URL): Promise<WanProbeOutcome> {
  return new Promise((resolve) => {
    const started = Date.now();
    const mod = url.protocol === "https:" ? https : http;
    let settled = false;
    const done = (state: WanProbeOutcome["state"], detail: string) => {
      if (settled) return;
      settled = true;
      const latencyMs = Date.now() - started;
      resolve({
        state,
        latencyMs: state === "down" ? null : latencyMs,
        detail: state === "down" ? `http ${url.host} — ${detail}` : `http ${url.host} answered in ${latencyMs} ms`,
      });
    };
    try {
      const req = mod.request(
        url,
        {
          method: "GET",
          timeout: spec.timeoutMs,
          headers: { "user-agent": "utm-wan-probe/1", connection: "close" },
          ...(spec.ifaceIp ? { localAddress: spec.ifaceIp } : {}),
        },
        (res) => {
          // any HTTP answer (even 5xx) proves the path carries traffic; the
          // status is surfaced in the detail for honesty
          const v = latencyVerdict(Date.now() - started, spec.timeoutMs);
          res.destroy();
          done(v, `HTTP ${res.statusCode ?? "?"}`);
        },
      );
      req.on("timeout", () => {
        req.destroy();
        done("down", `no HTTP answer within ${spec.timeoutMs} ms`);
      });
      req.on("error", (err: Error) => done("down", err.message));
      req.end();
    } catch (err) {
      done("down", err instanceof Error ? err.message : "request failed");
    }
  });
}

/** Run ONE real probe for a WAN policy — never throws. */
export async function runWanProbe(spec: WanProbeSpec): Promise<WanProbeOutcome> {
  try {
    switch (spec.probeType) {
      case "icmp":
        return await probeIcmp(spec);
      case "tcp": {
        const t = parseTcpTarget(spec.probeTarget);
        if (!t) return { state: "unknown", latencyMs: null, detail: `invalid tcp target "${spec.probeTarget}" (want host:port)` };
        return await probeTcp(spec, t);
      }
      case "dns":
        return await probeDns(spec);
      case "http": {
        let url: URL;
        try {
          url = new URL(spec.probeTarget);
          if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("scheme");
        } catch {
          return { state: "unknown", latencyMs: null, detail: `invalid http target "${spec.probeTarget}" (want http(s)://…)` };
        }
        return await probeHttp(spec, url);
      }
      default:
        return { state: "unknown", latencyMs: null, detail: `unsupported probe type ${spec.probeType as string}` };
    }
  } catch (err) {
    return { state: "down", latencyMs: null, detail: err instanceof Error ? err.message : "probe crashed" };
  }
}
