/**
 * HostCollector — REAL data-plane engine (ADR-021, ADAPTER_MODE=host).
 *
 * Replaces the MockEngine with actual host telemetry:
 *   • /proc/net/dev, /proc/stat, /proc/meminfo, /proc/net/tcp{,6}  → metrics ring
 *   • real gateway probes (TCP :53 via /proc/net/route)            → WAN states
 *   • Suricata eve.json tail (appliance)                           → ipsEvent rows
 *   • nftables kernel-log tail via journalctl (appliance)          → firewallLog rows
 *   • `wg show all dump` (appliance)                               → real VPN sessions
 *   • Kea leases CSV (appliance)                                   → dhcpLease rows
 *   • unbound query log (appliance)                                → dnsRing entries
 *   • systemctl states (appliance)                                 → service health
 *
 * Every source degrades to honest emptiness when the binary/file/permission
 * is missing (sandbox) — the engine NEVER fabricates values. The public
 * surface mirrors MockEngine (metricsRing, logsRing, dnsRing, uptimeSec,
 * wanStates, systemVitals, forceProbe, start) so all existing read routes
 * and the realtime pipeline work unchanged.
 */

import { promises as fs } from "fs";
import { readFile, stat } from "fs/promises";
import os from "os";
import { db } from "@/lib/db";
import { emitEvent, currentCursor, type FirewallLogEntry, type IpsEventEntry, type MetricsTick } from "./events";
import type { DnsQueryLogEntry } from "./generators/dns-queries";
import {
  readNetDev,
  readCpuTimes,
  readMemInfo,
  readDiskUsage,
  readThermalC,
  readConntrackCount,
  readTcpSessions,
  readUdpEndpoints,
  readInterfaces,
  readUptimeSec,
  type NetDevSample,
  type RealInterface,
} from "@/lib/host/proc";
import {
  hasTool,
  runTool,
  readNftRuleset,
  readWgPeers,
  readServiceStates,
  restartUnit,
  detectSuricataEve,
  detectKeaLeases,
  detectUnboundLog,
  probeGateway,
  type WgPeerDump,
} from "@/lib/host/tools";

export interface HostLogRingEntry {
  kind: "firewall" | "ips";
  entry: FirewallLogEntry | IpsEventEntry;
  seq: number;
}

const METRICS_RING_CAP = 500;
const LOGS_RING_CAP = 2000;
const DNS_RING_CAP = 2000;
const TICK_MS = 2000;

const WAN_EVERY = 5; // ticks → 10 s gateway probes
const SOURCES_EVERY = 5; // ticks → suricata / nft / wg / unbound tails
const SLOW_EVERY = 30; // ticks → kea leases, interface sync, disk, services

/** verbose logging window: first 120 ticks of a process, then sampled. */
function myTickVerbose(tickNo: number): boolean {
  return tickNo <= 120 || tickNo % 150 === 0;
}

export interface IfaceCounterDelta {
  errors: number;
  drops: number;
  rxBytes: number;
  txBytes: number;
  rxPackets: number;
  txPackets: number;
}

class HostCollector {
  private started = false;
  private starting: Promise<void> | null = null;
  private timer: ReturnType<typeof setInterval> | null = null;
  private heartbeat: ReturnType<typeof setInterval> | null = null;
  private tickNo = 0;

  readonly metricsRing: MetricsTick[] = [];
  readonly logsRing: HostLogRingEntry[] = [];
  readonly dnsRing: DnsQueryLogEntry[] = [];

  // real sampler state
  private lastNetDev: NetDevSample[] = [];
  private lastCpu: { idle: number; total: number } | null = null;
  /** counters accumulated since collector start (real deltas, no hashing) */
  private countersSinceStart = new Map<string, IfaceCounterDelta>();
  private diskPct = 0;
  private tempC: number | null = null;
  private tcpSessions = { total: 0, established: 0 };
  private udpEndpoints = 0;
  private conntrackReal: number | null = null;

  // WAN probe state (real)
  private wanProbes = new Map<string, { state: "up" | "degraded" | "down" | "unknown"; latencyMs: number | null; detail: string; lastTs: number }>();

  // optional real sources (resolved lazily)
  private evePath: string | null | undefined; // undefined = not yet probed
  private eveOffset = 0;
  private keaPath: string | null | undefined;
  private keaParsedSize = 0;
  private unboundPath: string | null | undefined;
  private unboundOffset = 0;
  private journalSince = new Date();
  private servicesAvailable: boolean | null = null;
  private lastServiceStates: Record<string, string> | null = null;
  private rulesetAvailable: boolean | null = null;

  // threshold watcher state (edge-triggered, real vitals)
  private thresholds = { cpuPct: 90, memPct: 90, diskPct: 85, tempC: 80 };
  private lastThresholdLoad = 0;
  private openAlerts = new Map<string, { crossedAtTick: number; notifiedCritical: boolean }>();

  get uptimeSec(): number {
    return readUptimeSec();
  }

  get tickNumber(): number {
    return this.tickNo;
  }

  get dataPlane(): "host" {
    return "host";
  }

  /** Real TCP/UDP session totals (dashboard "sessions" tile). */
  get sessionTotals(): { total: number; established: number; udp: number } {
    return { total: this.tcpSessions.total, established: this.tcpSessions.established, udp: this.udpEndpoints };
  }

  get wanStates(): Array<{ iface: string; state: string }> {
    return [...this.wanProbes.entries()].map(([iface, p]) => ({ iface, state: p.state }));
  }

  /**
   * Real cumulative per-interface error/drop counters since collector start —
   * replaces the hash-seeded simulated counters of the stats route.
   */
  ifaceCounters(name: string): IfaceCounterDelta | null {
    return this.countersSinceStart.get(name) ?? null;
  }

  /** Real vitals for /system/status + the health strip (disk/temp are measured). */
  systemVitals(): { cpuPct: number; memPct: number; diskPct: number; tempC: number } {
    const latest = this.metricsRing[this.metricsRing.length - 1];
    return {
      cpuPct: latest?.cpuPct ?? 0,
      memPct: latest?.memPct ?? 0,
      diskPct: Math.round(this.diskPct * 10) / 10,
      tempC: Math.round((this.tempC ?? 0) * 10) / 10,
    };
  }

  /** Real immediate probe (M02 §5 "Probe now") — null when iface is not tracked. */
  async forceProbe(iface: string): Promise<"up" | "degraded" | "down" | "unknown" | null> {
    const tracked = [...this.wanProbes.keys()];
    if (!tracked.includes(iface)) return null;
    const result = await probeGateway(iface);
    const prev = this.wanProbes.get(iface);
    this.wanProbes.set(iface, { ...result, lastTs: Date.now() });
    if (prev && prev.state !== result.state) {
      this.persistWanState(iface, result.state);
      if (result.state !== "unknown") {
        emitEvent({ type: "wan:status", payload: { iface, state: result.state } });
      }
    }
    return result.state;
  }

  async start(): Promise<void> {
    if (this.started) return;
    if (this.starting) return this.starting;
    this.starting = this.bootstrap();
    await this.starting;
    this.started = true;
    this.timer = setInterval(() => {
      void this.tick();
    }, TICK_MS);
    // liveness heartbeat — a REFFED timer that must keep firing as long as
    // the process lives; if heartbeats stop, the event loop itself is stuck.
    if (!this.heartbeat) {
      this.heartbeat = setInterval(() => {
        const handles = (process as unknown as { _getActiveHandles?: () => unknown[] })._getActiveHandles?.().length ?? -1;
        console.log(`[host-collector] heartbeat tick=${this.tickNo} handles=${handles} slow=${this.slowRunNo}`);
      }, 30_000);
    }
    void this.tick();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    this.started = false;
  }

  private async bootstrap(): Promise<void> {
    console.log("[host-collector] real data plane starting (ADR-021) — no simulated data");
    // seed sampler baselines so the first deltas are sane
    this.lastNetDev = await readNetDev();
    this.lastCpu = await readCpuTimes();
    for (const s of this.lastNetDev) {
      this.countersSinceStart.set(s.name, { errors: 0, drops: 0, rxBytes: 0, txBytes: 0, rxPackets: 0, txPackets: 0 });
    }
    // disk + temperature measured immediately (not only on the slow cycle)
    const disk = await readDiskUsage(process.cwd());
    if (disk) this.diskPct = disk.usedPct;
    this.tempC = await readThermalC();
    // real WAN policies from DB (config plane; probe results are real)
    try {
      const wans = await db.wanPolicy.findMany({ where: { tenantId: 1 }, select: { interfaceName: true, enabled: true } });
      for (const w of wans) {
        if (w.enabled) this.wanProbes.set(w.interfaceName, { state: "unknown", latencyMs: null, detail: "not probed yet", lastTs: 0 });
      }
    } catch {
      // DB not ready yet — probes re-read on the WAN cycle
    }
    this.journalSince = new Date(Date.now() - 15_000);
  }

  // ── tick pipeline ──────────────────────────────────────────────────────────

  private async tick(): Promise<void> {
    const myTick = this.tickNo + 1;
    this.tickNo += 1;
    const t0 = Date.now();
    if (myTick <= 120) console.log(`[host-collector] tick #${myTick} start`);
    try {
      const tickPayload = await this.stageTimeout("sampleMetrics", this.sampleMetrics(), 5000);
      if (tickPayload) {
        this.metricsRing.push(tickPayload);
        if (this.metricsRing.length > METRICS_RING_CAP) this.metricsRing.shift();
        emitEvent({ type: "metrics:tick", payload: tickPayload });
      }
      if (myTick % WAN_EVERY === 0) await this.wanProbeStep().catch(() => {});
      if (myTick % SOURCES_EVERY === 0) await this.realSourcesStep().catch(() => {});
      if (myTick % SLOW_EVERY === 0) await this.slowStep().catch(() => {});
      await this.thresholdStep(tickPayload).catch(() => {});
      // pipeline watchdog: a hung stage delays every subsequent tick — surface it
      const dt = Date.now() - t0;
      if (dt > 15_000 && myTick % 15 === 0) {
        console.warn(`[host-collector] tick #${myTick} took ${dt}ms — a pipeline stage is stalling`);
      }
    } catch (err) {
      console.error("[host-collector] tick error:", err instanceof Error ? err.message : err);
    }
    // stage-flow visibility (first 120 ticks of each process, then sampled)
    if (myTick <= 120 || myTick % 15 === 0) {
      console.log(`[host-collector] tick #${myTick} done in ${Date.now() - t0}ms`);
    }
  }

  /** REAL metrics: netdev deltas + CPU jiffies + meminfo + conntrack. */
  private async sampleMetrics(): Promise<MetricsTick | null> {
    const now = await readNetDev();
    const cpu = await readCpuTimes();
    const mem = await readMemInfo();

    const prev = new Map(this.lastNetDev.map((s) => [s.name, s]));
    const ifaces = now
      .filter((s) => s.name !== "lo")
      .map((s) => {
        const p = prev.get(s.name);
        const dtSec = Math.max(1, TICK_MS / 1000);
        const rxBps = p ? Math.max(0, (s.rxBytes - p.rxBytes) / dtSec) : 0;
        const txBps = p ? Math.max(0, (s.txBytes - p.txBytes) / dtSec) : 0;
        // accumulate real counters since start
        const c = this.countersSinceStart.get(s.name) ?? { errors: 0, drops: 0, rxBytes: 0, txBytes: 0, rxPackets: 0, txPackets: 0 };
        const d = p
          ? {
              errors: Math.max(0, s.rxErrors - p.rxErrors + s.txErrors - p.txErrors),
              drops: Math.max(0, s.rxDrops - p.rxDrops + s.txDrops - p.txDrops),
              rxBytes: Math.max(0, s.rxBytes - p.rxBytes),
              txBytes: Math.max(0, s.txBytes - p.txBytes),
              rxPackets: Math.max(0, s.rxPackets - p.rxPackets),
              txPackets: Math.max(0, s.txPackets - p.txPackets),
            }
          : { errors: 0, drops: 0, rxBytes: 0, txBytes: 0, rxPackets: 0, txPackets: 0 };
        this.countersSinceStart.set(s.name, {
          errors: c.errors + d.errors,
          drops: c.drops + d.drops,
          rxBytes: c.rxBytes + d.rxBytes,
          txBytes: c.txBytes + d.txBytes,
          rxPackets: c.rxPackets + d.rxPackets,
          txPackets: c.txPackets + d.txPackets,
        });
        return { name: s.name, rxKbps: Math.round((rxBps * 8) / 100) / 10, txKbps: Math.round((txBps * 8) / 100) / 10 };
      });
    this.lastNetDev = now;

    let cpuPct = 0;
    if (cpu && this.lastCpu && cpu.total > this.lastCpu.total) {
      const idleDelta = cpu.idle - this.lastCpu.idle;
      const totalDelta = cpu.total - this.lastCpu.total;
      cpuPct = Math.round((1 - idleDelta / totalDelta) * 1000) / 10;
    }
    this.lastCpu = cpu;

    let memPct = 0;
    if (mem && mem.totalBytes > 0) memPct = Math.round((1 - mem.availableBytes / mem.totalBytes) * 1000) / 10;

    // conntrack: real counter when present, else real TCP established count
    this.conntrackReal = await readConntrackCount().catch(() => null);
    this.tcpSessions = await readTcpSessions();
    this.udpEndpoints = await readUdpEndpoints();
    const conntrackCount = this.conntrackReal ?? this.tcpSessions.established;

    return {
      ts: new Date().toISOString(),
      ifaces,
      cpuPct: Math.max(0, cpuPct),
      memPct,
      conntrackCount,
    };
  }

  // ── WAN probes (real gateway TCP checks) ───────────────────────────────────

  private async wanProbeStep(): Promise<void> {
    const verbose = myTickVerbose(this.tickNo);
    const t0 = Date.now();
    // re-read WAN policies periodically (admin adds rows after boot)
    try {
      const wans = await db.wanPolicy.findMany({ where: { tenantId: 1 }, select: { interfaceName: true, enabled: true } });
      for (const w of wans) {
        if (w.enabled && !this.wanProbes.has(w.interfaceName)) {
          this.wanProbes.set(w.interfaceName, { state: "unknown", latencyMs: null, detail: "not probed yet", lastTs: 0 });
        }
      }
    } catch {
      // DB unavailable — keep current state
    }
    for (const [iface] of this.wanProbes) {
      const result = (await this.stageTimeout(`probeGateway:${iface}`, probeGateway(iface), 8000)) ?? {
        state: "unknown" as const,
        latencyMs: null,
        detail: "probe watchdog detached",
      };
      if (verbose) console.log(`[host-collector] wan probe ${iface} → ${result.state} (${Date.now() - t0}ms)`);
      const prev = this.wanProbes.get(iface)!;
      this.wanProbes.set(iface, { ...result, lastTs: Date.now() });
      if (prev.state !== result.state) {
        this.persistWanState(iface, result.state);
        if (result.state !== "unknown") {
          emitEvent({ type: "wan:status", payload: { iface, state: result.state } });
        }
      }
    }
  }

  private persistWanState(iface: string, state: string): void {
    void db.wanPolicy
      .updateMany({ where: { tenantId: 1, interfaceName: iface }, data: { state } })
      .catch(() => {});
  }

  // ── real optional sources (suricata / nft / wg / unbound) ──────────────────

  private async realSourcesStep(): Promise<void> {
    const verbose = myTickVerbose(this.tickNo);
    const t0 = Date.now();
    if (this.evePath === undefined) this.evePath = await detectSuricataEve();
    if (this.evePath) await this.stageTimeout("suricataStep", this.suricataStep(), 5000);

    if (this.unboundPath === undefined) this.unboundPath = await detectUnboundLog();
    if (this.unboundPath) await this.stageTimeout("unboundStep", this.unboundStep(), 5000);

    await this.stageTimeout("wireguardStep", this.wireguardStep(), 8000);
    await this.stageTimeout("kernelFirewallLogStep", this.kernelFirewallLogStep(), 10_000);
    this.journalSince = new Date(Date.now() - 12_000);
    if (verbose) console.log(`[host-collector] realSources done in ${Date.now() - t0}ms`);
  }

  /** Suricata eve.json → real ipsEvent rows + live tail. */
  private async suricataStep(): Promise<void> {
    const path = this.evePath;
    if (!path) return;
    let size = 0;
    try {
      const st = await stat(path);
      size = st.size;
    } catch {
      this.eveOffset = 0;
      return;
    }
    if (size < this.eveOffset) this.eveOffset = 0; // log rotated
    if (size === this.eveOffset) return;
    const fh = await fs.open(path, "r");
    try {
      const len = Math.min(size - this.eveOffset, 4 * 1024 * 1024);
      const buf = Buffer.alloc(len);
      await fh.read(buf, 0, len, this.eveOffset);
      this.eveOffset = size;
      const events: IpsEventEntry[] = [];
      for (const line of buf.toString("utf8").split("\n")) {
        if (!line.trim()) continue;
        const evt = this.parseEveAlert(line);
        if (evt) events.push(evt);
      }
      if (events.length === 0) return;
      try {
        await db.ipsEvent.createMany({
          data: events.map((e) => ({
            tenantId: 1,
            timestamp: new Date(e.ts),
            srcIp: e.srcIp,
            srcPort: e.srcPort,
            dstIp: e.dstIp,
            dstPort: e.dstPort,
            action: e.action,
            sid: e.sid,
            severity: e.severity,
            category: e.category,
            message: e.message,
          })),
        });
      } catch {
        // DB write failure — events still go to the live tail
      }
      for (const e of events) {
        this.logsRing.push({ kind: "ips", entry: e, seq: currentCursor() });
        emitEvent({ type: "logs:tail", payload: { kind: "ips", entry: e } });
      }
      if (this.logsRing.length > LOGS_RING_CAP) this.logsRing.splice(0, this.logsRing.length - LOGS_RING_CAP);
    } finally {
      await fh.close().catch(() => {});
    }
  }

  private parseEveAlert(line: string): IpsEventEntry | null {
    try {
      const j = JSON.parse(line) as {
        timestamp?: string;
        event_type?: string;
        src_ip?: string;
        src_port?: number;
        dest_ip?: string;
        dest_port?: number;
        proto?: string;
        alert?: { severity?: number; signature_id?: number; category?: string; signature?: string; action?: string };
      };
      if (j.event_type !== "alert" || !j.alert) return null;
      const sev = j.alert.severity ?? 8;
      const severity = sev <= 2 ? "critical" : sev <= 4 ? "high" : sev <= 6 ? "medium" : sev <= 8 ? "low" : "info";
      return {
        ts: j.timestamp ?? new Date().toISOString(),
        srcIp: j.src_ip ?? null,
        srcPort: j.src_port ?? null,
        dstIp: j.dest_ip ?? null,
        dstPort: j.dest_port ?? null,
        action: j.alert.action === "blocked" ? "blocked" : "allowed",
        sid: j.alert.signature_id ? String(j.alert.signature_id) : null,
        severity,
        category: j.alert.category ?? null,
        message: j.alert.signature ?? null,
      };
    } catch {
      return null;
    }
  }

  /** nftables kernel logs via journalctl → real firewallLog rows + live tail. */
  private async kernelFirewallLogStep(): Promise<void> {
    if (!(await hasTool("journalctl"))) return;
    const since = this.journalSince.toISOString().replace("T", " ").slice(0, 19);
    const res = await runTool(`journalctl -k -o cat --since "${since}" 2>/dev/null | head -400`, 8000);
    if (!res.ok || !res.stdout.trim()) return;
    const entries: FirewallLogEntry[] = [];
    for (const line of res.stdout.split("\n")) {
      if (!/IN=|OUT=/.test(line)) continue;
      const parsed = this.parseKernelFwLine(line);
      if (parsed) entries.push(parsed);
    }
    if (entries.length === 0) return;
    try {
      await db.firewallLog.createMany({
        data: entries.map((e) => ({
          tenantId: 1,
          timestamp: new Date(e.ts),
          srcIp: e.srcIp,
          dstIp: e.dstIp,
          srcPort: e.srcPort,
          dstPort: e.dstPort,
          protocol: e.protocol,
          action: e.action,
          ruleName: e.ruleName,
          appName: null,
          bytes: e.bytes,
          packets: e.packets,
          userName: null,
        })),
      });
    } catch {
      // DB write failure — keep the live tail
    }
    for (const e of entries) {
      this.logsRing.push({ kind: "firewall", entry: e, seq: currentCursor() });
      emitEvent({ type: "logs:tail", payload: { kind: "firewall", entry: e } });
    }
    if (this.logsRing.length > LOGS_RING_CAP) this.logsRing.splice(0, this.logsRing.length - LOGS_RING_CAP);
  }

  /**
   * Parse an nftables kernel log line:
   * `... CRYPTSK[ALLOW]: ... IN=eth0 SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP SPT=1 DPT=2`
   */
  private parseKernelFwLine(line: string): FirewallLogEntry | null {
    const get = (key: string): string | null => {
      const m = line.match(new RegExp(`(?:^|\\s)${key}=([^\\s]+)`));
      return m ? m[1] : null;
    };
    const srcIp = get("SRC");
    const dstIp = get("DST");
    if (!srcIp || !dstIp) return null;
    const protoRaw = (get("PROTO") ?? "UDP").toUpperCase();
    const protocol = protoRaw === "TCP" ? "tcp" : protoRaw === "UDP" ? "udp" : protoRaw === "ICMP" ? "icmp" : protoRaw.toLowerCase();
    const prefix = line.split(/\sIN=/)[0]?.trim() ?? "";
    const ruleMatch = prefix.match(/([A-Za-z0-9_-]+)\[([A-Za-z0-9_-]+)\]/);
    return {
      ts: new Date().toISOString(),
      srcIp,
      dstIp,
      srcPort: Number(get("SPT")) || 0,
      dstPort: Number(get("DPT")) || 0,
      protocol,
      action: (ruleMatch?.[2] ?? "deny").toLowerCase(),
      ruleName: ruleMatch?.[1] ?? null,
      appName: null,
      bytes: 0,
      packets: 1,
      userName: null,
    };
  }

  /** `wg show all dump` → real vpnSession sync + vpn status events. */
  private async wireguardStep(): Promise<void> {
    const peers = await readWgPeers();
    if (peers === null) return; // wg missing → honest empty
    if (peers.length === 0) return;
    const configs = await db.vpnConfig.findMany({ where: { tenantId: 1, type: { contains: "wireguard" } } }).catch(() => []);
    if (configs.length === 0) return;

    const nowSec = Math.floor(Date.now() / 1000);
    for (const peer of peers) {
      const cfg = configs.find((c) => c.name === peer.iface) ?? configs.find((c) => peer.iface.startsWith(c.name));
      if (!cfg) continue;
      const active = peer.handshakeAgeSec !== null && peer.handshakeAgeSec <= 180;
      const status = active ? "up" : peer.handshakeAgeSec !== null ? "idle" : "down";
      const assignedIp = peer.allowedIps[0]?.split("/")[0] ?? null;
      const sourceIp = peer.endpoint?.replace(/\[\]|\[.*\]/g, "").split(":")[0] ?? "0.0.0.0";

      const existing = await db.vpnSession.findFirst({
        where: { tenantId: 1, vpnId: cfg.id, assignedIp: assignedIp ?? undefined },
        orderBy: { id: "desc" },
      }).catch(() => null);

      if (!existing) {
        if (!active) continue; // don't invent sessions for never-connected peers
        await db.vpnSession.create({
          data: {
            tenantId: 1,
            vpnId: cfg.id,
            userName: peer.publicKey.slice(0, 12) + "…",
            sourceIp,
            assignedIp,
            bytesIn: peer.rxBytes,
            bytesOut: peer.txBytes,
            status: "active",
            lastActivity: new Date(),
          },
        }).catch(() => {});
      } else {
        await db.vpnSession.update({
          where: { id: existing.id },
          data: { bytesIn: peer.rxBytes, bytesOut: peer.txBytes, status: active ? "active" : "idle", lastActivity: new Date() },
        }).catch(() => {});
      }

      if (cfg.status !== status) {
        await db.vpnConfig.update({ where: { id: cfg.id }, data: { status, statusMessage: status === "up" ? `peer handshake ${peer.handshakeAgeSec}s ago` : status === "idle" ? "stale handshake" : "no handshake yet" } }).catch(() => {});
        emitEvent({ type: "vpn:status", payload: { vpnId: cfg.id, status: status === "up" ? "up" : "down" } });
      }
    }
  }

  /** unbound query log tail → dnsRing (real queries when unbound logs). */
  private async unboundStep(): Promise<void> {
    const path = this.unboundPath;
    if (!path) return;
    let size = 0;
    try {
      const st = await stat(path);
      size = st.size;
    } catch {
      this.unboundOffset = 0;
      return;
    }
    if (size < this.unboundOffset) this.unboundOffset = 0;
    if (size === this.unboundOffset) return;
    const fh = await fs.open(path, "r");
    try {
      const len = Math.min(size - this.unboundOffset, 2 * 1024 * 1024);
      const buf = Buffer.alloc(len);
      await fh.read(buf, 0, len, this.unboundOffset);
      this.unboundOffset = size;
      for (const line of buf.toString("utf8").split("\n")) {
        const q = this.parseUnboundQuery(line);
        if (q) {
          this.dnsRing.push(q);
        }
      }
      if (this.dnsRing.length > DNS_RING_CAP) this.dnsRing.splice(0, this.dnsRing.length - DNS_RING_CAP);
    } finally {
      await fh.close().catch(() => {});
    }
  }

  private parseUnboundQuery(line: string): DnsQueryLogEntry | null {
    // `... info: 1.2.3.4 query A www.example.com. IN`
    const m = line.match(/info:\s+(\d+\.\d+\.\d+\.\d+)\s+query\s+(\S+)\s+(\S+?\.?)\s+IN/);
    if (!m) return null;
    const [, clientIp, qtype, domain] = m;
    return {
      seq: currentCursor(),
      ts: new Date().toISOString(),
      clientIp,
      domain: domain.replace(/\.$/, ""),
      qtype,
      action: "allowed",
      blocked: false,
      category: null,
      latencyMs: 0,
    };
  }

  // ── slow cycle: kea leases, interfaces, disk, services ─────────────────────

  private slowRunNo = 0;
  private lastStageWarnAt = 0;

  /**
   * Hard per-stage watchdog: races `p` against `ms`. A stage that stalls
   * (spawn wedged, IO hang) is DETACHED with a rate-limited named warning
   * so the tick pipeline can never be dead-locked by a single source.
   */
  private stageTimeout<T>(label: string, p: Promise<T>, ms: number): Promise<T | null> {
    return new Promise<T | null>((resolve) => {
      let settled = false;
      const done = (v: T | null) => {
        if (!settled) {
          settled = true;
          resolve(v);
        }
      };
      const timer = setTimeout(() => {
        done(null);
        const now = Date.now();
        if (now - this.lastStageWarnAt > 300_000) {
          this.lastStageWarnAt = now;
          console.warn(`[host-collector] stage "${label}" exceeded ${ms}ms — detached from pipeline (check host: spawn/IO hang?)`);
        }
      }, ms);
      (timer as unknown as { unref?: () => void }).unref?.();
      p.then((v) => {
        clearTimeout(timer);
        done(v);
      }, () => {
        clearTimeout(timer);
        done(null);
      });
    });
  }

  /** Whether the last slow cycle reached the services read (null = not probed yet). */
  get servicesProbed(): boolean | null {
    return this.servicesAvailable;
  }

  private async slowStep(): Promise<void> {
    const t0 = Date.now();
    this.slowRunNo += 1;
    const verbose = this.slowRunNo <= 5 || this.slowRunNo % 10 === 0;
    if (verbose) console.log(`[host-collector] slowStep #${this.slowRunNo} (tick ${this.tickNo}) enter`);

    if (this.keaPath === undefined) this.keaPath = await detectKeaLeases();
    if (this.keaPath) await this.stageTimeout("keaStep", this.keaStep(), 8000);

    await this.stageTimeout("syncRealInterfaces", this.syncRealInterfaces(), 12_000);
    if (verbose) console.log(`[host-collector] slowStep #${this.slowRunNo} interfaces synced`);

    await this.stageTimeout("refreshDiskAndServices", this.refreshDiskAndServices(), 10_000);
    if (verbose) console.log(`[host-collector] slowStep #${this.slowRunNo} disk+services refreshed`);
    const dt = Date.now() - t0;
    if (dt > 8000) console.warn(`[host-collector] slowStep #${this.slowRunNo} took ${dt}ms — check earlier stage warnings`);
  }

  /** Kea memfile leases → real dhcpLease rows (subnet must resolve). */
  private async keaStep(): Promise<void> {
    const path = this.keaPath;
    if (!path) return;
    let content = "";
    try {
      const st = await stat(path);
      if (st.size === this.keaParsedSize) return;
      content = await readFile(path, "utf8");
      this.keaParsedSize = st.size;
    } catch {
      return;
    }
    const subnets = await db.dhcpSubnet.findMany({ where: { tenantId: 1 }, select: { id: true, networkCidr: true } }).catch(() => []);
    if (subnets.length === 0) return;
    for (const line of content.split("\n")) {
      const f = line.trim().split(",");
      if (f.length < 8 || f[0] === "address") continue;
      const ip = f[0];
      if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip)) continue;
      const subnet = subnets.find((s) => cidrContains(s.networkCidr, ip));
      if (!subnet) continue;
      const endsAt = Number(f[7]) > 0 ? new Date(Number(f[7]) * 1000) : new Date();
      await db.dhcpLease
        .upsert({
          where: { subnetId_ip: { subnetId: subnet.id, ip } },
          create: { tenantId: 1, subnetId: subnet.id, mac: (f[1] || f[2] || "unknown").slice(0, 64), ip, hostname: f[9] || null, state: "active", endsAt },
          update: { state: "active", endsAt, hostname: f[9] || null },
        })
        .catch(() => {});
    }
  }

  /** Upsert REAL host interfaces into the networkInterface table.
   *  MERGE semantics (BUG-6 fix): the collector owns the LIVE facts (mac,
   *  ipv4/ipv6 observation, operState, carrier) only — it must never clobber
   *  the console's desired-state fields (ip, cidrPrefix, gateway, wanType,
   *  dns, secondaryIps, lldp, speed, duplex) nor the operator-set role/mtu.
   *  The previous replace-everything update wiped L3 config every 30 ticks. */
  private async syncRealInterfaces(): Promise<void> {
    const real = await readInterfaces();
    if (real.length === 0) return;
    const existing = await db.networkInterface.findMany({ where: { tenantId: 1 }, select: { id: true, name: true, role: true, zoneId: true } }).catch(() => []);
    const existingNames = new Set(existing.map((i) => i.name));

    for (const iface of real) {
      // kernel pseudo-link — not a real interface, must never become a row
      if (iface.name === "bonding_masters") continue;
      const type = iface.name === "lo" ? "loopback" : "physical";
      const role = iface.isDefaultRoute ? "wan" : iface.name === "lo" ? "unused" : iface.ipv4.length > 0 ? "lan" : "unused";
      if (existingNames.has(iface.name)) {
        // merge: refresh live facts inside the existing config JSON
        const prev = await db.networkInterface
          .findFirst({ where: { tenantId: 1, name: iface.name }, select: { config: true } })
          .catch(() => null);
        let merged: Record<string, unknown> = {};
        try {
          merged = JSON.parse(prev?.config ?? "{}") as Record<string, unknown>;
        } catch {
          merged = {};
        }
        merged.mac = iface.mac;
        merged.ipv4 = iface.ipv4;
        merged.ipv6 = iface.ipv6.slice(0, 4);
        merged.operState = iface.operState;
        merged.carrier = iface.carrier;
        merged.source = "host-sync";
        await db.networkInterface
          .updateMany({
            where: { tenantId: 1, name: iface.name },
            data: { config: JSON.stringify(merged) },
          })
          .catch(() => {});
      } else {
        const config = JSON.stringify({ mac: iface.mac, ipv4: iface.ipv4, ipv6: iface.ipv6.slice(0, 4), operState: iface.operState, carrier: iface.carrier, source: "host-sync" });
        await db.networkInterface
          .create({
            data: { tenantId: 1, name: iface.name, type, mode: "l3", role, mtu: iface.mtu ?? 1500, enabled: iface.operState !== "down", config, description: "discovered by host collector (real interface)" },
          })
          .catch(() => {});
      }
    }
  }

  /** Real disk usage + systemd service states (appliance) / honest absence. */
  private async refreshDiskAndServices(): Promise<void> {
    const disk = await readDiskUsage(process.cwd());
    if (disk) this.diskPct = disk.usedPct;
    this.tempC = await readThermalC();

    const catalogUnits = ["nftables", "suricata", "sshd", "strongswan", "dnsmasq", "chronyd", "snmpd", "conntrackd", "rsyslogd", "unbound", "kea-dhcp4-server", "keepalived"];
    const states = await readServiceStates(catalogUnits);
    this.servicesAvailable = states !== null;
    if (states && (this.slowRunNo <= 5 || this.slowRunNo % 10 === 0)) {
      console.log(`[host-collector] service states: ${Object.entries(states).map(([u, s]) => `${u}=${s}`).join(" ")}`);
    }
    if (states) {
      const changed: string[] = [];
      for (const [unit, state] of Object.entries(states)) {
        if (this.lastServiceStates && this.lastServiceStates[unit] !== state) {
          changed.push(unit);
        }
      }
      this.lastServiceStates = states;
      for (const unit of changed) {
        const state = states[unit];
        const severity = state === "active" ? "info" : state === "failed" ? "critical" : "warning";
        await this.emitSystemNotification(
          severity,
          `Service ${unit} ${state}`,
          `systemd reports unit "${unit}" is now "${state}" on host ${hostname()}.`,
        );
      }
    }
  }

  /** Which systemd service states did we last observe (null = systemctl absent). */
  get serviceStates(): Record<string, string> | null {
    return this.lastServiceStates;
  }

  get nftStatus(): { available: boolean; permissionDenied: boolean } | null {
    return this.rulesetAvailable === null ? null : { available: this.rulesetAvailable, permissionDenied: false };
  }

  /** Read the real ruleset (used by firewall apply/status paths). */
  async currentRuleset(): Promise<string | null> {
    const rs = await readNftRuleset();
    this.rulesetAvailable = rs.available;
    return rs.available ? rs.ruleset : null;
  }

  /** Attempt a real systemctl restart; throws with the real error on failure. */
  async restartService(unit: string): Promise<{ restarted: boolean; error?: string }> {
    const res = await restartUnit(unit);
    if (res.ok) return { restarted: true };
    return { restarted: false, error: res.error ?? res.stderr ?? "restart failed" };
  }

  // ── threshold watcher (REAL vitals, edge-triggered) ────────────────────────

  private async thresholdStep(tick: MetricsTick | null): Promise<void> {
    if (!tick) return;
    const now = Date.now();
    if (now - this.lastThresholdLoad < 30_000) return;
    this.lastThresholdLoad = now;
    try {
      const row = await db.systemSetting.findUnique({
        where: { tenantId_category_key: { tenantId: 1, category: "notifications", key: "thresholds" } },
      });
      if (row) {
        const parsed = JSON.parse(row.value) as Partial<{ cpuPct: number; memPct: number; diskPct: number; tempC: number }>;
        this.thresholds = {
          cpuPct: parsed.cpuPct ?? 90,
          memPct: parsed.memPct ?? 90,
          diskPct: parsed.diskPct ?? 85,
          tempC: parsed.tempC ?? 80,
        };
      }
    } catch {
      // keep defaults
    }

    const checks: Array<{ key: string; label: string; value: number; unit: string; warnAt: number }> = [
      { key: "cpu", label: "CPU", value: tick.cpuPct, unit: "%", warnAt: this.thresholds.cpuPct },
      { key: "mem", label: "Memory", value: tick.memPct, unit: "%", warnAt: this.thresholds.memPct },
      { key: "disk", label: "Disk", value: this.diskPct, unit: "%", warnAt: this.thresholds.diskPct },
    ];
    if (this.tempC !== null) {
      checks.push({ key: "temp", label: "Temperature", value: this.tempC, unit: "°C", warnAt: this.thresholds.tempC });
    }
    for (const m of checks) {
      const open = this.openAlerts.get(m.key);
      const above = m.value >= m.warnAt && m.value > 0;
      const critical = above && (m.value >= m.warnAt + 10 || (open !== undefined && this.tickNo - open.crossedAtTick >= 150));
      if (!above) {
        if (open) {
          this.openAlerts.delete(m.key);
          await this.emitSystemNotification("info", `${m.label} back to normal`, `${m.label} recovered to ${m.value.toFixed(1)}${m.unit} (threshold ${m.warnAt}${m.unit}).`);
        }
        continue;
      }
      if (!open) {
        this.openAlerts.set(m.key, { crossedAtTick: this.tickNo, notifiedCritical: false });
        await this.emitSystemNotification("warning", `${m.label} above threshold`, `${m.label} at ${m.value.toFixed(1)}${m.unit} (threshold ${m.warnAt}${m.unit}).`);
      } else if (critical && !open.notifiedCritical) {
        open.notifiedCritical = true;
        await this.emitSystemNotification("critical", `${m.label} critical`, `${m.label} at ${m.value.toFixed(1)}${m.unit} — sustained beyond the ${m.warnAt}${m.unit} threshold.`);
      }
    }
  }

  private async emitSystemNotification(severity: string, title: string, message: string): Promise<void> {
    const notification = await db.notification
      .create({ data: { tenantId: 1, type: "system", severity, title, message, sourceModule: "system" } })
      .catch(() => null);
    if (!notification) return;
    emitEvent({
      type: "alerts:new",
      payload: {
        notification: {
          id: notification.id,
          type: notification.type,
          severity: notification.severity,
          title: notification.title,
          message: notification.message,
          sourceModule: notification.sourceModule,
          createdAt: notification.createdAt.toISOString(),
          isRead: notification.isRead,
        },
      },
    });
  }
}

// ── helpers ─────────────────────────────────────────────────────────────────

function hostname(): string {
  try {
    return os.hostname() || "appliance";
  } catch {
    return process.env.HOSTNAME || "appliance";
  }
}

function cidrContains(cidr: string, ip: string): boolean {
  const m = cidr.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
  if (!m) return false;
  const toInt = (s: string): number =>
    s.split(".").reduce((acc, o) => (acc << 8) + Number(o), 0) >>> 0;
  const base = toInt(m[1]);
  const probe = toInt(ip);
  const bits = Number(m[2]);
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (base & mask) === (probe & mask);
}

// ── singleton (globalThis trick, same as MockEngine) ────────────────────────

const g = globalThis as unknown as { __cryptskHostCollector?: HostCollector };

export function getHostCollector(): HostCollector {
  if (!g.__cryptskHostCollector) {
    g.__cryptskHostCollector = new HostCollector();
  }
  return g.__cryptskHostCollector;
}

export type { RealInterface, WgPeerDump };
