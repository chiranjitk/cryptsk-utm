/**
 * AgentEngine — EngineLike implementation served by a REMOTE sensor agent
 * (ADR-004 / deploy/AGENT_ADAPTER_CHECKLIST.md). Selected when
 * ADAPTER_MODE=agent: the console stops reading local /proc entirely and
 * consumes only what the Go agent (:8080) transports from the sensor host.
 *
 * Snapshot contract (console ⇄ agent, LOCKED):
 *   POST /v1/engine/snapshot  { sinceLogSeq, sinceDnsSeq }
 *   → { data: {
 *       tickNumber: number, uptimeSec: number,
 *       vitals: { cpuPct, memPct, diskPct, tempC },
 *       metricsTick: MetricsTick,
 *       metricsHistory?: MetricsTick[],          // one-shot backfill (~70 ticks)
 *       logsTail?:  LogRingEntry[],              // entries after sinceLogSeq
 *       dnsTail?:   DnsQueryLogEntry[],          // entries after sinceDnsSeq
 *       wanStates?: Array<{ iface: string; state: string }>,
 *     } }
 *
 * NO-FABRICATION POLICY (ADR-021): rings stay empty until the agent delivers
 * real entries; transport failures back off and log — nothing is ever invented.
 * Real log tails (ips / firewall) are PERSISTED into the same ipsEvent /
 * firewallLog tables HostCollector writes, so every dashboard aggregate stays
 * real in agent mode. Realtime events (metrics:tick / logs:tail / wan:status)
 * are re-emitted into the shared event ring so realtime-service :3003 works
 * unchanged.
 */

import { emitEvent, type FirewallLogEntry, type IpsEventEntry, type MetricsTick } from "./events";
import type { LogRingEntry } from "./mock-engine";
import { db } from "@/lib/db";
import { agentCall } from "@/lib/adapters/agent";
import type { DnsQueryLogEntry } from "./generators/dns-queries";

const TICK_MS = 2_000; // locked 2 s cadence (SIMULATION_LAYER §4 → checklist row 2)
const METRICS_RING_CAP = 500;
const LOGS_RING_CAP = 2_000;
const DNS_RING_CAP = 2_000;
const ERROR_LOG_EVERY = 15; // log transport failures every 15th tick (~30 s)

interface AgentVitals {
  cpuPct: number;
  memPct: number;
  diskPct: number;
  tempC: number;
}

interface AgentSnapshot {
  tickNumber: number;
  uptimeSec: number;
  vitals: AgentVitals;
  metricsTick: MetricsTick;
  metricsHistory?: MetricsTick[];
  logsTail?: LogRingEntry[];
  dnsTail?: DnsQueryLogEntry[];
  wanStates?: Array<{ iface: string; state: string }>;
}

export class AgentEngine {
  readonly metricsRing: MetricsTick[] = [];
  readonly logsRing: LogRingEntry[] = [];
  readonly dnsRing: DnsQueryLogEntry[] = [];
  uptimeSec = 0;
  tickNumber = 0;
  wanStates: Array<{ iface: string; state: string }> = [];

  private vitals: AgentVitals = { cpuPct: 0, memPct: 0, diskPct: 0, tempC: 0 };
  private sinceLogSeq = 0;
  private sinceDnsSeq = 0;
  private started = false;
  private running = false;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private errorTicks = 0;
  private backfilled = false;

  systemVitals(): AgentVitals {
    return { ...this.vitals };
  }

  async forceProbe(iface: string): Promise<"up" | "degraded" | "down" | "unknown" | null> {
    // 30 s mutation window — a real gateway probe on the sensor host
    const res = await agentCall<{ state: "up" | "degraded" | "down" | "unknown" | null }>(
      "/v1/wan/probe",
      { iface },
      { mutation: true },
    );
    const probed = res?.state || null; // "" → null (agent probed, no verdict)
    if (probed) {
      const known = this.wanStates.find((w) => w.iface === iface);
      if (known) known.state = probed;
      if (probed !== "unknown") {
        emitEvent({ type: "wan:status", payload: { iface, state: probed } });
      }
    }
    return probed;
  }

  async start(): Promise<void> {
    if (this.started) return;
    this.started = true;
    this.running = true;
    this.scheduleTick(TICK_MS);
    console.log("[agent-engine] polling remote sensor snapshot every 2s");
  }

  /** stops the poll loop (used by tests / graceful shutdown) */
  stop(): void {
    this.running = false;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  private scheduleTick(delay: number): void {
    if (!this.running) return;
    this.timer = setTimeout(() => void this.tick().catch(() => {}), delay);
  }

  private async tick(): Promise<void> {
    let snapshot: AgentSnapshot | null = null;
    try {
      snapshot = await agentCall<AgentSnapshot>("/v1/engine/snapshot", {
        sinceLogSeq: this.sinceLogSeq,
        sinceDnsSeq: this.sinceDnsSeq,
      });
      this.errorTicks = 0;
    } catch (err) {
      this.errorTicks += 1;
      if (this.errorTicks % ERROR_LOG_EVERY === 1) {
        console.error(
          `[agent-engine] sensor unreachable (${err instanceof Error ? err.message : err}) — keeping last known state, inventing nothing`,
        );
      }
    }

    if (snapshot) this.absorb(snapshot);

    // drift-corrected cadence: next tick TICK_MS from now, regardless of call latency
    this.scheduleTick(TICK_MS);
  }

  /** merge one agent snapshot into the rings + emit realtime events */
  private absorb(s: AgentSnapshot): void {
    this.tickNumber = s.tickNumber ?? this.tickNumber + 1;
    this.uptimeSec = s.uptimeSec ?? this.uptimeSec;
    if (s.vitals) this.vitals = { ...s.vitals };

    // one-shot chart backfill straight from the sensor
    if (!this.backfilled && Array.isArray(s.metricsHistory) && s.metricsHistory.length > 0) {
      for (const t of s.metricsHistory.slice(-METRICS_RING_CAP)) {
        this.metricsRing.push(t);
      }
      if (this.metricsRing.length > METRICS_RING_CAP) {
        this.metricsRing.splice(0, this.metricsRing.length - METRICS_RING_CAP);
      }
      this.backfilled = true;
    }

    if (s.metricsTick) {
      this.metricsRing.push(s.metricsTick);
      if (this.metricsRing.length > METRICS_RING_CAP) this.metricsRing.shift();
      emitEvent({ type: "metrics:tick", payload: s.metricsTick });
    }

    if (Array.isArray(s.logsTail) && s.logsTail.length > 0) {
      // persist the real sensor rows into the same tables host mode writes
      // (mirrors HostCollector.suricataStep / kernelFirewallLogStep)
      const ips = s.logsTail.filter((e) => e.kind === "ips").map((e) => e.entry as IpsEventEntry);
      const fw = s.logsTail.filter((e) => e.kind === "firewall").map((e) => e.entry as FirewallLogEntry);
      if (ips.length > 0) {
        void db.ipsEvent
          .createMany({
            data: ips.map((e) => ({
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
          })
          .catch(() => {}); // DB failure — live tail still flows
      }
      if (fw.length > 0) {
        void db.firewallLog
          .createMany({
            data: fw.map((e) => ({
              tenantId: 1,
              timestamp: new Date(e.ts),
              srcIp: e.srcIp,
              dstIp: e.dstIp,
              srcPort: e.srcPort,
              dstPort: e.dstPort,
              protocol: e.protocol,
              action: e.action,
              ruleName: e.ruleName,
              appName: e.appName,
              bytes: e.bytes,
              packets: e.packets,
              userName: e.userName,
            })),
          })
          .catch(() => {});
      }
      for (const e of s.logsTail) {
        this.logsRing.push(e);
        if (e.seq > this.sinceLogSeq) this.sinceLogSeq = e.seq;
        emitEvent({ type: "logs:tail", payload: { kind: e.kind, entry: e.entry } });
      }
      if (this.logsRing.length > LOGS_RING_CAP) {
        this.logsRing.splice(0, this.logsRing.length - LOGS_RING_CAP);
      }
    }

    if (Array.isArray(s.dnsTail)) {
      for (const q of s.dnsTail) {
        this.dnsRing.push(q);
        if (q.seq > this.sinceDnsSeq) this.sinceDnsSeq = q.seq;
      }
      if (this.dnsRing.length > DNS_RING_CAP) {
        this.dnsRing.splice(0, this.dnsRing.length - DNS_RING_CAP);
      }
    }

    if (Array.isArray(s.wanStates)) {
      const changed = JSON.stringify(s.wanStates) !== JSON.stringify(this.wanStates);
      this.wanStates = s.wanStates.map((w) => ({ iface: w.iface, state: w.state }));
      const first = this.wanStates[0];
      // EngineEvent locks wan:status payloads to up|down|degraded — the agent
      // only ever reports those three verdicts (probeGateway never says unknown)
      if (changed && first && (first.state === "up" || first.state === "down" || first.state === "degraded")) {
        emitEvent({ type: "wan:status", payload: { iface: first.iface, state: first.state } });
      }
    }
  }
}

// ── singleton (globalThis trick, same as the other engines) ──────────────────
const AGENT_ENGINE_KEY = "__cryptskAgentEngine";

export function getAgentEngine(): AgentEngine {
  const g = globalThis as unknown as { [AGENT_ENGINE_KEY]?: AgentEngine };
  if (!g[AGENT_ENGINE_KEY]) g[AGENT_ENGINE_KEY] = new AgentEngine();
  return g[AGENT_ENGINE_KEY];
}
