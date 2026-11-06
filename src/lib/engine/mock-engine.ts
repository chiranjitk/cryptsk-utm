/**
 * MockEngine — sandbox stand-in for the appliance data plane (SIMULATION_LAYER §4).
 * 2 s tick loop; seeded PRNG (mulberry32, MOCK_SEED env, default 1337);
 * ring buffers: 500 metric ticks + 2000 log entries; periodic persistence to
 * SQLite so /api/v1/logs/* and /api/v1/ips/events return live data.
 * Singleton per process (globalThis guard survives HMR).
 */

import { db } from "@/lib/db";
import { emitEvent, eventsSince, currentCursor, type FirewallLogEntry, type IpsEventEntry, type MetricsTick } from "./events";
import { getProfile, type TrafficProfile } from "./profiles";
import { MetricsGenerator, type IfaceMeta } from "./generators/metrics";
import {
  FirewallLogGenerator,
  type HostPoolEntry,
  type NatEvalRule,
} from "./generators/firewall-logs";
import { loadEvalRules, loadExpansionContext } from "@/lib/firewall/rule-loader";
import { parseIds } from "@/lib/firewall/refs";
import type { EvalRule } from "@/lib/firewall/rule-match";
import { IpsEventGenerator, type IpsPolicyRuntime } from "./generators/ips-events";
import { loadIpsPolicyStates } from "@/lib/ips/service";
import {
  SessionChurnMachine,
  VpnStateMachine,
  WanProbeMachine,
  type VpnTunnelState,
  type VpnTunnelStatus,
  type WanProbeState,
} from "./generators/sessions";

export interface VpnSessionState {
  id: number;
  vpnId: number;
  userName: string | null;
  status: string; // active | idle | disconnected
  bytesIn: number;
  bytesOut: number;
  lastActivity: string;
}

export interface LogRingEntry {
  kind: "firewall" | "ips";
  entry: FirewallLogEntry | IpsEventEntry;
  seq: number;
}

const METRICS_RING_CAP = 500; // SIMULATION_LAYER §4
const LOGS_RING_CAP = 2000; // SIMULATION_LAYER §4
const TICK_MS = 2000;
const PERSIST_EVERY = 10; // ticks (20 s)
const SESSIONS_EMIT_EVERY = 5; // ticks
const RETENTION_EVERY = 250; // ticks



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

class MockEngine {
  private started = false;
  private starting: Promise<void> | null = null;
  private timer: ReturnType<typeof setInterval> | null = null;
  private tickNo = 0;
  private rand: () => number = mulberry32(Number(process.env.MOCK_SEED ?? 1337));
  private profile: TrafficProfile = getProfile();

  readonly metricsRing: MetricsTick[] = [];
  readonly logsRing: LogRingEntry[] = [];

  private ifaces: IfaceMeta[] = [];
  private rules: EvalRule[] = [];
  private ipsPolicy: IpsPolicyRuntime | null = null; // default policy (ADR-017)
  private lastIpsLoad = 0;
  private ruleNameToId = new Map<string, number>();
  private hostPools: HostPoolEntry[] = [];
  private userNames: string[] = [];
  private policySeq = 0; // last event seq seen by the policy watcher
  private lastPolicyLoad = 0;
  private wanProbes = new Map<string, WanProbeState>();
  private tunnels: VpnTunnelState[] = [];
  private vpnSessions: VpnSessionState[] = [];
  private hitDeltas = new Map<number, number>();
  private natHitDeltas = new Map<number, number>();

  private metricsGen = new MetricsGenerator(this.rand);
  private fwGen = new FirewallLogGenerator(this.rand, [], []);
  private ipsGen = new IpsEventGenerator(this.rand, this.profile);
  private wanMachine = new WanProbeMachine(this.rand, this.profile.wanFlapRate);
  private vpnMachine = new VpnStateMachine(this.rand);
  private churn = new SessionChurnMachine(this.rand);

  private pendingFwLogs: FirewallLogEntry[] = [];
  private pendingIpsEvents: IpsEventEntry[] = [];
  private sessionDiffsBacklog: Array<{ id: number; userName: string | null; status?: string; bytesIn?: number; bytesOut?: number; lastActivity?: string }> = [];
  private lastAlertTick = -100;

  get uptimeSec(): number {
    return 983412 + Math.floor(process.uptime());
  }
  get tickNumber(): number {
    return this.tickNo;
  }
  get wanStates(): Array<{ iface: string; state: string }> {
    return [...this.wanProbes.values()].map((p) => ({ iface: p.iface, state: p.enabled ? p.state : "down" }));
  }

  /**
   * Force an immediate probe cycle for one WAN iface (M02 §5 "Probe now").
   * NOTE: bootstrap() only runs once — WAN policies created after engine boot
   * are not in wanProbes, so this returns null for them (sandbox behavior).
   */
  forceProbe(iface: string): "up" | "degraded" | "down" | "unknown" | null {
    const p = this.wanProbes.get(iface);
    if (!p) return null;
    if (!p.enabled) return null;
    // run a few immediate cycles so thresholds can actually cross
    for (let i = 0; i < 3; i++) this.wanMachine.step(p);
    if (p.state !== "unknown") emitEvent({ type: "wan:status", payload: { iface: p.iface, state: p.state } });
    return p.state;
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
    // first tick immediately so the UI has data on boot
    void this.tick();
  }

  private async bootstrap(): Promise<void> {
    try {
      const [ifaces, wans, vpns] = await Promise.all([
        db.networkInterface.findMany({ where: { tenantId: 1 }, select: { name: true, role: true, enabled: true } }),
        db.wanPolicy.findMany({ where: { tenantId: 1 }, include: { interface: { select: { enabled: true } } } }),
        db.vpnConfig.findMany({ where: { tenantId: 1 }, select: { id: true, name: true, type: true, enabled: true, status: true } }),
      ]);
      this.ifaces = ifaces.map((i) => ({ name: i.name, role: i.role, enabled: i.enabled }));
      await Promise.all([this.reloadPolicy(true), this.reloadIpsPolicies(true)]);
      this.policySeq = currentCursor();
      for (const w of wans) {
        this.wanProbes.set(w.interfaceName, {
          iface: w.interfaceName,
          enabled: w.enabled && w.interface.enabled,
          state: (w.state === "up" || w.state === "degraded" ? w.state : "down") as WanProbeState["state"],
          goodProbes: 0,
          badProbes: 0,
        });
      }
      this.tunnels = vpns.map((v) => ({
        id: v.id,
        name: v.name,
        type: v.type,
        enabled: v.enabled,
        status: (["up", "down", "connecting", "error"].includes(v.status) ? v.status : "down") as VpnTunnelStatus,
        dpdTicks: 0,
      }));
      const sessions = await db.vpnSession.findMany({
        where: { tenantId: 1, status: { not: "disconnected" } },
        select: { id: true, vpnId: true, userName: true, status: true, bytesIn: true, bytesOut: true, lastActivity: true },
      });
      this.vpnSessions = sessions.map((s) => ({
        id: s.id,
        vpnId: s.vpnId,
        userName: s.userName,
        status: s.status,
        bytesIn: s.bytesIn,
        bytesOut: s.bytesOut,
        lastActivity: s.lastActivity.toISOString(),
      }));
    } catch (err) {
      console.error("[mock-engine] bootstrap failed (will retry):", err instanceof Error ? err.message : err);
      // retry in 5 s — DB may not be ready yet
      setTimeout(() => {
        this.starting = null;
        void this.start();
      }, 5000);
      throw err;
    }
  }

  private logSeq = 0;

  /**
   * (Re)load the policy the generator enforces: enabled firewall rules with
   * fully expanded matchers (M03 §5), NAT rules for hit counters, zone pools
   * and the user roster. Called on bootstrap and whenever a `config:updated`
   * event for section firewall|nat is observed (throttled to 3 s).
   */
  async reloadPolicy(force = false): Promise<void> {
    const now = Date.now();
    if (!force && now - this.lastPolicyLoad < 3000) return;
    this.lastPolicyLoad = now;
    try {
      const [{ rules }, ctx, zones, natRows] = await Promise.all([
        loadEvalRules(1),
        loadExpansionContext(1),
        db.zone.findMany({ where: { tenantId: 1 }, select: { id: true, name: true } }),
        db.natRule.findMany({ where: { tenantId: 1 }, orderBy: { position: "asc" } }),
      ]);
      this.rules = rules;
      this.ruleNameToId = new Map(rules.map((r) => [r.name, r.id]));
      this.fwGen.setRules(rules);

      const natRules: NatEvalRule[] = natRows.map((n) => ({
        id: n.id,
        name: n.name,
        type: n.type as NatEvalRule["type"],
        enabled: n.enabled,
        position: n.position,
        srcAddrs: ctx.expandAddr(parseIds(n.srcAddrIds)),
        dstAddrs: ctx.expandAddr(parseIds(n.dstAddrIds)),
        services: ctx.expandSvc(parseIds(n.serviceIds)),
        outgoingIface: n.outgoingIface,
      }));
      this.fwGen.setNatRules(natRules);

      const byName = (n: string) => zones.find((z) => z.name === n)?.id ?? 0;
      this.fwGen.setZoneIds({
        wan: byName("WAN"),
        lan: byName("LAN"),
        dmz: byName("DMZ"),
        vpn: byName("VPN"),
      });

      // per-zone host pools for flow generation (deterministic, seed-style)
      const lanHosts = Array.from({ length: 24 }, (_, i) => `192.168.10.${10 + i * 10}`)
        .concat(Array.from({ length: 8 }, (_, i) => `192.168.20.${100 + i * 2}`))
        .map((ip) => ({ ip, zoneId: byName("LAN") }));
      const dmzHosts = Array.from({ length: 6 }, (_, i) => `172.16.20.${10 + i}`)
        .map((ip) => ({ ip, zoneId: byName("DMZ") }));
      const vpnHosts = Array.from({ length: 6 }, (_, i) => `10.99.1.${10 + i}`)
        .map((ip) => ({ ip, zoneId: byName("VPN") }));
      this.hostPools = [...lanHosts, ...dmzHosts, ...vpnHosts];

      const users = await db.user.findMany({ where: { tenantId: 1 }, select: { username: true } });
      this.userNames = users.map((u) => u.username);
    } catch (err) {
      console.error("[mock-engine] reloadPolicy failed:", err instanceof Error ? err.message : err);
    }
  }

  private watchPolicyChanges(): void {
    const { events, cursor } = eventsSince(this.policySeq);
    this.policySeq = cursor;
    for (const e of events) {
      if (e.type === "config:updated" && (e.payload.section === "firewall" || e.payload.section === "nat")) {
        void this.reloadPolicy(true);
        break;
      }
      // M04: policy/category/mode/preset changes re-arm the ips generator
      if (e.type === "config:updated" && e.payload.section === "ips") {
        void this.reloadIpsPolicies(true);
        break;
      }
    }
  }

  /**
   * (Re)load the IPS policy the generator enforces: enabled policies with
   * expanded category sets; the default policy is the first enabled by id asc
   * (ADR-017). Called on bootstrap and on `config:updated {section: ips}`
   * (throttled to 3 s, same as firewall rules).
   */
  async reloadIpsPolicies(force = false): Promise<void> {
    const now = Date.now();
    if (!force && now - this.lastIpsLoad < 3000) return;
    this.lastIpsLoad = now;
    try {
      const states = await loadIpsPolicyStates(1);
      // default policy = first enabled by seed order; prefer one attached to an
      // enabled rule when present so events match visible attachment
      const attached = states.find((p) => p.attachedToEnabledRule);
      this.ipsPolicy = attached ?? states[0] ?? null;
      this.ipsGen.setPolicy(this.ipsPolicy);
    } catch (err) {
      console.error("[mock-engine] reloadIpsPolicies failed:", err instanceof Error ? err.message : err);
    }
  }

  private async tick(): Promise<void> {
    try {
      this.tickNo += 1;
      // self-heal across HMR: the globalThis singleton keeps old generator
      // instances; re-syncing the profile is idempotent and cheap.
      this.ipsGen.setProfile(this.profile);

      // 1) metrics
      const tick = this.metricsGen.tick(this.ifaces, this.tickNo, this.profile.baselines);
      this.metricsRing.push(tick);
      if (this.metricsRing.length > METRICS_RING_CAP) this.metricsRing.shift();
      emitEvent({ type: "metrics:tick", payload: tick });

      // 2) wan probes
      for (const p of this.wanProbes.values()) {
        const next = this.wanMachine.step(p);
        if (next && next !== "unknown") {
          emitEvent({ type: "wan:status", payload: { iface: p.iface, state: next } });
        }
      }

      // 3) vpn tunnels
      for (const t of this.tunnels) {
        const next = this.vpnMachine.step(t);
        if (next) {
          const msg =
            next === "up" ? "Tunnel established" : next === "connecting" ? "IKE/DPD negotiation in progress" : "Tunnel down";
          emitEvent({ type: "vpn:status", payload: { vpnId: t.id, status: next, statusMessage: msg } });
        }
      }

      // 4) firewall logs (+ rule hit counters)
      const apps = this.profile.appMix.map(([a]) => a);
      const fwFlows = this.fwGen.generate(this.hostPools, apps, this.userNames);
      for (const flow of fwFlows) {
        const log = flow.log;
        // fwRuleId comes from the rule matcher — falls back to name lookup
        const ruleId = flow.fwRuleId ?? this.ruleNameToId.get(log.ruleName ?? "") ?? this.rules.find((r) => r.name === log.ruleName)?.id;
        if (ruleId) this.hitDeltas.set(ruleId, (this.hitDeltas.get(ruleId) ?? 0) + 1);
        this.logSeq += 1;
        this.logsRing.push({ kind: "firewall", entry: log, seq: this.logSeq });
        this.pendingFwLogs.push(log);
      }
      if (this.logsRing.length > LOGS_RING_CAP) this.logsRing.splice(0, this.logsRing.length - LOGS_RING_CAP);

      // 5) ips events (+ threat alerts as notifications)
      const generated = this.ipsGen.generate();
      const ips = generated?.event ?? null;
      if (ips) {
        this.logSeq += 1;
        this.logsRing.push({ kind: "ips", entry: ips, seq: this.logSeq });
        this.pendingIpsEvents.push(ips);
        if (this.logsRing.length > LOGS_RING_CAP) this.logsRing.splice(0, this.logsRing.length - LOGS_RING_CAP);

        // inline_drop policies also produce a correlated firewall_logs row
        // for the same flow (SIMULATION_LAYER §6 / M04 §5)
        if (generated!.correlatedFwDrop) {
          const fwCorrelated: FirewallLogEntry = {
            ts: ips.ts,
            srcIp: ips.srcIp ?? "0.0.0.0",
            dstIp: ips.dstIp ?? "0.0.0.0",
            srcPort: ips.srcPort ?? 0,
            dstPort: ips.dstPort ?? 0,
            protocol: "tcp",
            action: "drop",
            ruleName: this.ipsPolicy ? `ips:${this.ipsPolicy.name}` : "ips",
            appName: null,
            bytes: 800 + Math.floor(this.rand() * 60000),
            packets: 4 + Math.floor(this.rand() * 40),
            userName: null,
          };
          this.pendingFwLogs.push(fwCorrelated);
          emitEvent({ type: "logs:tail", payload: { kind: "firewall", entry: fwCorrelated } });
        }
        if ((ips.severity === "high" || ips.severity === "critical") && this.tickNo - this.lastAlertTick > 10) {
          this.lastAlertTick = this.tickNo;
          const notification = await db.notification
            .create({
              data: {
                tenantId: 1,
                type: "threat",
                severity: ips.severity === "critical" ? "critical" : "warning",
                title: `IPS ${ips.severity}: ${ips.category ?? "event"} on ${ips.action === "drop" ? "wan0" : "lan"}`,
                message: ips.message,
                sourceModule: "ips",
              },
            })
            .catch(() => null);
          if (notification) {
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
        emitEvent({ type: "logs:tail", payload: { kind: "ips", entry: ips } });
      }
      for (const flow of fwFlows) {
        emitEvent({ type: "logs:tail", payload: { kind: "firewall", entry: flow.log } });
      }

      // 6) vpn session churn
      const churnDiffs = this.churn.step(this.vpnSessions);
      this.sessionDiffsBacklog.push(...churnDiffs);
      if (this.tickNo % SESSIONS_EMIT_EVERY === 0 && this.sessionDiffsBacklog.length > 0) {
        emitEvent({ type: "sessions:update", payload: { kind: "vpn", diff: this.sessionDiffsBacklog.slice(0, 50) } });
        this.sessionDiffsBacklog = [];
      }

      // 7) periodic persistence
      if (this.tickNo % PERSIST_EVERY === 0) await this.persist();

      // 8) retention housekeeping
      if (this.tickNo % RETENTION_EVERY === 0) await this.retention();
    } catch (err) {
      console.error("[mock-engine] tick error:", err instanceof Error ? err.message : err);
    }
  }

  private async persist(): Promise<void> {
    // firewall logs
    const fw = this.pendingFwLogs.splice(0, this.pendingFwLogs.length);
    if (fw.length) {
      await db.firewallLog
        .createMany({
          data: fw.map((l) => ({
            tenantId: 1,
            timestamp: new Date(l.ts),
            srcIp: l.srcIp,
            dstIp: l.dstIp,
            srcPort: l.srcPort,
            dstPort: l.dstPort,
            protocol: l.protocol,
            action: l.action,
            ruleName: l.ruleName,
            appName: l.appName,
            bytes: l.bytes,
            packets: l.packets,
            userName: l.userName,
          })),
        })
        .catch((e: unknown) => {
          console.error("[mock-engine] firewallLog createMany failed:", e instanceof Error ? e.message : e);
        });
    }
    // ips events
    const ips = this.pendingIpsEvents.splice(0, this.pendingIpsEvents.length);
    if (ips.length) {
      await db.ipsEvent
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
        .catch(() => {});
    }
    // rule hit counters
    if (this.hitDeltas.size) {
      for (const [id, delta] of this.hitDeltas) {
        await db.firewallRule
          .update({ where: { id }, data: { hitCount: { increment: delta }, lastHitAt: new Date() } })
          .catch(() => {});
      }
      this.hitDeltas.clear();
    }
    // wan policy states
    for (const p of this.wanProbes.values()) {
      await db.wanPolicy
        .updateMany({ where: { tenantId: 1, interfaceName: p.iface }, data: { state: p.enabled ? p.state : "down" } })
        .catch(() => {});
    }
    // vpn tunnel statuses
    for (const t of this.tunnels) {
      await db.vpnConfig
        .update({ where: { id: t.id }, data: { status: t.status } })
        .catch(() => {});
    }
    // vpn session byte counters / status
    for (const s of this.vpnSessions) {
      await db.vpnSession
        .update({
          where: { id: s.id },
          data: { bytesIn: s.bytesIn, bytesOut: s.bytesOut, status: s.status, lastActivity: new Date(s.lastActivity) },
        })
        .catch(() => {});
    }
    // dhcp lease expiry housekeeping (lease state machine — DATA_LIFECYCLE §4)
    await db.dhcpLease
      .updateMany({ where: { tenantId: 1, state: "active", endsAt: { lt: new Date() } }, data: { state: "expired" } })
      .catch(() => {});
  }

  private async retention(): Promise<void> {
    // firewall_logs cap 50k, ips_events cap 5k (DATA_LIFECYCLE §4)
    await trim("firewallLog", 50_000);
    await trim("ipsEvent", 5_000);
  }
}

async function trim(model: "firewallLog" | "ipsEvent", cap: number) {
  const count =
    model === "firewallLog"
      ? await db.firewallLog.count({ where: { tenantId: 1 } })
      : await db.ipsEvent.count({ where: { tenantId: 1 } });
  if (count <= cap) return;
  const excess = count - cap;
  const oldest =
    model === "firewallLog"
      ? await db.firewallLog.findMany({
          where: { tenantId: 1 },
          orderBy: { timestamp: "asc" },
          take: excess,
          select: { id: true },
        })
      : await db.ipsEvent.findMany({
          where: { tenantId: 1 },
          orderBy: { timestamp: "asc" },
          take: excess,
          select: { id: true },
        });
  const ids = oldest.map((r) => r.id);
  if (model === "firewallLog") await db.firewallLog.deleteMany({ where: { id: { in: ids } } }).catch(() => {});
  else await db.ipsEvent.deleteMany({ where: { id: { in: ids } } }).catch(() => {});
}

// ── singleton (survives HMR via globalThis) ────────────────────────────────
const g = globalThis as unknown as { __cryptskMockEngine?: MockEngine };

export function getMockEngine(): MockEngine {
  if (!g.__cryptskMockEngine) g.__cryptskMockEngine = new MockEngine();
  return g.__cryptskMockEngine;
}

export type { MockEngine };
