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
import { loadVpnRuntime, type VpnGroupRuntime, type VpnRemoteRuntime } from "@/lib/vpn/service";
import {
  SessionChurnMachine,
  VpnStateMachine,
  WanProbeMachine,
  type VpnTunnelState,
  type VpnTunnelStatus,
  type WanProbeState,
} from "./generators/sessions";
import { DnsQueryGenerator, type DnsPolicyRuntime, type DnsQueryLogEntry } from "./generators/dns-queries";
import { loadDnsRuntime } from "@/lib/dns/service";
import { DhcpLeaseMachine, type DhcpRuntime } from "./generators/dhcp-leases";
import { loadDhcpRuntime } from "@/lib/dhcp/service";
import { loadQosRuntime, type QosRuntime } from "@/lib/qos/runtime";
import type { QosShaper } from "./generators/metrics";
import {
  IdentitySessionMachine,
  type IdentityChurnConfig,
  type IdentitySessionRuntime,
} from "./generators/identity-sessions";
import { consumeVoucher } from "@/lib/identity/vouchers";

export interface VpnSessionState {
  id: number;
  vpnId: number;
  userName: string | null;
  status: string; // active | idle | disconnected
  assignedIp?: string | null;
  bytesIn: number;
  bytesOut: number;
  lastActivity: string;
  /** group-policy churn timers (M05 §5) — set at load/spawn */
  idleChanceMul?: number;
  disconnectChanceMul?: number;
  expiresAt?: string | null;
}

/** Simulated remote-user roster (seed-aligned; identity is M07 scope). */
const REMOTE_ROSTER = ["c.reyes", "m.okafor", "j.tanaka", "l.novak", "s.patel", "d.kim", "r.almeida", "k.johnson", "a.hassan", "p.muller"];
const VPN_SESSION_TARGET = 10; // DATA_LIFECYCLE §5: ~10 live rows
const SPAWN_COOLDOWN_TICKS = 60; // kicked users are not respawned for ~2 min

export interface LogRingEntry {
  kind: "firewall" | "ips";
  entry: FirewallLogEntry | IpsEventEntry;
  seq: number;
}

const METRICS_RING_CAP = 500; // SIMULATION_LAYER §4
const LOGS_RING_CAP = 2000; // SIMULATION_LAYER §4
const DNS_RING_CAP = 2000; // M06 §8 sanctions 2000 (engine-only change)
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
  /** M06: derived DNS query log — ring-only, never persisted (M06 §2/§5.4). */
  readonly dnsRing: DnsQueryLogEntry[] = [];

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
  private vpnGroups: VpnGroupRuntime[] = [];
  private vpnRemote: VpnRemoteRuntime[] = [];
  private lastVpnLoad = 0;
  private disconnectedUsers = new Map<string, number>(); // userName → tickNo
  private hitDeltas = new Map<number, number>();
  private natHitDeltas = new Map<number, number>();

  private metricsGen = new MetricsGenerator(this.rand);
  private fwGen = new FirewallLogGenerator(this.rand, [], []);
  private ipsGen = new IpsEventGenerator(this.rand, this.profile);
  private wanMachine = new WanProbeMachine(this.rand, this.profile.wanFlapRate);
  private vpnMachine = new VpnStateMachine(this.rand);
  private churn = new SessionChurnMachine(this.rand);
  private dnsGen = new DnsQueryGenerator(this.rand, this.profile);
  private dhcpMachine = new DhcpLeaseMachine(this.rand);

  private pendingFwLogs: FirewallLogEntry[] = [];
  private pendingIpsEvents: IpsEventEntry[] = [];
  private dnsRuntime: DnsPolicyRuntime | null = null;
  private lastDnsLoad = 0;
  private dhcpRuntime: DhcpRuntime = { subnets: [], reservations: [], leases: [] };
  private lastDhcpLoad = 0;
  // M08: enabled shaper policies feed the metrics generator budget clamp
  private qosRuntime: QosRuntime = { policies: [] };
  private lastQosLoad = 0;
  private identityMachine = new IdentitySessionMachine(this.rand);
  private identitySessions: IdentitySessionRuntime[] = [];
  private identityBacklog: Array<{ id: number; userName?: string | null; status?: string; lastActivity?: string }> = [];
  private lastIdentityLoad = 0;
  private identityCfg: IdentityChurnConfig = {
    portalEnabled: false,
    portalMode: "clickthrough",
    portalTimeoutMin: 240,
    maxConcurrentPerUser: 4,
    userNames: [],
  };
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
      const [ifaces, wans] = await Promise.all([
        db.networkInterface.findMany({ where: { tenantId: 1 }, select: { name: true, role: true, enabled: true } }),
        db.wanPolicy.findMany({ where: { tenantId: 1 }, include: { interface: { select: { enabled: true } } } }),
      ]);
      this.ifaces = ifaces.map((i) => ({ name: i.name, role: i.role, enabled: i.enabled }));
      await Promise.all([this.reloadPolicy(true), this.reloadIpsPolicies(true), this.reloadDnsState(true), this.reloadDhcpState(true), this.reloadQosState(true)]);
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
      // M05: tunnels + sessions + group policies (VpnStateMachine takes over)
      await this.reloadVpnState(true);
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
    // collect every section first (no per-event break — two different-section
    // saves inside one 2 s window must both reload)
    let fw = false;
    let ips = false;
    let vpn = false;
    let dns = false;
    let dhcp = false;
    let qos = false;
    for (const e of events) {
      if (e.type !== "config:updated") continue;
      const s = e.payload.section;
      if (s === "firewall" || s === "nat") fw = true; // firewall rules expand
      else if (s === "ips") ips = true; // M04: re-arm the ips generator
      else if (s === "vpn") vpn = true; // M05: tunnels + sessions re-sync
      else if (s === "dns") dns = true; // M06: policies + resolver settings
      else if (s === "dhcp") dhcp = true; // M06: subnets/reservations churn
      else if (s === "qos") qos = true; // M08: shaper budgets re-arm the clamp
    }
    if (fw) void this.reloadPolicy(true);
    if (ips) void this.reloadIpsPolicies(true);
    if (vpn) void this.reloadVpnState(true);
    if (dns) void this.reloadDnsState(true);
    if (dhcp) void this.reloadDhcpState(true);
    if (qos) void this.reloadQosState(true);
  }

  /**
   * (Re)load tunnel + session state from the DB (M05 §5): tunnels mirror
   * enabled/status from the API apply-edge; sessions re-sync counters/status
   * so API disconnects are honored (no zombie rows persisting over the DB).
   * Called on bootstrap and on `config:updated {section: vpn}` (3 s throttle).
   */
  async reloadVpnState(force = false): Promise<void> {
    const now = Date.now();
    if (!force && now - this.lastVpnLoad < 3000) return;
    this.lastVpnLoad = now;
    try {
      const rt = await loadVpnRuntime(1);
      this.vpnGroups = rt.groups;
      this.vpnRemote = rt.remote;
      const byId = new Map(this.tunnels.map((t) => [t.id, t]));
      this.tunnels = rt.tunnels.map((t) => ({
        id: t.id,
        name: t.name,
        type: t.type,
        enabled: t.enabled,
        status: (["up", "down", "connecting", "error"].includes(t.status) ? t.status : "down") as VpnTunnelStatus,
        dpdTicks: byId.get(t.id)?.dpdTicks ?? 0,
        peerLabel: t.peerLabel,
      }));
      const rows = await db.vpnSession.findMany({
        where: { tenantId: 1 },
        select: { id: true, vpnId: true, userName: true, status: true, assignedIp: true, bytesIn: true, bytesOut: true, lastActivity: true, connectedAt: true },
      });
      const memById = new Map(this.vpnSessions.map((s) => [s.id, s]));
      this.vpnSessions = rows.map((s) => {
        const mem = memById.get(s.id);
        const churn = this.churnFieldsFor(s.userName);
        return {
          id: s.id,
          vpnId: s.vpnId,
          userName: s.userName,
          status: s.status,
          assignedIp: s.assignedIp,
          bytesIn: Math.max(s.bytesIn, mem?.bytesIn ?? 0),
          bytesOut: Math.max(s.bytesOut, mem?.bytesOut ?? 0),
          lastActivity: s.lastActivity.toISOString(),
          ...churn,
          expiresAt: churn.expiresAt(mem?.expiresAt ?? s.connectedAt.toISOString()),
        };
      });
    } catch (err) {
      console.error("[mock-engine] reloadVpnState failed:", err instanceof Error ? err.message : err);
    }
  }

  /** Group-policy churn timers for a session of `userName` (M05 §5). */
  private churnFieldsFor(userName: string | null): {
    idleChanceMul: number;
    disconnectChanceMul: number;
    expiresAt: (connectedIso: string) => string | null;
  } {
    const group = userName ? this.vpnGroups.find((g) => g.members.includes(userName)) : undefined;
    if (!group) return { idleChanceMul: 1, disconnectChanceMul: 1, expiresAt: () => null };
    return {
      idleChanceMul: group.idleTimeoutMin != null ? 1.5 : 1,
      disconnectChanceMul: group.idleTimeoutMin != null ? 3 : 1,
      expiresAt: (connectedIso) =>
        group.maxSessionMin != null
          ? new Date(Date.parse(connectedIso) + group.maxSessionMin * 60_000).toISOString()
          : null,
    };
  }

  /**
   * Spawn one remote-access session to keep ~10 live rows (DATA_LIFECYCLE §5).
   * assignedIp comes from the matching group pool when the user is a member,
   * else the config pool; maxSessionsPerUser blocks the connect (M05 §5).
   */
  private async spawnVpnSession(): Promise<void> {
    const live = this.vpnSessions.filter((s) => s.status !== "disconnected");
    if (live.length >= VPN_SESSION_TARGET) return;
    const hubs = this.vpnRemote.filter((r) => r.enabled && r.pool);
    if (hubs.length === 0) return;

    const candidates = REMOTE_ROSTER.filter((u) => {
      if (live.some((s) => s.userName === u)) return false;
      const seen = this.disconnectedUsers.get(u);
      return seen == null || this.tickNo - seen > SPAWN_COOLDOWN_TICKS;
    });
    if (candidates.length === 0) return;
    const userName = candidates[Math.floor(this.rand() * candidates.length)];

    const group = this.vpnGroups.find((g) => g.members.includes(userName));
    if (group?.maxSessionsPerUser != null) {
      const held = this.vpnSessions.filter((s) => s.userName === userName && s.status !== "disconnected").length;
      if (held >= group.maxSessionsPerUser) return; // "session limit reached"
    }

    const hub = hubs[Math.floor(this.rand() * hubs.length)];
    const pool = group?.pool ?? hub.pool ?? null;
    if (!pool) return;
    const used = new Set(live.map((s) => (s.assignedIp ?? "").split("/")[0]).filter(Boolean));
    const assigned = this.randomPoolIp(pool, used);
    if (!assigned) return;

    const now = new Date();
    const created = await db.vpnSession
      .create({
        data: {
          tenantId: 1,
          vpnId: hub.id,
          userName,
          sourceIp: `198.51.100.${60 + Math.floor(this.rand() * 180)}`,
          assignedIp: assigned,
          groupName: group?.name ?? null,
          bytesIn: 0,
          bytesOut: 0,
          connectedAt: now,
          lastActivity: now,
          status: "active",
        },
      })
      .catch(() => null);
    if (!created) return;
    const churn = this.churnFieldsFor(userName);
    this.vpnSessions.push({
      id: created.id,
      vpnId: hub.id,
      userName,
      status: "active",
      assignedIp: assigned,
      bytesIn: 0,
      bytesOut: 0,
      lastActivity: now.toISOString(),
      idleChanceMul: churn.idleChanceMul,
      disconnectChanceMul: churn.disconnectChanceMul,
      expiresAt: churn.expiresAt(now.toISOString()),
    });
  }

  /** First free host under `pool` not in `used` (deterministic scan from .10). */
  private randomPoolIp(pool: string, used: Set<string>): string | null {
    const [base, prefixRaw] = pool.split("/");
    const prefix = Number(prefixRaw);
    if (!Number.isFinite(prefix) || prefix < 8 || prefix > 32) return null;
    const octets = base.split(".").map(Number);
    if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return null;
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const network = (((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) & mask) >>> 0;
    const size = 2 ** (32 - prefix);
    for (let i = 10; i < size - 1; i++) {
      const n = network + i;
      const ip = [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
      if (!used.has(ip)) return `${ip}/32`;
    }
    return null;
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

  /**
   * M06: enabled DNS policies (id asc) + resolver settings arm the query-log
   * generator (evaluation order per M06 §5.1). 3 s throttle, same as rules.
   */
  async reloadDnsState(force = false): Promise<void> {
    const now = Date.now();
    if (!force && now - this.lastDnsLoad < 3000) return;
    this.lastDnsLoad = now;
    try {
      this.dnsRuntime = await loadDnsRuntime(1);
      this.dnsGen.setRuntime(this.dnsRuntime);
    } catch (err) {
      console.error("[mock-engine] reloadDnsState failed:", err instanceof Error ? err.message : err);
    }
  }

  /**
   * M06: enabled IPv4 subnets + reservations + active leases feed the lease
   * churn machine. v6 subnets are config-only in simulation (M06 §5.4).
   */
  async reloadDhcpState(force = false): Promise<void> {
    const now = Date.now();
    if (!force && now - this.lastDhcpLoad < 3000) return;
    this.lastDhcpLoad = now;
    try {
      this.dhcpRuntime = await loadDhcpRuntime(1);
    } catch (err) {
      console.error("[mock-engine] reloadDhcpState failed:", err instanceof Error ? err.message : err);
    }
  }

  /**
   * M08 §5.4: enabled shaper policies arm the metrics-generator budget clamp.
   * 3 s throttle, same as the other loaders; policy disable/enable and rule
   * edits arrive via `config:updated {section: qos}`.
   */
  async reloadQosState(force = false): Promise<void> {
    const now = Date.now();
    if (!force && now - this.lastQosLoad < 3000) return;
    this.lastQosLoad = now;
    try {
      this.qosRuntime = await loadQosRuntime(1);
    } catch (err) {
      console.error("[mock-engine] reloadQosState failed:", err instanceof Error ? err.message : err);
    }
  }

  /** QosShaper list for the metrics tick — guaranteed share of the first
   *  (highest-priority) guaranteed rule is reserved before clamping. */
  private qosShapers(): QosShaper[] {
    return this.qosRuntime.policies.map((p) => ({
      ifaceName: p.ifaceName,
      bandwidthKbps: p.bandwidthKbps,
      guaranteedFloorKbps: p.rules.find((r) => r.guaranteedKbps != null)?.guaranteedKbps ?? 0,
    }));
  }

  /**
   * M07: captive portal profile + auth session caps + enabled users arm the
   * identity churn machine. 15 s throttle — slower-moving config.
   */
  async reloadIdentityState(force = false): Promise<void> {
    const now = Date.now();
    if (!force && now - this.lastIdentityLoad < 15_000) return;
    this.lastIdentityLoad = now;
    try {
      const [portal, authSettings, users] = await Promise.all([
        db.captivePortalProfile.findFirst({ where: { tenantId: 1 }, orderBy: { id: "asc" } }),
        import("@/lib/identity/service").then((m) => m.getAuthSettings()),
        db.user.findMany({ where: { tenantId: 1, isActive: true }, select: { username: true } }),
      ]);
      this.identityCfg = {
        portalEnabled: portal?.enabled ?? false,
        portalMode: portal?.mode ?? "clickthrough",
        portalTimeoutMin: portal?.sessionTimeoutMin ?? 240,
        maxConcurrentPerUser: authSettings.sessionLimits.maxConcurrentPerUser,
        userNames: users.map((u) => u.username),
      };
    } catch (err) {
      console.error("[mock-engine] reloadIdentityState failed:", err instanceof Error ? err.message : err);
    }
  }

  private async tick(): Promise<void> {
    try {
      this.tickNo += 1;
      // self-heal across HMR: the globalThis singleton keeps old generator
      // instances; re-syncing the profile is idempotent and cheap.
      this.ipsGen.setProfile(this.profile);
      this.dnsGen.setProfile(this.profile);

      // 0) config:updated watcher — firewall/nat/ips/vpn policy reloads
      // (API routes emit in another bundle; the global ring bridges them)
      this.watchPolicyChanges();

      // 1) metrics (QoS shaper budgets clamp the series — M08 §5.4)
      const tick = this.metricsGen.tick(this.ifaces, this.tickNo, this.profile.baselines, this.qosShapers());
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
            next === "up"
              ? `Tunnel established — handshake complete with ${t.peerLabel ?? "peer"}`
              : next === "connecting"
                ? "IKE/DPD negotiation in progress"
                : "Tunnel down";
          emitEvent({ type: "vpn:status", payload: { vpnId: t.id, status: next, statusMessage: msg } });
          // persist the transition immediately — status reads (list + /status
          // dialogs) come from the DB and must not lag the state machine by
          // up to PERSIST_EVERY ticks (M05 §6: badges refetch on vpn:status)
          void db.vpnConfig
            .update({ where: { id: t.id }, data: { status: next, statusMessage: msg } })
            .catch(() => {});
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

      // 5b) dns query log — derived view, ring-only, never persisted, and no
      // socket event (M06 §2/§5.4/§6: the Query Log tab polls)
      for (const q of this.dnsGen.generate()) {
        this.dnsRing.push(q);
      }
      if (this.dnsRing.length > DNS_RING_CAP) this.dnsRing.splice(0, this.dnsRing.length - DNS_RING_CAP);

      // 6) vpn session churn
      const churnDiffs = this.churn.step(this.vpnSessions);
      for (const d of churnDiffs) {
        if (d.status === "disconnected" && d.userName) this.disconnectedUsers.set(d.userName, this.tickNo);
      }
      this.sessionDiffsBacklog.push(...churnDiffs);
      if (this.tickNo % SESSIONS_EMIT_EVERY === 0 && this.sessionDiffsBacklog.length > 0) {
        emitEvent({ type: "sessions:update", payload: { kind: "vpn", diff: this.sessionDiffsBacklog.slice(0, 50) } });
        this.sessionDiffsBacklog = [];
      }

      // 6b) spawn remote-access sessions to keep ~10 live rows (DATA_LIFECYCLE §5)
      if (this.tickNo % 5 === 0 && this.rand() < 0.15) {
        await this.spawnVpnSession();
      }

      // 6c) dhcp lease churn — planner plans, engine executes DB I/O (M06 §5.4)
      await this.dhcpChurnStep();

      // 6d) identity session churn — M07 §5.5 (portal logins, voucher
      // consumption, concurrent cap, lastSeen bumps, sessions:update diffs)
      await this.identityChurnStep();

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
    // dhcp leases: expired/released rows kept 7 days (DATA_LIFECYCLE §4 / M06 §4)
    await db.dhcpLease
      .deleteMany({
        where: {
          tenantId: 1,
          state: { in: ["expired", "released"] },
          endsAt: { lt: new Date(Date.now() - 7 * 86_400_000) },
        },
      })
      .catch(() => {});
  }

  /** M07 §5.5 identity churn: apply the planner's expire/cap/login plan. */
  private async identityChurnStep(): Promise<void> {
    await this.reloadIdentityState();
    const rows = await db.identitySession
      .findMany({
        where: { tenantId: 1 },
        select: { id: true, userName: true, sourceIp: true, method: true, state: true, lastSeen: true },
      })
      .catch(() => []);
    this.identitySessions = rows.map((r) => ({
      id: r.id,
      userName: r.userName,
      sourceIp: r.sourceIp,
      method: r.method,
      state: r.state,
      lastSeenMs: r.lastSeen.getTime(),
    }));

    const plan = this.identityMachine.step(this.identitySessions, this.identityCfg);

    // voucher-mode portal logins consume a live voucher first (M07 §5.4);
    // without an unused voucher the login is refused (dropped from the plan)
    if (this.identityCfg.portalEnabled && this.identityCfg.portalMode === "voucher") {
      for (const _ of plan.logins.filter((l) => l.method === "captive_portal")) {
        if (!consumeVoucher()) {
          const idx = plan.logins.findIndex((l) => l.method === "captive_portal");
          if (idx >= 0) plan.logins.splice(idx, 1);
        }
      }
    }

    const now = new Date();
    // lastSeen bump — light cadence, aligned with the emit cadence
    if (plan.bumpAll && this.tickNo % 5 === 0) {
      await db.identitySession
        .updateMany({ where: { tenantId: 1, state: "active" }, data: { lastSeen: now } })
        .catch(() => {});
    }
    const gone = new Set<number>([...plan.expireIds, ...plan.capExpiredIds]);
    if (gone.size > 0) {
      await db.identitySession
        .updateMany({ where: { id: { in: [...gone] } }, data: { state: "expired", lastSeen: now } })
        .catch(() => {});
      for (const id of gone) this.identityBacklog.push({ id, status: "expired" });
    }
    for (const login of plan.logins) {
      // @@unique([tenantId, sourceIp]) — a login from the same IP replaces
      // the prior session (M07 §5.5)
      const prior = await db.identitySession
        .findFirst({ where: { tenantId: 1, sourceIp: login.sourceIp } })
        .catch(() => null);
      const data = {
        userName: login.userName,
        method: login.method,
        deviceMac: login.deviceMac,
        startedAt: now,
        lastSeen: now,
        state: "active",
      };
      const row = prior
        ? await db.identitySession.update({ where: { id: prior.id }, data }).catch(() => null)
        : await db.identitySession.create({ data: { tenantId: 1, ...data } }).catch(() => null);
      if (row) {
        this.identityBacklog.push({
          id: row.id,
          userName: row.userName,
          status: row.state,
          lastActivity: row.lastSeen.toISOString(),
        });
      }
    }

    if (this.tickNo % SESSIONS_EMIT_EVERY === 0 && this.identityBacklog.length > 0) {
      emitEvent({ type: "sessions:update", payload: { kind: "identity", diff: this.identityBacklog.slice(0, 50) } });
      this.identityBacklog = [];
    }
  }

  /** M06 §5.4 lease churn: apply the planner's renew/release/expire/create plan. */
  private async dhcpChurnStep(): Promise<void> {
    if (this.dhcpRuntime.subnets.length === 0) return;
    const nowMs = Date.now();
    const plan = this.dhcpMachine.step(this.dhcpRuntime, nowMs);
    for (const id of plan.expireIds) {
      await db.dhcpLease.update({ where: { id }, data: { state: "expired" } }).catch(() => {});
    }
    for (const id of plan.renewIds) {
      const lease = this.dhcpRuntime.leases.find((l) => l.id === id);
      const leaseTimeSec = lease?.leaseTimeSec ?? 86400;
      await db.dhcpLease
        .update({ where: { id }, data: { endsAt: new Date(nowMs + leaseTimeSec * 1000) } })
        .catch(() => {});
    }
    for (const id of plan.releaseIds) {
      await db.dhcpLease.update({ where: { id }, data: { state: "released" } }).catch(() => {});
    }
    const gone = new Set<number>([...plan.expireIds, ...plan.releaseIds]);
    this.dhcpRuntime.leases = this.dhcpRuntime.leases.filter((l) => !gone.has(l.id));
    for (const c of plan.creates) {
      // release frees the IP for reuse — prune stale non-active rows first (M06 §3);
      // @@unique([subnetId, ip]) then accepts the fresh insert
      await db.dhcpLease
        .deleteMany({ where: { subnetId: c.subnetId, ip: c.ip, state: { not: "active" } } })
        .catch(() => {});
      const created = await db.dhcpLease
        .create({
          data: {
            tenantId: 1,
            subnetId: c.subnetId,
            mac: c.mac,
            ip: c.ip,
            hostname: c.hostname,
            state: "active",
            startsAt: new Date(nowMs),
            endsAt: new Date(c.endsAtMs),
          },
        })
        .catch(() => null);
      if (created) {
        this.dhcpRuntime.leases.push({
          id: created.id,
          subnetId: c.subnetId,
          mac: c.mac,
          ip: c.ip,
          hostname: c.hostname,
          endsAtMs: c.endsAtMs,
          leaseTimeSec: this.dhcpRuntime.subnets.find((s) => s.id === c.subnetId)?.leaseTime ?? 86400,
        });
      }
    }
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
