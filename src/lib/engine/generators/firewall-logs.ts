/**
 * firewall-logs generator — SIMULATION_LAYER §6 + M03 §5.
 * Flows are drawn from per-zone host pools, then evaluated through the REAL
 * firewall ruleset (position-first-match, schedule gating, group-expanded
 * addresses, app/user/MAC dimensions). Rows carry the matched rule name;
 * unmatched flows become implicit-deny rows. NAT hit counters increment for
 * the first matching enabled snat (egress) / dnat|hairpin (ingress) rule.
 */

import type { FirewallLogEntry } from "../events";
import {
  evaluateRules,
  serviceMatches,
  addrMatches,
  type EvalRule,
  type FlowSpec,
  type ServiceMatcher,
  type AddrMatcher,
} from "@/lib/firewall/rule-match";

export interface HostPoolEntry {
  ip: string;
  zoneId: number;
}

export interface NatEvalRule {
  id: number;
  name: string | null;
  type: "snat" | "dnat" | "hairpin" | "exempt";
  enabled: boolean;
  position: number;
  srcAddrs: AddrMatcher[];
  dstAddrs: AddrMatcher[];
  services: ServiceMatcher[];
  outgoingIface: string | null;
}

export interface GeneratedFlow {
  log: FirewallLogEntry;
  fwRuleId: number | null; // null = implicit deny
  natRuleId: number | null;
}

const WAN_INGRESS_SRC = () => `198.51.100.${1 + Math.floor(Math.random() * 250)}`;
const WAN_EGRESS_DST = () => `203.0.113.${2 + Math.floor(Math.random() * 250)}`;

export class FirewallLogGenerator {
  private zoneIds = { wan: 1, lan: 2, dmz: 3, vpn: 4 };

  constructor(
    private readonly rand: () => number,
    private rules: EvalRule[],
    private natRules: NatEvalRule[],
  ) {}

  setRules(rules: EvalRule[]) {
    this.rules = rules;
  }

  setNatRules(rules: NatEvalRule[]) {
    this.natRules = rules;
  }

  setZoneIds(zones: { wan: number; lan: number; dmz: number; vpn: number }) {
    if (zones.wan) this.zoneIds = zones;
  }

  /** 0–3 log rows per tick */
  generate(hosts: HostPoolEntry[], apps: string[], userNames: string[]): GeneratedFlow[] {
    const n = Math.floor(this.rand() * 4); // 0..3
    const out: GeneratedFlow[] = [];
    for (let i = 0; i < n; i++) {
      const egress = this.rand() < 0.62;
      const host = hosts.length ? hosts[Math.floor(this.rand() * hosts.length)] : { ip: "192.168.10.10", zoneId: this.zoneIds.lan };

      const dstPort = pick(this.rand, [80, 443, 443, 53, 22, 3389, 5060, 51820, 8080]);
      const protocol = this.rand() < 0.85 ? "tcp" : "udp";
      const app = apps.length ? pick(this.rand, apps) : null;
      const userName = userNames.length && this.rand() < 0.35 ? pick(this.rand, userNames) : null;
      const wanSrc = WAN_INGRESS_SRC();
      const wanDst = WAN_EGRESS_DST();

      const flow: FlowSpec = egress
        ? {
            srcIp: host.ip,
            dstIp: wanDst,
            srcPort: 1024 + Math.floor(this.rand() * 64000),
            dstPort,
            protocol,
            srcZoneId: host.zoneId,
            dstZoneId: this.zoneIds.wan,
            app,
            userName,
            srcMac: macForIp(host.ip),
          }
        : {
            srcIp: wanSrc,
            dstIp: host.ip,
            srcPort: 1024 + Math.floor(this.rand() * 64000),
            dstPort,
            protocol,
            srcZoneId: this.zoneIds.wan,
            dstZoneId: host.zoneId,
            app,
            userName,
            srcMac: macForIp(wanSrc),
          };

      const now = new Date();
      const matched = evaluateRules(this.rules, flow, now);
      const natRuleId = this.matchNat(flow, now, egress);

      out.push({
        log: {
          ts: now.toISOString(),
          srcIp: flow.srcIp,
          dstIp: flow.dstIp,
          srcPort: flow.srcPort,
          dstPort: flow.dstPort,
          protocol: flow.protocol,
          action: matched ? matched.action : "deny",
          ruleName: matched ? matched.name : "implicit deny",
          appName: flow.app,
          bytes: Math.floor(500 + this.rand() * 8_000_000),
          packets: Math.floor(4 + this.rand() * 8000),
          userName: flow.userName,
        },
        fwRuleId: matched ? matched.id : null,
        natRuleId,
      });
    }
    return out;
  }

  /** NAT pre-loop (M03 §5): first enabled match per direction, hit counter only. */
  private matchNat(f: FlowSpec, now: Date, egress: boolean): number | null {
    const ordered = [...this.natRules].filter((r) => r.enabled).sort((a, b) => a.position - b.position);
    for (const r of ordered) {
      if (egress) {
        if (r.type !== "snat") continue;
        if (r.srcAddrs.length > 0 && !r.srcAddrs.some((m) => addrMatches(m, f.srcIp, "src"))) continue;
      } else {
        if (r.type !== "dnat" && r.type !== "hairpin") continue;
        if (r.dstAddrs.length > 0 && !r.dstAddrs.some((m) => addrMatches(m, f.dstIp, "dst"))) continue;
      }
      if (r.outgoingIface && egress && r.outgoingIface !== "wan0") continue;
      if (r.services.length > 0 && !r.services.some((s) => serviceMatches(s, f.protocol, f.srcPort, f.dstPort))) continue;
      return r.id;
    }
    return null;
  }
}

function pick<T>(rand: () => number, arr: readonly T[]): T {
  return arr[Math.floor(rand() * arr.length)];
}

function macForIp(ip: string): string {
  const last = Number(ip.split(".")[3] ?? 0);
  const hex = (last % 256).toString(16).padStart(2, "0");
  return `aa:bb:cc:dd:ee:${hex}`;
}
