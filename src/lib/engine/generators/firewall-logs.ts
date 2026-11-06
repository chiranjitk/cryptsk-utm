/**
 * firewall-logs generator — SIMULATION_LAYER §6.
 * Plausible flows respecting active zones; action follows the rule mix;
 * hit counters bump the matched rule (flushed to DB by the engine).
 */

import type { FirewallLogEntry } from "../events";
import type { TrafficProfile } from "../profiles";

export interface RuleMeta {
  id: number;
  name: string;
  action: string;
  enabled: boolean;
}

const WAN_SRC = () => `198.51.100.${1 + Math.floor(Math.random() * 250)}`;

export class FirewallLogGenerator {
  constructor(
    private readonly rand: () => number,
    private rules: RuleMeta[],
    private profile: TrafficProfile,
  ) {}

  setRules(rules: RuleMeta[]) {
    this.rules = rules;
  }

  /** 0–3 log rows per tick */
  generate(lanHosts: string[], apps: string[]): FirewallLogEntry[] {
    const n = Math.floor(this.rand() * 4); // 0..3
    const out: FirewallLogEntry[] = [];
    for (let i = 0; i < n; i++) {
      const egress = this.rand() < 0.62;
      const srcIp = egress ? pick(this.rand, lanHosts) : WAN_SRC();
      const dstIp = egress
        ? `203.0.113.${2 + Math.floor(this.rand() * 250)}`
        : pick(this.rand, lanHosts);
      const blocked = this.rand() < this.profile.blockRate;
      const rule = blocked ? this.pickBlockRule() : this.pickAllowRule();
      const action = blocked ? pick(this.rand, ["deny", "drop", "reject"] as const) : "allow";
      out.push({
        ts: new Date().toISOString(),
        srcIp,
        dstIp,
        srcPort: 1024 + Math.floor(this.rand() * 64000),
        dstPort: pick(this.rand, [80, 443, 443, 53, 22, 3389, 5060, 51820, 8080]),
        protocol: this.rand() < 0.85 ? "tcp" : "udp",
        action,
        ruleName: rule?.name ?? "implicit-deny",
        appName: pick(this.rand, apps),
        bytes: Math.floor(500 + this.rand() * 8_000_000),
        packets: Math.floor(4 + this.rand() * 8000),
        userName: this.rand() < 0.35 ? pick(this.rand, ["j.doe", "a.smith", "m.lee", "g.guest"]) : null,
      });
    }
    return out;
  }

  private pickAllowRule(): RuleMeta | null {
    const allows = this.rules.filter((r) => r.enabled && r.action === "allow");
    return allows.length ? pick(this.rand, allows) : null;
  }
  private pickBlockRule(): RuleMeta | null {
    const blocks = this.rules.filter((r) => r.enabled && r.action !== "allow");
    return blocks.length ? pick(this.rand, blocks) : null;
  }
}

function pick<T>(rand: () => number, arr: readonly T[]): T {
  return arr[Math.floor(rand() * arr.length)];
}
