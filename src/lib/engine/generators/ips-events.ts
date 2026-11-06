/**
 * ips-events generator — SIMULATION_LAYER §6.
 * ET-style sids (2xxxxxx ranges per category), severity distribution per
 * profile, inline_drop policies produce drops that correlate with firewall logs.
 */

import type { IpsEventEntry } from "../events";
import type { TrafficProfile } from "../profiles";

const CATS: Array<[string, string, number]> = [
  // [category, default severity, sid base]
  ["scan", "medium", 2100000],
  ["web_attack", "high", 2020000],
  ["xss", "medium", 2021000],
  ["trojan", "critical", 2024000],
  ["botnet", "critical", 2025000],
  ["phishing", "high", 2026000],
  ["malware", "high", 2030000],
  ["exploit", "critical", 2032000],
  ["brute_force", "medium", 2101000],
  ["dos", "high", 2100000],
  ["info_leak", "low", 2200000],
  ["policy", "info", 2210000],
];

function weightedPick(rand: () => number, pairs: Array<[string, number]>): string {
  const total = pairs.reduce((s, [, w]) => s + w, 0);
  let r = rand() * total;
  for (const [v, w] of pairs) {
    r -= w;
    if (r <= 0) return v;
  }
  return pairs[pairs.length - 1][0];
}

export class IpsEventGenerator {
  constructor(
    private readonly rand: () => number,
    private profile: TrafficProfile,
  ) {}

  setProfile(p: TrafficProfile) {
    this.profile = p;
  }

  /** 0–1 event per tick (rate from profile) */
  generate(): IpsEventEntry | null {
    if (this.rand() > this.profile.ipsEventRate) return null;
    const severity = weightedPick(this.rand, this.profile.severityMix);
    const cat = CATS.find(([, sev]) => sev === severity) ?? CATS[Math.floor(this.rand() * CATS.length)];
    const [category, , sidBase] = cat;
    const ingress = this.rand() < 0.6;
    const action = severity === "critical" || severity === "high" ? "drop" : "alert";
    return {
      ts: new Date().toISOString(),
      srcIp: ingress ? `198.51.100.${2 + Math.floor(this.rand() * 250)}` : `192.168.10.${2 + Math.floor(this.rand() * 250)}`,
      srcPort: 1024 + Math.floor(this.rand() * 64000),
      dstIp: ingress ? "203.0.113.2" : "172.16.20.5",
      dstPort: Number(pick(this.rand, [80, 443, 22, 3389, 8080])),
      action,
      sid: String(sidBase + 1 + Math.floor(this.rand() * 9000)),
      severity,
      category,
      message: `${category.replace(/_/g, " ")} signature matched (simulated ET rule)`,
    };
  }
}

function pick<T>(rand: () => number, arr: readonly T[]): T {
  return arr[Math.floor(rand() * arr.length)];
}
