/**
 * ips-events generator — SIMULATION_LAYER §6, M04 §5.
 * Policy-aware: category gating (enabled categories of the applicable
 * policy), mode semantics (inline_drop → drop + correlated firewall log;
 * inline_tap/passive → detect-only alerts), preprocessor family gating,
 * TI blocklist feed drops (c2/malware), threshold rate-limiting
 * (action = suppressed) and exception bypass (ADR-017, sid 0 = any-SID).
 * ET-style sid ranges (2xxxxxx) come from the category catalog.
 */

import type { IpsEventEntry } from "../events";
import type { TrafficProfile } from "../profiles";
import { CATEGORY_CATALOG, TI_FEED_IPS, categoryDef, type ExceptionRow, type PreprocessorMap, type ThresholdRow } from "@/lib/ips/catalog";

export interface IpsPolicyRuntime {
  id: number;
  name: string;
  mode: "inline_drop" | "inline_tap" | "passive";
  enabledCategories: string[];
  preprocessors: PreprocessorMap;
  tiBlocklist: boolean;
  exceptions: ExceptionRow[];
  thresholds: ThresholdRow[];
  attachedToEnabledRule: boolean;
}

/** IPv4 CIDR containment (plain IP treated as /32) — exception matching. */
export function cidrContains(cidr: string, ip: string): boolean {
  const [base, bitsRaw] = cidr.split("/");
  if (!base) return false;
  const toInt = (v: string): number | null => {
    const parts = v.split(".");
    if (parts.length !== 4) return null;
    let n = 0;
    for (const p of parts) {
      const oct = Number(p);
      if (!Number.isInteger(oct) || oct < 0 || oct > 255) return null;
      n = (n << 8) | oct;
    }
    return n >>> 0;
  };
  const baseInt = toInt(base);
  const ipInt = toInt(ip);
  if (baseInt == null || ipInt == null) return base === ip;
  const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (baseInt & mask) === (ipInt & mask);
}

interface RuntimeCategory {
  name: string;
  sidBase: number;
  baseSeverity: IpsEventEntry["severity"];
  family: "stream" | "http" | "tls" | "ssh" | "generic";
}

const RUNTIME_CATS: RuntimeCategory[] = CATEGORY_CATALOG.map((c) => ({
  name: c.name,
  sidBase: c.sidBase,
  baseSeverity: c.baseSeverity,
  family: c.family,
}));

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
  /** engine-level default policy = first enabled by seed order (ADR-017) */
  private policy: IpsPolicyRuntime | null = null;
  /** per-sid+track timestamp windows for threshold suppression */
  private thresholdWindows = new Map<string, number[]>();
  private dosBurst = 0; // escalates severity when bursts continue

  constructor(
    private readonly rand: () => number,
    private profile: TrafficProfile,
  ) {}

  setProfile(p: TrafficProfile) {
    this.profile = p;
  }

  setPolicy(p: IpsPolicyRuntime | null) {
    if (this.policy?.id !== p?.id) this.thresholdWindows.clear();
    this.policy = p;
  }

  /** event probability per tick */
  private get rate(): number {
    return this.profile.ipsEventRate;
  }

  /**
   * 0–1 event per tick. Returns the event plus whether an inline drop
   * verdict applies (inline_drop mode) so the engine can correlate a
   * firewall_logs row with action=drop for the same flow.
   */
  generate(): { event: IpsEventEntry; correlatedFwDrop: boolean } | null {
    if (this.rand() > this.rate) return null;
    const policy = this.policy;
    if (!policy) return null; // no enabled policy → engine passes traffic silently

    const ingress = this.rand() < 0.6;
    // source pool: external 60% / LAN 25% / 10.0.0.0/24 15% (exception-testable)
    const srcRoll = this.rand();
    const srcIp =
      ingress || srcRoll < 0.6
        ? TI_FEED_IPS.length && this.rand() < 0.12
          ? TI_FEED_IPS[Math.floor(this.rand() * TI_FEED_IPS.length)]
          : `198.51.100.${2 + Math.floor(this.rand() * 250)}`
        : srcRoll < 0.85
          ? `192.168.10.${2 + Math.floor(this.rand() * 250)}`
          : `10.0.0.${2 + Math.floor(this.rand() * 250)}`;
    const dstIp = ingress ? "203.0.113.2" : this.rand() < 0.5 ? "172.16.20.5" : `192.168.10.${10 + Math.floor(this.rand() * 20)}`;

    // ── TI blocklist: feed-sourced sources drop at IPS level (M04 §5) ──
    if (policy.tiBlocklist && TI_FEED_IPS.includes(srcIp)) {
      const cat = this.rand() < 0.5 ? "c2" : "malware";
      const def = categoryDef(cat)!;
      const severity: IpsEventEntry["severity"] = this.rand() < 0.4 ? "critical" : "high";
      return this.emit(policy, def, cat, severity, srcIp, dstIp, "feed IP matched simulated TI blocklist");
    }

    // ── category pick: only enabled categories of the policy ──
    const enabled = new Set(policy.enabledCategories);
    if (enabled.size === 0) return null;
    const candidates = RUNTIME_CATS.filter((c) => enabled.has(c.name));
    if (candidates.length === 0) return null;

    // weight by profile severity mix so higher severities surface more often
    // under msp_branch etc. — category carries its own base severity
    const weights: Array<[string, number]> = candidates.map((c) => {
      const sevIdx = ["info", "low", "medium", "high", "critical"].indexOf(c.baseSeverity);
      const mix = this.profile.severityMix[sevIdx]?.[1] ?? 10;
      return [c.name, mix];
    });
    const categoryName = weightedPick(this.rand, weights);
    const cat = candidates.find((c) => c.name === categoryName)!;

    // ── preprocessor family gating (M04 §5) ──
    if (cat.family !== "generic") {
      const on = policy.preprocessors[cat.family];
      if (on === false) return null; // inspector off → family suppressed
    }

    // severity: category base with jitter; dos bursts escalate with rate
    let severity = cat.baseSeverity;
    if (cat.name === "dos") {
      this.dosBurst = this.rand() < 0.5 ? this.dosBurst + 1 : 0;
      if (this.dosBurst > 2) severity = "critical";
    } else {
      const roll = this.rand();
      if (roll < 0.15) severity = shiftSeverity(severity, -1);
      else if (roll > 0.9) severity = shiftSeverity(severity, 1);
    }

    return this.emit(policy, cat, cat.name, severity, srcIp, dstIp, `${cat.name.replace(/_/g, " ")} signature matched (simulated ET rule)`);
  }

  /** shared path: exceptions → bypass, thresholds → suppressed, mode → action */
  private emit(
    policy: IpsPolicyRuntime,
    cat: { sidBase: number },
    categoryName: string,
    severity: IpsEventEntry["severity"],
    srcIp: string,
    dstIp: string,
    message: string,
  ): { event: IpsEventEntry; correlatedFwDrop: boolean } | null {
    const sid = String(cat.sidBase + 1 + Math.floor(this.rand() * 9000));
    const sidNum = Number(sid);
    const dstPort = Number(pick(this.rand, [80, 443, 22, 3389, 8080, 53, 123]));
    const srcPort = 1024 + Math.floor(this.rand() * 64000);
    const event: IpsEventEntry = {
      ts: new Date().toISOString(),
      srcIp,
      srcPort,
      dstIp,
      dstPort,
      action: "alert",
      sid,
      severity,
      category: categoryName,
      message,
    };

    // ── exceptions (threshold.config suppress semantics, ADR-017) ──
    for (const ex of policy.exceptions) {
      const sidMatch = ex.sid === 0 || ex.sid === sidNum;
      if (!sidMatch) continue;
      const srcHit = !ex.source || cidrContains(ex.source, srcIp);
      const dstHit = !ex.dest || cidrContains(ex.dest, dstIp);
      if (srcHit && dstHit) {
        // capture-level bypass (sid 0) labels the row `bypass`; targeted
        // suppressions drop the row from existence per M04 §5
        if (ex.sid === 0) event.action = "bypass";
        else return null;
        return { event, correlatedFwDrop: false };
      }
    }

    // ── thresholds: count per seconds per tracked host ──
    for (const th of policy.thresholds) {
      if (th.sid !== sidNum) continue;
      const key = `${th.sid}:${th.track === "by_src" ? srcIp : dstIp}`;
      const now = Date.parse(event.ts);
      const window = (this.thresholdWindows.get(key) ?? []).filter((t) => now - t <= th.seconds * 1000);
      window.push(now);
      this.thresholdWindows.set(key, window);
      if (window.length > th.count) {
        event.action = "suppressed";
        return { event, correlatedFwDrop: false };
      }
    }

    // ── mode semantics: only inline_drop blocks (M04 §1/§5) ──
    const correlatedFwDrop = policy.mode === "inline_drop";
    event.action = correlatedFwDrop ? "drop" : "alert";
    return { event, correlatedFwDrop };
  }
}

function shiftSeverity(sev: IpsEventEntry["severity"], delta: number): IpsEventEntry["severity"] {
  const order: IpsEventEntry["severity"][] = ["info", "low", "medium", "high", "critical"];
  const idx = order.indexOf(sev);
  return order[Math.min(order.length - 1, Math.max(0, idx + delta))];
}

function pick<T>(rand: () => number, arr: readonly T[]): T {
  return arr[Math.floor(rand() * arr.length)];
}
