/**
 * NAT conflict/shadow detection + generator-faithful advisories (pure, no DB).
 *
 * Mirrors the firewall shadow semantics (rule-match.ts) on the NAT match
 * dimensions, split by CHAIN LEG because the generator compiles:
 *   • snat    → postrouting only
 *   • dnat    → prerouting only
 *   • hairpin → prerouting (dnat leg) + postrouting (src-rewrite leg)
 *   • exempt  → postrouting, ALWAYS evaluated before the rest regardless of
 *               GUI position (real-firewall NO-NAT semantics)
 *
 * An earlier rule E that covers a later rule R on every match dimension of a
 * shared leg makes R unreachable on that leg → shadowed_by (different
 * translation) / redundant (same translation). Advisories surface everything
 * the generator will honestly exclude or degrade (pools, no-PAT, wildcards).
 */

import type { AddrMatcher, ServiceMatcher } from "./rule-match";
import { poolRange } from "./nft-gen";

export interface NatCandidate {
  id: number | null;
  name: string | null;
  position: number;
  enabled: boolean;
  type: string; // snat | dnat | hairpin | exempt
  srcAddrs: AddrMatcher[];
  dstAddrs: AddrMatcher[];
  services: ServiceMatcher[];
  outgoingIface: string | null;
  translatedSrc: string | null;
  translatedSrcPool: string[];
  translatedDst: string | null;
  translatedPort: number | null;
  translatedPortRange: string | null;
  logging: string;
}

export interface NatConflictRow {
  ruleId: number | null;
  ruleName: string;
  reason: "shadowed_by" | "conflicts_with" | "redundant";
  withRuleId: number;
  withRuleName: string;
  leg: "prerouting" | "postrouting";
}

export interface NatAdvisory {
  code: string;
  message: string;
}

const addrKey = (m: AddrMatcher) => `${m.kind}|${JSON.stringify(m)}`;
const svcKey = (s: ServiceMatcher) => `${s.protocol}|${JSON.stringify(s.srcPorts)}|${JSON.stringify(s.dstPorts)}`;

function entrySuperset<T>(outer: T[], inner: T[], key: (t: T) => string): boolean {
  if (outer.length === 0) return true; // wildcard side covers everything
  if (inner.length === 0) return false;
  const ko = new Set(outer.map(key));
  return inner.every((i) => ko.has(key(i)));
}

function sameEntries<T>(a: T[], b: T[], key: (t: T) => string): boolean {
  if (a.length === 0 && b.length === 0) return true;
  if (a.length === 0 || b.length === 0) return false;
  const ka = new Set(a.map(key));
  const kb = new Set(b.map(key));
  return ka.size === kb.size && [...ka].every((k) => kb.has(k));
}

/** iface containment: null (any) covers everything; concrete requires equality. */
function ifaceSuperset(outer: string | null, inner: string | null): boolean {
  if (outer === null || outer === "") return true;
  return outer === inner;
}

function ifaceSame(a: string | null, b: string | null): boolean {
  return (a ?? null) === (b ?? null);
}

/** Which nat chain legs the generator compiles for this rule type. */
export function natLegs(type: string): Array<"prerouting" | "postrouting"> {
  switch (type) {
    case "snat":
    case "exempt":
      return ["postrouting"];
    case "dnat":
      return ["prerouting"];
    case "hairpin":
      return ["prerouting", "postrouting"];
    default:
      return [];
  }
}

/** Normalized translation target — "same" means the kernel does the same thing. */
export function natTranslationKey(r: NatCandidate): string {
  switch (r.type) {
    case "exempt":
      return "accept";
    case "snat": {
      if (r.translatedSrc === "masq") return "masquerade";
      if (r.translatedSrcPool.length > 1) {
        const range = poolRange(r.translatedSrcPool);
        if (range) return `snat:${range.lo}-${range.hi}`;
        return `pool:${[...r.translatedSrcPool].sort().join(",")}`;
      }
      if (r.translatedSrcPool.length === 1) return `snat:${r.translatedSrcPool[0]}`;
      if (r.translatedSrc && r.translatedSrc !== "masq") {
        return /^[0-9.]+$/.test(r.translatedSrc) ? `snat:${r.translatedSrc}` : "masquerade";
      }
      return "none";
    }
    case "dnat":
    case "hairpin": {
      const port = r.translatedPort != null ? String(r.translatedPort) : r.translatedPortRange ?? "";
      return `dnat:${r.translatedDst ?? "none"}:${port}`;
    }
    default:
      return "none";
  }
}

function coversOnLeg(E: NatCandidate, R: NatCandidate): boolean {
  return (
    entrySuperset(E.srcAddrs, R.srcAddrs, addrKey) &&
    entrySuperset(E.dstAddrs, R.dstAddrs, addrKey) &&
    entrySuperset(E.services, R.services, svcKey) &&
    ifaceSuperset(E.outgoingIface, R.outgoingIface)
  );
}

function identicalScopeOnLeg(R: NatCandidate, E: NatCandidate): boolean {
  return (
    sameEntries(R.srcAddrs, E.srcAddrs, addrKey) &&
    sameEntries(R.dstAddrs, E.dstAddrs, addrKey) &&
    sameEntries(R.services, E.services, svcKey) &&
    ifaceSame(R.outgoingIface, E.outgoingIface)
  );
}

/**
 * Compare the candidate against every ENABLED existing rule across shared
 * legs. Generator ordering: exempt first, then position order — an exempt
 * rule shadows postrouting legs no matter what position it carries, while
 * regular rules only shadow LATER (higher-position) rules.
 */
export function detectNatConflicts(candidate: NatCandidate, existing: NatCandidate[]): NatConflictRow[] {
  const conflicts: NatConflictRow[] = [];
  const candLegs = natLegs(candidate.type);
  if (candLegs.length === 0) return conflicts;

  for (const e of existing) {
    if (!e.enabled || e.id === null || candidate.id === e.id) continue;
    if (natLegs(e.type).length === 0) continue;
    const eEarlier =
      e.type === "exempt" || candidate.type === "exempt"
        ? e.type === "exempt" // exempt is reordered ahead of everything
        : e.position < candidate.position;
    if (!eEarlier && candidate.type !== "exempt") continue;

    for (const leg of candLegs) {
      if (!natLegs(e.type).includes(leg)) continue;
      // an exempt rule only stops the postrouting translation — hairpin's
      // prerouting leg still fires, so it can never shadow that side
      if (e.type === "exempt" && leg === "prerouting") continue;
      if (candidate.type === "exempt" && leg === "prerouting") continue;
      if (!coversOnLeg(e, candidate)) continue;
      const identical = identicalScopeOnLeg(candidate, e);
      const sameTarget = natTranslationKey(candidate) === natTranslationKey(e);
      if (identical && !sameTarget) {
        conflicts.push({
          ruleId: candidate.id,
          ruleName: candidate.name ?? `#${candidate.id ?? "?"}`,
          reason: "conflicts_with",
          withRuleId: e.id,
          withRuleName: e.name ?? `#${e.id}`,
          leg,
        });
      } else if (!sameTarget) {
        conflicts.push({
          ruleId: candidate.id,
          ruleName: candidate.name ?? `#${candidate.id ?? "?"}`,
          reason: "shadowed_by",
          withRuleId: e.id,
          withRuleName: e.name ?? `#${e.id}`,
          leg,
        });
      } else {
        conflicts.push({
          ruleId: candidate.id,
          ruleName: candidate.name ?? `#${candidate.id ?? "?"}`,
          reason: "redundant",
          withRuleId: e.id,
          withRuleName: e.name ?? `#${e.id}`,
          leg,
        });
      }
      break; // one row per existing rule is enough
    }
  }
  return conflicts;
}

/** Advisories mirroring exactly what the generator will do at apply time. */
export function natAdvisories(candidate: NatCandidate): NatAdvisory[] {
  const out: NatAdvisory[] = [];
  const matchers = [...candidate.srcAddrs, ...candidate.dstAddrs];
  if (matchers.some((m) => m.kind === "fqdn" || m.kind === "geo")) {
    out.push({ code: "nat-match-not-expressible", message: "fqdn/geo address matches cannot be enforced by nftables — this rule is excluded from the kernel ruleset" });
  }
  if (matchers.some((m) => m.kind === "wildcard")) {
    out.push({ code: "nat-match-not-expressible", message: "wildcard address matches cannot be enforced in NAT — this rule is excluded from the kernel ruleset" });
  }
  if (candidate.type === "snat") {
    const pool = candidate.translatedSrcPool.filter((p) => p);
    if (pool.length > 1) {
      const range = poolRange(pool);
      if (range) {
        out.push({ code: "nat-pool-range", message: `contiguous pool is enforced as a kernel round-robin range ${range.lo}-${range.hi}` });
      } else {
        out.push({ code: "nat-pool-unsupported", message: "non-contiguous pools are not expressible as a single nft statement — this rule is excluded from enforcement" });
      }
    }
    if (candidate.translatedSrc !== "masq" && candidate.translatedSrc && !/^[0-9.]+$/.test(candidate.translatedSrc) && candidate.translatedSrcPool.length === 0) {
      out.push({ code: "nat-egress-iface-masq", message: `translatedSrc '${candidate.translatedSrc}' is treated as an egress interface → masquerade on it` });
    }
  }
  if (candidate.type === "hairpin" && !candidate.translatedSrc) {
    out.push({ code: "nat-hairpin-masq", message: "no hairpin translatedSrc set — the source rewrite defaults to masquerade" });
  }
  if (candidate.type === "dnat") {
    const hasPort = candidate.translatedPort != null || Boolean(candidate.translatedPortRange);
    if (candidate.services.length === 0 && !hasPort) {
      out.push({ code: "nat-dnat-unconstrained", message: "DNAT without service or port match forwards EVERYTHING to the translated destination (DMZ-style) — verify intent" });
    }
  }
  if (candidate.type === "exempt") {
    out.push({ code: "nat-exempt-order", message: "exempt (NO-NAT) rules always evaluate before other NAT rules regardless of position" });
  }
  return out;
}
