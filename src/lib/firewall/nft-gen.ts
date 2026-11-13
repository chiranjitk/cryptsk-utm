/**
 * nft-gen — pure firewall-policy → nftables ruleset generator.
 *
 * Translates the GUI firewall model (zones, address/service objects, NAT
 * rules) into an nftables source file for the dedicated `inet
 * console-firewall` table. Pure module: no DB, no exec — fully unit-tested.
 *
 * Design contract (enterprise semantics, learned the hard way):
 *
 *  • MANAGEMENT PLANE IS SACRED — the `input` chain always starts with a
 *    baseline that accepts loopback, established/related flows, ICMP
 *    (gateway liveness — the exact class of outage PBR caused on
 *    2026-11-14), management SSH (22 + 22222), DHCP, VRRP and conntrackd.
 *    User rules can only restrict AFTER these. The input chain policy is
 *    therefore ALWAYS accept.
 *  • The generator NEVER emits `flush ruleset` — fail2ban and any foreign
 *    tables must survive every apply. Only `destroy table inet
 *    console-firewall` is used (delete-if-exists, atomic replace, nft ≥1.0.9).
 *  • STRICT UNDER-MATCHING — a rule with any match dimension nftables cannot
 *    express (fqdn/geo/app/user/schedule, `any`-protocol ports) is excluded
 *    from enforcement with a loud warning. NEVER generate an over-broad rule:
 *    widening an allow is a security hole, widening a deny is an outage.
 *  • Zones resolve to interface sets (`iifname { … }`); a referenced zone
 *    with no member interfaces makes the rule unmatchable → excluded with a
 *    warning instead of silently pretending enforcement.
 *  • First-match-wins → rules are emitted in `position` order; an enabled
 *    match-all deny (the GUI "default-deny") additionally forces the forward
 *    chain policy to drop.
 *  • NO-NAT precedence — exempt rules are emitted before snat/hairpin rules
 *    in postrouting regardless of GUI position (real-firewall semantics).
 */

import type { AddrMatcher, ScheduleSpec, ServiceMatcher } from "./rule-match";

export const NFT_TABLE_NAME = "console-firewall";
export const MANAGEMENT_SSH_PORTS = [22, 22222];

// ── input model ─────────────────────────────────────────────────────────────

export interface NftGenZone {
  id: number;
  name: string;
  interfaces: string[];
}

export interface NftGenRule {
  id: number;
  name: string;
  position: number;
  enabled: boolean;
  srcZoneIds: number[];
  dstZoneIds: number[];
  srcAddrs: AddrMatcher[];
  dstAddrs: AddrMatcher[];
  services: ServiceMatcher[];
  srcMacs: string[];
  applicationIds: string[];
  userNames: string[];
  schedule: ScheduleSpec | null;
  action: string; // allow | deny | drop | reject
  logging: string; // none | summary | detail
  rateLimit: number | null;
}

export interface NftGenNatRule {
  id: number;
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
}

export interface NftGenInput {
  rules: NftGenRule[];
  natRules: NftGenNatRule[];
  zones: NftGenZone[];
  /** live OS interface names — enables zone/iface coherence warnings */
  osInterfaces?: string[];
  generatedAt?: Date;
}

export interface NftGenWarning {
  scope: "rule" | "nat" | "zone" | "policy";
  id: number | null;
  name: string;
  code: string;
  message: string;
}

export interface NftGenCounts {
  forward: number;
  input: number;
  prerouting: number;
  postrouting: number;
  skipped: number;
}

export interface NftGenResult {
  /** complete nft source file (apply with `nft -f`) */
  file: string;
  counts: NftGenCounts;
  forwardPolicy: "accept" | "drop";
  warnings: NftGenWarning[];
}

// ── validation helpers ──────────────────────────────────────────────────────

const IFACE_RE = /^[A-Za-z0-9._:@-]{1,15}$/;
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const MAC_RE = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;

export function sanitizeComment(raw: string, maxLen = 40): string {
  const cleaned = raw.replace(/[^A-Za-z0-9._@:+-]/g, "-").replace(/^-+|-+$/g, "");
  return cleaned.slice(0, Math.max(1, maxLen));
}

function intToIp(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

/** Validate a port list against the ServiceMatcher ranges. */
function portsValid(ranges: Array<{ lo: number; hi: number }>): boolean {
  return ranges.every((r) => Number.isInteger(r.lo) && Number.isInteger(r.hi) && r.lo >= 1 && r.hi <= 65535 && r.lo <= r.hi);
}

/** nft port fragment: `{ 80, 443 }` / `{ 5000-5100 }` — null when empty. */
function portSet(ranges: Array<{ lo: number; hi: number }>): string | null {
  if (ranges.length === 0) return null;
  const items = ranges.map((r) => (r.lo === r.hi ? `${r.lo}` : `${r.lo}-${r.hi}`));
  return items.length === 1 && !items[0].includes("-") ? items[0] : `{ ${items.join(", ")} }`;
}

/** Which plain (non-wildcard) IPv4 matchers can go into one anonymous set. */
interface PlainAddrs {
  values: string[];
  wildcards: Array<{ base: number; mask: number }>;
}

function splitAddrs(matchers: AddrMatcher[]): PlainAddrs {
  const out: PlainAddrs = { values: [], wildcards: [] };
  for (const m of matchers) {
    switch (m.kind) {
      case "ip":
        if (IPV4_RE.test(m.value)) out.values.push(m.value);
        break;
      case "subnet": {
        const base = intToIp(m.base);
        if (m.bits >= 0 && m.bits <= 32) out.values.push(`${base}/${m.bits}`);
        break;
      }
      case "range": {
        const lo = Math.min(m.lo, m.hi);
        const hi = Math.max(m.lo, m.hi);
        out.values.push(`${intToIp(lo)}-${intToIp(hi)}`);
        break;
      }
      case "wildcard":
        out.wildcards.push({ base: m.base, mask: m.mask });
        break;
      default:
        break; // fqdn/geo handled by the caller (rule exclusion)
    }
  }
  return out;
}

/** `ip saddr { … }` for plain entries; null when none. */
function plainAddrClause(matchers: AddrMatcher[], direction: "src" | "dst"): string | null {
  const { values } = splitAddrs(matchers);
  if (values.length === 0) return null;
  const key = direction === "src" ? "saddr" : "daddr";
  return values.length === 1 ? `ip ${key} ${values[0]}` : `ip ${key} { ${values.join(", ")} }`;
}

/** `ip saddr & <mask> == <base>` wildcard clause. */
function wildcardAddrClause(w: { base: number; mask: number }, direction: "src" | "dst"): string {
  const key = direction === "src" ? "saddr" : "daddr";
  return `ip ${key} & ${intToIp(w.mask)} == ${intToIp(w.base)}`;
}

/** `iifname { … }` / `oifname { … }` — null when no interfaces. */
function ifaceClause(ifaces: string[], direction: "in" | "out"): string | null {
  if (ifaces.length === 0) return null;
  const key = direction === "in" ? "iifname" : "oifname";
  const items = ifaces.map((i) => JSON.stringify(i));
  return items.length === 1 ? `${key} ${items[0]}` : `${key} { ${items.join(", ")} }`;
}

/** Service match fragment — { match, valid, reason }. */
function serviceClause(s: ServiceMatcher): { match: string | null; valid: boolean; reason: string } {
  if (s.protocol === "any") {
    // ports without a protocol are unmatchable in nft — must not widen silently
    if (s.srcPorts.length > 0 || s.dstPorts.length > 0) {
      return { match: null, valid: false, reason: "'any'-protocol service with port constraints cannot be expressed in nftables" };
    }
    return { match: null, valid: true, reason: "" };
  }
  if (s.protocol === "icmp") return { match: "meta l4proto icmp", valid: true, reason: "" };
  if (!portsValid(s.srcPorts) || !portsValid(s.dstPorts)) {
    return { match: null, valid: false, reason: "invalid port range in service definition" };
  }
  const frag = s.protocol;
  const src = portSet(s.srcPorts);
  const dst = portSet(s.dstPorts);
  const parts = [frag, src ? `sport ${src}` : null, dst ? `dport ${dst}` : null].filter(Boolean);
  return { match: parts.join(" "), valid: true, reason: "" };
}

function verdictFor(action: string): string | null {
  switch (action) {
    case "allow":
      return "accept";
    case "deny":
    case "drop":
      return "drop";
    case "reject":
      return "reject with icmpx type port-unreachable";
    default:
      return null;
  }
}

function logFragments(rule: NftGenRule): string[] {
  if (rule.logging === "none") return [];
  const prefix = `fw:${rule.id}:${sanitizeComment(rule.name, 16)}`;
  if (rule.logging === "detail") {
    return [`limit rate 100/second burst 200 packets log prefix ${JSON.stringify(prefix)} flags all`];
  }
  return [`limit rate 10/second burst 20 packets log prefix ${JSON.stringify(prefix)}`];
}

/** A rule whose scope matches every flow (the GUI "default-deny" semantic). */
export function isCatchAllDeny(rule: NftGenRule): boolean {
  if (!rule.enabled) return false;
  if (!["deny", "drop", "reject"].includes(rule.action)) return false;
  return (
    rule.srcZoneIds.length === 0 &&
    rule.dstZoneIds.length === 0 &&
    rule.srcAddrs.length === 0 &&
    rule.dstAddrs.length === 0 &&
    rule.services.length === 0 &&
    rule.srcMacs.length === 0 &&
    rule.applicationIds.length === 0 &&
    rule.userNames.length === 0 &&
    rule.schedule === null
  );
}

// ── firewall filter rules ───────────────────────────────────────────────────

interface RuleClauseSet {
  forward: string[];
  input: string[];
}

/**
 * Compile one GUI rule into nft statements for the forward and input chains.
 * Empty arrays = no enforceable statement for that hook.
 */
function compileFilterRule(rule: NftGenRule, zones: Map<number, NftGenZone>, warn: (w: NftGenWarning) => void): RuleClauseSet {
  const out: RuleClauseSet = { forward: [], input: [] };

  if (!rule.enabled) return out;
  const verdict = verdictFor(rule.action);
  if (!verdict) {
    warn({ scope: "rule", id: rule.id, name: rule.name, code: "action-invalid", message: `unknown action '${rule.action}' — excluded from enforcement` });
    return out;
  }

  // not kernel-expressible → config-only, never widen
  if (rule.schedule !== null) {
    warn({ scope: "rule", id: rule.id, name: rule.name, code: "match-not-expressible", message: "schedule-bound rules cannot be enforced by nftables (time-conditioned policy stays config-only)" });
    return out;
  }
  if (rule.applicationIds.length > 0) {
    warn({ scope: "rule", id: rule.id, name: rule.name, code: "match-not-expressible", message: "application-id matches cannot be enforced by nftables — excluded (would over-match if dropped)" });
    return out;
  }
  if (rule.userNames.length > 0) {
    warn({ scope: "rule", id: rule.id, name: rule.name, code: "match-not-expressible", message: "user matches cannot be enforced by nftables — excluded" });
    return out;
  }
  if ([...rule.srcAddrs, ...rule.dstAddrs].some((m) => m.kind === "fqdn" || m.kind === "geo")) {
    warn({ scope: "rule", id: rule.id, name: rule.name, code: "match-not-expressible", message: "fqdn/geo address matches cannot be enforced by nftables — excluded" });
    return out;
  }

  // zones → interface sets
  const resolveIfaces = (ids: number[], side: "src" | "dst"): string[] | null => {
    const ifaces: string[] = [];
    for (const id of ids) {
      const z = zones.get(id);
      if (!z) {
        warn({ scope: "rule", id: rule.id, name: rule.name, code: "zone-unknown", message: `references unknown zone id ${id} — excluded from enforcement` });
        return null;
      }
      ifaces.push(...z.interfaces.filter((i) => IFACE_RE.test(i)));
    }
    return [...new Set(ifaces)];
  };
  const srcIfaces = resolveIfaces(rule.srcZoneIds, "src");
  if (srcIfaces === null) return out;
  const dstIfaces = resolveIfaces(rule.dstZoneIds, "dst");
  if (dstIfaces === null) return out;
  if (rule.srcZoneIds.length > 0 && srcIfaces.length === 0) {
    warn({ scope: "rule", id: rule.id, name: rule.name, code: "zone-no-iface", message: `source zone(s) have no member interfaces — rule cannot match traffic, excluded from enforcement` });
    return out;
  }
  if (rule.dstZoneIds.length > 0 && dstIfaces.length === 0) {
    warn({ scope: "rule", id: rule.id, name: rule.name, code: "zone-no-iface", message: `destination zone(s) have no member interfaces — rule cannot match traffic, excluded from enforcement` });
    return out;
  }

  // services — one nft rule per service selector. rule-match semantics: the
  // rule fires when ANY service matches, so a pure "any"-protocol service
  // makes every other service redundant (same logic as the eval engine).
  let svcFragments: Array<string | null> = [];
  for (const s of rule.services) {
    const c = serviceClause(s);
    if (!c.valid) {
      warn({ scope: "rule", id: rule.id, name: rule.name, code: "match-not-expressible", message: `${c.reason} — excluded from enforcement` });
      return out;
    }
    svcFragments.push(c.match);
  }
  if (svcFragments.includes(null)) svcFragments = [null];
  if (svcFragments.length === 0) svcFragments.push(null);

  // addresses — plain set + per-wildcard variants. GUARD: a variant must
  // never be empty when the rule carries address matchers (an empty variant
  // would silently over-match the whole rule — the one thing we never do).
  const srcPlain = plainAddrClause(rule.srcAddrs, "src");
  const dstPlain = plainAddrClause(rule.dstAddrs, "dst");
  const srcWildcards = splitAddrs(rule.srcAddrs).wildcards;
  const hasAddrMatch = rule.srcAddrs.length > 0 || rule.dstAddrs.length > 0;
  const addrVariants: Array<string[]> = [];
  if (srcPlain || dstPlain || !hasAddrMatch) addrVariants.push([srcPlain, dstPlain].filter(Boolean) as string[]);
  for (const w of srcWildcards) addrVariants.push([wildcardAddrClause(w, "src")]);

  // macs
  const macs = rule.srcMacs.filter((m) => MAC_RE.test(m));
  if (macs.length !== rule.srcMacs.length) {
    warn({ scope: "rule", id: rule.id, name: rule.name, code: "mac-invalid", message: "malformed MAC literal ignored" });
  }
  const macClause = macs.length > 0 ? (macs.length === 1 ? `ether saddr ${macs[0]}` : `ether saddr { ${macs.join(", ")} }`) : null;

  // rate limit only sharpens an allow (limiting a drop would leak floods through)
  const rate = rule.action === "allow" && rule.rateLimit != null && rule.rateLimit > 0 ? `limit rate ${Math.floor(rule.rateLimit)}/second burst ${Math.floor(rule.rateLimit) * 5} packets` : null;
  if (rule.action !== "allow" && rule.rateLimit != null && rule.rateLimit > 0) {
    warn({ scope: "rule", id: rule.id, name: rule.name, code: "rate-limit-ignored", message: "rate limit is only meaningful on allow rules — ignored on deny/drop/reject" });
  }

  const logParts = logFragments(rule);
  const iif = ifaceClause(srcIfaces, "in");
  const oif = ifaceClause(dstIfaces, "out");

  const appliesToInput = rule.dstZoneIds.length === 0; // "any" destination includes the host itself
  const comment = sanitizeComment(`fw:${rule.id}:${rule.name}`, 60);

  for (const svc of svcFragments) {
    for (const addrParts of addrVariants) {
      const fwdParts = [iif, oif, macClause, ...addrParts, svc, rate, ...logParts, verdict].filter(Boolean).join(" ");
      out.forward.push(`${fwdParts} comment ${JSON.stringify(comment)}`);

      if (appliesToInput) {
        // input variant (host-terminated traffic): no oifname, and ONLY
        // src-scoped address matches survive. A variant that carries just
        // destination matches cannot distinguish host-bound flows from the
        // object's network — emitting it would over-match (never allowed).
        const srcScoped = addrParts.filter((p) => p.startsWith("ip saddr"));
        if (srcScoped.length > 0 || !hasAddrMatch) {
          const inParts = [iif, macClause, ...srcScoped, svc, rate, ...logParts, verdict].filter(Boolean).join(" ");
          out.input.push(`${inParts} comment ${JSON.stringify(comment)}`);
        }
      }
    }
  }
  return out;
}

// ── NAT ─────────────────────────────────────────────────────────────────────

interface NatClause {
  hook: "prerouting" | "postrouting";
  line: string;
}

function natAddrClause(matchers: AddrMatcher[], direction: "src" | "dst", nat: NftGenNatRule, warn: (w: NftGenWarning) => void): string | null {
  if (matchers.length === 0) return ""; // no clause (match-all side)
  const { values, wildcards } = splitAddrs(matchers);
  if (wildcards.length > 0) {
    warn({ scope: "nat", id: nat.id, name: nat.name ?? `nat#${nat.id}`, code: "nat-match-not-expressible", message: "wildcard address match in NAT rule not expressible — rule excluded" });
    return null; // explicit skip
  }
  if (values.length === 0) {
    warn({ scope: "nat", id: nat.id, name: nat.name ?? `nat#${nat.id}`, code: "nat-match-not-expressible", message: "fqdn/geo address match in NAT rule not expressible — rule excluded" });
    return null; // explicit skip
  }
  const key = direction === "src" ? "saddr" : "daddr";
  return values.length === 1 ? `ip ${key} ${values[0]}` : `ip ${key} { ${values.join(", ")} }`;
}

function natServiceClause(nat: NftGenNatRule, warn: (w: NftGenWarning) => void): string | null {
  const frags: string[] = [];
  for (const s of nat.services) {
    const c = serviceClause(s);
    if (!c.valid || c.match === null) {
      if (!c.valid) {
        warn({ scope: "nat", id: nat.id, name: nat.name ?? `nat#${nat.id}`, code: "nat-match-not-expressible", message: `${c.reason} — NAT rule excluded` });
        return null;
      }
      continue; // pure "any" service contributes no clause
    }
    frags.push(c.match);
  }
  return frags.join(" "); // "" = no service clause (match-all)
}

function validIp(v: string | null | undefined): string | null {
  return v && IPV4_RE.test(v) ? v : null;
}

/** Compile one NAT rule into 0..2 chain statements. */
function compileNatRule(nat: NftGenNatRule, osInterfaces: string[] | undefined, warn: (w: NftGenWarning) => void): NatClause[] {
  const out: NatClause[] = [];
  const label = nat.name ?? `nat#${nat.id}`;
  const comment = sanitizeComment(`nat:${nat.id}:${label}`, 60);

  if (!nat.enabled) return out;

  const saddr = natAddrClause(nat.srcAddrs, "src", nat, warn);
  const daddr = natAddrClause(nat.dstAddrs, "dst", nat, warn);
  if (saddr === null || daddr === null) return out; // explicit skip (warning emitted)
  const svc = natServiceClause(nat, warn);
  if (svc === null) return out;

  const oif = nat.outgoingIface && IFACE_RE.test(nat.outgoingIface) ? `oifname ${JSON.stringify(nat.outgoingIface)}` : null;
  if (nat.outgoingIface && !oif) {
    warn({ scope: "nat", id: nat.id, name: label, code: "iface-invalid", message: `invalid outgoing interface ${JSON.stringify(nat.outgoingIface)} — ignored` });
  }

  const matchParts = [saddr, daddr, oif, svc].filter(Boolean).join(" ");

  if (nat.type === "exempt") {
    // NO-NAT: accept in the nat chain stops translation for these flows
    out.push({ hook: "postrouting", line: `${matchParts} accept comment ${JSON.stringify(comment)}` });
    return out;
  }

  if (nat.type === "snat" || nat.type === "hairpin") {
    let target: string | null = null;
    let extraOif: string | null = null;
    if (nat.translatedSrc === "masq") {
      target = "masquerade";
    } else if (validIp(nat.translatedSrc)) {
      target = `snat to ${nat.translatedSrc}`;
    } else if (
      nat.translatedSrc &&
      nat.translatedSrc !== "masq" &&
      IFACE_RE.test(nat.translatedSrc) &&
      osInterfaces?.includes(nat.translatedSrc)
    ) {
      // seed compat: translatedSrc may carry an egress iface name → masquerade
      // there — accepted ONLY for interfaces the OS actually has (no guessing)
      target = "masquerade";
      extraOif = `oifname ${JSON.stringify(nat.translatedSrc)}`;
    } else if (nat.translatedSrcPool.length > 0) {
      const pool = nat.translatedSrcPool.filter((p) => validIp(p));
      if (pool.length === 1) target = `snat to ${pool[0]}`;
      else {
        warn({ scope: "nat", id: nat.id, name: label, code: "nat-pool-unsupported", message: "multi-address NAT pools are not expressible in this generator — rule excluded" });
        return out;
      }
    }
    if (!target) {
      warn({ scope: "nat", id: nat.id, name: label, code: "nat-no-translate", message: `SNAT rule has no usable translation target — rule excluded` });
      return out;
    }
    const parts = [matchParts, extraOif, target].filter(Boolean).join(" ");
    out.push({ hook: "postrouting", line: `${parts} comment ${JSON.stringify(comment)}` });

    if (nat.type === "hairpin") {
      // hairpin = DNAT (prerouting) + post-DNAT masquerade (postrouting):
      // external-facing VIP folds back to an internal host, then the source
      // is masqueraded so replies hairpin through the box
      const hostIp = validIp(nat.translatedDst);
      if (!hostIp) {
        warn({ scope: "nat", id: nat.id, name: label, code: "nat-no-translate", message: "hairpin rule without a valid translated destination — rule excluded" });
        return out;
      }
      const hpParts = [saddr, `ip daddr ${hostIp}`, "masquerade"].filter(Boolean).join(" ");
      out.push({ hook: "postrouting", line: `${hpParts} comment ${JSON.stringify(`${comment}:hairpin`)}` });

      // prerouting DNAT leg — mirror of the dnat branch (public daddr → host)
      const iif = nat.outgoingIface && IFACE_RE.test(nat.outgoingIface) ? `iifname ${JSON.stringify(nat.outgoingIface)}` : null;
      const daddrPlain = daddr ? daddr.replace(/^ip daddr /, "") : null;
      const preMatch = [iif, daddrPlain ? `ip daddr ${daddrPlain}` : null, svc].filter(Boolean).join(" ");
      const target2 = nat.translatedPort != null && nat.translatedPort >= 1 && nat.translatedPort <= 65535 ? `dnat to ${hostIp}:${nat.translatedPort}` : `dnat to ${hostIp}`;
      out.push({ hook: "prerouting", line: `${preMatch} ${target2} comment ${JSON.stringify(comment)}` });
    }
    return out;
  }

  if (nat.type === "dnat") {
    const hostIp = validIp(nat.translatedDst);
    if (!hostIp) {
      warn({ scope: "nat", id: nat.id, name: label, code: "nat-no-translate", message: "DNAT rule without a valid translated destination — rule excluded" });
      return out;
    }
    let portPart: string | null = null;
    if (nat.translatedPort != null && nat.translatedPort >= 1 && nat.translatedPort <= 65535) {
      portPart = String(nat.translatedPort);
    } else if (nat.translatedPortRange) {
      const ranges = parseRangeForDnat(nat.translatedPortRange);
      if (ranges.length === 1) portPart = ranges[0];
      else {
        warn({ scope: "nat", id: nat.id, name: label, code: "nat-port-unsupported", message: "multi-range DNAT port lists are not expressible — rule excluded" });
        return out;
      }
    }
    const iif = nat.outgoingIface && IFACE_RE.test(nat.outgoingIface) ? `iifname ${JSON.stringify(nat.outgoingIface)}` : null;
    const pub = daddr ? daddr.replace(/^ip daddr /, "") : null;
    const preMatch = [iif, pub ? `ip daddr ${pub}` : null, svc].filter(Boolean).join(" ");
    const target = portPart ? `dnat to ${hostIp}:${portPart}` : `dnat to ${hostIp}`;
    out.push({ hook: "prerouting", line: `${preMatch} ${target} comment ${JSON.stringify(comment)}` });
    return out;
  }

  warn({ scope: "nat", id: nat.id, name: label, code: "nat-type-invalid", message: `unknown NAT type '${nat.type}' — rule excluded` });
  return out;
}

/** "5000-5100,6000" → expressible single token list (empty when multi-range). */
function parseRangeForDnat(raw: string): string[] {
  const tokens = raw
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);
  return tokens;
}

// ── assembly ────────────────────────────────────────────────────────────────

function baselineInputRules(): string[] {
  const c = (s: string) => `comment ${JSON.stringify(s)}`;
  return [
    `iifname "lo" accept ${c("baseline: loopback")}`,
    `ct state invalid drop ${c("baseline: invalid conntrack")}`,
    `ct state established,related accept ${c("baseline: established/related")}`,
    `meta l4proto icmp accept ${c("baseline: icmp liveness (gateway ping)")}`,
    `meta l4proto ipv6-icmp accept ${c("baseline: ipv6 ndp/icmp")}`,
    `tcp dport { ${MANAGEMENT_SSH_PORTS.join(", ")} } accept ${c("baseline: management ssh")}`,
    `udp dport { 67, 68 } accept ${c("baseline: dhcp")}`,
    `ip protocol vrrp accept ${c("baseline: keepalived vrrp")}`,
    `udp dport 3780 accept ${c("baseline: conntrackd sync")}`,
  ];
}

function baselineForwardRules(): string[] {
  const c = (s: string) => `comment ${JSON.stringify(s)}`;
  return [
    `ct state invalid drop ${c("baseline: invalid conntrack")}`,
    `ct state established,related accept ${c("baseline: established/related (return traffic)")}`,
  ];
}

const INDENT = "\t\t";
const CHAIN_INDENT = "\t";

/**
 * Generate the complete nft source file for `table inet console-firewall`.
 * Idempotent: apply twice → identical kernel state (atomic destroy+recreate).
 */
export function generateNftRuleset(input: NftGenInput): NftGenResult {
  const warnings: NftGenWarning[] = [];
  const warn = (w: NftGenWarning) => warnings.push(w);
  const zones = new Map(input.zones.map((z) => [z.id, z]));

  // zone coherence warnings (enterprise drift hygiene)
  for (const z of input.zones) {
    if (z.interfaces.length === 0) {
      warn({ scope: "zone", id: z.id, name: z.name, code: "zone-empty", message: `zone '${z.name}' has no member interfaces — rules referencing it cannot be enforced` });
    }
    if (input.osInterfaces) {
      for (const i of z.interfaces) {
        if (!input.osInterfaces.includes(i)) {
          warn({ scope: "zone", id: z.id, name: z.name, code: "iface-missing-os", message: `zone '${z.name}' references interface '${i}' which does not exist on the host` });
        }
      }
    }
  }

  // filter rules — position order = first-match-wins
  const forward: string[] = [];
  const inputChain: string[] = [];
  let skipped = 0;
  const ordered = [...input.rules].sort((a, b) => a.position - b.position);
  for (const rule of ordered) {
    if (!rule.enabled) continue;
    const compiled = compileFilterRule(rule, zones, warn);
    if (compiled.forward.length === 0 && compiled.input.length === 0) skipped += 1;
    forward.push(...compiled.forward);
    inputChain.push(...compiled.input);
  }

  // forward policy drops ONLY behind an explicit match-all deny (default-deny)
  const catchAll = ordered.find(isCatchAllDeny);
  const forwardPolicy: "accept" | "drop" = catchAll ? "drop" : "accept";
  if (catchAll) {
    warn({ scope: "policy", id: catchAll.id, name: catchAll.name, code: "forward-policy-drop", message: `match-all deny '${catchAll.name}' is enabled — forward chain policy becomes drop (unmatched forwarded flows are denied)` });
  }

  // NAT — exempt (NO-NAT) first, then snat/dnat/hairpin by position
  const enabledNat = input.natRules.filter((n) => n.enabled);
  const natPostrouting: string[] = [];
  const natPrerouting: string[] = [];
  const exempt = enabledNat.filter((n) => n.type === "exempt");
  const rest = enabledNat.filter((n) => n.type !== "exempt");
  for (const nat of [...exempt, ...rest].sort((a, b) => a.position - b.position)) {
    for (const clause of compileNatRule(nat, input.osInterfaces, warn)) {
      if (clause.hook === "postrouting") natPostrouting.push(clause.line);
      else natPrerouting.push(clause.line);
    }
  }

  const counts: NftGenCounts = {
    forward: forward.length,
    input: inputChain.length,
    prerouting: natPrerouting.length,
    postrouting: natPostrouting.length,
    skipped,
  };

  const genAt = (input.generatedAt ?? new Date()).toISOString();
  const lines: string[] = [
    "#!/usr/sbin/nft -f",
    `# console-firewall — managed by the UTM console (GUI: Firewall → Apply to Host)`,
    `# generated: ${genAt}`,
    "#",
    "# Atomic replace of the console-managed table ONLY — never flushes the",
    "# entire ruleset: fail2ban tables and any foreign rulesets survive every",
    "# apply. User filter rules are appended AFTER the baseline in each chain;",
    "# the input chain policy is permanently accept (management-plane guarantee).",
    "",
    `destroy table inet ${NFT_TABLE_NAME}`,
    "",
    `table inet ${NFT_TABLE_NAME} {`,
    `  chain input {`,
    `${CHAIN_INDENT}type filter hook input priority filter; policy accept;`,
    ...baselineInputRules().map((l) => `${INDENT}${l}`),
    ...inputChain.map((l) => `${INDENT}${l}`),
    `  }`,
    "",
    `  chain forward {`,
    `${CHAIN_INDENT}type filter hook forward priority filter; policy ${forwardPolicy};`,
    ...baselineForwardRules().map((l) => `${INDENT}${l}`),
    ...forward.map((l) => `${INDENT}${l}`),
    `  }`,
    "",
    `  chain postrouting {`,
    `${CHAIN_INDENT}type nat hook postrouting priority srcnat; policy accept;`,
    ...natPostrouting.map((l) => `${INDENT}${l}`),
    `  }`,
    "",
    `  chain prerouting {`,
    `${CHAIN_INDENT}type nat hook prerouting priority dstnat; policy accept;`,
    ...natPrerouting.map((l) => `${INDENT}${l}`),
    `  }`,
    `}`,
    "",
  ];

  return { file: lines.join("\n"), counts, forwardPolicy, warnings };
}
