/**
 * Pure rule-matching + shadow/conflict logic for M03 §5 — no DB access here.
 * Shared by POST /firewall-rules/validate (service) and the firewall-logs
 * generator (engine) so the simulated data plane evaluates exactly what the
 * console validates.
 */

// ── address matchers ───────────────────────────────────────────────────────

export type AddrMatcher =
  | { kind: "ip"; value: string }
  | { kind: "range"; lo: number; hi: number }
  | { kind: "subnet"; base: number; bits: number }
  | { kind: "wildcard"; base: number; mask: number }
  | { kind: "fqdn"; value: string }
  | { kind: "geo"; value: string };

export function ipToInt(ip: string): number {
  const p = ip.split(".").map(Number);
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
}

export function parseAddrMatcher(type: string, value: string): AddrMatcher {
  if (type === "ip") return { kind: "ip", value };
  if (type === "range") {
    const [a, b] = value.split("-").map((s) => s.trim());
    return { kind: "range", lo: ipToInt(a), hi: ipToInt(b) };
  }
  if (type === "subnet") {
    const [base, bits] = value.split("/");
    return { kind: "subnet", base: ipToInt(base.trim()), bits: Number(bits) };
  }
  if (type === "wildcard") {
    const [base, mask] = value.split(/\s+/);
    return { kind: "wildcard", base: ipToInt(base), mask: ipToInt(mask) };
  }
  if (type === "fqdn") return { kind: "fqdn", value };
  return { kind: "geo", value };
}

/** Simulated matcher for one flow/IP against an expanded address entry. */
export function addrMatches(m: AddrMatcher, ip: string, direction: "src" | "dst"): boolean {
  const n = ipToInt(ip);
  switch (m.kind) {
    case "ip":
      return n === ipToInt(m.value);
    case "range":
      return n >= Math.min(m.lo, m.hi) && n <= Math.max(m.lo, m.hi);
    case "subnet": {
      const mask = m.bits === 0 ? 0 : (0xffffffff << (32 - m.bits)) >>> 0;
      return (n & mask) === (m.base & mask);
    }
    case "wildcard":
      return (n & m.mask) === (m.base & m.mask);
    case "fqdn": {
      // simulated resolver: deterministic pseudo-resolution from the host octet
      const last = Number(ip.split(".")[3] ?? 0);
      let h = 7;
      for (const ch of m.value) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
      return h % 8 === last % 8;
    }
    case "geo": {
      // simulated GeoIP: WAN-sourced flows land in a deterministic country bucket
      if (direction !== "src") return false;
      const p = ip.split(".").map(Number);
      const bucket = (p[0] * 7 + p[1] * 13 + p[2] * 17 + p[3] * 23) % 10;
      return bucket < 2;
    }
  }
}

// ── services ───────────────────────────────────────────────────────────────

export interface PortRange {
  lo: number;
  hi: number;
}

export interface ServiceMatcher {
  protocol: "tcp" | "udp" | "icmp" | "any";
  srcPorts: PortRange[];
  dstPorts: PortRange[];
}

export function parsePortList(raw: string | null): PortRange[] {
  if (!raw || raw === "any") return [];
  const out: PortRange[] = [];
  for (const seg of raw.split(",")) {
    const s = seg.trim();
    if (s.includes("-")) {
      const [lo, hi] = s.split("-").map(Number);
      out.push({ lo, hi });
    } else if (s !== "") {
      const p = Number(s);
      out.push({ lo: p, hi: p });
    }
  }
  return out;
}

export function portInList(ranges: PortRange[], port: number): boolean {
  if (ranges.length === 0) return true; // unset = any
  return ranges.some((r) => port >= r.lo && port <= r.hi);
}

export function serviceMatches(s: ServiceMatcher, protocol: string, srcPort: number, dstPort: number): boolean {
  if (s.protocol === "icmp") return protocol === "icmp";
  if (s.protocol !== "any" && s.protocol !== protocol) return false;
  if (s.protocol === "any") return true;
  return portInList(s.srcPorts, srcPort) && portInList(s.dstPorts, dstPort);
}

// ── schedules ──────────────────────────────────────────────────────────────

export interface ScheduleSpec {
  type: "always" | "recurring" | "onetime";
  days: number[]; // 1=Mon..7=Sun
  start: string; // HH:MM
  end: string; // HH:MM
  startsAt: number | null;
  endsAt: number | null;
  timezone: string;
}

/** Current weekday (1=Mon..7=Sun) and HH:MM in a given IANA timezone. */
export function nowInZone(tz: string, at: Date): { day: number; minutes: number } | null {
  try {
    const fmt = new Intl.DateTimeFormat("en-US", {
      timeZone: tz,
      weekday: "short",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    });
    const parts = fmt.formatToParts(at);
    const get = (t: string) => parts.find((p) => p.type === t)?.value ?? "";
    const dayMap: Record<string, number> = { Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6, Sun: 7 };
    const day = dayMap[get("weekday")] ?? 1;
    const h = Number(get("hour")) % 24;
    const m = Number(get("minute"));
    return { day, minutes: h * 60 + m };
  } catch {
    return null;
  }
}

export function scheduleActive(s: ScheduleSpec, at: Date): boolean {
  if (s.type === "always") return true;
  if (s.type === "onetime") {
    const t = at.getTime();
    return (s.startsAt == null || t >= s.startsAt) && (s.endsAt == null || t <= s.endsAt);
  }
  const cur = nowInZone(s.timezone, at);
  if (!cur) return true; // fail-open on bad tz data (should not happen)
  if (!s.days.includes(cur.day)) return false;
  const toMin = (v: string) => {
    const [h, m] = v.split(":").map(Number);
    return h * 60 + m;
  };
  const start = toMin(s.start || "00:00");
  const end = toMin(s.end || "23:59");
  return start <= end ? cur.minutes >= start && cur.minutes <= end : cur.minutes >= start || cur.minutes <= end;
}

// ── evaluation (first match wins) ──────────────────────────────────────────

export interface FlowSpec {
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: string;
  srcZoneId: number;
  dstZoneId: number;
  app: string | null;
  userName: string | null;
  srcMac: string | null;
}

export interface EvalRule {
  id: number;
  name: string;
  action: string;
  enabled: boolean;
  position: number;
  srcZoneIds: number[];
  dstZoneIds: number[];
  srcAddrs: AddrMatcher[];
  dstAddrs: AddrMatcher[];
  services: ServiceMatcher[];
  applicationIds: string[];
  userNames: string[];
  srcMacs: string[];
  schedule: ScheduleSpec | null;
}

export function ruleMatches(r: EvalRule, f: FlowSpec, at: Date): boolean {
  if (!r.enabled) return false;
  if (r.srcZoneIds.length > 0 && !r.srcZoneIds.includes(f.srcZoneId)) return false;
  if (r.dstZoneIds.length > 0 && !r.dstZoneIds.includes(f.dstZoneId)) return false;
  if (r.srcAddrs.length > 0 && !r.srcAddrs.some((m) => addrMatches(m, f.srcIp, "src"))) return false;
  if (r.dstAddrs.length > 0 && !r.dstAddrs.some((m) => addrMatches(m, f.dstIp, "dst"))) return false;
  if (r.services.length > 0 && !r.services.some((s) => serviceMatches(s, f.protocol, f.srcPort, f.dstPort))) return false;
  if (r.applicationIds.length > 0 && (!f.app || !r.applicationIds.some((a) => a.toLowerCase() === f.app!.toLowerCase())))
    return false;
  if (r.userNames.length > 0 && (!f.userName || !r.userNames.includes(f.userName))) return false;
  if (r.srcMacs.length > 0 && (!f.srcMac || !r.srcMacs.some((m) => m.toLowerCase() === f.srcMac!.toLowerCase())))
    return false;
  if (r.schedule && !scheduleActive(r.schedule, at)) return false;
  return true;
}

/** First-match-wins evaluation; returns the matching rule or null (implicit deny). */
export function evaluateRules(rules: EvalRule[], f: FlowSpec, at: Date): EvalRule | null {
  const ordered = [...rules].sort((a, b) => a.position - b.position);
  for (const r of ordered) {
    if (ruleMatches(r, f, at)) return r;
  }
  return null;
}

// ── shadow / conflict detection (validate endpoint, M03 §5) ───────────────

export interface CandidateRule {
  name: string;
  action: string;
  srcZoneIds: number[];
  dstZoneIds: number[];
  srcAddrs: AddrMatcher[];
  dstAddrs: AddrMatcher[];
  services: ServiceMatcher[];
  applicationIds: string[];
  userNames: string[];
  schedule: ScheduleSpec | null;
}

export interface ConflictRow {
  ruleId: number | null;
  ruleName: string;
  reason: "shadowed_by" | "conflicts_with" | "redundant";
  withRuleId: number;
  withRuleName: string;
}

function setSuperset(outer: number[], inner: number[]): boolean {
  // empty = wildcard (matches everything → superset of any set)
  if (outer.length === 0) return true;
  if (inner.length === 0) return false;
  return inner.every((v) => outer.includes(v));
}

function sameSet(a: number[], b: number[]): boolean {
  if (a.length === 0 && b.length === 0) return true;
  if (a.length === 0 || b.length === 0) return false;
  return a.length === b.length && a.every((v) => b.includes(v));
}

function keySet<T>(items: T[], key: (t: T) => string): Set<string> {
  return new Set(items.map(key));
}

const addrKey = (m: AddrMatcher) => `${m.kind}|${JSON.stringify(m)}`;
const svcKey = (s: ServiceMatcher) => `${s.protocol}|${JSON.stringify(s.srcPorts)}|${JSON.stringify(s.dstPorts)}`;

/** addr/service superset: every entry of `inner` is also present in `outer` (empty outer = wildcard). */
function entrySuperset<T>(outer: T[], inner: T[], key: (t: T) => string): boolean {
  if (outer.length === 0) return true;
  if (inner.length === 0) return false;
  const ko = keySet(outer, key);
  return inner.every((i) => ko.has(key(i)));
}

function sameEntries<T>(a: T[], b: T[], key: (t: T) => string): boolean {
  if (a.length === 0 && b.length === 0) return true;
  if (a.length === 0 || b.length === 0) return false;
  const ka = keySet(a, key);
  const kb = keySet(b, key);
  return ka.size === kb.size && [...ka].every((k) => kb.has(k));
}

function sameSchedule(a: ScheduleSpec | null, b: ScheduleSpec | null): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * Every dimension: does E's constraint cover (⊇) R's? An unconstrained
 * dimension covers everything. E ⊇ R on all dimensions ⇒ R can never be
 * reached before E (shadowed/redundant); identical scope + different action
 * ⇒ contradictions.
 */
function covers(E: CandidateRule, R: CandidateRule): boolean {
  return (
    setSuperset(E.srcZoneIds, R.srcZoneIds) &&
    setSuperset(E.dstZoneIds, R.dstZoneIds) &&
    entrySuperset(E.srcAddrs, R.srcAddrs, addrKey) &&
    entrySuperset(E.dstAddrs, R.dstAddrs, addrKey) &&
    entrySuperset(E.services, R.services, svcKey) &&
    (E.applicationIds.length === 0 ||
      R.applicationIds.length === 0 ||
      R.applicationIds.every((a) => E.applicationIds.some((b) => b.toLowerCase() === a.toLowerCase()))) &&
    (E.userNames.length === 0 || R.userNames.length === 0 || R.userNames.every((u) => E.userNames.includes(u))) &&
    (E.schedule === null || sameSchedule(E.schedule, R.schedule))
  );
}

function identicalScope(R: CandidateRule, E: CandidateRule): boolean {
  const appsEq =
    R.applicationIds.length === E.applicationIds.length &&
    R.applicationIds.every((a) => E.applicationIds.some((b) => b.toLowerCase() === a.toLowerCase()));
  const usersEq =
    R.userNames.length === E.userNames.length && R.userNames.every((u) => E.userNames.includes(u));
  return (
    sameSet(R.srcZoneIds, E.srcZoneIds) &&
    sameSet(R.dstZoneIds, E.dstZoneIds) &&
    sameEntries(R.srcAddrs, E.srcAddrs, addrKey) &&
    sameEntries(R.dstAddrs, E.dstAddrs, addrKey) &&
    sameEntries(R.services, E.services, svcKey) &&
    appsEq &&
    usersEq &&
    sameSchedule(R.schedule, E.schedule)
  );
}

/**
 * Compare candidate R against every ENABLED existing rule with a LOWER
 * position (M03 §5). E ⊇ R + different action → shadowed_by (error);
 * identical scope + different action → conflicts_with (error);
 * E ⊇ R + same action → redundant (warning).
 */
export function detectConflicts(
  candidate: CandidateRule,
  existing: Array<EvalRule & { position: number }>,
  excludeRuleId?: number,
): ConflictRow[] {
  const conflicts: ConflictRow[] = [];
  const ordered = [...existing]
    .filter((r) => r.enabled && r.id !== excludeRuleId)
    .sort((a, b) => a.position - b.position);
  const maxPos = ordered.length ? ordered[ordered.length - 1].position + 1 : 1;
  const candidatePos = maxPos; // candidate is being created/appended at the end

  for (const e of ordered) {
    if (e.position >= candidatePos && e.id !== excludeRuleId) continue; // only earlier rules shadow
    const asCandidate: CandidateRule = {
      name: e.name,
      action: e.action,
      srcZoneIds: e.srcZoneIds,
      dstZoneIds: e.dstZoneIds,
      srcAddrs: e.srcAddrs,
      dstAddrs: e.dstAddrs,
      services: e.services,
      applicationIds: e.applicationIds,
      userNames: e.userNames,
      schedule: e.schedule,
    };
    const superset = covers(e, candidate);
    const identical = identicalScope(candidate, asCandidate);
    if (identical && e.action !== candidate.action) {
      conflicts.push({
        ruleId: excludeRuleId ?? null,
        ruleName: candidate.name,
        reason: "conflicts_with",
        withRuleId: e.id,
        withRuleName: e.name,
      });
    } else if (superset && e.action !== candidate.action) {
      conflicts.push({
        ruleId: excludeRuleId ?? null,
        ruleName: candidate.name,
        reason: "shadowed_by",
        withRuleId: e.id,
        withRuleName: e.name,
      });
    } else if (superset && e.action === candidate.action) {
      conflicts.push({
        ruleId: excludeRuleId ?? null,
        ruleName: candidate.name,
        reason: "redundant",
        withRuleId: e.id,
        withRuleName: e.name,
      });
    }
  }
  return conflicts;
}
