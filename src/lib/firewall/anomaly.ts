/**
 * Config anomaly detectors (spec §4.5 "Config anomaly" — rule-based part; the
 * ML column of the spec table is explicitly OUT of scope here) — PURE, no DB,
 * no clock, no Prisma imports. Every detector consumes a minimal rule-array
 * DTO (`AnomalyRule`) that mirrors the JSON id-array columns of FirewallRule
 * (empty array = wildcard "any", exactly like the M03 evaluator in
 * rule-match.ts) plus an expanded per-rule service list for port checks.
 *
 * Detectors (each returns 0..n finding drafts — persistence/dedup lives in
 * anomaly-service.ts):
 *   1. detectAnyAny          — enabled allow with src/dst/service all "any" → high
 *   2. detectWanPermissive   — WAN-sourced allow to any dst + any/all-port service → medium
 *   3. detectShadowed        — later rule unreachable behind an earlier
 *                              equal-action superset rule → medium
 *   4. detectLogDisabled     — WAN-boundary-crossing allow with logging off → low
 *   5. detectDuplicates      — exact duplicates (same normalized fields) → low
 *   6. detectUnusedObjects   — address/service objects referenced by zero
 *                              ENABLED rules → low (subjectRef
 *                              "address_object:<id>" / "service_object:<id>")
 *
 * Scope assumptions (documented for the rule-based pass):
 *   • Shadowing uses the SAME-ACTION superset rule only (BOTH-ACTIONS-EQUAL
 *     assumption): an earlier broader rule with a DIFFERENT action creates a
 *     partial overlap, not a dead rule — those overlaps are already reported
 *     by the rule validate endpoint (shadowed_by / conflicts_with) and are
 *     deliberately not duplicated here.
 *   • Unused-object detection counts direct rule references plus group
 *     membership expansion (an object used only through a group is IN use);
 *     groups themselves are never flagged as unused.
 */

// ── public shapes ───────────────────────────────────────────────────────────

export type AnomalyKind =
  | "any_any_rule"
  | "wan_permissive"
  | "unused_object"
  | "shadowed_rule"
  | "log_disabled"
  | "duplicate_rule";

export type AnomalySeverity = "low" | "medium" | "high";

/** Locked severity per finding kind (§4.5 rule-based pass). */
export const KIND_SEVERITY: Record<AnomalyKind, AnomalySeverity> = {
  any_any_rule: "high",
  wan_permissive: "medium",
  shadowed_rule: "medium",
  log_disabled: "low",
  duplicate_rule: "low",
  unused_object: "low",
};

/**
 * Expanded service reference used for port-permissiveness checks. The service
 * layer hydrates this from service_objects (+ groups); `dstPort` uses the
 * stored grammar ("any" | "80" | "5000-5100,6000" | null).
 */
export interface AnomalyServiceRef {
  protocol: string; // tcp | udp | icmp | any
  dstPort: string | null;
}

/**
 * Minimal rule DTO over the FirewallRule JSON id-array columns.
 * EMPTY ARRAY = wildcard "any" (M03 evaluator semantics); `services` is the
 * rule's serviceIds expanded to concrete service objects — when omitted and
 * serviceIds is non-empty, port judgment fails CLOSED (never permissive).
 */
export interface AnomalyRule {
  id: number;
  name: string;
  enabled: boolean;
  position: number;
  action: string; // allow | deny | drop | reject
  logging: string; // none | summary | detail
  srcZoneIds: number[];
  dstZoneIds: number[];
  srcAddrIds: number[];
  dstAddrIds: number[];
  serviceIds: number[];
  applicationIds: string[];
  userIds: number[];
  srcMacs: string[];
  scheduleId: number | null;
  family: string; // ipv4 | ipv6 | both
  services?: AnomalyServiceRef[];
}

/** Object inventory entry for detectUnusedObjects (leaf + group entries). */
export interface AnomalyObjectRef {
  kind: "address" | "service" | "address_group" | "service_group";
  id: number;
  name: string;
  /** group entries only: member leaf-object ids (address_objects/service_objects ids) */
  memberIds?: number[];
}

export interface AnomalyFindingDetail {
  message: string;
  ruleIds: number[];
  suggestion: string;
}

export interface AnomalyFindingDraft {
  kind: AnomalyKind;
  severity: AnomalySeverity;
  /** "firewall_rule:12" / "address_object:3" / "service_object:7" style */
  subjectRef: string;
  detail: AnomalyFindingDetail;
}

export interface LogDisabledOptions {
  /** master switch — WAN-boundary logging is only enforced when required */
  requireWanLogging: boolean;
  /** zone ids classified as WAN (service layer derives them from zone/iface roles) */
  wanZones?: number[];
}

const firewallRef = (id: number): string => `firewall_rule:${id}`;

function idSuperset(outer: number[], inner: number[]): boolean {
  // empty = wildcard → superset of anything; a wildcard can never be inside
  if (outer.length === 0) return true;
  if (inner.length === 0) return false;
  const set = new Set(outer);
  return inner.every((v) => set.has(v));
}

// ── service permissiveness ──────────────────────────────────────────────────

const FULL_PORT_SPAN = { lo: 1, hi: 65_535 } as const;

/** Parse the dstPort grammar ("any" | "80" | "5000-5100,6000") into ranges. */
export function parseDstPortRanges(raw: string | null): Array<{ lo: number; hi: number }> {
  if (!raw || raw.trim() === "" || raw.trim().toLowerCase() === "any") return [];
  const out: Array<{ lo: number; hi: number }> = [];
  for (const seg of raw.split(",")) {
    const s = seg.trim();
    if (s === "") continue;
    if (s.includes("-")) {
      const [lo, hi] = s.split("-").map(Number);
      if (Number.isFinite(lo) && Number.isFinite(hi)) out.push({ lo, hi });
    } else {
      const p = Number(s);
      if (Number.isFinite(p)) out.push({ lo: p, hi: p });
    }
  }
  return out;
}

/** True when the union of `ranges` covers every port in [1, 65535]. */
export function coversAllPorts(ranges: Array<{ lo: number; hi: number }>): boolean {
  if (ranges.length === 0) return false; // caller treats empty as "any" — this fn is for parsed lists
  const sorted = [...ranges].sort((a, b) => a.lo - b.lo);
  let cursor = FULL_PORT_SPAN.lo;
  for (const r of sorted) {
    if (r.lo > cursor) return false;
    cursor = Math.max(cursor, r.hi + 1);
    if (cursor > FULL_PORT_SPAN.hi) return true;
  }
  return cursor > FULL_PORT_SPAN.hi;
}

/**
 * A concrete service is "fully permissive" when it admits all tcp/udp ports:
 * protocol "any", or tcp/udp whose dst ports are unset ("any") or whose union
 * covers 0–65535 style spans. ICMP-only services are protocol-scoped → not
 * permissive.
 */
export function serviceIsPermissive(s: AnomalyServiceRef): boolean {
  const proto = s.protocol.toLowerCase();
  if (proto === "any") return true;
  if (proto !== "tcp" && proto !== "udp") return false;
  const ranges = parseDstPortRanges(s.dstPort);
  return ranges.length === 0 || coversAllPorts(ranges);
}

/**
 * Rule-level service permissiveness: unset service list = any → permissive;
 * otherwise ANY single expanded permissive service makes the rule permissive
 * (the rule admits at least that all-port service). Un-expandable rules
 * (services omitted with non-empty serviceIds) fail closed.
 */
function ruleServicePermissive(r: AnomalyRule): boolean {
  if (r.serviceIds.length === 0) return true;
  if (!r.services || r.services.length === 0) return false; // fail closed
  return r.services.some(serviceIsPermissive);
}

const intersects = (list: number[], wanZones: number[]): boolean => {
  const w = new Set(wanZones);
  return list.some((z) => w.has(z));
};

// ── 1. any-any allow ────────────────────────────────────────────────────────

/**
 * Enabled allow rules with src=any (zones AND addresses empty), dst=any and
 * service=any → the classic unrestricted pass-all rule, severity high.
 * Per the task definition the match is on src/dst/service only: app/user/
 * schedule constraints are NOT part of this rule of thumb (a review-worthy
 * warning is preferred over a silent miss).
 */
export function detectAnyAny(rules: AnomalyRule[]): AnomalyFindingDraft[] {
  const findings: AnomalyFindingDraft[] = [];
  for (const r of rules) {
    if (!r.enabled || r.action !== "allow") continue;
    const srcAny = r.srcZoneIds.length === 0 && r.srcAddrIds.length === 0;
    const dstAny = r.dstZoneIds.length === 0 && r.dstAddrIds.length === 0;
    const svcAny = r.serviceIds.length === 0;
    if (!(srcAny && dstAny && svcAny)) continue;
    findings.push({
      kind: "any_any_rule",
      severity: KIND_SEVERITY.any_any_rule,
      subjectRef: firewallRef(r.id),
      detail: {
        message: `Rule "${r.name}" (#${r.id}) allows any source to any destination on any service — fully unrestricted pass-all`,
        ruleIds: [r.id],
        suggestion: "Restrict source/destination/service scopes, or demote to deny; an implicit-deny posture should not contain a pass-all allow",
      },
    });
  }
  return findings.sort((a, b) => a.subjectRef.localeCompare(b.subjectRef, undefined, { numeric: true }));
}

// ── 2. WAN-permissive allow ─────────────────────────────────────────────────

/**
 * Enabled allow rules whose source zone explicitly includes a WAN zone and
 * whose destination is any (zones AND addresses empty) with a permissive
 * service (unset serviceIds = any, or an expanded all-port tcp/udp service)
 * → internet-initiated unrestricted allow, severity medium. Source "any"
 * rules are deliberately NOT flagged here (they are the any_any detector's
 * domain — avoids double-flagging the same rule).
 */
export function detectWanPermissive(rules: AnomalyRule[], wanZones: number[]): AnomalyFindingDraft[] {
  if (wanZones.length === 0) return [];
  const findings: AnomalyFindingDraft[] = [];
  for (const r of rules) {
    if (!r.enabled || r.action !== "allow") continue;
    if (!intersects(r.srcZoneIds, wanZones)) continue; // WAN must be explicit in src
    const dstAny = r.dstZoneIds.length === 0 && r.dstAddrIds.length === 0;
    if (!dstAny) continue;
    if (!ruleServicePermissive(r)) continue;
    findings.push({
      kind: "wan_permissive",
      severity: KIND_SEVERITY.wan_permissive,
      subjectRef: firewallRef(r.id),
      detail: {
        message: `Rule "${r.name}" (#${r.id}) allows inbound WAN traffic to any destination with unrestricted ports`,
        ruleIds: [r.id],
        suggestion: "Constrain destination and service (publish only required ports via DNAT rules instead of a WAN allow-all)",
      },
    });
  }
  return findings.sort((a, b) => a.subjectRef.localeCompare(b.subjectRef, undefined, { numeric: true }));
}

// ── 3. shadowed rules ───────────────────────────────────────────────────────

/**
 * Rule B is unreachable when an earlier rule A (lower position, both enabled)
 * with the SAME action covers every dimension of B (A ⊇ B):
 *   src zones ⊇ B, dst zones ⊇ B, src addrs ⊇ B, dst addrs ⊇ B, services ⊇ B
 *   (empty = wildcard), apps/users/mac lists ⊇ B, and A's schedule is either
 *   unset (always active) or identical to B's.
 *
 * BOTH-ACTIONS-EQUAL ASSUMPTION (documented): only equal-action supersets
 * make B fully redundant — every flow B could match is already terminated by
 * A with the same verdict, so B can never decide anything. Differing-action
 * overlaps are partial shadows handled by the M03 validate endpoint, not here.
 * One finding per shadowed rule (the first — earliest — shadower wins);
 * severity medium.
 */
export function detectShadowed(rules: AnomalyRule[]): AnomalyFindingDraft[] {
  const enabled = rules.filter((r) => r.enabled).sort((a, b) => a.position - b.position || a.id - b.id);
  const findings: AnomalyFindingDraft[] = [];

  const covers = (a: AnomalyRule, b: AnomalyRule): boolean =>
    idSuperset(a.srcZoneIds, b.srcZoneIds) &&
    idSuperset(a.dstZoneIds, b.dstZoneIds) &&
    idSuperset(a.srcAddrIds, b.srcAddrIds) &&
    idSuperset(a.dstAddrIds, b.dstAddrIds) &&
    idSuperset(a.serviceIds, b.serviceIds) &&
    appsCover(a.applicationIds, b.applicationIds) &&
    usersCover(a.userIds, b.userIds) &&
    macsCover(a.srcMacs, b.srcMacs) &&
    (a.scheduleId === null || a.scheduleId === b.scheduleId);

  for (let bi = 1; bi < enabled.length; bi++) {
    const b = enabled[bi];
    const shadower = enabled.slice(0, bi).find((a) => a.action === b.action && covers(a, b));
    if (!shadower) continue;
    findings.push({
      kind: "shadowed_rule",
      severity: KIND_SEVERITY.shadowed_rule,
      subjectRef: firewallRef(b.id),
      detail: {
        message: `Rule "${b.name}" (#${b.id}, ${b.action}) is unreachable — earlier rule "${shadower.name}" (#${shadower.id}) matches a superset of its scope with the same action`,
        ruleIds: [b.id, shadower.id],
        suggestion: `Remove rule #${b.id} or move/narrow it above #${shadower.id} if a distinct verdict was intended`,
      },
    });
  }
  return findings.sort((a, b) => a.subjectRef.localeCompare(b.subjectRef, undefined, { numeric: true }));
}

// helpers shared by the covers() predicate above
function appsCover(a: string[], b: string[]): boolean {
  if (a.length === 0) return true; // wildcard covers any app list
  if (b.length === 0) return false;
  return b.every((x) => a.some((y) => y.toLowerCase() === x.toLowerCase()));
}
function usersCover(a: number[], b: number[]): boolean {
  if (a.length === 0) return true;
  if (b.length === 0) return false;
  return b.every((x) => a.includes(x));
}
function macsCover(a: string[], b: string[]): boolean {
  if (a.length === 0) return true;
  if (b.length === 0) return false;
  const set = new Set(a.map((m) => m.toLowerCase()));
  return b.every((m) => set.has(m.toLowerCase()));
}

// ── 4. WAN-boundary logging disabled ────────────────────────────────────────

/**
 * Enabled allow rules able to carry WAN-boundary traffic with logging "none"
 * → audit-trail gap, severity low. A side "can be WAN" when its zone list is
 * empty (any) or intersects wanZones; it "can be non-WAN" when empty or not
 * WAN-only. Crossing = one side can be WAN while the other can be non-WAN
 * (so WAN→any, any→any and WAN→LAN all cross; WAN→WAN and LAN→LAN do not).
 * The whole check is gated on {requireWanLogging} and on a non-empty
 * wanZones list (no WAN classification → nothing to cross). deny/drop rules
 * need no logging here: their terminations surface in firewall deny
 * telemetry.
 */
export function detectLogDisabled(rules: AnomalyRule[], opts: LogDisabledOptions): AnomalyFindingDraft[] {
  const wanZones = opts.wanZones ?? [];
  if (!opts.requireWanLogging || wanZones.length === 0) return [];
  const wan = new Set(wanZones);
  const canWan = (zs: number[]): boolean => zs.length === 0 || zs.some((z) => wan.has(z));
  const canNonWan = (zs: number[]): boolean => zs.length === 0 || zs.some((z) => !wan.has(z));
  const findings: AnomalyFindingDraft[] = [];
  for (const r of rules) {
    if (!r.enabled || r.action !== "allow") continue;
    if (r.logging !== "none") continue;
    const crossing = (canWan(r.srcZoneIds) && canNonWan(r.dstZoneIds)) || (canWan(r.dstZoneIds) && canNonWan(r.srcZoneIds));
    if (!crossing) continue;
    findings.push({
      kind: "log_disabled",
      severity: KIND_SEVERITY.log_disabled,
      subjectRef: firewallRef(r.id),
      detail: {
        message: `Rule "${r.name}" (#${r.id}) allows traffic across the WAN boundary without logging`,
        ruleIds: [r.id],
        suggestion: "Set logging to summary (or detail) so internet-facing sessions leave an audit trail",
      },
    });
  }
  return findings.sort((a, b) => a.subjectRef.localeCompare(b.subjectRef, undefined, { numeric: true }));
}

// ── 5. exact duplicates ─────────────────────────────────────────────────────

/**
 * Exact duplicates: enabled rules whose NORMALIZED match/action fields are
 * identical — action, logging, family, src/dst zones, src/dst addresses,
 * services, applications (case-insensitive), users, src MACs
 * (case-insensitive), schedule. The earliest rule (lowest position/id) is the
 * survivor; every group yields ONE finding whose subjectRef anchors on the
 * lowest rule id, severity low.
 */
export function detectDuplicates(rules: AnomalyRule[]): AnomalyFindingDraft[] {
  const fingerprint = (r: AnomalyRule): string =>
    JSON.stringify({
      action: r.action,
      logging: r.logging,
      family: r.family,
      srcZoneIds: [...r.srcZoneIds].sort((a, b) => a - b),
      dstZoneIds: [...r.dstZoneIds].sort((a, b) => a - b),
      srcAddrIds: [...r.srcAddrIds].sort((a, b) => a - b),
      dstAddrIds: [...r.dstAddrIds].sort((a, b) => a - b),
      serviceIds: [...r.serviceIds].sort((a, b) => a - b),
      applicationIds: [...r.applicationIds].map((s) => s.toLowerCase()).sort(),
      userIds: [...r.userIds].sort((a, b) => a - b),
      srcMacs: [...r.srcMacs].map((m) => m.toLowerCase()).sort(),
      scheduleId: r.scheduleId,
    });

  const groups = new Map<string, AnomalyRule[]>();
  for (const r of rules) {
    if (!r.enabled) continue;
    const key = fingerprint(r);
    const rows = groups.get(key);
    if (rows) rows.push(r);
    else groups.set(key, [r]);
  }

  const findings: AnomalyFindingDraft[] = [];
  for (const members of groups.values()) {
    if (members.length < 2) continue;
    const ordered = [...members].sort((a, b) => a.position - b.position || a.id - b.id);
    const anchor = ordered.reduce((min, r) => (r.id < min ? r.id : min), ordered[0].id);
    findings.push({
      kind: "duplicate_rule",
      severity: KIND_SEVERITY.duplicate_rule,
      subjectRef: firewallRef(anchor),
      detail: {
        message: `Rules ${ordered.map((r) => `"${r.name}" (#${r.id})`).join(", ")} are exact duplicates (same match and action)`,
        ruleIds: ordered.map((r) => r.id),
        suggestion: `Keep #${anchor} and delete the redundant duplicate${ordered.length > 2 ? "s" : ""} — duplicates double the maintenance surface and skew hit counters`,
      },
    });
  }
  return findings.sort((a, b) => a.subjectRef.localeCompare(b.subjectRef, undefined, { numeric: true }));
}

// ── 6. unused objects ───────────────────────────────────────────────────────

/**
 * Address/service objects referenced by ZERO enabled rules → cleanup
 * candidates, severity low, subjectRef "address_object:<id>" /
 * "service_object:<id>". Group members count as used when the GROUP is
 * referenced (fixpoint expansion over memberIds), so an object reachable only
 * through a group is never falsely flagged; groups themselves are never
 * flagged (leaf objects only). Disabled-rule references do NOT count.
 */
export function detectUnusedObjects(rules: AnomalyRule[], objects: AnomalyObjectRef[]): AnomalyFindingDraft[] {
  const used = new Set<number>();
  const groups = new Map<number, number[]>(); // group id → member leaf ids
  const usedGroups = new Set<number>();

  for (const r of rules) {
    if (!r.enabled) continue;
    for (const id of r.srcAddrIds) used.add(id);
    for (const id of r.dstAddrIds) used.add(id);
    for (const id of r.serviceIds) used.add(id);
  }
  for (const o of objects) {
    if (o.kind === "address_group" || o.kind === "service_group") {
      groups.set(o.id, o.memberIds ?? []);
    }
  }

  // fixpoint: a used group marks all (transitively) reachable members used
  let grew = true;
  while (grew) {
    grew = false;
    for (const [gid, members] of groups) {
      if (!used.has(gid) || usedGroups.has(gid)) continue;
      usedGroups.add(gid);
      for (const m of members) {
        if (!used.has(m)) {
          used.add(m);
          grew = true; // a member may itself be a (nested) group id
        }
      }
    }
  }

  const findings: AnomalyFindingDraft[] = [];
  for (const o of objects) {
    if (o.kind !== "address" && o.kind !== "service") continue; // leaf objects only
    if (used.has(o.id)) continue;
    findings.push({
      kind: "unused_object",
      severity: KIND_SEVERITY.unused_object,
      subjectRef: `${o.kind}_object:${o.id}`,
      detail: {
        message: `${o.kind === "address" ? "Address" : "Service"} object "${o.name}" (#${o.id}) is not referenced by any enabled rule`,
        ruleIds: [],
        suggestion: "Delete the object or reference it from a rule — dead objects hide stale attack surface from reviewers",
      },
    });
  }
  return findings.sort((a, b) => a.subjectRef.localeCompare(b.subjectRef, undefined, { numeric: true }));
}

// ── aggregate ───────────────────────────────────────────────────────────────

/** Full rule-based pass: run every detector and concatenate the drafts. */
export function detectAllAnomalies(
  rules: AnomalyRule[],
  opts: { wanZones?: number[]; objects?: AnomalyObjectRef[]; requireWanLogging?: boolean },
): AnomalyFindingDraft[] {
  const wanZones = opts.wanZones ?? [];
  return [
    ...detectAnyAny(rules),
    ...detectWanPermissive(rules, wanZones),
    ...detectShadowed(rules),
    ...detectLogDisabled(rules, { requireWanLogging: opts.requireWanLogging ?? true, wanZones }),
    ...detectDuplicates(rules),
    ...detectUnusedObjects(rules, opts.objects ?? []),
  ];
}
