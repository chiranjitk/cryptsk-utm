/**
 * Config anomaly tests (spec §4.5 rule-based pass) — two layers:
 *   • PURE detectors (lib/firewall/anomaly): positive + negative cases for all
 *     six detectors — any-any allow (high), WAN-permissive allow incl. the
 *     port-permissiveness primitives (medium), shadowed rules incl. the
 *     superset logic and the BOTH-ACTIONS-EQUAL assumption (medium),
 *     WAN-boundary logging gaps (low), exact duplicates incl. normalization
 *     (low), unused address/service objects incl. group expansion (low),
 *   • DB-backed service over a per-run copy of the pushed dev schema (same
 *     copy-db harness as incidents.test.ts): scan on a dirty config creates
 *     the expected finding set, a second scan dedupes (no new rows), manual
 *     resolution is NOT resurrected by later scans (triage suppression
 *     window), open findings the config no longer produces are auto-resolved
 *     with resolvedAt, and triage validation.
 *
 * The db/service modules are imported AFTER the DATABASE_URL override —
 * static imports would resolve the Prisma datasource too early. WAN zones are
 * passed explicitly (no zone/iface fixtures needed — rule zone refs are
 * logical JSON ids, so a synthetic WAN id keeps the harness hermetic).
 */

import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// pure detectors — no DB dependency, safe to import statically
import {
  KIND_SEVERITY,
  coversAllPorts,
  detectAnyAny,
  detectDuplicates,
  detectLogDisabled,
  detectShadowed,
  detectUnusedObjects,
  detectWanPermissive,
  parseDstPortRanges,
  serviceIsPermissive,
  type AnomalyObjectRef,
  type AnomalyRule,
} from "@/lib/firewall/anomaly";

const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "config-anomaly-"));
const DB_PATH = path.join(TMP_DIR, "config-anomaly-test.db");
fs.copyFileSync(path.resolve(process.cwd(), "db/cryptsk.db"), DB_PATH);
process.env.DATABASE_URL = `file:${DB_PATH}`;

const { db } = await import("@/lib/db");
const service = await import("@/lib/firewall/anomaly-service");

const WAN_ZONE = 4242; // synthetic WAN zone id — firewall rule zone refs are logical ids
const LAN_ZONE_A = 4343;
const LAN_ZONE_B = 4444;

// ── pure fixtures ───────────────────────────────────────────────────────────

let seq = 0;

/** Canonical enabled allow rule with every scope empty (= any). */
function rule(overrides: Partial<AnomalyRule> = {}): AnomalyRule {
  seq += 1;
  return {
    id: seq,
    name: `ca-rule-${seq}`,
    enabled: true,
    position: seq * 10,
    action: "allow",
    logging: "summary",
    srcZoneIds: [],
    dstZoneIds: [],
    srcAddrIds: [],
    dstAddrIds: [],
    serviceIds: [],
    applicationIds: [],
    userIds: [],
    srcMacs: [],
    scheduleId: null,
    family: "ipv4",
    services: [],
    ...overrides,
  };
}

beforeAll(async () => {
  // the copied dev schema has no tenant rows — finding rows FK to tenants
  await db.tenant.upsert({ where: { id: 1 }, update: {}, create: { id: 1, name: "config-anomaly-test" } });
});

beforeEach(async () => {
  // the copy is a throwaway: wipe every input table the scan reads
  await db.configAnomalyFinding.deleteMany({});
  await db.firewallRule.deleteMany({});
  await db.addressObject.deleteMany({});
  await db.addressGroup.deleteMany({});
  await db.serviceObject.deleteMany({});
  await db.serviceGroup.deleteMany({});
});

afterAll(async () => {
  await db.$disconnect();
  fs.rmSync(TMP_DIR, { recursive: true, force: true });
});

// ═══════════════════════════════ PURE DETECTORS ═════════════════════════════

describe("detectAnyAny", () => {
  it("flags an enabled allow rule with src/dst/service all any as high", () => {
    const r = rule();
    const findings = detectAnyAny([r]);
    expect(findings).toHaveLength(1);
    expect(findings[0].kind).toBe("any_any_rule");
    expect(findings[0].severity).toBe("high");
    expect(findings[0].subjectRef).toBe(`firewall_rule:${r.id}`);
    expect(findings[0].detail.ruleIds).toEqual([r.id]);
    expect(findings[0].detail.suggestion.length).toBeGreaterThan(0);
  });

  it("does not flag rules with any side scoped (zone or address or service)", () => {
    expect(detectAnyAny([rule({ srcZoneIds: [WAN_ZONE] })])).toHaveLength(0);
    expect(detectAnyAny([rule({ srcAddrIds: [11] })])).toHaveLength(0);
    expect(detectAnyAny([rule({ dstZoneIds: [LAN_ZONE_A] })])).toHaveLength(0);
    expect(detectAnyAny([rule({ dstAddrIds: [12] })])).toHaveLength(0);
    expect(detectAnyAny([rule({ serviceIds: [13] })])).toHaveLength(0);
  });

  it("does not flag deny actions or disabled rules", () => {
    expect(detectAnyAny([rule({ action: "deny" })])).toHaveLength(0);
    expect(detectAnyAny([rule({ enabled: false })])).toHaveLength(0);
  });
});

describe("detectWanPermissive", () => {
  it("flags an explicit-WAN allow to any destination with any service as medium", () => {
    const r = rule({ srcZoneIds: [WAN_ZONE] });
    const findings = detectWanPermissive([r], [WAN_ZONE]);
    expect(findings).toHaveLength(1);
    expect(findings[0].kind).toBe("wan_permissive");
    expect(findings[0].severity).toBe("medium");
    expect(findings[0].subjectRef).toBe(`firewall_rule:${r.id}`);
  });

  it("flags a WAN allow whose expanded service covers all ports (0-65535 style)", () => {
    const r = rule({ srcZoneIds: [WAN_ZONE], serviceIds: [9], services: [{ protocol: "tcp", dstPort: "0-65535" }] });
    expect(detectWanPermissive([r], [WAN_ZONE])).toHaveLength(1);
  });

  it("does not flag restricted services, icmp-only services or un-expandable rules (fail closed)", () => {
    expect(
      detectWanPermissive([rule({ srcZoneIds: [WAN_ZONE], serviceIds: [9], services: [{ protocol: "tcp", dstPort: "443" }] })], [WAN_ZONE]),
    ).toHaveLength(0);
    expect(
      detectWanPermissive([rule({ srcZoneIds: [WAN_ZONE], serviceIds: [9], services: [{ protocol: "icmp", dstPort: null }] })], [WAN_ZONE]),
    ).toHaveLength(0);
    // services omitted + serviceIds set → judgment fails closed, never flags
    const unexpandable = rule({ srcZoneIds: [WAN_ZONE], serviceIds: [9] });
    delete unexpandable.services;
    expect(detectWanPermissive([unexpandable], [WAN_ZONE])).toHaveLength(0);
  });

  it("does not flag non-WAN sources, scoped destinations, denies or disabled rules", () => {
    expect(detectWanPermissive([rule({ srcZoneIds: [LAN_ZONE_A] })], [WAN_ZONE])).toHaveLength(0);
    expect(detectWanPermissive([rule({ srcZoneIds: [WAN_ZONE], dstZoneIds: [LAN_ZONE_A] })], [WAN_ZONE])).toHaveLength(0);
    expect(detectWanPermissive([rule({ srcZoneIds: [WAN_ZONE], action: "deny" })], [WAN_ZONE])).toHaveLength(0);
    expect(detectWanPermissive([rule({ srcZoneIds: [WAN_ZONE], enabled: false })], [WAN_ZONE])).toHaveLength(0);
    // src "any" is the any_any detector's domain — no double flagging here
    expect(detectWanPermissive([rule()], [WAN_ZONE])).toHaveLength(0);
  });

  it("returns nothing without a WAN classification", () => {
    expect(detectWanPermissive([rule({ srcZoneIds: [WAN_ZONE] })], [])).toHaveLength(0);
  });
});

describe("detectShadowed", () => {
  it("flags a later rule behind an earlier equal-action superset (A ⊇ B)", () => {
    const a = rule({ id: 1, position: 10 });
    const b = rule({ id: 2, position: 20, srcZoneIds: [LAN_ZONE_A] });
    const findings = detectShadowed([b, a]); // input order irrelevant — position decides
    expect(findings).toHaveLength(1);
    expect(findings[0].kind).toBe("shadowed_rule");
    expect(findings[0].severity).toBe("medium");
    expect(findings[0].subjectRef).toBe(`firewall_rule:${b.id}`);
    expect(findings[0].detail.ruleIds).toEqual([b.id, a.id]);
  });

  it("assumes BOTH ACTIONS EQUAL: differing actions are not shadowing here", () => {
    // an earlier allow covering a later deny creates a partial overlap, NOT a
    // dead rule — those are the M03 validate endpoint's shadowed_by/conflicts
    // findings and are deliberately not duplicated by this scanner
    const a = rule({ id: 1, position: 10, action: "allow" });
    const b = rule({ id: 2, position: 20, action: "deny", srcZoneIds: [LAN_ZONE_A] });
    expect(detectShadowed([a, b])).toHaveLength(0);
  });

  it("requires a genuine superset: a narrower earlier rule shadows nothing", () => {
    const a = rule({ id: 1, position: 10, srcZoneIds: [LAN_ZONE_A] });
    const b = rule({ id: 2, position: 20 });
    expect(detectShadowed([a, b])).toHaveLength(0);
  });

  it("treats an exact-scope same-action pair as shadowing", () => {
    const a = rule({ id: 1, position: 10, serviceIds: [5], srcAddrIds: [7] });
    const b = rule({ id: 2, position: 20, serviceIds: [5], srcAddrIds: [7] });
    const findings = detectShadowed([a, b]);
    expect(findings).toHaveLength(1);
    expect(findings[0].subjectRef).toBe(`firewall_rule:${b.id}`);
  });

  it("respects app/user/mac superset semantics and schedule equality", () => {
    // A with no app constraint covers B's app list
    expect(detectShadowed([rule({ id: 1, position: 10 }), rule({ id: 2, position: 20, applicationIds: ["youtube"] })])).toHaveLength(1);
    // A scoped to one app does NOT cover B matching two apps
    expect(
      detectShadowed([
        rule({ id: 1, position: 10, applicationIds: ["youtube"] }),
        rule({ id: 2, position: 20, applicationIds: ["youtube", "tiktok"] }),
      ]),
    ).toHaveLength(0);
    // app matching is case-insensitive
    expect(
      detectShadowed([
        rule({ id: 1, position: 10, applicationIds: ["YouTube"] }),
        rule({ id: 2, position: 20, applicationIds: ["youtube"] }),
      ]),
    ).toHaveLength(1);
    // a scheduled earlier rule is not always-on → cannot shadow
    expect(
      detectShadowed([rule({ id: 1, position: 10, scheduleId: 5 }), rule({ id: 2, position: 20, scheduleId: null })]),
    ).toHaveLength(0);
    // identical schedules shadow
    expect(
      detectShadowed([rule({ id: 1, position: 10, scheduleId: 5 }), rule({ id: 2, position: 20, scheduleId: 5 })]),
    ).toHaveLength(1);
  });

  it("ignores disabled rules on either side and later-only shadowers", () => {
    expect(detectShadowed([rule({ id: 1, position: 10, enabled: false }), rule({ id: 2, position: 20 })])).toHaveLength(0);
    expect(detectShadowed([rule({ id: 1, position: 10 }), rule({ id: 2, position: 20, enabled: false })])).toHaveLength(0);
    // later rule cannot shadow the earlier one
    expect(detectShadowed([rule({ id: 1, position: 10, srcZoneIds: [LAN_ZONE_A] }), rule({ id: 2, position: 20 })])).toHaveLength(0);
  });
});

describe("detectLogDisabled", () => {
  const OPTS = { requireWanLogging: true, wanZones: [WAN_ZONE] };

  it("flags unlogged WAN-crossing allow rules as low (WAN→LAN, WAN→any, any→WAN)", () => {
    for (const r of [
      rule({ srcZoneIds: [WAN_ZONE], dstZoneIds: [LAN_ZONE_A], logging: "none" }),
      rule({ srcZoneIds: [WAN_ZONE], logging: "none" }),
      rule({ dstZoneIds: [WAN_ZONE], logging: "none" }),
    ]) {
      const findings = detectLogDisabled([r], OPTS);
      expect(findings).toHaveLength(1);
      expect(findings[0].kind).toBe("log_disabled");
      expect(findings[0].severity).toBe("low");
      expect(findings[0].subjectRef).toBe(`firewall_rule:${r.id}`);
    }
  });

  it("does not flag logged rules, intra-WAN/LAN traffic, denies or disabled rules", () => {
    expect(detectLogDisabled([rule({ srcZoneIds: [WAN_ZONE], dstZoneIds: [LAN_ZONE_A], logging: "summary" })], OPTS)).toHaveLength(0);
    expect(detectLogDisabled([rule({ srcZoneIds: [WAN_ZONE], dstZoneIds: [LAN_ZONE_A], logging: "detail" })], OPTS)).toHaveLength(0);
    expect(detectLogDisabled([rule({ srcZoneIds: [WAN_ZONE], dstZoneIds: [WAN_ZONE], logging: "none" })], OPTS)).toHaveLength(0);
    expect(detectLogDisabled([rule({ srcZoneIds: [LAN_ZONE_A], dstZoneIds: [LAN_ZONE_B], logging: "none" })], OPTS)).toHaveLength(0);
    expect(detectLogDisabled([rule({ srcZoneIds: [WAN_ZONE], dstZoneIds: [LAN_ZONE_A], logging: "none", action: "deny" })], OPTS)).toHaveLength(0);
    expect(detectLogDisabled([rule({ srcZoneIds: [WAN_ZONE], dstZoneIds: [LAN_ZONE_A], logging: "none", enabled: false })], OPTS)).toHaveLength(0);
  });

  it("is gated by requireWanLogging and a non-empty WAN classification", () => {
    const r = rule({ srcZoneIds: [WAN_ZONE], dstZoneIds: [LAN_ZONE_A], logging: "none" });
    expect(detectLogDisabled([r], { requireWanLogging: false, wanZones: [WAN_ZONE] })).toHaveLength(0);
    expect(detectLogDisabled([r], { requireWanLogging: true, wanZones: [] })).toHaveLength(0);
  });
});

describe("detectDuplicates", () => {
  it("flags an exact duplicate pair once, anchored on the lowest rule id", () => {
    const a = rule({ id: 3, position: 10, srcZoneIds: [LAN_ZONE_A], dstZoneIds: [LAN_ZONE_B], serviceIds: [5], logging: "none" });
    const b = rule({ id: 9, position: 20, srcZoneIds: [LAN_ZONE_A], dstZoneIds: [LAN_ZONE_B], serviceIds: [5], logging: "none" });
    const findings = detectDuplicates([a, b]);
    expect(findings).toHaveLength(1);
    expect(findings[0].kind).toBe("duplicate_rule");
    expect(findings[0].severity).toBe("low");
    expect(findings[0].subjectRef).toBe("firewall_rule:3");
    expect(findings[0].detail.ruleIds).toEqual([3, 9]);
  });

  it("normalizes id order and app/mac case before comparing", () => {
    const a = rule({ id: 1, position: 10, applicationIds: ["YouTube"], srcMacs: ["AA:BB:CC:DD:EE:FF"], srcAddrIds: [1, 2] });
    const b = rule({ id: 2, position: 20, applicationIds: ["youtube"], srcMacs: ["aa:bb:cc:dd:ee:ff"], srcAddrIds: [2, 1] });
    expect(detectDuplicates([a, b])).toHaveLength(1);
  });

  it("does not flag rules that differ in any normalized field", () => {
    const base = { id: 1, position: 10, srcZoneIds: [LAN_ZONE_A] };
    const variants = [
      { ...base, action: "deny" },
      { ...base, logging: "detail" },
      { ...base, srcZoneIds: [LAN_ZONE_B] },
      { ...base, serviceIds: [5] },
      { ...base, scheduleId: 3 },
      { ...base, family: "ipv6" },
    ];
    for (const variant of variants) {
      const b = rule({ ...variant, id: 2, position: 20 });
      expect(detectDuplicates([rule(base), b])).toHaveLength(0);
    }
  });

  it("ignores disabled duplicates", () => {
    const a = rule({ id: 1, position: 10 });
    const b = rule({ id: 2, position: 20, enabled: false });
    expect(detectDuplicates([a, b])).toHaveLength(0);
  });
});

describe("detectUnusedObjects", () => {
  const orphanAddr: AnomalyObjectRef = { kind: "address", id: 31, name: "orphan-addr" };
  const usedAddr: AnomalyObjectRef = { kind: "address", id: 32, name: "used-addr" };
  const orphanSvc: AnomalyObjectRef = { kind: "service", id: 71, name: "orphan-svc" };
  const addrGroup: AnomalyObjectRef = { kind: "address_group", id: 91, name: "g", memberIds: [31, 32] };

  it("flags address/service objects referenced by zero enabled rules", () => {
    const findings = detectUnusedObjects([], [orphanAddr, orphanSvc]);
    expect(findings.map((f) => f.subjectRef)).toEqual(["address_object:31", "service_object:71"]);
    expect(findings.every((f) => f.severity === "low" && f.detail.ruleIds.length === 0)).toBe(true);
  });

  it("does not flag objects referenced from enabled rules (src or dst or service)", () => {
    const r = rule({ srcAddrIds: [32], dstAddrIds: [31], serviceIds: [71] });
    expect(detectUnusedObjects([r], [orphanAddr, usedAddr, orphanSvc])).toHaveLength(0);
  });

  it("expands groups: members of a referenced group count as used; groups are never flagged", () => {
    const r = rule({ srcAddrIds: [91] }); // references the GROUP, not member 31 directly
    const findings = detectUnusedObjects([r], [orphanAddr, usedAddr, addrGroup]);
    expect(findings).toHaveLength(0); // member 31 used via group 91; group 91 itself not flagged
    // an unreferenced group does not mark its members used
    const findings2 = detectUnusedObjects([], [orphanAddr, addrGroup]);
    expect(findings2.map((f) => f.subjectRef)).toEqual(["address_object:31"]);
  });

  it("does not count references from disabled rules", () => {
    const r = rule({ srcAddrIds: [31], enabled: false });
    expect(detectUnusedObjects([r], [orphanAddr])).toHaveLength(1);
  });
});

describe("port permissiveness primitives", () => {
  it("parses the dstPort grammar", () => {
    expect(parseDstPortRanges(null)).toEqual([]);
    expect(parseDstPortRanges("any")).toEqual([]);
    expect(parseDstPortRanges("80")).toEqual([{ lo: 80, hi: 80 }]);
    expect(parseDstPortRanges("5000-5100,6000")).toEqual([
      { lo: 5000, hi: 5100 },
      { lo: 6000, hi: 6000 },
    ]);
  });

  it("decides full port-span coverage", () => {
    expect(coversAllPorts([{ lo: 0, hi: 65_535 }])).toBe(true);
    expect(coversAllPorts([{ lo: 1, hi: 65_535 }])).toBe(true);
    expect(
      coversAllPorts([
        { lo: 1, hi: 32_768 },
        { lo: 32_769, hi: 65_535 },
      ]),
    ).toBe(true);
    expect(coversAllPorts([{ lo: 80, hi: 80 }])).toBe(false);
    expect(
      coversAllPorts([
        { lo: 1, hi: 100 },
        { lo: 200, hi: 65_535 },
      ]),
    ).toBe(false);
  });

  it("classifies services: any-protocol or all-port tcp/udp are permissive, icmp/scoped are not", () => {
    expect(serviceIsPermissive({ protocol: "any", dstPort: null })).toBe(true);
    expect(serviceIsPermissive({ protocol: "tcp", dstPort: "0-65535" })).toBe(true);
    expect(serviceIsPermissive({ protocol: "udp", dstPort: "1-65535" })).toBe(true);
    expect(serviceIsPermissive({ protocol: "tcp", dstPort: "any" })).toBe(true);
    expect(serviceIsPermissive({ protocol: "tcp", dstPort: "443" })).toBe(false);
    expect(serviceIsPermissive({ protocol: "icmp", dstPort: null })).toBe(false);
  });
});

describe("KIND_SEVERITY (locked §4.5 map)", () => {
  it("maps every kind to its locked severity", () => {
    expect(KIND_SEVERITY).toEqual({
      any_any_rule: "high",
      wan_permissive: "medium",
      shadowed_rule: "medium",
      log_disabled: "low",
      duplicate_rule: "low",
      unused_object: "low",
    });
  });
});

// ═══════════════════════════════ DB-BACKED SERVICE ══════════════════════════

/** Create a firewall rule row (JSON id-array columns as raw strings). */
async function seedRule(data: {
  name: string;
  position: number;
  action?: string;
  logging?: string;
  enabled?: boolean;
  srcZoneIds?: number[];
  dstZoneIds?: number[];
  srcAddrIds?: number[];
  dstAddrIds?: number[];
  serviceIds?: number[];
}): Promise<{ id: number }> {
  return db.firewallRule.create({
    data: {
      name: data.name,
      position: data.position,
      enabled: data.enabled ?? true,
      action: data.action ?? "allow",
      logging: data.logging ?? "summary",
      srcZoneIds: JSON.stringify(data.srcZoneIds ?? []),
      dstZoneIds: JSON.stringify(data.dstZoneIds ?? []),
      srcAddrIds: JSON.stringify(data.srcAddrIds ?? []),
      dstAddrIds: JSON.stringify(data.dstAddrIds ?? []),
      serviceIds: JSON.stringify(data.serviceIds ?? []),
    },
    select: { id: true },
  });
}

/** The dirty-config fixture: any-any allow + exact duplicate pair + unused objects. */
async function seedDirtyConfig() {
  const usedAddr = await db.addressObject.create({ data: { name: "ca-used-addr", type: "ip", value: "10.77.0.1" }, select: { id: true } });
  const orphanAddr = await db.addressObject.create({ data: { name: "ca-orphan-addr", type: "ip", value: "10.77.0.9" }, select: { id: true } });
  const orphanSvc = await db.serviceObject.create({ data: { name: "ca-orphan-svc", protocol: "tcp", dstPort: "8080" }, select: { id: true } });

  const dupA = await seedRule({
    name: "CA dup A",
    position: 10,
    srcZoneIds: [WAN_ZONE],
    dstZoneIds: [LAN_ZONE_A],
    srcAddrIds: [usedAddr.id],
  });
  const dupB = await seedRule({
    name: "CA dup B",
    position: 11,
    srcZoneIds: [WAN_ZONE],
    dstZoneIds: [LAN_ZONE_A],
    srcAddrIds: [usedAddr.id],
  });
  const anyAny = await seedRule({ name: "CA any-any", position: 100, logging: "detail" });
  return { usedAddrId: usedAddr.id, orphanAddrId: orphanAddr.id, orphanSvcId: orphanSvc.id, dupAId: dupA.id, dupBId: dupB.id, anyAnyId: anyAny.id };
}

describe("scanConfigAnomalies (DB-backed)", () => {
  it("creates the expected finding set for a dirty config", async () => {
    const ids = await seedDirtyConfig();
    const summary = await service.scanConfigAnomalies(1, { wanZoneIds: [WAN_ZONE] });

    expect(summary.detected).toBe(5);
    expect(summary.newOpen).toBe(5);
    expect(summary.autoResolved).toBe(0);
    expect(summary.byKind).toEqual({
      any_any_rule: 1,
      wan_permissive: 0,
      unused_object: 2,
      shadowed_rule: 1,
      log_disabled: 0,
      duplicate_rule: 1,
    });

    const rows = await db.configAnomalyFinding.findMany({ where: { tenantId: 1 } });
    expect(rows).toHaveLength(5);
    expect(rows.every((r) => r.status === "open" && r.resolvedAt === null)).toBe(true);

    const byKind = (kind: string) => rows.filter((r) => r.kind === kind);
    expect(byKind("any_any_rule").map((r) => r.subjectRef)).toEqual([`firewall_rule:${ids.anyAnyId}`]);
    expect(byKind("duplicate_rule").map((r) => JSON.parse(r.detail).ruleIds).flat().sort((a, b) => a - b)).toEqual([ids.dupAId, ids.dupBId]);
    expect(byKind("duplicate_rule")[0].subjectRef).toBe(`firewall_rule:${Math.min(ids.dupAId, ids.dupBId)}`);
    // the later duplicate is unreachable behind the earlier identical rule
    expect(byKind("shadowed_rule").map((r) => r.subjectRef)).toEqual([`firewall_rule:${ids.dupBId}`]);
    expect(JSON.parse(byKind("shadowed_rule")[0].detail).ruleIds).toEqual([ids.dupBId, ids.dupAId]);
    expect(byKind("unused_object").map((r) => r.subjectRef).sort()).toEqual([
      `address_object:${ids.orphanAddrId}`,
      `service_object:${ids.orphanSvcId}`,
    ]);
    // the referenced address object is NOT flagged unused
    expect(rows.some((r) => r.subjectRef === `address_object:${ids.usedAddrId}`)).toBe(false);
  });

  it("does not create duplicates on a second scan (open rows refresh in place)", async () => {
    await seedDirtyConfig();
    const first = await service.scanConfigAnomalies(1, { wanZoneIds: [WAN_ZONE] });
    const idsBefore = (await db.configAnomalyFinding.findMany({ where: { tenantId: 1 }, select: { id: true } })).map((r) => r.id).sort();

    const second = await service.scanConfigAnomalies(1, { wanZoneIds: [WAN_ZONE] });
    expect(second.detected).toBe(first.detected);
    expect(second.newOpen).toBe(0);
    expect(second.autoResolved).toBe(0);

    const idsAfter = (await db.configAnomalyFinding.findMany({ where: { tenantId: 1 }, select: { id: true } })).map((r) => r.id).sort();
    expect(idsAfter).toEqual(idsBefore);
  });

  it("does not resurrect manually resolved findings on later scans (triage suppression window)", async () => {
    await seedDirtyConfig();
    await service.scanConfigAnomalies(1, { wanZoneIds: [WAN_ZONE] });
    const open = await db.configAnomalyFinding.findMany({ where: { tenantId: 1, status: "open" } });
    expect(open.length).toBeGreaterThan(0);

    // resolve every finding through the triage path (stamps resolvedAt)
    for (const row of open) {
      await service.updateFindingStatus(1, row.id, "resolved");
    }
    const resolvedBefore = await db.configAnomalyFinding.findMany({ where: { tenantId: 1 } });
    expect(resolvedBefore.every((r) => r.status === "resolved" && r.resolvedAt !== null)).toBe(true);

    const summary = await service.scanConfigAnomalies(1, { wanZoneIds: [WAN_ZONE] });
    expect(summary.detected).toBe(5);
    expect(summary.newOpen).toBe(0); // still detected, but triaged subjects stay suppressed

    const after = await db.configAnomalyFinding.findMany({ where: { tenantId: 1 } });
    expect(after).toHaveLength(resolvedBefore.length);
    expect(after.every((r) => r.status === "resolved")).toBe(true);
    // resolved rows were not touched by the scan (no re-open, no auto-resolve churn)
    const beforeById = new Map(resolvedBefore.map((r) => [r.id, r]));
    for (const row of after) {
      expect(row.resolvedAt?.getTime()).toBe(beforeById.get(row.id)?.resolvedAt?.getTime());
    }
  });

  it("auto-resolves open findings the config no longer produces", async () => {
    const anyAny = await seedRule({ name: "CA any-any", position: 100, logging: "detail" });
    await service.scanConfigAnomalies(1, { wanZoneIds: [WAN_ZONE] });
    const before = await db.configAnomalyFinding.findFirst({ where: { tenantId: 1, kind: "any_any_rule" } });
    expect(before?.status).toBe("open");

    await db.firewallRule.delete({ where: { id: anyAny.id } }); // config moved on
    const summary = await service.scanConfigAnomalies(1, { wanZoneIds: [WAN_ZONE] });
    expect(summary.autoResolved).toBe(1);
    expect(summary.newOpen).toBe(0);

    const after = await db.configAnomalyFinding.findFirst({ where: { tenantId: 1, kind: "any_any_rule" } });
    expect(after?.status).toBe("resolved");
    expect(after?.resolvedAt).not.toBeNull();
    expect(after?.id).toBe(before?.id);
  });

  it("creates wan_permissive + log_disabled findings and honors requireWanLogging on rescan", async () => {
    const wanOpen = await seedRule({ name: "CA wan-open", position: 20, srcZoneIds: [WAN_ZONE], logging: "none" });
    const lanLan = await seedRule({ name: "CA lan-lan", position: 21, srcZoneIds: [LAN_ZONE_A], dstZoneIds: [LAN_ZONE_B], logging: "none" });

    const summary = await service.scanConfigAnomalies(1, { wanZoneIds: [WAN_ZONE] });
    expect(summary.byKind.wan_permissive).toBe(1);
    expect(summary.byKind.log_disabled).toBe(1);
    expect(summary.byKind.any_any_rule).toBe(0); // WAN-open has a scoped src → no any-any flag
    expect(summary.byKind.shadowed_rule).toBe(0); // WAN-open does not cover the LAN pair's scopes

    const rows = await db.configAnomalyFinding.findMany({ where: { tenantId: 1 } });
    const wanRows = rows.filter((r) => r.subjectRef === `firewall_rule:${wanOpen.id}`);
    expect(wanRows.map((r) => r.kind).sort()).toEqual(["log_disabled", "wan_permissive"]);
    expect(rows.some((r) => r.subjectRef === `firewall_rule:${lanLan.id}`)).toBe(false);

    // logging requirement off → the log_disabled finding is no longer produced → auto-resolved
    const summary2 = await service.scanConfigAnomalies(1, { wanZoneIds: [WAN_ZONE], requireWanLogging: false });
    expect(summary2.byKind.log_disabled).toBe(0);
    expect(summary2.autoResolved).toBe(1);
    const logRow = await db.configAnomalyFinding.findFirst({ where: { tenantId: 1, kind: "log_disabled" } });
    expect(logRow?.status).toBe("resolved");
    expect(logRow?.resolvedAt).not.toBeNull();
  });

  it("triage only accepts resolved|ignored and keeps resolvedAt consistent with status", async () => {
    await seedRule({ name: "CA any-any", position: 100, logging: "detail" });
    await service.scanConfigAnomalies(1, { wanZoneIds: [WAN_ZONE] });
    const finding = await db.configAnomalyFinding.findFirstOrThrow({ where: { tenantId: 1 } });

    // `open` is not a triage verb; unknown ids 404
    await expect(service.updateFindingStatus(1, finding.id, "open")).rejects.toThrow(/resolved \| ignored/);
    await expect(service.updateFindingStatus(1, 999999, "resolved")).rejects.toThrow(/not found/i);

    const ignored = await service.updateFindingStatus(1, finding.id, "ignored");
    expect(ignored.status).toBe("ignored");
    expect(ignored.resolvedAt).toBeNull();

    const resolved = await service.updateFindingStatus(1, finding.id, "resolved");
    expect(resolved.status).toBe("resolved");
    expect(resolved.resolvedAt).not.toBeNull();
  });

  it("lists findings paginated with kind/severity/status filters and reports stats", async () => {
    const wanOpen = await seedRule({ name: "CA wan-open", position: 20, srcZoneIds: [WAN_ZONE], logging: "none" });
    await seedRule({ name: "CA lan-lan", position: 21, srcZoneIds: [LAN_ZONE_A], dstZoneIds: [LAN_ZONE_B], logging: "none" });
    await service.scanConfigAnomalies(1, { wanZoneIds: [WAN_ZONE] });

    const openPage = await service.listFindings(1, { status: "open", page: 1, limit: 1 });
    expect(openPage.data).toHaveLength(1);
    expect(openPage.meta.total).toBe(2);
    expect(openPage.meta.totalPages).toBe(2);

    const byKind = await service.listFindings(1, { kind: "wan_permissive" });
    expect(byKind.data).toHaveLength(1);
    expect(byKind.data[0].subjectRef).toBe(`firewall_rule:${wanOpen.id}`);
    expect(byKind.data[0].detail.message).toContain(wanOpen.id);

    const bySeverity = await service.listFindings(1, { severity: "medium" });
    expect(bySeverity.data).toHaveLength(1);

    const stats = await service.statsFindings(1);
    expect(stats.openTotal).toBe(2);
    expect(stats.openByKind.wan_permissive).toBe(1);
    expect(stats.openByKind.log_disabled).toBe(1);
    expect(stats.openBySeverity.low).toBe(1);
    expect(stats.openBySeverity.medium).toBe(1);
    expect(stats.openBySeverity.high).toBe(0);
    expect(stats.total).toBe(2);
    expect(stats.lastScanAt).not.toBeNull();
  });
});
