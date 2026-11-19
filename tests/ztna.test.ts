/**
 * ZTNA tests (Phase 4 §4.4) — vitest.
 *
 * Part 1 exercises the PURE engine (no db): the evaluatePosture verdict
 * matrix (pass / fail / missing→unknown / no-requirements→vacuously
 * compliant) and the decideAccess precedence rules (deny wins over allow,
 * specificity device > user > group, deterministic id tie-break, disabled
 * policies ignored, posture gating fail-closed incl. unknown, no-match
 * default deny).
 *
 * Part 2 runs the service against a per-run copy of the pushed dev schema
 * (same copy-db harness as tests/incidents.test.ts — the ztna modules are
 * imported AFTER the DATABASE_URL override because static imports would
 * resolve the Prisma datasource too early): apps/policies/profiles CRUD with
 * reference + uniqueness guards, recordPostureCheck verdict persistence
 * (verdict column, results JSON, nextCheckAt = checkedAt + 60min),
 * continuous validation re-checks (due rows only, verdict flips when the
 * requirement set changes) and the evaluate paths (allow + deny) that back
 * POST /api/v1/ztna/evaluate (the route itself is a thin wrapper — service
 * style per tests/incidents.test.ts).
 */

import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// pure engine — no db dependency, safe to import statically
import {
  decideAccess,
  evaluatePosture,
  type AccessPolicyInput,
  type PostureResults,
} from "@/lib/ztna/engine";

const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "ztna-"));
const DB_PATH = path.join(TMP_DIR, "ztna-test.db");
fs.copyFileSync(path.resolve(process.cwd(), "db/cryptsk.db"), DB_PATH);
process.env.DATABASE_URL = `file:${DB_PATH}`;

const { db } = await import("@/lib/db");
const service = await import("@/lib/ztna/service");

beforeAll(async () => {
  // the copied dev schema has no tenant rows — ztna rows FK to tenants
  await db.tenant.upsert({ where: { id: 1 }, update: {}, create: { id: 1, name: "ztna-test" } });
});

beforeEach(async () => {
  await db.devicePostureCheck.deleteMany({});
  await db.ztnaAccessPolicy.deleteMany({});
  await db.postureProfile.deleteMany({});
  await db.ztnaApplication.deleteMany({});
  // only artifacts this suite creates — seeded audit rows stay untouched
  await db.auditLog.deleteMany({ where: { action: { startsWith: "ztna." } } });
});

afterAll(async () => {
  await db.$disconnect();
  fs.rmSync(TMP_DIR, { recursive: true, force: true });
});

// ════════════════════════════════════════════════════════════════════════════
// Part 1 — pure engine
// ════════════════════════════════════════════════════════════════════════════

describe("evaluatePosture verdict matrix", () => {
  const STRICT = { osPatchMaxAgeDays: 30, avRequired: true, diskEncryptRequired: true, firewallRequired: true };

  it("compliant when every required check passed", () => {
    const results: PostureResults = { osPatch: "pass", av: "pass", diskEncrypt: "pass", firewall: "pass" };
    expect(evaluatePosture(STRICT, results)).toEqual({ verdict: "compliant", failedChecks: [], unknownChecks: [] });
  });

  it("unknown when a required check has NO result (fail-closed, never implicit pass)", () => {
    const ev = evaluatePosture(STRICT, { osPatch: "pass" });
    expect(ev.verdict).toBe("unknown");
    expect(ev.failedChecks).toEqual([]);
    expect(ev.unknownChecks).toEqual(["av", "diskEncrypt", "firewall"]);
  });

  it("unknown when a required check result is explicitly 'unknown'", () => {
    const ev = evaluatePosture({ avRequired: true }, { av: "unknown" });
    expect(ev.verdict).toBe("unknown");
    expect(ev.unknownChecks).toEqual(["av"]);
  });

  it("non_compliant on any failed check, listing failed + still-unknown keys", () => {
    const ev = evaluatePosture(STRICT, { osPatch: "pass", av: "fail" });
    expect(ev.verdict).toBe("non_compliant");
    expect(ev.failedChecks).toEqual(["av"]);
    expect(ev.unknownChecks).toEqual(["diskEncrypt", "firewall"]);
  });

  it("fail outranks unknown; multiple fails are all listed", () => {
    const ev = evaluatePosture(STRICT, { osPatch: "fail", av: "fail", diskEncrypt: "pass" });
    expect(ev.verdict).toBe("non_compliant");
    expect(ev.failedChecks).toEqual(["osPatch", "av"]);
    expect(ev.unknownChecks).toEqual(["firewall"]);
  });

  it("a profile that requires nothing is vacuously compliant (extra results ignored)", () => {
    expect(evaluatePosture({}, { av: "fail" }).verdict).toBe("compliant");
    expect(evaluatePosture({ osPatchMaxAgeDays: 0, avRequired: false }, { osPatch: "fail" }).verdict).toBe("compliant");
  });

  it("unrecognized result values count as unknown", () => {
    const ev = evaluatePosture({ avRequired: true }, { av: "bogus" as unknown as PostureResults["av"] });
    expect(ev.verdict).toBe("unknown");
    expect(ev.unknownChecks).toEqual(["av"]);
  });

  it("osPatch becomes required only for a positive day ceiling", () => {
    expect(evaluatePosture({ osPatchMaxAgeDays: 30 }, {}).unknownChecks).toEqual(["osPatch"]);
    expect(evaluatePosture({ osPatchMaxAgeDays: 0 }, {}).verdict).toBe("compliant");
    expect(evaluatePosture({ osPatchMaxAgeDays: -5 }, {}).verdict).toBe("compliant");
  });
});

// ── decideAccess fixtures ────────────────────────────────────────────────────

let nextPolicyId = 1;
function policy(over: Partial<AccessPolicyInput>): AccessPolicyInput {
  return {
    id: nextPolicyId++,
    appId: 1,
    subjectType: "user",
    subjectRef: "alice",
    action: "allow",
    postureProfileId: null,
    enabled: true,
    ...over,
  };
}

const DEV = "aa:bb:cc:dd:ee:ff";
const ALICE = { user: "alice", groups: ["engineering"], deviceId: DEV };

describe("decideAccess precedence", () => {
  it("denies by default when nothing matches (zero trust)", () => {
    const d = decideAccess({ policies: [], subject: ALICE, app: { id: 1 }, postureVerdict: "compliant" });
    expect(d.decision).toBe("deny");
    expect(d.matchedPolicyId).toBeNull();
    expect(d.reason).toMatch(/default deny/i);
  });

  it("ignores disabled policies", () => {
    const d = decideAccess({
      policies: [policy({ enabled: false })],
      subject: ALICE,
      app: { id: 1 },
      postureVerdict: "compliant",
    });
    expect(d.decision).toBe("deny");
    expect(d.matchedPolicyId).toBeNull();
  });

  it("deny wins over allow regardless of subject specificity", () => {
    const allowDevice = policy({ action: "allow", subjectType: "device", subjectRef: DEV, id: 10 });
    const denyUser = policy({ action: "deny", subjectType: "user", subjectRef: "alice", id: 11 });
    const d = decideAccess({ policies: [allowDevice, denyUser], subject: ALICE, app: { id: 1 }, postureVerdict: "compliant" });
    expect(d.decision).toBe("deny");
    expect(d.matchedPolicyId).toBe(11);
  });

  it("most specific subject wins at equal action: device > user > group", () => {
    const group = policy({ action: "allow", subjectType: "group", subjectRef: "engineering", id: 20 });
    const user = policy({ action: "allow", subjectType: "user", subjectRef: "alice", id: 21 });
    const device = policy({ action: "allow", subjectType: "device", subjectRef: DEV, id: 22 });
    const d = decideAccess({ policies: [group, user, device], subject: ALICE, app: { id: 1 }, postureVerdict: "compliant" });
    expect(d.decision).toBe("allow");
    expect(d.matchedPolicyId).toBe(22);

    const d2 = decideAccess({ policies: [group, user], subject: ALICE, app: { id: 1 }, postureVerdict: "compliant" });
    expect(d2.matchedPolicyId).toBe(21);
  });

  it("breaks same-subjectType ties deterministically on the lowest policy id", () => {
    const later = policy({ id: 40 });
    const earlier = policy({ id: 39 });
    const d = decideAccess({ policies: [later, earlier], subject: ALICE, app: { id: 1 }, postureVerdict: "compliant" });
    expect(d.matchedPolicyId).toBe(39);
  });

  it("never matches policies scoped to another application", () => {
    const d = decideAccess({ policies: [policy({ appId: 2 })], subject: ALICE, app: { id: 1 }, postureVerdict: "compliant" });
    expect(d.matchedPolicyId).toBeNull();
  });

  it("matches each subject kind only on its own subjectType/ref", () => {
    const dGroup = decideAccess({ policies: [policy({ subjectType: "group", subjectRef: "engineering" })], subject: ALICE, app: { id: 1 }, postureVerdict: "compliant" });
    expect(dGroup.decision).toBe("allow");
    // group policy does not match on the username
    const dUserOnly = decideAccess({ policies: [policy({ subjectType: "group", subjectRef: "engineering" })], subject: { user: "alice", groups: [] }, app: { id: 1 }, postureVerdict: "compliant" });
    expect(dUserOnly.matchedPolicyId).toBeNull();
    // device policy needs the deviceId present
    const dNoDevice = decideAccess({ policies: [policy({ subjectType: "device", subjectRef: "aa:bb:cc:dd:ee:ff" })], subject: { user: "alice" }, app: { id: 1 }, postureVerdict: "compliant" });
    expect(dNoDevice.matchedPolicyId).toBeNull();
  });

  // ── posture gating ──
  it("posture non_compliant denies a gated allow policy (fail-closed)", () => {
    const gated = policy({ postureProfileId: 7, id: 50 });
    const d = decideAccess({ policies: [gated], subject: ALICE, app: { id: 1 }, postureVerdict: "non_compliant" });
    expect(d.decision).toBe("deny");
    expect(d.matchedPolicyId).toBe(50);
    expect(d.reason).toMatch(/non_compliant/);
  });

  it("posture unknown also denies a gated allow policy", () => {
    const d = decideAccess({ policies: [policy({ postureProfileId: 7 })], subject: ALICE, app: { id: 1 }, postureVerdict: "unknown" });
    expect(d.decision).toBe("deny");
    expect(d.reason).toMatch(/unknown/);
  });

  it("compliant posture lets the gated allow through", () => {
    const d = decideAccess({ policies: [policy({ postureProfileId: 7 })], subject: ALICE, app: { id: 1 }, postureVerdict: "compliant" });
    expect(d.decision).toBe("allow");
    expect(d.reason).toMatch(/compliant/);
  });

  it("posture non_compliant does NOT block an allow policy without an attached profile", () => {
    const ungated = policy({ postureProfileId: null, id: 60 });
    const gated = policy({ postureProfileId: 7, id: 61 });
    const d = decideAccess({ policies: [ungated, gated], subject: ALICE, app: { id: 1 }, postureVerdict: "non_compliant" });
    expect(d.decision).toBe("allow");
    expect(d.matchedPolicyId).toBe(60);
  });

  it("deny policies still apply when posture is non-compliant (posture never unlocks)", () => {
    const denyUser = policy({ action: "deny", id: 70 });
    const gatedAllow = policy({ postureProfileId: 7, id: 71 });
    const d = decideAccess({ policies: [denyUser, gatedAllow], subject: ALICE, app: { id: 1 }, postureVerdict: "non_compliant" });
    expect(d.decision).toBe("deny");
    expect(d.matchedPolicyId).toBe(70);
    expect(d.reason).not.toMatch(/non_compliant/); // plain subject deny
  });
});

// ════════════════════════════════════════════════════════════════════════════
// Part 2 — DB-backed service (copy-db harness)
// ════════════════════════════════════════════════════════════════════════════

describe("apps CRUD", () => {
  it("creates, lists with policy counts, enforces per-tenant unique names", async () => {
    const app = await service.createApp(1, { name: "intranet-wiki", host: "wiki.corp.internal", port: 8443, protocol: "tcp", group: "engineering" });
    expect(app.id).toBeGreaterThan(0);
    expect(app.policyCount).toBe(0);
    await expect(service.createApp(1, { name: "intranet-wiki", host: "x", port: 443, protocol: "tcp", group: "" })).rejects.toThrow(/already exists/);

    await service.createPolicy(1, { appId: app.id, subjectRef: "alice" });
    const listed = await service.listApps(1);
    expect(listed.find((a) => a.id === app.id)?.policyCount).toBe(1);
  });

  it("updates, refuses deletes while policies reference the app, then deletes", async () => {
    const app = await service.createApp(1, { name: "erp", host: "erp.corp.internal", port: 443, protocol: "tcp", group: "" });
    const updated = await service.updateApp(1, app.id, { name: "erp2", port: 9443 });
    expect(updated.name).toBe("erp2");
    expect(updated.port).toBe(9443);

    const policyRow = await service.createPolicy(1, { appId: app.id, subjectRef: "ops-team", subjectType: "group" });
    await expect(service.deleteApp(1, app.id)).rejects.toThrow(/polic/);

    await service.deletePolicy(1, policyRow.id);
    await service.deleteApp(1, app.id);
    expect(await db.ztnaApplication.findFirst({ where: { id: app.id } })).toBeNull();
  });

  it("404s on unknown app reads", async () => {
    await expect(service.getApp(1, 999999)).rejects.toThrow(/not found/i);
  });
});

describe("policies CRUD", () => {
  it("validates appId and postureProfileId existence", async () => {
    await expect(service.createPolicy(1, { appId: 424242, subjectRef: "alice" })).rejects.toThrow(/Unknown ZTNA application/);
    const app = await service.createApp(1, { name: "crm", host: "crm.corp.internal" });
    await expect(service.createPolicy(1, { appId: app.id, subjectRef: "alice", postureProfileId: 987654 })).rejects.toThrow(/Unknown posture profile/);
  });

  it("creates with defaults, lists filtered by appId, updates and deletes", async () => {
    const appA = await service.createApp(1, { name: "app-a", host: "a.corp.internal" });
    const appB = await service.createApp(1, { name: "app-b", host: "b.corp.internal" });
    const profile = await service.createPostureProfile(1, { name: "laptop", checks: { avRequired: true } });

    const p1 = await service.createPolicy(1, { appId: appA.id, subjectRef: "alice" });
    expect(p1.subjectType).toBe("user");
    expect(p1.action).toBe("allow");
    expect(p1.enabled).toBe(true);
    expect(p1.appName).toBe("app-a");
    expect(p1.postureProfileId).toBeNull();

    const p2 = await service.createPolicy(1, { appId: appB.id, subjectType: "group", subjectRef: "engineering", action: "deny", postureProfileId: profile.id, schedule: "Mon-Fri 09:00-17:00" });
    expect(p2.postureProfileName).toBe("laptop");

    const onlyA = await service.listPolicies(1, { appId: appA.id });
    expect(onlyA.map((p) => p.id)).toEqual([p1.id]);
    expect((await service.listPolicies(1, {})).length).toBe(2);

    const toggled = await service.updatePolicy(1, p1.id, { enabled: false });
    expect(toggled.enabled).toBe(false);
    expect((await service.listPolicies(1, {})).find((p) => p.id === p1.id)?.enabled).toBe(false);

    await service.deletePolicy(1, p2.id);
    expect(await service.listPolicies(1, {})).toHaveLength(1);
    await expect(service.deletePolicy(1, p2.id)).rejects.toThrow(/not found/i);
  });
});

describe("posture profiles CRUD", () => {
  it("stores the checks JSON, enforces unique names, refuses deletes while attached", async () => {
    const profile = await service.createPostureProfile(1, { name: "corporate-laptop", checks: { osPatchMaxAgeDays: 30, avRequired: true, diskEncryptRequired: true } });
    expect(profile.checks).toEqual({ osPatchMaxAgeDays: 30, avRequired: true, diskEncryptRequired: true });
    await expect(service.createPostureProfile(1, { name: "corporate-laptop" })).rejects.toThrow(/already exists/);

    const updated = await service.updatePostureProfile(1, profile.id, { checks: { firewallRequired: true } });
    expect(updated.checks).toEqual({ firewallRequired: true });

    const app = await service.createApp(1, { name: "wiki", host: "wiki.corp.internal" });
    await service.createPolicy(1, { appId: app.id, subjectRef: "alice", postureProfileId: profile.id });
    await expect(service.deletePostureProfile(1, profile.id)).rejects.toThrow(/attached/);
  });
});

describe("recordPostureCheck — verdict persistence", () => {
  it("persists verdict, results JSON and nextCheckAt = checkedAt + 60min (compliant)", async () => {
    const profile = await service.createPostureProfile(1, { name: "strict", checks: { osPatchMaxAgeDays: 30, avRequired: true, diskEncryptRequired: true, firewallRequired: true } });
    const check = await service.recordPostureCheck(1, {
      deviceId: "aa:bb:cc:dd:ee:01",
      profileId: profile.id,
      results: { osPatch: "pass", av: "pass", diskEncrypt: "pass", firewall: "pass" },
    });
    expect(check.verdict).toBe("compliant");
    expect(check.failedChecks).toEqual([]);
    expect(check.profileName).toBe("strict");

    const row = await db.devicePostureCheck.findUniqueOrThrow({ where: { id: check.id } });
    expect(row.verdict).toBe("compliant");
    expect(JSON.parse(row.results)).toEqual({ osPatch: "pass", av: "pass", diskEncrypt: "pass", firewall: "pass" });
    const horizonMs = row.nextCheckAt!.getTime() - row.checkedAt.getTime();
    expect(Math.abs(horizonMs - 60 * 60 * 1000)).toBeLessThan(2000);
  });

  it("non_compliant with failed checks inline; unknown when a required check is missing", async () => {
    const profile = await service.createPostureProfile(1, { name: "strict2", checks: { osPatchMaxAgeDays: 30, avRequired: true, diskEncryptRequired: true } });
    const bad = await service.recordPostureCheck(1, { deviceId: "d-bad", profileId: profile.id, results: { osPatch: "pass", av: "fail" } });
    expect(bad.verdict).toBe("non_compliant");
    expect(bad.failedChecks).toEqual(["av"]);
    expect(bad.unknownChecks).toEqual(["diskEncrypt"]);

    const partial = await service.recordPostureCheck(1, { deviceId: "d-partial", profileId: profile.id, results: { osPatch: "pass" } });
    expect(partial.verdict).toBe("unknown");
    expect(partial.unknownChecks.sort()).toEqual(["av", "diskEncrypt"]);
  });

  it("rejects unknown check keys and unknown profiles", async () => {
    const profile = await service.createPostureProfile(1, { name: "p-check", checks: { avRequired: true } });
    await expect(
      service.recordPostureCheck(1, { deviceId: "d", profileId: profile.id, results: { cpuOverheat: "pass" } }),
    ).rejects.toThrow(/Unknown posture check key/);
    await expect(service.recordPostureCheck(1, { deviceId: "d", profileId: 999999, results: {} })).rejects.toThrow(/not found/i);
  });
});

describe("latest-per-device listing", () => {
  it("returns only the latest check per device, newest first, with page meta", async () => {
    const profile = await service.createPostureProfile(1, { name: "latest", checks: { avRequired: true } });
    await service.recordPostureCheck(1, { deviceId: "dev-1", profileId: profile.id, results: { av: "fail" } });
    await service.recordPostureCheck(1, { deviceId: "dev-1", profileId: profile.id, results: { av: "pass" } });
    await service.recordPostureCheck(1, { deviceId: "dev-2", profileId: profile.id, results: { av: "pass" } });

    const page1 = await service.listLatestPostureChecks(1, { page: 1, limit: 1 });
    expect(page1.meta.total).toBe(2);
    expect(page1.meta.totalPages).toBe(2);
    expect(page1.data).toHaveLength(1);
    expect(page1.data[0].deviceId).toBe("dev-2");
    expect(page1.data[0].verdict).toBe("compliant");

    const page2 = await service.listLatestPostureChecks(1, { page: 2, limit: 1 });
    expect(page2.data[0].deviceId).toBe("dev-1");
    expect(page2.data[0].verdict).toBe("compliant"); // latest pass overwrote the earlier fail

    const scoped = await service.listLatestPostureChecks(1, { page: 1, limit: 25, deviceId: "dev-1" });
    expect(scoped.data).toHaveLength(1);
    expect(scoped.meta.total).toBe(1);
  });
});

describe("runContinuousValidation — periodic re-check", () => {
  it("re-evaluates only due latest rows, replays stored raw results, flips when requirements change", async () => {
    const profile = await service.createPostureProfile(1, { name: "cv", checks: { avRequired: true } });
    const check = await service.recordPostureCheck(1, { deviceId: "cv-dev", profileId: profile.id, results: { av: "pass" } });

    // nothing due yet (nextCheckAt is 60min ahead)
    expect(await service.runContinuousValidation(1)).toEqual({ rechecked: 0, changed: 0, results: [] });

    // force the re-check window to elapse
    await db.devicePostureCheck.update({ where: { id: check.id }, data: { nextCheckAt: new Date(Date.now() - 1000) } });
    const run1 = await service.runContinuousValidation(1);
    expect(run1.rechecked).toBe(1);
    expect(run1.changed).toBe(0);
    expect(run1.results[0]).toMatchObject({ deviceId: "cv-dev", profileId: profile.id, previousVerdict: "compliant", verdict: "compliant", changed: false });

    // a fresh row was persisted with a forward horizon → immediate re-run is a no-op
    const rows = await db.devicePostureCheck.findMany({ where: { tenantId: 1, deviceId: "cv-dev" }, orderBy: { id: "asc" } });
    expect(rows).toHaveLength(2);
    expect(rows[1].checkedAt.getTime()).toBeGreaterThanOrEqual(rows[0].checkedAt.getTime());
    expect(await service.runContinuousValidation(1)).toEqual({ rechecked: 0, changed: 0, results: [] });

    // tighten the requirements: stored results lack diskEncrypt → verdict flips
    await service.updatePostureProfile(1, profile.id, { checks: { avRequired: true, diskEncryptRequired: true } });
    const latest = rows[1];
    await db.devicePostureCheck.update({ where: { id: latest.id }, data: { nextCheckAt: new Date(Date.now() - 1000) } });
    const run2 = await service.runContinuousValidation(1);
    expect(run2.rechecked).toBe(1);
    expect(run2.changed).toBe(1);
    expect(run2.results[0].verdict).toBe("unknown");
    const flipped = await db.devicePostureCheck.findMany({ where: { deviceId: "cv-dev" }, orderBy: { id: "desc" }, take: 1 });
    expect(flipped[0].verdict).toBe("unknown");
    expect(JSON.parse(flipped[0].results)).toEqual({ av: "pass" }); // raw results replayed verbatim
  });
});

describe("evaluateAccess — allow + deny paths (backing POST /api/v1/ztna/evaluate)", () => {
  it("allows an ungated user policy and reports the matched policy", async () => {
    const app = await service.createApp(1, { name: "wiki-eval", host: "wiki.corp.internal" });
    await service.createPolicy(1, { appId: app.id, subjectType: "user", subjectRef: "alice" });

    const result = await service.evaluateAccess(1, { appId: app.id, subject: { user: "alice", groups: [], deviceId: "aa:bb:cc:dd:ee:99" } });
    expect(result.decision).toBe("allow");
    expect(result.matchedPolicyId).not.toBeNull();
    expect(result.matchedPolicyRef).toBe("alice");
    expect(result.postureVerdict).toBe("unknown"); // never checked, but no gate attached → allow
    expect(result.reason).toMatch(/Allowed by user policy/);
    expect(result.appName).toBe("wiki-eval");
  });

  it("denies a posture-gated allow when the device is non-compliant (deny path)", async () => {
    const app = await service.createApp(1, { name: "vault-eval", host: "vault.corp.internal" });
    const profile = await service.createPostureProfile(1, { name: "gated-laptop", checks: { avRequired: true, diskEncryptRequired: true } });
    await service.createPolicy(1, { appId: app.id, subjectType: "user", subjectRef: "alice", postureProfileId: profile.id });
    await service.recordPostureCheck(1, { deviceId: "aa:bb:cc:dd:ee:99", profileId: profile.id, results: { av: "pass", diskEncrypt: "fail" } });

    const denied = await service.evaluateAccess(1, { appId: app.id, subject: { user: "alice", groups: [], deviceId: "aa:bb:cc:dd:ee:99" } });
    expect(denied.decision).toBe("deny");
    expect(denied.postureVerdict).toBe("non_compliant");
    expect(denied.reason).toMatch(/non_compliant/);
  });

  it("falls back to default deny for unmatched subjects and honors deny-wins with a compliant device", async () => {
    const app = await service.createApp(1, { name: "files-eval", host: "files.corp.internal" });
    const allow = await service.createPolicy(1, { appId: app.id, subjectType: "group", subjectRef: "engineering" });
    const deny = await service.createPolicy(1, { appId: app.id, subjectType: "user", subjectRef: "mallory", action: "deny" });

    const noMatch = await service.evaluateAccess(1, { appId: app.id, subject: { user: "stranger", groups: [] } });
    expect(noMatch.decision).toBe("deny");
    expect(noMatch.matchedPolicyId).toBeNull();

    const mallory = await service.evaluateAccess(1, { appId: app.id, subject: { user: "mallory", groups: ["engineering"] } });
    expect(mallory.decision).toBe("deny");
    expect(mallory.matchedPolicyId).toBe(deny.id); // deny outranks the broader group allow

    const alice = await service.evaluateAccess(1, { appId: app.id, subject: { user: "alice", groups: ["engineering"] } });
    expect(alice.decision).toBe("allow");
    expect(alice.matchedPolicyId).toBe(allow.id);
  });
});

describe("stats — counts, compliance pie, recent denials", () => {
  it("aggregates apps/policies, latest-verdict pie, stale count and denied evaluations", async () => {
    const app = await service.createApp(1, { name: "stats-app", host: "stats.corp.internal" });
    const profile = await service.createPostureProfile(1, { name: "stats-profile", checks: { avRequired: true } });
    const p1 = await service.createPolicy(1, { appId: app.id, subjectRef: "alice" });
    await service.createPolicy(1, { appId: app.id, subjectRef: "bob", enabled: false });

    await service.recordPostureCheck(1, { deviceId: "s-ok", profileId: profile.id, results: { av: "pass" } });
    await service.recordPostureCheck(1, { deviceId: "s-bad", profileId: profile.id, results: { av: "fail" } });
    await service.recordPostureCheck(1, { deviceId: "s-stale", profileId: profile.id, results: { av: "pass" } });
    const staleRow = await db.devicePostureCheck.findFirstOrThrow({ where: { deviceId: "s-stale" } });
    await db.devicePostureCheck.update({ where: { id: staleRow.id }, data: { nextCheckAt: new Date(Date.now() - 1000) } });

    // audit rows exactly as the evaluate route writes them (result: success)
    await db.auditLog.create({
      data: {
        tenantId: 1,
        action: "ztna.evaluate",
        objectType: "ztna_application",
        objectId: app.id,
        objectName: app.name,
        result: "success",
        afterState: JSON.stringify({ decision: "deny", reason: "Denied by user policy 'mallory'", matchedPolicyId: p1.id, user: "mallory", deviceId: null, appName: app.name }),
      },
    });
    await db.auditLog.create({
      data: {
        tenantId: 1,
        action: "ztna.evaluate",
        objectType: "ztna_application",
        objectId: app.id,
        objectName: app.name,
        result: "success",
        afterState: JSON.stringify({ decision: "allow", reason: "Allowed by user policy 'alice'", matchedPolicyId: p1.id, user: "alice", deviceId: null, appName: app.name }),
      },
    });

    const stats = await service.getZtnaStats(1);
    expect(stats.apps).toBe(1);
    expect(stats.policies).toBe(2);
    expect(stats.enabledPolicies).toBe(1);
    expect(stats.profiles).toBe(1);
    expect(stats.compliance).toEqual({ compliant: 2, nonCompliant: 1, unknown: 0 });
    expect(stats.staleChecks).toBe(1);
    expect(stats.recentDenials).toHaveLength(1);
    expect(stats.recentDenials[0]).toMatchObject({ user: "mallory", appName: "stats-app", matchedPolicyId: p1.id, reason: "Denied by user policy 'mallory'" });
  });
});
