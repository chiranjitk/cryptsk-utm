/**
 * Incident Response service tests (Phase 3 §3.5) — DB-backed harness over a
 * per-run copy of the pushed dev schema (same pattern as the portal
 * persistence tests, which established it):
 *   • INC- ref generation (zero-padded per-tenant counter) + uniqueness under
 *     sequential creates (collision-safe retry),
 *   • the workflow state machine: allowed hops only; every transition appends
 *     a timeline status_change; resolution stamps resolvedAt; resolved-only
 *     delete,
 *   • fromAlert dedupe: an open incident with the same sourceRef is returned
 *     unchanged (flag) — resolved incidents no longer dedupe,
 *   • blockSource: address object + deny firewall rule via the rule-service
 *     create path, detail ids stamped, blocked timeline entry, re-block
 *     rejected.
 *
 * The identity/incident modules are imported AFTER the DATABASE_URL override —
 * static imports would resolve the Prisma datasource too early.
 */

import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "incidents-"));
const DB_PATH = path.join(TMP_DIR, "incidents-test.db");
fs.copyFileSync(path.resolve(process.cwd(), "db/cryptsk.db"), DB_PATH);
process.env.DATABASE_URL = `file:${DB_PATH}`;

const { db } = await import("@/lib/db");
const service = await import("@/lib/incidents/service");
const { createRule } = await import("@/lib/firewall/rule-service");

const ALERT_REF = JSON.stringify({ kind: "ips_event", id: 101, sid: "2050" });

beforeAll(async () => {
  // the copied dev schema has no tenant rows — incident rows FK to tenants
  await db.tenant.upsert({ where: { id: 1 }, update: {}, create: { id: 1, name: "incident-test" } });
});

beforeEach(async () => {
  await db.incidentTimelineEntry.deleteMany({});
  await db.incident.deleteMany({});
  // only artifacts this suite creates — seeded rules/objects stay untouched
  await db.firewallRule.deleteMany({ where: { name: { startsWith: "INC " } } });
  await db.addressObject.deleteMany({
    where: { AND: [{ name: { startsWith: "inc-" } }, { name: { endsWith: "-block" } }] },
  });
});

afterAll(async () => {
  await db.$disconnect();
  fs.rmSync(TMP_DIR, { recursive: true, force: true });
});

// ── refs ────────────────────────────────────────────────────────────────────

describe("INC- ref generation", () => {
  it("generates sequential zero-padded unique refs under sequential creates", async () => {
    const created: Awaited<ReturnType<typeof service.createIncident>>[] = [];
    for (let i = 1; i <= 4; i++) {
      const dto = await service.createIncident(1, { title: `incident ${i}`, source: "manual" }, "tester");
      created.push(dto);
    }
    expect(created.map((c) => c.ref)).toEqual(["INC-0001", "INC-0002", "INC-0003", "INC-0004"]);
    expect(new Set(created.map((c) => c.ref)).size).toBe(4);
    for (const c of created) {
      expect(c.status).toBe("new");
      expect(c.resolvedAt).toBeNull();
    }
  });

  it("stays collision-safe when the computed ref is already claimed (P2002 retry)", async () => {
    // seed a raw row holding the EXACT ref the counter computes next:
    // count = 1 → attempt 0 tries INC-0002 → unique violation → attempt 1
    // (count + offset) lands on INC-0003 instead of wedging/failing
    await db.incident.create({
      data: { tenantId: 1, ref: "INC-0002", title: "hole row", source: "manual" },
    });
    const dto = await service.createIncident(1, { title: "after collision", source: "manual" }, "tester");
    expect(dto.ref).toBe("INC-0003");
    const titles = await db.incident.findMany({ where: { tenantId: 1 }, select: { ref: true } });
    expect(new Set(titles.map((r) => r.ref)).size).toBe(titles.length); // no duplicate refs
  });
});

// ── workflow ────────────────────────────────────────────────────────────────

describe("workflow transitions + timeline", () => {
  it("appends a created entry on creation and status_change entries on transitions", async () => {
    const inc = await service.createIncident(1, { title: "beacon", source: "ips_event" }, "tester");
    await service.transition(1, inc.id, { kind: "status", status: "investigating" }, "analyst");
    await service.assign(1, inc.id, { kind: "assign", assignedTo: "alice" }, "admin");
    await service.addNote(1, inc.id, "observed periodic beaconing", "alice");

    const detail = await service.getIncident(1, inc.id);
    expect(detail.timeline?.map((t) => t.action)).toEqual(["created", "status_change", "assigned", "note"]);
    expect(detail.timeline?.[1].actor).toBe("analyst");
    expect(detail.timeline?.[1].detail).toContain("new → investigating");
    expect(detail.timeline?.[2].detail).toContain("alice");
    expect(detail.status).toBe("investigating");
    expect(detail.assignedTo).toBe("alice");
  });

  it("rejects illegal transitions (skipping hops and reopening resolved)", async () => {
    const inc = await service.createIncident(1, { title: "t1" }, "tester");
    // new → contained skips investigating
    await expect(
      service.transition(1, inc.id, { kind: "status", status: "contained" }, "tester"),
    ).rejects.toThrow(/Illegal transition new → contained/);
    // resolved → investigating reopens a closed case
    await service.transition(1, inc.id, { kind: "status", status: "resolved" }, "tester");
    await expect(
      service.transition(1, inc.id, { kind: "status", status: "investigating" }, "tester"),
    ).rejects.toThrow(/Illegal transition resolved → investigating/);
    // no timeline noise from the rejected attempts
    const detail = await service.getIncident(1, inc.id);
    expect(detail.timeline?.filter((t) => t.action === "status_change")).toHaveLength(1);
  });

  it("sets resolvedAt when transitioning to resolved and keeps it on the row", async () => {
    const inc = await service.createIncident(1, { title: "t2" }, "tester");
    expect(inc.resolvedAt).toBeNull();
    const resolved = await service.transition(1, inc.id, { kind: "status", status: "resolved" }, "tester");
    expect(resolved.resolvedAt).not.toBeNull();
    const row = await db.incident.findFirstOrThrow({ where: { id: inc.id } });
    expect(row.resolvedAt).toBeTruthy();
    // resolved is terminal: nothing may move out of it (covered above), and
    // resolution also appends a status_change timeline entry
    const detail = await service.getIncident(1, inc.id);
    expect(detail.timeline?.at(-1)?.action).toBe("status_change");
    expect(detail.timeline?.at(-1)?.detail).toContain("resolved");
  });

  it("allows only resolved incidents to be deleted (timeline cleaned up)", async () => {
    const open = await service.createIncident(1, { title: "still open" }, "tester");
    await expect(service.deleteIncident(1, open.id)).rejects.toThrow(/resolved/);
    await service.transition(1, open.id, { kind: "status", status: "resolved" }, "tester");
    await service.deleteIncident(1, open.id);
    expect(await db.incident.findFirst({ where: { id: open.id } })).toBeNull();
    expect(await db.incidentTimelineEntry.findMany({ where: { incidentId: open.id } })).toEqual([]);
  });
});

// ── fromAlert dedupe ────────────────────────────────────────────────────────

describe("fromAlert dedupe", () => {
  it("returns the existing open incident unchanged for a repeated sourceRef", async () => {
    const first = await service.fromAlert(
      1,
      { source: "ips_event", sourceRef: ALERT_REF, title: "brute force", severity: "high", detail: { srcIps: ["203.0.113.9"] } },
      "system",
    );
    expect(first.deduped).toBe(false);

    const second = await service.fromAlert(
      1,
      { source: "ips_event", sourceRef: ALERT_REF, title: "brute force (updated)", severity: "critical" },
      "system",
    );
    expect(second.deduped).toBe(true);
    expect(second.incident.id).toBe(first.incident.id);
    // unchanged: title stays the FIRST version, no extra timeline entries
    expect(second.incident.title).toBe("brute force");
    const entries = await db.incidentTimelineEntry.findMany({ where: { incidentId: first.incident.id } });
    expect(entries).toHaveLength(1);
    expect(entries[0].action).toBe("created");
    // and only one row exists for the alert
    expect(await db.incident.count({ where: { tenantId: 1, sourceRef: ALERT_REF } })).toBe(1);
  });

  it("creates a fresh incident once the previous one is resolved", async () => {
    const first = await service.fromAlert(1, { source: "ips_event", sourceRef: ALERT_REF, title: "scan" }, "system");
    await service.transition(1, first.incident.id, { kind: "status", status: "resolved" }, "tester");
    const again = await service.fromAlert(1, { source: "ips_event", sourceRef: ALERT_REF, title: "scan" }, "system");
    expect(again.deduped).toBe(false);
    expect(again.incident.id).not.toBe(first.incident.id);
    expect(again.incident.status).toBe("new");
  });
});

// ── blockSource ─────────────────────────────────────────────────────────────

describe("blockSource", () => {
  it("creates an ip address object + deny firewall rule, stamps detail ids and the timeline", async () => {
    const inc = await service.createIncident(
      1,
      { title: "c2 beaconing", source: "ips_event", detail: { srcIps: ["198.51.100.23"], description: "periodic c2 beacons" } },
      "tester",
    );
    const res = await service.blockSource(1, inc.id, "analyst");
    expect(res.addressObjectId).toBeGreaterThan(0);
    expect(res.firewallRuleId).toBeGreaterThan(0);

    const ao = await db.addressObject.findUniqueOrThrow({ where: { id: res.addressObjectId } });
    expect(ao.tenantId).toBe(1);
    expect(ao.type).toBe("ip");
    expect(ao.value).toBe("198.51.100.23");
    expect(ao.name).toBe(`inc-${inc.ref}-block`);

    const rule = await db.firewallRule.findUniqueOrThrow({ where: { id: res.firewallRuleId } });
    expect(rule.tenantId).toBe(1);
    expect(rule.name).toBe(`INC ${inc.ref} auto-block`);
    expect(rule.action).toBe("deny");
    expect(rule.enabled).toBe(true);
    expect(JSON.parse(rule.srcAddrIds)).toEqual([res.addressObjectId]);

    const detail = await service.getIncident(1, inc.id);
    expect(detail.detail.blockedRuleId).toBe(res.firewallRuleId);
    expect(detail.detail.blockedAddressId).toBe(res.addressObjectId);
    const blocked = detail.timeline?.find((t) => t.action === "blocked");
    expect(blocked).toBeTruthy();
    expect(blocked?.actor).toBe("analyst");
    expect(blocked?.detail).toContain(`#${res.firewallRuleId}`);
    expect(blocked?.detail).toContain(`#${res.addressObjectId}`);
  });

  it("rejects re-blocking and incidents without a blockable srcIps[0]", async () => {
    const inc = await service.createIncident(
      1,
      { title: "dup block", source: "manual", detail: { srcIps: ["192.0.2.44"] } },
      "tester",
    );
    await service.blockSource(1, inc.id, "analyst");
    await expect(service.blockSource(1, inc.id, "analyst")).rejects.toThrow(/already blocked/);

    const noIp = await service.createIncident(1, { title: "no ip" }, "tester");
    await expect(service.blockSource(1, noIp.id, "analyst")).rejects.toThrow(/srcIps/);

    const badIp = await service.createIncident(
      1,
      { title: "bad ip", source: "manual", detail: { srcIps: ["999.1.2.3"] } },
      "tester",
    );
    await expect(service.blockSource(1, badIp.id, "analyst")).rejects.toThrow(/blockable/);
  });

  it("refuses the never-blockable addresses (0.0.0.0, 255.255.255.255, leading-zero octets)", async () => {
    for (const ip of ["0.0.0.0", "255.255.255.255", "010.2.3.4", "192.168.01.5"]) {
      const inc = await service.createIncident(
        1,
        { title: `unblockable ${ip}`, source: "manual", detail: { srcIps: [ip] } },
        "tester",
      );
      await expect(service.blockSource(1, inc.id, "analyst")).rejects.toThrow(/blockable/);
      expect(
        await db.addressObject.count({ where: { tenantId: 1, name: `inc-${inc.ref}-block` } }),
      ).toBe(0); // nothing materialized
    }
  });

  it("recovers from a rule-service failure: artifacts cleaned up, retry succeeds (no wedge)", async () => {
    const inc = await service.createIncident(
      1,
      { title: "wedge-then-retry", source: "manual", detail: { srcIps: ["203.0.113.55"] } },
      "tester",
    );

    // force the rule-service create to FAIL: a rule with the auto-block name
    // already exists (dup-name guard → conflict) AFTER the address object was
    // created — the pre-fix behavior left that object orphaned and every
    // retry wedged on the unique name guard (audit fix F-d)
    await createRule(1, {
      name: `INC ${inc.ref} auto-block`,
      enabled: true,
      srcZoneIds: [],
      dstZoneIds: [],
      srcAddrIds: [],
      dstAddrIds: [],
      serviceIds: [],
      applicationIds: [],
      userIds: [],
      srcMacs: [],
      action: "allow",
      logging: "none",
      synProtection: false,
      tags: [],
    });
    await expect(service.blockSource(1, inc.id, "analyst")).rejects.toThrow(/already exists/);

    // COMPENSATION: the just-created address object was deleted before the
    // rethrow — no orphaned artifacts, no wedge
    expect(await db.addressObject.count({ where: { tenantId: 1, name: `inc-${inc.ref}-block` } })).toBe(0);
    const stamped = await service.getIncident(1, inc.id);
    expect(stamped.detail.blockedRuleId).toBeUndefined();
    expect(stamped.detail.blockedAddressId).toBeUndefined();

    // retry after removing the obstruction → the block fully succeeds
    await db.firewallRule.deleteMany({ where: { tenantId: 1, name: `INC ${inc.ref} auto-block` } });
    const res = await service.blockSource(1, inc.id, "analyst");
    expect(res.firewallRuleId).toBeGreaterThan(0);
    expect(res.addressObjectId).toBeGreaterThan(0);
    const detail = await service.getIncident(1, inc.id);
    expect(detail.detail.blockedRuleId).toBe(res.firewallRuleId);
    expect(detail.detail.blockedAddressId).toBe(res.addressObjectId);
    expect(
      await db.addressObject.count({ where: { tenantId: 1, name: `inc-${inc.ref}-block` } }),
    ).toBe(1); // exactly one object — the failed attempt left no residue
  });
});

// ── list + stats ────────────────────────────────────────────────────────────

describe("list filters + stats", () => {
  it("filters by status/severity/source/q and paginates", async () => {
    await service.createIncident(1, { title: "alpha", source: "manual", severity: "high" }, "tester");
    await service.createIncident(1, { title: "beta", source: "ips_event", severity: "low" }, "tester");

    const all = await service.listIncidents(1, { page: 1, limit: 10 });
    expect(all.meta.total).toBe(2);
    expect(all.data.map((d) => d.title).sort()).toEqual(["alpha", "beta"]);

    const highOnly = await service.listIncidents(1, {
      page: 1,
      limit: 10,
      severity: "high",
      status: "new",
      source: "manual",
      q: "alpha",
    });
    expect(highOnly.data).toHaveLength(1);
    expect(highOnly.data[0].title).toBe("alpha");

    const empty = await service.listIncidents(1, { page: 1, limit: 10, status: "resolved" });
    expect(empty.data).toEqual([]);
    expect(empty.meta.total).toBe(0);
  });

  it("aggregates open by severity, created-7d and mean time to resolve", async () => {
    const a = await service.createIncident(1, { title: "s1", severity: "critical" }, "tester");
    await service.createIncident(1, { title: "s2", severity: "medium" }, "tester");
    await service.transition(1, a.id, { kind: "status", status: "resolved" }, "tester");

    const stats = await service.getStats(1);
    expect(stats.openTotal).toBe(1);
    expect(stats.openBySeverity.critical).toBe(0); // resolved → no longer open
    expect(stats.openBySeverity.medium).toBe(1);
    expect(stats.created7d).toBe(2);
    expect(stats.resolvedTotal).toBe(1);
    expect(stats.mttrHours).not.toBeNull();
    expect(stats.mttrHours).toBeGreaterThanOrEqual(0);
  });
});
