/**
 * SOAR engine + service tests (Phase 4 §4.6) — vitest.
 *
 * Part 1 exercises the PURE engine (no db): matchesTrigger (kind match +
 * empty/non-empty filter dimensions across severities/sources/kinds,
 * case-insensitivity, string-or-object filter forms), evaluateActions
 * (per-kind param grammar for block_ip | notify | create_incident | delay |
 * webhook, positional error accumulation, 1..10 bounds) and the dedupe
 * decision (running|success block, failed/skipped don't).
 *
 * Part 2 runs the service against a per-run copy of the pushed dev schema
 * (same harness as tests/incidents.test.ts): manual fire creates the run row,
 * notify → Notification row, create_incident → Incident via the incidents
 * fromAlert path (sourceRef = triggerRef → deduped on re-fire), block_ip →
 * address object + deny rule through createRule (idempotent on re-run),
 * dedupe (same-key sibling playbooks coordinate; failed runs retry),
 * triggerIngest filter selection, the failure path (a throwing step fails the
 * run and records the remaining actions as skipped steps), stats and CRUD.
 *
 * The soar modules are imported AFTER the DATABASE_URL override — static
 * imports would resolve the Prisma datasource too early.
 */

import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "soar-"));
const DB_PATH = path.join(TMP_DIR, "soar-test.db");
fs.copyFileSync(path.resolve(process.cwd(), "db/cryptsk.db"), DB_PATH);
process.env.DATABASE_URL = `file:${DB_PATH}`;

const { db } = await import("@/lib/db");
const engine = await import("@/lib/soar/engine");
const service = await import("@/lib/soar/service");

beforeAll(async () => {
  // the copied dev schema has no tenant rows — soar rows FK to tenants
  await db.tenant.upsert({ where: { id: 1 }, update: {}, create: { id: 1, name: "soar-test" } });
});

beforeEach(async () => {
  // only artifacts this suite creates — seeded rules/objects stay untouched
  await db.soarPlaybookRun.deleteMany({});
  await db.soarPlaybook.deleteMany({});
  await db.incidentTimelineEntry.deleteMany({});
  await db.incident.deleteMany({});
  await db.notification.deleteMany({ where: { sourceModule: "soar" } });
  await db.firewallRule.deleteMany({ where: { name: { startsWith: "SOAR auto-block" } } });
  await db.addressObject.deleteMany({ where: { name: { startsWith: "soar-block-" } } });
});

afterAll(async () => {
  await db.$disconnect();
  fs.rmSync(TMP_DIR, { recursive: true, force: true });
});

// ── notify-step fault injector (failure path: a step that THROWS) ───────────

function withFailingNotify<T>(fn: () => Promise<T>): Promise<T> {
  const original = db.notification.create.bind(db.notification);
  db.notification.create = async (args: Parameters<typeof original>) => {
    throw new Error("simulated notification outage");
  };
  return fn().finally(() => {
    db.notification.create = original;
  });
}

// ═══════════════════════════ Part 1: pure engine ════════════════════════════

describe("matchesTrigger", () => {
  const trigger = (payload: Record<string, unknown>) => ({ kind: "incident_severity", triggerRef: "incident:INC-0007", payload });

  it("matches when triggerKind agrees and the filter is empty (match-all)", () => {
    expect(engine.matchesTrigger({ triggerKind: "incident_severity", triggerFilter: "{}" }, trigger({}))).toBe(true);
    expect(engine.matchesTrigger({ triggerKind: "incident_severity", triggerFilter: { severities: [], sources: [], kinds: [] } }, trigger({}))).toBe(true);
  });

  it("rejects a triggerKind mismatch even with an empty filter", () => {
    expect(engine.matchesTrigger({ triggerKind: "dlp_incident", triggerFilter: "{}" }, trigger({ severity: "critical" }))).toBe(false);
  });

  it("severity filter: listed severities match, others and missing fail", () => {
    const pb = { triggerKind: "incident_severity", triggerFilter: { severities: ["high", "critical"] } };
    expect(engine.matchesTrigger(pb, trigger({ severity: "critical" }))).toBe(true);
    expect(engine.matchesTrigger(pb, trigger({ severity: "low" }))).toBe(false);
    expect(engine.matchesTrigger(pb, trigger({}))).toBe(false); // payload must carry the dimension
  });

  it("source filter: payload source must be listed", () => {
    const pb = { triggerKind: "incident_severity", triggerFilter: { sources: ["ips_event"] } };
    expect(engine.matchesTrigger(pb, trigger({ source: "ips_event" }))).toBe(true);
    expect(engine.matchesTrigger(pb, trigger({ source: "manual" }))).toBe(false);
    expect(engine.matchesTrigger(pb, trigger({}))).toBe(false);
  });

  it("kind filter: payload kind must be listed (case-insensitive)", () => {
    const pb = { triggerKind: "dlp_incident", triggerFilter: { kinds: ["PII"] } };
    expect(engine.matchesTrigger(pb, { kind: "dlp_incident", triggerRef: "x", payload: { kind: "pii" } })).toBe(true);
    expect(engine.matchesTrigger(pb, { kind: "dlp_incident", triggerRef: "x", payload: { kind: "credentials" } })).toBe(false);
  });

  it("combined dimensions require ALL non-empty ones to pass", () => {
    const pb = {
      triggerKind: "incident_severity",
      triggerFilter: { severities: ["critical"], sources: ["ips_event"], kinds: ["beacon"] },
    };
    expect(engine.matchesTrigger(pb, trigger({ severity: "critical", source: "ips_event", kind: "beacon" }))).toBe(true);
    expect(engine.matchesTrigger(pb, trigger({ severity: "critical", source: "ips_event" }))).toBe(false); // kind missing
    expect(engine.matchesTrigger(pb, trigger({ severity: "critical", kind: "beacon" }))).toBe(false); // source missing
  });

  it("accepts the stored JSON string form and tolerates invalid JSON (match-all)", () => {
    const pb = { triggerKind: "dns_tunnel", triggerFilter: JSON.stringify({ severities: ["high"] }) };
    expect(engine.matchesTrigger(pb, { kind: "dns_tunnel", triggerRef: "x", payload: { severity: "high" } })).toBe(true);
    expect(engine.matchesTrigger(pb, { kind: "dns_tunnel", triggerRef: "x", payload: { severity: "low" } })).toBe(false);
    expect(engine.matchesTrigger({ triggerKind: "dns_tunnel", triggerFilter: "not-json{{" }, { kind: "dns_tunnel", triggerRef: "x", payload: {} })).toBe(true);
  });

  it("severity filter is case-insensitive", () => {
    const pb = { triggerKind: "incident_severity", triggerFilter: { severities: ["HIGH"] } };
    expect(engine.matchesTrigger(pb, trigger({ severity: "high" }))).toBe(true);
  });
});

describe("evaluateActions", () => {
  it("accepts one valid action per kind and preserves params", () => {
    const res = engine.evaluateActions([
      { kind: "block_ip", params: { ip: "198.51.100.23", direction: "out" } },
      { kind: "notify", params: { title: "Heads up", message: "C2 blocked" } },
      { kind: "create_incident", params: { title: "SOAR case", severity: "high" } },
      { kind: "delay", params: { seconds: 300 } },
      { kind: "webhook", params: { payload: { forwarded: true } } },
    ]);
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.actions).toHaveLength(5);
  });

  it("rejects invalid block_ip params (ip grammar, direction)", () => {
    expect(engine.evaluateActions([{ kind: "block_ip", params: { ip: "999.1.2.3" } }])).toMatchObject({ ok: false });
    expect(engine.evaluateActions([{ kind: "block_ip", params: { ip: "not-an-ip" } }]).ok).toBe(false);
    expect(engine.evaluateActions([{ kind: "block_ip", params: { ip: "192.0.2.1", direction: "sideways" } }]).ok).toBe(false);
    expect(engine.evaluateActions([{ kind: "block_ip", params: {} }]).ok).toBe(false);
  });

  it("rejects notify without title or message and create_incident with a bad severity", () => {
    expect(engine.evaluateActions([{ kind: "notify", params: { title: "x" } }]).ok).toBe(false);
    expect(engine.evaluateActions([{ kind: "notify", params: { title: "x", message: "" } }]).ok).toBe(false);
    expect(engine.evaluateActions([{ kind: "create_incident", params: { title: "x", severity: "apocalyptic" } }]).ok).toBe(false);
    expect(engine.evaluateActions([{ kind: "create_incident", params: { title: "x" } }]).ok).toBe(false);
  });

  it("bounds delay seconds to integers 1..300", () => {
    expect(engine.evaluateActions([{ kind: "delay", params: { seconds: 1 } }]).ok).toBe(true);
    expect(engine.evaluateActions([{ kind: "delay", params: { seconds: 300 } }]).ok).toBe(true);
    expect(engine.evaluateActions([{ kind: "delay", params: { seconds: 0 } }]).ok).toBe(false);
    expect(engine.evaluateActions([{ kind: "delay", params: { seconds: 301 } }]).ok).toBe(false);
    expect(engine.evaluateActions([{ kind: "delay", params: { seconds: 1.5 } }]).ok).toBe(false);
  });

  it("requires the webhook payload to be a JSON object", () => {
    expect(engine.evaluateActions([{ kind: "webhook", params: { payload: { a: 1 } } }]).ok).toBe(true);
    expect(engine.evaluateActions([{ kind: "webhook", params: { payload: [1, 2] } }]).ok).toBe(false);
    expect(engine.evaluateActions([{ kind: "webhook", params: {} }]).ok).toBe(false);
  });

  it("rejects unknown kinds and non-object entries", () => {
    expect(engine.evaluateActions([{ kind: "nuke", params: {} }]).ok).toBe(false);
    expect(engine.evaluateActions(["notify"]).ok).toBe(false);
  });

  it("enforces the 1..10 bounds", () => {
    expect(engine.evaluateActions([]).ok).toBe(false);
    expect(engine.evaluateActions("nope").ok).toBe(false);
    const ten = Array.from({ length: 10 }, (_, i) => ({ kind: "delay", params: { seconds: ((i % 300) + 1) as number } }));
    const eleven = [...ten, { kind: "delay", params: { seconds: 1 } }];
    expect(engine.evaluateActions(ten).ok).toBe(true);
    expect(engine.evaluateActions(eleven).ok).toBe(false);
  });

  it("accumulates positional errors for later fixing", () => {
    const res = engine.evaluateActions([
      { kind: "block_ip", params: { ip: "nope" } },
      { kind: "delay", params: { seconds: 500 } },
    ]);
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.errors.some((e) => e.startsWith("actions[0] block_ip"))).toBe(true);
      expect(res.errors.some((e) => e.startsWith("actions[1] delay"))).toBe(true);
    }
  });
});

describe("dedupeBlocks (pure decision)", () => {
  it("does not block without candidates or for failed/skipped runs", () => {
    expect(engine.dedupeBlocks([])).toBe(false);
    expect(engine.dedupeBlocks([{ status: "failed" }])).toBe(false);
    expect(engine.dedupeBlocks([{ status: "skipped" }])).toBe(false);
  });

  it("blocks on open (running|success) runs only", () => {
    expect(engine.dedupeBlocks([{ status: "running" }])).toBe(true);
    expect(engine.dedupeBlocks([{ status: "success" }])).toBe(true);
    expect(engine.dedupeBlocks([{ status: "failed" }, { status: "success" }])).toBe(true);
  });
});

// ═══════════════════════════ Part 2: DB-backed service ══════════════════════

describe("manual fire + notify step", () => {
  it("creates a run row, a Notification and stamps lastRunAt", async () => {
    const pb = await service.createPlaybook(1, {
      name: "notify-duty",
      enabled: true,
      triggerKind: "incident_created",
      triggerFilter: {},
      actions: [{ kind: "notify", params: { title: "New incident", message: "Triage it" } }],
      dedupeKey: "",
    });

    const run = await service.runPlaybookById(1, pb.id, { triggerRef: "incident:INC-0001", payload: {} });
    expect(run.status).toBe("success");
    expect(run.playbookName).toBe("notify-duty");
    expect(run.triggerRef).toBe("incident:INC-0001");
    expect(run.finishedAt).not.toBeNull();
    expect(run.durationMs).not.toBeNull();
    expect(run.steps).toEqual([
      { kind: "notify", status: "success", detail: expect.stringContaining("notification #") },
    ]);

    const row = await db.soarPlaybookRun.findUniqueOrThrow({ where: { id: run.id } });
    expect(row.tenantId).toBe(1);
    expect(row.playbookId).toBe(pb.id);
    expect(row.status).toBe("success");
    expect(JSON.parse(row.steps)).toHaveLength(1);

    const notification = await db.notification.findFirstOrThrow({ where: { tenantId: 1, sourceModule: "soar" } });
    expect(notification.type).toBe("threat");
    expect(notification.severity).toBe("warning");
    expect(notification.title).toBe("New incident");
    expect(notification.message).toBe("Triage it");

    const refreshed = await db.soarPlaybook.findUniqueOrThrow({ where: { id: pb.id } });
    expect(refreshed.lastRunAt).not.toBeNull();
  });

  it("404s on an unknown playbook and validates the trigger envelope", async () => {
    await expect(service.runPlaybookById(1, 424242, { triggerRef: "x" })).rejects.toThrow(/not found/i);
    await expect(service.triggerIngest(1, { kind: "bogus" as never, triggerRef: "x", payload: {} })).rejects.toThrow(/Unknown trigger kind/);
    await expect(service.triggerIngest(1, { kind: "ioc_hit", triggerRef: "  ", payload: {} })).rejects.toThrow(/triggerRef is required/);
    await expect(service.createPlaybook(1, {
      name: "bad-delay",
      enabled: true,
      triggerKind: "incident_created",
      triggerFilter: {},
      actions: [{ kind: "delay", params: { seconds: 500 } }],
      dedupeKey: "",
    })).rejects.toThrow(/Invalid actions/);
  });
});

describe("create_incident step", () => {
  it("creates an incident via the fromAlert path and dedupes on re-fire", async () => {
    const pb = await service.createPlaybook(1, {
      name: "open-case",
      enabled: true,
      triggerKind: "dlp_incident",
      triggerFilter: {},
      actions: [{ kind: "create_incident", params: { title: "DLP exfil response", severity: "high" } }],
      dedupeKey: "",
    });

    const first = await service.runPlaybookById(1, pb.id, { triggerRef: "dlp_incident:42", payload: { kind: "pii" } });
    expect(first.status).toBe("success");
    expect(first.steps[0].detail).toMatch(/incident INC-0001 opened/);

    const incident = await db.incident.findFirstOrThrow({ where: { tenantId: 1 } });
    expect(incident.ref).toBe("INC-0001");
    expect(incident.source).toBe("dlp_incident");
    expect(incident.sourceRef).toBe("dlp_incident:42");
    expect(incident.severity).toBe("high");
    const detail = JSON.parse(incident.detail) as Record<string, unknown>;
    expect(detail.playbook).toBe("open-case");
    expect(detail.triggerKind).toBe("dlp_incident");

    const second = await service.runPlaybookById(1, pb.id, { triggerRef: "dlp_incident:42", payload: { kind: "pii" } });
    expect(second.status).toBe("success");
    expect(second.steps[0].detail).toMatch(/already open/);
    expect(await db.incident.count({ where: { tenantId: 1, sourceRef: "dlp_incident:42" } })).toBe(1);
  });
});

describe("block_ip step", () => {
  it("creates an ip address object + deny rule through createRule", async () => {
    const pb = await service.createPlaybook(1, {
      name: "block-c2",
      enabled: true,
      triggerKind: "ioc_hit",
      triggerFilter: {},
      actions: [{ kind: "block_ip", params: { ip: "198.51.100.23", direction: "both" } }],
      dedupeKey: "",
    });

    const run = await service.runPlaybookById(1, pb.id, { triggerRef: "ioc:198.51.100.23", payload: {} });
    expect(run.status).toBe("success");
    expect(run.steps[0].detail).toMatch(/deny rule #\d+ 'SOAR auto-block 198\.51\.100\.23'/);

    const addr = await db.addressObject.findFirstOrThrow({ where: { tenantId: 1, name: "soar-block-198-51-100-23" } });
    expect(addr.type).toBe("ip");
    expect(addr.value).toBe("198.51.100.23");

    const rule = await db.firewallRule.findFirstOrThrow({ where: { tenantId: 1, name: "SOAR auto-block 198.51.100.23" } });
    expect(rule.action).toBe("deny");
    expect(rule.enabled).toBe(true);
    expect(JSON.parse(rule.srcAddrIds)).toEqual([addr.id]);
    expect(JSON.parse(rule.dstAddrIds)).toEqual([]);
  });

  it("is idempotent on re-run (reuses the object, recognizes the rule)", async () => {
    const pb = await service.createPlaybook(1, {
      name: "block-retry",
      enabled: true,
      triggerKind: "ioc_hit",
      triggerFilter: {},
      actions: [{ kind: "block_ip", params: { ip: "192.0.2.99" } }],
      dedupeKey: "",
    });
    const first = await service.runPlaybookById(1, pb.id, { triggerRef: "ioc:1" });
    const second = await service.runPlaybookById(1, pb.id, { triggerRef: "ioc:2" });
    expect(first.status).toBe("success");
    expect(second.status).toBe("success");
    expect(second.steps[0].detail).toMatch(/already present/);
    expect(await db.firewallRule.count({ where: { tenantId: 1, name: "SOAR auto-block 192.0.2.99" } })).toBe(1);
  });
});

describe("delay + webhook steps", () => {
  it("records delay as a no-op and webhook as skipped when no endpoint exists", async () => {
    const pb = await service.createPlaybook(1, {
      name: "fan-out",
      enabled: true,
      triggerKind: "dns_tunnel",
      triggerFilter: {},
      actions: [
        { kind: "delay", params: { seconds: 30 } },
        { kind: "webhook", params: { payload: { ref: "dns:9" } } },
      ],
      dedupeKey: "",
    });

    const run = await service.runPlaybookById(1, pb.id, { triggerRef: "dns_tunnel:9" });
    expect(run.status).toBe("success"); // skipped steps don't fail the run
    expect(run.steps.map((s) => s.status)).toEqual(["success", "skipped"]);
    expect(run.steps[0].detail).toMatch(/no-op/);
    expect(run.steps[1].detail).toMatch(/no webhook endpoint configured/);
  });
});

describe("failure path", () => {
  it("marks the run failed, records the throwing step and skips the rest", async () => {
    const pb = await service.createPlaybook(1, {
      name: "will-fail",
      enabled: true,
      triggerKind: "incident_created",
      triggerFilter: {},
      actions: [
        { kind: "notify", params: { title: "boom", message: "outage" } },
        { kind: "block_ip", params: { ip: "203.0.113.77" } },
        { kind: "delay", params: { seconds: 10 } },
      ],
      dedupeKey: "",
    });

    const run = await withFailingNotify(() => service.runPlaybookById(1, pb.id, { triggerRef: "incident:INC-0099" }));

    expect(run.status).toBe("failed");
    expect(run.steps.map((s) => s.status)).toEqual(["failed", "skipped", "skipped"]);
    expect(run.steps[0].detail).toContain("simulated notification outage");
    expect(run.steps[1].detail).toBe("not executed — previous step failed");
    expect(run.steps[2].kind).toBe("delay");

    const row = await db.soarPlaybookRun.findUniqueOrThrow({ where: { id: run.id } });
    expect(row.status).toBe("failed");
    expect(row.finishedAt).not.toBeNull();
    // the skipped block_ip really did not create anything
    expect(await db.firewallRule.count({ where: { tenantId: 1, name: "SOAR auto-block 203.0.113.77" } })).toBe(0);
    expect(await db.addressObject.count({ where: { tenantId: 1, name: "soar-block-203-0-113-77" } })).toBe(0);
  });

  it("fails the run with a validation step when stored actions are invalid", async () => {
    // seed directly past the validators — service re-checks at RUN time
    const seeded = await db.soarPlaybook.create({
      data: {
        tenantId: 1,
        name: "stale-actions",
        enabled: true,
        triggerKind: "incident_created",
        triggerFilter: "{}",
        actions: JSON.stringify([{ kind: "notify", params: { title: "missing message" } }]),
        dedupeKey: "",
      },
    });
    const run = await service.runPlaybookById(1, seeded.id, { triggerRef: "incident:INC-0100" });
    expect(run.status).toBe("failed");
    expect(run.steps).toEqual([
      { kind: "actions", status: "failed", detail: expect.stringContaining("invalid stored actions") },
    ]);
    expect(run.steps[0].detail).toContain("message is required");
  });

  it("a failed run does not block a dedupeKey retry", async () => {
    const pb = await db.soarPlaybook.create({
      data: {
        tenantId: 1,
        name: "retry-me",
        enabled: true,
        triggerKind: "incident_created",
        triggerFilter: "{}",
        actions: JSON.stringify([{ kind: "notify", params: { title: "t", message: "m" } }]),
        dedupeKey: "retry-key",
      },
    });
    await db.soarPlaybookRun.create({
      data: { tenantId: 1, playbookId: pb.id, triggerRef: "incident:INC-0007", status: "failed", steps: "[]" },
    });
    const run = await service.runPlaybookById(1, pb.id, { triggerRef: "incident:INC-0007" });
    expect(run.status).toBe("success");
  });
});

describe("dedupe via dedupeKey", () => {
  it("skips a re-fire for the same triggerRef and records a skipped run", async () => {
    const pb = await service.createPlaybook(1, {
      name: "deduped",
      enabled: true,
      triggerKind: "incident_created",
      triggerFilter: {},
      actions: [{ kind: "notify", params: { title: "once", message: "only once" } }],
      dedupeKey: "incident-once",
    });

    const first = await service.runPlaybookById(1, pb.id, { triggerRef: "incident:INC-0007" });
    expect(first.status).toBe("success");
    const lastRunAfterFirst = (await db.soarPlaybook.findUniqueOrThrow({ where: { id: pb.id } })).lastRunAt;

    const second = await service.runPlaybookById(1, pb.id, { triggerRef: "incident:INC-0007" });
    expect(second.status).toBe("skipped");
    expect(second.steps).toHaveLength(1);
    expect(second.steps[0].status).toBe("skipped");
    expect(second.steps[0].detail).toContain("incident-once");
    expect(second.steps[0].detail).toContain(`#${first.id}`);
    expect(second.finishedAt).not.toBeNull();
    // skipped runs leave lastRunAt (and the real artifacts) alone
    expect((await db.soarPlaybook.findUniqueOrThrow({ where: { id: pb.id } })).lastRunAt?.getTime()).toBe(
      lastRunAfterFirst?.getTime(),
    );
    expect(await db.notification.count({ where: { tenantId: 1, sourceModule: "soar" } })).toBe(1);

    // a different triggerRef fires again (dedupe is per triggerRef)
    const third = await service.runPlaybookById(1, pb.id, { triggerRef: "incident:INC-0008" });
    expect(third.status).toBe("success");
  });

  it("coordinates sibling playbooks sharing a dedupeKey (first wins, rest skip)", async () => {
    const common = {
      enabled: true,
      triggerKind: "ioc_hit" as const,
      triggerFilter: {},
      dedupeKey: "coord-1",
    };
    const pbA = await service.createPlaybook(1, {
      ...common,
      name: "coord-a",
      actions: [{ kind: "notify", params: { title: "A", message: "first" } }],
    });
    const pbB = await service.createPlaybook(1, {
      ...common,
      name: "coord-b",
      actions: [{ kind: "notify", params: { title: "B", message: "second" } }],
    });
    expect(pbB.id).toBeGreaterThan(pbA.id);

    const res = await service.triggerIngest(1, { kind: "ioc_hit", triggerRef: "ioc:coord", payload: {} });
    expect(res.runs).toHaveLength(2);
    expect(res.runs[0].playbookName).toBe("coord-a");
    expect(res.runs[0].status).toBe("success");
    expect(res.runs[1].playbookName).toBe("coord-b");
    expect(res.runs[1].status).toBe("skipped");
  });
});

describe("triggerIngest filter selection", () => {
  it("runs only enabled playbooks whose kind + filter match the payload", async () => {
    await service.createPlaybook(1, {
      name: "crit-only",
      enabled: true,
      triggerKind: "incident_severity",
      triggerFilter: { severities: ["critical"], sources: [], kinds: [] },
      actions: [{ kind: "notify", params: { title: "crit", message: "critical incident" } }],
      dedupeKey: "",
    });
    await service.createPlaybook(1, {
      name: "any-sev",
      enabled: true,
      triggerKind: "incident_severity",
      triggerFilter: {},
      actions: [{ kind: "delay", params: { seconds: 1 } }],
      dedupeKey: "",
    });
    await service.createPlaybook(1, {
      name: "other-kind",
      enabled: true,
      triggerKind: "incident_created",
      triggerFilter: {},
      actions: [{ kind: "delay", params: { seconds: 1 } }],
      dedupeKey: "",
    });
    await service.createPlaybook(1, {
      name: "crit-disabled",
      enabled: false,
      triggerKind: "incident_severity",
      triggerFilter: { severities: ["critical"], sources: [], kinds: [] },
      actions: [{ kind: "delay", params: { seconds: 1 } }],
      dedupeKey: "",
    });

    // high severity: the critical-only playbook must NOT fire
    const high = await service.triggerIngest(1, {
      kind: "incident_severity",
      triggerRef: "incident:INC-0010",
      payload: { severity: "high", source: "ips_event" },
    });
    expect(high.runs).toHaveLength(1);
    expect(high.runs[0].playbookName).toBe("any-sev");

    // critical severity: both enabled incident_severity playbooks fire
    const crit = await service.triggerIngest(1, {
      kind: "incident_severity",
      triggerRef: "incident:INC-0011",
      payload: { severity: "critical", source: "ips_event" },
    });
    expect(crit.runs.map((r) => r.playbookName).sort()).toEqual(["any-sev", "crit-only"]);
    expect(crit.runs.every((r) => r.status === "success")).toBe(true);

    // non-matching kind fires nothing; disabled playbooks never fire
    const none = await service.triggerIngest(1, { kind: "incident_created", triggerRef: "incident:INC-0012", payload: {} });
    expect(none.runs.map((r) => r.playbookName)).toEqual(["other-kind"]);
  });

  it("runs ordered actions sequentially across kinds in one playbook", async () => {
    const pb = await service.createPlaybook(1, {
      name: "full-chain",
      enabled: true,
      triggerKind: "incident_severity",
      triggerFilter: { severities: ["critical"], sources: [], kinds: [] },
      actions: [
        { kind: "notify", params: { title: "Chain", message: "step 1" } },
        { kind: "create_incident", params: { title: "Chain case", severity: "critical" } },
        { kind: "block_ip", params: { ip: "198.51.100.7", direction: "out" } },
        { kind: "delay", params: { seconds: 5 } },
      ],
      dedupeKey: "",
    });

    const res = await service.triggerIngest(1, {
      kind: "incident_severity",
      triggerRef: "incident:INC-0020",
      payload: { severity: "critical", source: "ips_event" },
      srcIps: ["198.51.100.7"],
    });
    expect(res.runs).toHaveLength(1);
    const run = res.runs[0];
    expect(run.playbookName).toBe("full-chain");
    expect(run.status).toBe("success");
    expect(run.steps.map((s) => s.kind)).toEqual(["notify", "create_incident", "block_ip", "delay"]);

    const incident = await db.incident.findFirstOrThrow({ where: { tenantId: 1, sourceRef: "incident:INC-0020" } });
    expect(incident.severity).toBe("critical");
    // direction=out → destination-side block (dstAddrIds)
    const rule = await db.firewallRule.findFirstOrThrow({ where: { tenantId: 1, name: "SOAR auto-block 198.51.100.7" } });
    expect(JSON.parse(rule.dstAddrIds)).toHaveLength(1);
    expect(JSON.parse(rule.srcAddrIds)).toEqual([]);
  });
});

describe("runs list + stats + CRUD", () => {
  it("lists runs paginated with playbook names and status filter", async () => {
    const pbA = await service.createPlaybook(1, {
      name: "list-a",
      enabled: true,
      triggerKind: "incident_created",
      triggerFilter: {},
      actions: [{ kind: "notify", params: { title: "a", message: "a" } }],
      dedupeKey: "",
    });
    const pbB = await service.createPlaybook(1, {
      name: "list-b",
      enabled: true,
      triggerKind: "dlp_incident",
      triggerFilter: {},
      actions: [{ kind: "delay", params: { seconds: 1 } }],
      dedupeKey: "",
    });
    await service.runPlaybookById(1, pbA.id, { triggerRef: "incident:INC-0001" });
    await service.runPlaybookById(1, pbB.id, { triggerRef: "dlp_incident:1" });
    await service.runPlaybookById(1, pbB.id, { triggerRef: "dlp_incident:2" });

    const all = await service.listRuns(1, { page: 1, limit: 2 });
    expect(all.meta.total).toBe(3);
    expect(all.data).toHaveLength(2);
    expect(all.data.every((r) => r.playbookName.length > 0)).toBe(true);

    const onlyB = await service.listRuns(1, { page: 1, limit: 25, playbookId: pbB.id });
    expect(onlyB.meta.total).toBe(2);

    const noFailed = await service.listRuns(1, { page: 1, limit: 25, status: "failed" });
    expect(noFailed.data).toEqual([]);
  });

  it("aggregates stats: totals, terminal success rate, 7d and per-kind counts", async () => {
    const pb1 = await service.createPlaybook(1, {
      name: "stats-a",
      enabled: true,
      triggerKind: "incident_created",
      triggerFilter: {},
      actions: [{ kind: "notify", params: { title: "s", message: "s" } }],
      dedupeKey: "",
    });
    const pb2 = await service.createPlaybook(1, {
      name: "stats-b",
      enabled: false,
      triggerKind: "dlp_incident",
      triggerFilter: {},
      actions: [{ kind: "notify", params: { title: "s", message: "s" } }],
      dedupeKey: "stats-dedupe",
    });

    await service.runPlaybookById(1, pb1.id, { triggerRef: "incident:INC-0001" }); // success
    await withFailingNotify(() => service.runPlaybookById(1, pb1.id, { triggerRef: "incident:INC-0002" })); // failed
    await service.runPlaybookById(1, pb2.id, { triggerRef: "dlp_incident:1" }); // success
    await service.runPlaybookById(1, pb2.id, { triggerRef: "dlp_incident:1" }); // skipped (dedupe)

    const stats = await service.getStats(1);
    expect(stats.playbooks).toEqual({ total: 2, enabled: 1 });
    expect(stats.runs.total).toBe(4);
    expect(stats.runs.success).toBe(2);
    expect(stats.runs.failed).toBe(1);
    expect(stats.runs.skipped).toBe(1);
    expect(stats.runs.running).toBe(0);
    expect(stats.runs.last7d).toBe(4);
    expect(stats.runs.successRate).toBe(67); // 2/(2+1) over terminal runs
    expect(stats.byTriggerKind).toMatchObject({ incident_created: 1, dlp_incident: 1 });
  });

  it("CRUD: rename conflict, partial update and delete cascades run rows", async () => {
    const pb = await service.createPlaybook(1, {
      name: "crud",
      enabled: true,
      triggerKind: "ioc_hit",
      triggerFilter: {},
      actions: [{ kind: "delay", params: { seconds: 1 } }],
      dedupeKey: "",
    });
    await service.runPlaybookById(1, pb.id, { triggerRef: "ioc:crud" });

    await expect(service.createPlaybook(1, {
      name: "crud",
      enabled: true,
      triggerKind: "ioc_hit",
      triggerFilter: {},
      actions: [{ kind: "delay", params: { seconds: 1 } }],
      dedupeKey: "",
    })).rejects.toThrow(/already exists/);

    const updated = await service.updatePlaybook(1, pb.id, { name: "crud-v2", actions: [{ kind: "notify", params: { title: "n", message: "m" } }] });
    expect(updated.name).toBe("crud-v2");
    expect(updated.actions[0].kind).toBe("notify");
    expect(updated.triggerKind).toBe("ioc_hit"); // untouched field survives a partial update

    await expect(service.deletePlaybook(1, 987654)).rejects.toThrow(/not found/i);
    await service.deletePlaybook(1, pb.id);
    expect(await db.soarPlaybook.count({ where: { id: pb.id } })).toBe(0);
    expect(await db.soarPlaybookRun.count({ where: { playbookId: pb.id } })).toBe(0);
  });
});
