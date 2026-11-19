/**
 * Logs/report-surface fixes (F-e) — vitest over a per-run copy of the dev
 * SQLite schema (same harness as tests/batch-pdf.test.ts):
 *   • F-e #18 — LIKE escaping: escapeLike() unit semantics + real `contains`
 *     queries where %/_/\\ in `q` match literally (Prisma SQLite adds ESCAPE '\').
 *   • F-e #15 — report schedules are no longer inert: runReportSchedule bumps
 *     lastRunAt AND creates an actual ReportRun (source "schedule").
 *   • F-e #17 — the PCI retention control measures the oldest retained
 *     firewall-log timestamp instead of a fresh-row ratio.
 */

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "fe-logs-"));
const DB_PATH = path.join(TMP_DIR, "fe-logs-test.db");
fs.copyFileSync(path.resolve(process.cwd(), "db/cryptsk.db"), DB_PATH);
process.env.DATABASE_URL = `file:${DB_PATH}`;

const { db } = await import("@/lib/db");
const { escapeLike, listFirewallLogs, runReportSchedule } = await import("@/lib/logs/service");
const { buildChecklist } = await import("@/app/api/v1/reports/engine");

const SRC_MARKER = "198.51.100.177";

async function seedFirewallLog(ruleName: string, ageDays: number): Promise<number> {
  const row = await db.firewallLog.create({
    data: {
      tenantId: 1,
      timestamp: new Date(Date.now() - ageDays * 86_400_000),
      srcIp: SRC_MARKER,
      dstIp: "198.51.100.9",
      srcPort: 1000,
      dstPort: 80,
      protocol: "tcp",
      action: "allow",
      ruleName,
      appName: null,
      bytes: 100,
      packets: 1,
      userName: null,
    },
  });
  return row.id;
}

beforeAll(async () => {
  await db.tenant.upsert({ where: { id: 1 }, update: {}, create: { id: 1, name: "fe-logs-test" } });
});

afterAll(async () => {
  await db.$disconnect();
  fs.rmSync(TMP_DIR, { recursive: true, force: true });
});

// ── F-e #18 — LIKE escaping ─────────────────────────────────────────────────

describe("escapeLike + listFirewallLogs q semantics (F-e #18)", () => {
  it("escapes %, _ and \\ in the search term", () => {
    expect(escapeLike("plain")).toBe("plain");
    expect(escapeLike("50%_off\\dir")).toBe("50\\%\\_off\\\\dir");
  });

  it("closes LIKE wildcard injection — q with % no longer matches every row", async () => {
    const plainId = await seedFirewallLog("plain-rule", 0);
    try {
      const total = await db.firewallLog.count({ where: { tenantId: 1 } });
      expect(total).toBeGreaterThan(0);
      // pre-fix, q="%" was a bare LIKE wildcard and matched EVERY row; post-fix
      // the escaped term matches nothing (no row contains a literal "%" here)
      const res = await listFirewallLogs(1, { q: "%", page: 1, limit: 25 } as Parameters<typeof listFirewallLogs>[1]);
      expect(res.rows.map((r) => r.id)).not.toContain(plainId);
      expect(res.meta.total).toBe(0);
      // plain substring searches are unaffected
      const res2 = await listFirewallLogs(1, { q: "plain-rule", page: 1, limit: 25 } as Parameters<typeof listFirewallLogs>[1]);
      expect(res2.rows.map((r) => r.id)).toContain(plainId);
    } finally {
      await db.firewallLog.deleteMany({ where: { id: plainId } });
    }
  });
});

// ── F-e #15 — report schedules actually run ─────────────────────────────────

describe("runReportSchedule creates a real ReportRun (F-e #15)", () => {
  it("bumps lastRunAt AND persists a schedule-sourced report run", async () => {
    const schedule = await db.reportSchedule.create({
      data: {
        tenantId: 1,
        name: "fe-sched-test",
        range: "daily",
        format: "pdf",
        sections: JSON.stringify(["traffic"]),
        enabled: true,
      },
    });
    try {
      const res = await runReportSchedule(1, schedule.id);
      expect(res.ok).toBe(true);
      expect(typeof res.lastRunAt).toBe("string");
      expect(res.run).toBeDefined();

      const bumped = await db.reportSchedule.findUniqueOrThrow({ where: { id: schedule.id } });
      expect(bumped.lastRunAt).not.toBeNull();

      const run = await db.reportRun.findUniqueOrThrow({ where: { id: res.run!.id } });
      expect(run.source).toBe("schedule");
      expect(run.scheduleId).toBe(schedule.id);
      expect(run.status).toBe("done");
      expect(run.contentHtml).toContain("fe-sched-test");
    } finally {
      await db.reportRun.deleteMany({ where: { scheduleId: schedule.id } });
      await db.reportSchedule.delete({ where: { id: schedule.id } });
    }
  });
});

// ── F-e #17 — PCI retention control measures actual retention ───────────────

describe("PCI checklist retention control (F-e #17)", () => {
  const seededIds: number[] = [];

  afterAll(async () => {
    if (seededIds.length) await db.firewallLog.deleteMany({ where: { id: { in: seededIds } } });
  });

  it("passes when the oldest retained firewall log is ≥ 90 days old", async () => {
    seededIds.push(await seedFirewallLog("fe-pci-old", 100));
    seededIds.push(await seedFirewallLog("fe-pci-new", 0));
    const rows = await buildChecklist(1, "PCI");
    const retention = rows.find((r) => r.control === "Log retention ≥ 90 days");
    expect(retention?.pass).toBe(true);
    expect(retention?.detail).toMatch(/oldest retained firewall log is \d+ days old/);
  });

  it("fails when every retained row is fresh (< 90 days) even though rows exist", async () => {
    // drop the old row — only fresh rows remain
    await db.firewallLog.deleteMany({ where: { id: { in: seededIds }, timestamp: { lt: new Date(Date.now() - 90 * 86_400_000) } } });
    seededIds.length = 0;
    const fresh = await db.firewallLog.create({
      data: {
        tenantId: 1,
        timestamp: new Date(),
        srcIp: SRC_MARKER,
        dstIp: "198.51.100.9",
        srcPort: 1000,
        dstPort: 80,
        protocol: "tcp",
        action: "allow",
        ruleName: "fe-pci-fresh-only",
        appName: null,
        bytes: 1,
        packets: 1,
        userName: null,
      },
    });
    try {
      const rows = await buildChecklist(1, "PCI");
      const retention = rows.find((r) => r.control === "Log retention ≥ 90 days");
      // the dev-schema copy carries rows whose oldest is ~30 days — well short
      // of the 90-day window, so the control must FAIL on actual measurement
      expect(retention?.pass).toBe(false);
      const days = Number(/oldest retained firewall log is (\d+) days old/.exec(retention?.detail ?? "")?.[1] ?? NaN);
      expect(days).toBeLessThan(90);
    } finally {
      await db.firewallLog.delete({ where: { id: fresh.id } });
    }
  });
});
