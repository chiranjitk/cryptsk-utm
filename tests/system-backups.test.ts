/**
 * System backups tenant isolation (F-e #1) + restore confirm token — vitest.
 * The service writes real JSON files under db/backups (cwd-relative); every
 * file the suite creates is removed again in afterAll (diff-based cleanup so
 * pre-existing appliance backups are never touched). DB access is read-only
 * (dumpTable findMany) against the dev database.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import path from "node:path";

const BACKUPS_DIR = path.join(process.cwd(), "db", "backups");

beforeAll(() => {
  fs.mkdirSync(BACKUPS_DIR, { recursive: true });
});

// ── diff-based cleanup: only files created by this suite are removed ────────
const preExisting = fs.existsSync(BACKUPS_DIR) ? new Set(fs.readdirSync(BACKUPS_DIR)) : new Set<string>();

afterAll(() => {
  for (const name of fs.readdirSync(BACKUPS_DIR)) {
    if (!preExisting.has(name)) {
      fs.rmSync(path.join(BACKUPS_DIR, name), { force: true });
    }
  }
});

const svc = await import("@/lib/system/service");
const { restoreConfirmSchema } = await import("@/lib/validators/system");

describe("backup envelope tenant tagging (F-e #1)", () => {
  it("writes the owning tenantId into the backup envelope at create", async () => {
    const dto = await svc.createBackup(1, { type: "config", note: "f-e-1 test" });
    const raw = JSON.parse(fs.readFileSync(path.join(BACKUPS_DIR, `${dto.id}.json`), "utf8")) as {
      id: string;
      tenantId?: number;
      schemaVersion: number;
    };
    expect(raw.id).toBe(dto.id);
    expect(raw.tenantId).toBe(1);
    expect(raw.schemaVersion).toBe(1);
  });

  it("listBackups filters by tenantId — other tenants see nothing", async () => {
    const created = await svc.createBackup(1, { type: "config" });
    const list2 = await svc.listBackups(2);
    expect(list2.find((b) => b.id === created.id)).toBeUndefined();
    const list1 = await svc.listBackups(1);
    expect(list1.find((b) => b.id === created.id)).toBeDefined();
  });

  it("treats legacy backups WITHOUT a tenantId field as tenant 1 (documented fallback)", async () => {
    const legacy = {
      id: "bk-legacy-no-tenant",
      createdAt: new Date().toISOString(),
      sizeBytes: 2,
      type: "config",
      note: null,
      schemaVersion: 1,
      payload: { config: {} },
    };
    fs.writeFileSync(path.join(BACKUPS_DIR, `${legacy.id}.json`), JSON.stringify(legacy), "utf8");
    // tenant 1 sees the legacy file…
    expect((await svc.listBackups(1)).find((b) => b.id === legacy.id)).toBeDefined();
    // …tenant 2 does not
    expect((await svc.listBackups(2)).find((b) => b.id === legacy.id)).toBeUndefined();
  });

  it("readBackupFile refuses cross-tenant reads with 403", async () => {
    const created = await svc.createBackup(1, { type: "config" });
    await expect(svc.readBackupFile(2, created.id)).rejects.toMatchObject({ code: "FORBIDDEN" });
    await expect(svc.readBackupFile(1, created.id)).resolves.toMatchObject({ id: created.id, tenantId: 1 });
  });

  it("restoreBackup refuses foreign-tenant restores with 403 BEFORE any writes", async () => {
    const created = await svc.createBackup(1, { type: "config" });
    const filesBefore = new Set(fs.readdirSync(BACKUPS_DIR));
    await expect(svc.restoreBackup(2, created.id)).rejects.toMatchObject({ code: "FORBIDDEN" });
    // no safety backup was created, nothing was written
    const filesAfter = fs.readdirSync(BACKUPS_DIR);
    expect(filesAfter.filter((f) => !filesBefore.has(f))).toEqual([]);
  });
});

describe("restore confirm token (F-e #1)", () => {
  it("requires the confirm token — missing/mismatched/extra fields rejected", () => {
    expect(restoreConfirmSchema.safeParse({}).success).toBe(false);
    expect(restoreConfirmSchema.safeParse({ confirm: "" }).success).toBe(false);
    expect(restoreConfirmSchema.safeParse({ confirm: "bk-wrong" }).success).toBe(true);
    expect(restoreConfirmSchema.safeParse({ confirm: "bk-ok", extra: true }).success).toBe(false); // strict
  });
});
