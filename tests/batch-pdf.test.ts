/**
 * T2-b tests — batch operations endpoint (spec §1.15) + dependency-free PDF
 * writer (spec §1.12 formats: PDF).
 *
 * Batch: whitelist rejection (unknown path → per-op error, NOT a crash),
 * sequential stop-on-first-error semantics, path → RBAC area mapping, and the
 * max-20 schema cap. The executor runs over a per-run copy of the pushed dev
 * schema (same harness as tests/incidents.test.ts — DATABASE_URL is overridden
 * BEFORE the db-backed modules are dynamically imported).
 *
 * PDF: valid %PDF header + %%EOF, xref offset roundtrip (parse startxref →
 * every entry points exactly at its "N 0 obj" marker, trailer present),
 * multi-page content split with footer page numbers, and table row rendering
 * asserted against a raw latin1 decode (content streams are uncompressed on
 * purpose, so the row text is directly visible in the buffer).
 */

import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// pure modules — no db dependency, safe to import statically
import { renderPdf } from "@/lib/reports/pdf";
import { BATCH_MAX_OPERATIONS, batchRequestSchema } from "@/lib/validators/batch";

// ── DB harness (imports AFTER the DATABASE_URL override, like incidents.test.ts) ──

const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "batch-pdf-"));
const DB_PATH = path.join(TMP_DIR, "batch-pdf-test.db");
fs.copyFileSync(path.resolve(process.cwd(), "db/cryptsk.db"), DB_PATH);
process.env.DATABASE_URL = `file:${DB_PATH}`;

const { db } = await import("@/lib/db");
const batch = await import("@/lib/api/batch");

const NAME_PREFIX = "batch-pdf-test-";
const adminAuth = { kind: "user" as const, role: "tenant_admin" as const, tenantId: 1, username: "batch-tester" };
const helpdeskAuth = { kind: "user" as const, role: "helpdesk" as const, tenantId: 1, username: "batch-helpdesk" };

const ipBody = (name: string) => ({ name, type: "ip", value: "198.51.100.7" });

beforeAll(async () => {
  // the copied dev schema has no tenant rows — batch rows FK to tenants
  await db.tenant.upsert({ where: { id: 1 }, update: {}, create: { id: 1, name: "batch-pdf-test" } });
});

beforeEach(async () => {
  await db.addressObject.deleteMany({ where: { name: { startsWith: NAME_PREFIX } } });
});

afterAll(async () => {
  await db.$disconnect();
  fs.rmSync(TMP_DIR, { recursive: true, force: true });
});

// ── batch: whitelist ────────────────────────────────────────────────────────

describe("batch whitelist", () => {
  it("rejects a non-whitelisted path as a per-op error without crashing", async () => {
    const out = await batch.executeBatchOperations(adminAuth, [
      { method: "POST", path: "/zones", body: { name: "evil" } },
    ]);
    expect(out.results).toHaveLength(1);
    expect(out.results[0]).toMatchObject({ index: 0, path: "/zones", method: "POST", ok: false });
    expect(out.results[0].status).toBe(400);
    expect(out.results[0].error).toMatch(/not batch-whitelisted/i);
    expect(out.ok).toBe(false);
    expect(out.executed).toBe(0); // F-e #9 semantics: failed/denied ops are not "executed"
    expect(out.failed).toBe(1);
    expect(await db.zone.count({ where: { name: "evil" } })).toBe(0);
  });

  it("rejects deep paths, non-numeric ids and query strings", async () => {
    for (const badPath of ["/address-objects/12/children", "/address-objects/abc", "/address-objects?x=1", "address-objects", ""]) {
      const out = await batch.executeBatchOperations(adminAuth, [{ method: "DELETE", path: badPath }]);
      expect(out.results[0].ok, badPath).toBe(false);
      expect(out.results[0].status, badPath).toBe(400);
    }
  });
});

// ── batch: sequential + stop-on-first-error ────────────────────────────────

describe("batch stop-on-first-error", () => {
  it("executes sequentially and stops at the first failing operation", async () => {
    const out = await batch.executeBatchOperations(adminAuth, [
      { method: "POST", path: "/address-objects", body: ipBody(`${NAME_PREFIX}first`) },
      { method: "POST", path: "/address-objects", body: ipBody(`${NAME_PREFIX}first`) }, // duplicate → 409
      { method: "POST", path: "/address-objects", body: ipBody(`${NAME_PREFIX}third`) },
    ]);
    expect(out.results.map((r) => r.ok)).toEqual([true, false]);
    expect(out.results[1].status).toBe(409);
    expect(out.results[1].error).toMatch(/already exists/i);
    expect(out.executed).toBe(1); // F-e #9 semantics: SUCCESSFUL ops only
    expect(out.failed).toBe(1);
    expect(out.ok).toBe(false);
    expect(out.results).toHaveLength(2);
    // the third operation was never attempted
    expect(await db.addressObject.count({ where: { name: `${NAME_PREFIX}third` } })).toBe(0);
    expect(await db.addressObject.count({ where: { name: `${NAME_PREFIX}first` } })).toBe(1);
  });

  it("runs a full create → update → delete roundtrip through the same service paths", async () => {
    const created = await batch.executeBatchOperations(adminAuth, [
      { method: "POST", path: "/address-objects", body: ipBody(`${NAME_PREFIX}round`) },
    ]);
    expect(created.ok).toBe(true);
    const id = (created.results[0].data as { id: number }).id;
    expect(id).toBeGreaterThan(0);

    const updated = await batch.executeBatchOperations(adminAuth, [
      {
        method: "PUT",
        path: `/address-objects/${id}`,
        body: { name: `${NAME_PREFIX}round2`, type: "ip", value: "203.0.113.9" },
      },
    ]);
    expect(updated.ok).toBe(true);
    expect((updated.results[0].data as { value: string }).value).toBe("203.0.113.9");

    const deleted = await batch.executeBatchOperations(adminAuth, [
      { method: "DELETE", path: `/address-objects/${id}` },
    ]);
    expect(deleted.ok).toBe(true);
    expect(await db.addressObject.count({ where: { id } })).toBe(0);
  });
});

// ── batch: RBAC mapping ─────────────────────────────────────────────────────

describe("batch RBAC mapping", () => {
  it("maps every whitelisted path family to its capability area", () => {
    expect(batch.pathToArea("/address-objects")).toBe("firewall");
    expect(batch.pathToArea("/service-objects/12")).toBe("firewall");
    expect(batch.pathToArea("/schedule-objects")).toBe("firewall");
    expect(batch.pathToArea("/firewall-rules")).toBe("firewall");
    expect(batch.pathToArea("/nat-rules/9")).toBe("firewall");
    expect(batch.pathToArea("/address-groups")).toBe("firewall");
    expect(batch.pathToArea("/service-groups/3")).toBe("firewall");
    // not whitelisted → no area at all
    expect(batch.pathToArea("/zones")).toBeNull();
    expect(batch.pathToArea("/users")).toBeNull();
  });

  it("denies a write role outside the mapped area with a 403 op error", async () => {
    const out = await batch.executeBatchOperations(helpdeskAuth, [
      { method: "POST", path: "/address-objects", body: ipBody(`${NAME_PREFIX}denied`) },
    ]);
    expect(out.results).toHaveLength(1);
    expect(out.results[0].ok).toBe(false);
    expect(out.results[0].status).toBe(403);
    expect(out.results[0].error).toMatch(/may not write firewall/i);
    expect(out.executed).toBe(0); // F-e #9: the route gates the config-version snapshot on this
    expect(out.failed).toBe(1);
    expect(await db.addressObject.count({ where: { name: `${NAME_PREFIX}denied` } })).toBe(0);
  });

  it("masks unexpected executor errors (F-e #8) — no internal message leaks into the result", async () => {
    const leakSpy = vi.spyOn(db.addressObject, "findFirst").mockRejectedValueOnce(new TypeError("E_SECRET_INTERNAL pg://admin:hunter2@db"));
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const out = await batch.executeBatchOperations(
        adminAuth,
        [{ method: "POST", path: "/address-objects", body: ipBody(`${NAME_PREFIX}masked`) }],
        "req-f-e8", // requestId — echoed into the server-side error log
      );
      expect(out.ok).toBe(false);
      expect(out.results[0].status).toBe(500);
      expect(out.results[0].error).toBe("Internal error during batch operation");
      expect(out.results[0].error).not.toContain("hunter2"); // internals never leak
      // details are logged server-side with the requestId for correlation
      expect(errSpy).toHaveBeenCalledWith(expect.stringContaining("[batch] req-f-e8"), expect.anything());
    } finally {
      leakSpy.mockRestore();
      errSpy.mockRestore();
    }
  });
});

// ── batch: max-20 cap ───────────────────────────────────────────────────────

describe("batch max-20 rejection", () => {
  it("rejects a batch over the 20-operation cap at the schema level", () => {
    const ops = Array.from({ length: BATCH_MAX_OPERATIONS + 1 }, (_, i) => ({
      method: "POST" as const,
      path: "/address-objects",
      body: ipBody(`${NAME_PREFIX}x${i}`),
    }));
    const rejected = batchRequestSchema.safeParse({ operations: ops });
    expect(rejected.success).toBe(false);
    const accepted = batchRequestSchema.safeParse({ operations: ops.slice(0, BATCH_MAX_OPERATIONS) });
    expect(accepted.success).toBe(true);
  });

  it("rejects empty batches and unknown methods at the schema level", () => {
    expect(batchRequestSchema.safeParse({ operations: [] }).success).toBe(false);
    expect(
      batchRequestSchema.safeParse({ operations: [{ method: "GET", path: "/address-objects" }] }).success,
    ).toBe(false);
    expect(batchRequestSchema.safeParse({ operations: [{ method: "POST", path: "address-objects" }] }).success).toBe(false);
  });

  it("guards the cap defensively inside the executor too", async () => {
    const ops = Array.from({ length: BATCH_MAX_OPERATIONS + 1 }, (_, i) => ({
      method: "POST" as const,
      path: "/address-objects",
      body: ipBody(`${NAME_PREFIX}y${i}`),
    }));
    await expect(batch.executeBatchOperations(adminAuth, ops)).rejects.toThrow(/20-operation cap/);
  });
});

// ── pdf writer ──────────────────────────────────────────────────────────────

const sampleDoc = {
  title: "Traffic report",
  subtitle: "Tenant: lab · Range: daily",
  sections: [
    {
      heading: "Traffic",
      table: { headers: ["Source IP", "Action", "Hits"], rows: [["198.51.100.23", "deny", "42"]] },
    },
    { heading: "Notes", text: "Generated from live conntrack samples.\nSecond paragraph line." },
  ],
};

describe("renderPdf syntax", () => {
  it("emits a valid %PDF header and %%EOF trailer", () => {
    const buf = renderPdf(sampleDoc);
    expect(buf.length).toBeGreaterThan(200);
    expect(buf.subarray(0, 8).toString("latin1")).toBe("%PDF-1.4");
    expect(buf.toString("latin1").trimEnd().endsWith("%%EOF")).toBe(true);
  });

  it("computes xref offsets that roundtrip to the real object positions", () => {
    const s = renderPdf(sampleDoc).toString("latin1");
    const startxref = Number(/startxref\s+(\d+)\s*%%EOF/.exec(s)![1]);
    expect(s.slice(startxref, startxref + 4)).toBe("xref");

    // parse the xref table: "0 N" then N 20-byte entries
    const lines = s.slice(startxref).split("\n");
    const size = Number(lines[1].trim().split(/\s+/)[1]);
    expect(size).toBeGreaterThan(5);
    for (let objId = 1; objId < size; objId++) {
      const entry = lines[2 + objId];
      const off = Number(entry.slice(0, 10));
      expect(s.slice(off, off + `${objId} 0 obj`.length)).toBe(`${objId} 0 obj`);
    }
    // trailer present with the catalog root
    expect(s).toMatch(/trailer\s*<<[\s\S]*\/Root 1 0 R[\s\S]*>>/);
    expect(s).toContain("/Type /Catalog");
    expect(s).toContain("/Type /Pages");
  });
});

describe("renderPdf layout", () => {
  it("splits long content across multiple pages with footer page numbers", () => {
    const sections = Array.from({ length: 80 }, (_, i) => ({
      heading: `Section ${i}`,
      text: `Paragraph ${i} — ${"lorem ipsum dolor sit amet consectetur adipiscing elit ".repeat(6)}`,
    }));
    const s = renderPdf({ title: "Long report", sections }).toString("latin1");
    const pageMatches = s.match(/\/Type \/Page(?![a-zA-Z])/g) ?? [];
    expect(pageMatches.length).toBeGreaterThan(1);
    expect(s).toContain(`/Count ${pageMatches.length}`);
    expect(s).toContain("Page 1 of");
    expect(s).toContain(`Page ${pageMatches.length} of ${pageMatches.length}`);
  });

  it("renders table headers and rows into the raw (uncompressed) content stream", () => {
    const s = renderPdf(sampleDoc).toString("latin1");
    expect(s).toContain("(Source IP) Tj");
    expect(s).toContain("(198.51.100.23) Tj");
    expect(s).toContain("(deny) Tj");
    expect(s).toContain("(42) Tj");
    // title + heading + subtitle made it in too
    expect(s).toContain("(Traffic report) Tj");
    expect(s).toContain("(Traffic) Tj");
  });

  it("sanitizes non-ASCII input instead of producing invalid PDF strings", () => {
    const s = renderPdf({
      title: "Report ✓",
      sections: [{ heading: "Héllo", text: "café — naïve" }],
    }).toString("latin1");
    expect(s).toContain("(Report ?) Tj");
    expect(s).toContain("(caf? ? na?ve) Tj");
    // every byte after the 15-byte header (incl. the binary comment marker) is plain ASCII
    const buf2 = renderPdf({ title: "ümlaut", sections: [] });
    for (let i = 15; i < buf2.length; i++) {
      expect(buf2[i], `byte at ${i}`).toBeLessThan(128);
    }
  });
});
