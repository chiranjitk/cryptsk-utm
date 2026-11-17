/**
 * DNS tunnel-detection tests (Phase 3 §3.4) — two layers:
 *   • PURE engine (lib/dns/tunnel-detect): Shannon entropy known values,
 *     LOCKED threshold verdicts (clean / suspicious / likely_tunnel incl.
 *     every OR/AND branch), fixed-window aggregation determinism + boundary
 *     semantics (epoch-grid alignment, start-inclusive/end-exclusive), detail
 *     helpers (topDomains/longestLabels),
 *   • DB-backed service over a per-run copy of the pushed dev schema (same
 *     harness as incidents.test.ts): runDetection upsert dedupe (same
 *     client+window+verdict → row UPDATED not duplicated; verdict escalation
 *     → separate row per spec key), clean windows never persisted, honest
 *     empty-data return, status transitions, list filters, stats.
 *
 * The db/service modules are imported AFTER the DATABASE_URL override —
 * static imports would resolve the Prisma datasource too early. The service
 * accepts an explicit `queries` array (test seam) instead of the engine ring
 * so DB tests stay deterministic.
 */

import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// pure engine — no DB dependency, safe to import statically
import {
  TUNNEL_THRESHOLDS,
  aggregateWindows,
  analyzeClientWindow,
  labelsExcludingTld,
  longestLabels,
  maxLabelLengthExcludingTld,
  shannonEntropy,
  topDomains,
  verdictFor,
  type TunnelQueryInput,
} from "@/lib/dns/tunnel-detect";

const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "dns-tunnel-"));
const DB_PATH = path.join(TMP_DIR, "dns-tunnel-test.db");
fs.copyFileSync(path.resolve(process.cwd(), "db/cryptsk.db"), DB_PATH);
process.env.DATABASE_URL = `file:${DB_PATH}`;

const { db } = await import("@/lib/db");
const service = await import("@/lib/dns/tunnel-service");

// ── fixtures ────────────────────────────────────────────────────────────────

const WINDOW: { windowStart: Date; windowEnd: Date } = {
  windowStart: new Date("2025-03-01T10:00:00Z"),
  windowEnd: new Date("2025-03-01T10:15:00Z"),
};

/** ISO ts `offsetMs` after 2025-03-01T10:00:00Z. */
function at(offsetMs: number): string {
  return new Date(Date.UTC(2025, 2, 1, 10, 0, 0) + offsetMs).toISOString();
}
const MIN = 60_000;

/** 25 low-entropy subdomains → suspicious via the uniqueDomains branch only. */
function lowEntropyDomains(n: number): string[] {
  return Array.from({ length: n }, (_, i) => `d${String(i).padStart(2, "0")}.corp.local`);
}

const HIGH_ENTROPY_DOMAIN = "t7zk9x2m4q8v5p1n6r3w0e.example.com"; // 22 distinct label chars

/** n unique high-entropy domains (indexed suffix keeps them distinct). */
function highEntropyDomains(n: number): string[] {
  return Array.from({ length: n }, (_, i) => `t7zk9x2m4q8v5p1n6r3w0e${String(i).padStart(2, "0")}.example.com`);
}

beforeAll(async () => {
  // the copied dev schema has no tenant rows — finding rows FK to tenants
  await db.tenant.upsert({ where: { id: 1 }, update: {}, create: { id: 1, name: "dns-tunnel-test" } });
});

beforeEach(async () => {
  await db.dnsTunnelFinding.deleteMany({});
});

afterAll(async () => {
  await db.$disconnect();
  fs.rmSync(TMP_DIR, { recursive: true, force: true });
});

// ── shannonEntropy ──────────────────────────────────────────────────────────

describe("shannonEntropy", () => {
  it("returns 0 for empty strings and single-symbol strings", () => {
    expect(shannonEntropy("")).toBe(0);
    expect(shannonEntropy("aaaa")).toBe(0);
  });

  it("returns the known values for uniform two-symbol strings", () => {
    expect(shannonEntropy("ab")).toBeCloseTo(1, 10);
    expect(shannonEntropy("aabb")).toBeCloseTo(1, 10);
  });

  it("matches log2(alphabet) when every symbol occurs once", () => {
    expect(shannonEntropy("abcdefghij")).toBeCloseTo(Math.log2(10), 10);
  });

  it("keeps normal corp domains well under the suspicious entropy bar", () => {
    expect(shannonEntropy("corp.local")).toBeLessThan(3.5);
    expect(shannonEntropy("intranet.corp.local")).toBeLessThan(3.5);
    expect(shannonEntropy(HIGH_ENTROPY_DOMAIN)).toBeGreaterThan(4.2);
  });
});

// ── LOCKED thresholds ───────────────────────────────────────────────────────

describe("TUNNEL_THRESHOLDS (spec §3.4)", () => {
  it("exposes the locked rule values", () => {
    expect(TUNNEL_THRESHOLDS.suspicious).toEqual({ entropy: 3.5, uniqueDomains: 25, maxLabelLength: 45 });
    expect(TUNNEL_THRESHOLDS.likelyTunnel).toEqual({ entropy: 4.2, uniqueDomains: 40, queryCount: 100 });
  });
});

// ── verdict branches ────────────────────────────────────────────────────────

describe("analyzeClientWindow verdicts", () => {
  const client = { clientIp: "192.168.10.5" };

  it("marks ordinary corp traffic clean (low entropy, few domains, short labels)", () => {
    const stats = analyzeClientWindow(
      ["corp.local", "intranet.corp.local", "nas.corp.local"].map((domain, i) => ({ ...client, domain, ts: at(i * 1000) })),
      WINDOW,
    );
    expect(stats).toHaveLength(1);
    expect(stats[0].verdict).toBe("clean");
    expect(stats[0].avgDomainEntropy).toBeLessThan(TUNNEL_THRESHOLDS.suspicious.entropy);
    expect(stats[0].queryCount).toBe(3);
    expect(stats[0].uniqueDomains).toBe(3);
  });

  it("flags suspicious via the uniqueDomains OR branch (entropy stays low)", () => {
    const queries = lowEntropyDomains(25).map((domain, i) => ({ ...client, domain, ts: at(i * 1000) }));
    const [stat] = analyzeClientWindow(queries, WINDOW);
    expect(stat!.uniqueDomains).toBe(25);
    expect(stat!.avgDomainEntropy).toBeLessThan(TUNNEL_THRESHOLDS.suspicious.entropy);
    expect(stat!.maxLabelLength).toBeLessThan(TUNNEL_THRESHOLDS.suspicious.maxLabelLength);
    expect(stat!.verdict).toBe("suspicious");
  });

  it("flags suspicious via the entropy OR branch without the likely AND (1 domain, 2 queries)", () => {
    const queries = [0, 1].map((i) => ({ ...client, domain: HIGH_ENTROPY_DOMAIN, ts: at(i * MIN) }));
    const [stat] = analyzeClientWindow(queries, WINDOW);
    expect(stat!.avgDomainEntropy).toBeGreaterThanOrEqual(TUNNEL_THRESHOLDS.likelyTunnel.entropy);
    expect(stat!.uniqueDomains).toBeLessThan(TUNNEL_THRESHOLDS.likelyTunnel.uniqueDomains);
    expect(stat!.queryCount).toBeLessThan(TUNNEL_THRESHOLDS.likelyTunnel.queryCount);
    expect(stat!.verdict).toBe("suspicious");
  });

  it("flags suspicious via the maxLabelLength OR branch (45-char label, low entropy)", () => {
    const domain = `${"a".repeat(45)}.example.com`;
    const [stat] = analyzeClientWindow([{ ...client, domain, ts: at(0) }], WINDOW);
    expect(stat!.maxLabelLength).toBe(45);
    expect(stat!.avgDomainEntropy).toBeLessThan(TUNNEL_THRESHOLDS.suspicious.entropy);
    expect(stat!.verdict).toBe("suspicious");
  });

  it("flags likely_tunnel via queryCount ≥ 100 with high entropy", () => {
    const queries = Array.from({ length: 100 }, (_, i) => ({ ...client, domain: HIGH_ENTROPY_DOMAIN, ts: at(i * 1000) }));
    const [stat] = analyzeClientWindow(queries, WINDOW);
    expect(stat!.queryCount).toBe(100);
    expect(stat!.uniqueDomains).toBe(1);
    expect(stat!.verdict).toBe("likely_tunnel");
  });

  it("flags likely_tunnel via uniqueDomains ≥ 40 with high entropy", () => {
    const queries = highEntropyDomains(40).map((domain, i) => ({ ...client, domain, ts: at(i * 1000) }));
    const [stat] = analyzeClientWindow(queries, WINDOW);
    expect(stat!.uniqueDomains).toBe(40);
    expect(stat!.avgDomainEntropy).toBeGreaterThanOrEqual(TUNNEL_THRESHOLDS.likelyTunnel.entropy);
    expect(stat!.verdict).toBe("likely_tunnel");
  });

  it("computes maxLabelLength excluding the TLD and keeps clients sorted", () => {
    const queries: TunnelQueryInput[] = [
      { clientIp: "192.168.10.9", domain: "aabbccdd.example.com", ts: at(0) },
      { clientIp: "192.168.10.2", domain: "www.google.com", ts: at(1000) },
      { clientIp: "192.168.10.9", domain: "localhost", ts: at(2000) },
    ];
    const stats = analyzeClientWindow(queries, WINDOW);
    expect(stats.map((s) => s.clientIp)).toEqual(["192.168.10.2", "192.168.10.9"]);
    expect(maxLabelLengthExcludingTld("aabbccdd.example.com")).toBe(8); // "aabbccdd", "example" — "com" excluded
    expect(maxLabelLengthExcludingTld("www.google.com")).toBe(6);
    expect(maxLabelLengthExcludingTld("localhost")).toBe(9); // single-label name: no TLD to exclude
    expect(stats[1]!.maxLabelLength).toBe(9);
    expect(labelsExcludingTld("single")).toEqual(["single"]);
  });

  it("drops rows outside the half-open window when ts is parseable", () => {
    const queries: TunnelQueryInput[] = [
      { clientIp: "10.0.0.1", domain: "a.example.com", ts: WINDOW.windowStart.toISOString() }, // start inclusive
      { clientIp: "10.0.0.1", domain: "b.example.com", ts: WINDOW.windowEnd.toISOString() }, // end exclusive
      { clientIp: "10.0.0.1", domain: "c.example.com", ts: at(5 * MIN) },
    ];
    const [stat] = analyzeClientWindow(queries, WINDOW);
    expect(stat!.queryCount).toBe(2);
    expect(stat!.uniqueDomains).toBe(2);
  });

  it("scores verdictFor directly at the locked boundaries", () => {
    expect(verdictFor({ queryCount: 1, uniqueDomains: 1, maxLabelLength: 1, avgDomainEntropy: 0 })).toBe("clean");
    expect(verdictFor({ queryCount: 1, uniqueDomains: 25, maxLabelLength: 1, avgDomainEntropy: 0 })).toBe("suspicious");
    expect(verdictFor({ queryCount: 100, uniqueDomains: 1, maxLabelLength: 1, avgDomainEntropy: 4.2 })).toBe("likely_tunnel");
    expect(verdictFor({ queryCount: 100, uniqueDomains: 1, maxLabelLength: 1, avgDomainEntropy: 4.19 })).toBe("suspicious");
  });
});

// ── fixed-window aggregation ────────────────────────────────────────────────

describe("aggregateWindows", () => {
  it("is deterministic across runs and row orderings (epoch-grid, not data-anchored)", () => {
    const base: TunnelQueryInput[] = [
      { clientIp: "10.0.0.1", domain: "alpha.example.com", ts: at(2 * MIN) },
      { clientIp: "10.0.0.2", domain: "beta.example.com", ts: at(6 * MIN) },
      { clientIp: "10.0.0.1", domain: "gamma.example.com", ts: at(7 * MIN) },
      { clientIp: "10.0.0.2", domain: HIGH_ENTROPY_DOMAIN, ts: at(31 * MIN) },
      { clientIp: "10.0.0.1", domain: "delta.example.com", ts: at(33 * MIN) },
      { clientIp: "10.0.0.2", domain: "eps.example.com", ts: at(36 * MIN) },
    ];
    const a = JSON.stringify(aggregateWindows(base, 15, 5));
    const b = JSON.stringify(aggregateWindows([...base].reverse(), 15, 5));
    const c = JSON.stringify(aggregateWindows(base, 15, 5));
    expect(a).toBe(b);
    expect(a).toBe(c);
  });

  it("aligns 15m/5m windows to the grid with start-inclusive / end-exclusive semantics", () => {
    const queries: TunnelQueryInput[] = [
      { clientIp: "10.0.0.1", domain: "probe.example.com", ts: at(7 * MIN) }, // 10:07
      { clientIp: "10.0.0.2", domain: "probe.example.com", ts: at(0) }, // exactly 10:00
      { clientIp: "10.0.0.3", domain: "probe.example.com", ts: at(15 * MIN) }, // exactly 10:15
    ];
    const windows = aggregateWindows(queries, 15, 5);
    const countAt = (iso: string) => windows.find((w) => w.windowStart.toISOString() === iso)?.clients.reduce((s, c) => s + c.queryCount, 0);

    // windows that contain 10:07: 09:55, 10:00, 10:05 — not 09:50
    expect(countAt("2025-03-01T09:50:00.000Z")).toBe(1); // only the 10:00 query
    expect(countAt("2025-03-01T09:55:00.000Z")).toBe(2); // 10:07 + 10:00
    expect(countAt("2025-03-01T10:00:00.000Z")).toBe(2); // 10:07 + 10:00 (start inclusive)
    expect(countAt("2025-03-01T10:05:00.000Z")).toBe(2); // 10:07 + 10:15 — NOT the 10:00 row (end exclusive)
    expect(countAt("2025-03-01T10:10:00.000Z")).toBe(1); // only 10:15
    expect(countAt("2025-03-01T10:15:00.000Z")).toBe(1);
    expect(windows).toHaveLength(6);

    for (const w of windows) {
      expect(w.windowEnd.getTime() - w.windowStart.getTime()).toBe(15 * MIN);
      expect(w.windowStart.getTime() % (5 * MIN)).toBe(0); // grid aligned
    }
    // clients separated inside one window, sorted by IP
    const w1005 = windows.find((w) => w.windowStart.toISOString() === "2025-03-01T10:05:00.000Z")!;
    expect(w1005.clients.map((c) => c.clientIp)).toEqual(["10.0.0.1", "10.0.0.3"]);
  });

  it("tumbles 1:1 when windowMinutes == stepMinutes", () => {
    const queries: TunnelQueryInput[] = [
      { clientIp: "10.0.0.1", domain: "a.example.com", ts: at(5 * MIN) },
      { clientIp: "10.0.0.2", domain: "b.example.com", ts: at(20 * MIN) },
    ];
    const windows = aggregateWindows(queries, 15, 15);
    expect(windows).toHaveLength(2);
    expect(windows.map((w) => w.windowStart.toISOString())).toEqual([
      "2025-03-01T10:00:00.000Z",
      "2025-03-01T10:15:00.000Z",
    ]);
    expect(windows.every((w) => w.clients.every((c) => c.queryCount === 1))).toBe(true);
  });

  it("skips rows without a parseable ts and returns [] for no usable data", () => {
    expect(aggregateWindows([{ clientIp: "10.0.0.1", domain: "a.example.com", ts: "not-a-date" }], 15, 5)).toEqual([]);
    expect(aggregateWindows([], 15, 5)).toEqual([]);
  });
});

// ── detail helpers ──────────────────────────────────────────────────────────

describe("topDomains + longestLabels", () => {
  it("ranks domains by count desc with alphabetical tie-breaks and honors the limit", () => {
    const queries: TunnelQueryInput[] = ["b.com", "a.com", "a.com", "c.com", "c.com", "c.com"].map((domain) => ({
      clientIp: "10.0.0.1",
      domain,
    }));
    expect(topDomains(queries, 10)).toEqual([
      { domain: "c.com", count: 3 },
      { domain: "a.com", count: 2 },
      { domain: "b.com", count: 1 },
    ]);
    expect(topDomains(queries, 2)).toEqual([
      { domain: "c.com", count: 3 },
      { domain: "a.com", count: 2 },
    ]);
  });

  it("returns the longest non-TLD label per domain, sorted by length desc", () => {
    const queries: TunnelQueryInput[] = ["x.example.com", "longlabel.example.org", "ab.example.net"].map((domain) => ({
      clientIp: "10.0.0.1",
      domain,
    }));
    const labels = longestLabels(queries, 10);
    expect(labels[0]).toEqual({ label: "longlabel", domain: "longlabel.example.org", length: 9 });
    expect(labels).toHaveLength(3); // one entry per unique domain
    expect(labels.every((l) => l.label !== "com" && l.label !== "org" && l.label !== "net")).toBe(true); // TLDs excluded
    expect(longestLabels(queries, 1)).toEqual([{ label: "longlabel", domain: "longlabel.example.org", length: 9 }]);
  });
});

// ── DB-backed service ───────────────────────────────────────────────────────

describe("runDetection persistence (upsert dedupe)", () => {
  it("persists suspicious client-windows once and updates metrics on re-run without duplicating rows", async () => {
    const mkQueries = (n: number, minuteOffsetMs: number) =>
      lowEntropyDomains(n).map((domain, i) => ({ clientIp: "192.168.10.77", domain, ts: at(minuteOffsetMs + i * 1000) }));

    // run 1 — 25 unique low-entropy domains → suspicious, first row created
    const run1 = await service.runDetection({ tenantId: 1, queries: mkQueries(25, 6 * MIN), windowMinutes: 15, stepMinutes: 15 });
    expect(run1.reason).toBeUndefined();
    expect(run1.windowsScanned).toBe(1);
    expect(run1.findings).toBe(1);
    expect(run1.created).toBe(1);
    expect(run1.updated).toBe(0);

    const rows1 = await db.dnsTunnelFinding.findMany({});
    expect(rows1).toHaveLength(1);
    expect(rows1[0].clientIp).toBe("192.168.10.77");
    expect(rows1[0].verdict).toBe("suspicious");
    expect(rows1[0].status).toBe("open");
    expect(rows1[0].queryCount).toBe(25);
    expect(rows1[0].uniqueDomains).toBe(25);
    expect(rows1[0].windowStart.toISOString()).toBe("2025-03-01T10:00:00.000Z");
    const detail1 = JSON.parse(rows1[0].detail) as { topDomains: unknown[]; longestLabels: unknown[] };
    expect(detail1.topDomains.length).toBeGreaterThan(0);
    expect(detail1.topDomains.length).toBeLessThanOrEqual(5);
    expect(detail1.longestLabels.every((l) => !["com", "local"].includes((l as { label: string }).label))).toBe(true);

    // run 2 — same client + window + verdict → SAME row updated, no duplicate
    const run2 = await service.runDetection({ tenantId: 1, queries: mkQueries(30, 7 * MIN), windowMinutes: 15, stepMinutes: 15 });
    expect(run2.findings).toBe(1);
    expect(run2.created).toBe(0);
    expect(run2.updated).toBe(1);

    const rows2 = await db.dnsTunnelFinding.findMany({});
    expect(rows2).toHaveLength(1); // dedupe: updated, not duplicated
    expect(rows2[0].queryCount).toBe(30);
    expect(rows2[0].uniqueDomains).toBe(30);
  });

  it("keeps a separate row when the verdict escalates (dedupe key includes verdict)", async () => {
    const suspicious = lowEntropyDomains(30).map((domain, i) => ({ clientIp: "192.168.10.60", domain, ts: at(6 * MIN + i * 1000) }));
    await service.runDetection({ tenantId: 1, queries: suspicious, windowMinutes: 15, stepMinutes: 15 });

    const escalated = highEntropyDomains(40).map((domain, i) => ({ clientIp: "192.168.10.60", domain, ts: at(6 * MIN + i * 1000) }));
    const run = await service.runDetection({ tenantId: 1, queries: escalated, windowMinutes: 15, stepMinutes: 15 });
    expect(run.created).toBe(1); // new verdict → new row

    const rows = await db.dnsTunnelFinding.findMany({ where: { clientIp: "192.168.10.60" }, orderBy: { id: "asc" } });
    expect(rows).toHaveLength(2);
    expect(rows.map((r) => r.verdict)).toEqual(["suspicious", "likely_tunnel"]);
    expect(rows[0].queryCount).toBe(30); // original row untouched
    expect(rows[1].entropyScore).toBeGreaterThanOrEqual(TUNNEL_THRESHOLDS.likelyTunnel.entropy);
  });

  it("never persists clean windows", async () => {
    const queries = ["corp.local", "intranet.corp.local", "nas.corp.local"].map((domain, i) => ({
      clientIp: "192.168.10.10",
      domain,
      ts: at(6 * MIN + i * 1000),
    }));
    const run = await service.runDetection({ tenantId: 1, queries, windowMinutes: 15, stepMinutes: 15 });
    expect(run.findings).toBe(0);
    expect(run.created).toBe(0);
    expect(run.updated).toBe(0);
    expect(await db.dnsTunnelFinding.count({})).toBe(0);
  });

  it("returns the honest empty result when there is no dns query data", async () => {
    const run = await service.runDetection({ tenantId: 1, queries: [], windowMinutes: 15, stepMinutes: 15 });
    expect(run.findings).toBe(0);
    expect(run.reason).toBe("no dns query data in window");
    expect(run.windowsScanned).toBe(0);
    expect(await db.dnsTunnelFinding.count({})).toBe(0);
  });
});

// ── status transitions + list + stats ───────────────────────────────────────

describe("updateFindingStatus / listFindings / statsFindings", () => {
  async function seedTwoClients(): Promise<{ suspiciousId: number; likelyId: number }> {
    const suspicious = lowEntropyDomains(25).map((domain, i) => ({ clientIp: "192.168.10.77", domain, ts: at(6 * MIN + i * 1000) }));
    const likely = highEntropyDomains(40).map((domain, i) => ({ clientIp: "192.168.10.88", domain, ts: at(31 * MIN + i * 1000) }));
    await service.runDetection({ tenantId: 1, queries: [...suspicious, ...likely], windowMinutes: 15, stepMinutes: 15 });
    const all = await db.dnsTunnelFinding.findMany({});
    const suspiciousId = all.find((r) => r.clientIp === "192.168.10.77")!.id;
    const likelyId = all.find((r) => r.clientIp === "192.168.10.88")!.id;
    return { suspiciousId, likelyId };
  }

  it("walks open → acknowledged → resolved and rejects invalid statuses / unknown ids", async () => {
    const { suspiciousId } = await seedTwoClients();

    const ack = await service.updateFindingStatus(1, suspiciousId, "acknowledged");
    expect(ack.status).toBe("acknowledged");
    const resolved = await service.updateFindingStatus(1, suspiciousId, "resolved");
    expect(resolved.status).toBe("resolved");
    const reopened = await service.updateFindingStatus(1, suspiciousId, "open");
    expect(reopened.status).toBe("open");

    await expect(service.updateFindingStatus(1, suspiciousId, "bogus")).rejects.toThrow(/status must be one of/);
    await expect(service.updateFindingStatus(1, 999_999, "open")).rejects.toThrow(/not found/i);
  });

  it("filters by verdict, status and client-IP substring, and paginates", async () => {
    const { suspiciousId } = await seedTwoClients();

    const likelyOnly = await service.listFindings(1, { verdict: "likely_tunnel" });
    expect(likelyOnly.data).toHaveLength(1);
    expect(likelyOnly.data[0].clientIp).toBe("192.168.10.88");
    expect(likelyOnly.data[0].detail.topDomains.length).toBeGreaterThan(0);
    expect(likelyOnly.meta.total).toBe(1);

    await service.updateFindingStatus(1, suspiciousId, "acknowledged");
    const acknowledged = await service.listFindings(1, { status: "acknowledged" });
    expect(acknowledged.data.map((d) => d.clientIp)).toEqual(["192.168.10.77"]);

    const byIp = await service.listFindings(1, { q: "10.88" });
    expect(byIp.data.map((d) => d.clientIp)).toEqual(["192.168.10.88"]);

    const paged = await service.listFindings(1, { page: 1, limit: 1 });
    expect(paged.data).toHaveLength(1);
    expect(paged.meta.total).toBe(2);
    expect(paged.meta.totalPages).toBe(2);

    const none = await service.listFindings(1, { verdict: "likely_tunnel", status: "resolved" });
    expect(none.data).toEqual([]);
    expect(none.meta.total).toBe(0);
  });

  it("aggregates open-by-verdict, totals and the 7d counter, honoring resolutions", async () => {
    const { suspiciousId } = await seedTwoClients();

    const stats = await service.statsFindings(1);
    expect(stats.total).toBe(2);
    expect(stats.openTotal).toBe(2);
    expect(stats.openByVerdict.suspicious).toBe(1);
    expect(stats.openByVerdict.likely_tunnel).toBe(1);
    expect(stats.resolvedTotal).toBe(0);
    expect(stats.created7d).toBe(2); // rows created now

    await service.updateFindingStatus(1, suspiciousId, "resolved");
    const after = await service.statsFindings(1);
    expect(after.openTotal).toBe(1);
    expect(after.openByVerdict.suspicious).toBe(0);
    expect(after.resolvedTotal).toBe(1);
    expect(after.total).toBe(2);
  });
});
