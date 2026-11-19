/**
 * GeoIP + FQDN integration tests (spec §1.4) — DB-backed harness over a
 * per-run copy of the pushed dev schema (same pattern as incidents.test.ts):
 *
 *   • parseGeoCsv: comments/blank tolerance, bad-line counting, per-country
 *     aggregation + dedup, IPv6 counted-but-warned, swapped-field tolerance,
 *   • renderGeoSets: determinism + sha256, per-country set fragment shape,
 *     documented >20000-prefix perf guard,
 *   • resolveFqdn: mocked node:dns — success/dedup, error strings, timeout,
 *   • refreshFqdnObjects: resolvedIps/resolvedAt stamping, 60s freshness
 *     skip, force flag, failure keeps the previous snapshot,
 *   • geoip service: loadSource upsert + error row, getSets merge,
 *     removeSource, getGeoResolver null-when-empty,
 *   • nft-gen: geo callback expansion (+ warning when callback is null),
 *     fqdn expansion from resolvedIps (+ stale/empty warnings).
 *
 * Modules are imported AFTER the DATABASE_URL override — static imports would
 * resolve the Prisma datasource too early. node:dns is mocked (vi.mock is
 * hoisted) so no test touches real DNS.
 */

import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

vi.mock("node:dns", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:dns")>();
  return {
    ...actual,
    promises: {
      ...actual.promises,
      resolve4: vi.fn(),
      resolve6: vi.fn(),
    },
  };
});

const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "geoip-fqdn-"));
const DB_PATH = path.join(TMP_DIR, "geoip-fqdn-test.db");
fs.copyFileSync(path.resolve(process.cwd(), "db/cryptsk.db"), DB_PATH);
process.env.DATABASE_URL = `file:${DB_PATH}`;
// managed GeoIP root override — sources MUST live inside it (confinement);
// the test root lives in this run's tmp area, never the repo working tree
const GEOIP_ROOT = path.join(TMP_DIR, "geoip-root");
process.env.CONSOLE_GEOIP_DIR = GEOIP_ROOT;

const { db } = await import("@/lib/db");
const geoipService = await import("@/lib/geoip/service");
const render = await import("@/lib/geoip/render");
const fqdn = await import("@/lib/firewall/fqdn-resolver");
const nftGen = await import("@/lib/firewall/nft-gen");
const dnsModule = await import("node:dns");

const resolve4Mock = vi.mocked(dnsModule.promises.resolve4);
const resolve6Mock = vi.mocked(dnsModule.promises.resolve6);

type AddrMatcher = import("@/lib/firewall/rule-match").AddrMatcher;
type NftGenRule = import("@/lib/firewall/nft-gen").NftGenRule;
type NftGenInput = import("@/lib/firewall/nft-gen").NftGenInput;

// ── helpers ─────────────────────────────────────────────────────────────────

function mockDns(opts: { a?: string[] | Error | "hang"; aaaa?: string[] | Error | "hang" }): void {
  const impl =
    (v: string[] | Error | "hang" | undefined) =>
    (_host: string): Promise<string[]> => {
      if (v === undefined) return Promise.resolve([]);
      if (v === "hang") return new Promise<string[]>(() => {});
      if (v instanceof Error) return Promise.reject(v);
      return Promise.resolve([...v]);
    };
  resolve4Mock.mockImplementation(impl(opts.a));
  resolve6Mock.mockImplementation(impl(opts.aaaa));
}

const rule = (over: Partial<NftGenRule> = {}): NftGenRule => ({
  id: 1,
  name: "dyn-rule",
  position: 1,
  enabled: true,
  srcZoneIds: [],
  dstZoneIds: [],
  srcAddrs: [],
  dstAddrs: [],
  services: [],
  srcMacs: [],
  applicationIds: [],
  userNames: [],
  schedule: null,
  action: "allow",
  logging: "none",
  rateLimit: null,
  ...over,
});

const baseInput = (over: Partial<NftGenInput> = {}): NftGenInput => ({
  rules: [],
  natRules: [],
  zones: [
    { id: 1, name: "wan", interfaces: ["ens32"] },
    { id: 2, name: "lan", interfaces: ["ens34"] },
  ],
  generatedAt: new Date("2026-01-01T00:00:00Z"),
  ...over,
});

function writeTmpFile(content: string): string {
  // fixtures MUST live inside the managed geoip root (confinement contract)
  fs.mkdirSync(GEOIP_ROOT, { recursive: true });
  const p = path.join(GEOIP_ROOT, `csv-${Math.random().toString(36).slice(2)}.csv`);
  fs.writeFileSync(p, content, "utf8");
  return p;
}

const overCapPrefixes = (count: number): string[] =>
  Array.from({ length: count }, (_, i) => `10.0.${Math.floor(i / 256) % 256}.${i % 256}/32`);

// ── harness ─────────────────────────────────────────────────────────────────

beforeAll(async () => {
  // the copied dev schema has no tenant rows — geoip/address rows FK to tenants
  await db.tenant.upsert({ where: { id: 1 }, update: {}, create: { id: 1, name: "geoip-fqdn-test" } });
});

beforeEach(async () => {
  await db.geoipSource.deleteMany({});
  await db.addressObject.deleteMany({ where: { name: { startsWith: "fqdn-tst-" } } });
  resolve4Mock.mockReset();
  resolve6Mock.mockReset();
});

afterAll(async () => {
  await db.$disconnect();
  fs.rmSync(TMP_DIR, { recursive: true, force: true });
});

// ── parseGeoCsv ─────────────────────────────────────────────────────────────

describe("parseGeoCsv", () => {
  it("tolerates comments and blank lines and aggregates + dedupes per country", () => {
    const res = geoipService.parseGeoCsv(
      [
        "# GeoLite2 country export",
        "",
        "DE,203.0.113.0/24",
        "DE,203.0.113.0/24",
        "  FR , 198.51.100.0/24  ",
        "# trailing comment",
        "DE,203.0.114.0/24",
        "",
      ].join("\n"),
    );
    expect(res.v4Count).toBe(3);
    expect(res.badLines).toBe(0);
    expect(res.v6Count).toBe(0);
    expect(res.countries["DE"]).toEqual(["203.0.113.0/24", "203.0.114.0/24"]);
    expect(res.countries["FR"]).toEqual(["198.51.100.0/24"]);
  });

  it("counts bad lines and IPv6 prefixes (warned, not fatal)", () => {
    const res = geoipService.parseGeoCsv(
      [
        "not-a-line",
        "GER,10.0.0.0/24", // 3-letter code → bad
        "DE,2001:db8::/32", // v6 → counted + excluded
        "DE,999.1.2.3/24", // octet > 255 → bad
        "DE,10.0.0.0/33", // bits > 32 → bad
        "203.0.113.0/24,DE", // swapped field order → tolerated
      ].join("\n"),
    );
    expect(res.badLines).toBe(4);
    expect(res.v6Count).toBe(1);
    expect(res.countries["DE"]).toEqual(["203.0.113.0/24"]);
    expect(res.warnings.some((w) => w.includes("IPv6"))).toBe(true);
    expect(res.warnings.some((w) => w.includes("unparseable"))).toBe(true);
  });

  it("accepts a file with only comments/blanks (empty aggregation)", () => {
    const res = geoipService.parseGeoCsv("# nothing here\n\n# still nothing\n");
    expect(res.v4Count).toBe(0);
    expect(Object.keys(res.countries)).toEqual([]);
  });
});

// ── renderGeoSets ───────────────────────────────────────────────────────────

describe("renderGeoSets", () => {
  const prefixData = {
    DE: ["203.0.113.0/24", "198.51.100.0/24", "203.0.113.0/24"],
    FR: ["198.51.100.0/24"],
  };

  it("renders deterministic per-country interval sets with a stable sha256", () => {
    const a = render.renderGeoSets(prefixData, ["DE", "FR"]);
    const b = render.renderGeoSets({ FR: ["198.51.100.0/24"], DE: ["203.0.113.0/24", "198.51.100.0/24"] }, ["FR", "DE"]);
    expect(a.fragment).toBe(b.fragment);
    expect(a.sha256).toBe(b.sha256);
    expect(a.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(a.fragment).toContain(
      "set utm_geo_de { type ipv4_addr; flags interval; auto-merge; elements = { 198.51.100.0/24, 203.0.113.0/24 } }",
    );
    expect(a.fragment).toContain(
      "set utm_geo_fr { type ipv4_addr; flags interval; auto-merge; elements = { 198.51.100.0/24 } }",
    );
    const de = a.sets.find((s) => s.country === "DE");
    expect(de?.skipped).toBe(false);
    expect(de?.prefixCount).toBe(2); // deduped
  });

  it("skips countries above the 20000-prefix cap with a documented perf-guard warning", () => {
    const data = { ...prefixData, US: overCapPrefixes(render.GEO_SET_MAX_PREFIXES + 1) };
    const res = render.renderGeoSets(data, ["US", "DE"]);
    const us = res.sets.find((s) => s.country === "US");
    expect(us?.skipped).toBe(true);
    expect(us?.skipReason).toContain("cap");
    expect(res.warnings.some((w) => w.includes("perf guard") && w.includes("US"))).toBe(true);
    expect(res.fragment).not.toContain("utm_geo_us");
    expect(res.fragment).toContain("utm_geo_de");
  });

  it("warns for wanted countries without data and drops malformed prefixes", () => {
    const res = render.renderGeoSets({ DE: ["203.0.113.0/24", "garbage"] }, ["DE", "ZZ"]);
    expect(res.sets.find((s) => s.country === "ZZ")?.skipped).toBe(true);
    expect(res.warnings.some((w) => w.includes("ZZ"))).toBe(true);
    expect(res.fragment).toContain("elements = { 203.0.113.0/24 }");
    expect(res.fragment).not.toContain("garbage");
  });
});

// ── resolveFqdn (mocked node:dns) ───────────────────────────────────────────

describe("resolveFqdn", () => {
  it("resolves A records, dedupes and drops malformed addresses", async () => {
    mockDns({ a: ["203.0.113.10", "203.0.113.10", "999.9.9.9"] });
    const res = await fqdn.resolveFqdn("portal.example.com");
    expect(res.ipv4).toEqual(["203.0.113.10"]);
    expect(res.ips).toEqual(["203.0.113.10"]);
    expect(res.errors).toEqual([]);
    expect(resolve4Mock).toHaveBeenCalledTimes(1);
    expect(resolve6Mock).not.toHaveBeenCalled();
  });

  it("resolves AAAA only when ipv6 is wanted", async () => {
    mockDns({ a: ["203.0.113.10"], aaaa: ["2001:db8::1"] });
    const v4only = await fqdn.resolveFqdn("portal.example.com");
    expect(v4only.ips).toEqual(["203.0.113.10"]);
    const dual = await fqdn.resolveFqdn("portal.example.com", { ipv6: true });
    expect(dual.ipv6).toEqual(["2001:db8::1"]);
    expect(dual.ips).toEqual(["203.0.113.10", "2001:db8::1"]);
    expect(resolve6Mock).toHaveBeenCalledTimes(1);
  });

  it("collects lookup errors instead of throwing", async () => {
    mockDns({ a: new Error("getaddrinfo ENOTFOUND missing.example.com") });
    const res = await fqdn.resolveFqdn("missing.example.com");
    expect(res.ips).toEqual([]);
    expect(res.errors[0]).toContain("ENOTFOUND");
  });

  it("applies the per-lookup timeout", async () => {
    mockDns({ a: "hang" });
    const res = await fqdn.resolveFqdn("slow.example.com", { timeoutMs: 60 });
    expect(res.ips).toEqual([]);
    expect(res.errors[0]).toContain("timed out");
    expect(res.durationMs).toBeLessThan(3000);
  }, 4000);
});

// ── refreshFqdnObjects (DB + mocked dns) ────────────────────────────────────

describe("refreshFqdnObjects", () => {
  const createObject = (name: string, value: string) =>
    db.addressObject.create({ data: { tenantId: 1, name, type: "fqdn", value } });

  it("resolves objects and stamps resolvedIps/resolvedAt", async () => {
    const obj = await createObject("fqdn-tst-portal", "portal.example.com");
    mockDns({ a: ["203.0.113.10", "203.0.113.10", "10.0.0.7", "999.9.9.9"] });

    const res = await fqdn.refreshFqdnObjects(1);
    expect(res.resolved).toBe(1);
    expect(res.failed).toBe(0);
    expect(res.unchanged).toBe(0);
    expect(res.results[0]).toMatchObject({ id: obj.id, status: "resolved", ipCount: 2 });

    const row = await db.addressObject.findUniqueOrThrow({ where: { id: obj.id } });
    expect(JSON.parse(row.resolvedIps)).toEqual(["203.0.113.10", "10.0.0.7"]);
    expect(row.resolvedAt).not.toBeNull();
  });

  it("skips objects resolved under 60s ago unless forced", async () => {
    const obj = await createObject("fqdn-tst-fresh", "fresh.example.com");
    mockDns({ a: ["203.0.113.20"] });
    await fqdn.refreshFqdnObjects(1);

    const first = JSON.parse((await db.addressObject.findUniqueOrThrow({ where: { id: obj.id } })).resolvedIps);
    const skip = await fqdn.refreshFqdnObjects(1);
    expect(skip.unchanged).toBe(1);
    expect(skip.resolved).toBe(0);
    expect(skip.results[0].status).toBe("unchanged");

    const forced = await fqdn.refreshFqdnObjects(1, { force: true });
    expect(forced.resolved).toBe(1);
    expect(forced.unchanged).toBe(0);
    expect(JSON.parse((await db.addressObject.findUniqueOrThrow({ where: { id: obj.id } })).resolvedIps)).toEqual(first);
  });

  it("keeps the previous snapshot on failure and reports errors in the run summary only", async () => {
    const obj = await createObject("fqdn-tst-dying", "dying.example.com");
    mockDns({ a: ["203.0.113.30"] });
    await fqdn.refreshFqdnObjects(1);
    const before = await db.addressObject.findUniqueOrThrow({ where: { id: obj.id } });

    mockDns({ a: new Error("getaddrinfo ENOTFOUND dying.example.com") });
    const res = await fqdn.refreshFqdnObjects(1, { force: true });
    expect(res.failed).toBe(1);
    expect(res.results[0].status).toBe("failed");
    expect(res.results[0].error).toContain("ENOTFOUND");

    const after = await db.addressObject.findUniqueOrThrow({ where: { id: obj.id } });
    expect(after.resolvedIps).toBe(before.resolvedIps); // last-known-good kept
    expect(after.resolvedAt?.getTime()).toBe(before.resolvedAt?.getTime());
  });

  it("returns a deterministic per-run summary shape (no persistence of results)", async () => {
    await createObject("fqdn-tst-summary", "summary.example.com");
    mockDns({ a: [] }); // no A record → failed with "no addresses"
    const res = await fqdn.refreshFqdnObjects(1);
    expect(res.failed).toBe(1);
    expect(res.results[0].error).toContain("no addresses");
    expect(typeof res.ranAt).toBe("string");
    expect(res.results).toHaveLength(1);
  });
});

// ── geoip service (DB) ──────────────────────────────────────────────────────

describe("geoip source service", () => {
  it("loads a CSV file into a loaded GeoipSource row (aggregated per country)", async () => {
    const filePath = writeTmpFile(["# export", "DE,203.0.113.0/24", "", "DE,203.0.114.0/24", "FR,198.51.100.0/24"].join("\n"));
    const res = await geoipService.loadSource(1, { name: "tst-src", filePath });
    expect(res.source.status).toBe("loaded");
    expect(res.source.prefixCount).toBe(3);
    expect(res.source.countries).toEqual(["DE", "FR"]);
    expect(res.countries).toEqual([
      { country: "DE", prefixCount: 2 },
      { country: "FR", prefixCount: 1 },
    ]);

    const row = await db.geoipSource.findFirstOrThrow({ where: { tenantId: 1, name: "tst-src" } });
    expect(JSON.parse(row.countries)).toEqual(["DE", "FR"]);
    expect(row.prefixCount).toBe(3);
    expect(row.kind).toBe("csv");
  });

  it("upserts by name instead of duplicating rows", async () => {
    const filePath = writeTmpFile("DE,203.0.113.0/24\n");
    await geoipService.loadSource(1, { name: "tst-upsert", filePath });
    const filePath2 = writeTmpFile("DE,203.0.113.0/24\nDE,203.0.114.0/24\n");
    const again = await geoipService.loadSource(1, { name: "tst-upsert", filePath: filePath2 });
    expect(again.source.prefixCount).toBe(2);
    expect(await db.geoipSource.count({ where: { tenantId: 1, name: "tst-upsert" } })).toBe(1);
  });

  it("marks the row error and throws on unreadable files", async () => {
    await expect(geoipService.loadSource(1, { name: "tst-missing", filePath: path.join(GEOIP_ROOT, "does-not-exist.csv") })).rejects.toThrow(
      /Cannot read/,
    );
    const row = await db.geoipSource.findFirstOrThrow({ where: { tenantId: 1, name: "tst-missing" } });
    expect(row.status).toBe("error");
    expect(row.error).toContain("Cannot read");
  });

  it("rejects path-traversal filePaths with 400 and never reads or stores them", async () => {
    // raw `..` segments must be rejected BEFORE path.resolve collapses them
    await expect(geoipService.loadSource(1, { name: "tst-traversal", filePath: "../../etc/passwd" })).rejects.toThrow(
      /filePath must point inside the managed geoip directory/,
    );
    await expect(geoipService.loadSource(1, { name: "tst-abs-escape", filePath: "/etc/passwd" })).rejects.toThrow(
      /filePath must point inside the managed geoip directory/,
    );
    // no error row is written for a confinement violation (invalid input, not a load failure)
    expect(await db.geoipSource.count({ where: { tenantId: 1, name: { startsWith: "tst-" } } })).toBe(0);
    // existing rows are untouched too (no status=error stamp from the violation)
    const filePath = writeTmpFile("DE,203.0.113.0/24\n");
    await geoipService.loadSource(1, { name: "tst-traversal-keep", filePath });
    await expect(geoipService.loadSource(1, { name: "tst-traversal-keep", filePath: "../../../etc/shadow" })).rejects.toThrow(
      /managed geoip directory/,
    );
    const kept = await db.geoipSource.findFirstOrThrow({ where: { tenantId: 1, name: "tst-traversal-keep" } });
    expect(kept.status).toBe("loaded");
  });

  it("rejects symlinked sources pointing outside the managed root", async () => {
    const outside = path.join(TMP_DIR, "outside-secret.csv");
    fs.writeFileSync(outside, "DE,203.0.113.0/24\n", "utf8");
    fs.mkdirSync(GEOIP_ROOT, { recursive: true });
    const link = path.join(GEOIP_ROOT, "sneaky-link.csv");
    try {
      fs.symlinkSync(outside, link);
    } catch {
      return; // filesystem without symlink support — nothing to prove here
    }
    await expect(geoipService.loadSource(1, { name: "tst-symlink", filePath: link })).rejects.toThrow(
      /filePath must point inside the managed geoip directory/,
    );
    await expect(geoipService.readPrefixes(link)).rejects.toThrow(/managed geoip directory/);
  });

  it("loads a valid relative path inside the managed root (root created on demand)", async () => {
    fs.mkdirSync(GEOIP_ROOT, { recursive: true });
    fs.writeFileSync(path.join(GEOIP_ROOT, "in-root-fixture.csv"), "DE,203.0.113.0/24\n", "utf8");
    const res = await geoipService.loadSource(1, { name: "tst-inroot", filePath: "in-root-fixture.csv" });
    expect(res.source.status).toBe("loaded");
    // audit fix L22 — the DTO carries the display-relative path only; the
    // absolute filesystem path (which leaks the server root) never leaves
    // the server. The DB row keeps the absolute path for re-reads.
    expect(res.source.filePath).toBe("in-root-fixture.csv");
    expect(res.source.prefixCount).toBe(1);
    // the stored absolute path still re-reads correctly (prefixes re-confined)
    const row = await db.geoipSource.findFirstOrThrow({ where: { tenantId: 1, name: "tst-inroot" } });
    expect(row.filePath.startsWith(GEOIP_ROOT + path.sep)).toBe(true);
    const prefixes = await geoipService.readPrefixes(row.filePath);
    expect(prefixes.prefixes["DE"]).toEqual(["203.0.113.0/24"]);
  });

  it("marks the row error when the file has no usable IPv4 prefixes", async () => {
    const filePath = writeTmpFile("# only comments\nDE,2001:db8::/32\n");
    await expect(geoipService.loadSource(1, { name: "tst-empty", filePath })).rejects.toThrow(/no usable IPv4/);
    const row = await db.geoipSource.findFirstOrThrow({ where: { tenantId: 1, name: "tst-empty" } });
    expect(row.status).toBe("error");
  });

  it("getSets re-reads loaded files and merges country prefix maps", async () => {
    const p1 = writeTmpFile("DE,203.0.113.0/24\nFR,198.51.100.0/24\n");
    const p2 = writeTmpFile("DE,203.0.114.0/24\n");
    await geoipService.loadSource(1, { name: "tst-a", filePath: p1 });
    await geoipService.loadSource(1, { name: "tst-b", filePath: p2 });
    // an error-status row must NOT contribute
    const bad = await db.geoipSource.create({ data: { tenantId: 1, name: "tst-err", filePath: p1, status: "error" } });
    void bad;

    const sets = await geoipService.getSets(1);
    expect(sets.countries).toEqual(["DE", "FR"]);
    expect(sets.counts).toEqual({ DE: 2, FR: 1 });
    expect(sets.prefixes["DE"].sort()).toEqual(["203.0.113.0/24", "203.0.114.0/24"]);
  });

  it("getSets degrades a legacy out-of-root row to an honest warning (no arbitrary re-read)", async () => {
    const ok = await geoipService.loadSource(1, { name: "tst-legacy-ok", filePath: writeTmpFile("DE,203.0.113.0/24\n") });
    void ok;
    // simulate a pre-confinement row pointing outside the managed root
    await db.geoipSource.create({ data: { tenantId: 1, name: "tst-legacy", filePath: "/etc/passwd", status: "loaded" } });
    const sets = await geoipService.getSets(1);
    expect(sets.prefixes["DE"]).toEqual(["203.0.113.0/24"]); // the in-root source still renders
    const w = sets.warnings.find((x) => x.includes("tst-legacy") && x.includes("could not be re-read"));
    expect(w).toBeTruthy();
    expect(w).toContain("managed geoip directory"); // sanitized — no fs internals
    expect(w).not.toContain("/etc/");
  });

  it("readPrefixes re-reads the file fresh (DB stores counts, not prefixes)", async () => {
    const filePath = writeTmpFile("DE,203.0.113.0/24\n");
    await geoipService.loadSource(1, { name: "tst-reread", filePath });
    fs.writeFileSync(filePath, "DE,203.0.113.0/24\nDE,203.0.115.0/24\n", "utf8");
    const { prefixes } = await geoipService.readPrefixes(filePath);
    expect(prefixes["DE"]).toEqual(["203.0.113.0/24", "203.0.115.0/24"]);
  });

  it("removeSource deletes the row and 404s afterwards", async () => {
    const filePath = writeTmpFile("DE,203.0.113.0/24\n");
    const res = await geoipService.loadSource(1, { name: "tst-del", filePath });
    const removed = await geoipService.removeSource(1, res.source.id);
    expect(removed.ok).toBe(true);
    expect(await db.geoipSource.count({ where: { id: res.source.id } })).toBe(0);
    await expect(geoipService.removeSource(1, res.source.id)).rejects.toThrow(/not found/i);
  });

  it("getGeoResolver returns a working callback, or null when nothing is loaded", async () => {
    expect(await geoipService.getGeoResolver(1)).toBeNull();

    const filePath = writeTmpFile("DE,203.0.113.0/24\nFR,198.51.100.0/24\n");
    await geoipService.loadSource(1, { name: "tst-resolver", filePath });
    const resolver = await geoipService.getGeoResolver(1);
    expect(resolver).not.toBeNull();
    expect(resolver?.("DE")).toEqual(["203.0.113.0/24"]);
    expect(resolver?.("de")).toEqual(["203.0.113.0/24"]); // case-insensitive
    expect(resolver?.("ZZ")).toBeNull();
  });

  it("getGeoipStatus reports sources, set accounting, geo resolution and fqdn health", async () => {
    const filePath = writeTmpFile("DE,203.0.113.0/24\nDE,203.0.114.0/24\nFR,198.51.100.0/24\n");
    await geoipService.loadSource(1, { name: "tst-status", filePath });
    await db.addressObject.createMany({
      data: [
        { tenantId: 1, name: "fqdn-tst-status-geo", type: "geo", value: "DE" },
        { tenantId: 1, name: "fqdn-tst-status-geo2", type: "geo", value: "ZZ" },
        { tenantId: 1, name: "fqdn-tst-status-fqdn", type: "fqdn", value: "portal.example.com", resolvedIps: JSON.stringify(["203.0.113.10"]) },
      ],
    });

    const status = await geoipService.getGeoipStatus(1);
    expect(status.sources).toHaveLength(1);
    expect(status.sets.map((s) => s.country)).toEqual(["DE", "FR"]);
    expect(status.sets.find((s) => s.country === "DE")?.prefixCount).toBe(2);
    expect(status.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(status.cap).toBe(20000);
    expect(status.geoObjects.find((g) => g.value === "DE")?.resolvable).toBe(true);
    expect(status.geoObjects.find((g) => g.value === "ZZ")?.resolvable).toBe(false);
    const fqdnRow = status.fqdnObjects.find((f) => f.name === "fqdn-tst-status-fqdn");
    expect(fqdnRow?.ipCount).toBe(1);
    expect(fqdnRow?.stale).toBe(true); // never refreshed → no resolvedAt
  });
});

// ── nft-gen integration ─────────────────────────────────────────────────────

describe("nft-gen geo expansion", () => {
  it("expands a geo matcher into a named set via the injected callback", () => {
    const res = nftGen.generateNftRuleset(
      baseInput({
        rules: [rule({ srcAddrs: [{ kind: "geo", value: "DE" }], dstZoneIds: [1] })],
        geoResolver: (cc) => (cc === "DE" ? ["203.0.113.0/24", "198.51.100.0/24"] : null),
      }),
    );
    expect(res.file).toContain(
      "set utm_geo_de { type ipv4_addr; flags interval; auto-merge; elements = { 198.51.100.0/24, 203.0.113.0/24 } }",
    );
    expect(res.file).toContain("ip saddr @utm_geo_de accept");
    expect(res.sets).toContainEqual({ name: "utm_geo_de", kind: "geo", country: "DE", elements: 2 });
    expect(res.warnings.some((w) => w.code === "match-not-expressible")).toBe(false);
  });

  it("keeps geo rules config-only with the no-source warning when the callback is null", () => {
    const res = nftGen.generateNftRuleset(baseInput({ rules: [rule({ srcAddrs: [{ kind: "geo", value: "DE" }] })] }));
    expect(res.counts.forward).toBe(0);
    expect(res.counts.skipped).toBe(1);
    expect(res.file).not.toContain("utm_geo_de");
    const w = res.warnings.find((x) => x.code === "match-not-expressible");
    expect(w?.message).toContain("geo object skipped: no GeoIP source loaded");
    expect(res.sets).toEqual([]);
  });

  it("warns when the callback has no data for the country or exceeds the set cap", () => {
    const unknown = nftGen.generateNftRuleset(
      baseInput({ rules: [rule({ srcAddrs: [{ kind: "geo", value: "ZZ" }] })], geoResolver: () => null }),
    );
    expect(unknown.counts.forward).toBe(0);
    expect(unknown.warnings.some((w) => w.message.includes("has no prefixes"))).toBe(true);

    const capped = nftGen.generateNftRuleset(
      baseInput({
        rules: [rule({ srcAddrs: [{ kind: "geo", value: "US" }] })],
        geoResolver: () => overCapPrefixes(render.GEO_SET_MAX_PREFIXES + 1),
      }),
    );
    expect(capped.counts.forward).toBe(0);
    expect(capped.warnings.some((w) => w.message.includes("set cap"))).toBe(true);
    expect(capped.file).not.toContain("utm_geo_us");
  });
});

describe("nft-gen fqdn expansion", () => {
  it("expands a fqdn matcher into a named set from the object's resolvedIps", () => {
    const res = nftGen.generateNftRuleset(
      baseInput({
        rules: [rule({ srcAddrs: [{ kind: "fqdn", value: "Portal.Example.com" }] })],
        fqdnObjects: [{ hostname: "portal.example.com", ips: ["203.0.113.10", "bad-ip", "203.0.113.11"] }],
      }),
    );
    expect(res.file).toContain("set utm_fqdn_portal_example_com { type ipv4_addr; elements = { 203.0.113.10, 203.0.113.11 } }");
    expect(res.file).toContain("ip saddr @utm_fqdn_portal_example_com accept");
    expect(res.sets).toContainEqual({ name: "utm_fqdn_portal_example_com", kind: "fqdn", elements: 2 });
  });

  it("warns and skips stale or empty snapshots (rule excluded, never widened)", () => {
    const stale = nftGen.generateNftRuleset(
      baseInput({
        rules: [rule({ srcAddrs: [{ kind: "fqdn", value: "portal.example.com" }] })],
        fqdnObjects: [{ hostname: "portal.example.com", ips: ["203.0.113.10"], stale: true }],
      }),
    );
    expect(stale.counts.forward).toBe(0);
    expect(stale.warnings.some((w) => w.message.includes("stale"))).toBe(true);
    expect(stale.file).not.toContain("utm_fqdn");

    const empty = nftGen.generateNftRuleset(
      baseInput({
        rules: [rule({ srcAddrs: [{ kind: "fqdn", value: "portal.example.com" }] })],
        fqdnObjects: [{ hostname: "portal.example.com", ips: [] }],
      }),
    );
    expect(empty.counts.forward).toBe(0);
    expect(empty.warnings.some((w) => w.message.includes("no usable IPv4"))).toBe(true);

    const missing = nftGen.generateNftRuleset(baseInput({ rules: [rule({ srcAddrs: [{ kind: "fqdn", value: "portal.example.com" }] })] }));
    expect(missing.warnings.some((w) => w.message.includes("no resolver snapshot"))).toBe(true);
  });

  it("combines plain and fqdn matchers without dropping either constraint", () => {
    const res = nftGen.generateNftRuleset(
      baseInput({
        rules: [
          rule({
            srcAddrs: [{ kind: "ip", value: "203.0.113.5" }, { kind: "fqdn", value: "portal.example.com" }],
            dstAddrs: [{ kind: "subnet", base: 0x0a000000, bits: 8 }],
          }),
        ],
        fqdnObjects: [{ hostname: "portal.example.com", ips: ["203.0.113.10"] }],
      }),
    );
    // plain variant keeps the full (src ∧ dst) constraint
    expect(res.file).toContain("ip saddr 203.0.113.5 ip daddr 10.0.0.0/8 accept");
    // fqdn variant carries the plain opposite-side constraint (never over-matches)
    expect(res.file).toContain("ip saddr @utm_fqdn_portal_example_com ip daddr 10.0.0.0/8 accept");
    expect(res.warnings.some((w) => w.code === "match-not-expressible")).toBe(false);
  });
});
