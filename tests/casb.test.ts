/**
 * CASB tests (Phase 4 §4.3) — two layers:
 *   • PURE matcher (lib/casb/matcher): hint normalization (scheme/port/path
 *     stripping), domain suffix matching incl. the "*.x" wildcard semantics
 *     (subdomains only, never the bare parent), longest-domain specificity,
 *     no-match → null, and the verdict mapping (unknown / sanctioned /
 *     shadow at the SANCTIONED_MAX_RISK boundary),
 *   • DB-backed service over a per-run copy of the pushed dev schema (same
 *     harness as incidents.test.ts): idempotent default catalog seed (twice →
 *     no dupes), runScan over seeded app_control_logs rows producing the
 *     expected discoveries with correct verdicts + accumulated bytes and
 *     session/first/lastSeen accumulation on re-scan, connector config-shell
 *     validation (valid shape → connected, missing keys / missing secret ref
 *     → error) with zero network calls.
 *
 * The db/service modules are imported AFTER the DATABASE_URL override —
 * static imports would resolve the Prisma datasource too early (lib/casb/
 * catalog.ts imports db, so it is dynamically imported below too).
 */

import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// pure matcher — no DB dependency, safe to import statically
import {
  SANCTIONED_MAX_RISK,
  classifyVerdict,
  matchHint,
  normalizeHint,
  type MatchCatalogEntry,
} from "@/lib/casb/matcher";

const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "casb-"));
const DB_PATH = path.join(TMP_DIR, "casb-test.db");
fs.copyFileSync(path.resolve(process.cwd(), "db/cryptsk.db"), DB_PATH);
process.env.DATABASE_URL = `file:${DB_PATH}`;

const { db } = await import("@/lib/db");
const service = await import("@/lib/casb/service");
const { DEFAULT_SAAS_APPS, ensureSaasCatalog } = await import("@/lib/casb/catalog");

// ── pure fixtures ───────────────────────────────────────────────────────────

function entry(id: number, name: string, domains: string[], riskScore: number): MatchCatalogEntry {
  return { id, name, vendor: name, category: "other", domains, riskScore };
}

const CATALOG: MatchCatalogEntry[] = [
  entry(1, "Google Workspace", ["google.com", "docs.google.com"], 10),
  entry(2, "Zoom", ["zoom.us", "*.zoom.us"], 15),
  entry(3, "Personal Gmail", ["gmail.com", "mail.google.com"], 60),
  entry(4, "Wildcard Only", ["*.teams.example.com"], 40),
];

beforeAll(async () => {
  // the copied dev schema has no tenant rows — CASB rows FK to tenants
  await db.tenant.upsert({ where: { id: 1 }, update: {}, create: { id: 1, name: "casb-test" } });
});

beforeEach(async () => {
  await db.saasDiscovery.deleteMany({});
  await db.saasAppCatalog.deleteMany({});
  await db.casbConnector.deleteMany({});
  await db.appControlLog.deleteMany({});
});

afterAll(async () => {
  await db.$disconnect();
  fs.rmSync(TMP_DIR, { recursive: true, force: true });
});

// ── normalizeHint (pure) ────────────────────────────────────────────────────

describe("normalizeHint", () => {
  it("reduces URLs to bare hostnames (scheme, userinfo, port, path, trailing dot)", () => {
    expect(normalizeHint("https://docs.google.com/document/d/1")).toBe("docs.google.com");
    expect(normalizeHint("http://user@us02web.zoom.us:8443/join")).toBe("us02web.zoom.us");
    expect(normalizeHint("Docs.Google.com.")).toBe("docs.google.com");
    expect(normalizeHint("  slack.com  ")).toBe("slack.com");
  });

  it("passes plain hosts through and returns '' for empty input", () => {
    expect(normalizeHint("zoom.us")).toBe("zoom.us");
    expect(normalizeHint("")).toBe("");
    expect(normalizeHint("   ")).toBe("");
  });
});

// ── matchHint (pure) ────────────────────────────────────────────────────────

describe("matchHint", () => {
  it("suffix-matches plain domain entries (subdomains included)", () => {
    const m = matchHint("calendar.corp.google.com", CATALOG);
    expect(m?.app.id).toBe(1);
    expect(m?.matchedDomain).toBe("google.com");
  });

  it("matches an exact domain entry", () => {
    const m = matchHint("docs.google.com", CATALOG);
    expect(m?.app.name).toBe("Google Workspace");
    expect(m?.matchedDomain).toBe("docs.google.com"); // longest match wins over "google.com"
  });

  it("matches wildcard '*.x' entries for subdomains", () => {
    const m = matchHint("us02web.zoom.us", CATALOG);
    expect(m?.app.name).toBe("Zoom");
  });

  it("never matches the bare parent of a '*.x' wildcard", () => {
    expect(matchHint("teams.example.com", CATALOG)).toBeNull();
    expect(matchHint("a.b.teams.example.com", CATALOG)?.app.name).toBe("Wildcard Only");
  });

  it("prefers the longest matching domain across apps (specificity)", () => {
    // "mail.google.com" is BOTH a Google Workspace suffix ("google.com") and
    // an exact Personal Gmail entry — the longer entry attributes it
    const m = matchHint("mail.google.com", CATALOG);
    expect(m?.app.name).toBe("Personal Gmail");
    expect(m?.matchedDomain).toBe("mail.google.com");
  });

  it("returns null when nothing matches and for non-host hints", () => {
    expect(matchHint("mega-share.io", CATALOG)).toBeNull();
    expect(matchHint("Google-Workspace", CATALOG)).toBeNull(); // nDPI label, not a host
    expect(matchHint("", CATALOG)).toBeNull();
  });

  it("is case-insensitive and strips URL wrapping before matching", () => {
    expect(matchHint("HTTPS://US02WEB.ZOOM.US/join", CATALOG)?.app.name).toBe("Zoom");
  });

  it("ties on equal-length domains resolve to the first catalog entry", () => {
    const tie: MatchCatalogEntry[] = [
      entry(7, "Alpha", ["same.io"], 10),
      entry(8, "Beta", ["same.io"], 90),
    ];
    expect(matchHint("x.same.io", tie)?.app.name).toBe("Alpha");
  });
});

// ── classifyVerdict (pure) ──────────────────────────────────────────────────

describe("classifyVerdict", () => {
  it("maps a non-match to unknown (shadow-IT triage candidate)", () => {
    expect(classifyVerdict(null)).toBe("unknown");
  });

  it("maps cataloged low-risk apps to sanctioned", () => {
    const m = matchHint("docs.google.com", CATALOG);
    expect(classifyVerdict(m)).toBe("sanctioned");
  });

  it("maps cataloged high-risk apps to shadow", () => {
    const m = matchHint("mail.google.com", CATALOG);
    expect(classifyVerdict(m)).toBe("shadow");
  });

  it("uses the SANCTIONED_MAX_RISK boundary (≤ sanctioned, > shadow)", () => {
    expect(SANCTIONED_MAX_RISK).toBe(50);
    expect(classifyVerdict({ app: entry(9, "Edge50", ["edge50.io"], 50), matchedDomain: "edge50.io" })).toBe("sanctioned");
    expect(classifyVerdict({ app: entry(10, "Edge51", ["edge51.io"], 51), matchedDomain: "edge51.io" })).toBe("shadow");
  });

  it("classifies the shipped defaults (workspace sanctioned, consumer mail shadow)", () => {
    const asEntries: MatchCatalogEntry[] = DEFAULT_SAAS_APPS.map((a, i) => ({
      id: i + 1,
      name: a.name,
      vendor: a.vendor,
      category: a.category,
      domains: a.domains,
      riskScore: a.riskScore,
    }));
    expect(classifyVerdict(matchHint("docs.google.com", asEntries))).toBe("sanctioned");
    expect(classifyVerdict(matchHint("mail.google.com", asEntries))).toBe("shadow");
    expect(asEntries.length).toBeGreaterThanOrEqual(12);
  });
});

// ── DB-backed: idempotent seed ──────────────────────────────────────────────

describe("ensureSaasCatalog (idempotent seed)", () => {
  it("creates every default once and never duplicates on re-seed", async () => {
    const run1 = await ensureSaasCatalog(1);
    expect(run1).toBe(DEFAULT_SAAS_APPS.length);
    const count1 = await db.saasAppCatalog.count({ where: { tenantId: 1 } });
    expect(count1).toBe(DEFAULT_SAAS_APPS.length);

    // second call — nothing created, no duplicate rows
    const run2 = await ensureSaasCatalog(1);
    expect(run2).toBe(0);
    const count2 = await db.saasAppCatalog.count({ where: { tenantId: 1 } });
    expect(count2).toBe(DEFAULT_SAAS_APPS.length);

    // spot-check shipped entries carry real domains + risk scores
    const gw = await db.saasAppCatalog.findFirst({ where: { tenantId: 1, name: "Google Workspace" } });
    expect(gw).toBeTruthy();
    expect(JSON.parse(gw!.domains)).toEqual(["google.com", "googledrive.com", "docs.google.com", "drive.google.com"]);
    expect(gw!.riskScore).toBe(10);
    const m365 = await db.saasAppCatalog.findFirst({ where: { tenantId: 1, name: "Microsoft 365" } });
    expect(JSON.parse(m365!.domains)).toContain("sharepoint.com");
  });
});

// ── DB-backed: scan ─────────────────────────────────────────────────────────

describe("runScan (nDPI log aggregation)", () => {
  async function seedLogs() {
    // (client, hint, count, bytes) — deterministic rows inside the 24h window
    const mk = (clientIp: string, appName: string, count: number, bytes: number) =>
      Array.from({ length: count }, () => ({ tenantId: 1, clientIp, appName, action: "allowed", bytes }));
    await db.appControlLog.createMany({
      data: [
        ...mk("192.168.20.10", "docs.google.com", 3, 1000), // sanctioned (Google Workspace)
        ...mk("192.168.20.10", "us02web.zoom.us", 2, 500), // sanctioned (Zoom, wildcard)
        ...mk("192.168.20.11", "mail.google.com", 2, 700), // shadow (Personal Gmail, risk 60)
        ...mk("192.168.20.12", "mega-share.io", 4, 250), // unknown (no catalog match)
      ],
    });
  }

  it("produces discoveries with correct verdicts, attribution and accumulated bytes", async () => {
    await seedLogs();
    const summary = await service.runScan(1, { windowMinutes: 1440 });
    expect(summary).toEqual({ scanned: 11, upserted: 4, sanctioned: 2, shadow: 1, unknown: 1 });

    const rows = await db.saasDiscovery.findMany({ where: { tenantId: 1 }, orderBy: { id: "asc" } });
    expect(rows).toHaveLength(4);

    const byHint = new Map(rows.map((r) => [r.appHint, r]));

    const gw = byHint.get("docs.google.com")!;
    expect(gw.verdict).toBe("sanctioned");
    expect(gw.clientIp).toBe("192.168.20.10");
    expect(gw.appId).not.toBeNull(); // attributed to the Google Workspace catalog row
    const gwApp = await db.saasAppCatalog.findUniqueOrThrow({ where: { id: gw.appId! } });
    expect(gwApp.name).toBe("Google Workspace");
    expect(gw.sessions).toBe(3);
    expect(gw.bytesIn).toBe(3000); // directionless log bytes accounted as bytesIn
    expect(gw.bytesOut).toBe(0);

    const zoom = byHint.get("us02web.zoom.us")!;
    expect(zoom.verdict).toBe("sanctioned");
    expect(zoom.sessions).toBe(2);
    expect(zoom.bytesIn).toBe(1000);

    const gmail = byHint.get("mail.google.com")!;
    expect(gmail.verdict).toBe("shadow"); // cataloged but riskScore 60 > 50
    expect(gmail.clientIp).toBe("192.168.20.11");
    expect(gmail.bytesIn).toBe(1400);

    const unknown = byHint.get("mega-share.io")!;
    expect(unknown.verdict).toBe("unknown");
    expect(unknown.appId).toBeNull(); // no catalog attribution
    expect(unknown.sessions).toBe(4);
    expect(unknown.bytesIn).toBe(1000);

    // first/lastSeen track the seeded log timestamps
    expect(gw.firstSeenAt.getTime()).toBeLessThanOrEqual(gw.lastSeenAt.getTime());
  });

  it("accumulates sessions/bytes across scans without duplicating rows", async () => {
    await seedLogs();
    const first = await service.runScan(1, { windowMinutes: 1440 });
    expect(first).toEqual({ scanned: 11, upserted: 4, sanctioned: 2, shadow: 1, unknown: 1 });

    // one more Google Workspace session from the same client
    await db.appControlLog.create({
      data: { tenantId: 1, clientIp: "192.168.20.10", appName: "docs.google.com", action: "allowed", bytes: 2000 },
    });

    // a scan INGESTS the logs inside its window into the cumulative discovery
    // counters — the 24h window still contains the earlier logs, so they are
    // counted again (schedule non-overlapping windows to avoid re-ingest);
    // the row count is what must never grow
    const second = await service.runScan(1, { windowMinutes: 1440 });
    expect(second).toEqual({ scanned: 12, upserted: 4, sanctioned: 2, shadow: 1, unknown: 1 });

    const rows = await db.saasDiscovery.findMany({ where: { tenantId: 1 } });
    expect(rows).toHaveLength(4); // same (clientIp, appHint) keys — updated, never duplicated
    const gw = rows.find((r) => r.appHint === "docs.google.com")!;
    expect(gw.sessions).toBe(7); // 3 + (3 re-ingested + 1 new)
    expect(gw.bytesIn).toBe(8000); // 3000 + (3000 re-ingested + 2000 new)
  });

  it("returns the honest zero summary when the window has no log rows", async () => {
    const summary = await service.runScan(1, { windowMinutes: 1440 });
    expect(summary).toEqual({ scanned: 0, upserted: 0, sanctioned: 0, shadow: 0, unknown: 0 });
    expect(await db.saasDiscovery.count({})).toBe(0);
  });

  it("honors the scan window (logs outside it are ignored)", async () => {
    await db.appControlLog.create({
      data: {
        tenantId: 1,
        clientIp: "192.168.20.99",
        appName: "slack.com",
        action: "allowed",
        bytes: 10,
        createdAt: new Date(Date.now() - 3 * 60 * 60_000), // 3h ago
      },
    });
    const summary = await service.runScan(1, { windowMinutes: 60 }); // last hour only
    expect(summary.scanned).toBe(0);
    expect(await db.saasDiscovery.count({})).toBe(0);
  });
});

// ── DB-backed: discovery filters + catalog detach ───────────────────────────

describe("listDiscoveries filters + deleteSaasApp detach", () => {
  it("filters by verdict and category and paginates", async () => {
    await db.appControlLog.createMany({
      data: [
        { tenantId: 1, clientIp: "10.0.0.1", appName: "docs.google.com", action: "allowed", bytes: 100 },
        { tenantId: 1, clientIp: "10.0.0.2", appName: "mail.google.com", action: "allowed", bytes: 100 },
        { tenantId: 1, clientIp: "10.0.0.3", appName: "mega-share.io", action: "allowed", bytes: 100 },
      ],
    });
    await service.runScan(1, { windowMinutes: 1440 });

    const shadow = await service.listDiscoveries(1, { page: 1, limit: 25, verdict: "shadow" });
    expect(shadow.data.map((d) => d.appHint)).toEqual(["mail.google.com"]);
    expect(shadow.data[0].appName).toBe("Personal Gmail");
    expect(shadow.data[0].riskScore).toBe(60);

    const collab = await service.listDiscoveries(1, { page: 1, limit: 25, category: "collaboration" });
    // category is catalog-side: collaboration = Google Workspace (docs hint)
    expect(collab.data.map((d) => d.appHint).sort()).toEqual(["docs.google.com"]);

    const byIp = await service.listDiscoveries(1, { page: 1, limit: 25, q: "10.0.0.3" });
    expect(byIp.data.map((d) => d.appHint)).toEqual(["mega-share.io"]);
    expect(byIp.data[0].category).toBeNull();

    const paged = await service.listDiscoveries(1, { page: 1, limit: 2 });
    expect(paged.data).toHaveLength(2);
    expect(paged.meta.total).toBe(3);
    expect(paged.meta.totalPages).toBe(2);
  });

  it("detaches the logical appId when the catalog app is deleted (hint kept)", async () => {
    await db.appControlLog.create({
      data: { tenantId: 1, clientIp: "10.9.9.9", appName: "docs.google.com", action: "allowed", bytes: 100 },
    });
    await service.runScan(1, { windowMinutes: 1440 });
    const before = await db.saasDiscovery.findFirstOrThrow({ where: { tenantId: 1, appHint: "docs.google.com" } });
    expect(before.appId).not.toBeNull();

    await service.deleteSaasApp(1, before.appId!);
    const after = await db.saasDiscovery.findFirstOrThrow({ where: { tenantId: 1, appHint: "docs.google.com" } });
    expect(after.appId).toBeNull();
    expect(after.appHint).toBe("docs.google.com"); // observation record stays intact
  });
});

// ── DB-backed: connector config shell (no network calls) ────────────────────

describe("connectors (config shell validation)", () => {
  it("flips to connected only when the vendor shape is valid AND a secret ref is present", async () => {
    const gw = await service.createConnector(1, {
      vendor: "google_workspace",
      config: { domain: "corp.example.com", serviceAccountSecretRef: "vault/casb/gw-sa" },
    });
    const gwTest = await service.testConnector(1, gw.id);
    expect(gwTest.ok).toBe(true);
    expect(gwTest.status).toBe("connected");
    expect(gwTest.missingKeys).toEqual([]);
    const gwRow = await db.casbConnector.findUniqueOrThrow({ where: { id: gw.id } });
    expect(gwRow.status).toBe("connected");
    expect(gwRow.lastSyncAt).not.toBeNull(); // shape-validation stamp (live sync deferred)

    const slack = await service.createConnector(1, { vendor: "slack", config: { botTokenRef: "vault/casb/slack" } });
    const slackTest = await service.testConnector(1, slack.id);
    expect(slackTest.ok).toBe(true);
    expect(slackTest.status).toBe("connected");
  });

  it("marks error for missing keys and for configs without a secret-store ref", async () => {
    const empty = await service.createConnector(1, { vendor: "microsoft_365", config: {} });
    const emptyTest = await service.testConnector(1, empty.id);
    expect(emptyTest.ok).toBe(false);
    expect(emptyTest.status).toBe("error");
    expect(emptyTest.missingKeys).toEqual(["tenantId", "clientSecretRef"]);
    expect(emptyTest.message).toContain("tenantId");

    // plaintext secret instead of a ref — rejected even when keys exist
    const plaintext = await service.createConnector(1, {
      vendor: "salesforce",
      config: { instanceUrl: "https://acme.my.salesforce.com", consumerSecretRef: "" },
    });
    const plaintextTest = await service.testConnector(1, plaintext.id);
    expect(plaintextTest.ok).toBe(false);
    expect(plaintextTest.status).toBe("error");
    expect(plaintextTest.missingKeys).toContain("consumerSecretRef"); // empty string counts as missing
    const plaintextRow = await db.casbConnector.findUniqueOrThrow({ where: { id: plaintext.id } });
    expect(plaintextRow.status).toBe("error");
    expect(plaintextRow.lastSyncAt).toBeNull();

    // required ref key absent entirely → missing-keys error (the separate
    // no-secret-ref guard is a defensive check for vendor maps that lack a
    // *Ref requirement — every shipped vendor map requires one)
    const noRef = await service.createConnector(1, {
      vendor: "dropbox",
      config: { teamFolderId: "12345" },
    });
    const noRefTest = await service.testConnector(1, noRef.id);
    expect(noRefTest.ok).toBe(false);
    expect(noRefTest.status).toBe("error");
    expect(noRefTest.missingKeys).toEqual(["accessTokenRef"]);
    expect(noRefTest.message).toContain("accessTokenRef");
  });

  it("keeps one connector per vendor and updates config via PATCH path", async () => {
    await service.createConnector(1, { vendor: "dropbox", config: {} });
    await expect(service.createConnector(1, { vendor: "dropbox", config: {} })).rejects.toThrow(/already exists/);

    const rows = await db.casbConnector.findMany({ where: { tenantId: 1, vendor: "dropbox" } });
    expect(rows).toHaveLength(1);

    const updated = await service.updateConnector(1, rows[0].id, {
      config: { accessTokenRef: "vault/casb/dbx" },
    });
    expect(updated.config).toEqual({ accessTokenRef: "vault/casb/dbx" });
    expect(updated.requiredKeys).toEqual(["accessTokenRef"]);
    expect(updated.missingKeys).toEqual([]);

    const dto = await service.listConnectors(1);
    expect(dto.map((c) => c.vendor)).toEqual(["dropbox"]);

    await service.deleteConnector(1, rows[0].id);
    expect(await db.casbConnector.count({ where: { tenantId: 1 } })).toBe(0);
  });

  it("rejects unknown connector ids on test/update/delete", async () => {
    await expect(service.testConnector(1, 999_999)).rejects.toThrow(/not found/i);
    await expect(service.updateConnector(1, 999_999, { status: "disconnected" })).rejects.toThrow(/not found/i);
    await expect(service.deleteConnector(1, 999_999)).rejects.toThrow(/not found/i);
  });
});
