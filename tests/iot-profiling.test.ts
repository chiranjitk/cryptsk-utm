/**
 * IoT device management tests (Phase 3 §3.6) — pure profiling (MAC
 * normalization, OUI lookup, hostname/vendor-class/nDPI signal fusion,
 * confidence aggregation, rogue check, risk formula + clamp) and the DB-backed
 * service (rescan re-profiling with the risk formula, DHCP-lease onboarding
 * with the 500-row cap, inventory filters + pagination, stats aggregation,
 * rescore, quarantine/restore reuse) over a per-run copy of the pushed dev
 * schema (same temp-DB pattern as tests/incidents.test.ts).
 *
 * The iot modules are imported AFTER the DATABASE_URL override — static
 * imports would resolve the Prisma datasource too early.
 */

import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "iot-profiling-"));
const DB_PATH = path.join(TMP_DIR, "iot-profiling-test.db");
fs.copyFileSync(path.resolve(process.cwd(), "db/cryptsk.db"), DB_PATH);
process.env.DATABASE_URL = `file:${DB_PATH}`;

const { db } = await import("@/lib/db");
const oui = await import("@/lib/iot/oui");
const profiling = await import("@/lib/iot/profiling");
const service = await import("@/lib/iot/service");

// ── fixtures ────────────────────────────────────────────────────────────────

const MAC_HIK = "44:47:CC:11:22:33"; // Hikvision camera OUI (curated map)
const MAC_APPLE = "F0:18:98:AA:BB:CC"; // Apple OUI (curated map)
const MAC_ESP = "5C:CF:7F:10:20:30"; // Espressif OUI (curated map)
const MAC_BARE = "aabbccddeeff"; // bare notation, no curated vendor
const MAC_UNKNOWN = "DE:AD:BE:EF:00:02"; // not in the curated map

const HOUR = 3_600_000;

let subnetId = 0;

beforeAll(async () => {
  // the copied dev schema has no tenant rows — devices/leases FK to tenants
  await db.tenant.upsert({ where: { id: 1 }, update: {}, create: { id: 1, name: "iot-test" } });
});

beforeEach(async () => {
  await db.nacDevice.deleteMany({});
  await db.dhcpLease.deleteMany({});
  await db.dhcpSubnet.deleteMany({});
  await db.identityActivityEvent.deleteMany({});
  const subnet = await db.dhcpSubnet.create({
    data: {
      tenantId: 1,
      interfaceName: "lan0",
      subnetCidr: "192.168.77.0/24",
      rangeStart: "192.168.77.10",
      rangeEnd: "192.168.77.250",
      gateway: "192.168.77.1",
    },
  });
  subnetId = subnet.id;
});

afterAll(async () => {
  await db.$disconnect();
  fs.rmSync(TMP_DIR, { recursive: true, force: true });
});

function leaseIp(i: number): string {
  return `10.99.${Math.floor(i / 250)}.${(i % 250) + 1}`;
}

function macFromIndex(i: number, prefix = "D4:CA:6D"): string {
  const hex = i.toString(16).padStart(6, "0");
  return `${prefix}:${hex.slice(0, 2)}:${hex.slice(2, 4)}:${hex.slice(4, 6)}`.toUpperCase();
}

function leaseRow(mac: string, ip: string, hostname: string | null, ageMs = 60_000) {
  return {
    tenantId: 1,
    subnetId,
    mac,
    ip,
    hostname,
    state: "active",
    startsAt: new Date(Date.now() - ageMs),
    endsAt: new Date(Date.now() + HOUR),
  };
}

async function createDevice(overrides: Record<string, unknown> = {}) {
  return db.nacDevice.create({
    data: {
      tenantId: 1,
      macAddress: MAC_UNKNOWN,
      ip: "192.168.77.99",
      ...overrides,
    } as Parameters<typeof db.nacDevice.create>[0]["data"],
  });
}

// ── pure: MAC normalization ─────────────────────────────────────────────────

describe("normalizeMac", () => {
  it("handles dash, bare and colon notations into uppercase colon form", () => {
    expect(oui.normalizeMac("aa-bb-cc-dd-ee-ff")).toBe("AA:BB:CC:DD:EE:FF");
    expect(oui.normalizeMac("aabbccddeeff")).toBe("AA:BB:CC:DD:EE:FF");
    expect(oui.normalizeMac("AA:BB:CC:DD:EE:FF")).toBe("AA:BB:CC:DD:EE:FF");
    expect(oui.normalizeMac(" 44-47-cC-11-22-33 ")).toBe("44:47:CC:11:22:33");
  });

  it("accepts a 6-hex OUI prefix and rejects malformed input", () => {
    expect(oui.normalizeMac("aabbcc")).toBe("AA:BB:CC");
    expect(oui.normalizeMac("aa-bb-cc")).toBe("AA:BB:CC");
    expect(oui.normalizeMac("AA:BB:CC")).toBe("AA:BB:CC");
    expect(oui.normalizeMac("aa-bb")).toBeNull(); // truncated
    expect(oui.normalizeMac("aa:bb:cc:dd:ee:gg")).toBeNull(); // non-hex
    expect(oui.normalizeMac("")).toBeNull();
  });
});

// ── pure: OUI lookup ────────────────────────────────────────────────────────

describe("lookupOui", () => {
  it("maps known prefixes to vendor + device class hints", () => {
    expect(oui.lookupOui(MAC_HIK)).toEqual({
      vendor: "Hikvision",
      deviceTypeHint: "camera",
      osHint: "camera firmware",
    });
    expect(oui.lookupOui(MAC_APPLE)?.vendor).toBe("Apple");
    expect(oui.lookupOui(MAC_APPLE)?.deviceTypeHint).toBe("mobile");
    expect(oui.lookupOui("00:1B:A9:00:00:01")?.vendor).toBe("Brother Industries");
    expect(oui.lookupOui("24:5E:BE:00:00:01")?.vendor).toBe("Ubiquiti Networks");
    expect(oui.lookupOui("00:11:32:00:00:01")?.vendor).toBe("Synology");
    expect(oui.lookupOui("00:0E:58:00:00:01")?.vendor).toBe("Sonos");
  });

  it("accepts every notation (dash / bare / colon / prefix) and returns null for unknowns", () => {
    expect(oui.lookupOui("4447cc")?.vendor).toBe("Hikvision");
    expect(oui.lookupOui("44-47-cc")?.vendor).toBe("Hikvision");
    expect(oui.lookupOui("44:47:cc:00:00:01")?.vendor).toBe("Hikvision");
    expect(oui.lookupOui(MAC_UNKNOWN)).toBeNull();
    expect(oui.lookupOui("000000")).toBeNull();
    expect(oui.lookupOui("not-a-mac")).toBeNull();
  });

  it("curated subset stays honest (real assigned prefixes only, ~120 entries)", () => {
    expect(oui.ouiMapSize()).toBeGreaterThanOrEqual(100);
    expect(oui.ouiMapSize()).toBeLessThanOrEqual(200);
    // unassigned / unknown prefixes must never guess
    expect(oui.lookupOui("00:00:00:00:00:00")).toBeNull();
    expect(oui.lookupOui("00:00:01")).toEqual({
      vendor: "Xerox",
      deviceTypeHint: "printer",
      osHint: "embedded print server",
    });
  });
});

// ── pure: signal fusion ─────────────────────────────────────────────────────

describe("profileFromSignals", () => {
  it("fuses agreeing OUI + hostname signals (confidence 80)", () => {
    const profile = profiling.profileFromSignals({ mac: MAC_HIK, hostname: "cam-parking" });
    expect(profile.vendor).toBe("Hikvision");
    expect(profile.deviceType).toBe("camera");
    expect(profile.osGuess).toBe("camera firmware");
    expect(profile.confidence).toBe(80); // oui 45 + hostname 35
    expect(profile.matchedSignals).toEqual(["oui:camera", "hostname:camera"]);
  });

  it("classifies from hostname alone when the OUI is unknown (confidence 35)", () => {
    const printer = profiling.profileFromSignals({ mac: MAC_BARE, hostname: "epson-lobby" });
    expect(printer.deviceType).toBe("printer");
    expect(printer.vendor).toBeNull();
    expect(printer.confidence).toBe(35);

    const tv = profiling.profileFromSignals({ mac: MAC_BARE, hostname: "tv-lobby" });
    expect(tv.deviceType).toBe("iot");

    const phone = profiling.profileFromSignals({ mac: MAC_BARE, hostname: "iphone-mk" });
    expect(phone.deviceType).toBe("mobile");

    const ws = profiling.profileFromSignals({ mac: MAC_BARE, hostname: "ws-finance-02" });
    expect(ws.deviceType).toBe("workstation");
  });

  it("maps DHCP vendor classes (android-dhcp → Android, MSFT 5.0 → Windows)", () => {
    const android = profiling.profileFromSignals({ mac: MAC_BARE, dhcpVendorClass: "android-dhcp-13" });
    expect(android.deviceType).toBe("mobile");
    expect(android.osGuess).toBe("Android");
    expect(android.confidence).toBe(25);

    const windows = profiling.profileFromSignals({ mac: MAC_BARE, dhcpVendorClass: "MSFT 5.0" });
    expect(windows.deviceType).toBe("workstation");
    expect(windows.osGuess).toBe("Windows");
    expect(windows.confidence).toBe(25);
  });

  it("nDPI labels override the OUI hint and drop disagreeing os guesses", () => {
    // Apple OUI says mobile, RTSP says camera — nDPI wins, osHint discarded
    const profile = profiling.profileFromSignals({ mac: MAC_APPLE, nDpiLabels: ["RTSP"] });
    expect(profile.deviceType).toBe("camera");
    expect(profile.vendor).toBe("Apple"); // vendor is still known
    expect(profile.osGuess).toBeNull(); // iOS/macOS disagrees → dropped
    expect(profile.confidence).toBe(60); // only the nDPI signal agrees
  });

  it("nDPI + hostname agreement stacks confidence (capped at 100)", () => {
    const profile = profiling.profileFromSignals({
      mac: MAC_BARE,
      hostname: "printer-3f",
      dhcpVendorClass: "MSFT 5.0",
      nDpiLabels: ["AirPrint"],
    });
    // ndpi 60 + hostname 35 agree, vendor-class (workstation) disagrees
    expect(profile.deviceType).toBe("printer");
    expect(profile.confidence).toBe(95);
  });

  it("keeps vendor-only OUI entries without claiming a type", () => {
    const profile = profiling.profileFromSignals({ mac: "00:07:AB:00:00:01", hostname: "living-room-tv" });
    expect(profile.vendor).toBe("Samsung Electronics");
    expect(profile.deviceType).toBe("iot"); // hostname signal
    expect(profile.confidence).toBe(35);
  });

  it("stays honestly unknown with no usable signals", () => {
    const profile = profiling.profileFromSignals({ mac: MAC_UNKNOWN });
    expect(profile.vendor).toBeNull();
    expect(profile.deviceType).toBe("unknown");
    expect(profile.osGuess).toBeNull();
    expect(profile.confidence).toBe(0);
    expect(profile.matchedSignals).toEqual([]);
  });

  it("keeps the strongest signal when two disagree (OUI > hostname)", () => {
    const profile = profiling.profileFromSignals({ mac: MAC_HIK, hostname: "iphone-mk" });
    expect(profile.deviceType).toBe("camera"); // OUI 45 beats hostname 35
    expect(profile.confidence).toBe(45);
  });
});

// ── pure: rogue check ───────────────────────────────────────────────────────

describe("rogueCheck", () => {
  const now = new Date("2026-01-01T12:00:00Z");

  it("flags unknown, unclassified and fresh MACs", () => {
    const device = { macAddress: MAC_UNKNOWN, firstSeen: new Date(Date.parse("2026-01-01T11:00:00Z")), deviceType: "unknown" as const };
    expect(profiling.rogueCheck(device, ["AA:BB:CC:DD:EE:FF"], now)).toBe(true);
  });

  it("does not flag known MACs, classified devices or stale firstSeen", () => {
    const fresh = { macAddress: MAC_UNKNOWN, firstSeen: new Date(Date.parse("2026-01-01T11:00:00Z")), deviceType: "unknown" as const };
    expect(profiling.rogueCheck(fresh, [MAC_UNKNOWN], now)).toBe(false); // MAC known
    expect(profiling.rogueCheck(fresh, [macFromIndex(1)], now)).toBe(true); // different list → still rogue

    const printer = { ...fresh, deviceType: "printer" as const };
    expect(profiling.rogueCheck(printer, [], now)).toBe(false); // classified

    const stale = { ...fresh, firstSeen: new Date(Date.parse("2026-01-01T11:00:00Z") - 25 * HOUR) };
    expect(profiling.rogueCheck(stale, [], now)).toBe(false); // older than 24h
  });

  it("accepts ISO string firstSeen and normalizes MAC notation", () => {
    expect(profiling.rogueCheck({ macAddress: "de-ad-be-ef-00-02", firstSeen: "2026-01-01T11:30:00Z", deviceType: "unknown" }, ["DE:AD:BE:EF:00:02"], now)).toBe(false);
    expect(profiling.rogueCheck({ macAddress: "DE:AD:BE:EF:00:02", firstSeen: "2026-01-01T11:30:00Z", deviceType: "unknown" }, [], now)).toBe(true);
  });
});

// ── pure: risk scoring ──────────────────────────────────────────────────────

describe("riskScoreFor + clampRisk", () => {
  it("applies the §3.6 formula deterministically", () => {
    expect(profiling.riskScoreFor({ deviceType: "workstation", quarantined: false, osGuess: "Windows 11" })).toBe(30);
    expect(profiling.riskScoreFor({ deviceType: "camera", quarantined: false, osGuess: "camera firmware" })).toBe(45);
    expect(profiling.riskScoreFor({ deviceType: "iot", quarantined: false, osGuess: "ESP firmware" })).toBe(45);
    expect(profiling.riskScoreFor({ deviceType: "unknown", quarantined: false, osGuess: null })).toBe(60);
    expect(profiling.riskScoreFor({ deviceType: "unknown", quarantined: true, osGuess: null })).toBe(90); // max combo
  });

  it("clamps to 0-100", () => {
    expect(profiling.clampRisk(140)).toBe(100);
    expect(profiling.clampRisk(-3)).toBe(0);
    expect(profiling.riskScoreFor({ deviceType: "unknown", quarantined: true, osGuess: "" })).toBeLessThanOrEqual(100);
  });
});

// ── DB: rescan ──────────────────────────────────────────────────────────────

describe("rescanProfile (DB)", () => {
  it("re-profiles devices, applies the risk formula and refreshes lastSeen", async () => {
    const beforeMs = Date.now();
    const cam = await createDevice({
      macAddress: MAC_HIK,
      ip: "192.168.77.31",
      hostname: "cam-parking",
      deviceType: "unknown",
      nacState: "quarantine",
      vlanId: 900,
      riskScore: 10,
      firstSeen: new Date(beforeMs - 24 * HOUR),
      lastSeen: new Date(beforeMs - HOUR),
    });
    const ws = await createDevice({
      macAddress: MAC_UNKNOWN,
      ip: "192.168.77.32",
      hostname: "ws-finance-02",
      deviceType: "unknown",
      nacState: "authenticated",
      riskScore: 10,
      firstSeen: new Date(beforeMs - HOUR),
    });

    const summary = await service.rescanProfile(1);
    expect(summary.rescanned).toBe(2);
    expect(summary.created).toBe(0);

    const camAfter = await db.nacDevice.findUniqueOrThrow({ where: { id: cam.id } });
    expect(camAfter.deviceType).toBe("camera");
    expect(camAfter.vendor).toBe("Hikvision");
    expect(camAfter.osGuess).toBe("camera firmware"); // OUI osHint fills the gap
    // base 30 + camera 15 + quarantined 30 = 75 (osGuess now present)
    expect(camAfter.riskScore).toBe(75);
    expect(camAfter.lastSeen.getTime()).toBeGreaterThan(beforeMs);

    const wsAfter = await db.nacDevice.findUniqueOrThrow({ where: { id: ws.id } });
    expect(wsAfter.deviceType).toBe("workstation"); // hostname pattern
    expect(wsAfter.osGuess).toBeNull(); // hostname carries no OS claim
    expect(wsAfter.riskScore).toBe(40); // base 30 + 10 missing osGuess
  });

  it("keeps an existing classification when the curated subset cannot improve it", async () => {
    const device = await createDevice({
      macAddress: MAC_UNKNOWN,
      ip: "192.168.77.33",
      hostname: null,
      deviceType: "printer", // typed earlier by another probe
      nacState: "authenticated",
      riskScore: 35,
    });
    await service.rescanProfile(1);
    const after = await db.nacDevice.findUniqueOrThrow({ where: { id: device.id } });
    expect(after.deviceType).toBe("printer"); // no regression to unknown
    expect(after.riskScore).toBe(40); // 30 base + 10 missing osGuess
  });

  it("onboards pending devices from the newest leases and skips known MACs", async () => {
    await createDevice({
      macAddress: MAC_HIK,
      ip: "192.168.77.31",
      hostname: "cam-parking",
      deviceType: "camera",
      nacState: "mab",
      riskScore: 55,
    });
    await db.dhcpLease.createMany({
      data: [
        leaseRow(MAC_ESP, "192.168.77.101", "shelly-plug-1"),
        leaseRow(MAC_BARE, "192.168.77.102", null),
        leaseRow(MAC_HIK, "192.168.77.103", "cam-parking"), // device row exists
      ],
    });

    const summary = await service.rescanProfile(1);
    expect(summary.rescanned).toBe(1);
    expect(summary.created).toBe(2);
    expect(summary.skipped).toBe(1);

    const esp = await db.nacDevice.findFirstOrThrow({ where: { macAddress: MAC_ESP } });
    expect(esp.nacState).toBe("pending");
    expect(esp.vendor).toBe("Espressif Systems");
    expect(esp.deviceType).toBe("iot"); // OUI + hostname agree
    expect(esp.osGuess).toBe("ESP firmware");
    expect(esp.riskScore).toBe(45); // 30 + 15 iot, os present
    expect(esp.ip).toBe("192.168.77.101");

    const bare = await db.nacDevice.findFirstOrThrow({ where: { macAddress: "AA:BB:CC:DD:EE:FF" } });
    expect(bare.nacState).toBe("pending");
    expect(bare.deviceType).toBe("unknown"); // lease carried lowercase mac → normalized
    expect(bare.riskScore).toBe(60); // 30 + 20 unknown + 10 missing os
  });

  it("honors the 500-lease scan cap", async () => {
    const rows = Array.from({ length: 503 }, (_, i) =>
      leaseRow(macFromIndex(i), leaseIp(i), `esp-plug-${i}`, i * 1000),
    );
    await db.dhcpLease.createMany({ data: rows });

    const summary = await service.rescanProfile(1);
    expect(summary.rescanned).toBe(0);
    expect(summary.created).toBe(500); // cap honored — 3 leases beyond the scan cap
    expect(summary.skipped).toBe(0);
    expect(await db.nacDevice.count({ where: { tenantId: 1 } })).toBe(500);

    // second sweep: every lease MAC is now known → nothing new
    const again = await service.rescanProfile(1);
    expect(again.created).toBe(0);
    expect(again.rescanned).toBe(500);
    expect(again.skipped).toBe(500);
  });
});

// ── DB: inventory ───────────────────────────────────────────────────────────

describe("listInventory (DB)", () => {
  async function seedInventory() {
    const printer = await createDevice({
      macAddress: "00:1F:29:00:00:11",
      ip: "192.168.77.20",
      hostname: "prn-hq-01",
      vendor: "Hewlett-Packard",
      deviceType: "printer",
      osGuess: "embedded print server",
      nacState: "authenticated",
      riskScore: 30,
    });
    const cam = await createDevice({
      macAddress: MAC_HIK,
      ip: "192.168.77.31",
      hostname: "cam-parking",
      vendor: "Hikvision",
      deviceType: "camera",
      nacState: "quarantine",
      riskScore: 75,
    });
    const iot = await createDevice({
      macAddress: MAC_ESP,
      ip: "192.168.77.40",
      hostname: "shelly-plug-1",
      vendor: "Espressif Systems",
      deviceType: "iot",
      nacState: "pending",
      riskScore: 45,
    });
    const rogue = await createDevice({
      macAddress: MAC_UNKNOWN,
      ip: "192.168.77.50",
      hostname: null,
      deviceType: "unknown",
      nacState: "pending",
      riskScore: 60,
      firstSeen: new Date(Date.now() - HOUR),
    });
    // leases "vouch" for everything except the rogue
    await db.dhcpLease.createMany({
      data: [
        leaseRow("00:1F:29:00:00:11", "192.168.77.20", "prn-hq-01"),
        leaseRow(MAC_HIK, "192.168.77.31", "cam-parking"),
        leaseRow(MAC_ESP, "192.168.77.40", "shelly-plug-1"),
      ],
    });
    return { printer, cam, iot, rogue };
  }

  it("paginates with PageMeta semantics", async () => {
    await seedInventory();
    const page = await service.listInventory(1, { page: 1, limit: 2 });
    expect(page.data).toHaveLength(2);
    expect(page.meta).toEqual({ page: 1, limit: 2, total: 4, totalPages: 2 });
    const second = await service.listInventory(1, { page: 2, limit: 2 });
    expect(second.data).toHaveLength(2);
  });

  it("filters by deviceType, vendor, quarantined and q", async () => {
    await seedInventory();

    const printers = await service.listInventory(1, { deviceType: "printer" });
    expect(printers.meta.total).toBe(1);
    expect(printers.data[0].deviceType).toBe("printer");

    const quarantined = await service.listInventory(1, { quarantined: true });
    expect(quarantined.meta.total).toBe(1);
    expect(quarantined.data[0].nacState).toBe("quarantine");
    const notQuarantined = await service.listInventory(1, { quarantined: false });
    expect(notQuarantined.meta.total).toBe(3);

    const vendorHit = await service.listInventory(1, { vendor: "hewlett" });
    expect(vendorHit.meta.total).toBe(1); // SQLite contains is case-insensitive
    expect(vendorHit.data[0].vendor).toBe("Hewlett-Packard");

    const byIp = await service.listInventory(1, { q: "77.50" });
    expect(byIp.meta.total).toBe(1);
    expect(byIp.data[0].ip).toBe("192.168.77.50");
  });

  it("enriches rows with the rogue flag (unknown + unleased + fresh)", async () => {
    const { rogue } = await seedInventory();
    const all = await service.listInventory(1, {});
    const flagged = all.data.filter((d) => d.rogue);
    expect(flagged).toHaveLength(1);
    expect(flagged[0].id).toBe(rogue.id);
  });
});

// ── DB: rescore ─────────────────────────────────────────────────────────────

describe("rescoreDevice (DB)", () => {
  it("recomputes the risk score with the formula and clamps", async () => {
    const device = await createDevice({
      macAddress: MAC_UNKNOWN,
      ip: "192.168.77.60",
      deviceType: "unknown",
      nacState: "quarantine",
      riskScore: 5,
    });

    const first = await service.rescoreDevice(1, device.id);
    expect(first.device.riskScore).toBe(90); // 30 + 20 + 30 + 10 (max combo)
    expect(first.audit.action).toBe("iot.rescore");
    expect(first.audit.after).toEqual({ riskScore: 90 });

    await db.nacDevice.update({ where: { id: device.id }, data: { osGuess: "embedded Linux" } });
    const second = await service.rescoreDevice(1, device.id);
    expect(second.device.riskScore).toBe(80); // osGuess no longer missing

    expect(profiling.clampRisk(140)).toBe(100); // clamp guard stays in place
    expect(profiling.riskScoreFor({ deviceType: "unknown", quarantined: true, osGuess: null })).toBeLessThanOrEqual(100);

    await expect(service.rescoreDevice(1, 999_999)).rejects.toThrow(/not found/i);
  });
});

// ── DB: stats ───────────────────────────────────────────────────────────────

describe("getIotStats (DB)", () => {
  it("aggregates type counts, quarantined, avg risk and rogue candidates", async () => {
    await createDevice({
      macAddress: MAC_HIK,
      ip: "192.168.77.31",
      deviceType: "camera",
      nacState: "quarantine",
      riskScore: 75,
    });
    await createDevice({
      macAddress: MAC_ESP,
      ip: "192.168.77.40",
      deviceType: "iot",
      nacState: "pending",
      riskScore: 45,
    });
    await createDevice({
      macAddress: MAC_UNKNOWN,
      ip: "192.168.77.50",
      deviceType: "unknown",
      nacState: "pending",
      riskScore: 60,
      firstSeen: new Date(Date.now() - HOUR), // no lease → rogue
    });
    await createDevice({
      macAddress: MAC_BARE.toUpperCase().replace(/(..)(?=.)/g, "$1:"),
      ip: "192.168.77.51",
      deviceType: "unknown",
      nacState: "quarantine",
      riskScore: 90,
      firstSeen: new Date(Date.now() - 48 * HOUR), // stale → no rogue flag
    });
    await db.dhcpLease.createMany({
      data: [leaseRow(MAC_HIK, "192.168.77.31", "cam-parking"), leaseRow(MAC_ESP, "192.168.77.40", "shelly-plug-1")],
    });

    const stats = await service.getIotStats(1);
    expect(stats.total).toBe(4);
    expect(stats.byType.camera).toBe(1);
    expect(stats.byType.iot).toBe(1);
    expect(stats.byType.unknown).toBe(2);
    expect(stats.iot).toBe(1);
    expect(stats.cameras).toBe(1);
    expect(stats.quarantined).toBe(2);
    expect(stats.avgRisk).toBe(Math.round((75 + 45 + 60 + 90) / 4));
    expect(stats.rogues).toBe(1);
  });

  it("returns zeros for an empty tenant", async () => {
    const stats = await service.getIotStats(1);
    expect(stats.total).toBe(0);
    expect(stats.avgRisk).toBe(0);
    expect(stats.rogues).toBe(0);
    expect(stats.byType.unknown).toBe(0);
  });
});

// ── DB: quarantine/restore reuse ────────────────────────────────────────────

describe("quarantine/restore reuse (DB)", () => {
  it("delegates to the shared M23 lifecycle and interacts with rescoring", async () => {
    const device = await createDevice({
      macAddress: MAC_APPLE,
      ip: "192.168.77.70",
      hostname: "iphone-mk",
      deviceType: "mobile",
      nacState: "authenticated",
      vlanId: 30,
      riskScore: 25,
    });

    const q = await service.quarantineNacDevice(1, device.id);
    expect(q.device.nacState).toBe("quarantine");
    expect(q.device.vlanId).toBe(30); // kept when no explicit VLAN is passed
    expect(q.audit.action).toBe("nac.device.quarantine");

    // rescan now adds the quarantine bump on top of the profiled type
    await service.rescanProfile(1);
    const after = await db.nacDevice.findUniqueOrThrow({ where: { id: device.id } });
    expect(after.deviceType).toBe("mobile"); // OUI + hostname agree
    expect(after.osGuess).toBe("iOS/macOS");
    // base 30 + quarantined 30 (mobile: no class bump, os present: no os bump)
    expect(after.riskScore).toBe(60);
    expect(after.riskScore).toBe(
      profiling.riskScoreFor({ deviceType: "mobile", quarantined: true, osGuess: "iOS/macOS" }),
    );

    const events = await db.identityActivityEvent.findMany({ where: { tenantId: 1, event: "vlan_change" } });
    expect(events).toHaveLength(1);
    expect(JSON.parse(events[0].detail)).toMatchObject({ quarantined: true, vlanId: 30, mac: MAC_APPLE });

    const r = await service.restoreNacDevice(1, device.id);
    expect(r.device.nacState).toBe("authenticated");
    expect(r.device.vlanId).toBeNull();
    expect(r.audit.action).toBe("nac.device.restore");

    await expect(service.quarantineNacDevice(1, 999_999)).rejects.toThrow(/not found/i);
    await expect(service.restoreNacDevice(1, 999_999)).rejects.toThrow(/not found/i);
  });

  it("honors an explicit quarantine VLAN override", async () => {
    const device = await createDevice({ nacState: "authenticated", vlanId: 10 });
    const q = await service.quarantineNacDevice(1, device.id, 900);
    expect(q.device.vlanId).toBe(900);
    expect(q.audit.after).toEqual({ nacState: "quarantine", vlanId: 900 });
  });
});
