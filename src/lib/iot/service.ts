/**
 * IoT device management service (Phase 3 §3.6) — DB-backed layer over the
 * EXISTING NAC tables (no new Prisma models): re-profiles nac_devices from
 * OUI/hostname/DHCP signals, onboards pending devices from the newest DHCP
 * leases (500-row scan cap), serves the paginated inventory with rogue flags,
 * recomputes risk scores and aggregates the stats chips.
 *
 * Quarantine/restore REUSE the identity-advanced shared lifecycle helpers
 * (M23 _lib/server.ts) via re-export — no duplicated logic; the IoT view
 * calls the same /identity-advanced quarantine/restore endpoints.
 */

import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import {
  quarantineNacDevice,
  restoreNacDevice,
  toDeviceDTO,
  type DeviceDTO,
} from "@/app/api/v1/identity-advanced/_lib/server";
import { normalizeMac } from "./oui";
import { profileFromSignals, riskScoreFor, rogueCheck, type DeviceType } from "./profiling";

/** Shared device lifecycle — the single M23 implementation, re-exported. */
export { quarantineNacDevice, restoreNacDevice };

// ── DTOs (client mirrors live in identity-advanced-api.ts) ──────────────────

export interface IotDeviceDTO extends DeviceDTO {
  /** MAC unknown to DHCP + firstSeen <24h + still unclassified. */
  rogue: boolean;
}

export interface IotInventoryPage {
  data: IotDeviceDTO[];
  meta: { page: number; limit: number; total: number; totalPages: number };
}

export interface IotRescanSummary {
  /** Existing devices re-profiled. */
  rescanned: number;
  /** Pending devices onboarded from leases. */
  created: number;
  /** Lease rows examined but not converted (invalid/duplicate/known MAC or over cap). */
  skipped: number;
}

export interface IotStatsDTO {
  total: number;
  byType: Record<DeviceType, number>;
  iot: number;
  cameras: number;
  quarantined: number;
  avgRisk: number;
  rogues: number;
}

// ── helpers ──────────────────────────────────────────────────────────────────

/** Newest leases considered per sweep — the mission cap (§3.6). */
export const LEASE_SCAN_CAP = 500;

function isFullMac(mac: string | null): mac is string {
  return mac !== null && mac.split(":").length === 6;
}

/** Every MAC the DHCP server has leased for the tenant — the "known" baseline. */
async function knownLeaseMacs(tenantId: number): Promise<Set<string>> {
  const leases = await db.dhcpLease.findMany({ where: { tenantId }, select: { mac: true } });
  const known = new Set<string>();
  for (const lease of leases) {
    const mac = normalizeMac(lease.mac);
    if (isFullMac(mac)) known.add(mac);
  }
  return known;
}

function withRogueFlag(
  row: { macAddress: string; firstSeen: Date; deviceType: string } & Record<string, unknown>,
  knownMacs: Set<string>,
): IotDeviceDTO {
  const dto = toDeviceDTO(row as Parameters<typeof toDeviceDTO>[0], null);
  return {
    ...dto,
    rogue: rogueCheck(
      { macAddress: row.macAddress, firstSeen: row.firstSeen, deviceType: dto.deviceType },
      knownMacs,
    ),
  };
}

// ── rescan ───────────────────────────────────────────────────────────────────

/**
 * Profiling rescan sweep:
 *  1. re-runs profileFromSignals for EVERY NacDevice and refreshes
 *     vendor/deviceType/osGuess/riskScore + lastSeen (existing non-unknown
 *     classifications are kept when the curated OUI subset can't improve on
 *     them — no churn on partial coverage),
 *  2. scans the newest 500 DhcpLease rows and creates a pending NacDevice for
 *     every not-yet-known MAC with the profiled fields (cap honored).
 */
export async function rescanProfile(tenantId: number): Promise<IotRescanSummary> {
  const now = new Date();
  const devices = await db.nacDevice.findMany({ where: { tenantId } });

  let rescanned = 0;
  for (const device of devices) {
    const profile = profileFromSignals({ mac: device.macAddress, hostname: device.hostname });
    const deviceType: DeviceType =
      profile.deviceType !== "unknown" ? profile.deviceType : (device.deviceType as DeviceType);
    const vendor = profile.vendor ?? device.vendor ?? null;
    const osGuess = profile.osGuess ?? device.osGuess ?? null;
    const riskScore = riskScoreFor({
      deviceType,
      quarantined: device.nacState === "quarantine",
      osGuess,
    });
    await db.nacDevice.update({
      where: { id: device.id },
      data: { vendor, deviceType, osGuess, riskScore, lastSeen: now },
    });
    rescanned += 1;
  }

  const existingMacs = new Set(
    devices.map((d) => normalizeMac(d.macAddress)).filter(isFullMac),
  );

  const leases = await db.dhcpLease.findMany({
    where: { tenantId },
    orderBy: { id: "desc" },
    take: LEASE_SCAN_CAP,
  });

  let created = 0;
  let skipped = 0;
  const seenInSweep = new Set<string>();
  for (const lease of leases) {
    const mac = normalizeMac(lease.mac);
    if (!isFullMac(mac) || seenInSweep.has(mac) || existingMacs.has(mac)) {
      skipped += 1;
      continue;
    }
    seenInSweep.add(mac);
    existingMacs.add(mac);

    const profile = profileFromSignals({ mac, hostname: lease.hostname });
    const riskScore = riskScoreFor({
      deviceType: profile.deviceType,
      quarantined: false,
      osGuess: profile.osGuess,
    });
    await db.nacDevice.create({
      data: {
        tenantId,
        macAddress: mac,
        ip: lease.ip,
        hostname: lease.hostname ?? null,
        vendor: profile.vendor,
        deviceType: profile.deviceType,
        osGuess: profile.osGuess,
        nacState: "pending",
        riskScore,
        firstSeen: now,
        lastSeen: now,
      },
    });
    created += 1;
  }

  return { rescanned, created, skipped };
}

// ── inventory ────────────────────────────────────────────────────────────────

export interface IotInventoryFilters {
  deviceType?: DeviceType;
  /** Substring match against the vendor column (case-insensitive ASCII). */
  vendor?: string;
  /** true → only quarantine state, false → everything else. */
  quarantined?: boolean;
  /** Free-text match over MAC / IP / hostname / vendor. */
  q?: string;
  page?: number;
  limit?: number;
}

export async function listInventory(
  tenantId: number,
  filters: IotInventoryFilters = {},
): Promise<IotInventoryPage> {
  const page = Math.max(1, Math.trunc(filters.page ?? 1));
  const limit = Math.min(200, Math.max(1, Math.trunc(filters.limit ?? 100)));

  const where = {
    tenantId,
    ...(filters.deviceType ? { deviceType: filters.deviceType } : {}),
    ...(filters.quarantined !== undefined
      ? { nacState: filters.quarantined ? "quarantine" : { not: "quarantine" } }
      : {}),
    ...(filters.vendor ? { vendor: { contains: filters.vendor } } : {}),
    ...(filters.q
      ? {
          OR: [
            { macAddress: { contains: filters.q } },
            { ip: { contains: filters.q } },
            { hostname: { contains: filters.q } },
            { vendor: { contains: filters.q } },
          ],
        }
      : {}),
  };

  const [rows, total, knownMacs] = await Promise.all([
    db.nacDevice.findMany({
      where,
      orderBy: { lastSeen: "desc" },
      skip: (page - 1) * limit,
      take: limit,
    }),
    db.nacDevice.count({ where }),
    knownLeaseMacs(tenantId),
  ]);

  return {
    data: rows.map((row) => withRogueFlag(row, knownMacs)),
    meta: { page, limit, total, totalPages: Math.max(1, Math.ceil(total / limit)) },
  };
}

// ── rescore ──────────────────────────────────────────────────────────────────

/**
 * Recompute one device's risk score with the §3.6 formula (clamped 0-100)
 * and refresh lastSeen. Returns the updated row + the audit payload.
 */
export async function rescoreDevice(tenantId: number, deviceId: number) {
  const device = await db.nacDevice.findFirst({ where: { id: deviceId, tenantId } });
  if (!device) throw ApiError.notFound("Device not found");

  const riskScore = riskScoreFor({
    deviceType: device.deviceType as DeviceType,
    quarantined: device.nacState === "quarantine",
    osGuess: device.osGuess,
  });
  const updated = await db.nacDevice.update({
    where: { id: device.id },
    data: { riskScore, lastSeen: new Date() },
  });

  return {
    device: updated,
    audit: {
      action: "iot.rescore",
      objectType: "nac_device",
      objectId: device.id,
      objectName: device.hostname ?? device.macAddress,
      before: { riskScore: device.riskScore },
      after: { riskScore },
    },
  };
}

// ── stats ────────────────────────────────────────────────────────────────────

export async function getIotStats(tenantId: number): Promise<IotStatsDTO> {
  const [devices, knownMacs] = await Promise.all([
    db.nacDevice.findMany({ where: { tenantId } }),
    knownLeaseMacs(tenantId),
  ]);

  const byType: Record<DeviceType, number> = {
    printer: 0,
    phone: 0,
    camera: 0,
    workstation: 0,
    mobile: 0,
    iot: 0,
    unknown: 0,
  };
  let quarantined = 0;
  let riskSum = 0;
  let rogues = 0;

  for (const row of devices) {
    const deviceType = row.deviceType as DeviceType;
    byType[deviceType] = (byType[deviceType] ?? 0) + 1;
    if (row.nacState === "quarantine") quarantined += 1;
    riskSum += row.riskScore;
    if (rogueCheck({ macAddress: row.macAddress, firstSeen: row.firstSeen, deviceType }, knownMacs)) {
      rogues += 1;
    }
  }

  return {
    total: devices.length,
    byType,
    iot: byType.iot,
    cameras: byType.camera,
    quarantined,
    avgRisk: devices.length === 0 ? 0 : Math.round(riskSum / devices.length),
    rogues,
  };
}
