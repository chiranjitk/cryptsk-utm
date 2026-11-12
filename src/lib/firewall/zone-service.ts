/**
 * Zone service — keeps `Zone.interfaceNames` (JSON array) and the hard FK
 * `NetworkInterface.zoneId` consistent on every save/delete (M03 §2),
 * validates member iface names and enforces protected zones (WAN/LAN).
 */

import { db } from "@/lib/db";
import type { Prisma } from "@prisma/client";
import { ApiError } from "@/lib/api/errors";

export const PROTECTED_ZONES = ["WAN", "LAN"];

/**
 * DbClient — the global prisma client OR an interactive-transaction client.
 * Zone sync runs INSIDE $transaction blocks on the write paths; using the
 * global client there self-deadlocks on SQLite (the tx holds the write lock,
 * the global client's UPDATE waits on it, the tx waits for the callback).
 * Callers inside a transaction MUST pass their `tx`.
 */
type DbClient = Prisma.TransactionClient | typeof db;

export async function syncZoneMembers(
  zoneId: number,
  tenantId: number,
  nextNames: string[],
  client: DbClient = db,
): Promise<void> {
  const zone = await client.zone.findFirst({ where: { id: zoneId, tenantId } });
  const prevNames = zone ? (JSON.parse(zone.interfaceNames) as string[]) : [];
  const allIfaces = await client.networkInterface.findMany({ where: { tenantId } });

  const valid = new Set(allIfaces.map((i) => i.name));
  const missing = nextNames.filter((n) => !valid.has(n));
  if (missing.length > 0) {
    throw ApiError.validation("Unknown interface name in interfaceNames", { offendingNames: missing });
  }

  const next = new Set(nextNames);
  const prev = new Set(prevNames);

  // remove: ifaces that were members and are no longer listed
  const removed = [...prev].filter((n) => !next.has(n));
  if (removed.length) {
    await client.networkInterface.updateMany({
      where: { tenantId, name: { in: removed }, zoneId },
      data: { zoneId: null },
    });
  }
  // add/move: listed ifaces (including ones currently in another zone)
  if (nextNames.length) {
    await client.networkInterface.updateMany({
      where: { tenantId, name: { in: nextNames } },
      data: { zoneId },
    });
  }
  // guard: an iface should belong to at most one zone
  await client.networkInterface.updateMany({
    where: { tenantId, zoneId, name: { notIn: nextNames.length ? nextNames : ["__none__"] } },
    data: { zoneId: null },
  });
}

export async function detachZoneMembers(zoneId: number, client: DbClient = db): Promise<void> {
  await client.networkInterface.updateMany({ where: { zoneId }, data: { zoneId: null } });
}

export function assertZoneNotProtected(name: string, action: string): void {
  if (PROTECTED_ZONES.includes(name)) {
    throw ApiError.conflict(`Zone '${name}' is protected and cannot be ${action}`, { protected: true });
  }
}
