/**
 * Audit + config versioning (ADR-011) — docs/04-API/API_STANDARDS.md §7.
 * Called from lib/api/handler.ts only; routes never hand-roll audit writes.
 */

import { db } from "@/lib/db";
import { emitEvent } from "@/lib/engine/events";

export interface AuditInfo {
  action: string; // e.g. "rule.create" — <objectType>.<verb>
  objectType: string;
  objectId?: number;
  objectName?: string;
  before?: unknown;
  after?: unknown;
  result?: "success" | "failure" | "denied";
}

export async function writeAudit(opts: {
  tenantId: number;
  userId?: number;
  username?: string;
  sourceIp?: string;
  info: AuditInfo;
}): Promise<void> {
  await db.auditLog.create({
    data: {
      tenantId: opts.tenantId,
      userId: opts.userId ?? null,
      username: opts.username ?? null,
      sourceIp: opts.sourceIp ?? null,
      action: opts.info.action,
      objectType: opts.info.objectType,
      objectId: opts.info.objectId ?? null,
      objectName: opts.info.objectName ?? null,
      beforeState: opts.info.before === undefined ? null : JSON.stringify(opts.info.before),
      afterState: opts.info.after === undefined ? null : JSON.stringify(opts.info.after),
      result: opts.info.result ?? "success",
    },
  });
}

/**
 * Snapshot a config section after a successful mutation and broadcast
 * `config:updated {section}` (realtime service relays it to clients).
 */
export async function snapshotConfigVersion(opts: {
  tenantId: number;
  section: string;
  changeSummary: string;
  userId?: number;
}): Promise<void> {
  const last = await db.configVersion.findFirst({
    where: { tenantId: opts.tenantId, section: opts.section },
    orderBy: { version: "desc" },
  });
  const nextVersion = (last?.version ?? 0) + 1;
  await db.configVersion.create({
    data: {
      tenantId: opts.tenantId,
      version: nextVersion,
      section: opts.section,
      configSnapshot: JSON.stringify({ section: opts.section, version: nextVersion }),
      changeSummary: opts.changeSummary,
      createdBy: opts.userId ?? null,
    },
  });
  emitEvent({ type: "config:updated", payload: { section: opts.section } });
}
