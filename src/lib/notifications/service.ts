/**
 * Notifications service (M10 §5.5) — the Notification table is written by the
 * MockEngine (threat alerts, resource alerts) and by restore/firmware flows;
 * this service owns the read/mark-read surface. `isRead` is the only mutable
 * field in Phase 1 (no delete/dismiss — pruning is automatic, DATA_LIFECYCLE §4).
 */

import { db } from "@/lib/db";

export type NotificationDTO = {
  id: number;
  type: string;
  severity: string;
  title: string;
  message: string | null;
  sourceModule: string | null;
  isRead: boolean;
  createdAt: string;
};

function toDTO(row: {
  id: number;
  type: string;
  severity: string;
  title: string;
  message: string | null;
  sourceModule: string | null;
  isRead: boolean;
  createdAt: Date;
}): NotificationDTO {
  return {
    id: row.id,
    type: row.type,
    severity: row.severity,
    title: row.title,
    message: row.message,
    sourceModule: row.sourceModule,
    isRead: row.isRead,
    createdAt: row.createdAt.toISOString(),
  };
}

export async function listNotifications(
  tenantId: number,
  q: { unread?: boolean; type?: string; page: number; limit: number },
): Promise<{ data: NotificationDTO[]; meta: { page: number; limit: number; total: number; totalPages: number } }> {
  const where = {
    tenantId,
    ...(q.unread !== undefined ? { isRead: !q.unread } : {}),
    ...(q.type ? { type: q.type } : {}),
  };
  const [total, rows] = await Promise.all([
    db.notification.count({ where }),
    db.notification.findMany({
      where,
      orderBy: { createdAt: "desc" },
      skip: (q.page - 1) * q.limit,
      take: q.limit,
    }),
  ]);
  return {
    data: rows.map(toDTO),
    meta: { page: q.page, limit: q.limit, total, totalPages: Math.max(1, Math.ceil(total / q.limit)) },
  };
}

export async function unreadCount(tenantId: number): Promise<number> {
  return db.notification.count({ where: { tenantId, isRead: false } });
}

export async function markRead(tenantId: number, id: number, isRead = true): Promise<NotificationDTO | null> {
  const row = await db.notification.findFirst({ where: { tenantId, id } });
  if (!row) return null;
  const updated = await db.notification.update({ where: { id }, data: { isRead } });
  return toDTO(updated);
}

export async function markAllRead(tenantId: number): Promise<number> {
  const res = await db.notification.updateMany({ where: { tenantId, isRead: false }, data: { isRead: true } });
  return res.count;
}
