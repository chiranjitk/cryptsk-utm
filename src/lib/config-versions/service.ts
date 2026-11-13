/**
 * Config versions service (M10 §4 card 12) — read-only listing + detail for
 * the diff viewer. Rows are written exclusively by lib/api/audit.ts
 * (snapshotConfigVersion) on every significant apply; never pruned
 * (DATA_LIFECYCLE §4) so the viewer can always reach v1.
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";

export type ConfigVersionDTO = {
  id: number;
  version: number;
  section: string;
  changeSummary: string | null;
  createdBy: number | null;
  authorUsername: string | null;
  createdAt: string;
};

export type ConfigVersionDetailDTO = ConfigVersionDTO & {
  configSnapshot: string;
};

function toDTO(r: {
  id: number;
  version: number;
  section: string;
  changeSummary: string | null;
  createdBy: number | null;
  author?: { username: string } | null;
  createdAt: Date;
}): ConfigVersionDTO {
  return {
    id: r.id,
    version: r.version,
    section: r.section,
    changeSummary: r.changeSummary,
    createdBy: r.createdBy,
    authorUsername: r.author?.username ?? null,
    createdAt: r.createdAt.toISOString(),
  };
}

export async function listConfigVersions(
  tenantId: number,
  q: { section?: string; page: number; limit: number },
): Promise<{ data: ConfigVersionDTO[]; meta: { page: number; limit: number; total: number; totalPages: number } }> {
  const where = { tenantId, ...(q.section ? { section: q.section } : {}) };
  const [total, rows] = await Promise.all([
    db.configVersion.count({ where }),
    db.configVersion.findMany({
      where,
      orderBy: [{ createdAt: "desc" }, { version: "desc" }],
      include: { author: { select: { username: true } } },
      skip: (q.page - 1) * q.limit,
      take: q.limit,
    }),
  ]);
  return {
    data: rows.map(toDTO),
    meta: { page: q.page, limit: q.limit, total, totalPages: Math.max(1, Math.ceil(total / q.limit)) },
  };
}

export async function getConfigVersion(tenantId: number, id: number): Promise<ConfigVersionDetailDTO> {
  const r = await db.configVersion.findFirst({
    where: { tenantId, id },
    include: { author: { select: { username: true } } },
  });
  if (!r) throw ApiError.notFound("Config version not found");
  return {
    ...toDTO(r),
    configSnapshot: r.configSnapshot,
  };
}
