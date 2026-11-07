/**
 * NAC devices list (M23, spec 2.9) — paged-lite (max 100 rows, no PageMeta).
 * Filters: ?state= ?deviceType= ?q= (matches mac/ip/hostname). Rows carry the
 * NAC profile name via a logical-ref map (nacProfileId is not a relation).
 */

import { route } from "@/lib/api/handler";
import { devicesQuerySchema } from "@/lib/validators/identity-advanced";
import { db } from "@/lib/db";
import { toDeviceDTO } from "@/app/api/v1/identity-advanced/_lib/server";

export const dynamic = "force-dynamic";

export const GET = route({ area: "identity", querySchema: devicesQuerySchema }, async ({ auth, query }) => {
  const where = {
    tenantId: auth.tenantId,
    ...(query.state ? { nacState: query.state } : {}),
    ...(query.deviceType ? { deviceType: query.deviceType } : {}),
    ...(query.q
      ? {
          OR: [
            { macAddress: { contains: query.q } },
            { ip: { contains: query.q } },
            { hostname: { contains: query.q } },
          ],
        }
      : {}),
  };
  const [rows, profiles] = await Promise.all([
    db.nacDevice.findMany({ where, orderBy: { lastSeen: "desc" }, take: query.limit }),
    db.nacProfile.findMany({ where: { tenantId: auth.tenantId }, select: { id: true, name: true } }),
  ]);
  const profileNames = new Map(profiles.map((p) => [p.id, p.name]));
  return { data: rows.map((row) => toDeviceDTO(row, profileNames.get(row.nacProfileId ?? -1) ?? null)) };
});
