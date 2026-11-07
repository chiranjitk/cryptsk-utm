/**
 * Identity activity timeline (M23, spec 2.9) — IdentityActivityEvent rows,
 * newest first. Filters: ?userName= (substring) ?event= (locked enum)
 * ?limit= (default 100). The detail JSON is pre-parsed into chips on the
 * client; malformed rows degrade to { raw }.
 */

import { route } from "@/lib/api/handler";
import { activityQuerySchema } from "@/lib/validators/identity-advanced";
import { db } from "@/lib/db";
import { toActivityDTO } from "@/app/api/v1/identity-advanced/_lib/server";

export const dynamic = "force-dynamic";

export const GET = route({ area: "identity", querySchema: activityQuerySchema }, async ({ auth, query }) => {
  const rows = await db.identityActivityEvent.findMany({
    where: {
      tenantId: auth.tenantId,
      ...(query.userName ? { userName: { contains: query.userName } } : {}),
      ...(query.event ? { event: query.event } : {}),
    },
    orderBy: { createdAt: "desc" },
    take: query.limit,
  });
  return { data: rows.map(toActivityDTO) };
});
