/**
 * GET /api/v1/users — minimal identity roster for pickers (M03 Users picker;
 * full user management is M07). Read floor: identity.read matrix (super_admin,
 * tenant_admin, security_admin — the matrix wins over the coarse floor).
 */

import { route } from "@/lib/api/handler";
import { db } from "@/lib/db";

export const dynamic = "force-dynamic";

export const GET = route({ area: "identity" }, async ({ auth }) => {
  const users = await db.user.findMany({
    where: { tenantId: auth.tenantId },
    orderBy: { username: "asc" },
    select: { id: true, username: true, role: true, isActive: true },
  });
  return { data: users };
});
