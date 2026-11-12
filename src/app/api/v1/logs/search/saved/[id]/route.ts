/**
 * M12 saved log searches — DELETE by id (spec 2.13 §2). 404 for other tenants.
 * Write area is `reports` (the `logs` matrix has no write column).
 */

import { route, numericId } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";

export const dynamic = "force-dynamic";

export const DELETE = route({ area: "reports", section: "reports" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  if (!Number.isInteger(id) || id <= 0) throw ApiError.validation("Invalid saved search id");
  const existing = await db.savedLogSearch.findFirst({ where: { tenantId: auth.tenantId, id } });
  if (!existing) throw ApiError.notFound("Saved search not found");
  await db.savedLogSearch.delete({ where: { id } });
  return {
    data: { ok: true },
    audit: {
      action: "saved_search.delete",
      objectType: "saved_search",
      objectId: existing.id,
      objectName: existing.name,
      after: { id: existing.id, name: existing.name },
    },
  };
});
