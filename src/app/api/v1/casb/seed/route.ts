/**
 * POST /api/v1/casb/seed — idempotent default SaaS catalog seed (Phase 4
 * §4.3). Creates only missing defaults (operator edits survive re-seeds);
 * returns the created count and the resulting catalog size.
 */

import { route } from "@/lib/api/handler";
import { ensureSaasCatalog } from "@/lib/casb/catalog";
import { db } from "@/lib/db";

export const dynamic = "force-dynamic";

export const POST = route({ area: "casb" }, async ({ auth }) => {
  const created = await ensureSaasCatalog(auth.tenantId);
  const total = await db.saasAppCatalog.count({ where: { tenantId: auth.tenantId } });
  return {
    data: { created, total },
    audit: {
      action: "casb.catalog.seed",
      objectType: "saas_app_catalog",
      after: { created, total },
    },
  };
});
