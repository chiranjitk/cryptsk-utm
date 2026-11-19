/**
 * /api/v1/casb/catalog — tenant SaaS catalog list + create (Phase 4 §4.3).
 * The shipped defaults come from POST /api/v1/casb/seed (idempotent) and are
 * also auto-seeded by a scan; this endpoint manages operator entries.
 */

import { route } from "@/lib/api/handler";
import { saasAppCreateSchema, saasAppQuerySchema } from "@/lib/validators/casb";
import { createSaasApp, listSaasApps } from "@/lib/casb/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "casb", querySchema: saasAppQuerySchema }, async ({ auth, query }) => {
  return listSaasApps(auth.tenantId, query);
});

export const POST = route({ area: "casb", bodySchema: saasAppCreateSchema }, async ({ auth, body }) => {
  const created = await createSaasApp(auth.tenantId, body);
  return {
    data: created,
    audit: {
      action: "casb.catalog.create",
      objectType: "saas_app_catalog",
      objectId: created.id,
      objectName: created.name,
      after: created,
    },
  };
});
