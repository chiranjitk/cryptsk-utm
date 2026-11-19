/**
 * /api/v1/casb/catalog/[id] — update or remove one SaaS catalog entry.
 * Deleting a catalog app detaches its logical appId from existing discovery
 * rows (raw hints stay; the next scan re-classifies them).
 */

import { route, numericId } from "@/lib/api/handler";
import { saasAppUpdateSchema } from "@/lib/validators/casb";
import { deleteSaasApp, updateSaasApp } from "@/lib/casb/service";

export const dynamic = "force-dynamic";

export const PATCH = route({ area: "casb", bodySchema: saasAppUpdateSchema }, async ({ auth, body, params }) => {
  const id = numericId(params, "id");
  const updated = await updateSaasApp(auth.tenantId, id, body);
  return {
    data: updated,
    audit: {
      action: "casb.catalog.update",
      objectType: "saas_app_catalog",
      objectId: id,
      objectName: updated.name,
      after: updated,
    },
  };
});

export const DELETE = route({ area: "casb" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const deleted = await deleteSaasApp(auth.tenantId, id);
  return { data: deleted, audit: { action: "casb.catalog.delete", objectType: "saas_app_catalog", objectId: id } };
});
