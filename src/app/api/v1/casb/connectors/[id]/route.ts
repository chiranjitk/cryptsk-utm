/**
 * /api/v1/casb/connectors/[id] — update config (or manually reset status)
 * and delete the connector shell. Config edits keep the current status; the
 * shape-only test endpoint re-validates.
 */

import { route, numericId } from "@/lib/api/handler";
import { connectorPatchSchema } from "@/lib/validators/casb";
import { deleteConnector, updateConnector } from "@/lib/casb/service";

export const dynamic = "force-dynamic";

export const PATCH = route({ area: "casb", bodySchema: connectorPatchSchema }, async ({ auth, body, params }) => {
  const id = numericId(params, "id");
  const updated = await updateConnector(auth.tenantId, id, body);
  return {
    data: updated,
    audit: {
      action: "casb.connector.update",
      objectType: "casb_connector",
      objectId: id,
      objectName: updated.vendorLabel,
      after: { status: updated.status },
    },
  };
});

export const DELETE = route({ area: "casb" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const deleted = await deleteConnector(auth.tenantId, id);
  return { data: deleted, audit: { action: "casb.connector.delete", objectType: "casb_connector", objectId: id } };
});
