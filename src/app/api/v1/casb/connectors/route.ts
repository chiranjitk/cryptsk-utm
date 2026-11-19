/**
 * /api/v1/casb/connectors — vendor API connector shell list + create
 * (Phase 4 §4.3). One connector per vendor per tenant; config values are
 * secret-store refs (never plaintext). NO vendor network calls — live sync
 * is deferred per the spec note.
 */

import { route } from "@/lib/api/handler";
import { connectorCreateSchema } from "@/lib/validators/casb";
import { createConnector, listConnectors } from "@/lib/casb/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "casb" }, async ({ auth }) => {
  return { data: await listConnectors(auth.tenantId) };
});

export const POST = route({ area: "casb", bodySchema: connectorCreateSchema }, async ({ auth, body }) => {
  const created = await createConnector(auth.tenantId, body);
  return {
    data: created,
    audit: {
      action: "casb.connector.create",
      objectType: "casb_connector",
      objectId: created.id,
      objectName: created.vendorLabel,
      after: { vendor: created.vendor, status: created.status },
    },
  };
});
