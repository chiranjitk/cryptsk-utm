/**
 * Email gateway item (M22 §2.8.1) — update / delete, audit
 * `email_gateway.update|delete`, snapshot section `email_security`.
 */

import { route } from "@/lib/api/handler";
import { gatewayUpdateSchema } from "@/lib/validators/email-security";
import { deleteGateway, updateGateway } from "@/app/api/v1/email-security/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "email_security", bodySchema: gatewayUpdateSchema, section: "email_security" },
  async ({ auth, body, params }) => {
    const id = Number(params.id);
    const updated = await updateGateway(auth.tenantId, id, body);
    return {
      data: updated,
      audit: {
        action: "email_gateway.update",
        objectType: "email_gateway",
        objectId: id,
        objectName: updated.name,
        after: updated,
      },
    };
  },
);

export const DELETE = route(
  { area: "email_security", section: "email_security" },
  async ({ auth, params }) => {
    const id = Number(params.id);
    await deleteGateway(auth.tenantId, id);
    return {
      data: { ok: true },
      audit: { action: "email_gateway.delete", objectType: "email_gateway", objectId: id },
    };
  },
);
