/**
 * Email gateways (M22 §2.8.1) — GET list + POST create.
 * Mutations audit `email_gateway.create` and snapshot section `email_security`.
 */

import { route } from "@/lib/api/handler";
import { gatewayCreateSchema } from "@/lib/validators/email-security";
import { createGateway, listGateways } from "@/app/api/v1/email-security/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "email_security" }, async ({ auth }) => {
  return { data: await listGateways(auth.tenantId) };
});

export const POST = route(
  { area: "email_security", bodySchema: gatewayCreateSchema, section: "email_security" },
  async ({ auth, body }) => {
    const created = await createGateway(auth.tenantId, body);
    return {
      data: created,
      audit: {
        action: "email_gateway.create",
        objectType: "email_gateway",
        objectId: created.id,
        objectName: created.name,
        after: created,
      },
    };
  },
);
