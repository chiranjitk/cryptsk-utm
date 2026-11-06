/**
 * Webhooks (M11 §3/§5.6) — registration CRUD. `secret` is write-only (set on
 * POST, never returned by GET). RBAC: area "webhooks" → interactive admins
 * only; machine keys are denied outright (rbac matrix + explicit guard).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { webhookCreateSchema } from "@/lib/validators/api-keys";
import { createWebhook, listWebhooks } from "@/lib/api-keys/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "webhooks" }, async ({ auth }) => {
  return { data: await listWebhooks(auth.tenantId) };
});

export const POST = route(
  { area: "webhooks", bodySchema: webhookCreateSchema, section: "system" },
  async ({ auth, body }) => {
    if (auth.kind === "key") throw ApiError.forbidden("Machine keys cannot manage webhooks");
    const created = await createWebhook(auth.tenantId, body);
    return {
      data: created, // WebhookDTO — secret structurally absent
      audit: {
        action: "webhook.create",
        objectType: "webhook",
        objectId: created.id,
        objectName: created.name,
        after: created,
      },
    };
  },
);
