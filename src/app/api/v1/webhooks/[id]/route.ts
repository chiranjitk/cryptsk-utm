/**
 * Webhook item (M11 §3/§5.6) — update (omit `secret` to keep the stored
 * value) and delete. Interactive admins only; machine keys get 403.
 */

import { route, numericId } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { webhookUpdateSchema } from "@/lib/validators/api-keys";
import { deleteWebhook, updateWebhook } from "@/lib/api-keys/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "webhooks", bodySchema: webhookUpdateSchema, section: "system" },
  async ({ auth, body, params }) => {
    if (auth.kind === "key") throw ApiError.forbidden("Machine keys cannot manage webhooks");
    const id = numericId(params, "id");
    const updated = await updateWebhook(auth.tenantId, id, body);
    return {
      data: updated, // WebhookDTO — secret never returned
      audit: {
        action: "webhook.update",
        objectType: "webhook",
        objectId: id,
        objectName: updated.name,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "webhooks", section: "system" }, async ({ auth, params }) => {
  if (auth.kind === "key") throw ApiError.forbidden("Machine keys cannot manage webhooks");
  const id = numericId(params, "id");
  const result = await deleteWebhook(auth.tenantId, id);
  return {
    data: result,
    audit: { action: "webhook.delete", objectType: "webhook", objectId: id, after: result },
  };
});
