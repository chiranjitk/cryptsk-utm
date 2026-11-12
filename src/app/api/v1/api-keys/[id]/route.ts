/**
 * API key item (M11 §3/§5.1) — soft revoke. Revoked keys fail 401 on the
 * next call (session.ts); the row stays visible in the M10 list for history.
 */

import { route, numericId } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { revokeKey } from "@/lib/api-keys/service";

export const dynamic = "force-dynamic";

export const DELETE = route({ area: "api_keys", section: "system" }, async ({ auth, params }) => {
  if (auth.kind === "key") throw ApiError.forbidden("API keys cannot manage API keys");
  const id = numericId(params, "id");
  const revoked = await revokeKey(auth.tenantId, id);
  return {
    data: revoked,
    audit: {
      action: "api_key.revoke",
      objectType: "api_key",
      objectId: id,
      objectName: revoked.name,
      after: revoked,
    },
  };
});
