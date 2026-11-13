/**
 * API keys (M11 §3/§5.1) — list + create (full key returned EXACTLY ONCE).
 * RBAC: area "api_keys" → read: tenant_admin+super_admin; write: super_admin
 * only. Machine keys are denied outright (AUTH_AND_RBAC §4 — keys cannot
 * manage keys): the rbac matrix returns false for api_service on this area,
 * and the handler-level guard below keeps that invariant self-documenting.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { apiKeyCreateSchema } from "@/lib/validators/api-keys";
import { createKey, listKeys } from "@/lib/api-keys/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "api_keys" }, async ({ auth }) => {
  return { data: await listKeys(auth.tenantId) };
});

export const POST = route(
  { area: "api_keys", bodySchema: apiKeyCreateSchema, section: "system" },
  async ({ auth, body }) => {
    if (auth.kind === "key") throw ApiError.forbidden("API keys cannot manage API keys");
    const created = await createKey(auth.tenantId, body);
    return {
      data: created, // {…ApiKeyDTO, key: "ck_…"} — the one-time reveal payload
      audit: {
        action: "api_key.create",
        objectType: "api_key",
        objectId: created.id,
        objectName: created.name,
        // never audit the full key: DTO only (prefix + hashedKey stay server-side)
        after: { ...created, key: undefined },
      },
    };
  },
);
