/**
 * Users (M07 §3) — list with ?q= ?role= ?groupId= and create.
 * GET floor: identity.read matrix (super_admin/tenant_admin/security_admin).
 * POST body is policy-checked in the service; password is never echoed nor
 * written to audit (before/after JSON carries the DTO only — ADR-011).
 */

import { route } from "@/lib/api/handler";
import { userCreateSchema, userQuerySchema } from "@/lib/validators/identity";
import { createUser, listUsers } from "@/lib/identity/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "identity", querySchema: userQuerySchema }, async ({ auth, query }) => {
  return { data: await listUsers(auth.tenantId, query) };
});

export const POST = route(
  { area: "identity", bodySchema: userCreateSchema, section: "identity" },
  async ({ auth, body }) => {
    const created = await createUser(auth.tenantId, body);
    return {
      data: created,
      audit: { action: "user.create", objectType: "user", objectId: created.id, objectName: created.username, after: created },
    };
  },
);
