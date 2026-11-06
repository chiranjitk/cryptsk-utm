/**
 * User item (M07 §3) — update (optional `password` = set/reset; `totpEnroll`
 * one-time secret) / delete (self-delete + last-admin guardrails in service).
 */

import { route } from "@/lib/api/handler";
import { userUpdateSchema } from "@/lib/validators/identity";
import { deleteUser, updateUser } from "@/lib/identity/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "identity", bodySchema: userUpdateSchema, section: "identity" },
  async ({ auth, body, params }) => {
    const id = Number(params.id);
    const updated = await updateUser(auth.tenantId, id, body);
    const { totpEnrollment, ...dto } = updated;
    return {
      data: dto,
      audit: {
        action: totpEnrollment ? "user.totp_enroll" : "user.update",
        objectType: "user",
        objectId: id,
        objectName: dto.username,
        after: dto, // never contains passwordHash/totpSecret
      },
    };
  },
);

export const DELETE = route({ area: "identity", section: "identity" }, async ({ auth, params }) => {
  const id = Number(params.id);
  await deleteUser(auth.tenantId, auth.userId, id);
  return {
    data: { ok: true },
    audit: { action: "user.delete", objectType: "user", objectId: id },
  };
});
