/**
 * Force-expire an identity session (M07 §3/§5.5) — security_admin-class
 * action (identity.write matrix), audited, and emits
 * `sessions:update {kind:"identity"}` so open views flip the row in place.
 */

import { route } from "@/lib/api/handler";
import { expireIdentitySession } from "@/lib/identity/service";
import { emitEvent } from "@/lib/engine/events";

export const dynamic = "force-dynamic";

export const POST = route({ area: "identity" }, async ({ auth, params }) => {
  const id = Number(params.id);
  const expired = await expireIdentitySession(auth.tenantId, id);
  emitEvent({
    type: "sessions:update",
    payload: { kind: "identity", diff: [{ id: expired.id, userName: expired.userName, status: "expired" }] },
  });
  return {
    data: expired,
    audit: { action: "identity_session.expire", objectType: "identity_session", objectId: id, objectName: expired.userName, after: expired },
  };
});
