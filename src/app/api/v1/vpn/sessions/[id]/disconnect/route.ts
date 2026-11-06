/**
 * /api/v1/vpn/sessions/[id]/disconnect — kick a session (M05 §3/§5).
 * 404 on unknown session; idempotent success when already disconnected.
 */

import { route } from "@/lib/api/handler";
import { disconnectSession } from "@/lib/vpn/service";

export const dynamic = "force-dynamic";

export const POST = route({ area: "vpn_sessions", section: "vpn" }, async ({ auth, params }) => {
  const id = Number(params.id);
  const session = await disconnectSession(auth.tenantId, id);
  return {
    data: session,
    audit: { action: "vpn_session.disconnect", objectType: "vpn_session", objectId: id, objectName: session.userName ?? undefined },
  };
});
