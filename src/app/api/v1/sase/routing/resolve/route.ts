/**
 * /api/v1/sase/routing/resolve — identity-aware routing test path (§4.2).
 * POST {userEmail} → the mapped region and the nearest routable node
 * (same-region gateway first, else first active — see pickNearestNode), or
 * nulls when the user has no mapping / no node is active. Read-only stub.
 */

import { route } from "@/lib/api/handler";
import { saseResolveSchema } from "@/lib/validators/sase";
import { resolveNode } from "@/lib/sase/service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "sase", bodySchema: saseResolveSchema },
  async ({ auth, body }) => {
    return { data: await resolveNode(auth.tenantId, body) };
  },
);
