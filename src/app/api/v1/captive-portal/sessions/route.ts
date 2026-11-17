/** Portal auth sessions (spec §7, T1-d) — filtered list; stale rows age out on read. */

import { route } from "@/lib/api/handler";
import { portalSessionQuerySchema } from "@/lib/validators/identity";
import { listPortalSessions } from "@/lib/identity/service";
import { expireSweep } from "@/lib/identity/vouchers";

export const dynamic = "force-dynamic";

export const GET = route(
  { area: "identity", querySchema: portalSessionQuerySchema },
  async ({ auth, query }) => {
    await expireSweep(auth.tenantId); // truthy states — active-but-past-expiry flips before the read
    return listPortalSessions(auth.tenantId, query);
  },
);
