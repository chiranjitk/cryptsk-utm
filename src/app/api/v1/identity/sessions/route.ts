/**
 * Live identity sessions (M07 §3/§5.5) — the ip→user map
 * (?method= ?state=active default ?q=). Paged per API_STANDARDS §6.
 */

import { route } from "@/lib/api/handler";
import { identitySessionQuerySchema } from "@/lib/validators/identity";
import { listIdentitySessions } from "@/lib/identity/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "identity", querySchema: identitySessionQuerySchema }, async ({ auth, query }) => {
  const { data, meta } = await listIdentitySessions(auth.tenantId, query);
  return { data, meta };
});
