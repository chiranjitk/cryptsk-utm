/**
 * Routing Information Base (M19 §2.6) — GET list with optional ?protocol=
 * (bgp|ospf|static|connected) and ?q= substring filter over prefix, nextHop,
 * interfaceName and asPath. Rows are ordered by prefix (spec). Read-only:
 * the RIB is populated by POST /rib/refresh (simulated FRR sync).
 */

import { route } from "@/lib/api/handler";
import { ribQuerySchema } from "@/lib/validators/dynamic-routing";
import { db } from "@/lib/db";

export const dynamic = "force-dynamic";

export const GET = route(
  { area: "dynamic_routing", querySchema: ribQuerySchema },
  async ({ auth, query }) => {
    const rows = await db.ribRoute.findMany({
      where: { tenantId: auth.tenantId },
      orderBy: [{ prefix: "asc" }],
    });
    const q = query.q?.toLowerCase() ?? "";
    const data = rows.filter((row) => {
      if (query.protocol && row.protocol !== query.protocol) return false;
      if (!q) return true;
      return (
        row.prefix.toLowerCase().includes(q) ||
        row.nextHop.toLowerCase().includes(q) ||
        row.interfaceName.toLowerCase().includes(q) ||
        (row.asPath ?? "").toLowerCase().includes(q)
      );
    });
    return { data };
  },
);
