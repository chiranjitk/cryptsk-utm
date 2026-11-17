/**
 * IoT device inventory (Phase 3 §3.6) — paginated view over nac_devices with
 * rogue-flag enrichment (MAC unseen in DHCP leases + firstSeen <24h +
 * unclassified). Filters: ?deviceType= ?vendor= ?quarantined=true|false ?q=
 * ?page= ?limit=. RBAC mirrors the identity-advanced device routes (area
 * `identity`).
 */

import { route } from "@/lib/api/handler";
import { listInventory } from "@/lib/iot/service";
import { iotInventoryQuerySchema } from "@/lib/validators/iot";

export const dynamic = "force-dynamic";

export const GET = route({ area: "identity", querySchema: iotInventoryQuerySchema }, async ({ auth, query }) => {
  const result = await listInventory(auth.tenantId, {
    deviceType: query.deviceType,
    vendor: query.vendor,
    quarantined: query.quarantined === "true" ? true : query.quarantined === "false" ? false : undefined,
    q: query.q,
    page: query.page,
    limit: query.limit,
  });
  return { data: result.data, meta: result.meta };
});
