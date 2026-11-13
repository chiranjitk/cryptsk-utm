/**
 * GET /api/v1/objects/references?type=&id= — server-side usage tracking for
 * Objects/Zones (previously only discoverable via delete-time 409 payloads).
 * type: address | address-group | service | service-group | schedule | zone
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { z } from "zod";
import {
  addressGroupReferences,
  addressObjectReferences,
  scheduleReferences,
  serviceGroupReferences,
  serviceObjectReferences,
  zoneReferences,
} from "@/lib/firewall/refs";

export const dynamic = "force-dynamic";

const querySchema = z.object({
  type: z.enum(["address", "address-group", "service", "service-group", "schedule", "zone"]),
  id: z.coerce.number().int().min(1),
});

export const GET = route({ area: "firewall", querySchema }, async ({ auth, query }) => {
  const { type, id } = query;
  const refs = await (async () => {
    switch (type) {
      case "address":
        return addressObjectReferences(auth.tenantId, id);
      case "address-group":
        return addressGroupReferences(auth.tenantId, id);
      case "service":
        return serviceObjectReferences(auth.tenantId, id);
      case "service-group":
        return serviceGroupReferences(auth.tenantId, id);
      case "schedule":
        return scheduleReferences(auth.tenantId, id);
      case "zone":
        return zoneReferences(auth.tenantId, id);
    }
  })();
  return {
    data: { type, id, references: refs, total: refs.length },
  };
});
