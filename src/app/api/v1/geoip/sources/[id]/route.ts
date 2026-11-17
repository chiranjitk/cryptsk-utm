/**
 * DELETE /api/v1/geoip/sources/{id} — drop a GeoIP source row. The prefixes
 * it contributed stop feeding the `utm_geo_*` named sets on the next
 * firewall convergence (geo address objects that lose all sources fall back
 * to config-only with a generator warning). Audits `geoip_source.delete`.
 */

import { route, numericId } from "@/lib/api/handler";
import { removeSource } from "@/lib/geoip/service";

export const dynamic = "force-dynamic";

export const DELETE = route({ area: "firewall", section: "firewall" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const result = await removeSource(auth.tenantId, id);
  return {
    data: { ok: true },
    audit: {
      action: "geoip_source.delete",
      objectType: "geoip_source",
      objectId: id,
      objectName: result.removed.name,
      before: result.removed,
    },
  };
});
