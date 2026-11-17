/**
 * GET  /api/v1/geoip/sources — list configured GeoIP sources (M03 spec §1.4).
 * POST /api/v1/geoip/sources — load one: read + parse the admin-provided
 * country CSV (`ISO_CODE,prefix` lines), aggregate per-country prefixes and
 * write/update the GeoipSource row (status loaded/error). Audits
 * `geoip_source.load`; the firewall section snapshot triggers the debounced
 * nftables convergence so newly resolvable geo objects take effect.
 */

import { route } from "@/lib/api/handler";
import { geoipSourceLoadSchema } from "@/lib/validators/geoip";
import { listSources, loadSource } from "@/lib/geoip/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "firewall" }, async ({ auth }) => {
  return { data: await listSources(auth.tenantId) };
});

export const POST = route(
  { area: "firewall", bodySchema: geoipSourceLoadSchema, section: "firewall" },
  async ({ auth, body }) => {
    const result = await loadSource(auth.tenantId, body);
    return {
      data: result,
      audit: {
        action: "geoip_source.load",
        objectType: "geoip_source",
        objectId: result.source.id,
        objectName: result.source.name,
        after: {
          ...result.source,
          v6Count: result.v6Count,
          badLines: result.badLines,
        },
      },
    };
  },
);
