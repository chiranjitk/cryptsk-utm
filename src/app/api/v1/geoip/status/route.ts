/**
 * GET /api/v1/geoip/status — single read for the firewall objects view:
 * configured sources, per-country named-set accounting (rendered with the
 * same pure renderer the generator uses — cap warnings included), which geo
 * address objects resolve from the loaded sources, and the fqdn objects'
 * resolver snapshot health (ip count, resolvedAt, staleness).
 */

import { route } from "@/lib/api/handler";
import { getGeoipStatus } from "@/lib/geoip/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "firewall" }, async ({ auth }) => {
  return { data: await getGeoipStatus(auth.tenantId) };
});
