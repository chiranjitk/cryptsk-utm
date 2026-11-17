/**
 * POST /api/v1/objects/fqdn/refresh — re-resolve every fqdn address object
 * (spec §1.4): node:dns resolve4 (+AAAA on request) with a 3s timeout per
 * lookup, stamps resolvedIps/resolvedAt per object. Objects refreshed <60s
 * ago are skipped as unchanged unless {force:true}. Per-object errors are
 * reported in the returned per-run summary only — no new table. Audits
 * `fqdn.refresh`; the firewall section snapshot triggers the debounced
 * nftables convergence so updated snapshots reach the kernel sets.
 */

import { route } from "@/lib/api/handler";
import { fqdnRefreshBodySchema } from "@/lib/validators/geoip";
import { refreshFqdnObjects } from "@/lib/firewall/fqdn-resolver";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "firewall", bodySchema: fqdnRefreshBodySchema, section: "firewall" },
  async ({ auth, body }) => {
    const result = await refreshFqdnObjects(auth.tenantId, { force: body.force === true });
    return {
      data: result,
      audit: {
        action: "fqdn.refresh",
        objectType: "address_object",
        objectName: `fqdn refresh (resolved ${result.resolved}, failed ${result.failed}, unchanged ${result.unchanged})`,
        after: { resolved: result.resolved, failed: result.failed, unchanged: result.unchanged, durationMs: result.durationMs },
      },
    };
  },
);
