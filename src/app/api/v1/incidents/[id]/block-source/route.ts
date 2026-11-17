/**
 * POST /api/v1/incidents/[id]/block-source — manual containment (§3.5):
 * materializes an ip address object + deny firewall rule via the rule-service
 * create path, stamps the artifact ids on incident.detail and appends a
 * `blocked` timeline entry. section: "firewall" so the handler snapshots the
 * config version and schedules the nftables convergence for the new deny rule.
 */

import { route, numericId } from "@/lib/api/handler";
import { blockSource } from "@/lib/incidents/service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "ips_events", section: "firewall" },
  async ({ auth, params }) => {
    const id = numericId(params, "id");
    const actor = auth.username ?? "system";
    const result = await blockSource(auth.tenantId, id, actor);
    return {
      data: result,
      audit: {
        action: "incident.block_source",
        objectType: "incident",
        objectId: id,
        objectName: result.incident.ref,
        after: {
          srcIp: result.incident.detail.srcIps?.[0] ?? null,
          blockedRuleId: result.firewallRuleId,
          blockedAddressId: result.addressObjectId,
        },
      },
    };
  },
);
