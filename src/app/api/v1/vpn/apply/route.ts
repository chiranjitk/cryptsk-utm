/**
 * /api/v1/vpn/apply — build + execute the VPN OS convergence plan
 * (GUI desired state → swanctl/wg-quick/openvpn live state). Gate:
 * CONSOLE_VPN_OS=1 executes; otherwise the plan is a preview only
 * (same contract as Firewall / Interfaces / Multi-WAN apply).
 * Audit: vpn.os-apply.plan (preview) | vpn.os-apply.exec (applied).
 */

import { route } from "@/lib/api/handler";
import { collectVpnConfigs, readVpnOsFacts, buildVpnApplyPlan, execVpnApplyPlan, connName, MANAGED_PREFIX } from "@/lib/vpn/os";

export const dynamic = "force-dynamic";

export const POST = route({ area: "vpn_config", section: "vpn" }, async ({ auth }) => {
  const configs = await collectVpnConfigs(auth.tenantId);
  const slugs = configs.map((c) => connName(c.name).slice(MANAGED_PREFIX.length));
  const facts = await readVpnOsFacts(slugs);
  const plan = buildVpnApplyPlan(configs, facts);
  const outcome = await execVpnApplyPlan(plan);
  return {
    data: outcome,
    audit: {
      action: outcome.gate === "on" ? "vpn.os-apply.exec" : "vpn.os-apply.plan",
      objectType: "vpn_config",
      objectName: `plan:${plan.steps.length}-steps`,
    },
  };
});
