/**
 * POST /api/v1/ipv6/apply — build + execute the IPv6 OS convergence plan
 * (GUI desired state → kea-dhcp6.conf + radvd.conf + inet utm_nat66 +
 * sysctl forwarding). Gates: CONSOLE_OS_APPLY=1 AND data-plane host mode —
 * off → plan preview only (rendered files + step list attached, honest).
 *
 * Audit: section "ipv6" (same section as ipv6.settings) with actions
 * ipv6.os-apply.plan | ipv6.os-apply.exec | ipv6.os-apply.failed.
 */

import { route } from "@/lib/api/handler";
import { applyIpv6Os } from "@/lib/ipv6/os-service";

export const dynamic = "force-dynamic";

export const POST = route({ area: "ipv6", section: "ipv6" }, async ({ auth }) => {
  const outcome = await applyIpv6Os(auth.tenantId);

  const auditAction = outcome.applied
    ? "ipv6.os-apply.exec"
    : outcome.gate === "off" || outcome.refused
      ? "ipv6.os-apply.plan"
      : "ipv6.os-apply.failed";

  return {
    data: outcome,
    audit: {
      action: auditAction,
      objectType: "ipv6_settings",
      objectName: `kea6:${outcome.plan.keaSubnets.length}-subnets radvd:${outcome.plan.radvdIfaces.length}-ifaces nat66:${outcome.plan.nat66Statements.length}-stmts`,
      result: outcome.applied ? "success" : outcome.gate === "off" || outcome.refused ? undefined : "failure",
    },
  };
});
