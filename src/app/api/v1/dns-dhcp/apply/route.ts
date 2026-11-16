/**
 * /api/v1/dns-dhcp/apply — build + execute the DNS & DHCP OS convergence
 * plans (GUI desired state → unbound live state + Kea live state).
 * Gates: CONSOLE_DNS_OS=1 executes unbound; CONSOLE_DHCP_OS=1 executes kea.
 * Off gates produce plan previews only (same contract as VPN/Firewall/
 * Interfaces/Multi-WAN apply).
 *
 * The two plans run INDEPENDENTLY: a kea validation failure never rolls back
 * unbound and vice versa (separate services, separate managed files).
 * Audit: dns-dhcp.os-apply.plan | dns-dhcp.os-apply.exec.
 */

import { route } from "@/lib/api/handler";
import { collectDnsInputs, readDnsOsFacts, buildDnsApplyPlan, execDnsApplyPlan } from "@/lib/dns/os";
import { collectDhcpInputs, readDhcpOsFacts, buildDhcpApplyPlan, execDhcpApplyPlan } from "@/lib/dhcp/os";

export const dynamic = "force-dynamic";

export const POST = route({ area: "dns_dhcp", section: "dns" }, async ({ auth }) => {
  const tenantId = auth.tenantId;
  const [dnsInput, dhcpInput, dnsFacts, dhcpFacts] = await Promise.all([
    collectDnsInputs(tenantId),
    collectDhcpInputs(tenantId),
    readDnsOsFacts(),
    readDhcpOsFacts(),
  ]);

  const dnsPlan = buildDnsApplyPlan(dnsInput, dnsFacts);
  const dhcpPlan = await buildDhcpApplyPlan(dhcpInput, dhcpFacts);

  const [dnsOutcome, dhcpOutcome] = await Promise.all([
    execDnsApplyPlan(dnsPlan),
    execDhcpApplyPlan(dhcpPlan),
  ]);

  const applied = dnsOutcome.applied || dhcpOutcome.applied;
  const bothOff = dnsOutcome.gate === "off" && dhcpOutcome.gate === "off";
  const parts: string[] = [];
  if (dnsOutcome.applied) parts.push(`dns: ${dnsOutcome.reason}`);
  else parts.push(`dns: ${dnsOutcome.reason}`);
  if (dhcpOutcome.applied) parts.push(`dhcp: ${dhcpOutcome.reason}`);
  else parts.push(`dhcp: ${dhcpOutcome.reason}`);

  return {
    data: {
      applied,
      gate: bothOff ? "off" : "on",
      reason: parts.join(" | "),
      dns: dnsOutcome,
      dhcp: dhcpOutcome,
    },
    audit: {
      action: bothOff ? "dns-dhcp.os-apply.plan" : "dns-dhcp.os-apply.exec",
      objectType: "dns_dhcp",
      objectName: `dns:${dnsPlan.steps.length}-steps dhcp:${dhcpPlan.steps.length}-steps`,
    },
  };
});
