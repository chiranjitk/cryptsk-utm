/**
 * /api/v1/vpn/os-status — GUI↔OS honesty view (enterprise gap fix).
 * Real host facts: charon/VICI plane, loaded utm-* conns, established SAs,
 * wireguard ifaces with live counters, openvpn units — plus per-tunnel
 * drift (in-sync / drift / missing / disabled) exactly like the firewall
 * and multi-WAN OS pages.
 */

import { route } from "@/lib/api/handler";
import { collectVpnConfigs, readVpnOsFacts, computeVpnDrift, connName, MANAGED_PREFIX } from "@/lib/vpn/os";

export const dynamic = "force-dynamic";

export const GET = route({ area: "vpn_config" }, async ({ auth }) => {
  const configs = await collectVpnConfigs(auth.tenantId);
  const slugs = configs.map((c) => connName(c.name).slice(MANAGED_PREFIX.length));
  const facts = await readVpnOsFacts(slugs);
  const drift = computeVpnDrift(configs, facts);
  const inSync = drift.filter((d) => d.osState === "in-sync" || d.osState === "disabled").length;
  return {
    data: {
      gate: facts.gate,
      available: facts.available,
      tools: facts.tools,
      charonRunning: facts.charonRunning,
      ikePortsBound: facts.ikePortsBound,
      swanctlConns: facts.swanctlConns,
      establishedSas: facts.establishedSas,
      wgIfaces: facts.wgIfaces,
      openvpnServices: facts.openvpnServices,
      drift,
      summary: {
        total: drift.length,
        inSync,
        driftCount: drift.filter((d) => d.osState === "drift" || d.osState === "missing").length,
      },
    },
  };
});
