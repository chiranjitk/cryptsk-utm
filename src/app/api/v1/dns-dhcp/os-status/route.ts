/**
 * /api/v1/dns-dhcp/os-status — GUI↔OS honesty view (enterprise gap fix),
 * mirrors /api/v1/vpn/os-status: real host facts for unbound + Kea plus
 * per-entity drift (in-sync / drift / missing / disabled / unsupported)
 * computed against the RENDERED managed configs (hash comparison).
 */

import { route } from "@/lib/api/handler";
import {
  collectDnsInputs,
  readDnsOsFacts,
  computeDnsDrift,
  renderUnboundManaged,
  fnv1aHash,
} from "@/lib/dns/os";
import {
  collectDhcpInputs,
  readDhcpOsFacts,
  computeDhcpDrift,
  mergeKeaConfig,
} from "@/lib/dhcp/os";

export const dynamic = "force-dynamic";

export const GET = route({ area: "dns_dhcp" }, async ({ auth }) => {
  const tenantId = auth.tenantId;
  const [dnsInput, dhcpInput, dnsFacts, dhcpFacts] = await Promise.all([
    collectDnsInputs(tenantId),
    collectDhcpInputs(tenantId),
    readDnsOsFacts(),
    readDhcpOsFacts(),
  ]);

  // render both managed configs and compare hashes with the live files
  const renderedUnbound = renderUnboundManaged(dnsInput);
  const dnsDrift = computeDnsDrift(dnsInput.settings, dnsInput.policies, dnsInput.records, dnsFacts, fnv1aHash(renderedUnbound));

  let renderedKea: string | null = null;
  let keaMergeError: string | null = null;
  try {
    // os-status must never fail because of a corrupted live file — the
    // merge can throw ApiError (refusal); drift then reports GUI-only state
    let liveText: string | null = null;
    try {
      const { readFile } = await import("fs/promises");
      liveText = await readFile("/etc/kea/kea-dhcp4.conf", "utf8");
    } catch {
      /* conf absent — merge from skeleton */
    }
    renderedKea = mergeKeaConfig(liveText, dhcpInput.subnets, dhcpInput.reservations).text;
  } catch (err) {
    keaMergeError = err instanceof Error ? err.message : "kea merge refused";
  }
  const dhcpDrift = computeDhcpDrift(dhcpInput.subnets, dhcpInput.reservations, dhcpInput.relay, dhcpFacts, renderedKea);

  const all = [...dnsDrift, ...dhcpDrift];
  const inSync = all.filter((d) => d.osState === "in-sync" || d.osState === "disabled").length;
  const driftCount = all.filter((d) => d.osState === "drift" || d.osState === "missing").length;
  const unsupported = all.filter((d) => d.osState === "unsupported").length;

  return {
    data: {
      dns: {
        gate: dnsFacts.gate,
        available: dnsFacts.available,
        tools: dnsFacts.tools,
        running: dnsFacts.running,
        ports53Bound: dnsFacts.ports53Bound,
        checkconfOk: dnsFacts.checkconfOk,
        controlOk: dnsFacts.controlOk,
        version: dnsFacts.version,
        managedFilePresent: dnsFacts.managedFilePresent,
        logQueriesEnabled: dnsFacts.logQueriesEnabled,
        logFileBytes: dnsFacts.logFileBytes,
        effectiveInterfaces: dnsFacts.effectiveInterfaces,
        drift: dnsDrift,
      },
      dhcp: {
        gate: dhcpFacts.gate,
        available: dhcpFacts.available,
        tools: dhcpFacts.tools,
        running: dhcpFacts.running,
        port67Bound: dhcpFacts.port67Bound,
        configValid: dhcpFacts.configValid,
        version: dhcpFacts.version,
        confPresent: dhcpFacts.confPresent,
        liveManagedSubnetIds: dhcpFacts.liveManagedSubnetIds,
        liveForeignSubnetIds: dhcpFacts.liveForeignSubnetIds,
        relayUnitExists: dhcpFacts.relayUnitExists,
        relayDefaultsPresent: dhcpFacts.relayDefaultsPresent,
        leases: dhcpFacts.leases.slice(0, 50),
        leaseCount: dhcpFacts.leases.length,
        leaseReadError: dhcpFacts.leaseReadError,
        mergeError: keaMergeError,
        drift: dhcpDrift,
      },
      summary: {
        total: all.length,
        inSync,
        driftCount,
        unsupported,
      },
    },
  };
});
