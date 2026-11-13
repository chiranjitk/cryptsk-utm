/**
 * M21 seed — IPv6 Dual-Stack (spec 2.7). Idempotent, tenantId=1: the settings
 * singleton (enabled, DHCPv6, SLAAC, RDNSS, PD on wan0, /56, slaac_dhcpv6 —
 * upsert-by-find since the singleton has no unique name), three NAT66 rules
 * ("corp-nptv6" NPTv6 2001:db8:1::/48 → 2001:db8:2::/48 on lan0 with 421 hits,
 * "guest-masq" masquerade66 on wan0 with 1204 hits, "mail-dnat" DNAT66 :25 on
 * wan0 with 87 hits) and two DHCPv6 servers (lan0 pool 2001:db8:10::100 →
 * ::1ff, dmz0 pool 2001:db8:20::100 → ::1ff). Run via: bun prisma/seed-phase2.ts
 */

import type { PrismaClient } from "@prisma/client";

const TENANT = 1;

export default async function seed(prisma: PrismaClient): Promise<string> {
  // ── settings singleton (no unique name — create when absent, keep edits) ───
  const existingSettings = await prisma.ipv6Settings.findFirst({ where: { tenantId: TENANT } });
  if (!existingSettings) {
    await prisma.ipv6Settings.create({
      data: {
        tenantId: TENANT,
        enabled: true,
        dhcpv6Enabled: true,
        slaacEnabled: true,
        rdnssEnabled: true,
        pdWanInterface: "wan0",
        pdPrefixLength: 56,
        raMode: "slaac_dhcpv6",
      },
    });
  }

  // ── NAT66 rules (hitCount preserved on re-run) ─────────────────────────────
  await prisma.nat66Rule.upsert({
    where: { tenantId_name: { tenantId: TENANT, name: "corp-nptv6" } },
    update: {},
    create: {
      tenantId: TENANT,
      name: "corp-nptv6",
      type: "nptv6",
      sourcePrefix: "2001:db8:1::/48",
      translatedPrefix: "2001:db8:2::/48",
      destPort: null,
      interfaceName: "lan0",
      enabled: true,
      hitCount: 421,
    },
  });

  await prisma.nat66Rule.upsert({
    where: { tenantId_name: { tenantId: TENANT, name: "guest-masq" } },
    update: {},
    create: {
      tenantId: TENANT,
      name: "guest-masq",
      type: "masquerade66",
      sourcePrefix: null,
      translatedPrefix: null,
      destPort: null,
      interfaceName: "wan0",
      enabled: true,
      hitCount: 1204,
    },
  });

  await prisma.nat66Rule.upsert({
    where: { tenantId_name: { tenantId: TENANT, name: "mail-dnat" } },
    update: {},
    create: {
      tenantId: TENANT,
      name: "mail-dnat",
      type: "dnat66",
      sourcePrefix: null,
      translatedPrefix: null,
      destPort: 25,
      interfaceName: "wan0",
      enabled: true,
      hitCount: 87,
    },
  });

  // ── DHCPv6 servers (one per interface — unique per tenant) ─────────────────
  await prisma.dhcpv6Server.upsert({
    where: { tenantId_interfaceName: { tenantId: TENANT, interfaceName: "lan0" } },
    update: {},
    create: {
      tenantId: TENANT,
      interfaceName: "lan0",
      poolStart: "2001:db8:10::100",
      poolEnd: "2001:db8:10::1ff",
      prefixLength: 64,
      preferredLifetime: 3600,
      validLifetime: 7200,
      dnsServers: '["2001:db8:10::1"]',
      domainSearch: null,
      enabled: true,
    },
  });

  await prisma.dhcpv6Server.upsert({
    where: { tenantId_interfaceName: { tenantId: TENANT, interfaceName: "dmz0" } },
    update: {},
    create: {
      tenantId: TENANT,
      interfaceName: "dmz0",
      poolStart: "2001:db8:20::100",
      poolEnd: "2001:db8:20::1ff",
      prefixLength: 64,
      preferredLifetime: 3600,
      validLifetime: 7200,
      dnsServers: '["2001:db8:20::1"]',
      domainSearch: null,
      enabled: true,
    },
  });

  return "M21: settings live, 3 NAT66 rules, 2 DHCPv6 servers";
}
