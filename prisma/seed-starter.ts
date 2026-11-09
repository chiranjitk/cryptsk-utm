/**
 * seed-starter.ts — PRODUCTION starter configuration (config-only, zero mock telemetry).
 *
 * Complements `bun prisma/seed.ts --production` (ADR-021 baseline: users/system only).
 * Populates the policy/config tables so every console view renders meaningful,
 * REAL configuration data. Nothing here is simulated telemetry: no fake logs,
 * events, sessions or counters — those stay empty until the host produces them.
 *
 * Safety posture:
 *  - inbound deny rules ship enabled=false with a review comment
 *  - DHCP / URL-filter / app-control / SSL-inspection / VPN / WAF / QoS / PBR ship disabled
 *  - IPS policy is passive (cannot drop traffic)
 *  - threat feeds point at real public URLs with autoBlock=false
 *
 * Idempotent: guarded creates — safe to re-run. `bun prisma/seed-starter.ts`
 */

import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();
const T = 1; // tenant

async function guard(name: string, fn: () => Promise<unknown>) {
  const existing = await fn();
  if (existing) console.log(`  = ${name} (exists)`);
  else console.log(`  + ${name}`);
}

async function main() {
  console.log("Seeding PRODUCTION starter configuration (config-only, no mock telemetry)…");

  // ── Zones ──────────────────────────────────────────────────────────────
  const zoneWan = await prisma.zone.upsert({
    where: { tenantId_name: { tenantId: T, name: "wan" } },
    create: { tenantId: T, name: "wan", type: "L3", interfaceNames: JSON.stringify(["ens32"]), description: "Uplink / internet edge" },
    update: {},
  });
  const zoneLan = await prisma.zone.upsert({
    where: { tenantId_name: { tenantId: T, name: "lan" } },
    create: { tenantId: T, name: "lan", type: "L3", interfaceNames: JSON.stringify(["ens34"]), description: "Internal corporate network (ens34 — enable when cabled)" },
    update: {},
  });
  const zoneDmz = await prisma.zone.upsert({
    where: { tenantId_name: { tenantId: T, name: "dmz" } },
    create: { tenantId: T, name: "dmz", type: "L3", interfaceNames: JSON.stringify([]), description: "Public services segment (reserved)" },
    update: {},
  });
  console.log("  + zones: wan, lan, dmz");

  // ── Address objects & groups ───────────────────────────────────────────
  const addr = {
    lanSubnet: await prisma.addressObject.upsert({
      where: { tenantId_name: { tenantId: T, name: "lan-subnet" } },
      create: { tenantId: T, name: "lan-subnet", type: "subnet", value: "192.168.10.0/24", description: "Corporate LAN" },
      update: {},
    }),
    webSrv: await prisma.addressObject.upsert({
      where: { tenantId_name: { tenantId: T, name: "srv-web" } },
      create: { tenantId: T, name: "srv-web", type: "ip", value: "192.168.10.5", description: "Internal web server" },
      update: {},
    }),
    dbSrv: await prisma.addressObject.upsert({
      where: { tenantId_name: { tenantId: T, name: "srv-db" } },
      create: { tenantId: T, name: "srv-db", type: "ip", value: "192.168.10.6", description: "Internal database server" },
      update: {},
    }),
    adminPc: await prisma.addressObject.upsert({
      where: { tenantId_name: { tenantId: T, name: "admin-workstation" } },
      create: { tenantId: T, name: "admin-workstation", type: "ip", value: "192.168.10.50", description: "IT admin workstation" },
      update: {},
    }),
    guestSubnet: await prisma.addressObject.upsert({
      where: { tenantId_name: { tenantId: T, name: "guest-subnet" } },
      create: { tenantId: T, name: "guest-subnet", type: "subnet", value: "192.168.20.0/24", description: "Guest Wi-Fi segment" },
      update: {},
    }),
  };
  await guard("addr-group corp-servers", async () =>
    prisma.addressGroup.upsert({
      where: { tenantId_name: { tenantId: T, name: "corp-servers" } },
      // explicit high ids: srcAddrIds/serviceIds mix object+group ids, so groups
      // must NEVER occupy the object autoincrement range (label resolver maps by id)
      create: { id: 101, tenantId: T, name: "corp-servers", memberIds: JSON.stringify([addr.webSrv.id, addr.dbSrv.id]), description: "Managed servers" },
      update: {},
    }));
  await guard("addr-group trusted-hosts", async () =>
    prisma.addressGroup.upsert({
      where: { tenantId_name: { tenantId: T, name: "trusted-hosts" } },
      create: { id: 102, tenantId: T, name: "trusted-hosts", memberIds: JSON.stringify([addr.adminPc.id, addr.webSrv.id, addr.dbSrv.id]), description: "Hosts allowed management access" },
      update: {},
    }));

  // ── Service objects & groups ───────────────────────────────────────────
  const svc = {
    http: await prisma.serviceObject.upsert({
      where: { tenantId_name: { tenantId: T, name: "http" } },
      create: { tenantId: T, name: "http", protocol: "tcp", dstPort: "80", description: "HTTP" },
      update: {},
    }),
    https: await prisma.serviceObject.upsert({
      where: { tenantId_name: { tenantId: T, name: "https" } },
      create: { tenantId: T, name: "https", protocol: "tcp", dstPort: "443", description: "HTTPS" },
      update: {},
    }),
    dns: await prisma.serviceObject.upsert({
      where: { tenantId_name: { tenantId: T, name: "domain" } },
      create: { tenantId: T, name: "domain", protocol: "udp", dstPort: "53", description: "DNS" },
      update: {},
    }),
    ssh: await prisma.serviceObject.upsert({
      where: { tenantId_name: { tenantId: T, name: "ssh" } },
      create: { tenantId: T, name: "ssh", protocol: "tcp", dstPort: "22", description: "SSH (appliance uses 22222)" },
      update: {},
    }),
    sshMgmt: await prisma.serviceObject.upsert({
      where: { tenantId_name: { tenantId: T, name: "ssh-mgmt-22222" } },
      create: { tenantId: T, name: "ssh-mgmt-22222", protocol: "tcp", dstPort: "22222", description: "Appliance SSH management port" },
      update: {},
    }),
    ntp: await prisma.serviceObject.upsert({
      where: { tenantId_name: { tenantId: T, name: "ntp" } },
      create: { tenantId: T, name: "ntp", protocol: "udp", dstPort: "123", description: "NTP" },
      update: {},
    }),
    rdp: await prisma.serviceObject.upsert({
      where: { tenantId_name: { tenantId: T, name: "rdp" } },
      create: { tenantId: T, name: "rdp", protocol: "tcp", dstPort: "3389", description: "Remote Desktop" },
      update: {},
    }),
  };
  const svcGroupWeb = await prisma.serviceGroup.upsert({
    where: { tenantId_name: { tenantId: T, name: "web-services" } },
    create: { id: 101, tenantId: T, name: "web-services", memberIds: JSON.stringify([svc.http.id, svc.https.id]), description: "Standard web services" },
    update: {},
  });
  await guard("service-group mgmt-services", async () =>
    prisma.serviceGroup.upsert({
      where: { tenantId_name: { tenantId: T, name: "mgmt-services" } },
      create: { id: 102, tenantId: T, name: "mgmt-services", memberIds: JSON.stringify([svc.ssh.id, svc.sshMgmt.id, svc.dns.id, svc.ntp.id]), description: "Management protocols" },
      update: {},
    }));

  // ── Schedule objects ───────────────────────────────────────────────────
  const schedHours = await prisma.scheduleObject.upsert({
    where: { tenantId_name: { tenantId: T, name: "business-hours" } },
    create: {
      tenantId: T, name: "business-hours", type: "recurring",
      recurrence: JSON.stringify({ days: [1, 2, 3, 4, 5], start: "09:00", end: "18:00" }),
      timezone: "Asia/Calcutta",
    },
    update: {},
  });
  await guard("schedule always", async () =>
    prisma.scheduleObject.upsert({
      where: { tenantId_name: { tenantId: T, name: "always" } },
      create: { tenantId: T, name: "always", type: "always", timezone: "Asia/Calcutta" },
      update: {},
    }));

  // ── Firewall rules (real baseline; inbound denies ship DISABLED) ───────
  const J = JSON.stringify;
  const fwSeed: Array<{ name: string; position: number; data: Record<string, unknown> }> = [
    { name: "allow-mgmt-ssh-from-lan", position: 1, data: {
      name: "allow-mgmt-ssh-from-lan", position: 1, enabled: true, description: "Admin workstation to appliance management ports",
      srcZoneIds: J([zoneLan.id]), dstZoneIds: J([zoneWan.id]), srcAddrIds: J([addr.adminPc.id]), dstAddrIds: J([]),
      serviceIds: J([svc.sshMgmt.id, svc.ssh.id]), action: "allow", logging: "summary" } },
    { name: "allow-lan-to-wan-web", position: 2, data: {
      name: "allow-lan-to-wan-web", position: 2, enabled: true, description: "LAN outbound web browsing",
      srcZoneIds: J([zoneLan.id]), dstZoneIds: J([zoneWan.id]), srcAddrIds: J([addr.lanSubnet.id]), dstAddrIds: J([]),
      serviceIds: J([101]), action: "allow", logging: "summary" } },
    { name: "allow-lan-to-wan-dns-ntp", position: 3, data: {
      name: "allow-lan-to-wan-dns-ntp", position: 3, enabled: true, description: "LAN outbound DNS and NTP",
      srcZoneIds: J([zoneLan.id]), dstZoneIds: J([zoneWan.id]), srcAddrIds: J([addr.lanSubnet.id]), dstAddrIds: J([]),
      serviceIds: J([svc.dns.id, svc.ntp.id]), action: "allow", logging: "none" } },
    { name: "allow-lan-to-lan", position: 4, data: {
      name: "allow-lan-to-lan", position: 4, enabled: true, description: "Intra-LAN east-west traffic",
      srcZoneIds: J([zoneLan.id]), dstZoneIds: J([zoneLan.id]), srcAddrIds: J([]), dstAddrIds: J([]),
      serviceIds: J([]), action: "allow", logging: "none" } },
    { name: "allow-dmz-to-wan-https", position: 5, data: {
      name: "allow-dmz-to-wan-https", position: 5, enabled: true, description: "DMZ outbound HTTPS only",
      srcZoneIds: J([zoneDmz.id]), dstZoneIds: J([zoneWan.id]), srcAddrIds: J([]), dstAddrIds: J([]),
      serviceIds: J([svc.https.id]), action: "allow", logging: "summary" } },
    { name: "deny-wan-inbound", position: 6, data: {
      name: "deny-wan-inbound", position: 6, enabled: false, description: "REVIEW-THEN-ENABLE: block all unsolicited WAN→LAN/DMZ",
      srcZoneIds: J([zoneWan.id]), dstZoneIds: J([zoneLan.id, zoneDmz.id]), srcAddrIds: J([]), dstAddrIds: J([]),
      serviceIds: J([]), action: "deny", logging: "detail", comment: "Disabled at seed so enabling the policy set cannot cut remote management. Enable after verifying allow-mgmt-ssh-from-lan." } },
    { name: "block-lan-to-wan-rdp", position: 7, data: {
      name: "block-lan-to-wan-rdp", position: 7, enabled: true, description: "RDP must not leave the LAN",
      srcZoneIds: J([zoneLan.id]), dstZoneIds: J([zoneWan.id]), srcAddrIds: J([]), dstAddrIds: J([]),
      serviceIds: J([svc.rdp.id]), action: "deny", logging: "summary" } },
    { name: "default-deny", position: 99, data: {
      name: "default-deny", position: 99, enabled: false, description: "REVIEW-THEN-ENABLE: zone-pair default drop",
      srcZoneIds: J([]), dstZoneIds: J([]), srcAddrIds: J([]), dstAddrIds: J([]),
      serviceIds: J([]), action: "deny", logging: "summary", comment: "Implicit-deny catch-all. Disabled at seed — enable after reviewing the allow rules." } },
  ];
  for (const r of fwSeed) {
    await guard(`fw-rule ${r.name}`, async () => {
      const existing = await prisma.firewallRule.findFirst({ where: { tenantId: T, name: r.name } });
      return existing ? existing : prisma.firewallRule.create({ data: r.data as never });
    });
  }

  // ── NAT rules (config only; snat enabled, dnat example disabled) ───────
  await guard("nat-rule snat-lan-masquerade", async () => {
    const existing = await prisma.natRule.findFirst({ where: { tenantId: T, name: "snat-lan-masquerade" } });
    return existing ? existing : prisma.natRule.create({ data: {
      tenantId: T, name: "snat-lan-masquerade", position: 1, type: "snat", enabled: true,
      srcAddrIds: J([addr.lanSubnet.id]), dstAddrIds: J([]), serviceIds: J([]),
      outgoingIface: "ens32", translatedSrc: "masq", comment: "Internet access for the LAN",
    } as never });
  });
  await guard("nat-rule dnat-web-publish", async () => {
    const existing = await prisma.natRule.findFirst({ where: { tenantId: T, name: "dnat-web-publish" } });
    return existing ? existing : prisma.natRule.create({ data: {
      tenantId: T, name: "dnat-web-publish", position: 2, type: "dnat", enabled: false,
      srcAddrIds: J([]), dstAddrIds: J([]), serviceIds: J([svc.https.id]),
      translatedDst: "192.168.10.5", translatedPort: 443, comment: "Publish internal web server — set a WAN VIP and enable when ready",
    } as never });
  });

  // ── WAN policy (probe-only, harmless) ─────────────────────────────────
  await guard("wan-policy ens32 priority", async () =>
    prisma.wanPolicy.upsert({
      where: { tenantId_interfaceName: { tenantId: T, interfaceName: "ens32" } },
      create: { tenantId: T, interfaceName: "ens32", mode: "priority", priority: 1, probeType: "icmp", probeTarget: "1.1.1.1", intervalSec: 5, enabled: true },
      update: {},
    }));

  // ── DHCP (disabled until you want it live) ─────────────────────────────
  await guard("dhcp-subnet lan-192.168.10.0", async () => {
    const existing = await prisma.dhcpSubnet.findFirst({ where: { tenantId: T, interfaceName: "ens34", family: "ipv4" } });
    return existing ? existing : prisma.dhcpSubnet.create({ data: {
      tenantId: T, interfaceName: "ens34", family: "ipv4", subnetCidr: "192.168.10.0/24",
      rangeStart: "192.168.10.100", rangeEnd: "192.168.10.200", gateway: "192.168.10.1",
      dnsServers: J(["192.168.10.1", "1.1.1.1"]), leaseTime: 86400, enabled: false,
    } });
  });

  // ── DNS records + policy ───────────────────────────────────────────────
  const dnsSeed = [
    { zone: "corp.local", name: "fw", type: "A", value: "192.168.10.1" },
    { zone: "corp.local", name: "web", type: "A", value: "192.168.10.5" },
    { zone: "corp.local", name: "db", type: "A", value: "192.168.10.6" },
    { zone: "corp.local", name: "portal", type: "CNAME", value: "fw.corp.local" },
    { zone: "corp.local", name: "@", type: "TXT", value: "v=spf1 -all" },
  ];
  for (const r of dnsSeed) {
    await guard(`dns-record ${r.zone}/${r.name} ${r.type}`, async () => {
      const existing = await prisma.dnsRecord.findFirst({ where: { tenantId: T, zone: r.zone, name: r.name, type: r.type } });
      return existing ? existing : prisma.dnsRecord.create({ data: { tenantId: T, ...r, ttl: 3600, enabled: true } });
    });
  }
  await guard("dns-policy corporate-dns", async () =>
    prisma.dnsPolicy.upsert({
      where: { tenantId_name: { tenantId: T, name: "corporate-dns" } },
      create: { tenantId: T, name: "corporate-dns", enabled: false, blockCategories: J(["ads", "malware", "phishing"]), action: "sinkhole", sinkholeIp: "192.168.10.1" },
      update: {},
    }));

  // ── QoS (disabled) ─────────────────────────────────────────────────────
  const qosPolicy = await prisma.qosPolicy.upsert({
    where: { tenantId_name: { tenantId: T, name: "wan-uplink" } },
    create: { tenantId: T, name: "wan-uplink", enabled: false, template: "custom", bandwidthKbps: 100000, ifaceName: "ens32" },
    update: {},
  });
  for (const r of [
    { name: "voip-priority", priority: 1, guaranteedKbps: 5000, maxKbps: null, dscpMark: 46 },
    { name: "video-streaming", priority: 4, guaranteedKbps: null, maxKbps: 40000, dscpMark: 34 },
    { name: "bulk-transfers", priority: 7, guaranteedKbps: null, maxKbps: 10000, dscpMark: null },
  ]) {
    await guard(`qos-rule ${r.name}`, async () => {
      const existing = await prisma.qosRule.findFirst({ where: { tenantId: T, policyId: qosPolicy.id, name: r.name } });
      return existing ? existing : prisma.qosRule.create({ data: {
        tenantId: T, policyId: qosPolicy.id, name: r.name, priority: r.priority,
        guaranteedKbps: r.guaranteedKbps, maxKbps: r.maxKbps, dscpMark: r.dscpMark,
      } });
    });
  }

  // ── IPS (passive — cannot drop) ────────────────────────────────────────
  await guard("ips-policy balanced-passive", async () =>
    prisma.ipsPolicy.upsert({
      where: { tenantId_name: { tenantId: T, name: "balanced-passive" } },
      create: {
        tenantId: T, name: "balanced-passive", mode: "passive", enabled: true,
        ruleCategories: JSON.stringify({ trojan: true, web_attack: true, scan: true, malware: true, botnet: true, policy: false }),
        tiBlocklist: false,
      },
      update: {},
    }));

  // ── Threat intelligence feeds (real public URLs, autoBlock off) ────────
  const feeds = [
    { name: "spamhaus-drop", provider: "spamhaus", url: "https://www.spamhaus.org/drop/drop.txt", format: "csv", category: "botnet", intervalMinutes: 720 },
    { name: "urlhaus-malicious-urls", provider: "abusech", url: "https://urlhaus.abuse.ch/downloads/csv_recent/", format: "csv", category: "malware", intervalMinutes: 60 },
    { name: "feodo-c2-ipblocklist", provider: "abusech", url: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", format: "csv", category: "c2", intervalMinutes: 60 },
  ];
  for (const f of feeds) {
    await guard(`threat-feed ${f.name}`, async () =>
      prisma.threatFeed.upsert({
        where: { tenantId_name: { tenantId: T, name: f.name } },
        create: { tenantId: T, ...f, autoBlock: false, enabled: true },
        update: {},
      }));
  }

  // ── URL filtering (disabled policy + category rules + custom lists) ────
  const ufPolicy = await prisma.urlFilterPolicy.upsert({
    where: { tenantId_name: { tenantId: T, name: "corporate-web-filter" } },
    create: { tenantId: T, name: "corporate-web-filter", defaultAction: "allow", safeSearchEnforce: true, httpsInspection: false, transparentProxy: true, enabled: false },
    update: {},
  });
  for (const cat of ["gambling", "adult", "malware", "phishing", "p2p", "weapons"]) {
    await guard(`url-category ${cat}=block`, async () => {
      const existing = await prisma.urlCategoryRule.findFirst({ where: { tenantId: T, policyId: ufPolicy.id, category: cat } });
      return existing ? existing : prisma.urlCategoryRule.create({ data: { tenantId: T, policyId: ufPolicy.id, category: cat, action: "block" } });
    });
  }
  await guard("url-list allow corp.local", async () => {
    const existing = await prisma.urlCustomList.findFirst({ where: { tenantId: T, policyId: ufPolicy.id, value: "corp.local" } });
    return existing ? existing : prisma.urlCustomList.create({ data: { tenantId: T, policyId: ufPolicy.id, listType: "allow", matchType: "domain", value: "corp.local", note: "Always allow internal domains" } });
  });

  // ── App control (disabled) ─────────────────────────────────────────────
  const acPolicy = await prisma.appControlPolicy.upsert({
    where: { tenantId_name: { tenantId: T, name: "media-and-remote-limits" } },
    create: { tenantId: T, name: "media-and-remote-limits", defaultAction: "allow", unknownAppAction: "log", enabled: false },
    update: {},
  });
  for (const r of [
    { appName: "youtube", category: "media", action: "limit", bandwidthLimitMbps: 50 },
    { appName: "netflix", category: "media", action: "limit", bandwidthLimitMbps: 50 },
    { appName: "bittorrent", category: "filesharing", action: "block", bandwidthLimitMbps: null },
  ]) {
    await guard(`app-rule ${r.appName}`, async () => {
      const existing = await prisma.appControlRule.findFirst({ where: { tenantId: T, policyId: acPolicy.id, appName: r.appName } });
      return existing ? existing : prisma.appControlRule.create({ data: { tenantId: T, policyId: acPolicy.id, ...r } });
    });
  }

  // ── SSL inspection (disabled; needs a signing CA first) ────────────────
  await guard("ssl-policy selective-inspection", async () =>
    prisma.sslInspectionPolicy.upsert({
      where: { tenantId_name: { tenantId: T, name: "selective-inspection" } },
      create: { tenantId: T, name: "selective-inspection", mode: "selective", enabled: false, minTlsVersion: "1.2" },
      update: {},
    }));

  // ── VPN ────────────────────────────────────────────────────────────────
  await guard("vpn-user-group remote-staff", async () =>
    prisma.vpnUserGroup.upsert({
      where: { tenantId_name: { tenantId: T, name: "remote-staff" } },
      create: { tenantId: T, name: "remote-staff", description: "Remote workers", pool: "10.10.50.0/24", dns: "192.168.10.1", maxSessionsPerUser: 2 },
      update: {},
    }));
  await guard("vpn-config hq-s2s-wireguard", async () =>
    prisma.vpnConfig.upsert({
      where: { tenantId_name: { tenantId: T, name: "hq-s2s-wireguard" } },
      create: { tenantId: T, name: "hq-s2s-wireguard", type: "wireguard_s2s", enabled: false, status: "down", config: JSON.stringify({ listenPort: 51820, peers: [], note: "Fill in peer public key + endpoint, then enable" }) },
      update: {},
    }));

  // ── WAF (disabled, learning mode) ──────────────────────────────────────
  const wafVhost = await prisma.wafVhost.upsert({
    where: { tenantId_hostname: { tenantId: T, hostname: "portal.corp.example" } },
    create: { tenantId: T, name: "corporate-portal", hostname: "portal.corp.example", backendHost: "192.168.10.5", backendPort: 8080, listenPort: 443, tls: true, mode: "waf", enabled: false },
    update: {},
  });
  await guard("waf-policy portal-owasp", async () =>
    prisma.wafPolicy.upsert({
      where: { tenantId_name: { tenantId: T, name: "portal-owasp" } },
      create: { tenantId: T, name: "portal-owasp", vhostId: wafVhost.id, owaspCrsEnabled: true, crsVersion: "4.0", paranoiaLevel: 1, learningMode: true, enabled: false },
      update: {},
    }));

  // ── PBR + static routes + forwarding targets (disabled) ────────────────
  await guard("pbr-rule guest-via-wan", async () => {
    const existing = await prisma.pbrRule.findFirst({ where: { tenantId: T, name: "guest-via-wan" } });
    return existing ? existing : prisma.pbrRule.create({ data: {
      tenantId: T, name: "guest-via-wan", position: 1, enabled: false,
      srcAddrIds: J([addr.guestSubnet.id]), dstAddrIds: J([]), serviceIds: J([]), outgoingIface: "ens32",
      description: "Guest traffic always egresses via primary WAN",
    } as never });
  });
  await guard("pbr-rule servers-via-wan", async () => {
    const existing = await prisma.pbrRule.findFirst({ where: { tenantId: T, name: "servers-via-wan" } });
    return existing ? existing : prisma.pbrRule.create({ data: {
      tenantId: T, name: "servers-via-wan", position: 2, enabled: false,
      srcAddrIds: J([]), dstAddrIds: J([]), serviceIds: J([]), outgoingIface: "ens32",
      description: "Server subnet egress binding",
    } as never });
  });
  await guard("static-route dmz-rfc5737", async () => {
    const existing = await prisma.staticRoute.findFirst({ where: { tenantId: T, destinationCidr: "192.0.2.0/24" } });
    return existing ? existing : prisma.staticRoute.create({ data: {
      tenantId: T, name: "dmz-example", destinationCidr: "192.0.2.0/24", gateway: "192.168.10.254",
      interfaceName: "ens34", enabled: false, description: "EXAMPLE — replace with your real next hop",
    } });
  });
  await guard("syslog-target collector", async () =>
    prisma.syslogTarget.upsert({
      where: { tenantId_name: { tenantId: T, name: "log-collector" } },
      create: { tenantId: T, name: "log-collector", host: "192.168.10.30", port: 514, protocol: "udp", minSeverity: "info", enabled: false },
      update: {},
    }));
  await guard("netflow-target collector", async () =>
    prisma.netflowTarget.upsert({
      where: { tenantId_name: { tenantId: T, name: "flow-collector" } },
      create: { tenantId: T, name: "flow-collector", host: "192.168.10.30", port: 2055, version: "ipfix", samplingRate: 100, enabled: false },
      update: {},
    }));
  await guard("report-schedule weekly-security", async () =>
    prisma.reportSchedule.upsert({
      where: { tenantId_name: { tenantId: T, name: "weekly-security-report" } },
      create: { tenantId: T, name: "weekly-security-report", range: "weekly", format: "pdf", sections: J(["traffic", "threats", "audit"]), enabled: false },
      update: {},
    }));
  await guard("webhook audit-forwarder", async () =>
    prisma.webhook.upsert({
      where: { tenantId_name: { tenantId: T, name: "audit-forwarder" } },
      create: { tenantId: T, name: "audit-forwarder", url: "https://hooks.corp.example/audit", events: J(["alerts.new", "config.updated"]), enabled: false, secret: "changeme-hmac-secret" },
      update: {},
    }));
  await guard("radius-profile internal-radius", async () =>
    prisma.radiusProfile.upsert({
      where: { tenantId_name: { tenantId: T, name: "internal-radius" } },
      create: { tenantId: T, name: "internal-radius", serverIp: "192.168.10.1", authPort: 1812, sharedSecret: "changeme-radius-secret", timeoutSec: 3, retries: 2 },
      update: {},
    }));

  console.log("Starter configuration seeded. Telemetry tables left real-empty (no mock data).");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
