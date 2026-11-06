/**
 * Cryptsk Console — idempotent seed (M0).
 * Dataset contract: docs/03-DATABASE/DATA_LIFECYCLE.md §2 + docs/03-DATABASE/SCHEMA.md notes.
 *
 * Demo credentials (documented here + shown on the login view helper text):
 *   admin   / admin123   super_admin
 *   tadmin  / tadmin123  tenant_admin
 *   secops  / secops123  security_admin
 *   netops  / netops123  network_admin
 *   socuser / socuser123 soc_analyst
 *   helpdesk/ helpdesk123 helpdesk
 *   viewer  / viewer123  auditor (read-only human)
 *   svcapi  / svcapi123  api_service (interactive stand-in; machines use API keys)
 *
 * Demo API key (read scope, shown once here; only the sha256 hash is stored):
 *   ck_demoroad_0123456789abcdef0123456789abcdef
 *
 * Deterministic: MOCK_SEED env (default 1337) drives the log backfill PRNG (ADR-012).
 */
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";
import { createHash } from "crypto";

const prisma = new PrismaClient();
const RESET = process.argv.includes("--reset");

function mulberry32(seed: number) {
  let a = seed >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rand = mulberry32(Number(process.env.MOCK_SEED ?? 1337));
const pick = <T>(arr: T[]): T => arr[Math.floor(rand() * arr.length)];
const int = (min: number, max: number) => Math.floor(rand() * (max - min + 1)) + min;
const iso = (d: Date) => d.toISOString();
const daysAgo = (d: number) => new Date(Date.now() - d * 86_400_000);

const BCRYPT_COST = 12;
async function hashPassword(pw: string) {
  return bcrypt.hash(pw, BCRYPT_COST);
}

function sha256(s: string) {
  return createHash("sha256").update(s).digest("hex");
}

async function main() {
  console.log("Seeding Cryptsk sandbox data (tenant 1 'Default')…");

  // ── Tenant ────────────────────────────────────────────────────────────────
  await prisma.tenant.upsert({
    where: { id: 1 },
    update: {},
    create: {
      id: 1,
      name: "Default",
      company: "Cryptsk Demo Ltd.",
      contactEmail: "ops@cryptsk.local",
      status: "active",
    },
  });

  // ── Users (8 roles) ───────────────────────────────────────────────────────
  const users: Array<[string, string, string]> = [
    ["admin", "admin123", "super_admin"],
    ["tadmin", "tadmin123", "tenant_admin"],
    ["secops", "secops123", "security_admin"],
    ["netops", "netops123", "network_admin"],
    ["socuser", "socuser123", "soc_analyst"],
    ["helpdesk", "helpdesk123", "helpdesk"],
    ["viewer", "viewer123", "auditor"],
    ["svcapi", "svcapi123", "api_service"],
  ];
  const userIds: Record<string, number> = {};
  for (const [username, pw, role] of users) {
    const passwordHash = await hashPassword(pw);
    const u = await prisma.user.upsert({
      where: { tenantId_username: { tenantId: 1, username } },
      update: { passwordHash, role, isActive: true },
      create: {
        tenantId: 1,
        username,
        passwordHash,
        role,
        email: `${username}@cryptsk.local`,
      },
    });
    userIds[username] = u.id;
  }

  // ── User groups ───────────────────────────────────────────────────────────
  const itStaff = await prisma.userGroup.upsert({
    where: { tenantId_name: { tenantId: 1, name: "IT Staff" } },
    update: {},
    create: { tenantId: 1, name: "IT Staff", description: "Platform administrators and network ops" },
  });
  const security = await prisma.userGroup.upsert({
    where: { tenantId_name: { tenantId: 1, name: "Security" } },
    update: {},
    create: { tenantId: 1, name: "Security", description: "Security operations team" },
  });
  await prisma.userGroupMember.upsert({
    where: { groupId_userId: { groupId: itStaff.id, userId: userIds.admin } },
    update: {},
    create: { groupId: itStaff.id, userId: userIds.admin },
  });
  await prisma.userGroupMember.upsert({
    where: { groupId_userId: { groupId: itStaff.id, userId: userIds.netops } },
    update: {},
    create: { groupId: itStaff.id, userId: userIds.netops },
  });
  await prisma.userGroupMember.upsert({
    where: { groupId_userId: { groupId: security.id, userId: userIds.secops } },
    update: {},
    create: { groupId: security.id, userId: userIds.secops },
  });

  // ── API key (demo read-only; full key documented above) ──────────────────
  const demoKey = "ck_demoroad_0123456789abcdef0123456789abcdef";
  await prisma.apiKey.upsert({
    where: { prefix: "ck_demoroad" },
    update: {},
    create: {
      tenantId: 1,
      name: "demo-readonly",
      prefix: "ck_demoroad",
      hashedKey: sha256(demoKey),
      scopes: JSON.stringify(["read"]),
    },
  });

  // ── Interfaces (DATA_LIFECYCLE §2.2) ─────────────────────────────────────
  const ifaces = [
    {
      name: "wan0",
      type: "physical",
      role: "wan",
      enabled: true,
      config: {
        wanType: "static",
        ip: "203.0.113.2",
        cidrPrefix: 24,
        gateway: "203.0.113.1",
        dns: ["1.1.1.1", "9.9.9.9"],
        mac: "52:54:00:a1:b2:c3",
        speedMbps: 1000,
        duplex: "full",
        lldp: true,
      },
      description: "Primary WAN uplink (fiber 1 Gbps)",
    },
    {
      name: "wan1",
      type: "physical",
      role: "wan",
      enabled: false,
      config: { wanType: "dhcp", lldp: true },
      description: "Backup WAN (LTE bridge) — disabled",
    },
    {
      name: "lan0",
      type: "physical",
      role: "lan",
      enabled: true,
      config: {
        wanType: "static",
        ip: "192.168.10.1",
        cidrPrefix: 24,
        mac: "52:54:00:c4:d5:e6",
        speedMbps: 1000,
        duplex: "full",
        lldp: true,
      },
      description: "Corporate LAN",
    },
    {
      name: "dmz0",
      type: "physical",
      role: "dmz",
      enabled: true,
      config: {
        wanType: "static",
        ip: "172.16.20.1",
        cidrPrefix: 24,
        mac: "52:54:00:f7:08:19",
        speedMbps: 1000,
        duplex: "full",
        lldp: true,
      },
      description: "DMZ segment (public services)",
    },
    {
      name: "vlan10",
      type: "vlan",
      role: "lan",
      parentName: "lan0",
      vlanId: 10,
      enabled: true,
      config: { parent: "lan0" },
      description: "Guest VLAN 10 (captive portal)",
    },
    {
      name: "br-mgmt",
      type: "bridge",
      role: "mgmt",
      enabled: true,
      config: { members: ["lan0"], stp: true, stpMode: "rstp", igmpSnooping: true },
      description: "Management bridge",
    },
    {
      name: "wg0",
      type: "loopback",
      role: "vpn",
      enabled: true,
      config: {},
      description: "WireGuard hub interface",
    },
  ] as const;
  for (const i of ifaces) {
    await prisma.networkInterface.upsert({
      where: { tenantId_name: { tenantId: 1, name: i.name } },
      update: { role: i.role, enabled: i.enabled, config: JSON.stringify(i.config), description: i.description },
      create: { tenantId: 1, name: i.name, type: i.type, mode: "l3", role: i.role, enabled: i.enabled, config: JSON.stringify(i.config), description: i.description },
    });
  }

  // ── Zones ────────────────────────────────────────────────────────────────
  const zoneDefs: Array<[string, string, string[]]> = [
    ["WAN", "L3", ["wan0", "wan1"]],
    ["LAN", "L3", ["lan0", "vlan10"]],
    ["DMZ", "L3", ["dmz0"]],
    ["VPN", "VPN", ["wg0"]],
  ];
  const zoneIds: Record<string, number> = {};
  for (const [name, type, members] of zoneDefs) {
    const z = await prisma.zone.upsert({
      where: { tenantId_name: { tenantId: 1, name } },
      update: { interfaceNames: JSON.stringify(members) },
      create: { tenantId: 1, name, type, interfaceNames: JSON.stringify(members), description: `${name} security zone` },
    });
    zoneIds[name] = z.id;
  }

  // ── Static routes + PBR ──────────────────────────────────────────────────
  await prisma.staticRoute.upsert({
    where: { id: 1 },
    update: {},
    create: {
      id: 1,
      name: "branch-net",
      destinationCidr: "10.50.0.0/16",
      gateway: "192.168.10.254",
      interfaceName: "lan0",
      distance: 1,
      bfd: true,
      description: "Branch office via HQ mesh",
    },
  });
  await prisma.staticRoute.upsert({
    where: { id: 2 },
    update: {},
    create: {
      id: 2,
      name: "sinkhole-scam-net",
      destinationCidr: "203.0.113.128/25",
      blackhole: true,
      distance: 254,
      description: "Blackhole for scam netblock",
    },
  });
  const sip = await prisma.serviceObject.findUnique({ where: { tenantId_name: { tenantId: 1, name: "SIP" } } });
  await prisma.pbrRule.upsert({
    where: { id: 1 },
    update: {},
    create: {
      id: 1,
      name: "VOIP-VIA-WAN1",
      position: 1,
      serviceIds: JSON.stringify(sip ? [sip.id] : []),
      outgoingIface: "wan1",
      description: "Force SIP trunk traffic out the backup WAN",
    },
  });

  // ── WAN policies ─────────────────────────────────────────────────────────
  await prisma.wanPolicy.upsert({
    where: { tenantId_interfaceName: { tenantId: 1, interfaceName: "wan0" } },
    update: {},
    create: {
      interfaceName: "wan0",
      mode: "priority",
      priority: 1,
      probeType: "icmp",
      probeTarget: "1.1.1.1",
      intervalSec: 5,
      state: "up",
    },
  });
  await prisma.wanPolicy.upsert({
    where: { tenantId_interfaceName: { tenantId: 1, interfaceName: "wan1" } },
    update: {},
    create: {
      interfaceName: "wan1",
      mode: "failover",
      priority: 2,
      probeType: "http",
      probeTarget: "http://connectivity-check.example.net/",
      intervalSec: 10,
      state: "down",
      enabled: false,
    },
  });

  // ── Address objects (10) ─────────────────────────────────────────────────
  const addrDefs: Array<[string, string, string, string?]> = [
    ["LAN_NET", "subnet", "192.168.10.0/24", "Corporate LAN"],
    ["GUEST_NET", "subnet", "192.168.20.0/24", "Guest Wi-Fi"],
    ["DMZ_NET", "subnet", "172.16.20.0/24", "Public services"],
    ["VPN_NET", "subnet", "10.99.0.0/16", "Remote access pools"],
    ["MGMT_NET", "subnet", "192.168.1.0/24", "Management workstations"],
    ["BRANCH_NET", "subnet", "10.50.0.0/16", "Branch office"],
    ["PRINTER_01", "ip", "192.168.10.50", "HP LaserJet reception"],
    ["SERVER_WEB", "ip", "172.16.20.5", "Public web server"],
    ["SERVER_MAIL", "ip", "172.16.20.6", "Mail relay"],
    ["GEO_BLOCKLIST", "geo", "RU", "Sanctioned / blocked origins"],
  ];
  const addrIds: Record<string, number> = {};
  for (const [name, type, value, description] of addrDefs) {
    const a = await prisma.addressObject.upsert({
      where: { tenantId_name: { tenantId: 1, name } },
      update: { type, value, description },
      create: { tenantId: 1, name, type, value, description },
    });
    addrIds[name] = a.id;
  }

  // ── Address groups (3) ───────────────────────────────────────────────────
  const groupDefs: Array<[string, string[], string?]> = [
    ["TRUSTED", ["LAN_NET", "MGMT_NET", "VPN_NET"], "Fully trusted origins"],
    ["SERVERS", ["SERVER_WEB", "SERVER_MAIL"], "Published servers"],
    ["GUESTS", ["GUEST_NET"], "Untrusted guest origins"],
  ];
  const addrGroupIds: Record<string, number> = {};
  for (const [name, members, description] of groupDefs) {
    const g = await prisma.addressGroup.upsert({
      where: { tenantId_name: { tenantId: 1, name } },
      update: { memberIds: JSON.stringify(members.map((m) => addrIds[m])) },
      create: { tenantId: 1, name, memberIds: JSON.stringify(members.map((m) => addrIds[m])), description },
    });
    addrGroupIds[name] = g.id;
  }

  // ── Service objects (7) + groups (2) ─────────────────────────────────────
  const svcDefs: Array<[string, string, string | null, string | null]> = [
    ["HTTP", "tcp", null, "80"],
    ["HTTPS", "tcp", null, "443"],
    ["DNS_UDP", "udp", null, "53"],
    ["SSH", "tcp", null, "22"],
    ["RDP", "tcp", null, "3389"],
    ["WIREGUARD", "udp", null, "51820"],
    ["SIP", "udp", "5060", "5060-5061"],
  ];
  const svcIds: Record<string, number> = {};
  for (const [name, protocol, srcPort, dstPort] of svcDefs) {
    const s = await prisma.serviceObject.upsert({
      where: { tenantId_name: { tenantId: 1, name } },
      update: { protocol, srcPort, dstPort },
      create: { tenantId: 1, name, protocol, srcPort, dstPort, description: `${name} service` },
    });
    svcIds[name] = s.id;
  }
  const svcGroupDefs: Array<[string, string[]]> = [
    ["WEB_SERVICES", ["HTTP", "HTTPS"]],
    ["ADMIN_SERVICES", ["SSH", "RDP"]],
  ];
  const svcGroupIds: Record<string, number> = {};
  for (const [name, members] of svcGroupDefs) {
    const g = await prisma.serviceGroup.upsert({
      where: { tenantId_name: { tenantId: 1, name } },
      update: { memberIds: JSON.stringify(members.map((m) => svcIds[m])) },
      create: { tenantId: 1, name, memberIds: JSON.stringify(members.map((m) => svcIds[m])) },
    });
    svcGroupIds[name] = g.id;
  }

  // ── Schedule ─────────────────────────────────────────────────────────────
  const businessHours = await prisma.scheduleObject.upsert({
    where: { tenantId_name: { tenantId: 1, name: "BUSINESS_HOURS" } },
    update: {},
    create: {
      tenantId: 1,
      name: "BUSINESS_HOURS",
      type: "recurring",
      recurrence: JSON.stringify({ days: [1, 2, 3, 4, 5], start: "09:00", end: "17:00" }),
      timezone: "Asia/Calcutta",
    },
  });

  // ── IPS policies ─────────────────────────────────────────────────────────
  const allCategories = [
    "trojan", "worm", "phishing", "botnet", "scan", "dos", "web_attack",
    "sql_injection", "xss", "brute_force", "malware", "c2", "info_leak",
    "policy", "exploit",
  ];
  const balancedCats: Record<string, boolean> = {};
  for (const c of allCategories) balancedCats[c] = !["dos", "info_leak"].includes(c);
  const balanced = await prisma.ipsPolicy.upsert({
    where: { tenantId_name: { tenantId: 1, name: "BALANCED" } },
    update: { ruleCategories: JSON.stringify(balancedCats) },
    create: {
      tenantId: 1,
      name: "BALANCED",
      mode: "inline_drop",
      enabled: true,
      ruleCategories: JSON.stringify(balancedCats),
      preprocessors: JSON.stringify({ stream: true, http: true, tls: true, ssh: true }),
      tiBlocklist: true,
    },
  });
  const strictCats: Record<string, boolean> = {};
  for (const c of allCategories) strictCats[c] = ["web_attack", "sql_injection", "xss", "exploit"].includes(c);
  await prisma.ipsPolicy.upsert({
    where: { tenantId_name: { tenantId: 1, name: "STRICT_WEB" } },
    update: { ruleCategories: JSON.stringify(strictCats) },
    create: {
      tenantId: 1,
      name: "STRICT_WEB",
      mode: "inline_tap",
      enabled: false,
      ruleCategories: JSON.stringify(strictCats),
      preprocessors: JSON.stringify({ stream: true, http: true, tls: true, ssh: false }),
    },
  });

  // ── Firewall rules (12) ──────────────────────────────────────────────────
  const fwDefs: Array<{
    name: string; description?: string; enabled?: boolean; action: string; logging?: string;
    srcZoneIds?: number[]; dstZoneIds?: number[]; srcAddrIds?: number[]; dstAddrIds?: number[];
    serviceIds?: number[]; applicationIds?: string[]; scheduleId?: number; ipsPolicyId?: number;
    comment?: string; synProtection?: boolean; rateLimit?: number;
  }> = [
    {
      name: "allow-mgmt-ssh", description: "Management SSH from trusted nets", action: "allow", logging: "summary",
      srcAddrIds: [addrGroupIds.TRUSTED], dstAddrIds: [addrIds.MGMT_NET], serviceIds: [svcIds.SSH],
    },
    {
      name: "allow-lan-to-wan", description: "Standard corporate egress", action: "allow", logging: "summary",
      srcZoneIds: [zoneIds.LAN], dstZoneIds: [zoneIds.WAN],
    },
    {
      name: "block-guest-to-corp", description: "Guest VLAN isolation", action: "deny", logging: "summary",
      srcAddrIds: [addrGroupIds.GUESTS], dstAddrIds: [addrGroupIds.TRUSTED],
    },
    {
      name: "deny-dmz-to-lan", description: "No lateral movement from DMZ", action: "deny", logging: "detail",
      srcZoneIds: [zoneIds.DMZ], dstZoneIds: [zoneIds.LAN],
    },
    {
      name: "allow-wan-web", description: "Ingress to published web (DNAT-protected)", action: "allow", logging: "summary",
      srcZoneIds: [zoneIds.WAN], dstAddrIds: [addrIds.SERVER_WEB], serviceIds: [svcGroupIds.WEB_SERVICES],
      ipsPolicyId: balanced.id, rateLimit: 200,
    },
    {
      name: "block-social-workhours", description: "No social media during office hours", action: "reject", logging: "summary",
      srcZoneIds: [zoneIds.LAN], dstZoneIds: [zoneIds.WAN], applicationIds: ["Facebook", "Instagram", "TikTok"],
      scheduleId: businessHours.id,
    },
    {
      name: "geo-block-wan-ingress", description: "Drop sanctioned origins at the edge", action: "drop", logging: "summary",
      srcZoneIds: [zoneIds.WAN], srcAddrIds: [addrIds.GEO_BLOCKLIST],
    },
    {
      name: "allow-dns-lan", description: "LAN may query the resolver", action: "allow", logging: "none",
      srcZoneIds: [zoneIds.LAN], dstZoneIds: [zoneIds.LAN], serviceIds: [svcIds.DNS_UDP],
    },
    {
      name: "block-bittorrent", description: "No P2P on the corporate link", action: "reject", logging: "summary",
      srcZoneIds: [zoneIds.LAN], dstZoneIds: [zoneIds.WAN], applicationIds: ["BitTorrent"],
    },
    {
      name: "allow-vpn-clients", description: "Remote access clients reach LAN", action: "allow", logging: "summary",
      srcZoneIds: [zoneIds.VPN], dstZoneIds: [zoneIds.LAN],
    },
    {
      name: "allow-icmp-monitoring", description: "ICMP for monitoring/troubleshooting", action: "allow", logging: "none",
      srcZoneIds: [zoneIds.LAN], dstZoneIds: [zoneIds.WAN],
    },
    {
      name: "implicit-deny-final", description: "Placeholder documentation rule for the built-in implicit deny",
      enabled: false, action: "deny", logging: "summary", comment: "Built-in default deny — kept disabled for documentation.",
    },
  ];
  // firewall_rules has no natural unique key (SCHEMA.md §3) — idempotency via find-then-write
  let position = 1;
  for (const def of fwDefs) {
    const data = {
      tenantId: 1, name: def.name, description: def.description, enabled: def.enabled ?? true,
      position, action: def.action, logging: def.logging ?? "none",
      srcZoneIds: JSON.stringify(def.srcZoneIds ?? []), dstZoneIds: JSON.stringify(def.dstZoneIds ?? []),
      srcAddrIds: JSON.stringify(def.srcAddrIds ?? []), dstAddrIds: JSON.stringify(def.dstAddrIds ?? []),
      serviceIds: JSON.stringify(def.serviceIds ?? []), applicationIds: JSON.stringify(def.applicationIds ?? []),
      userIds: "[]", srcMacs: "[]", tags: "[]",
      scheduleId: def.scheduleId ?? null, ipsPolicyId: def.ipsPolicyId ?? null,
      comment: def.comment ?? null, synProtection: def.synProtection ?? false,
      rateLimit: def.rateLimit ?? null,
    };
    const existing = await prisma.firewallRule.findFirst({ where: { tenantId: 1, name: def.name } });
    if (existing) {
      await prisma.firewallRule.update({ where: { id: existing.id }, data: { ...data, enabled: def.enabled ?? true } });
    } else {
      await prisma.firewallRule.create({
        data: { ...data, hitCount: int(0, 30000), lastHitAt: daysAgo(int(0, 3)) },
      });
    }
    position++;
  }

  // ── NAT rules (4) ────────────────────────────────────────────────────────
  const natDefs: Array<[string, number, string, string | null, string | null, string | null, string | null]> = [
    ["MASQ_LAN_WAN", 1, "snat", null, "masq", "wan0", null],
    ["WEB_PORT_FWD", 2, "dnat", "8080", "172.16.20.5", null, "80"],
    ["HAIRPIN_WEB", 3, "hairpin", null, "172.16.20.5", null, "80"],
    ["VPN_NO_NAT", 4, "exempt", null, null, null, null],
  ];
  // nat_rules likewise has no natural unique key — find-then-write
  for (const [name, pos, type, dport, tdst, tsrc, tport] of natDefs) {
    const data = {
      tenantId: 1, name, position: pos, type, enabled: true,
      srcAddrIds: JSON.stringify(type === "snat" || type === "exempt" ? [addrGroupIds.TRUSTED] : []),
      dstAddrIds: JSON.stringify(type === "dnat" ? [addrIds.SERVER_WEB] : []),
      serviceIds: JSON.stringify(type === "dnat" || type === "hairpin" ? [svcGroupIds.WEB_SERVICES] : []),
      outgoingIface: type === "snat" ? "wan0" : null,
      translatedSrc: tsrc, translatedDst: tdst,
      translatedPort: tport ? Number(tport) : null,
      translatedPortRange: null,
      logging: "none",
    };
    const existing = await prisma.natRule.findFirst({ where: { tenantId: 1, name } });
    if (existing) {
      await prisma.natRule.update({ where: { id: existing.id }, data });
    } else {
      await prisma.natRule.create({ data: { ...data, hitCount: int(1000, 90000) } });
    }
  }

  // ── VPN configs + sessions + user group ─────────────────────────────────
  const vpnDefs: Array<[string, string, string, string]> = [
    ["HQ-MESH", "wireguard_s2s", "up", "Tunnel to branch established"],
    ["ROADWARRIORS", "wireguard_remote", "up", "Remote access hub"],
    ["BRANCH-IPSEC", "ipsec_s2s", "connecting", "IKE negotiation in progress"],
    ["SSL-ACCESS", "openvpn", "down", "Disabled by operator"],
  ];
  const vpnIds: Record<string, number> = {};
  for (const [name, type, status, msg] of vpnDefs) {
    let config: Record<string, unknown>;
    if (type === "wireguard_s2s") {
      config = {
        privateKey: "QBase64PlaceholderPrivateKeyM0SeedValue==",
        listenPort: 51820, address: "10.99.0.1/24",
        peers: [{ name: "branch-fw", publicKey: "BranchFwPublicKeyPlaceholderM0==", allowedIps: ["10.50.0.0/16"], endpoint: "198.51.100.10:51820", keepaliveSec: 25 }],
      };
    } else if (type === "wireguard_remote") {
      config = { privateKey: "RWBase64PlaceholderPrivateKeyM0SeedValue==", listenPort: 51821, address: "10.99.1.1/24", pool: "10.99.1.0/24", dns: "192.168.10.1", keepaliveSec: 25, peers: [] };
    } else if (type === "ipsec_s2s") {
      config = { localIp: "203.0.113.2", remoteIp: "198.51.100.10", localSubnets: ["192.168.10.0/24"], remoteSubnets: ["10.50.0.0/16"], psk: "seed-psk-change-me", ike: "aes256-sha256-modp2048", esp: "aes256gcm16-modp2048", dpdSec: 30, pfs: true };
    } else {
      config = { proto: "udp", port: 1194, cipher: "AES-256-GCM", auth: "SHA256", pool: "10.99.2.0/24", tls: true, dns: "192.168.10.1", keepaliveSec: 10 };
    }
    const v = await prisma.vpnConfig.upsert({
      where: { tenantId_name: { tenantId: 1, name } },
      update: { type, status, statusMessage: msg, config: JSON.stringify(config) },
      create: { tenantId: 1, name, type, enabled: status !== "down", config: JSON.stringify(config), status, statusMessage: msg },
    });
    vpnIds[name] = v.id;
  }
  const vpnSessionCount = await prisma.vpnSession.count({ where: { tenantId: 1 } });
  if (RESET || vpnSessionCount === 0) {
    if (RESET) await prisma.vpnSession.deleteMany({ where: { tenantId: 1 } });
    const remoteUsers = ["c.reyes", "m.okafor", "j.tanaka", "l.novak", "s.patel", "d.kim", "r.almeida", "k.johnson", "a.hassan", "p.muller"];
    const rows = remoteUsers.map((userName, i) => {
      const vpnId = i < 7 ? vpnIds.ROADWARRIORS : vpnIds["SSL-ACCESS"];
      const status = i === 8 ? "idle" : "active";
      return {
        tenantId: 1, vpnId, userName, sourceIp: `198.51.100.${60 + i}`,
        assignedIp: i < 7 ? `10.99.1.${10 + i}/32` : `10.99.2.${10 + (i - 7)}/32`,
        bytesIn: int(1_000_000, 900_000_000), bytesOut: int(1_000_000, 400_000_000),
        groupName: "CONTRACTORS", status,
        connectedAt: daysAgo(int(0, 2)), lastActivity: new Date(Date.now() - int(1, 3600) * 1000),
      };
    });
    await prisma.vpnSession.createMany({ data: rows });
  }
  await prisma.vpnUserGroup.upsert({
    where: { tenantId_name: { tenantId: 1, name: "CONTRACTORS" } },
    update: {},
    create: {
      tenantId: 1, name: "CONTRACTORS", pool: "10.99.1.128/25", dns: "192.168.10.1",
      idleTimeoutMin: 30, maxSessionMin: 600, maxSessionsPerUser: 1,
      memberUsernames: JSON.stringify(["c.reyes", "m.okafor"]),
      description: "Contractor remote-access policy",
    },
  });

  // ── DNS: policy, records, resolver settings ──────────────────────────────
  await prisma.dnsPolicy.upsert({
    where: { tenantId_name: { tenantId: 1, name: "DEFAULT" } },
    update: {},
    create: {
      tenantId: 1, name: "DEFAULT", enabled: true,
      blockCategories: JSON.stringify(["ads", "malware", "phishing"]),
      customBlock: JSON.stringify(["tracker.example.net"]),
      customAllow: JSON.stringify(["cdn.corp.local"]),
      sinkholeIp: "0.0.0.0", action: "sinkhole",
    },
  });
  const dnsRecords: Array<[string, string, string, number?]> = [
    ["gw", "A", "192.168.10.1"], ["web", "A", "172.16.20.5"], ["mail", "A", "172.16.20.6"],
    ["nas", "A", "192.168.10.20"], ["vpn", "A", "203.0.113.2"], ["printer", "A", "192.168.10.50"],
    ["intranet", "CNAME", "web.corp.local"], ["portal", "CNAME", "web.corp.local"],
    ["corp.local", "MX", "mail.corp.local", 10], ["corp.local", "TXT", "v=spf1 mx -all"],
    ["_sip._tcp", "SRV", "10 60 5060 sip.corp.local", 10], ["1.10.168.192.in-addr.arpa", "PTR", "gw.corp.local"],
  ];
  for (const [name, type, value, priority] of dnsRecords) {
    const key = { tenantId: 1, zone: "corp.local", name, type };
    const existing = await prisma.dnsRecord.findFirst({ where: key });
    if (!existing) {
      await prisma.dnsRecord.create({ data: { ...key, value, ttl: 3600, priority: priority ?? null } });
    }
  }
  await upsertSetting("general", "hostname", { value: "cryptsk-demo" });
  await upsertSetting("general", "timezone", { value: "Asia/Calcutta" });
  await upsertSetting("general", "ntp", { enabled: true, servers: ["pool.debian.org"], synced: true, lastSyncAt: iso(daysAgo(0)) });
  await upsertSetting("dns", "resolver", {
    forwarders: ["1.1.1.1", "9.9.9.9"], cacheSizeMb: 64, rrl: false, dot: false,
    forwardZones: [{ domain: "corp.local", server: "192.168.10.254" }],
  });

  // ── DHCP: subnets, reservations, leases, relay ───────────────────────────
  const lanSubnet = await prisma.dhcpSubnet.upsert({
    where: { id: 1 },
    update: {},
    create: {
      interfaceName: "lan0", family: "ipv4", subnetCidr: "192.168.10.0/24",
      rangeStart: "192.168.10.100", rangeEnd: "192.168.10.200", gateway: "192.168.10.1",
      dnsServers: JSON.stringify(["192.168.10.1"]), leaseTime: 86400,
      options: JSON.stringify({ "42": "192.168.10.1" }),
    },
  });
  const dmzSubnet = await prisma.dhcpSubnet.upsert({
    where: { id: 2 },
    update: {},
    create: {
      interfaceName: "dmz0", family: "ipv4", subnetCidr: "172.16.20.0/24",
      rangeStart: "172.16.20.100", rangeEnd: "172.16.20.150", gateway: "172.16.20.1",
      dnsServers: JSON.stringify(["172.16.20.1"]), leaseTime: 3600, options: "{}",
    },
  });
  const reservations: Array<[string, string, string, number]> = [
    ["aa:bb:cc:00:11:01", "192.168.10.50", "printer-01", lanSubnet.id],
    ["aa:bb:cc:00:11:02", "192.168.10.20", "nas-01", lanSubnet.id],
    ["aa:bb:cc:00:11:03", "192.168.10.21", "ap-lobby", lanSubnet.id],
    ["aa:bb:cc:00:11:04", "172.16.20.10", "dmz-cam-01", dmzSubnet.id],
  ];
  for (const [mac, ip, hostname, subnetId] of reservations) {
    await prisma.dhcpReservation.upsert({
      where: { tenantId_mac: { tenantId: 1, mac } },
      update: { ip, hostname, subnetId },
      create: { tenantId: 1, subnetId, mac, ip, hostname },
    });
  }
  const leaseCount = await prisma.dhcpLease.count({ where: { tenantId: 1 } });
  if (RESET || leaseCount === 0) {
    if (RESET) await prisma.dhcpLease.deleteMany({ where: { tenantId: 1 } });
    const hosts = ["ws-finance", "ws-hr", "ws-eng-01", "ws-eng-02", "ws-sales", "mac-design", "ipad-recep", "phone-lobby", "cam-front", "cam-rear", "tv-meeting", "chromebox-01", "laptop-vpn", "ws-it-01", "scanner-hr", "clock-floor", "sensor-temp", "ws-support", "tablet-ward", "pos-01", "pos-02", "ws-legal", "ws-marketing", "laptop-cto", "ws-qa-01"];
    const rows = hosts.map((hostname, i) => {
      const state = i % 9 === 0 ? "expired" : i % 13 === 0 ? "released" : "active";
      const subnetId = i % 7 === 0 ? dmzSubnet.id : lanSubnet.id;
      const ip = subnetId === lanSubnet.id ? `192.168.10.${100 + i}` : `172.16.20.${100 + (i % 50)}`;
      const startsAt = daysAgo(int(0, 2));
      return {
        tenantId: 1, subnetId, mac: `aa:bb:cc:10:${(i).toString(16).padStart(2, "0")}:${(i * 7 % 255).toString(16).padStart(2, "0")}`,
        ip, hostname, state, startsAt, endsAt: new Date(startsAt.getTime() + 86_400_000),
      };
    });
    await prisma.dhcpLease.createMany({ data: rows });
  }
  await upsertSetting("dhcp", "relay", { enabled: false, servers: ["192.168.10.254"], interfaces: [] });

  // ── QoS ──────────────────────────────────────────────────────────────────
  const shaper = await prisma.qosPolicy.upsert({
    where: { tenantId_name: { tenantId: 1, name: "WAN-SHAPER" } },
    update: {},
    create: {
      tenantId: 1, name: "WAN-SHAPER", enabled: true, template: "video",
      bandwidthKbps: 50000, ifaceName: "wan0",
    },
  });
  const qosRules: Array<[string, number, number | null, number | null, number | null, string[]]> = [
    ["VOIP-PRIORITY", 0, 4000, null, 46, ["SIP"]],
    ["STREAMING-CAP", 5, null, 15000, 34, ["YouTube", "Netflix"]],
    ["BULK-LOW", 7, null, 5000, 0, ["BitTorrent", "Windows-Update"]],
  ];
  for (const [name, priority, guaranteedKbps, maxKbps, dscpMark, matchApps] of qosRules) {
    const existing = await prisma.qosRule.findFirst({ where: { tenantId: 1, policyId: shaper.id, name } });
    if (!existing) {
      await prisma.qosRule.create({
        data: { tenantId: 1, policyId: shaper.id, name, priority, guaranteedKbps, maxKbps, dscpMark, matchApps: JSON.stringify(matchApps), matchUsers: "[]", matchAddresses: "[]" },
      });
    }
  }

  // ── HA (disabled standby sample) ─────────────────────────────────────────
  const haCount = await prisma.haConfig.count({ where: { tenantId: 1 } });
  if (haCount === 0) {
    await prisma.haConfig.create({
      data: {
        tenantId: 1, enabled: false, role: "standby", priority: 100,
        virtualIp: "192.168.10.254/24", ifaceName: "lan0", peerIp: "192.168.10.253",
        syncConfig: true, sessionSync: true,
        trackedInterfaces: JSON.stringify(["wan0", "lan0"]),
      },
    });
  }

  // ── Log forwarding, webhooks, reports, ssh keys, radius, portal ──────────
  await prisma.syslogTarget.upsert({
    where: { tenantId_name: { tenantId: 1, name: "SIEM-01" } },
    update: {},
    create: { tenantId: 1, name: "SIEM-01", host: "10.20.0.9", port: 514, protocol: "udp", minSeverity: "info", enabled: false },
  });
  await prisma.netflowTarget.upsert({
    where: { tenantId_name: { tenantId: 1, name: "NFDUMP-01" } },
    update: {},
    create: { tenantId: 1, name: "NFDUMP-01", host: "10.20.0.9", port: 2055, version: "ipfix", samplingRate: 100, enabled: false },
  });
  await prisma.webhook.upsert({
    where: { tenantId_name: { tenantId: 1, name: "soc-callback" } },
    update: {},
    create: { tenantId: 1, name: "soc-callback", url: "https://soc.example.net/hooks/cryptsk", events: JSON.stringify(["alerts.new"]), enabled: false, secret: "seed-hmac-secret" },
  });
  await prisma.reportSchedule.upsert({
    where: { tenantId_name: { tenantId: 1, name: "DAILY-TRAFFIC" } },
    update: {},
    create: { tenantId: 1, name: "DAILY-TRAFFIC", range: "daily", format: "html", sections: JSON.stringify(["traffic", "threats"]), recipients: "ops@cryptsk.local" },
  });
  await prisma.sshKey.upsert({
    where: { tenantId_name: { tenantId: 1, name: "ops-laptop" } },
    update: {},
    create: {
      tenantId: 1, name: "ops-laptop",
      publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyPlaceholderForM0Seed ops@laptop",
      fingerprint: "SHA256:0mF4ExamplePlaceholderFingerprintValueM0", addedBy: "admin",
    },
  });
  await prisma.radiusProfile.upsert({
    where: { tenantId_name: { tenantId: 1, name: "CORP-RADIUS" } },
    update: {},
    create: { tenantId: 1, name: "CORP-RADIUS", serverIp: "192.168.1.10", authPort: 1812, sharedSecret: "seed-radius-secret", timeoutSec: 3, retries: 2 },
  });
  await prisma.captivePortalProfile.upsert({
    where: { tenantId_name: { tenantId: 1, name: "GUEST-PORTAL" } },
    update: {},
    create: { tenantId: 1, name: "GUEST-PORTAL", enabled: true, mode: "voucher", interfaceName: "vlan10", sessionTimeoutMin: 240, bandwidthKbps: 5120, voucherTtlHours: 24 },
  });

  // ── Identity sessions (seeded map for top-talker attribution) ────────────
  const identityRows: Array<[string, string, string]> = [
    ["j.doe", "192.168.10.24", "local"], ["a.smith", "192.168.10.31", "radius"],
    ["m.lee", "192.168.10.51", "radius"], ["svc-backup", "192.168.10.66", "local"],
    ["g.guest", "192.168.20.101", "captive_portal"], ["c.reyes", "10.99.1.10", "vpn"],
  ];
  for (const [userName, sourceIp, method] of identityRows) {
    const existing = await prisma.identitySession.findFirst({ where: { tenantId: 1, sourceIp } });
    if (!existing) {
      await prisma.identitySession.create({
        data: {
          tenantId: 1, userName, sourceIp, method,
          deviceMac: `aa:bb:cc:20:${int(0, 99).toString(16).padStart(2, "0")}:${int(0, 99).toString(16).padStart(2, "0")}`,
          startedAt: daysAgo(int(0, 1)), lastSeen: new Date(Date.now() - int(1, 600) * 1000),
        },
      });
    }
  }

  // ── System settings (auth/logging/notifications/advanced/ips) ────────────
  await upsertSetting("auth", "passwordPolicy", { minLength: 8, complexity: "letters_digits", expiryDays: 0, history: 0 });
  await upsertSetting("auth", "lockout", { maxFailures: 5, lockoutMinutes: 15 });
  await upsertSetting("auth", "totp", { required: false });
  await upsertSetting("auth", "sessionLimits", { maxConcurrentPerUser: 4 });
  await upsertSetting("logging", "retention", { firewallLogDays: 30, ipsEventDays: 30, auditDays: 365 });
  await upsertSetting("logging", "disk_quota", { diskQuotaMb: 2048 });
  await upsertSetting("logging", "syslog", { enabled: false });
  await upsertSetting("notifications", "email", { enabled: false });
  await upsertSetting("notifications", "thresholds", { cpuPct: 90, memPct: 90, diskPct: 85, tempC: 80 });
  await upsertSetting("ips", "auto_update", { enabled: true, interval: "daily", time: "03:00", source: "et_free", lastUpdateAt: iso(daysAgo(1)), nextUpdateAt: iso(daysAgo(-1)) });
  await upsertSetting("advanced", "hardening", { sshPasswordAuth: true, managementAllowlist: ["192.168.1.0/24"], stopUnusedServices: true });
  await upsertSetting("advanced", "snmp", { enabled: false, version: "v2c", port: 161 });
  await upsertSetting("advanced", "firmware", { current: "1.0.0", channel: "stable", history: [{ version: "1.0.0", appliedAt: iso(daysAgo(30)) }] });
  await upsertSetting("system", "setup", { completed: true });

  // ── Notifications (5 unread) ─────────────────────────────────────────────
  const notifCount = await prisma.notification.count({ where: { tenantId: 1 } });
  if (RESET || notifCount === 0) {
    if (RESET) await prisma.notification.deleteMany({ where: { tenantId: 1 } });
    await prisma.notification.createMany({
      data: [
        { type: "threat", severity: "critical", title: "Critical IPS event: trojan C2 attempt", message: "Inline drop triggered on wan0 ingress (sid 2027865).", sourceModule: "ips", createdAt: daysAgo(0.2) },
        { type: "threat", severity: "critical", title: "Geo-block flood from blocked origin", message: "GEO_BLOCKLIST rule hit-rate exceeded threshold.", sourceModule: "firewall", createdAt: daysAgo(0.5) },
        { type: "vpn", severity: "warning", title: "VPN BRANCH-IPSEC renegotiating", message: "Tunnel status changed to connecting (DPD timeout).", sourceModule: "vpn", createdAt: daysAgo(0.8) },
        { type: "ha", severity: "info", title: "HA peer heartbeat missed", message: "Standby node re-synced; no failover required.", sourceModule: "ha", createdAt: daysAgo(1.5) },
        { type: "system", severity: "info", title: "IPS rule set updated", message: "Emerging Threats feed refreshed (et_free).", sourceModule: "system", createdAt: daysAgo(2) },
      ],
    });
  }

  // ── Config versions (v1 per section) ─────────────────────────────────────
  const sections = ["firewall", "nat", "interfaces", "routing", "dns", "dhcp", "vpn", "ips", "qos", "ha", "identity", "system"];
  for (const section of sections) {
    const existing = await prisma.configVersion.findFirst({ where: { tenantId: 1, section, version: 1 } });
    if (!existing) {
      await prisma.configVersion.create({
        data: {
          tenantId: 1, version: 1, section,
          configSnapshot: JSON.stringify({ seeded: true, section }),
          changeSummary: "Initial seed snapshot",
          createdBy: userIds.admin,
        },
      });
    }
  }

  // ── Backfill logs (30 days) ──────────────────────────────────────────────
  const logCount = await prisma.firewallLog.count({ where: { tenantId: 1 } });
  if (RESET || logCount < 1000) {
    if (RESET) await prisma.firewallLog.deleteMany({ where: { tenantId: 1 } });
    await backfillFirewallLogs();
  }
  const ipsCount = await prisma.ipsEvent.count({ where: { tenantId: 1 } });
  if (RESET || ipsCount < 100) {
    if (RESET) await prisma.ipsEvent.deleteMany({ where: { tenantId: 1 } });
    await backfillIpsEvents();
  }

  console.log("Seed complete.");
  const counts = {
    users: await prisma.user.count(), interfaces: await prisma.networkInterface.count(),
    firewallRules: await prisma.firewallRule.count(), natRules: await prisma.natRule.count(),
    firewallLogs: await prisma.firewallLog.count(), ipsEvents: await prisma.ipsEvent.count(),
    dhcpLeases: await prisma.dhcpLease.count(), vpnSessions: await prisma.vpnSession.count(),
    notifications: await prisma.notification.count(),
  };
  console.log(JSON.stringify(counts));
}

async function upsertSetting(category: string, key: string, value: unknown) {
  await prisma.systemSetting.upsert({
    where: { tenantId_category_key: { tenantId: 1, category, key } },
    update: { value: JSON.stringify(value) },
    create: { tenantId: 1, category, key, value: JSON.stringify(value) },
  });
}

const APPS = ["HTTPS", "YouTube", "Netflix", "SIP", "DNS", "SSH", "RDP", "Windows-Update", "BitTorrent", "Teams", "Slack", "Facebook"];
const RULES = ["allow-lan-to-wan", "block-guest-to-corp", "deny-dmz-to-lan", "allow-wan-web", "geo-block-wan-ingress", "block-bittorrent", "block-social-workhours", "allow-dns-lan", "implicit-deny"];
const ACTIONS = ["allow", "allow", "allow", "deny", "drop", "reject"] as const;

async function backfillFirewallLogs() {
  console.log("Backfilling ~5000 firewall logs (30 days)…");
  const lans = ["192.168.10.", "192.168.20.", "10.99.1."];
  const batch: Array<Parameters<typeof prisma.firewallLog.createMany>[0]["data"]> = [];
  let rows: typeof batch[number] = [];
  const TOTAL = 5000;
  for (let i = 0; i < TOTAL; i++) {
    const lanPrefix = pick([...lans, ...lans, "172.16.20."]);
    const srcIp = `${lanPrefix}${int(2, 250)}`;
    const isWan = rand() < 0.5;
    const dstIp = isWan ? `203.0.113.${int(2, 254)}` : `192.168.10.${int(2, 250)}`;
    const action = pick([...ACTIONS]);
    const userName = rand() < 0.35 ? pick(["j.doe", "a.smith", "m.lee", "g.guest", "svc-backup"]) : null;
    rows.push({
      tenantId: 1,
      timestamp: daysAgo(rand() * 30),
      srcIp, dstIp,
      srcPort: int(1024, 65535),
      dstPort: pick([80, 443, 443, 53, 22, 3389, 5060, 51820]),
      protocol: rand() < 0.85 ? "tcp" : "udp",
      action,
      ruleName: pick(RULES),
      appName: pick(APPS),
      bytes: int(500, 25_000_000),
      packets: int(5, 20_000),
      userName,
    });
    if (rows.length >= 500) {
      batch.push(...[rows]);
      rows = [];
    }
  }
  if (rows.length) batch.push(rows as typeof batch[number]);
  for (const chunk of batch) {
    await prisma.firewallLog.createMany({ data: chunk as never });
  }
}

const IPS_CATS: Array<[string, string, string]> = [
  ["scan", "medium", "port_scan"], ["web_attack", "high", "sqli_attempt"],
  ["xss", "medium", "reflected_xss"], ["trojan", "critical", "c2_beacon"],
  ["botnet", "critical", "botnet_c2"], ["phishing", "high", "credential_phish"],
  ["brute_force", "medium", "ssh_bruteforce"], ["dos", "high", "syn_flood"],
  ["info_leak", "low", "version_disclosure"], ["policy", "info", "policy_violation"],
  ["malware", "high", "malware_download"], ["exploit", "critical", "exploit_kit"],
];
const SID_RANGE: Record<string, number> = { scan: 2000000, web_attack: 2020000, trojan: 2024000, botnet: 2025000, phishing: 2026000, malware: 2030000, exploit: 2032000, dos: 2100000, brute_force: 2101000, xss: 2021000, info_leak: 2200000, policy: 2210000 };

async function backfillIpsEvents() {
  console.log("Backfilling ~300 IPS events (30 days)…");
  const rows: never[] = [];
  for (let i = 0; i < 300; i++) {
    const [category, severity] = pick(IPS_CATS);
    const sid = SID_RANGE[category] + int(1, 9000);
    const ingress = rand() < 0.6;
    rows.push({
      tenantId: 1,
      timestamp: daysAgo(rand() * 30),
      srcIp: ingress ? `198.51.100.${int(2, 254)}` : `192.168.10.${int(2, 250)}`,
      srcPort: int(1024, 65535),
      dstIp: ingress ? "203.0.113.2" : "172.16.20.5",
      dstPort: pick([80, 443, 22, 3389, 8080]),
      action: severity === "critical" || severity === "high" ? "drop" : "alert",
      sid: String(sid),
      severity,
      category,
      message: `${category.replace("_", " ")} signature matched (simulated ET rule)`,
    } as never);
  }
  await prisma.ipsEvent.createMany({ data: rows });
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
