# Database Schema — Definitive Prisma (SQLite)

> TL;DR: This file IS the schema. `prisma/schema.prisma` must be an exact copy of the
> block in §3. PostgreSQL columns from the product spec are mapped per §1 (ADR-005).
> Enums are String + zod (values locked in PROJECT_MEMORY §6). Apply with `bun run db:push`.

Related: ER_DIAGRAM.md (relations) · DATA_LIFECYCLE.md (seed/reset/volumes) ·
../00-PROJECT-MEMORY/PROJECT_MEMORY.md §6 (enum values) §10 (mapping rules)

---

## 1. PostgreSQL → SQLite Mapping Rules (LOCKED, ADR-005)

| Spec (PostgreSQL) | Prisma/SQLite here | Notes |
|---|---|---|
| `SERIAL` / `BIGSERIAL` PK | `Int @id @default(autoincrement())` | SQLite ints are 64-bit |
| `TIMESTAMPTZ` | `DateTime` | ISO-8601 UTC storage |
| `JSONB` | `String` (JSON text) `@default("{}")` / `@default("[]")` | zod-validated at the edges; helpers in `lib/json.ts` |
| `TEXT[]` / `INET[]` / `INTEGER[]` | `String` (JSON array text) | same as above |
| id lists (`source_addr_ids INTEGER[]`) | `String` JSON array of ids | **logical reference** — integrity enforced in service layer (see ER_DIAGRAM §3) |
| `INET` / `CIDR` / `MACADDR` | `String` + zod (`ipv4`, cidr regex, mac regex) | no DB-level type |
| `DATERANGE` | `startsAt DateTime?` + `endsAt DateTime?` | |
| PG enums | `String` + zod enum | **never Prisma enums, never Prisma Json, never array scalars on SQLite** |
| `VARCHAR(n)` | `String` | length enforced by zod |

## 2. Conventions

- Model name PascalCase singular; table/column snake_case via `@@map`/`@map`.
- Every tenant-scoped model: `tenantId Int @default(1)` + relation to `Tenant` (ADR-009).
- Timestamps: `createdAt DateTime @default(now())` → `created_at`; `updatedAt DateTime @updatedAt` → `updated_at` where the spec has it.
- No money columns. Big counters: `Int` (SQLite 64-bit is plenty for sandbox; appliance uses BIGINT equivalents).
- Deleting a parent with children: restrict for config objects (must reassign/clean children first); cascade for operational children (sessions, leases, join rows); logs are only ever trimmed by the retention job (never FK cascade on logs).
- **Tenant relation exceptions:** the three append-heavy log models (`FirewallLog`, `IpsEvent`, `AuditLog`) carry `tenantId` as a plain indexed column with **no Prisma relation** — this mirrors the spec's log-table design (`tenant_id INTEGER` without `REFERENCES`) so retention deletes never fight FKs. Every other tenant-scoped model has a real relation to `Tenant`. Query scoping is identical either way (handler filters by `tenantId`).

## 3. The Schema (copy verbatim into `prisma/schema.prisma`)

```prisma
// Cryptsk Console — sandbox schema (SQLite). Source of truth: docs/03-DATABASE/SCHEMA.md
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "sqlite"
  url      = "file:../db/cryptsk.db"
}

// ───────────────────────── Tenancy & Users ─────────────────────────

model Tenant {
  id           Int      @id @default(autoincrement())
  name         String   @unique @map("name")
  company      String?
  contactEmail String?  @map("contact_email")
  status       String   @default("active") // active | suspended
  createdAt    DateTime @default(now()) @map("created_at")

  users             User[]
  zones             Zone[]
  interfaces        NetworkInterface[]
  staticRoutes      StaticRoute[]
  wanPolicies       WanPolicy[]
  addressObjects    AddressObject[]
  addressGroups     AddressGroup[]
  serviceObjects    ServiceObject[]
  serviceGroups     ServiceGroup[]
  scheduleObjects   ScheduleObject[]
  firewallRules     FirewallRule[]
  natRules          NatRule[]
  ipsPolicies       IpsPolicy[]
  vpnConfigs        VpnConfig[]
  dnsPolicies       DnsPolicy[]
  dnsRecords        DnsRecord[]
  dhcpSubnets       DhcpSubnet[]
  qosPolicies       QosPolicy[]
  radiusProfiles    RadiusProfile[]
  captivePortal     CaptivePortalProfile[]
  userGroups        UserGroup[]
  apiKeys           ApiKey[]
  notifications     Notification[]
  configVersions    ConfigVersion[]
  systemSettings    SystemSetting[]
  haConfigs         HaConfig[]
  vpnSessions       VpnSession[]
  dhcpReservations  DhcpReservation[]
  dhcpLeases        DhcpLease[]
  qosRules          QosRule[]
  identitySessions  IdentitySession[]

  @@map("tenants")
}

model User {
  id           Int       @id @default(autoincrement())
  tenantId     Int       @default(1) @map("tenant_id")
  username     String    @map("username")
  passwordHash String    @map("password_hash") // bcrypt
  role         String    @default("helpdesk") // see enum table: super_admin..api_service (8 roles, no "viewer")
  email        String?
  totpSecret   String?   @map("totp_secret")
  isActive     Boolean   @default(true) @map("is_active")
  lastLoginAt  DateTime? @map("last_login_at")
  createdAt    DateTime  @default(now()) @map("created_at")

  tenant        Tenant            @relation(fields: [tenantId], references: [id])
  auditLogs     AuditLog[]
  configVersions ConfigVersion[]  @relation("ConfigVersionAuthor")
  groupMembers  UserGroupMember[]

  @@unique([tenantId, username])
  @@index([tenantId, role])
  @@map("users")
}

model UserGroup {
  id          Int    @id @default(autoincrement())
  tenantId    Int    @default(1) @map("tenant_id")
  name        String
  description String?

  tenant   Tenant            @relation(fields: [tenantId], references: [id])
  members  UserGroupMember[]

  @@unique([tenantId, name])
  @@map("user_groups")
}

model UserGroupMember {
  groupId Int @map("group_id")
  userId  Int @map("user_id")

  group UserGroup @relation(fields: [groupId], references: [id], onDelete: Cascade)
  user  User      @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@id([groupId, userId])
  @@map("user_group_members")
}

// ───────────────────────── Network: zones, interfaces, routing ─────────────────────────

model Zone {
  id             Int     @id @default(autoincrement())
  tenantId       Int     @default(1) @map("tenant_id")
  name           String
  type           String  // L3 | L2 | VPN
  interfaceNames String  @default("[]") @map("interface_names") // JSON array of iface names
  description    String?

  tenant      Tenant             @relation(fields: [tenantId], references: [id])
  interfaces  NetworkInterface[] @relation("ZoneInterfaces")

  @@unique([tenantId, name])
  @@map("zones")
}

model NetworkInterface {
  id          Int     @id @default(autoincrement())
  tenantId    Int     @default(1) @map("tenant_id")
  name        String  // wan0, lan0, dmz0, vlan10, br0, bond0, gre1 …
  type        String  // physical | vlan | bridge | bond | loopback | gre
  role        String  @default("unused") // wan | lan | dmz | vpn | mgmt | unused
  parentName  String? @map("parent_name") // vlan/bridge/bond members
  vlanId      Int?    @map("vlan_id")
  mtu         Int     @default(1500)
  mssClamp    Int?    @map("mss_clamp")
  enabled     Boolean @default(true)
  config      String  @default("{}") // JSON, shape per type (see notes §4)
  description String?

  tenant Tenant @relation(fields: [tenantId], references: [id])
  zone   Zone?  @relation("ZoneInterfaces", fields: [zoneId], references: [id])
  zoneId Int?   @map("zone_id")

  wanPolicy WanPolicy?

  @@unique([tenantId, name])
  @@index([tenantId, type])
  @@map("interfaces")
}

model StaticRoute {
  id             Int     @id @default(autoincrement())
  tenantId       Int     @default(1) @map("tenant_id")
  name           String? // optional label
  destinationCidr String @map("destination_cidr") // e.g. 10.20.0.0/16
  gateway        String? // next-hop ip; null when blackhole
  interfaceName  String? @map("interface_name")
  distance       Int     @default(1) // metric/admin distance
  blackhole      Boolean @default(false)
  enabled        Boolean @default(true)
  description    String?
  createdAt      DateTime @default(now()) @map("created_at")

  tenant Tenant @relation(fields: [tenantId], references: [id])

  @@index([tenantId, enabled])
  @@map("static_routes")
}

model WanPolicy {
  id            Int     @id @default(autoincrement())
  tenantId      Int     @default(1) @map("tenant_id")
  interfaceName String  @map("interface_name") // must exist in interfaces
  mode          String  @default("failover") // priority | failover | load_balance
  weight        Int     @default(50) // load_balance weight %
  priority      Int     @default(1)  // lower = preferred
  probeType     String  @default("icmp") @map("probe_type") // icmp | tcp | dns | http
  probeTarget   String  @default("1.1.1.1") @map("probe_target")
  intervalSec   Int     @default(5) @map("interval_sec")
  timeoutMs     Int     @default(2000) @map("timeout_ms")
  failThreshold Int     @default(3) @map("fail_threshold")
  okThreshold   Int     @default(3) @map("ok_threshold")
  state         String  @default("unknown") @map("state") // up | degraded | down | unknown
  enabled       Boolean @default(true)

  tenant    Tenant           @relation(fields: [tenantId], references: [id])
  // compound FK: interfaces.name is unique per tenant, not globally (see @@unique on NetworkInterface);
  // field order matches the @@unique([tenantId, name]) definition on NetworkInterface
  interface NetworkInterface @relation(fields: [tenantId, interfaceName], references: [tenantId, name], onDelete: Restrict)

  @@unique([tenantId, interfaceName])
  @@map("wan_policies")
}

// ───────────────────────── Objects ─────────────────────────

model AddressObject {
  id          Int     @id @default(autoincrement())
  tenantId    Int     @default(1) @map("tenant_id")
  name        String
  type        String  // ip | range | subnet | fqdn | geo | wildcard
  value       String  // "10.0.0.5" | "10.0.0.5-10.0.0.20" | "10.0.0.0/24" | "example.com" | "DE" | "10.0.0.0 255.0.0.0"
  description String?
  createdAt   DateTime @default(now()) @map("created_at")

  tenant Tenant @relation(fields: [tenantId], references: [id])

  @@unique([tenantId, name])
  @@index([tenantId, type])
  @@map("address_objects")
}

model AddressGroup {
  id          Int     @id @default(autoincrement())
  tenantId    Int     @default(1) @map("tenant_id")
  name        String
  memberIds   String  @default("[]") @map("member_ids") // JSON array of address_objects.id
  description String?

  tenant Tenant @relation(fields: [tenantId], references: [id])

  @@unique([tenantId, name])
  @@map("address_groups")
}

model ServiceObject {
  id          Int     @id @default(autoincrement())
  tenantId    Int     @default(1) @map("tenant_id")
  name        String
  protocol    String  // tcp | udp | icmp | any
  srcPort     String? @map("src_port") // "any" | "80" | "5000-5100,6000"
  dstPort     String? @map("dst_port")
  icmpType    Int?    @map("icmp_type")
  description String?

  tenant Tenant @relation(fields: [tenantId], references: [id])

  @@unique([tenantId, name])
  @@map("service_objects")
}

model ServiceGroup {
  id          Int     @id @default(autoincrement())
  tenantId    Int     @default(1) @map("tenant_id")
  name        String
  memberIds   String  @default("[]") @map("member_ids") // JSON array of service_objects.id
  description String?

  tenant Tenant @relation(fields: [tenantId], references: [id])

  @@unique([tenantId, name])
  @@map("service_groups")
}

model ScheduleObject {
  id          Int     @id @default(autoincrement())
  tenantId    Int     @default(1) @map("tenant_id")
  name        String
  type        String  @default("always") // always | recurring | onetime
  recurrence  String? // JSON {days:[1-7], start:"09:00", end:"17:00"} (1=Monday)
  startsAt    DateTime? @map("starts_at") // onetime begin
  endsAt      DateTime? @map("ends_at")   // onetime end / recurrence end
  timezone    String  @default("UTC")   // IANA name e.g. Asia/Calcutta

  tenant     Tenant         @relation(fields: [tenantId], references: [id])
  fwRules    FirewallRule[]

  @@unique([tenantId, name])
  @@map("schedule_objects")
}

// ───────────────────────── Firewall & NAT ─────────────────────────

model FirewallRule {
  id             Int     @id @default(autoincrement())
  tenantId       Int     @default(1) @map("tenant_id")
  name           String
  description    String?
  enabled        Boolean @default(true)
  position       Int     // ordering (top = evaluated first)
  srcZoneIds     String  @default("[]") @map("src_zone_ids")   // JSON id arrays — logical refs
  dstZoneIds     String  @default("[]") @map("dst_zone_ids")
  srcAddrIds     String  @default("[]") @map("src_addr_ids")  // address_objects + groups ids
  dstAddrIds     String  @default("[]") @map("dst_addr_ids")
  serviceIds     String  @default("[]") @map("service_ids")   // service_objects + groups ids
  applicationIds String  @default("[]") @map("application_ids") // nDPI app label ids
  userIds        String  @default("[]") @map("user_ids")
  scheduleId     Int?    @map("schedule_id")
  action         String  @default("deny") // allow | deny | drop | reject
  logging        String  @default("none") @map("logging") // none | summary | detail
  connLimit      Int?    @map("conn_limit")
  rateLimit      Int?    @map("rate_limit") // conn/s per source
  synProtection  Boolean @default(false) @map("syn_protection")
  synThreshold   Int?    @map("syn_threshold")
  ipsPolicyId    Int?    @map("ips_policy_id")
  qosPolicyId    Int?    @map("qos_policy_id")
  tags           String  @default("[]") // JSON array of strings
  comment        String?
  hitCount       Int     @default(0) @map("hit_count")
  lastHitAt      DateTime? @map("last_hit_at")
  createdAt      DateTime @default(now()) @map("created_at")
  updatedAt      DateTime @updatedAt @map("updated_at")

  tenant    Tenant          @relation(fields: [tenantId], references: [id])
  // explicit Restrict on optional relations: deleting a referenced object must fail
  // (409) instead of silently detaching it from rules (Prisma default would be SetNull)
  schedule  ScheduleObject? @relation(fields: [scheduleId], references: [id], onDelete: Restrict)
  ipsPolicy IpsPolicy?      @relation(fields: [ipsPolicyId], references: [id], onDelete: Restrict)
  qosPolicy QosPolicy?      @relation(fields: [qosPolicyId], references: [id], onDelete: Restrict)
  // NOTE: srcZoneIds/dstZoneIds/srcAddrIds/… are LOGICAL refs (JSON id arrays) —
  // no Prisma relations for them; integrity enforced in the service layer (ER_DIAGRAM §3).
  // NOTE: NAT is NOT on firewall rules in the build — the spec's nat_type/nat_target/
  // nat_port columns are consolidated into the dedicated `nat_rules` table.

  @@index([tenantId, enabled, position])
  @@map("firewall_rules")
}

model NatRule {
  id             Int     @id @default(autoincrement())
  tenantId       Int     @default(1) @map("tenant_id")
  name           String?
  position       Int
  type           String  // snat | dnat | hairpin | exempt
  enabled        Boolean @default(true)
  srcAddrIds     String  @default("[]") @map("src_addr_ids")
  dstAddrIds     String  @default("[]") @map("dst_addr_ids")
  serviceIds     String  @default("[]") @map("service_ids")
  outgoingIface  String? @map("outgoing_iface")
  translatedSrc  String? @map("translated_src") // ip or masquerade flag "masq"
  translatedDst  String? @map("translated_dst")
  translatedPort Int?    @map("translated_port")
  comment        String?
  hitCount       Int     @default(0) @map("hit_count")
  createdAt      DateTime @default(now()) @map("created_at")

  tenant Tenant @relation(fields: [tenantId], references: [id])

  @@index([tenantId, enabled, position])
  @@map("nat_rules")
}

// ───────────────────────── IPS ─────────────────────────

model IpsPolicy {
  id             Int     @id @default(autoincrement())
  tenantId       Int     @default(1) @map("tenant_id")
  name           String
  mode           String  @default("inline_drop") // inline_drop | inline_tap | passive
  enabled        Boolean @default(true)
  ruleCategories String  @default("{}") @map("rule_categories") // JSON {"trojan":true,...}
  customRules    String  @default("[]") @map("custom_rules")  // JSON array of raw suricata rule strings
  exceptions     String  @default("[]") // JSON [{sid, source?, dest?, comment}]
  thresholds     String  @default("[]") // JSON [{sid, track, count, seconds}]

  tenant   Tenant         @relation(fields: [tenantId], references: [id])
  fwRules  FirewallRule[]

  @@unique([tenantId, name])
  @@map("ips_policies")
}

model IpsEvent {
  id        Int      @id @default(autoincrement())
  tenantId  Int      @default(1) @map("tenant_id")
  timestamp DateTime @default(now())
  srcIp     String?  @map("src_ip")
  srcPort   Int?     @map("src_port")
  dstIp     String?  @map("dst_ip")
  dstPort   Int?     @map("dst_port")
  action    String   // alert | drop | reject | bypass | suppressed
  sid       String?  // suricata rule id
  severity  String   // info | low | medium | high | critical
  category  String?  // e.g. trojan, web_attack, scan, policy
  message   String?
  suppressedUntil DateTime? @map("suppressed_until")

  @@index([tenantId, timestamp])
  @@index([tenantId, severity])
  @@map("ips_events")
}

// ───────────────────────── VPN ─────────────────────────

model VpnConfig {
  id            Int     @id @default(autoincrement())
  tenantId      Int     @default(1) @map("tenant_id")
  name          String
  type          String  // wireguard_s2s | wireguard_remote | ipsec_s2s | ipsec_remote | openvpn
  enabled       Boolean @default(true)
  config        String  @default("{}") // JSON, shape per type (§4)
  status        String  @default("down") // up | down | connecting | error
  statusMessage String? @map("status_message")
  createdAt     DateTime @default(now()) @map("created_at")

  tenant   Tenant       @relation(fields: [tenantId], references: [id])
  sessions VpnSession[]

  @@unique([tenantId, name])
  @@index([tenantId, type])
  @@map("vpn_configs")
}

model VpnSession {
  id           Int      @id @default(autoincrement())
  tenantId     Int      @default(1) @map("tenant_id")
  vpnId        Int      @map("vpn_id")
  userName     String?  @map("user_name")
  sourceIp     String   @map("source_ip")
  assignedIp   String?  @map("assigned_ip")
  bytesIn      Int      @default(0) @map("bytes_in")
  bytesOut     Int      @default(0) @map("bytes_out")
  connectedAt  DateTime @default(now()) @map("connected_at")
  lastActivity DateTime @default(now()) @map("last_activity")
  status       String   @default("active") // active | idle | disconnected

  tenant Tenant    @relation(fields: [tenantId], references: [id])
  config VpnConfig @relation(fields: [vpnId], references: [id], onDelete: Cascade)

  @@index([tenantId, vpnId, status])
  @@map("vpn_sessions")
}

// ───────────────────────── DNS & DHCP ─────────────────────────

model DnsPolicy {
  id              Int     @id @default(autoincrement())
  tenantId        Int     @default(1) @map("tenant_id")
  name            String
  enabled         Boolean @default(true)
  blockCategories String  @default("[]") @map("block_categories") // JSON: ads, malware, phishing, adult, social, gambling
  customBlock     String  @default("[]") @map("custom_block") // JSON array of domains
  customAllow     String  @default("[]") @map("custom_allow")
  sinkholeIp      String  @default("0.0.0.0") @map("sinkhole_ip")
  action          String  @default("sinkhole") // sinkhole | nxdomain

  tenant Tenant @relation(fields: [tenantId], references: [id])

  @@unique([tenantId, name])
  @@map("dns_policies")
}

model DnsRecord {
  id       Int     @id @default(autoincrement())
  tenantId Int     @default(1) @map("tenant_id")
  zone     String  // e.g. corp.local
  name     String
  type     String  // A | AAAA | CNAME | MX | TXT | SRV | PTR
  value    String
  ttl      Int     @default(3600)
  priority Int?
  enabled  Boolean @default(true)

  tenant Tenant @relation(fields: [tenantId], references: [id])

  @@index([tenantId, zone, name])
  @@map("dns_records")
}

model DhcpSubnet {
  id          Int     @id @default(autoincrement())
  tenantId    Int     @default(1) @map("tenant_id")
  interfaceName String @map("interface_name")
  subnetCidr  String  @map("subnet_cidr") // 192.168.10.0/24
  rangeStart  String  @map("range_start")
  rangeEnd    String  @map("range_end")
  gateway     String?
  dnsServers  String  @default("[]") @map("dns_servers") // JSON array of ips
  leaseTime   Int     @default(86400) @map("lease_time")
  options     String  @default("{}") // JSON custom dhcp options
  enabled     Boolean @default(true)

  tenant       Tenant            @relation(fields: [tenantId], references: [id])
  reservations DhcpReservation[]
  leases       DhcpLease[]

  @@index([tenantId, interfaceName])
  @@map("dhcp_subnets")
}

model DhcpReservation {
  id        Int    @id @default(autoincrement())
  tenantId  Int    @default(1) @map("tenant_id")
  subnetId  Int    @map("subnet_id")
  mac       String
  ip        String
  hostname  String?

  tenant Tenant     @relation(fields: [tenantId], references: [id])
  subnet DhcpSubnet @relation(fields: [subnetId], references: [id], onDelete: Cascade)

  @@unique([tenantId, mac]) // NOT globally unique — two tenants may have the same MAC
  @@map("dhcp_reservations")
}

model DhcpLease {
  id        Int      @id @default(autoincrement())
  tenantId  Int      @default(1) @map("tenant_id")
  subnetId  Int      @map("subnet_id")
  mac       String
  ip        String
  hostname  String?
  state     String   @default("active") // active | expired | released
  startsAt  DateTime @default(now()) @map("starts_at")
  endsAt    DateTime @map("ends_at")

  tenant Tenant     @relation(fields: [tenantId], references: [id])
  subnet DhcpSubnet @relation(fields: [subnetId], references: [id], onDelete: Cascade)

  @@index([tenantId, state])
  @@unique([subnetId, ip]) // unique per subnet, not globally (tenants reuse RFC1918 space)
  @@map("dhcp_leases")
}

// ───────────────────────── QoS ─────────────────────────

model QosPolicy {
  id            Int     @id @default(autoincrement())
  tenantId      Int     @default(1) @map("tenant_id")
  name          String
  enabled       Boolean @default(true)
  template      String? // voip | video | gaming | bulk | custom
  bandwidthKbps Int     @map("bandwidth_kbps") // total shaper for the policy
  ifaceName     String? @map("iface_name") // optional per-wan attachment

  tenant Tenant   @relation(fields: [tenantId], references: [id])
  rules  QosRule[]
  fwRules FirewallRule[]

  @@unique([tenantId, name])
  @@map("qos_policies")
}

model QosRule {
  id             Int     @id @default(autoincrement())
  tenantId       Int     @default(1) @map("tenant_id")
  policyId       Int     @map("policy_id")
  name           String
  priority       Int     // 0 highest .. 7 lowest
  guaranteedKbps Int?    @map("guaranteed_kbps")
  maxKbps        Int?    @map("max_kbps")
  dscpMark       Int?    @map("dscp_mark")
  matchApps      String  @default("[]") @map("match_apps")       // JSON nDPI label ids
  matchUsers     String  @default("[]") @map("match_users")
  matchAddresses String  @default("[]") @map("match_addresses")  // address_objects ids

  tenant Tenant    @relation(fields: [tenantId], references: [id])
  policy QosPolicy @relation(fields: [policyId], references: [id], onDelete: Cascade)

  @@index([tenantId, policyId])
  @@map("qos_rules")
}

// ───────────────────────── Identity ─────────────────────────

model RadiusProfile {
  id           Int    @id @default(autoincrement())
  tenantId     Int    @default(1) @map("tenant_id")
  name         String
  serverIp     String @map("server_ip")
  authPort     Int    @default(1812) @map("auth_port")
  sharedSecret String @map("shared_secret") // masked in API responses
  timeoutSec   Int    @default(3) @map("timeout_sec")
  retries      Int    @default(2)

  tenant Tenant @relation(fields: [tenantId], references: [id])

  @@unique([tenantId, name])
  @@map("radius_profiles")
}

model CaptivePortalProfile {
  id                Int     @id @default(autoincrement())
  tenantId          Int     @default(1) @map("tenant_id")
  name              String
  enabled           Boolean @default(false)
  mode              String  @default("clickthrough") // clickthrough | credentials | voucher
  interfaceName     String  @map("interface_name")
  sessionTimeoutMin Int     @default(240) @map("session_timeout_min")
  bandwidthKbps     Int?    @map("bandwidth_kbps")
  redirectUrl       String? @map("redirect_url")
  voucherTtlHours   Int     @default(24) @map("voucher_ttl_hours")

  tenant Tenant @relation(fields: [tenantId], references: [id])

  @@unique([tenantId, name])
  @@map("captive_portal_profiles")
}

model IdentitySession {
  id        Int      @id @default(autoincrement())
  tenantId  Int      @default(1) @map("tenant_id")
  userName  String   @map("user_name")
  sourceIp  String   @map("source_ip")
  method    String   // local | radius | captive_portal | vpn
  deviceMac String?  @map("device_mac")
  startedAt DateTime @default(now()) @map("started_at")
  lastSeen  DateTime @default(now()) @map("last_seen")
  state     String   @default("active") // active | expired

  tenant Tenant @relation(fields: [tenantId], references: [id])

  @@index([tenantId, state])
  @@unique([tenantId, sourceIp]) // one identity per source IP per tenant
  @@map("identity_sessions")
}

// ───────────────────────── Logs (append-heavy) ─────────────────────────

model FirewallLog {
  id        Int      @id @default(autoincrement())
  tenantId  Int      @default(1) @map("tenant_id")
  timestamp DateTime @default(now())
  srcIp     String?  @map("src_ip")
  dstIp     String?  @map("dst_ip")
  srcPort   Int?     @map("src_port")
  dstPort   Int?     @map("dst_port")
  protocol  String?  // tcp | udp | icmp
  action    String?  // allow | deny | drop | reject
  ruleName  String?  @map("rule_name")
  appName   String?  @map("app_name") // nDPI label
  bytes     Int      @default(0)
  packets   Int      @default(0)
  userName  String?  @map("user_name")

  @@index([tenantId, timestamp])
  @@index([srcIp])
  @@index([dstIp])
  @@map("firewall_logs")
}

model AuditLog {
  id         Int      @id @default(autoincrement())
  tenantId   Int      @default(1) @map("tenant_id")
  userId     Int?     @map("user_id")
  username   String?
  sourceIp   String?  @map("source_ip")
  action     String   // login, rule.create, rule.update, iface.update, config.apply, …
  objectType String   @map("object_type") // firewall_rule, nat_rule, interface, …
  objectId   Int?     @map("object_id")
  objectName String?  @map("object_name")
  beforeState String? @map("before_state") // JSON
  afterState  String? @map("after_state")  // JSON
  result     String   @default("success") // success | failure | denied
  createdAt  DateTime @default(now()) @map("created_at")

  user User? @relation(fields: [userId], references: [id])

  @@index([tenantId, createdAt])
  @@index([tenantId, objectType])
  @@map("audit_log")
}

// ───────────────────────── System ─────────────────────────

model ConfigVersion {
  id            Int      @id @default(autoincrement())
  tenantId      Int      @default(1) @map("tenant_id")
  version       Int
  section       String   // firewall | nat | interfaces | routing | dns | dhcp | vpn | ips | qos | ha | identity | system
  configSnapshot String  @map("config_snapshot") // JSON snapshot of the section
  changeSummary String?  @map("change_summary")
  createdBy     Int?     @map("created_by")
  createdAt     DateTime @default(now()) @map("created_at")

  tenant Tenant @relation(fields: [tenantId], references: [id])
  author User?  @relation("ConfigVersionAuthor", fields: [createdBy], references: [id])

  @@unique([tenantId, section, version])
  @@map("config_versions")
}

model SystemSetting {
  id        Int      @id @default(autoincrement())
  tenantId  Int      @default(1) @map("tenant_id")
  category  String   // general | auth | logging | notifications | dns | advanced
  key       String
  value     String   // JSON
  updatedAt DateTime @updatedAt @map("updated_at")

  tenant Tenant @relation(fields: [tenantId], references: [id])

  @@unique([tenantId, category, key])
  @@map("system_settings")
}

model Notification {
  id           Int      @id @default(autoincrement())
  tenantId     Int      @default(1) @map("tenant_id")
  type         String   // threat | system | vpn | ha | config
  severity     String   // info | warning | critical
  title        String
  message      String?
  sourceModule String?  @map("source_module")
  isRead       Boolean  @default(false) @map("is_read")
  createdAt    DateTime @default(now()) @map("created_at")

  tenant Tenant @relation(fields: [tenantId], references: [id])

  @@index([tenantId, isRead, createdAt])
  @@map("notifications")
}

model ApiKey {
  id         Int       @id @default(autoincrement())
  tenantId   Int       @default(1) @map("tenant_id")
  name       String
  prefix     String    @unique // "ck_" + 8 chars — stored for lookup, full key shown once
  hashedKey  String    @map("hashed_key") // sha256 of full key
  scopes     String    @default("[\"read\"]") // JSON: read | write | admin
  lastUsedAt DateTime? @map("last_used_at")
  expiresAt  DateTime? @map("expires_at")
  revoked    Boolean   @default(false)
  createdAt  DateTime  @default(now()) @map("created_at")

  tenant Tenant @relation(fields: [tenantId], references: [id])

  @@map("api_keys")
}

model HaConfig {
  id         Int     @id @default(autoincrement())
  tenantId   Int     @default(1) @map("tenant_id")
  enabled    Boolean @default(false)
  role       String  @default("disabled") // disabled | active | standby
  priority   Int     @default(100) // higher wins master election (Keepalived semantics)
  virtualIp  String? @map("virtual_ip") // CIDR
  ifaceName  String  @map("iface_name")
  peerIp     String? @map("peer_ip")
  syncConfig Boolean @default(true) @map("sync_config")
  failAfterSec Int   @default(10) @map("fail_after_sec")
  holdDownSec  Int   @default(60) @map("hold_down_sec")

  tenant Tenant @relation(fields: [tenantId], references: [id])

  @@map("ha_configs")
}
```

## 4. JSON Field Shapes (zod-validated)

| Field | Shape |
|---|---|
| `NetworkInterface.config` (physical) | `{ mac?: string, speedMbps?: number, duplex?: "half"\|"full", wanType?: "static"\|"dhcp"\|"pppoe", ip?: string, cidrPrefix?: number, gateway?: string, dns?: string[], pppoe?: { user: string, password: string, service?: string } }` |
| `NetworkInterface.config` (vlan) | `{ parent: string }` (vlanId is a column) |
| `NetworkInterface.config` (bridge) | `{ members: string[], stp?: boolean }` |
| `NetworkInterface.config` (bond) | `{ members: string[], mode: "active-backup"\|"802.3ad"\|"balance-xor" }` |
| `NetworkInterface.config` (gre) | `{ local: string, remote: string, ttl?: number }` |
| `ScheduleObject.recurrence` | `{ days: number[], start: "HH:MM", end: "HH:MM" }` (days 1=Mon..7=Sun) |
| `IpsPolicy.ruleCategories` | `{ [category: string]: boolean }` — categories list served by `/api/v1/ips/rule-categories` |
| `IpsPolicy.exceptions` | `[{ sid: number, source?: string, dest?: string, comment?: string }]` — `sid: 0` means "any SID" (SID-less capture-level bypass; generator renders it as an nftables `skip queue` rule ahead of the Suricata queue rule — ADR-017) |
| `IpsPolicy.thresholds` | `[{ sid: number, track: "by_src"\|"by_dst", count: number, seconds: number }]` |
| `VpnConfig.config` (wireguard_s2s) | `{ privateKey: string, listenPort: number, peers: [{ name, publicKey, allowedIps: string[], endpoint?, keepaliveSec? }], address: string }` |
| `VpnConfig.config` (wireguard_remote) | `{ privateKey: string, listenPort: number, address: string, pool: string, dns?: string, keepaliveSec?: number, peers: [{ name, publicKey, allowedIps: string[] }] }` — each provisioned remote client is a peer with a `/32` `allowedIps` from the pool (pool + peer `/32`s are the IPAM; client-bundle generation appends peers, M05 §5) |
| `VpnConfig.config` (ipsec_*) | `{ localIp, remoteIp?, localSubnets: string[], remoteSubnets: string[], psk, ike: string, esp: string, dpdSec?: number, pfs?: boolean, authMethod?: "psk"\|"eap_mschapv2"\|"eap_tls" }` |
| `VpnConfig.config` (openvpn) | `{ proto: "udp"\|"tcp", port: number, cipher: string, auth: string, pool: string, tls?: boolean }` |
| `DhcpSubnet.options` | `{ [optionCode: string]: string }` e.g. `{ "42": "192.168.10.1" }` (NTP) |
| `QosPolicy`/`QosRule` matches | arrays of ids / nDPI label ids (strings) |
| `SystemSetting.value` | free JSON per settings schema (M10) |
| `ApiKey.scopes` | `["read"]`, `["read","write"]`, or `["read","write","admin"]` |

## 5. Index & Integrity Notes

- Hot paths: `firewall_logs(tenantId,timestamp)`, `ips_events(tenantId,timestamp)`,
  `audit_log(tenantId,createdAt)`, `firewall_rules(tenantId,enabled,position)`.
- Log retention job (DATA_LIFECYCLE §4) deletes by timestamp in batches; no FK from logs to config tables (rows survive rule deletion — `ruleName`/`appName` are denormalized strings on purpose).
- Deletes: config objects RESTRICT when referenced (service layer checks logical refs before delete and returns `CONFLICT` with referencing rule names); children with FK cascade: reservations/leases (subnet), vpn_sessions (vpn), qos_rules (policy), group members.
- All list endpoints are tenant-scoped automatically (handler injects `tenantId` from JWT).

## 6. Pseudo-Resources (no dedicated table — persistence decisions)

| Resource | Persistence | Notes |
|---|---|---|
| DNS resolver settings (`GET/PUT /api/v1/dns/settings`) | `SystemSetting` row: category `dns`, key `resolver`, JSON value | forwarders, cache size, RRL toggle, DoT display flag |
| Backups (`/api/v1/system/backups`) | Filesystem JSON files under `db/backups/<ts>-<label>.json` | list = directory scan; restore = snapshot reload; never stored in SQLite (avoid self-copy problem) |
| Captive-portal vouchers | In-memory (MockEngine), volatile by design (Phase 1) | list/generate/revoke via `/api/v1/captive-portal/vouchers` |
| DNS query log | Derived view from MockEngine ring buffer (not a table) | see DATA_LIFECYCLE §3 |

## 7. Do / Don't

- DO copy §3 verbatim into `prisma/schema.prisma` at bootstrap (M0), then `bun run db:push`.
- DO extend schema only together with this doc (recipe PROJECT_MEMORY §12).
- DON'T add Prisma enums, `Json` type, or array scalars.
- DON'T add FKs for JSON-array logical references — they live in ER_DIAGRAM §3 and service-layer checks only.
