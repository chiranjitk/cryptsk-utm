/**
 * DNS & DHCP validators (M06) — per M06-DNS-DHCP.md §3/§5 and SCHEMA.md §4.
 * zod is the single source of allowed values at the edge (API_STANDARDS §3);
 * locked enums from PROJECT_MEMORY §6 via validators/enums.ts.
 *
 * Format-level grammar lives here (zod). Cross-field / DB-dependent checks
 * (CIDR containment, overlap, MAC uniqueness, interface existence) live in
 * lib/dns/service.ts + lib/dhcp/service.ts and throw ApiError.
 */

import { z } from "zod";
import {
  dnsRecordTypeSchema,
  dnsPolicyActionSchema,
  dnsBlockCategorySchema,
  dhcpFamilySchema,
  dhcpLeaseStateSchema,
} from "./enums";

// ── primitive grammars ──────────────────────────────────────────────────────

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
// Practical IPv6 form check: groups with at most one "::" compression.
const IPV6_RE =
  /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$/;
// DNS name label — allows leading "_" (SRV owner names like _sip._tcp) and dots.
const DNS_NAME_RE = /^[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?(\.[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?)*$/;
// Public domain for custom block/allow lists — at least one dot, no underscores.
export const DOMAIN_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;
const MAC_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/;
const IFNAME_RE = /^[a-zA-Z0-9._-]{1,15}$/;

export const ipv4Schema = z.string().regex(IPV4_RE, "Must be a valid IPv4 address");
export const ipv6Schema = z.string().regex(IPV6_RE, "Must be a valid IPv6 address");
export const ipAddressSchema = z.string().regex(IPV4_RE, "Must be a valid IPv4 address").or(
  z.string().regex(IPV6_RE, "Must be a valid IPv6 address"),
);
export const dnsNameSchema = z.string().regex(DNS_NAME_RE, "Must be a DNS name (letters, digits, hyphens, dots; '_' allowed in owner names)").max(253);
export const domainSchema = z.string().regex(DOMAIN_RE, "Must be a domain like example.com").max(253);
export const macSchema = z
  .string()
  .transform((v) => v.trim().toLowerCase())
  .refine((v) => MAC_RE.test(v), "MAC must look like aa:bb:cc:dd:ee:ff (lowercase hex, colon separated)");
const ifaceNameSchema = z.string().regex(IFNAME_RE, "Interface name looks like lan0 / eth0.100");
const portSchema = z.number().int().min(1, "Port must be 1-65535").max(65535, "Port must be 1-65535");
const ttlSchema = z
  .number({ message: "TTL must be a number (seconds)" })
  .int()
  .min(60, "TTL must be 60-604800 s")
  .max(604800, "TTL must be 60-604800 s");
const leaseTimeSchema = z
  .number({ message: "Lease time must be a number (seconds)" })
  .int()
  .min(60, "Lease time must be 60-604800 s")
  .max(604800, "Lease time must be 60-604800 s");

const nonEmpty = (label: string, max: number) =>
  z.string().trim().min(1, `${label} is required`).max(max, `${label} must be ≤ ${max} chars`);

// ── DNS policies ────────────────────────────────────────────────────────────

export const dnsPolicyCreateSchema = z.object({
  name: nonEmpty("Policy name", 64),
  enabled: z.boolean().default(true),
  blockCategories: z.array(dnsBlockCategorySchema).max(6).default([]),
  customBlock: z.array(domainSchema).max(500).default([]),
  customAllow: z.array(domainSchema).max(500).default([]),
  action: dnsPolicyActionSchema.default("sinkhole"),
  sinkholeIp: ipv4Schema.default("0.0.0.0"),
});

export const dnsPolicyUpdateSchema = dnsPolicyCreateSchema
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── DNS records (per-type value grammar, M06 §5.2) ─────────────────────────

const SRV_VALUE_RE = /^\d{1,5}\s+\d{1,5}\s+[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?(\.[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?)+$/;

const dnsRecordBaseSchema = z.object({
  zone: dnsNameSchema,
  name: nonEmpty("Record name", 253),
  type: dnsRecordTypeSchema,
  value: nonEmpty("Record value", 1024),
  ttl: ttlSchema.default(3600),
  priority: z.number().int().min(10, "Priority must be 10-65535").max(65535, "Priority must be 10-65535").nullable().optional(),
  enabled: z.boolean().default(true),
});

/** Per-type value grammar + priority rules (M06 §5.2). Base has no refinements
 *  so `.partial()` stays available for the update schema (zod 4 restriction). */
export const dnsRecordCreateSchema = dnsRecordBaseSchema.superRefine((rec, ctx) => {
    const needsPriority = rec.type === "MX" || rec.type === "SRV";
    if (needsPriority && (rec.priority == null)) {
      ctx.addIssue({ code: "custom", path: ["priority"], message: `Priority is required for ${rec.type} records` });
    }
    if (!needsPriority && rec.priority != null) {
      ctx.addIssue({ code: "custom", path: ["priority"], message: `Priority is only valid for MX/SRV records` });
    }
    switch (rec.type) {
      case "A":
        if (!IPV4_RE.test(rec.value)) ctx.addIssue({ code: "custom", path: ["value"], message: "A record value must be an IPv4 address" });
        break;
      case "AAAA":
        if (!IPV6_RE.test(rec.value)) ctx.addIssue({ code: "custom", path: ["value"], message: "AAAA record value must be an IPv6 address" });
        break;
      case "CNAME":
      case "MX":
        if (!DNS_NAME_RE.test(rec.value)) ctx.addIssue({ code: "custom", path: ["value"], message: "Value must be a hostname" });
        break;
      case "TXT":
        if (rec.value.length > 255) ctx.addIssue({ code: "custom", path: ["value"], message: "TXT string must be ≤ 255 chars" });
        break;
      case "SRV":
        if (!SRV_VALUE_RE.test(rec.value)) ctx.addIssue({ code: "custom", path: ["value"], message: "SRV value must be 'weight port target' (e.g. 10 60 5060 sip.corp.local)" });
        break;
      case "PTR":
        if (!rec.value.endsWith(".in-addr.arpa") && !rec.value.endsWith(".ip6.arpa")) {
          ctx.addIssue({ code: "custom", path: ["value"], message: "PTR value must be a reverse zone name (…in-addr.arpa)" });
        }
        break;
    }
  });

export const dnsRecordUpdateSchema = dnsRecordBaseSchema
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── DNS records / query-log list queries ────────────────────────────────────

export const dnsRecordQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(50),
  q: z.string().trim().max(253).optional(),
  zone: z.string().trim().max(253).optional(),
  type: dnsRecordTypeSchema.optional(),
});

export const dnsQueryLogQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  q: z.string().trim().max(253).optional(),
  blocked: z
    .enum(["true", "false"])
    .optional()
    .transform((v) => (v === undefined ? undefined : v === "true")),
});

// ── Resolver settings (SystemSetting ("dns","resolver") JSON) ───────────────

export const forwardZoneSchema = z.object({
  domain: dnsNameSchema,
  server: ipv4Schema,
  port: portSchema.optional(),
});

export const resolverSettingsSchema = z.object({
  forwarders: z.array(ipv4Schema).max(8, "At most 8 forwarders").default([]),
  cacheSizeMb: z.number({ message: "Cache size must be a number (MB)" }).int().min(16, "Cache size must be 16-4096 MB").max(4096, "Cache size must be 16-4096 MB"),
  rrl: z.boolean().default(false),
  dot: z.boolean().default(false),
  forwardZones: z.array(forwardZoneSchema).max(16, "At most 16 forward zones").default([]),
  doh: z
    .object({ enabled: z.boolean().default(false), port: portSchema.default(443) })
    .default({ enabled: false, port: 443 }),
});

// ── DHCP subnets ────────────────────────────────────────────────────────────

export const dhcpSubnetCreateSchema = z.object({
  interfaceName: ifaceNameSchema,
  family: dhcpFamilySchema.default("ipv4"),
  subnetCidr: z.string().trim().min(3, "Subnet CIDR is required").max(50),
  rangeStart: z.string().trim().min(3, "Pool start is required").max(45),
  rangeEnd: z.string().trim().min(3, "Pool end is required").max(45),
  gateway: ipAddressSchema.nullish(),
  dnsServers: z.array(ipAddressSchema).max(4, "At most 4 DNS servers").default([]),
  leaseTime: leaseTimeSchema.default(86400),
  options: z.record(z.string().regex(/^\d{1,3}$/, "Option keys are DHCP option codes (digits)"), z.string().max(255)).default({}),
  enabled: z.boolean().default(true),
});

export const dhcpSubnetUpdateSchema = dhcpSubnetCreateSchema
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── DHCP reservations ───────────────────────────────────────────────────────

export const dhcpReservationCreateSchema = z.object({
  subnetId: z.coerce.number().int().positive("subnetId is required"),
  mac: macSchema,
  ip: z.string().trim().min(3, "IP is required").max(45),
  hostname: z.string().trim().max(64).nullish(),
});

export const dhcpReservationUpdateSchema = dhcpReservationCreateSchema.partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

export const dhcpReservationQuerySchema = z.object({
  subnetId: z.coerce.number().int().positive().optional(),
});

// ── DHCP leases ─────────────────────────────────────────────────────────────

export const dhcpLeaseQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(25),
  state: dhcpLeaseStateSchema.optional(),
  subnetId: z.coerce.number().int().positive().optional(),
  q: z.string().trim().max(64).optional(),
});

// ── DHCP relay (SystemSetting ("dhcp","relay") JSON, M06 §5.3) ──────────────

export const dhcpRelaySchema = z.object({
  enabled: z.boolean().default(false),
  servers: z.array(ipv4Schema).min(1, "At least 1 relay server").max(8, "At most 8 relay servers"),
  interfaces: z.array(ifaceNameSchema).min(1, "At least 1 interface").max(8, "At most 8 interfaces"),
});

// ── inferred types ──────────────────────────────────────────────────────────

export type DnsPolicyCreate = z.infer<typeof dnsPolicyCreateSchema>;
export type DnsPolicyUpdate = z.infer<typeof dnsPolicyUpdateSchema>;
export type DnsRecordCreate = z.infer<typeof dnsRecordCreateSchema>;
export type DnsRecordUpdate = z.infer<typeof dnsRecordUpdateSchema>;
export type DnsRecordQuery = z.infer<typeof dnsRecordQuerySchema>;
export type DnsQueryLogQuery = z.infer<typeof dnsQueryLogQuerySchema>;
export type ResolverSettings = z.infer<typeof resolverSettingsSchema>;
export type DhcpSubnetCreate = z.infer<typeof dhcpSubnetCreateSchema>;
export type DhcpSubnetUpdate = z.infer<typeof dhcpSubnetUpdateSchema>;
export type DhcpReservationCreate = z.infer<typeof dhcpReservationCreateSchema>;
export type DhcpReservationUpdate = z.infer<typeof dhcpReservationUpdateSchema>;
export type DhcpLeaseQuery = z.infer<typeof dhcpLeaseQuerySchema>;
export type DhcpRelay = z.infer<typeof dhcpRelaySchema>;
