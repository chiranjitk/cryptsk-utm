/**
 * Firewall & NAT validators (M03) — zod is the single source of allowed
 * values at the edge (API_STANDARDS §3). Shapes follow SCHEMA.md §3 field
 * names; JSON-array columns arrive as real arrays (lib/json semantics).
 */

import { z } from "zod";
import {
  firewallActionSchema,
  loggingLevelSchema,
  natTypeSchema,
  serviceProtocolSchema,
} from "./enums";

// ── primitive grammars ──────────────────────────────────────────────────────

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const MAC_RE = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
const FQDN_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const GEO_RE = /^[A-Z]{2}$/;
const TIME_RE = /^([01]\d|2[0-3]):[0-5]\d$/;

export const ipv4Schema = z.string().regex(IPV4_RE, "Must be a valid IPv4 address");
export const macSchema = z.string().regex(MAC_RE, "Must be a MAC address like aa:bb:cc:dd:ee:01");

/** Port list grammar: "80", "5000-5100,6000" (each 0-65535, lo<=hi). */
export function isValidPortList(v: string): boolean {
  return v.split(",").every((seg) => {
    const s = seg.trim();
    if (!/^\d{1,5}(-\d{1,5})?$/.test(s)) return false;
    if (s.includes("-")) {
      const [lo, hi] = s.split("-").map(Number);
      return lo <= hi && lo >= 0 && hi <= 65535;
    }
    const p = Number(s);
    return p >= 0 && p <= 65535;
  });
}

export const portListSchema = z
  .string()
  .refine(isValidPortList, "Port list must look like 80 or 5000-5100,6000 (0-65535)");

/** IANA timezone — validated against the runtime ICU database. */
export function isValidTimezone(tz: string): boolean {
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

export const timezoneSchema = z.string().refine(isValidTimezone, "Unknown IANA timezone");

const isoDatetime = z
  .string()
  .refine((v) => !Number.isNaN(new Date(v).getTime()), "Must be an ISO-8601 datetime");

// ── pagination (module default 50, cap 200 per M03 build spec) ─────────────

export const fwListQuery = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  q: z.string().optional(),
  search: z.string().optional(),
  zone: z.string().optional(),
  type: z.string().optional(),
  enabled: z.enum(["true", "false"]).optional(),
});

export const idParamSchema = z.object({ id: z.coerce.number().int().min(1) });

// ── zones ───────────────────────────────────────────────────────────────────

export const zoneTypeSchema = z.enum(["L3", "L2", "VPN"]);

export const zoneBodySchema = z.object({
  name: z.string().min(1).max(64),
  type: zoneTypeSchema,
  interfaceNames: z.array(z.string().min(1).max(32)).default([]),
  description: z.string().max(512).nullable().optional(),
});

export const zonePutSchema = zoneBodySchema;

// ── address objects ────────────────────────────────────────────────────────

export const addressTypeSchema = z.enum(["ip", "range", "subnet", "fqdn", "geo", "wildcard"]);

export function validateAddressValue(type: string, value: string): string | null {
  const v = value.trim();
  switch (type) {
    case "ip":
      return IPV4_RE.test(v) ? null : "Value must be a valid IPv4 address (e.g. 10.0.0.5)";
    case "range": {
      const parts = v.split("-").map((p) => p.trim());
      if (parts.length !== 2 || !IPV4_RE.test(parts[0]) || !IPV4_RE.test(parts[1]))
        return "Range must look like 10.0.0.5-10.0.0.20";
      return null;
    }
    case "subnet": {
      const m = v.match(/^(.+?)\/(\d{1,2})$/);
      if (!m || !IPV4_RE.test(m[1].trim()) || Number(m[2]) > 32)
        return "Subnet must look like 10.0.0.0/24";
      return null;
    }
    case "fqdn":
      return FQDN_RE.test(v) ? null : "Value must be a hostname (e.g. portal.example.com)";
    case "geo":
      return GEO_RE.test(v) ? null : "Geo value must be a 2-letter country code (e.g. DE)";
    case "wildcard": {
      const parts = v.split(/\s+/);
      if (parts.length !== 2 || !IPV4_RE.test(parts[0]) || !IPV4_RE.test(parts[1]))
        return "Wildcard must look like 10.0.0.0 255.0.0.0";
      return null;
    }
    default:
      return "Unknown address type";
  }
}

export const addressObjectBodySchema = z
  .object({
    name: z.string().min(1).max(64),
    type: addressTypeSchema,
    value: z.string().min(1).max(256),
    description: z.string().max(512).nullable().optional(),
  })
  .superRefine((v, ctx) => {
    const err = validateAddressValue(v.type, v.value);
    if (err) ctx.addIssue({ code: "custom", path: ["value"], message: err });
  });

// ── groups (flat, members are object ids) ──────────────────────────────────

export const addressGroupBodySchema = z.object({
  name: z.string().min(1).max(64),
  memberIds: z.array(z.number().int().min(1)).default([]),
  description: z.string().max(512).nullable().optional(),
});

export const serviceGroupBodySchema = z.object({
  name: z.string().min(1).max(64),
  memberIds: z.array(z.number().int().min(1)).default([]),
  description: z.string().max(512).nullable().optional(),
});

// ── service objects ────────────────────────────────────────────────────────

export const serviceObjectBodySchema = z
  .object({
    name: z.string().min(1).max(64),
    protocol: serviceProtocolSchema,
    srcPort: portListSchema.nullish(),
    dstPort: portListSchema.nullish(),
    icmpType: z.number().int().min(0).max(255).nullish(),
    icmpCode: z.number().int().min(0).max(255).nullish(),
    description: z.string().max(512).nullable().optional(),
  })
  .superRefine((v, ctx) => {
    if ((v.protocol === "tcp" || v.protocol === "udp") && !v.srcPort && !v.dstPort) {
      ctx.addIssue({
        code: "custom",
        path: ["dstPort"],
        message: "TCP/UDP services need a source or destination port list",
      });
    }
  });

// ── schedule objects ───────────────────────────────────────────────────────

export const scheduleRecurrenceSchema = z.object({
  days: z.array(z.number().int().min(1).max(7)).min(1),
  start: z.string().regex(TIME_RE, "Start must be HH:MM"),
  end: z.string().regex(TIME_RE, "End must be HH:MM"),
});

export const scheduleObjectBodySchema = z
  .object({
    name: z.string().min(1).max(64),
    type: z.enum(["always", "recurring", "onetime"]),
    recurrence: scheduleRecurrenceSchema.nullish(),
    startsAt: isoDatetime.nullish(),
    endsAt: isoDatetime.nullish(),
    timezone: timezoneSchema.default("UTC"),
  })
  .superRefine((v, ctx) => {
    if (v.type === "recurring" && !v.recurrence) {
      ctx.addIssue({ code: "custom", path: ["recurrence"], message: "Recurring schedules need days + start/end time" });
    }
    if (v.type === "onetime") {
      if (!v.startsAt || !v.endsAt) {
        ctx.addIssue({ code: "custom", path: ["startsAt"], message: "One-time schedules need a start and end datetime" });
      } else if (new Date(v.startsAt).getTime() >= new Date(v.endsAt).getTime()) {
        ctx.addIssue({ code: "custom", path: ["endsAt"], message: "End must be after start" });
      }
    }
  });

// ── firewall rules ─────────────────────────────────────────────────────────

export const firewallRuleBodySchema = z.object({
  name: z.string().min(1).max(128),
  description: z.string().max(1024).nullish(),
  enabled: z.boolean().default(true),
  position: z.number().int().min(1).optional(),
  srcZoneIds: z.array(z.number().int().min(1)).default([]),
  dstZoneIds: z.array(z.number().int().min(1)).default([]),
  srcAddrIds: z.array(z.number().int().min(1)).default([]),
  dstAddrIds: z.array(z.number().int().min(1)).default([]),
  serviceIds: z.array(z.number().int().min(1)).default([]),
  applicationIds: z.array(z.string().min(1).max(64)).default([]),
  userIds: z.array(z.number().int().min(1)).default([]),
  srcMacs: z.array(macSchema).default([]),
  scheduleId: z.number().int().min(1).nullish(),
  action: firewallActionSchema.default("deny"),
  logging: loggingLevelSchema.default("none"),
  connLimit: z.number().int().min(1).max(1_000_000).nullish(),
  rateLimit: z.number().int().min(1).max(1_000_000).nullish(),
  synProtection: z.boolean().default(false),
  synThreshold: z.number().int().min(1).max(1_000_000).nullish(),
  ipsPolicyId: z.number().int().min(1).nullish(),
  qosPolicyId: z.number().int().min(1).nullish(),
  tags: z.array(z.string().min(1).max(32)).default([]),
  comment: z.string().max(2048).nullish(),
});

export const toggleBodySchema = z.object({ enabled: z.boolean() });
export const reorderBodySchema = z.object({
  orderedIds: z.array(z.number().int().min(1)).min(1),
});

export const importBodySchema = z.object({
  format: z.enum(["json", "csv"]),
  payload: z.string(),
});

export const exportQuerySchema = z.object({ format: z.enum(["json", "csv"]).default("json") });

export const validateBodySchema = z.object({
  rule: firewallRuleBodySchema,
  excludeRuleId: z.number().int().min(1).optional(),
});

// ── NAT rules ──────────────────────────────────────────────────────────────

/** translatedSrc is an ip, the literal "masq", or an egress iface name (seed compat). */
export const translatedSrcSchema = z
  .string()
  .min(1)
  .max(64)
  .refine(
    (v) => v === "masq" || IPV4_RE.test(v) || /^[a-z0-9][a-z0-9-_.]{0,31}$/i.test(v),
    "translatedSrc must be an IPv4, 'masq' or an interface name",
  );

export const natRuleBodySchema = z
  .object({
    name: z.string().min(1).max(128).nullish(),
    enabled: z.boolean().default(true),
    position: z.number().int().min(1).optional(),
    type: natTypeSchema,
    srcAddrIds: z.array(z.number().int().min(1)).default([]),
    dstAddrIds: z.array(z.number().int().min(1)).default([]),
    serviceIds: z.array(z.number().int().min(1)).default([]),
    outgoingIface: z.string().max(32).nullish(),
    translatedSrc: translatedSrcSchema.nullish(),
    translatedSrcPool: z.array(ipv4Schema).default([]),
    overload: z.boolean().default(true),
    translatedDst: ipv4Schema.nullish(),
    translatedPort: z.number().int().min(1).max(65535).nullish(),
    translatedPortRange: portListSchema.nullish(),
    logging: loggingLevelSchema.default("none"),
    comment: z.string().max(2048).nullish(),
  })
  .superRefine((v, ctx) => {
    const add = (path: string, message: string) =>
      ctx.addIssue({ code: "custom", path: [path], message });

    if (v.translatedSrc === "masq" && v.translatedSrcPool.length > 0)
      add("translatedSrcPool", "translatedSrc 'masq' is mutually exclusive with translatedSrcPool");
    if (v.translatedPort != null && v.translatedPortRange)
      add("translatedPortRange", "translatedPort and translatedPortRange are mutually exclusive");
    if (v.translatedSrcPool.length > 0 && (v.translatedSrcPool.length < 2 || v.translatedSrcPool.length > 16))
      add("translatedSrcPool", "NAT pool accepts 2-16 IPv4 addresses");

    if (v.type === "snat") {
      if (!v.translatedSrc && v.translatedSrcPool.length === 0)
        add("translatedSrc", "SNAT needs translatedSrc (ip or 'masq') or a translatedSrcPool");
      if (v.translatedDst) add("translatedDst", "SNAT rules cannot set translatedDst");
    }
    if (v.type === "dnat" && !v.translatedDst)
      add("translatedDst", "DNAT rules require translatedDst");
    if (v.type === "hairpin" && !v.translatedDst)
      add("translatedDst", "Hairpin rules require translatedDst");
    if (v.type === "exempt") {
      if (v.translatedSrc || v.translatedSrcPool.length || v.translatedDst || v.translatedPort || v.translatedPortRange)
        add("translatedSrc", "Exempt NAT is identity NAT — translation fields must stay empty");
    }
  });

/** 1:1 NAT helper — emits paired dnat + snat rows atomically (M03 §4). */
export const oneToOneBodySchema = z.object({
  oneToOne: z.object({
    publicIp: ipv4Schema,
    internalHost: ipv4Schema,
    iface: z.string().max(32).optional(),
    name: z.string().max(128).optional(),
    comment: z.string().max(2048).optional(),
  }),
});

export const natPostBodySchema = z.union([oneToOneBodySchema, natRuleBodySchema]);
