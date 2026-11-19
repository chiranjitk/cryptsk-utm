/**
 * Logging & Reporting zod schemas (M09 §3/§5) — locked enums from
 * validators/enums.ts. List queries are server-paginated; `since`/`until`
 * take ISO datetimes and `until < since` is rejected (VALIDATION_ERROR 400,
 * M09 §3 expected errors). Free-text `q` is applied server-side per view.
 */

import { z } from "zod";
import {
  auditResultSchema,
  firewallActionSchema,
  ipsSeveritySchema,
  netflowVersionSchema,
  reportFormatSchema,
  reportRangeSchema,
  syslogProtocolSchema,
} from "./enums";
import { isLoopbackHost } from "@/lib/logs/os";

const isoOrEmpty = z
  .string()
  .refine((v) => v === "" || !Number.isNaN(Date.parse(v)), "must be an ISO timestamp");

// ── shared grammars (F-e #16/#20) ─────────────────────────────────────────

/** Plain email entry — used for the comma-separated report recipients list. */
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

/** Comma-separated list of email addresses (empty string allowed — cleared). */
const recipientsSchema = z
  .string()
  .max(512)
  .refine(
    (v) =>
      v.trim() === "" ||
      v
        .split(",")
        .map((s) => s.trim())
        .every((s) => EMAIL_RE.test(s)),
    "recipients must be a comma-separated list of valid email addresses",
  );

/** RFC-1123-ish hostname (no underscores/spaces/quotes — rsyslog omfwd-safe). */
const HOSTNAME_RE = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

/** IPv6 including the :: compression forms (matches logs/os.ts refusals). */
const IPV6_RE =
  /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$/;

/** IPv6 link-local block fe80::/10 (fe8x, fe9x, feax, febx). */
function isLinkLocalHost(host: string): boolean {
  const h = host.trim().toLowerCase();
  if (/^fe[89ab]/.test(h)) return true; // fe80::/10
  return /^169\.254\./.test(h); // IPv4 link-local 169.254/16
}

/**
 * Syslog/NetFlow target host grammar (F-e #20): hostname | IPv4 | IPv6 —
 * loopback (localhost, 127/8, ::1) and link-local (169.254/16, fe80::/10)
 * targets are refused at create with the same reasoning as logs/os.ts §
 * "hard refusals" (self-loop / non-routable).
 */
const targetHostSchema = z
  .string()
  .trim()
  .min(1)
  .max(253)
  .refine((v) => HOSTNAME_RE.test(v) || IPV4_RE.test(v) || IPV6_RE.test(v), "Must be a hostname, IPv4 or IPv6 address")
  .refine(
    (v) => !isLoopbackHost(v),
    "loopback targets are refused — forwarding to this appliance would feed the collector its own output (self-loop)",
  )
  .refine(
    (v) => !isLinkLocalHost(v),
    "link-local targets are refused — 169.254/16 and fe80::/10 are not routable forwarding destinations",
  );

/** `?until=` earlier than `?since=` → 400 VALIDATION_ERROR (M09 §3). */
const sinceBeforeUntil = <T extends { since?: string; until?: string }>(data: T) =>
  !data.since ||
  !data.until ||
  data.since === "" ||
  data.until === "" ||
  Date.parse(data.until) >= Date.parse(data.since);

const rangeMessage = "until must not be earlier than since";

// ── firewall log list / export (M09 §3 — same filter set, export has no page) ──

export const firewallLogQuerySchema = z
  .object({
    q: z.string().max(128).optional(),
    action: firewallActionSchema.optional(),
    src: z.string().max(64).optional(),
    dst: z.string().max(64).optional(),
    since: isoOrEmpty.optional(),
    until: isoOrEmpty.optional(),
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(25),
    sort: z.string().max(32).optional(), // only -timestamp supported; ignored otherwise
  })
  .refine(sinceBeforeUntil, { message: rangeMessage, path: ["until"] });

export const firewallExportQuerySchema = z
  .object({
    q: z.string().max(128).optional(),
    action: firewallActionSchema.optional(),
    src: z.string().max(64).optional(),
    dst: z.string().max(64).optional(),
    since: isoOrEmpty.optional(),
    until: isoOrEmpty.optional(),
    sort: z.string().max(32).optional(),
  })
  .refine(sinceBeforeUntil, { message: rangeMessage, path: ["until"] });

// ── IPS events list (M09 §3; severity is a csv of enum values for the multi-chips) ──

export const ipsLogQuerySchema = z
  .object({
    severity: z
      .string()
      .max(64)
      .optional()
      .refine(
        (v) =>
          v === undefined ||
          v === "" ||
          v
            .split(",")
            .map((s) => s.trim())
            .every((s) => (ipsSeveritySchema.options as readonly string[]).includes(s)),
        "unknown severity value",
      ),
    category: z.string().max(64).optional(),
    q: z.string().max(128).optional(),
    since: isoOrEmpty.optional(),
    until: isoOrEmpty.optional(),
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(25),
  })
  .refine(sinceBeforeUntil, { message: rangeMessage, path: ["until"] });

// ── audit log list (M09 §3; user matches username) ─────────────────────────

export const auditLogQuerySchema = z
  .object({
    /** Facets mode — returns { objectTypes } for the filter Select, no rows. */
    facets: z.enum(["objectTypes"]).optional(),
    user: z.string().max(64).optional(),
    objectType: z.string().max(64).optional(),
    result: auditResultSchema.optional(),
    q: z.string().max(128).optional(),
    since: isoOrEmpty.optional(),
    until: isoOrEmpty.optional(),
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(25),
  })
  .refine(sinceBeforeUntil, { message: rangeMessage, path: ["until"] });

// ── stats / report export (M09 §3 — range 1h|24h|7d) ───────────────────────

export const statsRangeSchema = z.enum(["1h", "24h", "7d"]);

export const statsQuerySchema = z.object({
  range: statsRangeSchema.default("24h"),
});

export const reportExportQuerySchema = z.object({
  range: statsRangeSchema.default("24h"),
  format: z.enum(["csv", "json"]).default("csv"),
});

// ── forwarding targets (M09 §4 tab 3) ──────────────────────────────────────

export const syslogTargetCreateSchema = z.object({
  name: z.string().min(1).max(64),
  host: targetHostSchema,
  port: z.coerce.number().int().min(1).max(65535).default(514),
  protocol: syslogProtocolSchema.default("udp"),
  minSeverity: ipsSeveritySchema.default("info"),
  enabled: z.boolean().default(true),
});

/** Partial update — fields WITHOUT defaults so `.partial()` stays truly
 *  optional (zod 4: defaults survive `.partial()` and would clobber missing keys). */
export const syslogTargetUpdateSchema = z
  .object({
    name: z.string().min(1).max(64),
    host: z.string().min(1).max(253),
    port: z.coerce.number().int().min(1).max(65535),
    protocol: syslogProtocolSchema,
    minSeverity: ipsSeveritySchema,
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

export const netflowTargetCreateSchema = z.object({
  name: z.string().min(1).max(64),
  host: targetHostSchema,
  port: z.coerce.number().int().min(1).max(65535).default(2055),
  version: netflowVersionSchema.default("ipfix"),
  samplingRate: z.coerce.number().int().min(1).max(65536).default(100),
  enabled: z.boolean().default(true),
});

export const netflowTargetUpdateSchema = z
  .object({
    name: z.string().min(1).max(64),
    host: z.string().min(1).max(253),
    port: z.coerce.number().int().min(1).max(65535),
    version: netflowVersionSchema,
    samplingRate: z.coerce.number().int().min(1).max(65536),
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── scheduled reports (M09 §4 tab 2; spec §1.12) ───────────────────────────

export const reportSectionsSchema = z.array(z.enum(["traffic", "threats", "audit"])).min(1);

export const reportScheduleCreateSchema = z.object({
  name: z.string().min(1).max(64),
  range: reportRangeSchema.default("daily"),
  format: reportFormatSchema.default("pdf"),
  sections: reportSectionsSchema.default(["traffic", "threats"]),
  recipients: recipientsSchema.optional().nullable(), // comma-separated emails (F-e #16)
  enabled: z.boolean().default(true),
});

/** Partial update without defaults — see syslogTargetUpdateSchema note. */
export const reportScheduleUpdateSchema = z
  .object({
    name: z.string().min(1).max(64),
    range: reportRangeSchema,
    format: reportFormatSchema,
    sections: reportSectionsSchema,
    recipients: recipientsSchema.nullable(),
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── inferred types (server services consume these) ─────────────────────────

export type FirewallLogQuery = z.infer<typeof firewallLogQuerySchema>;
export type FirewallExportQuery = z.infer<typeof firewallExportQuerySchema>;
export type IpsLogQuery = z.infer<typeof ipsLogQuerySchema>;
export type AuditLogQuery = z.infer<typeof auditLogQuerySchema>;
export type StatsRange = z.infer<typeof statsRangeSchema>;
export type SyslogTargetCreate = z.infer<typeof syslogTargetCreateSchema>;
export type SyslogTargetUpdate = z.infer<typeof syslogTargetUpdateSchema>;
export type NetflowTargetCreate = z.infer<typeof netflowTargetCreateSchema>;
export type NetflowTargetUpdate = z.infer<typeof netflowTargetUpdateSchema>;
export type ReportScheduleCreate = z.infer<typeof reportScheduleCreateSchema>;
export type ReportScheduleUpdate = z.infer<typeof reportScheduleUpdateSchema>;
