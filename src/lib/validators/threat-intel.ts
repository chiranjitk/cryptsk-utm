/**
 * Threat Intelligence zod schemas (M13 §2.11) — feeds, IOCs, auto-block
 * rules and hit queries. M13 uses its OWN severity scale (info|warning|critical,
 * NOT the IPS info|low|medium|high|critical one) and its own category set, so
 * the enums are module-local instead of shared with validators/enums.ts.
 * List queries are server-paginated; `since`/`expiresAt` accept ISO datetimes
 * or "" (treated as absent by the route layer).
 */

import { z } from "zod";

// ── locked enums (M13 §2.11) ────────────────────────────────────────────────

export const feedProviderSchema = z.enum(["abusech", "otx", "spamhaus", "custom"]);
export const feedFormatSchema = z.enum(["csv", "json", "stix", "taxii"]);
export const threatCategorySchema = z.enum([
  "botnet",
  "malware",
  "phishing",
  "c2",
  "ransomware",
  "scanner",
]);
export const threatSeveritySchema = z.enum(["info", "warning", "critical"]);
export const iocTypeSchema = z.enum(["ip", "cidr", "domain", "url", "hash"]);
export const autoBlockActionSchema = z.enum(["drop", "reject", "quarantine_vlan"]);
export const blockDirectionSchema = z.enum(["in", "out", "both"]);
export const hitActionSchema = z.enum(["allowed", "blocked", "quarantined"]);

const isoOrEmpty = z
  .string()
  .refine((v) => v === "" || !Number.isNaN(Date.parse(v)), "must be an ISO timestamp");

// ── feeds (tab 1) ───────────────────────────────────────────────────────────

export const feedCreateSchema = z.object({
  name: z.string().min(1).max(64),
  provider: feedProviderSchema.default("abusech"),
  url: z.string().min(1).max(512),
  format: feedFormatSchema.default("csv"),
  category: threatCategorySchema.default("botnet"),
  /** Poll interval — 5 minutes .. 1 day. */
  intervalMinutes: z.coerce.number().int().min(5).max(1440).default(60),
  /** Create an AutoBlockRule per NEW critical IOC on each sync. */
  autoBlock: z.boolean().default(false),
  enabled: z.boolean().default(true),
});

/** Partial update without defaults — see validators/logs.ts note (zod 4 keeps
 *  defaults alive through `.partial()`, so field schemas are default-less here). */
export const feedUpdateSchema = z
  .object({
    name: z.string().min(1).max(64),
    provider: feedProviderSchema,
    url: z.string().min(1).max(512),
    format: feedFormatSchema,
    category: threatCategorySchema,
    intervalMinutes: z.coerce.number().int().min(5).max(1440),
    autoBlock: z.boolean(),
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── IOCs (tab 2) ────────────────────────────────────────────────────────────

export const iocQuerySchema = z.object({
  severity: threatSeveritySchema.optional(),
  category: threatCategorySchema.optional(),
  type: iocTypeSchema.optional(),
  q: z.string().max(128).optional(),
  feedId: z.coerce.number().int().positive().optional(),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(25),
});

export const iocCreateSchema = z.object({
  type: iocTypeSchema,
  value: z.string().min(1).max(253),
  category: threatCategorySchema.default("malware"),
  severity: threatSeveritySchema.default("warning"),
  confidence: z.coerce.number().int().min(0).max(100).default(70),
  description: z.string().max(256).optional().nullable(),
  expiresAt: isoOrEmpty.optional().nullable(),
});

/** POST /[id]/disable body — defaults to enabled=false per spec; the console
 *  switch also re-enables by sending { enabled: true }. */
export const iocDisableSchema = z.object({
  enabled: z.boolean().default(false),
});

// ── auto-block rules (tab 3) ────────────────────────────────────────────────

export const autoBlockCreateSchema = z.object({
  name: z.string().min(1).max(64),
  /** Logical IOC reference — optional (manual rules may predate the IOC). */
  iocId: z.coerce.number().int().positive().optional().nullable(),
  matchType: iocTypeSchema,
  matchValue: z.string().min(1).max(253),
  action: autoBlockActionSchema.default("drop"),
  direction: blockDirectionSchema.default("both"),
  enabled: z.boolean().default(true),
});

/** Partial update without defaults (source/createdBy/hitCount are engine-owned). */
export const autoBlockUpdateSchema = z
  .object({
    name: z.string().min(1).max(64),
    iocId: z.coerce.number().int().positive().nullable(),
    matchType: iocTypeSchema,
    matchValue: z.string().min(1).max(253),
    action: autoBlockActionSchema,
    direction: blockDirectionSchema,
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── hits (recent matches feed) ──────────────────────────────────────────────

export const hitsQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(200).default(50),
  since: isoOrEmpty.optional(),
});

// ── inferred types (server routes + client api consume these) ───────────────

export type FeedProvider = z.infer<typeof feedProviderSchema>;
export type FeedFormat = z.infer<typeof feedFormatSchema>;
export type ThreatCategory = z.infer<typeof threatCategorySchema>;
export type ThreatSeverity = z.infer<typeof threatSeveritySchema>;
export type IocType = z.infer<typeof iocTypeSchema>;
export type AutoBlockAction = z.infer<typeof autoBlockActionSchema>;
export type BlockDirection = z.infer<typeof blockDirectionSchema>;
export type FeedCreate = z.infer<typeof feedCreateSchema>;
export type FeedUpdate = z.infer<typeof feedUpdateSchema>;
export type IocQuery = z.infer<typeof iocQuerySchema>;
export type IocCreate = z.infer<typeof iocCreateSchema>;
export type AutoBlockCreate = z.infer<typeof autoBlockCreateSchema>;
export type AutoBlockUpdate = z.infer<typeof autoBlockUpdateSchema>;
export type HitsQuery = z.infer<typeof hitsQuerySchema>;
