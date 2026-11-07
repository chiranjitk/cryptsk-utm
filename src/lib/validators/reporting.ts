/**
 * M12 — Enhanced Logging & Reporting zod schemas (spec 2.13).
 * Unified log search, saved searches, report runs, compliance templates/runs,
 * anonymization rules + preview, and CEF/LEEF export.
 * `since`/`until` take ISO datetimes and `until < since` is rejected with a
 * 400 VALIDATION_ERROR via `.refine` (same contract as validators/logs.ts).
 */

import { z } from "zod";
import { ipsSeveritySchema } from "./enums";

// ── shared building blocks ──────────────────────────────────────────────────

const isoOrEmpty = z
  .string()
  .refine((v) => v === "" || !Number.isNaN(Date.parse(v)), "must be an ISO timestamp");

/** `?until=` earlier than `?since=` → 400 VALIDATION_ERROR. */
const sinceBeforeUntil = <T extends { since?: string; until?: string }>(data: T) =>
  !data.since ||
  !data.until ||
  data.since === "" ||
  data.until === "" ||
  Date.parse(data.until) >= Date.parse(data.since);

const rangeMessage = "until must not be earlier than since";

// ── canonical value sets (M12) ──────────────────────────────────────────────

export const searchDatasetSchema = z.enum(["firewall", "ips", "audit"]);
export type SearchDataset = z.infer<typeof searchDatasetSchema>;

/** Datasets with anonymizable fields (schema comment: firewall|ips|audit|dns|email|waf). */
export const anonDatasetSchema = z.enum(["firewall", "ips", "audit", "dns", "email", "waf"]);
export const anonymizationStrategySchema = z.enum(["hash", "mask", "pseudonymize"]);
export const frameworkSchema = z.enum(["PCI", "HIPAA", "GDPR", "ISO27001", "SOC2"]);

/** M12 report ranges — extends the M09 enum (no `quarterly`) with quarterly. */
export const reportRangeExtSchema = z.enum(["daily", "weekly", "monthly", "quarterly"]);
export type ReportRangeExt = z.infer<typeof reportRangeExtSchema>;

export const reportSectionSchema = z.enum(["traffic", "threats", "audit"]);
export type ReportSection = z.infer<typeof reportSectionSchema>;

export const reportRunFormatSchema = z.enum(["html", "pdf"]);
export const reportRunSourceSchema = z.enum(["ad-hoc", "schedule", "compliance"]);

// ── unified log search (GET /api/v1/logs/search) ────────────────────────────

export const unifiedSearchQuerySchema = z
  .object({
    dataset: searchDatasetSchema.default("firewall"),
    q: z.string().max(128).optional(),
    /** ips only — single severity value. */
    severity: ipsSeveritySchema.optional(),
    /** firewall: allow|deny|drop|reject · ips: alert|drop|… · audit: substring. */
    action: z.string().max(32).optional(),
    since: isoOrEmpty.optional(),
    until: isoOrEmpty.optional(),
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce
      .number()
      .int()
      .refine((v): v is 10 | 25 | 50 | 100 => v === 10 || v === 25 || v === 50 || v === 100, {
        message: "limit must be one of 10, 25, 50, 100",
      })
      .default(25),
  })
  .refine(sinceBeforeUntil, { message: rangeMessage, path: ["until"] });

export type UnifiedSearchQuery = z.infer<typeof unifiedSearchQuerySchema>;

// ── saved log searches (spec 2.13 — name unique per tenant) ─────────────────

export const savedSearchCreateSchema = z.object({
  name: z.string().min(1).max(64),
  dataset: searchDatasetSchema,
  queryText: z.string().max(128).default(""),
  /** JSON-safe filter bag (severity, action, since, until — string values). */
  filters: z.record(z.string(), z.string()).default({}),
});

export const savedSearchUpdateSchema = z
  .object({
    name: z.string().min(1).max(64),
    dataset: searchDatasetSchema,
    queryText: z.string().max(128),
    filters: z.record(z.string(), z.string()),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

export type SavedSearchCreate = z.infer<typeof savedSearchCreateSchema>;
export type SavedSearchUpdate = z.infer<typeof savedSearchUpdateSchema>;

// ── report runs (GET paged / POST render-now) ───────────────────────────────

export const reportRunListQuerySchema = z.object({
  source: reportRunSourceSchema.optional(),
  status: z.enum(["pending", "running", "done", "failed"]).optional(),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(25),
});

export type ReportRunListQuery = z.infer<typeof reportRunListQuerySchema>;

export const reportRunCreateSchema = z.object({
  name: z.string().min(1).max(96),
  range: reportRangeExtSchema.default("daily"),
  sections: z.array(reportSectionSchema).min(1).default(["traffic", "threats"]),
  format: reportRunFormatSchema.default("pdf"),
});

export type ReportRunCreate = z.infer<typeof reportRunCreateSchema>;

// ── compliance templates (spec 2.13) ────────────────────────────────────────

export const complianceTemplateCreateSchema = z.object({
  name: z.string().min(1).max(96),
  framework: frameworkSchema,
  sections: z.array(reportSectionSchema).min(1).default(["traffic", "threats", "audit"]),
  range: reportRangeExtSchema.default("monthly"),
  enabled: z.boolean().default(true),
});

export const complianceTemplateUpdateSchema = z
  .object({
    name: z.string().min(1).max(96),
    framework: frameworkSchema,
    sections: z.array(reportSectionSchema).min(1),
    range: reportRangeExtSchema,
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

export const complianceRunSchema = z.object({
  templateId: z.coerce.number().int().min(1),
});

export type ComplianceTemplateCreate = z.infer<typeof complianceTemplateCreateSchema>;
export type ComplianceTemplateUpdate = z.infer<typeof complianceTemplateUpdateSchema>;

// ── anonymization rules + preview (spec 2.13) ───────────────────────────────

export const anonymizationRuleCreateSchema = z.object({
  name: z.string().min(1).max(64),
  dataset: anonDatasetSchema,
  /** e.g. source_ip | user_name | url | email. */
  field: z.string().min(1).max(64),
  strategy: anonymizationStrategySchema.default("hash"),
  enabled: z.boolean().default(true),
});

export const anonymizationRuleUpdateSchema = z
  .object({
    name: z.string().min(1).max(64),
    dataset: anonDatasetSchema,
    field: z.string().min(1).max(64),
    strategy: anonymizationStrategySchema,
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

export const anonymizationPreviewQuerySchema = z.object({
  dataset: anonDatasetSchema.default("firewall"),
});

export type AnonymizationRuleCreate = z.infer<typeof anonymizationRuleCreateSchema>;
export type AnonymizationRuleUpdate = z.infer<typeof anonymizationRuleUpdateSchema>;

// ── CEF / LEEF export (spec 2.13 §8) ────────────────────────────────────────

export const logExportQuerySchema = z.object({
  dataset: z.enum(["firewall", "ips"]).default("firewall"),
  format: z.enum(["cef", "leef"]).default("cef"),
  limit: z.coerce.number().int().min(1).max(1000).default(100),
});

export type LogExportQuery = z.infer<typeof logExportQuerySchema>;

// ── inferred types re-exports ───────────────────────────────────────────────

export type Framework = z.infer<typeof frameworkSchema>;
export type AnonymizationStrategy = z.infer<typeof anonymizationStrategySchema>;
