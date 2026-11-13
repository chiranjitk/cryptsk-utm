/**
 * URL Filtering / Web Security zod schemas (M16, spec 2.3). Enums are
 * module-local (web categories are unique to this milestone) — actions reuse
 * plain string enums. fileTypesBlocked crosses the API as a JSON-friendly
 * string[] (lowercase extensions, ≤20) and is serialized to the DB JSON column
 * by the service. Custom-list `value` is validated per matchType: bare domain,
 * `*.domain` wildcard or absolute http(s) URL.
 */

import { z } from "zod";

// ── enums ───────────────────────────────────────────────────────────────────

export const urlFilterActionSchema = z.enum(["allow", "block"]);
export const categoryRuleActionSchema = z.enum(["allow", "block", "warn"]);
export const listSourceSchema = z.enum(["aggregated", "custom"]);
export const urlCategorySchema = z.enum([
  "gambling",
  "adult",
  "social_media",
  "malware",
  "phishing",
  "p2p",
  "streaming",
  "games",
  "news",
  "shopping",
  "weapons",
  "hate",
  "custom",
]);
export const listTypeSchema = z.enum(["block", "allow"]);
export const matchTypeSchema = z.enum(["domain", "wildcard", "url"]);
export const urlLogActionSchema = z.enum(["allowed", "blocked", "warned"]);

// ── shared value shapes ─────────────────────────────────────────────────────

/** Bare hostname with at least two labels (example.com) — no wildcard, no scheme. */
export const DOMAIN_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,63}$/;

const fileTypeItem = z
  .string()
  .trim()
  .toLowerCase()
  .regex(/^[a-z0-9]{1,10}$/, "must be a short lowercase extension, e.g. exe");

const fileTypeList = z
  .array(fileTypeItem)
  .max(20, "at most 20 file types")
  .refine((arr) => new Set(arr).size === arr.length, { message: "Duplicate file types" });

/** Per-matchType validation of a custom-list value. */
export function valueMatchesMatchType(matchType: string, raw: string): boolean {
  const v = raw.trim().toLowerCase();
  if (matchType === "url") return /^https?:\/\/\S+$/.test(v);
  if (matchType === "wildcard") return v.startsWith("*.") && DOMAIN_RE.test(v.slice(2));
  return DOMAIN_RE.test(v);
}

// ── policies ────────────────────────────────────────────────────────────────

export const policyCreateSchema = z.object({
  name: z.string().trim().min(1).max(64),
  defaultAction: urlFilterActionSchema.default("allow"),
  safeSearchEnforce: z.boolean().default(true),
  fileTypesBlocked: fileTypeList.default([]),
  httpsInspection: z.boolean().default(false),
  transparentProxy: z.boolean().default(true),
  enabled: z.boolean().default(true),
});

/** Partial update WITHOUT defaults (zod 4: defaults survive .partial() and
 *  would clobber missing keys) — see syslogTargetUpdateSchema note. */
export const policyUpdateSchema = z
  .object({
    name: z.string().trim().min(1).max(64),
    defaultAction: urlFilterActionSchema,
    safeSearchEnforce: z.boolean(),
    fileTypesBlocked: fileTypeList,
    httpsInspection: z.boolean(),
    transparentProxy: z.boolean(),
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── category rules (PUT replace-all) ────────────────────────────────────────

export const categoryRulesPutSchema = z
  .object({
    rules: z
      .array(
        z.object({
          category: urlCategorySchema,
          action: categoryRuleActionSchema,
          listSource: listSourceSchema.default("aggregated"),
          enabled: z.boolean(),
        }),
      )
      .min(1)
      .max(13),
  })
  .refine((d) => new Set(d.rules.map((r) => r.category)).size === d.rules.length, {
    message: "Duplicate categories in rule set",
    path: ["rules"],
  });

// ── custom lists ────────────────────────────────────────────────────────────

export const customListQuerySchema = z.object({
  policyId: z.coerce.number().int().positive().optional(),
  listType: listTypeSchema.optional(),
});

export const customListCreateSchema = z
  .object({
    policyId: z.coerce.number().int().positive(),
    listType: listTypeSchema.default("block"),
    matchType: matchTypeSchema.default("domain"),
    value: z.string().trim().min(1).max(253),
    note: z.string().trim().max(256).optional().nullable(),
  })
  .refine((d) => valueMatchesMatchType(d.matchType, d.value), {
    message: "Value does not match the selected match type (domain / *.domain / http(s) URL)",
    path: ["value"],
  });

/** Import-by-paste — server splits lines, infers matchType, skips bad rows. */
export const customListImportSchema = z.object({
  policyId: z.coerce.number().int().positive(),
  listType: listTypeSchema,
  text: z.string().min(1).max(65_536),
});

// ── simulated test (M16 §2.3.4) ─────────────────────────────────────────────

export const urlTestSchema = z.object({
  url: z
    .string()
    .trim()
    .min(1)
    .max(2048)
    .refine((v) => {
      try {
        const u = new URL(v);
        return u.protocol === "http:" || u.protocol === "https:";
      } catch {
        return false;
      }
    }, "must be an absolute http(s) URL"),
});

// ── logs (paged-lite) + stats ───────────────────────────────────────────────

export const urlFilterLogQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(100),
  action: urlLogActionSchema.optional(),
  q: z.string().max(128).optional(),
});

// ── inferred types ──────────────────────────────────────────────────────────

export type PolicyCreate = z.infer<typeof policyCreateSchema>;
export type PolicyUpdate = z.infer<typeof policyUpdateSchema>;
export type CategoryRulesPut = z.infer<typeof categoryRulesPutSchema>;
export type CustomListCreate = z.infer<typeof customListCreateSchema>;
export type CustomListImport = z.infer<typeof customListImportSchema>;
export type UrlTestInput = z.infer<typeof urlTestSchema>;
export type UrlFilterLogQuery = z.infer<typeof urlFilterLogQuerySchema>;
