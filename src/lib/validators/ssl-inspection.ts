/**
 * SSL/TLS Inspection zod schemas (M15 §2.1) — mirrors validators/logs.ts
 * style. matchValue is validated per matchType: domain = plain hostname,
 * wildcard = `*.x` shape, cidr = IPv4 CIDR. `assertMatchValue` is exported
 * so partial-update routes can re-validate the effective
 * (merged) type/value pair.
 */

import { z } from "zod";
import { ApiError } from "@/lib/api/errors";

// ── locked enums (schema.prisma column comments) ────────────────────────────

export const sslModeSchema = z.enum(["none", "selective", "full"]);
export const hstsHandlingSchema = z.enum(["honor", "bypass"]);
export const certPinningActionSchema = z.enum(["bypass", "block"]);
export const invalidCertActionSchema = z.enum(["block", "warn_bypass"]);
export const minTlsVersionSchema = z.enum(["1.2", "1.3"]);
export const sslMatchTypeSchema = z.enum(["domain", "wildcard", "category", "ip", "cidr"]);
export const sslDecisionSchema = z.enum(["inspected", "bypassed", "blocked"]);

export type SslMode = z.infer<typeof sslModeSchema>;
export type SslMatchType = z.infer<typeof sslMatchTypeSchema>;
export type SslDecision = z.infer<typeof sslDecisionSchema>;

// ── matchValue shape validation (per type) ──────────────────────────────────

/** Plain hostname — labels + TLD, no wildcard (wildcards use matchType wildcard). */
export const HOSTNAME_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
/** `*.x` shape — `*.` + at least one label + TLD. */
export const WILDCARD_RE = /^\*\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
export const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
/** IPv4 CIDR — /0 … /32. */
export const CIDR_RE =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\/(3[0-2]|[12]?\d)$/;
/** Category word — lowercase-ish token (e.g. banking). */
export const CATEGORY_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/i;

/** Returns an error message when the pair is invalid, null when valid. */
export function matchValueError(matchType: SslMatchType, matchValue: string): string | null {
  switch (matchType) {
    case "domain":
      return HOSTNAME_RE.test(matchValue) ? null : "must be a hostname (e.g. example.com)";
    case "wildcard":
      return WILDCARD_RE.test(matchValue) ? null : "must be a wildcard domain (e.g. *.example.com)";
    case "category":
      return CATEGORY_RE.test(matchValue) ? null : "must be a category word (e.g. banking)";
    case "ip":
      return IPV4_RE.test(matchValue) ? null : "must be an IPv4 address (e.g. 10.0.0.5)";
    case "cidr":
      return CIDR_RE.test(matchValue) ? null : "must be an IPv4 CIDR (e.g. 10.0.0.0/8)";
  }
}

/** Throws ApiError(VALIDATION_ERROR) when the type/value pair is invalid. */
export function assertMatchValue(matchType: SslMatchType, matchValue: string): void {
  const msg = matchValueError(matchType, matchValue);
  if (msg) {
    throw ApiError.validation(`matchValue ${msg}`);
  }
}

// ── policy create / update ──────────────────────────────────────────────────

export const sslPolicyCreateSchema = z.object({
  name: z.string().trim().min(1).max(64),
  mode: sslModeSchema.default("selective"),
  signingCaId: z.coerce.number().int().positive().nullish(),
  hstsHandling: hstsHandlingSchema.default("honor"),
  certPinningAction: certPinningActionSchema.default("bypass"),
  invalidCertAction: invalidCertActionSchema.default("block"),
  minTlsVersion: minTlsVersionSchema.default("1.2"),
  enabled: z.boolean().default(true),
});

export type SslPolicyCreate = z.infer<typeof sslPolicyCreateSchema>;

/** Partial update — fields WITHOUT defaults so `.partial()` stays truly
 *  optional (zod 4: defaults survive `.partial()` and would clobber missing keys). */
export const sslPolicyUpdateSchema = z
  .object({
    name: z.string().trim().min(1).max(64),
    mode: sslModeSchema,
    signingCaId: z.coerce.number().int().positive().nullable(),
    hstsHandling: hstsHandlingSchema,
    certPinningAction: certPinningActionSchema,
    invalidCertAction: invalidCertActionSchema,
    minTlsVersion: minTlsVersionSchema,
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

export type SslPolicyUpdate = z.infer<typeof sslPolicyUpdateSchema>;

// ── bypass rules ────────────────────────────────────────────────────────────

export const sslBypassRuleCreateSchema = z
  .object({
    policyId: z.coerce.number().int().positive().optional(),
    matchType: sslMatchTypeSchema.default("domain"),
    matchValue: z.string().trim().min(1).max(253),
    reason: z.string().trim().max(128).nullish(),
    enabled: z.boolean().default(true),
  })
  .refine((v) => matchValueError(v.matchType, v.matchValue) === null, {
    message: "matchValue does not match the selected type",
    path: ["matchValue"],
  });

export type SslBypassRuleCreate = z.infer<typeof sslBypassRuleCreateSchema>;

export const sslBypassRuleUpdateSchema = z
  .object({
    policyId: z.coerce.number().int().positive(),
    matchType: sslMatchTypeSchema,
    matchValue: z.string().trim().min(1).max(253),
    reason: z.string().trim().max(128).nullable(),
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

export type SslBypassRuleUpdate = z.infer<typeof sslBypassRuleUpdateSchema>;

export const sslBypassRuleQuerySchema = z.object({
  policyId: z.coerce.number().int().positive().optional(),
});

export type SslBypassRuleQuery = z.infer<typeof sslBypassRuleQuerySchema>;

// ── simulated connection test ───────────────────────────────────────────────

export const sslTestSchema = z.object({
  sni: z
    .string()
    .trim()
    .min(1, "SNI is required")
    .max(253)
    .refine((v) => HOSTNAME_RE.test(v), "must be a hostname (e.g. www.example.com)"),
});

export type SslTestInput = z.infer<typeof sslTestSchema>;

// ── inspection logs (paged-lite) ────────────────────────────────────────────

export const sslLogQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(100),
  decision: sslDecisionSchema.optional(),
  q: z.string().max(128).optional(),
});

export type SslLogQuery = z.infer<typeof sslLogQuerySchema>;
