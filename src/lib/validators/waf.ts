/**
 * WAF zod schemas (M17 §2.4) — vhosts, policies, exclusions and the
 * simulated CRS test-request body. `area` is "waf" for every route that
 * consumes these. Follows the validators/logs.ts conventions: create schemas
 * carry defaults, update schemas are default-free objects passed through
 * `.partial()` (zod 4: defaults survive `.partial()` and would clobber
 * missing keys), so PATCH-style updates only see the fields actually sent.
 */

import { z } from "zod";

// ── primitives ──────────────────────────────────────────────────────────────

/** Strict FQDN: 1–253 chars, dot-separated labels of [a-z0-9-], no
 *  leading/trailing hyphen per label, at least one dot (TLD ≥ 2 chars). */
const FQDN_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i;
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

export const fqdnSchema = z
  .string()
  .max(253)
  .refine((v) => FQDN_RE.test(v), "must be a fully-qualified domain name (e.g. shop.corp.example)");

/** Backend host accepts an FQDN or an IPv4 literal (upstream target). */
export const backendHostSchema = z
  .string()
  .min(1)
  .max(253)
  .refine((v) => FQDN_RE.test(v) || IPV4_RE.test(v), "must be an FQDN or IPv4 address");

/** Two-letter uppercase ISO 3166-1 alpha-2 country code. */
export const isoCountrySchema = z
  .string()
  .length(2)
  .regex(/^[A-Z]{2}$/, "must be a 2-letter uppercase ISO code (e.g. CN)");

export const geoCountriesSchema = z
  .array(isoCountrySchema)
  .max(128, "too many country codes")
  .refine((codes) => new Set(codes).size === codes.length, "duplicate country codes");

export const wafModeSchema = z.enum(["reverse_proxy", "waf"]);
export const crsVersionSchema = z.enum(["3.3", "4.0"]);
export const exclusionScopeSchema = z.enum(["rule_id", "param", "url"]);
export const wafActionSchema = z.enum(["pass", "log", "block"]);
export const testMethodSchema = z.enum(["GET", "POST", "PUT", "DELETE"]);

// ── vhosts (M17 §2.4.1) ─────────────────────────────────────────────────────

export const vhostCreateSchema = z.object({
  name: z.string().trim().min(1).max(64),
  hostname: fqdnSchema,
  backendHost: backendHostSchema,
  backendPort: z.coerce.number().int().min(1).max(65535).default(8080),
  listenPort: z.coerce.number().int().min(1).max(65535).default(443),
  tls: z.boolean().default(true),
  /** Logical ref → certificates; validated (exists + active + issuedFor waf|general) in the route. */
  certId: z.number().int().positive().nullish(),
  mode: wafModeSchema.default("waf"),
  enabled: z.boolean().default(true),
});

export const vhostUpdateSchema = z
  .object({
    name: z.string().trim().min(1).max(64),
    hostname: fqdnSchema,
    backendHost: backendHostSchema,
    backendPort: z.coerce.number().int().min(1).max(65535),
    listenPort: z.coerce.number().int().min(1).max(65535),
    tls: z.boolean(),
    certId: z.number().int().positive().nullish(),
    mode: wafModeSchema,
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── policies (M17 §2.4.2) ───────────────────────────────────────────────────

export const policyCreateSchema = z.object({
  name: z.string().trim().min(1).max(64),
  vhostId: z.coerce.number().int().positive(),
  owaspCrsEnabled: z.boolean().default(true),
  crsVersion: crsVersionSchema.default("4.0"),
  paranoiaLevel: z.coerce.number().int().min(1).max(3).default(1),
  anomalyInThreshold: z.coerce.number().int().min(1).max(50).default(5),
  anomalyOutThreshold: z.coerce.number().int().min(1).max(50).default(4),
  learningMode: z.boolean().default(false),
  geoBlockCountries: geoCountriesSchema.default([]),
  rateLimitRpm: z.number().int().min(10).max(10000).nullish(),
  rateLimitBurst: z.number().int().min(1).max(10000).nullish(),
  apiProtection: z.boolean().default(false),
  enabled: z.boolean().default(true),
});

export const policyUpdateSchema = z
  .object({
    name: z.string().trim().min(1).max(64),
    vhostId: z.coerce.number().int().positive(),
    owaspCrsEnabled: z.boolean(),
    crsVersion: crsVersionSchema,
    paranoiaLevel: z.coerce.number().int().min(1).max(3),
    anomalyInThreshold: z.coerce.number().int().min(1).max(50),
    anomalyOutThreshold: z.coerce.number().int().min(1).max(50),
    learningMode: z.boolean(),
    geoBlockCountries: geoCountriesSchema,
    rateLimitRpm: z.number().int().min(10).max(10000).nullish(),
    rateLimitBurst: z.number().int().min(1).max(10000).nullish(),
    apiProtection: z.boolean(),
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── exclusions (M17 §2.4.3) ─────────────────────────────────────────────────

export const exclusionCreateSchema = z.object({
  scope: exclusionScopeSchema,
  /** rule_id → "942100", param → "arg:password", url → "/api/login". */
  matchValue: z.string().trim().min(1).max(256),
  ruleId: z.number().int().positive().nullish(),
  note: z.string().trim().max(256).nullish(),
  enabled: z.boolean().default(true),
});

export const exclusionUpdateSchema = z
  .object({
    scope: exclusionScopeSchema,
    matchValue: z.string().trim().min(1).max(256),
    ruleId: z.number().int().positive().nullish(),
    note: z.string().trim().max(256).nullish(),
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── simulated CRS test request (M17 §2.4.4) ─────────────────────────────────

export const wafTestSchema = z.object({
  method: testMethodSchema,
  url: z.string().min(1).max(2048),
  payload: z.string().max(4096).optional().default(""),
});

// ── log list (M17 §2.4.5 — paged-lite: ?vhostId?&action?&limit=100) ─────────

export const wafLogQuerySchema = z.object({
  vhostId: z.coerce.number().int().positive().optional(),
  action: wafActionSchema.optional(),
  limit: z.coerce.number().int().min(1).max(500).default(100),
});

// ── inferred types (routes consume these) ───────────────────────────────────

export type VhostCreate = z.infer<typeof vhostCreateSchema>;
export type VhostUpdate = z.infer<typeof vhostUpdateSchema>;
export type PolicyCreate = z.infer<typeof policyCreateSchema>;
export type PolicyUpdate = z.infer<typeof policyUpdateSchema>;
export type ExclusionCreate = z.infer<typeof exclusionCreateSchema>;
export type ExclusionUpdate = z.infer<typeof exclusionUpdateSchema>;
export type WafTestInput = z.infer<typeof wafTestSchema>;
export type WafLogQuery = z.infer<typeof wafLogQuerySchema>;
