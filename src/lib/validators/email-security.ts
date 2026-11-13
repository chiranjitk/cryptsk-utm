/**
 * Email Security zod schemas (M22, spec 2.8). Gateways expose a proxy or relay
 * listener (mode=relay requires upstreamHost); the content policy is a
 * per-tenant SINGLETON (GET auto-creates defaults, PUT validates the full
 * form); routing rules match a domain (bare or "@domain", single-label TLDs
 * like "@zip" allowed) to an action with a per-tenant unique priority checked
 * by the service (409). relayDomains/blockedExtensions cross the API as
 * JSON-friendly string arrays and are serialized to the DB JSON columns by
 * the service.
 */

import { z } from "zod";

// ── enums ───────────────────────────────────────────────────────────────────

export const gatewayModeSchema = z.enum(["proxy", "relay"]);
export const tlsModeSchema = z.enum(["none", "starttls", "wrapper"]);
export const dmarcPolicySchema = z.enum(["none", "quarantine", "reject"]);
export const routingActionSchema = z.enum(["deliver", "relay", "reject", "quarantine"]);
export const emailVerdictSchema = z.enum(["delivered", "quarantined", "rejected"]);

// ── shared value shapes ─────────────────────────────────────────────────────

/** Bare domain with at least two labels (corp.example) — no wildcard, no scheme. */
export const DOMAIN_RE =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,63}$/;

/** Routing matchDomain: bare domain, single label or "@label" (partner.com, @zip). */
export const MATCH_DOMAIN_RE =
  /^@?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

/** Minimal RFC-ish email shape — local@domain, no spaces. */
export const EMAIL_ADDR_RE = /^[^\s@]+@[^\s@]+$/;

const relayDomainItem = z
  .string()
  .trim()
  .toLowerCase()
  .regex(DOMAIN_RE, "must be a domain like corp.example");

const relayDomainsList = z
  .array(relayDomainItem)
  .max(50, "at most 50 relay domains")
  .refine((arr) => new Set(arr).size === arr.length, { message: "Duplicate relay domains" });

const blockedExtItem = z
  .string()
  .trim()
  .toLowerCase()
  .regex(/^[a-z0-9]{1,10}$/, "must be a short lowercase extension, e.g. exe");

const blockedExtList = z
  .array(blockedExtItem)
  .max(20, "at most 20 blocked extensions")
  .refine((arr) => new Set(arr).size === arr.length, { message: "Duplicate blocked extensions" });

/** spamThreshold accepts 0–20 in 0.5 steps only. */
const halfStep = (v: number) => Math.abs(v * 2 - Math.round(v * 2)) < 1e-9;

// ── gateways (M22 §2.8.1) ───────────────────────────────────────────────────

export const gatewayCreateSchema = z
  .object({
    name: z.string().trim().min(1).max(64),
    mode: gatewayModeSchema.default("proxy"),
    listenPort: z.coerce.number().int().min(1).max(65535).default(25),
    relayDomains: relayDomainsList.default([]),
    upstreamHost: z.string().trim().max(253).optional().nullable(),
    tlsMode: tlsModeSchema.default("starttls"),
    enabled: z.boolean().default(true),
  })
  .refine((d) => d.mode !== "relay" || (d.upstreamHost?.trim().length ?? 0) > 0, {
    message: "upstreamHost is required when mode is relay",
    path: ["upstreamHost"],
  });

/** Partial update WITHOUT defaults (zod 4: defaults survive .partial() and
 *  would clobber missing keys) — see syslogTargetUpdateSchema note. The
 *  mode=relay → upstreamHost rule is re-checked by the service after merge. */
export const gatewayUpdateSchema = z
  .object({
    name: z.string().trim().min(1).max(64),
    mode: gatewayModeSchema,
    listenPort: z.coerce.number().int().min(1).max(65535),
    relayDomains: relayDomainsList,
    upstreamHost: z.string().trim().max(253).nullable(),
    tlsMode: tlsModeSchema,
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── policy singleton (M22 §2.8.2) ───────────────────────────────────────────

/** Full-object PUT — the policy form always sends every field; defaults mirror
 *  the GET auto-create row so a PUT fully defines singleton state. */
export const policyUpdateSchema = z.object({
  spamThreshold: z.coerce
    .number()
    .min(0)
    .max(20)
    .refine(halfStep, "must be a multiple of 0.5")
    .default(6.0),
  blockPhishing: z.boolean().default(true),
  blockMalware: z.boolean().default(true),
  scanArchives: z.boolean().default(true),
  maxMessageSizeMb: z.coerce.number().int().min(1).max(1024).default(25),
  blockedExtensions: blockedExtList.default(["exe", "js", "vbs", "scr", "bat"]),
  spfVerify: z.boolean().default(true),
  dkimVerify: z.boolean().default(true),
  dmarcPolicy: dmarcPolicySchema.default("quarantine"),
  quarantineRetentionDays: z.coerce.number().int().min(1).max(90).default(14),
  enabled: z.boolean().default(true),
});

// ── routing rules (M22 §2.8.3 — priority uniqueness → 409 in service) ───────

export const routingRuleCreateSchema = z
  .object({
    name: z.string().trim().min(1).max(64),
    matchDomain: z
      .string()
      .trim()
      .toLowerCase()
      .max(253)
      .regex(MATCH_DOMAIN_RE, "must be a domain or @domain (e.g. partner.com, @zip)"),
    action: routingActionSchema.default("relay"),
    targetHost: z.string().trim().max(253).optional().nullable(),
    priority: z.coerce.number().int().min(1).max(100).default(10),
    enabled: z.boolean().default(true),
  })
  .refine((d) => d.action !== "relay" || (d.targetHost?.trim().length ?? 0) > 0, {
    message: "targetHost is required when action is relay",
    path: ["targetHost"],
  });

/** Partial update WITHOUT defaults — relay→targetHost re-checked in service. */
export const routingRuleUpdateSchema = z
  .object({
    name: z.string().trim().min(1).max(64),
    matchDomain: z
      .string()
      .trim()
      .toLowerCase()
      .max(253)
      .regex(MATCH_DOMAIN_RE, "must be a domain or @domain (e.g. partner.com, @zip)"),
    action: routingActionSchema,
    targetHost: z.string().trim().max(253).nullable(),
    priority: z.coerce.number().int().min(1).max(100),
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── simulated test (M22 §2.8.4 — appliance runs real Rspamd+ClamAV) ─────────

const attachmentName = z.string().trim().min(1).max(255);

export const emailTestSchema = z.object({
  from: z
    .string()
    .trim()
    .min(3)
    .max(254)
    .refine((v) => EMAIL_ADDR_RE.test(v), "must be an email address (local@domain)"),
  to: z
    .string()
    .trim()
    .min(3)
    .max(254)
    .refine((v) => EMAIL_ADDR_RE.test(v), "must be an email address (local@domain)"),
  subject: z.string().max(255).optional(),
  body: z.string().max(65_536).optional(),
  attachments: z.array(attachmentName).max(20, "at most 20 attachments").optional(),
  sizeKb: z.coerce.number().int().min(0).max(2_000_000).optional(),
});

// ── mail log list (paged-lite) ──────────────────────────────────────────────

export const emailLogQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(100),
  verdict: emailVerdictSchema.optional(),
  q: z.string().max(128).optional(),
});

// ── inferred types (server service consumes these) ──────────────────────────

export type GatewayMode = z.infer<typeof gatewayModeSchema>;
export type TlsMode = z.infer<typeof tlsModeSchema>;
export type DmarcPolicy = z.infer<typeof dmarcPolicySchema>;
export type RoutingAction = z.infer<typeof routingActionSchema>;
export type EmailVerdict = z.infer<typeof emailVerdictSchema>;
export type GatewayCreate = z.infer<typeof gatewayCreateSchema>;
export type GatewayUpdate = z.infer<typeof gatewayUpdateSchema>;
export type PolicyUpdate = z.infer<typeof policyUpdateSchema>;
export type RoutingRuleCreate = z.infer<typeof routingRuleCreateSchema>;
export type RoutingRuleUpdate = z.infer<typeof routingRuleUpdateSchema>;
export type EmailTestInput = z.infer<typeof emailTestSchema>;
export type EmailLogQuery = z.infer<typeof emailLogQuerySchema>;
