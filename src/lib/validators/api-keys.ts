/**
 * API Platform validators (M11) — per M11-API-PLATFORM.md §5.1/§5.6 + SCHEMA.md §4.
 * zod is the single source of allowed values at the edge (API_STANDARDS §3);
 * the LOCKED scope arrays and the webhooks.events enum (PROJECT_MEMORY §6 via
 * validators/enums.ts) are enforced exactly here.
 *
 * Cross-field / DB-dependent checks (prefix/hashedKey derivation, duplicate
 * webhook name) live in lib/api-keys/service.ts and throw ApiError.
 */

import { z } from "zod";
import { webhookEventsSchema } from "./enums";

// ── API keys (M11 §5.1) ─────────────────────────────────────────────────────

/** The three LOCKED scope arrays (SCHEMA §4 / M11 §3.1) — nothing else is accepted. */
export const API_KEY_SCOPE_SETS = [
  ["read"],
  ["read", "write"],
  ["read", "write", "admin"],
] as const;

export const apiKeyScopesSchema = z
  .array(z.enum(["read", "write", "admin"]))
  .refine(
    (v) =>
      API_KEY_SCOPE_SETS.some((s) => s.length === v.length && s.every((x, i) => v[i] === x)),
    {
      message: 'scopes must be exactly one of ["read"] | ["read","write"] | ["read","write","admin"]',
    },
  );

/** Accepts ISO-8601 (UTC) and datetime-local ("2027-01-31T00:00") values; must be in the future. */
const futureDatetime = z
  .string()
  .refine((v) => !Number.isNaN(new Date(v).getTime()), "Must be an ISO-8601 datetime")
  .refine((v) => new Date(v).getTime() > Date.now(), "Expiry must be in the future");

export const apiKeyCreateSchema = z.object({
  name: z.string().trim().min(1, "Name is required").max(64, "Name must be ≤ 64 chars"),
  scopes: apiKeyScopesSchema,
  expiresAt: z.preprocess(
    (v) => (v === "" || v === null ? undefined : v),
    futureDatetime.optional(),
  ),
});

export type ApiKeyCreate = z.infer<typeof apiKeyCreateSchema>;

// ── Webhooks (M11 §5.6) ─────────────────────────────────────────────────────

/** https-only absolute URL (zod URL grammar + explicit scheme check). */
export const webhookUrlSchema = z
  .string()
  .trim()
  .min(1, "URL is required")
  .max(2048, "URL must be ≤ 2048 chars")
  .url("Must be an absolute URL")
  .startsWith("https://", "URL must use https (webhook endpoints are TLS-only)");

const webhookSecretSchema = z
  .string()
  .min(16, "Secret must be 16-128 chars")
  .max(128, "Secret must be 16-128 chars");

export const webhookCreateSchema = z.object({
  name: z.string().trim().min(1, "Name is required").max(64, "Name must be ≤ 64 chars"),
  url: webhookUrlSchema,
  events: z
    .array(webhookEventsSchema)
    .min(1, "Select at least one event (alerts.new, config.updated, wan.status, vpn.status, sessions.update)"),
  secret: webhookSecretSchema.optional(),
  enabled: z.boolean().default(true),
});

/** Omit `secret` (or send "") to keep the stored value — never set it to empty. */
export const webhookUpdateSchema = z.object({
  name: z.string().trim().min(1, "Name is required").max(64, "Name must be ≤ 64 chars").optional(),
  url: webhookUrlSchema.optional(),
  events: z.array(webhookEventsSchema).min(1, "Select at least one event").optional(),
  secret: webhookSecretSchema.optional(),
  enabled: z.boolean().optional(),
});

export type WebhookCreate = z.infer<typeof webhookCreateSchema>;
export type WebhookUpdate = z.infer<typeof webhookUpdateSchema>;
export type WebhookEvent = z.infer<typeof webhookEventsSchema>;
