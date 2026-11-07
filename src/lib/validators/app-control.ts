/**
 * Application Control zod schemas (M18, spec 2.2). Enums are module-local —
 * the app-control actions (allow|block|limit), the policy unknown-app action
 * (allow|block|log) and traffic direction are unique to this milestone.
 * `userGroupIds` crosses the API as a JSON number array (empty = all groups)
 * and is validated against the tenant's groups in the service layer.
 * bandwidthLimitMbps is required when action=limit (1–10000) and must be
 * null/absent otherwise.
 */

import { z } from "zod";

// ── enums ───────────────────────────────────────────────────────────────────

/** Policy default action (M18 §2.2.1). */
export const policyActionSchema = z.enum(["allow", "block"]);

/** What happens to apps with no matching rule and no catalog entry. */
export const unknownAppActionSchema = z.enum(["allow", "block", "log"]);

/** Per-app rule action — `limit` requires bandwidthLimitMbps. */
export const ruleActionSchema = z.enum(["allow", "block", "limit"]);

export const directionSchema = z.enum(["both", "upload", "download"]);

/** Log decision enum (AppControlLog.action). */
export const appLogActionSchema = z.enum(["allowed", "blocked", "limited"]);

/** nDPI-style categories (locked — mirrors catalog.ts). */
export const appCategorySchema = z.enum([
  "media",
  "collaboration",
  "remote",
  "filesharing",
  "social",
  "gaming",
  "devops",
]);

// ── shared shapes ───────────────────────────────────────────────────────────

/** nDPI label — lowercase identifier, catalog membership checked in the service. */
export const appNameSchema = z
  .string()
  .trim()
  .toLowerCase()
  .min(1)
  .max(64)
  .regex(/^[a-z0-9][a-z0-9-]*$/, "must be an nDPI-style label, e.g. youtube or docker-registry");

export const userGroupIdsSchema = z
  .array(z.coerce.number().int().min(1))
  .max(50, "at most 50 groups")
  .refine((arr) => new Set(arr).size === arr.length, { message: "Duplicate group ids" });

const bandwidth = z.coerce.number().int().min(1).max(10000, "bandwidth limit must be 1–10000 Mbps");

// ── policies (M18 §2.2.1) ───────────────────────────────────────────────────

export const policyCreateSchema = z.object({
  name: z.string().trim().min(1).max(64),
  defaultAction: policyActionSchema.default("allow"),
  unknownAppAction: unknownAppActionSchema.default("log"),
  enabled: z.boolean().default(true),
});

/** Partial update WITHOUT defaults (zod 4: defaults survive .partial() and
 *  would clobber missing keys) — see syslogTargetUpdateSchema note. */
export const policyUpdateSchema = z
  .object({
    name: z.string().trim().min(1).max(64),
    defaultAction: policyActionSchema,
    unknownAppAction: unknownAppActionSchema,
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── rules (M18 §2.2.2) ──────────────────────────────────────────────────────

const bandwidthPairing = (action: RuleAction, bw: number | null | undefined) => {
  if (action === "limit") return typeof bw === "number";
  return bw === undefined || bw === null;
};

export const ruleCreateSchema = z
  .object({
    appName: appNameSchema,
    /** Optional — defaults to the catalog category of appName in the service. */
    category: appCategorySchema.optional(),
    action: ruleActionSchema.default("block"),
    bandwidthLimitMbps: bandwidth.nullish(),
    direction: directionSchema.default("both"),
    userGroupIds: userGroupIdsSchema.default([]),
    enabled: z.boolean().default(true),
  })
  .refine((v) => bandwidthPairing(v.action, v.bandwidthLimitMbps), {
    message: "bandwidthLimitMbps (1–10000) is required when action=limit, and only allowed then",
    path: ["bandwidthLimitMbps"],
  });

/** Partial update without defaults — bandwidth pairing validated only when
 *  `action` is present (a bare bandwidth tweak on an existing limit is fine). */
export const ruleUpdateSchema = z
  .object({
    appName: appNameSchema,
    category: appCategorySchema,
    action: ruleActionSchema,
    bandwidthLimitMbps: bandwidth.nullish(),
    direction: directionSchema,
    userGroupIds: userGroupIdsSchema,
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" })
  .refine((v) => v.action === undefined || bandwidthPairing(v.action, v.bandwidthLimitMbps), {
    message: "bandwidthLimitMbps (1–10000) is required when action=limit, and only allowed then",
    path: ["bandwidthLimitMbps"],
  });

// ── simulated test (M18 §2.2.4) ─────────────────────────────────────────────

export const appTestSchema = z.object({
  appName: appNameSchema,
  clientIp: z.string().trim().max(64).optional(),
  direction: directionSchema.default("both"),
});

// ── logs list (M18 §2.2.5 — paged-lite) ─────────────────────────────────────

export const appControlLogQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(500).default(100),
  appName: appNameSchema.optional(),
  action: appLogActionSchema.optional(),
});

// ── inferred types (server services consume these) ─────────────────────────

export type PolicyAction = z.infer<typeof policyActionSchema>;
export type UnknownAppAction = z.infer<typeof unknownAppActionSchema>;
export type RuleAction = z.infer<typeof ruleActionSchema>;
export type Direction = z.infer<typeof directionSchema>;
export type AppLogAction = z.infer<typeof appLogActionSchema>;
export type AppCategory = z.infer<typeof appCategorySchema>;
export type PolicyCreate = z.infer<typeof policyCreateSchema>;
export type PolicyUpdate = z.infer<typeof policyUpdateSchema>;
export type RuleCreate = z.infer<typeof ruleCreateSchema>;
export type RuleUpdate = z.infer<typeof ruleUpdateSchema>;
export type AppTestInput = z.infer<typeof appTestSchema>;
export type AppControlLogQuery = z.infer<typeof appControlLogQuerySchema>;
