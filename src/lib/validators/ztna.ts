/**
 * ZTNA validators (Phase 4 §4.4) — applications, access policies, posture
 * profiles, posture checks and the access-evaluate body. zod is the single
 * source of allowed values at the edge (API_STANDARDS §3); the enums mirror
 * the ztna_* / posture_* columns in schema.prisma (Phase 4 block).
 *
 * Format-level grammar lives here (zod). Cross-field / DB-dependent checks
 * (appId/postureProfileId existence in-tenant, name uniqueness) live in
 * lib/ztna/service.ts and throw ApiError.
 */

import { z } from "zod";

// ── locked enums (schema.prisma Phase 4 ztna_* comments) ─────────────────────

export const ztnaProtocolSchema = z.enum(["tcp", "udp"]);
export const ztnaSubjectTypeSchema = z.enum(["user", "group", "device"]);
export const ztnaActionSchema = z.enum(["allow", "deny"]);
export const postureResultSchema = z.enum(["pass", "fail", "unknown"]);

// ── primitive grammars ───────────────────────────────────────────────────────

const nonEmpty = (label: string, max: number) =>
  z.string().trim().min(1, `${label} is required`).max(max, `${label} must be ≤ ${max} chars`);

// ── applications ─────────────────────────────────────────────────────────────

export const ztnaAppCreateSchema = z.object({
  name: nonEmpty("Application name", 64),
  /** hostname or IP of the protected resource */
  host: nonEmpty("Host", 253),
  port: z.coerce.number().int().min(1).max(65535).default(443),
  protocol: ztnaProtocolSchema.default("tcp"),
  /** business group label (empty = ungrouped) */
  group: z.string().trim().max(64).default(""),
});

export const ztnaAppUpdateSchema = z
  .object({
    name: nonEmpty("Application name", 64),
    host: nonEmpty("Host", 253),
    port: z.coerce.number().int().min(1).max(65535),
    protocol: ztnaProtocolSchema,
    group: z.string().trim().max(64),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── access policies ──────────────────────────────────────────────────────────

export const ztnaPolicyCreateSchema = z.object({
  /** logical ref → ztna_applications — existence validated in the service */
  appId: z.coerce.number().int().positive(),
  subjectType: ztnaSubjectTypeSchema.default("user"),
  /** username | group name | device id (MAC or agent id), per subjectType */
  subjectRef: nonEmpty("Subject", 128),
  action: ztnaActionSchema.default("allow"),
  /** logical ref → posture_profiles — empty = no posture gate on this policy */
  postureProfileId: z.coerce.number().int().positive().nullable().optional(),
  /** "Mon-Fri 09:00-17:00" style label; empty = always (displayed, not clock-evaluated) */
  schedule: z.string().trim().max(64).default(""),
  enabled: z.boolean().default(true),
});

export const ztnaPolicyUpdateSchema = z
  .object({
    appId: z.coerce.number().int().positive(),
    subjectType: ztnaSubjectTypeSchema,
    subjectRef: nonEmpty("Subject", 128),
    action: ztnaActionSchema,
    postureProfileId: z.coerce.number().int().positive().nullable(),
    schedule: z.string().trim().max(64),
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

/** GET /api/v1/ztna/policies?appId= — filterable by app. */
export const ztnaPolicyQuerySchema = z.object({
  appId: z.coerce.number().int().positive().optional(),
});

// ── posture profiles ─────────────────────────────────────────────────────────

/**
 * Requirement set — JSON stored on posture_profiles.checks. A check is
 * REQUIRED when its flag is true (av/diskEncrypt/firewall) or when
 * osPatchMaxAgeDays is a positive day ceiling; absent flags require nothing.
 */
export const postureChecksSchema = z.object({
  osPatchMaxAgeDays: z.coerce.number().int().min(1).max(365).optional(),
  avRequired: z.boolean().optional(),
  diskEncryptRequired: z.boolean().optional(),
  firewallRequired: z.boolean().optional(),
});

export const postureProfileCreateSchema = z.object({
  name: nonEmpty("Profile name", 64),
  checks: postureChecksSchema.default({}),
});

export const postureProfileUpdateSchema = z
  .object({
    name: nonEmpty("Profile name", 64),
    checks: postureChecksSchema,
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── posture checks (continuous validation snapshots) ─────────────────────────

/** POST /api/v1/ztna/posture-checks — record a manual/agent check. */
export const postureCheckCreateSchema = z.object({
  /** MAC or agent id */
  deviceId: nonEmpty("Device id", 128),
  profileId: z.coerce.number().int().positive(),
  /** per-check {check: pass|fail|unknown} — keys ⊆ CHECK_KEYS (validated in the service), missing → unknown */
  results: z.record(z.string(), postureResultSchema).default({}),
});

/** GET /api/v1/ztna/posture-checks — latest check per device, paged. */
export const postureCheckQuerySchema = z.object({
  deviceId: z.string().trim().max(128).optional(),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(25),
});

// ── access evaluation (user-to-resource simulation / enforcement point) ─────

export const ztnaEvaluateSchema = z.object({
  appId: z.coerce.number().int().positive(),
  subject: z.object({
    user: z.string().trim().max(128).optional(),
    groups: z.array(z.string().trim().min(1).max(128)).max(64).default([]),
    deviceId: z.string().trim().max(128).optional(),
  }),
});

// ── inferred types ───────────────────────────────────────────────────────────

export type ZtnaProtocol = z.infer<typeof ztnaProtocolSchema>;
export type ZtnaSubjectType = z.infer<typeof ztnaSubjectTypeSchema>;
export type ZtnaAction = z.infer<typeof ztnaActionSchema>;
export type ZtnaAppCreate = z.infer<typeof ztnaAppCreateSchema>;
export type ZtnaAppUpdate = z.infer<typeof ztnaAppUpdateSchema>;
export type ZtnaPolicyCreate = z.infer<typeof ztnaPolicyCreateSchema>;
export type ZtnaPolicyUpdate = z.infer<typeof ztnaPolicyUpdateSchema>;
export type ZtnaPolicyQuery = z.infer<typeof ztnaPolicyQuerySchema>;
export type PostureChecksInput = z.infer<typeof postureChecksSchema>;
export type PostureProfileCreate = z.infer<typeof postureProfileCreateSchema>;
export type PostureProfileUpdate = z.infer<typeof postureProfileUpdateSchema>;
export type PostureCheckCreate = z.infer<typeof postureCheckCreateSchema>;
export type PostureCheckQuery = z.infer<typeof postureCheckQuerySchema>;
export type ZtnaEvaluateInput = z.infer<typeof ztnaEvaluateSchema>;

/**
 * Service-caller inputs (z.input) — schema defaults stay optional so tests,
 * the engine and webhooks may omit them (same split as lib/incidents).
 * Routes pass the zod-PARSED output, which is assignable to these.
 */
export type ZtnaAppInput = z.input<typeof ztnaAppCreateSchema>;
export type ZtnaPolicyInput = z.input<typeof ztnaPolicyCreateSchema>;
export type PostureProfileInput = z.input<typeof postureProfileCreateSchema>;
export type PostureCheckInput = z.input<typeof postureCheckCreateSchema>;
export type ZtnaEvaluateBody = z.input<typeof ztnaEvaluateSchema>;
