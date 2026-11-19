/**
 * Multi-Site Central Manager zod schemas (Phase 4 §4.1) — locked enums for the
 * site fleet (PROJECT_MEMORY §6 style: module-local, mirrors the incidents
 * validator). List queries are server-paginated; the push body cross-checks
 * its kind-specific fields via superRefine (template push needs templateId,
 * firmware push needs firmwareVersion) so the route rejects malformed pushes
 * before the service layer is reached.
 */

import { z } from "zod";
import { boundedJson } from "@/lib/validators/bounded";

// ── locked enums (schema.prisma comments + spec §4.1) ───────────────────────

export const siteRoleSchema = z.enum(["hub", "spoke", "standalone"]);

export const siteStatusSchema = z.enum(["online", "offline", "degraded", "never_seen"]);

export const deploymentKindSchema = z.enum(["policy", "template", "firmware"]);

export const deploymentStatusSchema = z.enum(["pending", "pushing", "applied", "failed"]);

export const firmwareChannelSchema = z.enum(["stable", "beta"]);

// ── site list query (GET /api/v1/sites) ─────────────────────────────────────

export const siteQuerySchema = z.object({
  status: siteStatusSchema.optional(),
  role: siteRoleSchema.optional(),
  q: z.string().max(128).optional(),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(25),
});

// ── site create / update ────────────────────────────────────────────────────

/** host:port of the site console — empty until the site reports it. */
const endpointSchema = z
  .string()
  .max(254)
  .refine((v) => v === "" || /^[A-Za-z0-9._-]+:\d{1,5}$/.test(v), "publicEndpoint must look like host:port (e.g. hq.corp.example:8443)");

/** Per-site resource caps — open JSON {maxRules,maxCpuPct,maxTunnelCount,…}
 * capped at 4 KB of serialized JSON (audit fix F-d — unbounded payload DoS). */
export const siteLimitsSchema = boundedJson(4096, "resourceLimits");

export const siteCreateSchema = z.object({
  name: z.string().trim().min(1).max(100),
  region: z.string().max(64).default(""),
  role: siteRoleSchema.default("standalone"),
  publicEndpoint: endpointSchema.default(""),
  version: z.string().max(64).default(""),
  status: siteStatusSchema.default("never_seen"),
  resourceLimits: siteLimitsSchema.optional(),
  notes: z.string().max(2000).default(""),
});

export const siteUpdateSchema = z
  .object({
    name: z.string().trim().min(1).max(100).optional(),
    region: z.string().max(64).optional(),
    role: siteRoleSchema.optional(),
    publicEndpoint: endpointSchema.optional(),
    version: z.string().max(64).optional(),
    status: siteStatusSchema.optional(),
    resourceLimits: siteLimitsSchema.optional(),
    notes: z.string().max(2000).optional(),
  })
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── push (POST /api/v1/sites/[id]/push) ─────────────────────────────────────

/**
 * Push a bundle to a remote site. `kind` picks the transport payload:
 *   policy   → free-form `payload` JSON (optional),
 *   template → requires `templateId` (the template bundle is sent),
 *   firmware → requires `firmwareVersion` (must exist in the catalog).
 */
export const sitePushSchema = z
  .object({
    kind: deploymentKindSchema,
    templateId: z.coerce.number().int().min(1).optional(),
    firmwareVersion: z.string().min(1).max(64).optional(),
    /** free-form policy bundle — capped at 256 KB of JSON (audit fix F-d) */
    payload: boundedJson(262144).optional(),
  })
  .superRefine((v, ctx) => {
    if (v.kind === "template" && v.templateId === undefined) {
      ctx.addIssue({ code: "custom", path: ["templateId"], message: "template pushes require templateId" });
    }
    if (v.kind === "firmware" && v.firmwareVersion === undefined) {
      ctx.addIssue({ code: "custom", path: ["firmwareVersion"], message: "firmware pushes require firmwareVersion" });
    }
  });

// ── deployments list query (GET /api/v1/sites/deployments) ──────────────────

export const deploymentQuerySchema = z.object({
  siteId: z.coerce.number().int().min(1).optional(),
  kind: deploymentKindSchema.optional(),
  status: deploymentStatusSchema.optional(),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(25),
});

// ── site templates ──────────────────────────────────────────────────────────

/** Open config bundle — {firewallRules[], natRules[], dnsPolicies[], …}
 * capped at 256 KB of serialized JSON (audit fix F-d — unbounded payload DoS). */
export const templatePayloadSchema = boundedJson(262144, "template payload");

export const templateCreateSchema = z.object({
  name: z.string().trim().min(1).max(100),
  description: z.string().max(500).default(""),
  version: z.string().max(32).default("1"),
  payload: templatePayloadSchema.default({}),
});

export const templateUpdateSchema = z
  .object({
    name: z.string().trim().min(1).max(100).optional(),
    description: z.string().max(500).optional(),
    version: z.string().max(32).optional(),
    payload: templatePayloadSchema.optional(),
  })
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── firmware catalog ────────────────────────────────────────────────────────

/** sha256 hex digest of the release image — exactly 64 hex chars. */
export const sha256Schema = z
  .string()
  .regex(/^[0-9a-fA-F]{64}$/, "sha256 must be exactly 64 hex characters");

export const firmwareCreateSchema = z.object({
  version: z.string().trim().min(1).max(64),
  channel: firmwareChannelSchema.default("stable"),
  sha256: sha256Schema,
  releaseNotes: z.string().max(5000).default(""),
});

// ── inferred types ──────────────────────────────────────────────────────────

export type SiteRole = z.infer<typeof siteRoleSchema>;
export type SiteStatus = z.infer<typeof siteStatusSchema>;
export type DeploymentKind = z.infer<typeof deploymentKindSchema>;
export type DeploymentStatus = z.infer<typeof deploymentStatusSchema>;
export type FirmwareChannel = z.infer<typeof firmwareChannelSchema>;
export type SiteQuery = z.infer<typeof siteQuerySchema>;
export type SiteCreate = z.infer<typeof siteCreateSchema>;
export type SiteUpdate = z.infer<typeof siteUpdateSchema>;
export type SitePush = z.infer<typeof sitePushSchema>;
export type DeploymentQuery = z.infer<typeof deploymentQuerySchema>;
export type TemplateCreate = z.infer<typeof templateCreateSchema>;
export type TemplateUpdate = z.infer<typeof templateUpdateSchema>;
export type FirmwareCreate = z.infer<typeof firmwareCreateSchema>;
