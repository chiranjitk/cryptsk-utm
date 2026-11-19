/**
 * Incident Response zod schemas (Phase 3 §3.5) — locked enums for the
 * incident workflow (PROJECT_MEMORY §6 style: module-local, no cross-module
 * drift with the IPS/DLP scales). List queries are server-paginated; PATCH
 * is a discriminated union on `kind` (status transition vs assignment) so
 * the route can audit each workflow verb separately.
 */

import { z } from "zod";
import { boundedJson } from "@/lib/validators/bounded";

// ── locked enums (spec §3.5) ────────────────────────────────────────────────

export const incidentSourceSchema = z.enum([
  "manual",
  "ips_event",
  "dlp_incident",
  "dns_tunnel",
  "threat_intel",
  "ai",
]);

export const incidentSeveritySchema = z.enum(["info", "low", "medium", "high", "critical"]);

export const incidentStatusSchema = z.enum(["new", "investigating", "contained", "resolved"]);

// ── list query (GET /api/v1/incidents) ──────────────────────────────────────

export const incidentQuerySchema = z.object({
  status: incidentStatusSchema.optional(),
  severity: incidentSeveritySchema.optional(),
  source: incidentSourceSchema.optional(),
  q: z.string().max(128).optional(),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(25),
});

// ── create (manual shape; `fromAlert` shape adds sourceRef + detail JSON) ───

/** Open JSON detail — {description, srcIps[], tags[], …} per schema.prisma,
 * capped at 16 KB of serialized JSON (audit fix F-d — unbounded payload DoS). */
export const incidentDetailSchema = boundedJson(16384, "incident detail");

export const incidentCreateSchema = z.object({
  title: z.string().min(1).max(200),
  source: incidentSourceSchema.default("manual"),
  /** JSON pointer string to the originating alert — presence switches the
   *  POST into the fromAlert path (dedupe against open incidents). */
  sourceRef: z.string().min(1).max(512).optional().nullable(),
  severity: incidentSeveritySchema.default("medium"),
  assignedTo: z.string().max(64).optional().nullable(),
  detail: incidentDetailSchema.optional(),
});

// ── PATCH /api/v1/incidents/[id] — discriminated on kind ────────────────────

export const incidentPatchSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("status"), status: incidentStatusSchema }),
  z.object({ kind: z.literal("assign"), assignedTo: z.string().max(64).nullable() }),
]);

// ── notes + stats ───────────────────────────────────────────────────────────

export const incidentNoteSchema = z.object({
  note: z.string().min(1).max(2000),
});

// ── inferred types ──────────────────────────────────────────────────────────

export type IncidentSource = z.infer<typeof incidentSourceSchema>;
export type IncidentSeverity = z.infer<typeof incidentSeveritySchema>;
export type IncidentStatus = z.infer<typeof incidentStatusSchema>;
export type IncidentQuery = z.infer<typeof incidentQuerySchema>;
export type IncidentCreate = z.infer<typeof incidentCreateSchema>;
export type IncidentPatch = z.infer<typeof incidentPatchSchema>;
