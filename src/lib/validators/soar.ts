/**
 * SOAR validators (Phase 4 §4.6) — playbook CRUD, the ordered action list
 * (z.discriminatedUnion on `kind` so each action validates its own param
 * grammar) and the manual-fire body. zod is the single source of allowed
 * values at the API edge (API_STANDARDS §3); enums mirror the soar_*
 * column comments in SCHEMA §4.6.
 *
 * The same grammar is re-checked at RUN time by lib/soar/engine.ts
 * (evaluateActions — pure, no zod) because stored rows can predate a validator
 * change; drift between the two is covered by tests/soar-engine.test.ts.
 *
 * Vocabulary is module-local (PROJECT_MEMORY §6 style — no cross-module drift
 * with the incidents/dlp scales).
 */

import { z } from "zod";

// ── locked enums (SCHEMA soar_playbooks column comments / SPEC §4.6) ────────

export const soarTriggerKindSchema = z.enum([
  "incident_created",
  "incident_severity",
  "dlp_incident",
  "dns_tunnel",
  "ioc_hit",
]);

export const soarActionKindSchema = z.enum(["block_ip", "notify", "create_incident", "delay", "webhook"]);

export const soarSeveritySchema = z.enum(["info", "low", "medium", "high", "critical"]);

export const soarSourceSchema = z.enum(["manual", "ips_event", "dlp_incident", "dns_tunnel", "threat_intel", "ai"]);

export const soarRunStatusSchema = z.enum(["running", "success", "failed", "skipped"]);

// ── primitive grammars ──────────────────────────────────────────────────────

const nonEmpty = (label: string, max: number) =>
  z.string().trim().min(1, `${label} is required`).max(max, `${label} must be ≤ ${max} chars`);

/** IPv4 grammar shared with the engine + incidents blockSource semantics. */
const ipv4Schema = z
  .string()
  .trim()
  .regex(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/, "Must be a dotted-quad IPv4 address")
  .refine((v) => v.split(".").every((oct) => Number(oct) >= 0 && Number(oct) <= 255), "Octets must be 0-255");

// ── trigger filter ({severities[], sources[], kinds[]} — empty = match-all) ──

export const soarTriggerFilterSchema = z
  .object({
    severities: z.array(soarSeveritySchema).max(5).default([]),
    sources: z.array(soarSourceSchema).max(6).default([]),
    /** free-form kinds (dlp category, ioc type, …) — engine matches on payload.kind */
    kinds: z.array(z.string().trim().min(1).max(64)).max(20).default([]),
  })
  .default({});

// ── ordered actions (discriminated on kind; 1..10 per playbook) ─────────────

export const soarBlockIpActionSchema = z.object({
  kind: z.literal("block_ip"),
  params: z.object({
    ip: ipv4Schema,
    /** in = block as source, out = block as destination, both = source-side */
    direction: z.enum(["in", "out", "both"]).default("both"),
  }),
});

export const soarNotifyActionSchema = z.object({
  kind: z.literal("notify"),
  params: z.object({
    title: nonEmpty("Notification title", 200),
    message: nonEmpty("Notification message", 2000),
  }),
});

export const soarCreateIncidentActionSchema = z.object({
  kind: z.literal("create_incident"),
  params: z.object({
    title: nonEmpty("Incident title", 200),
    severity: soarSeveritySchema,
  }),
});

export const soarDelayActionSchema = z.object({
  kind: z.literal("delay"),
  params: z.object({
    seconds: z.coerce.number().int().min(1, "seconds must be ≥ 1").max(300, "seconds must be ≤ 300"),
  }),
});

export const soarWebhookActionSchema = z.object({
  kind: z.literal("webhook"),
  params: z.object({
    /** open JSON payload fanned out through the Phase 1 webhook dispatcher */
    payload: z.record(z.string(), z.unknown()),
  }),
});

export const soarActionSchema = z.discriminatedUnion("kind", [
  soarBlockIpActionSchema,
  soarNotifyActionSchema,
  soarCreateIncidentActionSchema,
  soarDelayActionSchema,
  soarWebhookActionSchema,
]);

export const soarActionsSchema = z
  .array(soarActionSchema)
  .min(1, "A playbook needs at least one action")
  .max(10, "At most 10 actions per playbook");

// ── playbook create / update ────────────────────────────────────────────────

export const soarPlaybookCreateSchema = z.object({
  name: nonEmpty("Playbook name", 64),
  enabled: z.boolean().default(true),
  triggerKind: soarTriggerKindSchema.default("incident_created"),
  triggerFilter: soarTriggerFilterSchema,
  actions: soarActionsSchema,
  /** empty = always run; else skip when an open run shares key + triggerRef */
  dedupeKey: z.string().trim().max(128, "dedupeKey must be ≤ 128 chars").default(""),
});

export const soarPlaybookUpdateSchema = z
  .object({
    name: nonEmpty("Playbook name", 64),
    enabled: z.boolean(),
    triggerKind: soarTriggerKindSchema,
    triggerFilter: soarTriggerFilterSchema,
    actions: soarActionsSchema,
    dedupeKey: z.string().trim().max(128, "dedupeKey must be ≤ 128 chars"),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── manual fire (POST /api/v1/soar/playbooks/{id}/run) ──────────────────────

export const soarRunSchema = z.object({
  /** "incident:INC-0007" style pointer recorded on the run row */
  triggerRef: nonEmpty("triggerRef", 256),
  /** trigger payload the filter would have seen (severity/source/kind…) */
  payload: z.record(z.string(), z.unknown()).default({}),
});

// ── runs list query (GET /api/v1/soar/runs) ─────────────────────────────────

export const soarRunsQuerySchema = z.object({
  playbookId: z.coerce.number().int().positive().optional(),
  status: soarRunStatusSchema.optional(),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(25),
});

// ── inferred types ──────────────────────────────────────────────────────────

export type SoarTriggerKind = z.infer<typeof soarTriggerKindSchema>;
export type SoarActionKind = z.infer<typeof soarActionKindSchema>;
export type SoarSeverity = z.infer<typeof soarSeveritySchema>;
export type SoarSource = z.infer<typeof soarSourceSchema>;
export type SoarRunStatus = z.infer<typeof soarRunStatusSchema>;
export type SoarTriggerFilter = z.infer<typeof soarTriggerFilterSchema>;
export type SoarAction = z.infer<typeof soarActionSchema>;
export type SoarPlaybookCreate = z.infer<typeof soarPlaybookCreateSchema>;
export type SoarPlaybookUpdate = z.infer<typeof soarPlaybookUpdateSchema>;
export type SoarRunInput = z.infer<typeof soarRunSchema>;
export type SoarRunsQuery = z.infer<typeof soarRunsQuerySchema>;
