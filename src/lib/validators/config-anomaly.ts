/**
 * Config anomaly validators (spec §4.5 rule-based pass) — zod is the single
 * source of allowed values at the edge (API_STANDARDS §3). Separate file keeps
 * the firewall validators grammar untouched (additive module).
 */

import { z } from "zod";

export const configAnomalyKindSchema = z.enum([
  "any_any_rule",
  "wan_permissive",
  "unused_object",
  "shadowed_rule",
  "log_disabled",
  "duplicate_rule",
]);
export const configAnomalySeveritySchema = z.enum(["low", "medium", "high"]);
export const configAnomalyStatusSchema = z.enum(["open", "resolved", "ignored"]);

/** POST /config-anomaly/scan body — all options optional. `wanZoneIds`
 *  overrides the auto-derived WAN zone classification when provided;
 *  `requireWanLogging` (default true) gates the log_disabled detector. */
export const configAnomalyScanSchema = z.object({
  wanZoneIds: z.array(z.number().int().min(1)).max(64).optional(),
  requireWanLogging: z.boolean().optional(),
});

/** GET /config-anomaly/findings query. */
export const configAnomalyFindingsQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  kind: configAnomalyKindSchema.optional(),
  severity: configAnomalySeveritySchema.optional(),
  status: configAnomalyStatusSchema.optional(),
});

/**
 * PATCH /config-anomaly/findings/[id] body — triage only: resolved | ignored.
 * `open` is deliberately NOT settable (re-opening a triaged finding happens
 * implicitly when a later scan re-detects it).
 */
export const configAnomalyFindingPatchSchema = z.object({
  status: z.enum(["resolved", "ignored"]),
});

export type ConfigAnomalyScanOptions = z.infer<typeof configAnomalyScanSchema>;
export type ConfigAnomalyFindingsQuery = z.infer<typeof configAnomalyFindingsQuerySchema>;
export type ConfigAnomalyKind = z.infer<typeof configAnomalyKindSchema>;
export type ConfigAnomalySeverity = z.infer<typeof configAnomalySeveritySchema>;
export type ConfigAnomalyStatus = z.infer<typeof configAnomalyStatusSchema>;
