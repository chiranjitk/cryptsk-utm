/**
 * QoS validators (M08) — per M08-QOS.md §3/§5 and SCHEMA.md §3.
 * zod is the single source of allowed values at the edge (API_STANDARDS §3);
 * locked enum qos_policies.template from PROJECT_MEMORY §6 via validators/enums.ts.
 *
 * Format-level grammar lives here (zod). Cross-field / DB-dependent checks
 * (guaranteed ≤ max, guaranteed-sum vs budget, matcher id existence in-tenant,
 * catch-all uniqueness, one policy per iface) live in lib/qos/service.ts and
 * throw ApiError.
 */

import { z } from "zod";
import { qosTemplateSchema } from "./enums";

const IFNAME_RE = /^[a-zA-Z0-9._-]{1,15}$/;

const nonEmpty = (label: string, max: number) =>
  z.string().trim().min(1, `${label} is required`).max(max, `${label} must be ≤ ${max} chars`);

const ifaceNameSchema = z.string().regex(IFNAME_RE, "Interface name looks like wan0 / eth0.100");

// ── primitive grammars ──────────────────────────────────────────────────────

/** Total shaper rate in kbps — spec §5.2 floors at 1000 (guards Mbps typos). */
const bandwidthSchema = z
  .number({ message: "Bandwidth must be a number (kbps)" })
  .int("Bandwidth must be an integer number of kbps")
  .min(1000, "bandwidthKbps must be ≥ 1000 kbps (units are kbps — 50 Mbps = 50000)");

const prioritySchema = z
  .number({ message: "Priority must be a number" })
  .int("Priority must be an integer")
  .min(0, "Priority must be 0-7 (0 = highest precedence)")
  .max(7, "Priority must be 0-7 (7 = lowest precedence)");

const rateKbpsSchema = z
  .number({ message: "Rate must be a number (kbps)" })
  .int("Rate must be an integer number of kbps")
  .min(0, "Rate must be ≥ 0 kbps");

const dscpSchema = z
  .number({ message: "DSCP mark must be a number" })
  .int("DSCP mark must be an integer")
  .min(0, "DSCP mark must be 0-63")
  .max(63, "DSCP mark must be 0-63");

/**
 * Matcher arrays: nDPI app labels are strings; user/address ids arrive as
 * strings or numbers and are stored as JSON arrays of strings (SCHEMA.md —
 * JSONB → String holding JSON array; integrity enforced in the service).
 */
const matcherArray = z
  .array(z.union([z.string(), z.number()]))
  .max(100, "At most 100 matchers per dimension")
  .transform((arr) =>
    [...new Set(arr.map((v) => String(v).trim()).filter((v) => v.length > 0))],
  );

// ── policies ────────────────────────────────────────────────────────────────

export const qosPolicyCreateSchema = z.object({
  name: nonEmpty("Policy name", 64),
  template: qosTemplateSchema.nullish(),
  bandwidthKbps: bandwidthSchema,
  ifaceName: ifaceNameSchema.nullish(),
  enabled: z.boolean().default(true),
});

export const qosPolicyUpdateSchema = qosPolicyCreateSchema
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── rules ───────────────────────────────────────────────────────────────────

export const qosRuleCreateSchema = z.object({
  policyId: z.coerce.number().int().positive("policyId is required"),
  name: nonEmpty("Rule name", 64),
  priority: prioritySchema,
  guaranteedKbps: rateKbpsSchema.nullish(),
  maxKbps: rateKbpsSchema.nullish(),
  dscpMark: dscpSchema.nullish(),
  matchApps: matcherArray.default([]),
  matchUsers: matcherArray.default([]),
  matchAddresses: matcherArray.default([]),
});

export const qosRuleUpdateSchema = qosRuleCreateSchema
  .omit({ policyId: true })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── list query (?policyId=) ─────────────────────────────────────────────────

export const qosRulesQuerySchema = z.object({
  policyId: z.coerce.number().int().positive().optional(),
});

// ── inferred types ──────────────────────────────────────────────────────────

export type QosPolicyCreate = z.infer<typeof qosPolicyCreateSchema>;
export type QosPolicyUpdate = z.infer<typeof qosPolicyUpdateSchema>;
export type QosRuleCreate = z.infer<typeof qosRuleCreateSchema>;
export type QosRuleUpdate = z.infer<typeof qosRuleUpdateSchema>;
export type QosRulesQuery = z.infer<typeof qosRulesQuerySchema>;
