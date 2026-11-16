/**
 * IPS zod schemas (M04 §3/§5) — locked enums from PROJECT_MEMORY §6 via
 * validators/enums.ts. Custom rules are LOOSELY validated here (non-empty,
 * known action keyword, contains `sid:`) — real signature parsing is
 * explicitly out of simulation scope (SIMULATION_LAYER §9); per-line errors
 * are surfaced as details.lines.
 */

import { z } from "zod";
import { ipsModeSchema, ipsPresetSchema } from "./enums";

export const IPS_CATEGORIES = [
  "trojan", "worm", "phishing", "botnet", "scan", "dos", "web_attack",
  "sql_injection", "xss", "brute_force", "malware", "c2", "info_leak",
  "policy", "exploit",
] as const;

export type IpsCategory = (typeof IPS_CATEGORIES)[number];

export const categoryMapSchema = z
  .record(z.string(), z.boolean())
  .refine((m) => Object.keys(m).every((k) => (IPS_CATEGORIES as readonly string[]).includes(k)), {
    message: "Unknown rule category",
  });

export const preprocessorMapSchema = z
  .object({
    stream: z.boolean().optional(),
    http: z.boolean().optional(),
    tls: z.boolean().optional(),
    ssh: z.boolean().optional(),
  })
  .strict();

/** Loose suricata rule check — matches M04 §3 error table (400 with line numbers). */
export const customRuleSchema = z
  .string()
  .max(512)
  .refine((line) => /^\s*(alert|drop|pass|reject|drop\s|\w)/.test(line), "must start with an action keyword (alert|drop|pass|reject)")
  .refine((line) => /\bsid:\s*\d+\s*;/.test(line), "missing `sid:<number>;`");

export const customRulesSchema = z
  .array(z.string().min(1))
  .max(100)
  .superRefine((rules, ctx) => {
    rules.forEach((line, i) => {
      const trimmed = line.trim();
      if (!trimmed) return; // blank lines are skipped silently by the editor
      if (!/^(alert|drop|pass|reject)\b/.test(trimmed)) {
        ctx.addIssue({ code: "custom", path: [i], message: `line ${i + 1}: must start with an action keyword (alert|drop|pass|reject)` });
        return;
      }
      if (!/\bsid:\s*\d+\s*;/.test(trimmed)) {
        ctx.addIssue({ code: "custom", path: [i], message: `line ${i + 1}: missing \`sid:<number>;\`` });
      }
    });
  });

export const exceptionSchema = z.object({
  sid: z.coerce.number().int().min(0).max(99_999_999),
  source: z.string().max(64).optional().nullable(),
  dest: z.string().max(64).optional().nullable(),
  comment: z.string().max(256).optional().nullable(),
});

export const thresholdSchema = z.object({
  sid: z.coerce.number().int().min(1).max(99_999_999),
  track: z.enum(["by_src", "by_dst"]),
  count: z.coerce.number().int().min(1).max(10_000),
  seconds: z.coerce.number().int().min(1).max(86_400),
});

export const ipsPolicyCreateSchema = z.object({
  name: z.string().min(1).max(64),
  mode: ipsModeSchema.default("inline_drop"),
  enabled: z.boolean().default(true),
  ruleCategories: categoryMapSchema.default({}),
  customRules: customRulesSchema.default([]),
  exceptions: z.array(exceptionSchema).max(200).default([]),
  thresholds: z.array(thresholdSchema).max(200).default([]),
  preprocessors: preprocessorMapSchema.default({}),
  tiBlocklist: z.boolean().default(false),
});

/**
 * PATCH-style update — fields are optional WITHOUT create-time defaults.
 * zod v4's `.partial()` still fires `.default()` for absent keys, which would
 * silently reset mode/enabled/categories/etc. on every partial PUT, so each
 * field is rebuilt from the create schema's shape with removeDefault().
 */
export const ipsPolicyUpdateSchema = z
  .object({
    name: ipsPolicyCreateSchema.shape.name.optional(),
    mode: ipsPolicyCreateSchema.shape.mode.removeDefault().optional(),
    enabled: ipsPolicyCreateSchema.shape.enabled.removeDefault().optional(),
    ruleCategories: ipsPolicyCreateSchema.shape.ruleCategories.removeDefault().optional(),
    customRules: ipsPolicyCreateSchema.shape.customRules.removeDefault().optional(),
    exceptions: ipsPolicyCreateSchema.shape.exceptions.removeDefault().optional(),
    thresholds: ipsPolicyCreateSchema.shape.thresholds.removeDefault().optional(),
    preprocessors: ipsPolicyCreateSchema.shape.preprocessors.removeDefault().optional(),
    tiBlocklist: ipsPolicyCreateSchema.shape.tiBlocklist.removeDefault().optional(),
  })
  .refine(
    (v) => Object.keys(v).length > 0,
    { message: "Empty update" },
  );

// ── events query (M04 §3 locked param set) ─────────────────────────────────

const isoOrEmpty = z
  .string()
  .refine((v) => v === "" || !Number.isNaN(Date.parse(v)), "must be an ISO timestamp");

export const ipsEventsQuerySchema = z.object({
  severity: z.string().optional(), // csv of ipsSeveritySchema values
  sid: z.string().max(32).optional(),
  q: z.string().max(128).optional(),
  since: isoOrEmpty.optional(),
  until: isoOrEmpty.optional(),
  category: z.string().max(64).optional(),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(25),
});

export const ipsSuppressBodySchema = z.object({
  duration: z.enum(["24h", "7d", "forever"]),
});

export const ipsPresetBodySchema = z.object({
  preset: ipsPresetSchema,
  name: z.string().min(1).max(64).optional(),
  /** When set, replace that policy's category map + mode instead of creating. */
  replacePolicyId: z.coerce.number().int().min(1).optional(),
});

// ── auto-update scheduler (M04 §4 Rule Updates card) ───────────────────────

const timeOfDay = z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/, "must be HH:MM");

export const ipsUpdateSettingsBodySchema = z.object({
  enabled: z.boolean(),
  interval: z.enum(["daily", "weekly"]),
  time: timeOfDay,
});

export type IpsPolicyCreateInput = z.infer<typeof ipsPolicyCreateSchema>;
export type IpsPolicyUpdateInput = z.infer<typeof ipsPolicyUpdateSchema>;
export type IpsEventsQuery = z.infer<typeof ipsEventsQuerySchema>;
export type IpsUpdateSettingsInput = z.infer<typeof ipsUpdateSettingsBodySchema>;
