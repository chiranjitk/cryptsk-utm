/**
 * DLP validators (Phase 3 §3.3) — patterns, policies, incidents and the scan
 * endpoint. zod is the single source of allowed values at the edge
 * (API_STANDARDS §3); the enums mirror the dlp_* columns in SCHEMA §3.
 *
 * Format-level grammar lives here (zod). Cross-field / DB-dependent checks
 * (patternIds existence in-tenant, name uniqueness) live in
 * lib/dlp/service.ts and throw ApiError.
 */

import { z } from "zod";

// ── locked enums (SCHEMA dlp_* column comments / SPEC §3.3) ─────────────────

export const dlpKindSchema = z.enum(["regex", "keyword"]);
export const dlpSeveritySchema = z.enum(["low", "medium", "high", "critical"]);
export const dlpCategorySchema = z.enum(["pii", "financial", "credentials", "custom"]);
export const dlpActionSchema = z.enum(["alert", "block", "quarantine"]);
export const dlpProtocolSchema = z.enum(["http", "https", "smtp", "ftp", "dns"]);
export const dlpIncidentStatusSchema = z.enum(["new", "reviewing", "resolved", "false_positive"]);

// ── ReDoS guard (audit fix F-d) ─────────────────────────────────────────────

/**
 * Nested-quantifier screen (audit fixes F-d + M4). The original flat RE only
 * matched `(...)` groups with no nested parens; M4 replaces the check with a
 * structural scanner below (the RE is kept as a flat fast-path).
 */
export const NESTED_QUANTIFIER_RE = /[(][^()]*[+*][^()]*[)][+*{]/;

const UNBOUNDED_QUANT_RE = /^[+*]|^\{\d+,\d*\}/; // +, *, {n,}, {n,m}
const BOUNDED_EXACT_RE = /^\{\d+\}/; // {n} — no ambiguity, safe

/** True when `s` (a regex fragment) contains an UNBOUNDED quantifier at any
 *  depth. `?` (bounded 0-1) and `{n}` exact never cause exponential
 *  partitioning, so they do not trigger the screen — `(https?)+` stays legal
 *  while `(a+)+` / `(\d{1,10})+` / `((a|b*)+)+` are rejected. */
function hasUnboundedQuantifier(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "\\") {
      i++; // escaped char — literal
      continue;
    }
    if (c === "[") {
      // character class — quantifier chars inside are literals
      i++;
      while (i < s.length && (s[i] === "\\" ? (i++, true) : s[i] !== "]")) i++;
      continue;
    }
    if (c === "+" || c === "*") return true;
    if (c === "{") {
      if (UNBOUNDED_QUANT_RE.test(s.slice(i))) return true;
      const exact = BOUNDED_EXACT_RE.exec(s.slice(i));
      if (exact) i += exact[0].length - 1;
      continue;
    }
  }
  return false;
}

/**
 * Structural nested-quantifier screen (audit fix M4 — closes the F-d gap
 * where nested-paren shapes like `((a+)+)b` slipped past the flat RE).
 * Walks the pattern with a paren stack: when a group closes AND an unbounded
 * quantifier directly follows it, the group body is checked for an unbounded
 * quantifier at ANY depth (alternations and nested groups included). Escaped
 * characters and character classes are skipped so literals like `\(+\)+` or
 * `[(]` cannot desync the scanner. Still a DOCUMENTED HEURISTIC — real
 * ambiguity analysis would need a full regex parser — but the nested
 * catastrophic shapes are now covered. Engine-side chunked execution + the
 * scan deadline (lib/dlp/engine.ts) remain the second layer.
 */
export function containsNestedQuantifier(pattern: string): boolean {
  if (NESTED_QUANTIFIER_RE.test(pattern)) return true; // flat fast-path
  const groupStart: number[] = [];
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === "\\") {
      i++; // escaped char — literal
      continue;
    }
    if (c === "[") {
      i++;
      while (i < pattern.length && (pattern[i] === "\\" ? (i++, true) : pattern[i] !== "]")) i++;
      continue;
    }
    if (c === "(") {
      groupStart.push(i + 1);
      continue;
    }
    if (c === ")") {
      const start = groupStart.pop();
      if (start === undefined) continue; // unmatched closer — regex compile will reject
      const body = pattern.slice(start, i);
      if (UNBOUNDED_QUANT_RE.test(pattern.slice(i + 1)) && hasUnboundedQuantifier(body)) {
        return true;
      }
      continue;
    }
    if (c === "{") {
      const exact = BOUNDED_EXACT_RE.exec(pattern.slice(i));
      if (exact) i += exact[0].length - 1; // don't confuse {n} bodies with group markers
    }
  }
  return false;
}

// ── primitive grammars ──────────────────────────────────────────────────────

const nonEmpty = (label: string, max: number) =>
  z.string().trim().min(1, `${label} is required`).max(max, `${label} must be ≤ ${max} chars`);

/**
 * Keyword values are comma-separated keyword lists (SCHEMA §3.3 dlp_patterns
 * comment) — split/trim happens in the engine at scan time.
 */
const patternValueSchema = z
  .string()
  .trim()
  .min(1, "Pattern value is required")
  .max(512, "Pattern value must be ≤ 512 chars");

/** Blocked file extensions: ".pdf" / "pdf" normalize to lowercase "pdf". */
const fileExtensionSchema = z
  .string()
  .trim()
  .regex(/^\.?[a-z0-9]{1,12}$/i, "Extension looks like pdf or .docx")
  .transform((v) => v.replace(/^\./, "").toLowerCase());

const fileTypeArray = z.array(fileExtensionSchema).max(50, "At most 50 blocked extensions");

const protocolArray = z.array(dlpProtocolSchema).max(5);
const patternIdArray = z
  .array(z.coerce.number().int().positive())
  .max(200, "At most 200 patterns per policy");

const sourceIpSchema = z
  .string()
  .trim()
  .min(1, "sourceIp is required")
  .max(64, "sourceIp must be ≤ 64 chars");

// ── patterns ────────────────────────────────────────────────────────────────

export const dlpPatternCreateSchema = z
  .object({
    name: nonEmpty("Pattern name", 64),
    kind: dlpKindSchema.default("regex"),
    value: patternValueSchema,
    severity: dlpSeveritySchema.default("medium"),
    category: dlpCategorySchema.default("pii"),
    enabled: z.boolean().default(true),
  })
  .superRefine((v, ctx) => {
    // ReDoS guard (audit fix F-d) — regex kind only (keywords are literals)
    if (v.kind === "regex" && containsNestedQuantifier(v.value)) {
      ctx.addIssue({ code: "custom", path: ["value"], message: "nested quantifiers rejected (ReDoS guard)" });
    }
  });

/** Partial update without defaults — zod 4 keeps defaults alive through
 * `.partial()`, so field schemas are default-less here (validators/logs note). */
export const dlpPatternUpdateSchema = z
  .object({
    name: nonEmpty("Pattern name", 64),
    kind: dlpKindSchema,
    value: patternValueSchema,
    severity: dlpSeveritySchema,
    category: dlpCategorySchema,
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" })
  .superRefine((v, ctx) => {
    // ReDoS guard (audit fix F-d) — applies when the update keeps/sets the
    // regex kind and carries a value (kind-only / value-only updates pass
    // through; the service re-checks the merged row for those)
    if (v.value !== undefined && (v.kind ?? "regex") === "regex" && containsNestedQuantifier(v.value)) {
      ctx.addIssue({ code: "custom", path: ["value"], message: "nested quantifiers rejected (ReDoS guard)" });
    }
  });

// ── policies ────────────────────────────────────────────────────────────────

export const dlpPolicyCreateSchema = z.object({
  name: nonEmpty("Policy name", 64),
  /** Protocol scope — empty means none of the scan protocols match the policy. */
  protocols: protocolArray.min(1, "Pick at least one protocol").default(["http", "https", "smtp", "ftp"]),
  /** References into dlp_patterns — existence validated in the service. */
  patternIds: patternIdArray.default([]),
  /** Blocked file extensions (SPEC §3.3 file type control). */
  fileTypes: fileTypeArray.default([]),
  action: dlpActionSchema.default("alert"),
  /** SPEC §3.3 user notification (block page / warning). */
  notifyUser: z.boolean().default(false),
  enabled: z.boolean().default(true),
});

export const dlpPolicyUpdateSchema = z
  .object({
    name: nonEmpty("Policy name", 64),
    protocols: protocolArray,
    patternIds: patternIdArray,
    fileTypes: fileTypeArray,
    action: dlpActionSchema,
    notifyUser: z.boolean(),
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── incidents (list query + status workflow) ────────────────────────────────

export const dlpIncidentsQuerySchema = z.object({
  status: dlpIncidentStatusSchema.optional(),
  severity: dlpSeveritySchema.optional(),
  q: z.string().trim().max(128).optional(),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(25),
});

export const dlpIncidentStatusUpdateSchema = z.object({
  status: dlpIncidentStatusSchema,
});

// ── scan (SPEC §3.3 protocol-aware scanning entry point) ────────────────────

export const dlpScanSchema = z.object({
  protocol: dlpProtocolSchema,
  sourceIp: sourceIpSchema,
  userName: z.string().trim().max(64).optional(),
  text: z.string().min(1, "text is required").max(1_000_000, "text must be ≤ 1 MB"),
  fileExtension: z
    .string()
    .trim()
    .regex(/^\.?[a-z0-9]{1,12}$/i, "Extension looks like pdf or .docx")
    .optional(),
});

// ── inferred types ──────────────────────────────────────────────────────────

export type DlpKind = z.infer<typeof dlpKindSchema>;
export type DlpSeverity = z.infer<typeof dlpSeveritySchema>;
export type DlpCategory = z.infer<typeof dlpCategorySchema>;
export type DlpAction = z.infer<typeof dlpActionSchema>;
export type DlpProtocol = z.infer<typeof dlpProtocolSchema>;
export type DlpIncidentStatus = z.infer<typeof dlpIncidentStatusSchema>;
export type DlpPatternCreate = z.infer<typeof dlpPatternCreateSchema>;
export type DlpPatternUpdate = z.infer<typeof dlpPatternUpdateSchema>;
export type DlpPolicyCreate = z.infer<typeof dlpPolicyCreateSchema>;
export type DlpPolicyUpdate = z.infer<typeof dlpPolicyUpdateSchema>;
export type DlpIncidentsQuery = z.infer<typeof dlpIncidentsQuerySchema>;
export type DlpScanInput = z.infer<typeof dlpScanSchema>;
