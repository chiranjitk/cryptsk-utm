/**
 * CASB zod schemas (Phase 4 §4.3) — SaaS catalog, discovery list queries,
 * the scan trigger and the connector config shell. Vendor live calls are OUT
 * of scope (spec §4.3 note: full CASB needs 50+ SaaS API integrations; the
 * connector only validates config shape), so `config` is an open record —
 * secrets MUST be secret-store refs (`*SecretRef` / `*TokenRef`), never
 * plaintext; the service-side testConnector enforces that shape.
 */

import { z } from "zod";

// ── locked enums (schema.prisma comments + spec §4.3) ───────────────────────

export const saasAppCategorySchema = z.enum([
  "collaboration",
  "storage",
  "crm",
  "productivity",
  "devops",
  "other",
]);

export const saasVerdictSchema = z.enum(["sanctioned", "shadow", "unknown"]);

export const casbVendorSchema = z.enum([
  "google_workspace",
  "microsoft_365",
  "salesforce",
  "dropbox",
  "slack",
]);

export const connectorStatusSchema = z.enum(["disconnected", "connected", "error"]);

// ── catalog (GET/POST /api/v1/casb/catalog, PATCH/DELETE /[id]) ─────────────

/** Domain match entry — plain ("zoom.us", suffix-matched) or wildcard ("*.zoom.us"). */
const domainEntry = z
  .string()
  .trim()
  .toLowerCase()
  .min(1)
  .max(253)
  .regex(/^\*?[\w-]+(\.[\w-]+)+$/, "domain must be like 'zoom.us' or '*.zoom.us'");

export const saasAppCreateSchema = z.object({
  name: z.string().trim().min(1).max(100),
  vendor: z.string().trim().max(100).default(""),
  category: saasAppCategorySchema.default("collaboration"),
  domains: z.array(domainEntry).min(1, "at least one domain is required"),
  riskScore: z.coerce.number().int().min(0).max(100).default(0),
});

export const saasAppUpdateSchema = z.object({
  name: z.string().trim().min(1).max(100).optional(),
  vendor: z.string().trim().max(100).optional(),
  category: saasAppCategorySchema.optional(),
  domains: z.array(domainEntry).min(1, "at least one domain is required").optional(),
  riskScore: z.coerce.number().int().min(0).max(100).optional(),
});

export const saasAppQuerySchema = z.object({
  category: saasAppCategorySchema.optional(),
  q: z.string().max(128).optional(),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(50),
});

// ── discoveries (GET /api/v1/casb/discoveries) ──────────────────────────────

export const discoveryQuerySchema = z.object({
  verdict: saasVerdictSchema.optional(),
  category: saasAppCategorySchema.optional(),
  q: z.string().max(128).optional(),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(25),
});

// ── scan (POST /api/v1/casb/scan) ───────────────────────────────────────────

export const casbScanSchema = z.object({
  windowMinutes: z.coerce.number().int().min(1).max(60 * 24 * 30).default(1440),
});

// ── connectors (GET/POST /api/v1/casb/connectors, PATCH/DELETE /[id]) ───────

/**
 * Open config record — shape per vendor is validated by the service
 * (testConnector) against a per-vendor required-key map. No network calls:
 * values are secret-store references, not credentials.
 */
export const connectorConfigSchema = z.record(z.string(), z.unknown());

export const connectorCreateSchema = z.object({
  vendor: casbVendorSchema,
  config: connectorConfigSchema.default({}),
});

export const connectorPatchSchema = z.object({
  config: connectorConfigSchema.optional(),
  status: connectorStatusSchema.optional(),
});

// ── inferred types ──────────────────────────────────────────────────────────

export type SaasAppCategory = z.infer<typeof saasAppCategorySchema>;
export type SaasVerdict = z.infer<typeof saasVerdictSchema>;
export type CasbVendor = z.infer<typeof casbVendorSchema>;
export type ConnectorStatus = z.infer<typeof connectorStatusSchema>;
export type SaasAppCreate = z.infer<typeof saasAppCreateSchema>;
export type SaasAppUpdate = z.infer<typeof saasAppUpdateSchema>;
export type SaasAppQuery = z.infer<typeof saasAppQuerySchema>;
export type DiscoveryQuery = z.infer<typeof discoveryQuerySchema>;
export type CasbScanInput = z.infer<typeof casbScanSchema>;
export type ConnectorCreate = z.infer<typeof connectorCreateSchema>;
export type ConnectorPatch = z.infer<typeof connectorPatchSchema>;
