/**
 * SD-WAN zod schemas (M20, spec 2.5) — SLA profiles, overlays, sites, paths,
 * policies and the simulated probe body. Formats are validated loose on
 * purpose (lab-grade appliance): wgPubKey is a 40+ char base64-ish string,
 * DSCP accepts CS0–CS6 / EF / AFxy labels, destinations are IPv4 CIDR only.
 *
 * Update schemas follow the M09/M16 pattern: fields WITHOUT defaults so
 * `.partial()` stays truly optional (zod 4: defaults survive `.partial()`
 * and would clobber missing keys).
 */

import { z } from "zod";

// ── loose format helpers (mirrored in components/views/sdwan/sdwan-api.ts) ──

export const IPV4_RE =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

export const IPV4_CIDR_RE =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\/(3[0-2]|[12]?\d)$/;

/** 40+ chars of base64 alphabet — WireGuard keys are 44 char base64; keep loose. */
export const WG_PUBKEY_RE = /^[A-Za-z0-9+/=]{40,}$/;

/** CS0–CS6, EF, AF11–AF43 (class/drop suffix optional → "AF31" and "AF3" both pass). */
export const DSCP_RE = /^(CS[0-6]|EF|AF[1-4][1-3]?)$/i;

// ── locked enums (module-local — schema stores plain strings) ───────────────

export const slaActionSchema = z.enum(["switch", "warn"]);
export const topologySchema = z.enum(["hub_spoke", "full_mesh"]);
export const encryptionSchema = z.enum(["wireguard", "ipsec"]);
export const siteRoleSchema = z.enum(["hub", "spoke"]);
export const wanInterfaceSchema = z.enum(["wan0", "wan1", "wan2"]);
export const pathLabelSchema = z.enum(["mpls", "broadband", "lte"]);
export const pathStateSchema = z.enum(["up", "degraded", "down"]);
export const preferredPathSchema = z.enum(["latency", "jitter", "loss", "fixed"]);

const isoOrEmpty = z
  .string()
  .refine((v) => v === "" || !Number.isNaN(Date.parse(v)), "must be an ISO timestamp");

// ── SLA profiles (spec 2.5 §1) ──────────────────────────────────────────────

export const slaProfileCreateSchema = z.object({
  name: z.string().min(1).max(64),
  latencyMsMax: z.coerce.number().int().min(5).max(1000),
  jitterMsMax: z.coerce.number().int().min(1).max(500),
  lossPctMax: z.coerce.number().min(0).max(50),
  actionOnBreach: slaActionSchema.default("switch"),
});

export const slaProfileUpdateSchema = z
  .object({
    name: z.string().min(1).max(64),
    latencyMsMax: z.coerce.number().int().min(5).max(1000),
    jitterMsMax: z.coerce.number().int().min(1).max(500),
    lossPctMax: z.coerce.number().min(0).max(50),
    actionOnBreach: slaActionSchema,
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── overlays ────────────────────────────────────────────────────────────────

export const overlayCreateSchema = z.object({
  name: z.string().min(1).max(64),
  topology: topologySchema.default("hub_spoke"),
  encryption: encryptionSchema.default("wireguard"),
  enabled: z.boolean().default(true),
});

export const overlayUpdateSchema = z
  .object({
    name: z.string().min(1).max(64),
    topology: topologySchema,
    encryption: encryptionSchema,
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── sites (unique tenant+overlay+name — enforced by the DB) ─────────────────

export const siteCreateSchema = z.object({
  overlayId: z.coerce.number().int().positive(),
  name: z.string().min(1).max(64),
  role: siteRoleSchema.default("spoke"),
  publicIp: z.string().regex(IPV4_RE, "must be a valid IPv4 address"),
  wgPubKey: z
    .string()
    .regex(WG_PUBKEY_RE, "must be a base64 string of at least 40 characters")
    .optional()
    .nullable(),
  region: z.string().max(64).optional().nullable(),
  enabled: z.boolean().default(true),
});

export const siteUpdateSchema = z
  .object({
    overlayId: z.coerce.number().int().positive(),
    name: z.string().min(1).max(64),
    role: siteRoleSchema,
    publicIp: z.string().regex(IPV4_RE, "must be a valid IPv4 address"),
    wgPubKey: z.string().regex(WG_PUBKEY_RE, "must be a base64 string of at least 40 characters").nullable(),
    region: z.string().max(64).nullable(),
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── sites list query (?overlayId) ───────────────────────────────────────────

export const sdwanIdQuerySchema = z.object({
  overlayId: z.coerce.number().int().positive().optional(),
});

// ── paths ───────────────────────────────────────────────────────────────────

export const pathCreateSchema = z.object({
  wanInterface: wanInterfaceSchema,
  label: pathLabelSchema.default("broadband"),
  latencyMs: z.coerce.number().min(0).max(10_000).default(20),
  jitterMs: z.coerce.number().min(0).max(2000).default(3),
  lossPct: z.coerce.number().min(0).max(100).default(0),
  state: pathStateSchema.default("up"),
  lastProbeAt: isoOrEmpty.optional(),
});

export const pathUpdateSchema = z
  .object({
    wanInterface: wanInterfaceSchema,
    label: pathLabelSchema,
    latencyMs: z.coerce.number().min(0).max(10_000),
    jitterMs: z.coerce.number().min(0).max(2000),
    lossPct: z.coerce.number().min(0).max(100),
    state: pathStateSchema,
    lastProbeAt: isoOrEmpty,
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

export const pathsQuerySchema = z.object({
  siteId: z.coerce.number().int().positive().optional(),
});

// ── simulated probe (POST /paths/probe; optional overlay scoping) ──────────

export const probeBodySchema = z.object({
  overlayId: z.coerce.number().int().positive().optional(),
});

// ── policies (fixedWanInterface required when preferredPath=fixed) ──────────

export const policyCreateSchema = z
  .object({
    name: z.string().min(1).max(64),
    overlayId: z.coerce.number().int().positive(),
    matchApp: z.string().max(64).optional().nullable(),
    matchDscp: z
      .string()
      .regex(DSCP_RE, "use CS0–CS6, EF or AFxy (e.g. EF, AF31)")
      .optional()
      .nullable(),
    matchDestCidr: z
      .string()
      .regex(IPV4_CIDR_RE, "must be an IPv4 CIDR like 10.0.0.0/8")
      .optional()
      .nullable(),
    preferredPath: preferredPathSchema.default("latency"),
    fixedWanInterface: wanInterfaceSchema.optional().nullable(),
    slaProfileId: z.coerce.number().int().positive().optional().nullable(),
    enabled: z.boolean().default(true),
  })
  .refine((v) => v.preferredPath !== "fixed" || !!v.fixedWanInterface, {
    message: "fixedWanInterface is required when preferredPath is fixed",
    path: ["fixedWanInterface"],
  });

export const policyUpdateSchema = z
  .object({
    name: z.string().min(1).max(64),
    overlayId: z.coerce.number().int().positive(),
    matchApp: z.string().max(64).nullable(),
    matchDscp: z.string().regex(DSCP_RE, "use CS0–CS6, EF or AFxy (e.g. EF, AF31)").nullable(),
    matchDestCidr: z.string().regex(IPV4_CIDR_RE, "must be an IPv4 CIDR like 10.0.0.0/8").nullable(),
    preferredPath: preferredPathSchema,
    fixedWanInterface: wanInterfaceSchema.nullable(),
    slaProfileId: z.coerce.number().int().positive().nullable(),
    enabled: z.boolean(),
  })
  .partial()
  .refine(
    (v) => Object.keys(v).length > 0 && (v.preferredPath !== "fixed" || !!v.fixedWanInterface),
    { message: "Empty update or fixedWanInterface missing for preferredPath=fixed" },
  );

// ── inferred types (services consume these) ─────────────────────────────────

export type SlaProfileCreate = z.infer<typeof slaProfileCreateSchema>;
export type SlaProfileUpdate = z.infer<typeof slaProfileUpdateSchema>;
export type OverlayCreate = z.infer<typeof overlayCreateSchema>;
export type OverlayUpdate = z.infer<typeof overlayUpdateSchema>;
export type SiteCreate = z.infer<typeof siteCreateSchema>;
export type SiteUpdate = z.infer<typeof siteUpdateSchema>;
export type PathCreate = z.infer<typeof pathCreateSchema>;
export type PathUpdate = z.infer<typeof pathUpdateSchema>;
export type PolicyCreate = z.infer<typeof policyCreateSchema>;
export type PolicyUpdate = z.infer<typeof policyUpdateSchema>;
export type ProbeBody = z.infer<typeof probeBodySchema>;
