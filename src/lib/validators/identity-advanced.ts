/**
 * Advanced identity & NAC zod schemas (M23, spec 2.9 + 2.10) — federated
 * IdPs (SAML2/OIDC), RADIUS CoA profiles + packet sends, NAC profiles,
 * device quarantine/restore/rescan, BYOD enrollments and the identity
 * activity timeline. Enums are local to this module (locked by the M23
 * schema columns); cross-module enums stay in validators/enums.ts.
 *
 * Secret rule: `clientSecret` is write-only — accepted on create/update,
 * never echoed back (the API returns `hasSecret`). The BYOD token follows
 * the one-time-secret rule — returned once on create, never on list.
 */

import { z } from "zod";

// ── locked enums (M23 schema comment values) ────────────────────────────────

export const idpProtocolSchema = z.enum(["saml2", "oidc"]);
export const idpStatusSchema = z.enum(["untested", "ok", "error"]);
export const coaActionSchema = z.enum(["reauth", "disconnect", "vlan"]);
export const nacMethodSchema = z.enum(["802.1x", "mab", "both"]);
export const eapTypeSchema = z.enum(["peap", "ttls", "tls"]);
export const deviceTypeSchema = z.enum(["printer", "phone", "camera", "workstation", "mobile", "iot", "unknown"]);
export const nacStateSchema = z.enum(["authenticated", "mab", "quarantine", "pending", "denied"]);
export const byodStatusSchema = z.enum(["pending", "approved", "enrolled", "expired", "revoked"]);
export const activityEventSchema = z.enum([
  "login",
  "logout",
  "portal",
  "vpn",
  "coa",
  "vlan_change",
  "nac_auth",
  "idp_sso",
]);

/** VLAN ids stay in the 1-4094 802.1Q range everywhere in M23. */
const vlanId = z.coerce.number().int().min(1).max(4094);

// ── federated IdPs (area `federation`) ──────────────────────────────────────

/**
 * Cross-field semantics for an IdP payload: SAML2 needs entityId or
 * metadataUrl, OIDC needs a clientId, redirectUri must be https. Shared by
 * the create refine and the PUT merge check.
 */
export function idpSemanticError(v: {
  protocol: string;
  entityId?: string | null;
  metadataUrl?: string | null;
  clientId?: string | null;
  redirectUri?: string | null;
}): string | null {
  if (v.protocol === "saml2" && !v.entityId && !v.metadataUrl) {
    return "SAML2 requires an entityId or a metadataUrl";
  }
  if (v.protocol === "oidc" && !v.clientId) {
    return "OIDC requires a clientId";
  }
  if (v.redirectUri && !v.redirectUri.startsWith("https://")) {
    return "redirectUri must be an https URL";
  }
  return null;
}

const httpUrlWhenPresent = (v: string | null | undefined) =>
  !v || /^https?:\/\/\S+$/.test(v);

export const idpCreateSchema = z
  .object({
    name: z.string().min(1).max(64),
    protocol: idpProtocolSchema.default("saml2"),
    entityId: z.string().min(1).max(255).optional().nullable(),
    metadataUrl: z
      .string()
      .max(512)
      .optional()
      .nullable()
      .refine(httpUrlWhenPresent, "metadataUrl must be an http(s) URL"),
    ssoUrl: z
      .string()
      .max(512)
      .optional()
      .nullable()
      .refine(httpUrlWhenPresent, "ssoUrl must be an http(s) URL"),
    clientId: z.string().min(1).max(128).optional().nullable(),
    /** Write-only — create sets it; responses never include it. */
    clientSecret: z.string().min(1).max(512).optional().nullable(),
    idpCertId: z.coerce.number().int().positive().optional().nullable(),
    redirectUri: z.string().max(512).optional().nullable(),
    enabled: z.boolean().default(true),
  })
  .refine((v) => idpSemanticError(v) === null, {
    message: "SAML2 needs entityId/metadataUrl, OIDC needs clientId, redirectUri must be https",
    path: ["protocol"],
  });

/** Partial update without defaults (zod 4: defaults survive .partial()). */
export const idpUpdateSchema = z
  .object({
    name: z.string().min(1).max(64),
    protocol: idpProtocolSchema,
    entityId: z.string().min(1).max(255).nullable(),
    metadataUrl: z.string().max(512).nullable(),
    ssoUrl: z.string().max(512).nullable(),
    clientId: z.string().min(1).max(128).nullable(),
    /** null / omitted → keep the stored secret; a string replaces it. */
    clientSecret: z.string().min(1).max(512).nullable(),
    idpCertId: z.coerce.number().int().positive().nullable(),
    redirectUri: z.string().max(512).nullable(),
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── RADIUS CoA profiles (area `identity`) ───────────────────────────────────

const vlanPoolTogether = <T extends { dynamicVlan?: boolean; vlanPoolStart?: number | null; vlanPoolEnd?: number | null }>(
  v: T,
) => !v.dynamicVlan || (v.vlanPoolStart != null && v.vlanPoolEnd != null);

const vlanPoolOrdered = <T extends { vlanPoolStart?: number | null; vlanPoolEnd?: number | null }>(v: T) =>
  v.vlanPoolStart == null || v.vlanPoolEnd == null || v.vlanPoolEnd >= v.vlanPoolStart;

export const coaProfileCreateSchema = z
  .object({
    name: z.string().min(1).max(64),
    radiusProfileId: z.coerce.number().int().positive().optional().nullable(),
    coaEnabled: z.boolean().default(true),
    dynamicVlan: z.boolean().default(true),
    vlanPoolStart: vlanId.optional().nullable(),
    vlanPoolEnd: vlanId.optional().nullable(),
    sessionTimeoutMin: z.coerce.number().int().min(5).max(10080).default(480),
    enabled: z.boolean().default(true),
  })
  .refine(vlanPoolTogether, {
    message: "VLAN pool start and end are required together when dynamic VLAN is enabled",
    path: ["vlanPoolEnd"],
  })
  .refine(vlanPoolOrdered, { message: "VLAN pool end must be ≥ start", path: ["vlanPoolEnd"] });

export const coaProfileUpdateSchema = z
  .object({
    name: z.string().min(1).max(64),
    radiusProfileId: z.coerce.number().int().positive().nullable(),
    coaEnabled: z.boolean(),
    dynamicVlan: z.boolean(),
    vlanPoolStart: vlanId.nullable(),
    vlanPoolEnd: vlanId.nullable(),
    sessionTimeoutMin: z.coerce.number().int().min(5).max(10080),
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" })
  .refine(vlanPoolTogether, {
    message: "VLAN pool start and end are required together when dynamic VLAN is enabled",
    path: ["vlanPoolEnd"],
  })
  .refine(vlanPoolOrdered, { message: "VLAN pool end must be ≥ start", path: ["vlanPoolEnd"] });

/** Simulated CoA packet send — the appliance sends the real RADIUS packet. */
export const coaSendSchema = z
  .object({
    userName: z.string().min(1).max(64),
    action: coaActionSchema,
    vlanId: vlanId.optional(),
  })
  .refine((v) => v.action !== "vlan" || v.vlanId !== undefined, {
    message: "vlanId is required for the vlan action",
    path: ["vlanId"],
  });

// ── NAC profiles (area `identity`) ──────────────────────────────────────────

export const nacProfileCreateSchema = z.object({
  name: z.string().min(1).max(64),
  method: nacMethodSchema.default("802.1x"),
  eapType: eapTypeSchema.default("peap"),
  dynamicVlan: z.boolean().default(true),
  guestVlan: vlanId.optional().nullable(),
  authFailVlan: vlanId.optional().nullable(),
  profiling: z.boolean().default(true),
  byodOnboarding: z.boolean().default(false),
  enabled: z.boolean().default(true),
});

export const nacProfileUpdateSchema = z
  .object({
    name: z.string().min(1).max(64),
    method: nacMethodSchema,
    eapType: eapTypeSchema,
    dynamicVlan: z.boolean(),
    guestVlan: vlanId.nullable(),
    authFailVlan: vlanId.nullable(),
    profiling: z.boolean(),
    byodOnboarding: z.boolean(),
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── devices (area `identity`) ───────────────────────────────────────────────

/** paged-lite — the view caps at 100 rows, no PageMeta. */
export const devicesQuerySchema = z.object({
  state: nacStateSchema.optional(),
  deviceType: deviceTypeSchema.optional(),
  q: z.string().max(64).optional(),
  limit: z.coerce.number().int().min(1).max(100).default(100),
});

export const quarantineSchema = z.object({
  vlanId: vlanId.optional(),
});

// ── BYOD enrollments (area `identity`) ──────────────────────────────────────

export const byodCreateSchema = z.object({
  userName: z.string().min(1).max(64),
  deviceId: z.coerce.number().int().positive().optional().nullable(),
  ttlHours: z.coerce.number().int().min(1).max(720).default(24),
});

// ── activity timeline (area `identity`) ─────────────────────────────────────

export const activityQuerySchema = z.object({
  userName: z.string().max(64).optional(),
  event: activityEventSchema.optional(),
  limit: z.coerce.number().int().min(1).max(200).default(100),
});

// ── inferred types ──────────────────────────────────────────────────────────

export type IdpCreate = z.infer<typeof idpCreateSchema>;
export type IdpUpdate = z.infer<typeof idpUpdateSchema>;
export type CoaProfileCreate = z.infer<typeof coaProfileCreateSchema>;
export type CoaProfileUpdate = z.infer<typeof coaProfileUpdateSchema>;
export type CoaSend = z.infer<typeof coaSendSchema>;
export type NacProfileCreate = z.infer<typeof nacProfileCreateSchema>;
export type NacProfileUpdate = z.infer<typeof nacProfileUpdateSchema>;
export type DevicesQuery = z.infer<typeof devicesQuerySchema>;
export type QuarantineInput = z.infer<typeof quarantineSchema>;
export type ByodCreate = z.infer<typeof byodCreateSchema>;
export type ActivityQuery = z.infer<typeof activityQuerySchema>;
