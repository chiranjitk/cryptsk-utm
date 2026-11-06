/**
 * Identity validators (M07) — per M07-IDENTITY.md §3/§5 and SCHEMA.md §4.
 * zod is the single source of allowed values at the edge (API_STANDARDS §3);
 * role enum from PROJECT_MEMORY §6 (8 roles, no "viewer") via lib/auth/rbac.
 *
 * Format-level grammar lives here (zod). DB-dependent checks (duplicate
 * username/group/profile name, last-admin guard, self-delete, policy history)
 * live in lib/identity/service.ts and throw ApiError.
 */

import { z } from "zod";
import { ROLES } from "@/lib/auth/rbac";
import { ipv4Schema } from "./dns-dhcp";

// ── primitive grammars ──────────────────────────────────────────────────────

const IPV6_RE =
  /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$/;
export const ipAddressSchema = ipv4Schema.or(
  z.string().regex(IPV6_RE, "Must be a valid IPv6 address"),
);

const USERNAME_RE = /^[a-z0-9._-]{3,32}$/;
const MAC_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/;
const IFNAME_RE = /^[a-zA-Z0-9._-]{1,15}$/;
const DN_RE = /^(cn|ou|dc|o|uid|c|st|l)=[^,]+(,\s*(cn|ou|dc|o|uid|c|st|l)=[^,]+)*$/i;

const usernameSchema = z
  .string()
  .trim()
  .toLowerCase()
  .regex(USERNAME_RE, "Username must be 3-32 chars: lowercase letters, digits, dots, underscores, hyphens");

const emailSchema = z
  .string()
  .trim()
  .max(254, "Email must be ≤ 254 chars")
  .refine((v) => v === "" || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v), "Must be a valid email address")
  .transform((v) => (v === "" ? null : v))
  .nullish();

const macSchema = z
  .string()
  .trim()
  .transform((v) => v.toLowerCase())
  .refine((v) => v === "" || MAC_RE.test(v), "MAC must look like aa:bb:cc:dd:ee:ff")
  .transform((v) => (v === "" ? null : v))
  .nullish();

const ifaceNameSchema = z.string().trim().regex(IFNAME_RE, "Interface name looks like lan0 / eth0.100");

/** Password value — strength is checked against the auth policy in the service
 *  layer (policy is DB state, not a static grammar). */
const passwordSchema = z
  .string({ message: "Password is required" })
  .min(1, "Password is required")
  .max(128, "Password must be ≤ 128 chars");

// ── users ───────────────────────────────────────────────────────────────────

export const roleSchema = z.enum(ROLES);

export const userCreateSchema = z.object({
  username: usernameSchema,
  email: emailSchema,
  role: roleSchema.default("helpdesk"),
  isActive: z.boolean().default(true),
  password: passwordSchema,
  groupIds: z.array(z.coerce.number().int().positive()).max(32).default([]),
});

export const userUpdateSchema = z
  .object({
    email: emailSchema,
    role: roleSchema.optional(),
    isActive: z.boolean().optional(),
    /** optional key = set/reset password (M07 §3; never echoed back) */
    password: passwordSchema.optional(),
    /** group membership replace-all on the user editor */
    groupIds: z.array(z.coerce.number().int().positive()).max(32).optional(),
    /** true = enroll TOTP (response carries the one-time secret); false = disenroll */
    totpEnroll: z.boolean().optional(),
  })
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

export const userQuerySchema = z.object({
  q: z.string().trim().max(64).optional(),
  role: roleSchema.optional(),
  groupId: z.coerce.number().int().positive().optional(),
});

// ── user groups ─────────────────────────────────────────────────────────────

const groupNameSchema = z
  .string()
  .trim()
  .min(1, "Group name is required")
  .max(64, "Group name must be ≤ 64 chars");

export const userGroupCreateSchema = z.object({
  name: groupNameSchema,
  description: z.string().trim().max(255).nullish(),
  memberIds: z.array(z.coerce.number().int().positive()).max(256).default([]),
});

export const userGroupUpdateSchema = userGroupCreateSchema
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── auth settings (GET/PUT /api/v1/auth-settings — M07 §5.2) ────────────────

export const authSettingsSchema = z.object({
  password: z.object({
    minLength: z.number({ message: "Minimum length must be a number" }).int().min(8, "Minimum length is 8").max(64, "Minimum length is 64"),
    requireComplexity: z.boolean().default(true),
    expiryDays: z.number({ message: "Expiry must be a number of days" }).int().min(0, "Expiry must be 0-365 (0 = never)").max(365, "Expiry must be 0-365 (0 = never)"),
  }),
  lockout: z.object({
    maxAttempts: z.number({ message: "Max attempts must be a number" }).int().min(3, "Max attempts is 3-10").max(10, "Max attempts is 3-10"),
    windowMin: z.number({ message: "Window must be a number of minutes" }).int().min(5, "Window is 5-60 min").max(60, "Window is 5-60 min"),
  }),
  sessionLifetimeHours: z.number({ message: "Session lifetime must be a number of hours" }).int().min(1, "Session lifetime is 1-24 h").max(24, "Session lifetime is 1-24 h"),
  totp: z.object({
    required: z.boolean().default(false),
  }),
  sessionLimits: z.object({
    maxConcurrentPerUser: z.number({ message: "Concurrent cap must be a number" }).int().min(1, "Concurrent cap is 1-16").max(16, "Concurrent cap is 1-16"),
  }),
});

// ── RADIUS profiles ─────────────────────────────────────────────────────────

const radiusNameSchema = z
  .string()
  .trim()
  .min(1, "Profile name is required")
  .max(64, "Profile name must be ≤ 64 chars");

export const radiusProfileCreateSchema = z.object({
  name: radiusNameSchema,
  serverIp: ipv4Schema,
  authPort: z.coerce.number().int().min(1, "Port must be 1-65535").max(65535, "Port must be 1-65535").default(1812),
  sharedSecret: z.string().trim().min(4, "Shared secret must be at least 4 chars").max(128, "Shared secret must be ≤ 128 chars"),
  timeoutSec: z.coerce.number().int().min(1, "Timeout is 1-30 s").max(30, "Timeout is 1-30 s").default(3),
  retries: z.coerce.number().int().min(0, "Retries is 0-5").max(5, "Retries is 0-5").default(2),
});

export const radiusProfileUpdateSchema = radiusProfileCreateSchema
  .extend({
    /** omit to keep the stored secret (the masked literal sent back is ignored) */
    sharedSecret: z.string().trim().min(4, "Shared secret must be at least 4 chars").max(128, "Shared secret must be ≤ 128 chars").optional(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── directory sources (LDAP/AD) ─────────────────────────────────────────────

const dirNameSchema = z
  .string()
  .trim()
  .min(1, "Source name is required")
  .max(64, "Source name must be ≤ 64 chars");

export const directorySourceCreateSchema = z.object({
  name: dirNameSchema,
  type: z.enum(["ldap", "ad"]).default("ldap"),
  serverIp: ipAddressSchema,
  port: z.coerce.number().int().min(1, "Port must be 1-65535").max(65535, "Port must be 1-65535").default(389),
  baseDn: z.string().trim().min(1, "Base DN is required").max(255).refine((v) => DN_RE.test(v), "Base DN looks like dc=corp,dc=local"),
  bindDn: z.string().trim().max(255).refine((v) => v === "" || DN_RE.test(v), "Bind DN looks like cn=svc,dc=corp,dc=local")
    .transform((v) => (v === "" ? null : v))
    .nullish(),
  bindPassword: z.string().trim().max(128).nullish(),
  userFilter: z.string().trim().max(255).refine((v) => v === "" || /^\(.*\)$/.test(v), "User filter looks like (memberOf=cn=vpn,ou=groups,dc=corp,dc=local)")
    .transform((v) => (v === "" ? null : v))
    .nullish(),
  enabled: z.boolean().default(true),
});

export const directorySourceUpdateSchema = directorySourceCreateSchema
  .extend({
    /** omit to keep the stored bind password (masked literal sent back is ignored) */
    bindPassword: z.string().trim().max(128).optional(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── captive portal profile (singleton upsert — M07 §5.4) ────────────────────

export const captivePortalUpdateSchema = z.object({
  name: z.string().trim().min(1, "Profile name is required").max(64).default("GUEST-PORTAL"),
  enabled: z.boolean().default(false),
  mode: z.enum(["clickthrough", "credentials", "voucher"]).default("clickthrough"),
  interfaceName: ifaceNameSchema,
  sessionTimeoutMin: z.coerce.number().int().min(5, "Session timeout is 5-1440 min").max(1440, "Session timeout is 5-1440 min").default(240),
  bandwidthKbps: z.coerce.number().int().min(64, "Bandwidth cap is 64-1048576 kbps").max(1_048_576, "Bandwidth cap is 64-1048576 kbps").nullish(),
  redirectUrl: z
    .string()
    .trim()
    .max(512)
    .refine((v) => v === "" || /^https?:\/\/.+/.test(v), "Redirect URL must start with http:// or https://")
    .transform((v) => (v === "" ? null : v))
    .nullish(),
  voucherTtlHours: z.coerce.number().int().min(1, "Voucher TTL is 1-720 h").max(720, "Voucher TTL is 1-720 h").default(24),
});

// ── vouchers (MockEngine in-memory — SCHEMA.md §6 pseudo-resource) ──────────

export const voucherGenerateSchema = z.object({
  count: z.coerce.number({ message: "Count must be a number" }).int().min(1, "Count is 1-500").max(500, "Count is 1-500"),
  ttlHours: z.coerce.number().int().min(1, "TTL is 1-720 h").max(720, "TTL is 1-720 h").optional(),
  bandwidthKbps: z.coerce.number().int().min(64, "Bandwidth cap is 64-1048576 kbps").max(1_048_576, "Bandwidth cap is 64-1048576 kbps").optional(),
});

// ── identity sessions list query ────────────────────────────────────────────

export const identitySessionQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(50),
  method: z.enum(["local", "radius", "captive_portal", "vpn"]).optional(),
  state: z.enum(["active", "expired"]).default("active"),
  q: z.string().trim().max(64).optional(),
});

// ── inferred types ──────────────────────────────────────────────────────────

export type UserCreate = z.infer<typeof userCreateSchema>;
export type UserUpdate = z.infer<typeof userUpdateSchema>;
export type UserQuery = z.infer<typeof userQuerySchema>;
export type UserGroupCreate = z.infer<typeof userGroupCreateSchema>;
export type UserGroupUpdate = z.infer<typeof userGroupUpdateSchema>;
export type AuthSettings = z.infer<typeof authSettingsSchema>;
export type RadiusProfileCreate = z.infer<typeof radiusProfileCreateSchema>;
export type RadiusProfileUpdate = z.infer<typeof radiusProfileUpdateSchema>;
export type DirectorySourceCreate = z.infer<typeof directorySourceCreateSchema>;
export type DirectorySourceUpdate = z.infer<typeof directorySourceUpdateSchema>;
export type CaptivePortalUpdate = z.infer<typeof captivePortalUpdateSchema>;
export type VoucherGenerate = z.infer<typeof voucherGenerateSchema>;
export type IdentitySessionQuery = z.infer<typeof identitySessionQuerySchema>;
