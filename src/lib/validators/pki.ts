/**
 * PKI zod schemas (M14 §2.12) — mirrors validators/logs.ts style.
 * keyType is restricted to rsa2048|rsa4096: node-forge 1.4.3 (the genuine
 * crypto requirement) cannot GENERATE ECDSA keypairs, so ec256/ec384 from the
 * schema comment are intentionally not issuable in the sandbox.
 * Leaf validityDays ≤ 3980 (spec: internal-style ceiling).
 */

import { z } from "zod";

// ── locked enums ────────────────────────────────────────────────────────────

export const pkiKeyTypeSchema = z.enum(["rsa2048", "rsa4096"]);
export const caTypeSchema = z.enum(["root", "subordinate"]);
export const certTypeSchema = z.enum(["server", "client", "device", "user"]);
export const issuedForSchema = z.enum(["ssl_inspect", "waf", "vpn", "email", "general"]);
export const revocationReasonSchema = z.enum([
  "unspecified",
  "keyCompromise",
  "caCompromise",
  "superseded",
  "ceaseOfOperation",
]);
export const pkiStatusSchema = z.enum(["active", "revoked", "expired"]);

// ── SAN shape validation (DNS / IP, "DNS:"/"IP:" prefixes auto-applied) ─────

const DNS_RE = /^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IPV6_RE = /^[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){1,7}$/i; // accepts :: shorthand

export const sanSchema = z
  .string()
  .trim()
  .min(1, "SAN must not be empty")
  .max(253, "SAN too long")
  .refine(
    (v) => {
      const value = /^IP:/i.test(v)
        ? v.slice(3).trim()
        : /^DNS:/i.test(v)
          ? v.slice(4).trim()
          : v.trim();
      return DNS_RE.test(value) || IPV4_RE.test(value) || IPV6_RE.test(value);
    },
    "SAN must be a DNS name (wildcards ok) or an IPv4/IPv6 address",
  );

export const sansSchema = z.array(sanSchema).max(100).default([]);

// ── CA create / update ──────────────────────────────────────────────────────

const httpUrl = z
  .string()
  .trim()
  .max(255)
  .refine((v) => /^https?:\/\/\S+$/.test(v), "must be an http(s) URL")
  .nullish();

export const caCreateSchema = z
  .object({
    name: z.string().trim().min(1).max(64),
    type: caTypeSchema.default("root"),
    commonName: z.string().trim().min(1).max(64),
    org: z.string().trim().max(64).nullish(),
    keyType: pkiKeyTypeSchema.default("rsa2048"),
    validityDays: z.coerce.number().int().min(30).max(7300).default(1825),
    parentCaId: z.coerce.number().int().positive().optional(),
    crlUrl: httpUrl,
    ocspUrl: httpUrl,
    autoRenew: z.boolean().default(false),
  })
  .refine((v) => v.type !== "subordinate" || v.parentCaId !== undefined, {
    message: "parentCaId is required for subordinate CAs",
    path: ["parentCaId"],
  });

export type CaCreate = z.infer<typeof caCreateSchema>;

/** Partial update — fields WITHOUT defaults so `.partial()` stays truly
 *  optional (zod 4: defaults survive `.partial()` and would clobber missing keys). */
export const caUpdateSchema = z
  .object({
    name: z.string().trim().min(1).max(64),
    crlUrl: httpUrl,
    ocspUrl: httpUrl,
    autoRenew: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

export type CaUpdate = z.infer<typeof caUpdateSchema>;

// ── certificate issue / list / revoke ───────────────────────────────────────

export const certCreateSchema = z.object({
  caId: z.coerce.number().int().positive(),
  name: z.string().trim().min(1).max(64),
  commonName: z.string().trim().min(1).max(64),
  sans: sansSchema,
  type: certTypeSchema.default("server"),
  issuedFor: issuedForSchema.default("general"),
  keyType: pkiKeyTypeSchema.default("rsa2048"),
  validityDays: z.coerce.number().int().min(30).max(3980).default(365),
});

export type CertCreate = z.infer<typeof certCreateSchema>;

export const certListQuerySchema = z.object({
  caId: z.coerce.number().int().positive().optional(),
  type: certTypeSchema.optional(),
  status: pkiStatusSchema.optional(),
  issuedFor: issuedForSchema.optional(),
  q: z.string().trim().max(128).optional(),
});

export type CertListQuery = z.infer<typeof certListQuerySchema>;

export const certRevokeSchema = z.object({
  reason: revocationReasonSchema.default("unspecified"),
});

export type CertRevoke = z.infer<typeof certRevokeSchema>;

// ── downloads / CRL / expiry monitoring ─────────────────────────────────────

export const pkiPartQuerySchema = z.object({
  part: z.enum(["cert", "key", "chain"]).default("cert"),
});

export type PkiPartQuery = z.infer<typeof pkiPartQuerySchema>;

export const crlQuerySchema = z.object({
  nextUpdateDays: z.coerce.number().int().min(1).max(365).default(30),
});

export type CrlQuery = z.infer<typeof crlQuerySchema>;

export const expiringQuerySchema = z.object({
  days: z.coerce.number().int().min(1).max(365).default(30),
});

export type ExpiringQuery = z.infer<typeof expiringQuerySchema>;
