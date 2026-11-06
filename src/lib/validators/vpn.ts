/**
 * VPN validators (M05) — per-type config shapes (SCHEMA.md §4, exact),
 * VpnUserGroup payloads and the sessions query. zod is the single source of
 * allowed values at the edge (API_STANDARDS §3); locked enums from
 * PROJECT_MEMORY §6 via validators/enums.ts.
 */

import { z } from "zod";
import { vpnTypeSchema, vpnStatusSchema } from "./enums";

// ── primitive grammars ──────────────────────────────────────────────────────

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const CIDR_RE = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
const HOSTPORT_RE = /^[a-zA-Z0-9._-]+:\d{1,5}$/;

export const ipv4Schema = z.string().regex(IPV4_RE, "Must be a valid IPv4 address");

export const cidrSchema = z
  .string()
  .regex(CIDR_RE, "Must be a CIDR like 10.20.0.0/16")
  .refine((v) => {
    const [ip, prefix] = v.split("/");
    const octets = ip.split(".").map(Number);
    return Number(prefix) <= 32 && octets.every((o) => o >= 0 && o <= 255);
  }, "Prefix must be 0-32 and each octet 0-255");

const hostPort = z.string().regex(HOSTPORT_RE, "Must be host:port (e.g. 198.51.100.10:51820)");

const portSchema = z.number().int().min(1, "Port must be 1-65535").max(65535, "Port must be 1-65535");
const keepaliveSchema = z.number().int().min(0, "Keepalive must be 0-120 s").max(120, "Keepalive must be 0-120 s");
const dpdSchema = z.number().int().min(5, "DPD must be 5-600 s").max(600, "DPD must be 5-600 s");
const replayWindowSchema = z.union([z.literal(32), z.literal(64), z.literal(128), z.literal(256), z.literal(512), z.literal(1024)]);

// ── WireGuard ───────────────────────────────────────────────────────────────

export const wgPeerSchema = z.object({
  name: z.string().min(1, "Peer name is required").max(64),
  publicKey: z.string().min(1, "publicKey is required").max(256),
  allowedIps: z.array(cidrSchema).min(1, "At least one AllowedIPs CIDR is required").max(32),
  endpoint: hostPort.optional(),
  keepaliveSec: keepaliveSchema.optional(),
});

export const wgS2sConfigSchema = z.object({
  privateKey: z.string().min(1, "Private key is required").max(256),
  listenPort: portSchema,
  peers: z.array(wgPeerSchema).max(64),
  address: cidrSchema,
});

export const wgRemoteConfigSchema = z.object({
  privateKey: z.string().min(1, "Private key is required").max(256),
  listenPort: portSchema,
  address: cidrSchema,
  pool: cidrSchema,
  dns: ipv4Schema.optional().or(z.literal("")),
  keepaliveSec: keepaliveSchema.optional(),
  peers: z.array(wgPeerSchema).max(256),
});

// ── IPSec (s2s + remote share one shape; remoteIp only on s2s) ──────────────

export const ipsecConfigSchema = z.object({
  localIp: ipv4Schema,
  remoteIp: ipv4Schema.optional().or(z.literal("")),
  localSubnets: z.array(cidrSchema).min(1, "At least one local subnet is required").max(32),
  remoteSubnets: z.array(cidrSchema).max(32),
  psk: z.string().min(1, "PSK is required").max(256),
  ike: z.string().min(1, "IKE proposal is required").max(128),
  esp: z.string().min(1, "ESP proposal is required").max(128),
  dpdSec: dpdSchema.optional(),
  pfs: z.boolean().optional(),
  authMethod: z.enum(["psk", "eap_mschapv2", "eap_tls"]).optional(),
  replayWindow: replayWindowSchema.optional(),
  dns: ipv4Schema.optional().or(z.literal("")),
});

// ── OpenVPN ─────────────────────────────────────────────────────────────────

export const openVpnConfigSchema = z.object({
  proto: z.enum(["udp", "tcp"]),
  port: portSchema,
  cipher: z.string().min(1, "Cipher is required").max(64),
  auth: z.string().min(1, "Auth digest is required").max(64),
  pool: cidrSchema,
  tls: z.boolean().optional(),
  dns: ipv4Schema.optional().or(z.literal("")),
  keepaliveSec: keepaliveSchema.optional(),
});

/** Discriminated per-type config union (M05 §5: the shape must match the row's type). */
export const vpnConfigSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("wireguard_s2s"), config: wgS2sConfigSchema }),
  z.object({ type: z.literal("wireguard_remote"), config: wgRemoteConfigSchema }),
  z.object({ type: z.literal("ipsec_s2s"), config: ipsecConfigSchema }),
  z.object({ type: z.literal("ipsec_remote"), config: ipsecConfigSchema }),
  z.object({ type: z.literal("openvpn"), config: openVpnConfigSchema }),
]);

// ── create / update bodies ──────────────────────────────────────────────────

export const vpnConfigCreateSchema = z
  .object({
    name: z.string().min(1, "Name is required").max(64),
    type: vpnTypeSchema,
    enabled: z.boolean().default(true),
    config: z.unknown(),
  })
  .superRefine((v, ctx) => {
    const r = vpnConfigSchema.safeParse({ type: v.type, config: v.config });
    if (!r.success) {
      for (const issue of r.error.issues) {
        ctx.addIssue({ code: "custom", path: ["config", ...issue.path], message: issue.message });
      }
    }
  });

export const vpnConfigUpdateSchema = z
  .object({
    name: z.string().min(1).max(64).optional(),
    enabled: z.boolean().optional(),
    config: z.unknown().optional(),
    // engine-owned (ENDPOINTS §7): accepted but ignored
    status: vpnStatusSchema.optional(),
    statusMessage: z.string().optional(),
  })
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── sessions ────────────────────────────────────────────────────────────────

export const vpnSessionsQuerySchema = z.object({
  vpnId: z.coerce.number().int().min(1).optional(),
  status: z.enum(["active", "idle", "disconnected"]).optional(),
  q: z.string().max(128).optional(),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(25),
});

// ── VPN user groups ─────────────────────────────────────────────────────────

export const vpnUserGroupCreateSchema = z.object({
  name: z.string().min(1, "Name is required").max(64),
  description: z.string().max(256).nullish(),
  pool: cidrSchema.nullish(),
  dns: ipv4Schema.nullish(),
  idleTimeoutMin: z.number().int().min(1).max(10080).nullish(),
  maxSessionMin: z.number().int().min(1).max(525600).nullish(),
  maxSessionsPerUser: z.number().int().min(1).max(100).nullish(),
  memberUsernames: z.array(z.string().min(1).max(64)).max(256).default([]),
});

export const vpnUserGroupUpdateSchema = vpnUserGroupCreateSchema.partial().refine(
  (v) => Object.keys(v).length > 0,
  { message: "Empty update" },
);

export type VpnConfigCreateInput = z.infer<typeof vpnConfigCreateSchema>;
export type VpnConfigUpdateInput = z.infer<typeof vpnConfigUpdateSchema>;
export type VpnSessionsQuery = z.infer<typeof vpnSessionsQuerySchema>;
export type VpnUserGroupCreateInput = z.infer<typeof vpnUserGroupCreateSchema>;
export type VpnUserGroupUpdateInput = z.infer<typeof vpnUserGroupUpdateSchema>;
