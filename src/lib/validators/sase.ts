/**
 * SASE zod schemas (spec §4.2) — cloud firewall nodes, edge-to-cloud
 * WireGuard tunnels and the identity-aware routing map (user → region).
 *
 * Formats are validated loose on purpose (lab-grade appliance): the tunnel
 * endpoint accepts `host` or `host:port` and the PURE renderer
 * (lib/sase/mesh.ts) collects the precise endpoint errors (missing endpoint,
 * missing :port) into the plan — a half-configured mesh must stay previewable.
 * `pskRef` is a secret-store REFERENCE string, never the PSK itself; key
 * material never travels through these schemas at all.
 *
 * Update schemas follow the M09/M16 pattern: fields WITHOUT defaults so
 * `.partial()` stays truly optional (zod 4: defaults survive `.partial()`
 * and would clobber missing keys).
 */

import { z } from "zod";

// ── loose format helpers ─────────────────────────────────────────────────────

export const SASE_IPV4_CIDR_RE =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\/(3[0-2]|[12]?\d)$/;

/** host[:port] — hostname or IPv4, optional numeric port (renderer is strict). */
export const SASE_ENDPOINT_RE = /^\S+?(:\d{1,5})?$/;

export const SASE_EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ── locked enums (schema.prisma comments + spec §4.2) ───────────────────────

export const saseCloudSchema = z.enum(["onprem", "aws", "azure", "gcp"]);
export const saseRoleSchema = z.enum(["edge", "gateway"]);
export const saseStatusSchema = z.enum(["planned", "active", "down"]);
export const saseTunnelStateSchema = z.enum(["planned", "active", "down"]);

export const SASE_CLOUDS: SaseCloud[] = ["onprem", "aws", "azure", "gcp"];
export const SASE_ROLES: SaseRole[] = ["edge", "gateway"];
export const SASE_STATUSES: SaseStatus[] = ["planned", "active", "down"];
export const SASE_TUNNEL_STATES: SaseTunnelState[] = ["planned", "active", "down"];

export type SaseCloud = z.infer<typeof saseCloudSchema>;
export type SaseRole = z.infer<typeof saseRoleSchema>;
export type SaseStatus = z.infer<typeof saseStatusSchema>;
export type SaseTunnelState = z.infer<typeof saseTunnelStateSchema>;

const cidrList = z
  .array(z.string().regex(SASE_IPV4_CIDR_RE, "must be an IPv4 CIDR like 10.0.0.0/8"))
  .max(64, "at most 64 subnets");

const endpoint = z
  .string()
  .max(255)
  .regex(SASE_ENDPOINT_RE, "use host[:port] without spaces (e.g. edge.example.com:51820)");

const pskRef = z
  .string()
  .max(256)
  .refine((v) => v === "" || !SASE_KEY_MATERIAL_RE.test(v), {
    message: "pskRef is a secret-store REFERENCE (e.g. vault:wg/<name>) — never key material",
  });

/** Anything that looks like a 44-char base64 WireGuard key is refused. */
const SASE_KEY_MATERIAL_RE = /^[A-Za-z0-9+/]{43}=$/;

// ── nodes (spec §4.2 cloud firewall node) ────────────────────────────────────

export const saseNodeCreateSchema = z.object({
  name: z.string().min(1).max(64),
  cloud: saseCloudSchema.default("onprem"),
  region: z.string().max(64).default(""),
  role: saseRoleSchema.default("edge"),
  tunnelEndpoint: endpoint.default(""),
  publicSubnets: cidrList.default([]),
  status: saseStatusSchema.default("planned"),
});

export const saseNodeUpdateSchema = z
  .object({
    name: z.string().min(1).max(64),
    cloud: saseCloudSchema,
    region: z.string().max(64),
    role: saseRoleSchema,
    tunnelEndpoint: endpoint,
    publicSubnets: cidrList,
    status: saseStatusSchema,
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── tunnels (spec §4.2 edge-to-cloud WireGuard mesh link) ────────────────────

export const saseTunnelCreateSchema = z
  .object({
    name: z.string().min(1).max(64),
    fromNodeId: z.coerce.number().int().positive(),
    toNodeId: z.coerce.number().int().positive(),
    state: saseTunnelStateSchema.default("planned"),
    pskRef: pskRef.default(""),
    allowedSubnets: cidrList.default([]),
  })
  .refine((v) => v.fromNodeId !== v.toNodeId, {
    message: "A tunnel cannot connect a node to itself",
    path: ["toNodeId"],
  });

export const saseTunnelUpdateSchema = z
  .object({
    name: z.string().min(1).max(64),
    fromNodeId: z.coerce.number().int().positive(),
    toNodeId: z.coerce.number().int().positive(),
    state: saseTunnelStateSchema,
    pskRef,
    allowedSubnets: cidrList,
  })
  .partial()
  .refine(
    (v) => Object.keys(v).length > 0 && (v.fromNodeId === undefined || v.fromNodeId !== v.toNodeId),
    { message: "Empty update or a tunnel cannot connect a node to itself" },
  );

// ── identity-aware routing (spec §4.2 user → nearest node) ──────────────────

export const saseRoutingUpsertSchema = z.object({
  userEmail: z
    .string()
    .trim()
    .toLowerCase()
    .max(254)
    .regex(SASE_EMAIL_RE, "must be an email address"),
  region: z.string().trim().min(1).max(64),
});

export const saseResolveSchema = z.object({
  userEmail: z
    .string()
    .trim()
    .toLowerCase()
    .max(254)
    .regex(SASE_EMAIL_RE, "must be an email address"),
});

// ── inferred types (services consume these) ─────────────────────────────────

export type SaseNodeCreate = z.infer<typeof saseNodeCreateSchema>;
export type SaseNodeUpdate = z.infer<typeof saseNodeUpdateSchema>;
export type SaseTunnelCreate = z.infer<typeof saseTunnelCreateSchema>;
export type SaseTunnelUpdate = z.infer<typeof saseTunnelUpdateSchema>;
export type SaseRoutingUpsert = z.infer<typeof saseRoutingUpsertSchema>;
export type SaseResolve = z.infer<typeof saseResolveSchema>;
