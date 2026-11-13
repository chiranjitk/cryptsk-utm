/**
 * Network validators (M02) — interfaces, static routes, PBR, port mirrors and
 * multi-WAN policies. zod is the single source of allowed values at the edge
 * (API_STANDARDS §3); shapes follow SCHEMA.md §3/§4 (M02 §2). Locked enums
 * per PROJECT_MEMORY §6.
 */

import { z } from "zod";

// ── primitive grammars ──────────────────────────────────────────────────────

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const CIDR_RE = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;

export const ipv4Schema = z.string().regex(IPV4_RE, "Must be a valid IPv4 address");

/** Interface name grammar (M02 §5): lowercase alnum + dash, 1–15 chars. */
export const ifaceNameSchema = z
  .string()
  .regex(/^[a-z0-9-]{1,15}$/, "Must match ^[a-z0-9-]{1,15}$ (e.g. wan0, vlan10, br-lan)");

/** Secondary (alias) IPv4 address on an interface — enterprise addressing. */
export const secondaryIpSchema = z.object({
  ip: ipv4Schema,
  cidrPrefix: z.number().int().min(1).max(32),
});
export const secondaryIpsSchema = z
  .array(secondaryIpSchema)
  .max(8, "At most 8 secondary addresses per interface");

export type SecondaryIp = z.infer<typeof secondaryIpSchema>;

/** CIDR grammar (M02 §5) with prefix ≤ 32 (octets still range-checked). */
export const cidrSchema = z
  .string()
  .regex(CIDR_RE, "Must be a CIDR like 10.20.0.0/16")
  .refine((v) => {
    const [ip, prefix] = v.split("/");
    const octets = ip.split(".").map(Number);
    return Number(prefix) <= 32 && octets.every((o) => o >= 0 && o <= 255);
  }, "Prefix must be 0-32 and each octet 0-255");

const L3_FIELD_KEYS = ["ip", "cidrPrefix", "gateway", "wanType", "dns", "secondaryIps"] as const;

/** L3 addressing shared by logical L3 interfaces (vlan/bridge/bond) on create. */
const logicalAddressing = {
  ip: ipv4Schema.optional(),
  cidrPrefix: z.number().int().min(1).max(32).optional(),
  gateway: ipv4Schema.nullish(),
  dns: z.array(ipv4Schema).max(4, "At most 4 DNS servers").optional(),
  secondaryIps: secondaryIpsSchema.optional(),
};

/** First L3 field present on an l2-mode payload, else null (M02 §5). */
function firstL3FieldOnL2(mode: string | undefined, v: Record<string, unknown>): string | null {
  if (mode !== "l2") return null;
  for (const key of L3_FIELD_KEYS) {
    const val = v[key];
    if (val !== undefined && val !== null) return key;
  }
  return null;
}

// ── interface create — discriminated by type (physical is NOT creatable) ───

const ifaceCommonFields = {
  role: z.enum(["wan", "lan", "dmz", "vpn", "mgmt", "unused"]).default("unused"),
  mtu: z.number().int().min(68).max(9000).default(1500),
  mssClamp: z.number().int().min(536).max(1460).nullish(),
  enabled: z.boolean().default(true),
  description: z.string().max(512).nullish(),
  zoneId: z.number().int().min(1).nullish(),
};

/** L2/L3 toggle — every type except bond, whose `mode` key is the bond mode. */
const l3ModeField = { mode: z.enum(["l2", "l3"]).default("l3") };

const vlanIfaceCreate = z.object({
  type: z.literal("vlan"),
  name: ifaceNameSchema,
  parent: ifaceNameSchema,
  vlanId: z.number().int().min(1).max(4094),
  ...logicalAddressing,
  ...ifaceCommonFields,
  ...l3ModeField,
});

const bridgeIfaceCreate = z.object({
  type: z.literal("bridge"),
  name: ifaceNameSchema,
  members: z.array(ifaceNameSchema).min(1, "Bridge needs at least 1 member"),
  stp: z.boolean().optional(),
  stpMode: z.enum(["stp", "rstp"]).optional(),
  stpPriority: z.number().int().min(0).max(65535).optional(),
  forwardDelay: z.number().int().min(4).max(30).optional(),
  igmpSnooping: z.boolean().optional(),
  ...logicalAddressing,
  ...ifaceCommonFields,
  ...l3ModeField,
});

const bondIfaceCreate = z.object({
  type: z.literal("bond"),
  name: ifaceNameSchema,
  members: z.array(ifaceNameSchema).min(2, "Bond needs at least 2 members"),
  // NOTE: a bond's `mode` is its aggregation mode — the l2|l3 toggle is not
  // part of the create payload for bonds (defaults to l3; settable via PUT).
  mode: z.enum(["active-backup", "802.3ad", "balance-xor"]),
  lacpRate: z.enum(["slow", "fast"]).optional(),
  miimon: z.number().int().min(0).max(1000).optional(),
  ...logicalAddressing,
  ...ifaceCommonFields,
});

const greIfaceCreate = z.object({
  type: z.literal("gre"),
  name: ifaceNameSchema,
  local: ipv4Schema,
  remote: ipv4Schema,
  ttl: z.number().int().min(1).max(255).optional(),
  ...ifaceCommonFields,
  ...l3ModeField,
});

const ipipIfaceCreate = z.object({
  type: z.literal("ipip"),
  name: ifaceNameSchema,
  local: ipv4Schema,
  remote: ipv4Schema,
  ...ifaceCommonFields,
  ...l3ModeField,
});

const loopbackIfaceCreate = z.object({
  type: z.literal("loopback"),
  name: ifaceNameSchema,
  ip: ipv4Schema.optional(),
  cidrPrefix: z.number().int().min(0).max(32).optional(),
  ...ifaceCommonFields,
  ...l3ModeField,
});

/** Shell member so `type: "physical"` hits the superRefine message, not a bare union error. */
const physicalIfaceCreate = z.object({ type: z.literal("physical") });

export const ifaceCreateSchema = z
  .discriminatedUnion("type", [
    vlanIfaceCreate,
    bridgeIfaceCreate,
    bondIfaceCreate,
    greIfaceCreate,
    ipipIfaceCreate,
    loopbackIfaceCreate,
    physicalIfaceCreate,
  ])
  .superRefine((v, ctx) => {
    if (v.type === "physical") {
      ctx.addIssue({
        code: "custom",
        path: ["type"],
        message: "Physical interfaces are provisioned by the appliance",
      });
      return;
    }
    if (v.type === "gre" || v.type === "ipip") {
      if (v.local === v.remote) {
        ctx.addIssue({ code: "custom", path: ["remote"], message: "local and remote must differ" });
      }
    }
    const offending = firstL3FieldOnL2(v.mode, v);
    if (offending) {
      ctx.addIssue({ code: "custom", path: [offending], message: "L2 mode interfaces carry no L3 config" });
    }
  });

export type IfaceCreateBody = z.infer<typeof ifaceCreateSchema>;

export type CreatableIfaceType = Exclude<IfaceCreateBody["type"], "physical">;

// ── interface update — one flat schema; per-type semantics live in the service ──

export const ifaceUpdateSchema = z
  .object({
    name: ifaceNameSchema.optional(),
    mode: z.enum(["l2", "l3"]).optional(),
    role: z.enum(["wan", "lan", "dmz", "vpn", "mgmt", "unused"]).optional(),
    mtu: z.number().int().min(68).max(9000).optional(),
    mssClamp: z.number().int().min(536).max(1460).nullish(),
    enabled: z.boolean().optional(),
    description: z.string().max(512).nullish(),
    zoneId: z.number().int().min(1).nullish(),
    // physical WAN fields (M02 §2) — the service applies wanType switch semantics
    wanType: z.enum(["static", "dhcp", "pppoe"]).optional(),
    ip: ipv4Schema.optional(),
    cidrPrefix: z.number().int().min(1).max(32).optional(),
    gateway: ipv4Schema.nullish(),
    dns: z.array(ipv4Schema).max(4, "At most 4 DNS servers").optional(),
    secondaryIps: secondaryIpsSchema.optional(),
    // physical NIC hints (best-effort on apply — NIC dependent)
    speed: z.enum(["auto", "10", "100", "1000", "10000"]).optional(),
    duplex: z.enum(["half", "full"]).optional(),
    /** reference-conflict override for disable/L2 switches (409 → force) */
    force: z.boolean().optional(),
    pppoe: z
      .object({
        user: z.string().min(1),
        password: z.string().min(1),
        service: z.string().optional(),
      })
      .optional(),
    lldp: z.boolean().optional(),
    // logical config passthrough — validated per row type in the service
    config: z.record(z.string(), z.unknown()).optional(),
  })
  .superRefine((v, ctx) => {
    const offending = firstL3FieldOnL2(v.mode, v);
    if (offending) {
      ctx.addIssue({ code: "custom", path: [offending], message: "L2 mode interfaces carry no L3 config" });
    }
  });

export type IfaceUpdateBody = z.infer<typeof ifaceUpdateSchema>;

// ── per-type config patches (applied to the merged config by the service) ──

export const vlanConfigPatch = z.object({
  parent: ifaceNameSchema.optional(),
  ip: ipv4Schema.optional(),
  cidrPrefix: z.number().int().min(1).max(32).optional(),
  gateway: ipv4Schema.nullish(),
  dns: z.array(ipv4Schema).max(4).optional(),
  secondaryIps: secondaryIpsSchema.optional(),
});
export const bridgeConfigPatch = z.object({
  members: z.array(ifaceNameSchema).min(1).optional(),
  stp: z.boolean().optional(),
  stpMode: z.enum(["stp", "rstp"]).optional(),
  stpPriority: z.number().int().min(0).max(65535).optional(),
  forwardDelay: z.number().int().min(4).max(30).optional(),
  igmpSnooping: z.boolean().optional(),
  ip: ipv4Schema.optional(),
  cidrPrefix: z.number().int().min(1).max(32).optional(),
  gateway: ipv4Schema.nullish(),
  dns: z.array(ipv4Schema).max(4).optional(),
  secondaryIps: secondaryIpsSchema.optional(),
});
export const bondConfigPatch = z.object({
  members: z.array(ifaceNameSchema).min(2, "Bond needs at least 2 members").optional(),
  mode: z.enum(["active-backup", "802.3ad", "balance-xor"]).optional(),
  lacpRate: z.enum(["slow", "fast"]).optional(),
  miimon: z.number().int().min(0).max(1000).optional(),
  ip: ipv4Schema.optional(),
  cidrPrefix: z.number().int().min(1).max(32).optional(),
  gateway: ipv4Schema.nullish(),
  dns: z.array(ipv4Schema).max(4).optional(),
  secondaryIps: secondaryIpsSchema.optional(),
});
export const greConfigPatch = z.object({
  local: ipv4Schema.optional(),
  remote: ipv4Schema.optional(),
  ttl: z.number().int().min(1).max(255).optional(),
});
export const ipipConfigPatch = z.object({
  local: ipv4Schema.optional(),
  remote: ipv4Schema.optional(),
});
export const loopbackConfigPatch = z.object({
  ip: ipv4Schema.optional(),
  cidrPrefix: z.number().int().min(0).max(32).optional(),
});

// ── static routes ───────────────────────────────────────────────────────────

export const routeBodySchema = z
  .object({
    name: z.string().max(128).optional(),
    destinationCidr: cidrSchema,
    gateway: ipv4Schema.nullish(),
    interfaceName: z.string().max(64).optional(),
    distance: z.number().int().min(1).max(255).default(1),
    bfd: z.boolean().default(false),
    blackhole: z.boolean().default(false),
    enabled: z.boolean().default(true),
    description: z.string().max(512).nullish(),
  })
  .superRefine((v, ctx) => {
    if (v.blackhole && v.gateway) {
      ctx.addIssue({ code: "custom", path: ["gateway"], message: "Blackhole routes must not set a gateway" });
    }
  });

export type RouteBody = z.infer<typeof routeBodySchema>;

/** create/update with conflict-force (BR-ROUTE-DUP / BR-ROUTE-DEFAULT-PRIMARY 409s) */
export const routeCreateSchema = routeBodySchema.extend({
  force: z.boolean().default(false),
});

// ── policy-based routing ────────────────────────────────────────────────────

export const pbrBodySchema = z
  .object({
    name: z.string().min(1).max(128),
    position: z.number().int().min(1).optional(),
    enabled: z.boolean().default(true),
    srcAddrIds: z.array(z.number().int().min(1)).default([]),
    dstAddrIds: z.array(z.number().int().min(1)).default([]),
    serviceIds: z.array(z.number().int().min(1)).default([]),
    outgoingIface: z.string().max(64).optional(),
    gateway: ipv4Schema.nullish(),
    description: z.string().max(512).nullish(),
  })
  .superRefine((v, ctx) => {
    const hasIface = Boolean(v.outgoingIface);
    const hasGateway = Boolean(v.gateway);
    if (hasIface === hasGateway) {
      ctx.addIssue({
        code: "custom",
        path: [hasIface ? "gateway" : "outgoingIface"],
        message: "Set either an outgoing interface or a gateway, not both/neither",
      });
    }
  });

export type PbrBody = z.infer<typeof pbrBodySchema>;

/** POST /pbr-rules/{id}/move — reorder by swapping with the occupant */
export const pbrMoveBody = z.object({
  position: z.number().int().min(1).max(1000),
});

// ── port mirroring (SPAN) ───────────────────────────────────────────────────

export const mirrorBodySchema = z
  .object({
    name: z.string().min(1).max(64),
    srcIface: z.string().min(1).max(64),
    dstIface: z.string().min(1).max(64),
    direction: z.enum(["ingress", "egress", "both"]).default("both"),
    enabled: z.boolean().default(true),
    description: z.string().max(512).nullish(),
  })
  .superRefine((v, ctx) => {
    if (v.srcIface === v.dstIface) {
      ctx.addIssue({
        code: "custom",
        path: ["dstIface"],
        message: "Mirror source and target interfaces must differ",
      });
    }
  });

export type MirrorBody = z.infer<typeof mirrorBodySchema>;

// ── multi-WAN policies ──────────────────────────────────────────────────────

export const wanProbeTypeSchema = z.enum(["icmp", "tcp", "dns", "http"]);

/** Probe target defaults per type (M02 §8 — centralized to avoid divergence). */
export const probeTargetDefaults: Record<z.infer<typeof wanProbeTypeSchema>, string> = {
  icmp: "1.1.1.1",
  dns: "1.1.1.1",
  http: "http://1.1.1.1",
  tcp: "1.1.1.1:443",
};

const HOST_OR_FQDN = /^(\d{1,3}(\.\d{1,3}){3}|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+)$/;

/** Per-type probeTarget shape (enterprise gap: dead/invalid targets wasted a probe slot). */
export function probeTargetValidFor(type: z.infer<typeof wanProbeTypeSchema>, target: string): string | null {
  const t = target.trim();
  if (!t) return "Probe target is required";
  switch (type) {
    case "icmp":
    case "dns":
      if (!HOST_OR_FQDN.test(t)) return "Target must be an IPv4 address or a hostname";
      return null;
    case "tcp": {
      const m = /^([^:]+):(\d{1,5})$/.exec(t);
      if (!m || !HOST_OR_FQDN.test(m[1]) || Number(m[2]) < 1 || Number(m[2]) > 65535) {
        return "TCP target must be host:port (e.g. 1.1.1.1:443)";
      }
      return null;
    }
    case "http": {
      try {
        const u = new URL(t);
        if (u.protocol !== "http:" && u.protocol !== "https:") return "HTTP target must be an http(s):// URL";
        return null;
      } catch {
        return "HTTP target must be an http(s):// URL";
      }
    }
    default:
      return null;
  }
}

export const wanPolicyBodySchema = z
  .object({
    interfaceName: z.string().min(1).max(64),
    mode: z.enum(["priority", "failover", "load_balance"]).default("failover"),
    weight: z.number().int().min(1).max(99).default(50),
    priority: z.number().int().min(1).max(10).default(1),
    probeType: wanProbeTypeSchema.default("icmp"),
    probeTarget: z.string().min(1).max(256).optional(),
    intervalSec: z.number().int().min(2).max(300).default(5),
    timeoutMs: z.number().int().min(100).max(10000).default(2000),
    failThreshold: z.number().int().min(1).max(10).default(3),
    okThreshold: z.number().int().min(1).max(10).default(3),
    enabled: z.boolean().default(true),
    description: z.string().max(255).optional().nullable(),
  })
  .transform((v) => ({ ...v, probeTarget: v.probeTarget ?? probeTargetDefaults[v.probeType] }))
  .superRefine((v, ctx) => {
    const err = probeTargetValidFor(v.probeType, v.probeTarget);
    if (err) {
      ctx.addIssue({ code: "custom", path: ["probeTarget"], message: err });
    }
  });

export type WanPolicyBody = z.infer<typeof wanPolicyBodySchema>;

// ── shared bits ─────────────────────────────────────────────────────────────

export const toggleBodySchema = z.object({ enabled: z.boolean() });

export const idParamSchema = z.object({ id: z.coerce.number().int().min(1) });

/** List query for M02 collections — additive field filters (M02 §3, PROJECT_MEMORY §7.1). */
export const netListQuery = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(200).default(200),
  type: z.string().optional(),
  role: z.string().optional(),
  iface: z.string().optional(),
  vlan: z.coerce.number().int().optional(),
  q: z.string().optional(),
  enabled: z.enum(["true", "false"]).optional(),
});
