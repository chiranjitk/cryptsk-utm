/**
 * IPv6 Dual-Stack zod schemas (M21, spec 2.7). Cross-field rules enforced here:
 * nptv6 needs a source AND a translated IPv6 CIDR that differ, dnat66 owns the
 * only legal destPort, DHCPv6 pools compare start/end as 128-bit BigInts of the
 * expanded address and validLifetime must be ≥ preferredLifetime. pdWanInterface
 * existence is checked SERVER-side against db.networkInterface (shared.ts).
 */

import { z } from "zod";

// ── loose format regexes (re-exported for the client via ipv6-api.ts) ───────

/** Full IPv6 body incl. "::" compression and v4-mapped tails (no zone id). */
const IPV6_BODY =
  "([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}" +
  "|([0-9a-fA-F]{1,4}:){1,7}:" +
  "|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}" +
  "|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}" +
  "|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}" +
  "|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}" +
  "|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}" +
  "|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})" +
  "|:((:[0-9a-fA-F]{1,4}){1,7}|:)" +
  "|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}" +
  "(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])" +
  "|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}" +
  "(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])";

export const IPV6_RE = new RegExp(`^(?:${IPV6_BODY})$`);
export const IPV6_CIDR_RE = new RegExp(`^(?:${IPV6_BODY})\\/(12[0-8]|1[01][0-9]|[0-9]{1,2})$`);

/**
 * Expand an IPv6 address to its 128-bit BigInt (null when not a valid v6
 * address). Handles "::" compression, full form and v4-mapped tails.
 */
export function ipv6ToBigInt(addr: string): bigint | null {
  const s = addr.trim().toLowerCase();
  if (!IPV6_RE.test(s)) return null;
  let head = s;
  let tail = "";
  if (s.includes("::")) {
    const parts = s.split("::");
    if (parts.length !== 2) return null;
    head = parts[0] ?? "";
    tail = parts[1] ?? "";
  }
  const headGroups = head === "" ? [] : head.split(":");
  const tailGroups = tail === "" ? [] : tail.split(":");
  // v4-mapped tail ("::ffff:1.2.3.4") — expand the dotted quad into 2 groups
  const lastTail = tailGroups[tailGroups.length - 1];
  if (lastTail !== undefined && lastTail.includes(".")) {
    const octets = lastTail.split(".");
    if (octets.length !== 4) return null;
    const nums: number[] = [];
    for (const o of octets) {
      const n = Number(o);
      if (!Number.isInteger(n) || n < 0 || n > 255) return null;
      nums.push(n);
    }
    tailGroups[tailGroups.length - 1] = ((nums[0] ?? 0) * 256 + (nums[1] ?? 0)).toString(16);
    tailGroups.push(((nums[2] ?? 0) * 256 + (nums[3] ?? 0)).toString(16));
  }
  const compressed = s.includes("::");
  const missing = 8 - headGroups.length - tailGroups.length;
  if (missing < 0 || (!compressed && missing !== 0)) return null;
  const groups = compressed
    ? [...headGroups, ...Array.from({ length: missing }, () => "0"), ...tailGroups]
    : [...headGroups, ...tailGroups];
  if (groups.length !== 8) return null;
  let value = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    value = (value << 16n) | BigInt(parseInt(g, 16));
  }
  return value;
}

// ── locked enums ────────────────────────────────────────────────────────────

export const PD_PREFIX_LENGTHS = [48, 52, 56, 60, 64] as const;
export const RA_MODES = ["disabled", "router_only", "slaac", "slaac_dhcpv6"] as const;
export const NAT66_TYPES = ["nptv6", "masquerade66", "dnat66"] as const;
export const DHCPV6_PREFIX_LENGTHS = [64, 128] as const;

export type PdPrefixLength = (typeof PD_PREFIX_LENGTHS)[number];
export type RaMode = (typeof RA_MODES)[number];
export type Nat66Type = (typeof NAT66_TYPES)[number];
export type Dhcpv6PrefixLength = (typeof DHCPV6_PREFIX_LENGTHS)[number];

const pdPrefixLengthSchema = z.union([
  z.literal(48),
  z.literal(52),
  z.literal(56),
  z.literal(60),
  z.literal(64),
]);

const raModeSchema = z.enum(["disabled", "router_only", "slaac", "slaac_dhcpv6"]);

const nat66TypeSchema = z.enum(["nptv6", "masquerade66", "dnat66"]);

const dhcpv6PrefixLengthSchema = z.union([z.literal(64), z.literal(128)]);

const ifaceNameSchema = z
  .string()
  .min(1)
  .max(32)
  .regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/, "invalid interface name");

const ipv6CidrSchema = z
  .string()
  .max(47)
  .regex(IPV6_CIDR_RE, "must be an IPv6 CIDR like 2001:db8:1::/48");

const ipv6AddrSchema = z
  .string()
  .max(45)
  .regex(IPV6_RE, "must be an IPv6 address like 2001:db8:1::100");

// ── settings singleton (spec 2.7 — full PUT) ────────────────────────────────

export const ipv6SettingsUpdateSchema = z.object({
  enabled: z.boolean(),
  dhcpv6Enabled: z.boolean(),
  slaacEnabled: z.boolean(),
  rdnssEnabled: z.boolean(),
  pdWanInterface: ifaceNameSchema,
  pdPrefixLength: pdPrefixLengthSchema,
  raMode: raModeSchema,
});

// ── NAT66 rules ─────────────────────────────────────────────────────────────

type Nat66Cross = {
  type: Nat66Type;
  sourcePrefix?: string | null;
  translatedPrefix?: string | null;
  destPort?: number | null;
};

/** nptv6 → both prefixes required + different; dnat66 → destPort required; else destPort forbidden. */
export function nat66Issues(v: Nat66Cross): Array<{ path: string; message: string }> {
  const issues: Array<{ path: string; message: string }> = [];
  if (v.type === "nptv6") {
    if (!v.sourcePrefix) issues.push({ path: "sourcePrefix", message: "source prefix is required for NPTv6" });
    if (!v.translatedPrefix)
      issues.push({ path: "translatedPrefix", message: "translated prefix is required for NPTv6" });
    if (
      v.sourcePrefix &&
      v.translatedPrefix &&
      v.sourcePrefix.trim().toLowerCase() === v.translatedPrefix.trim().toLowerCase()
    ) {
      issues.push({ path: "translatedPrefix", message: "translated prefix must differ from the source prefix" });
    }
  }
  if (v.type === "dnat66" && (v.destPort === undefined || v.destPort === null)) {
    issues.push({ path: "destPort", message: "destination port is required for DNAT66" });
  }
  if (v.type !== "dnat66" && v.destPort !== undefined && v.destPort !== null) {
    issues.push({ path: "destPort", message: "destination port applies to DNAT66 rules only" });
  }
  return issues;
}

function applyNat66Issues(ctx: z.RefinementCtx, v: Nat66Cross): void {
  for (const issue of nat66Issues(v)) ctx.addIssue({ code: "custom", path: [issue.path], message: issue.message });
}

/** Partial-aware cross-field check — only compares keys present in the patch;
 *  the service re-runs the FULL check after merging with the stored row. */
function applyNat66PartialIssues(ctx: z.RefinementCtx, v: Partial<Nat66Cross>): void {
  if (
    v.type === "nptv6" &&
    v.sourcePrefix &&
    v.translatedPrefix &&
    v.sourcePrefix.trim().toLowerCase() === v.translatedPrefix.trim().toLowerCase()
  ) {
    ctx.addIssue({
      code: "custom",
      path: ["translatedPrefix"],
      message: "translated prefix must differ from the source prefix",
    });
  }
  if (v.type !== undefined && v.destPort !== undefined && v.destPort !== null) {
    if (v.type === "dnat66" && (v.destPort < 1 || v.destPort > 65535)) {
      ctx.addIssue({ code: "custom", path: ["destPort"], message: "destination port out of range" });
    }
    if (v.type !== "dnat66") {
      ctx.addIssue({
        code: "custom",
        path: ["destPort"],
        message: "destination port applies to DNAT66 rules only",
      });
    }
  }
}

export const nat66CreateSchema = z
  .object({
    name: z.string().min(1).max(64),
    type: nat66TypeSchema.default("nptv6"),
    sourcePrefix: ipv6CidrSchema.optional().nullable(),
    translatedPrefix: ipv6CidrSchema.optional().nullable(),
    destPort: z.number().int().min(1).max(65535).optional().nullable(),
    interfaceName: ifaceNameSchema,
    enabled: z.boolean().default(true),
  })
  .superRefine((v, ctx) => applyNat66Issues(ctx, v));

/** Partial update without defaults (zod 4 — defaults survive `.partial()`). */
export const nat66UpdateSchema = z
  .object({
    name: z.string().min(1).max(64),
    type: nat66TypeSchema,
    sourcePrefix: ipv6CidrSchema.nullable(),
    translatedPrefix: ipv6CidrSchema.nullable(),
    destPort: z.number().int().min(1).max(65535).nullable(),
    interfaceName: ifaceNameSchema,
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" })
  .superRefine(applyNat66PartialIssues);

// ── DHCPv6 servers ──────────────────────────────────────────────────────────

const lifetimeSchema = z
  .number()
  .int()
  .min(60, "lifetime must be at least 60 seconds")
  .max(2592000, "lifetime must be at most 30 days");

type Dhcpv6Cross = {
  poolStart: string;
  poolEnd: string;
  preferredLifetime?: number;
  validLifetime?: number;
};

export function dhcpv6Issues(v: Dhcpv6Cross): Array<{ path: string; message: string }> {
  const issues: Array<{ path: string; message: string }> = [];
  const start = ipv6ToBigInt(v.poolStart);
  const end = ipv6ToBigInt(v.poolEnd);
  if (start !== null && end !== null && end <= start) {
    issues.push({ path: "poolEnd", message: "pool end must be greater than pool start" });
  }
  if (
    v.preferredLifetime !== undefined &&
    v.validLifetime !== undefined &&
    v.validLifetime < v.preferredLifetime
  ) {
    issues.push({ path: "validLifetime", message: "valid lifetime must be ≥ preferred lifetime" });
  }
  return issues;
}

function applyDhcpv6Issues(ctx: z.RefinementCtx, v: Dhcpv6Cross): void {
  for (const issue of dhcpv6Issues(v)) ctx.addIssue({ code: "custom", path: [issue.path], message: issue.message });
}

export const dhcpv6CreateSchema = z
  .object({
    interfaceName: ifaceNameSchema,
    poolStart: ipv6AddrSchema,
    poolEnd: ipv6AddrSchema,
    prefixLength: dhcpv6PrefixLengthSchema.default(64),
    preferredLifetime: lifetimeSchema.default(3600),
    validLifetime: lifetimeSchema.default(7200),
    dnsServers: z.array(ipv6AddrSchema).min(1, "at least one DNS server").max(8).default(["2001:db8:1::1"]),
    domainSearch: z.string().max(255).optional().nullable(),
    enabled: z.boolean().default(true),
  })
  .superRefine((v, ctx) => applyDhcpv6Issues(ctx, v));

/** Partial update without defaults — see nat66UpdateSchema note. */
export const dhcpv6UpdateSchema = z
  .object({
    interfaceName: ifaceNameSchema,
    poolStart: ipv6AddrSchema,
    poolEnd: ipv6AddrSchema,
    prefixLength: dhcpv6PrefixLengthSchema,
    preferredLifetime: lifetimeSchema,
    validLifetime: lifetimeSchema,
    dnsServers: z.array(ipv6AddrSchema).min(1, "at least one DNS server").max(8),
    domainSearch: z.string().max(255).nullable(),
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" })
  .superRefine((v, ctx) => {
    // pool / lifetime checks only when both halves of the comparison are present;
    // the service re-runs the FULL check after merging with the stored row
    if (v.poolStart !== undefined && v.poolEnd !== undefined) {
      applyDhcpv6Issues(ctx, {
        poolStart: v.poolStart,
        poolEnd: v.poolEnd,
        preferredLifetime: v.preferredLifetime,
        validLifetime: v.validLifetime,
      });
    }
  });

// ── inferred types (server shared.ts consumes these) ────────────────────────

export type Ipv6SettingsUpdate = z.infer<typeof ipv6SettingsUpdateSchema>;
export type Nat66Create = z.infer<typeof nat66CreateSchema>;
export type Nat66Update = z.infer<typeof nat66UpdateSchema>;
export type Dhcpv6Create = z.infer<typeof dhcpv6CreateSchema>;
export type Dhcpv6Update = z.infer<typeof dhcpv6UpdateSchema>;
