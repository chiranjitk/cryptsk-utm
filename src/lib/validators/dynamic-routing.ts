/**
 * Dynamic Routing (M19 §2.6) zod schemas — BGP neighbors, OSPF settings/
 * interfaces, policy objects (prefix lists / route maps / community lists),
 * BFD profiles and the simulated RIB. Cross-field rules live in superRefine:
 * holdtime ≥ 3×keepalive (BGP), dead ≥ 2×hello (OSPF), prefix-CIDR family
 * matching, unique entry seqs and AS:NN community syntax.
 */

import { z } from "zod";

// ── address helpers (pure, reused by routes for deterministic simulation) ───

export const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

export function isIpv4(value: string): boolean {
  return IPV4_RE.test(value);
}

/** `a.b.c.d/plen` — plen 0..32, host octets validated. */
export function isIpv4Cidr(value: string): boolean {
  const slash = value.indexOf("/");
  if (slash < 0) return false;
  const plenRaw = value.slice(slash + 1);
  if (!/^\d{1,3}$/.test(plenRaw)) return false;
  const plen = Number(plenRaw);
  if (plen > 32) return false;
  return isIpv4(value.slice(0, slash));
}

/** Loose IPv6 CIDR check — hex groups + `:` with plen 0..128 (sandbox scope). */
export function isIpv6Cidr(value: string): boolean {
  const slash = value.indexOf("/");
  if (slash < 0) return false;
  const addr = value.slice(0, slash);
  const plenRaw = value.slice(slash + 1);
  if (!/^\d{1,3}$/.test(plenRaw)) return false;
  if (Number(plenRaw) > 128) return false;
  return addr.includes(":") && /^[0-9a-fA-F:]+$/.test(addr) && addr.length >= 2;
}

/** FNV-1a over a dotted IPv4 string — deterministic 2..maxInclusive (session/rib sim). */
export function hashIpv4To(ip: string, maxInclusive: number, minInclusive = 1): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < ip.length; i++) {
    h ^= ip.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  const span = maxInclusive - minInclusive + 1;
  return minInclusive + (h % span);
}

// ── shared atoms ─────────────────────────────────────────────────────────────

const ipv4Field = z.string().refine(isIpv4, "must be a valid IPv4 address");
const cidrField = (family: "ipv4" | "ipv6") =>
  z.string().refine((v) => (family === "ipv4" ? isIpv4Cidr(v) : isIpv6Cidr(v)), {
    message: `must be a valid ${family} CIDR prefix`,
  });

export const prefixListFamilySchema = z.enum(["ipv4", "ipv6"]);
export const networkTypeSchema = z.enum(["broadcast", "p2p", "nbma"]);
export const ribProtocolSchema = z.enum(["bgp", "ospf", "static", "connected"]);
export const pfaActionSchema = z.enum(["permit", "deny"]);

/** "AS:NN" community — e.g. 65000:100. */
export const communityTagField = z
  .string()
  .trim()
  .regex(/^\d{1,10}:\d{1,10}$/, 'must be "AS:NN" (e.g. 65000:100)');

// ── BGP neighbors ────────────────────────────────────────────────────────────

const neighborBase = z.object({
  name: z.string().trim().min(1).max(64),
  remoteAs: z.coerce.number().int().min(1).max(4294967295),
  peerIp: z.string().trim().refine(isIpv4, "must be a valid IPv4 address"),
  peerIface: z.string().trim().max(32).optional().nullable(),
  password: z.string().min(1).max(128).optional().nullable(),
  keepaliveSec: z.coerce.number().int().min(3).max(3600),
  holdtimeSec: z.coerce.number().int().min(3).max(65535),
  gracefulRestart: z.boolean(),
  bfdEnabled: z.boolean(),
  bfdProfileId: z.coerce.number().int().positive().optional().nullable(),
  prefixListInId: z.coerce.number().int().positive().optional().nullable(),
  prefixListOutId: z.coerce.number().int().positive().optional().nullable(),
  routeMapInId: z.coerce.number().int().positive().optional().nullable(),
  routeMapOutId: z.coerce.number().int().positive().optional().nullable(),
  localAs: z.coerce.number().int().min(1).max(4294967295).optional().nullable(),
  ebgpMultihop: z.boolean(),
  enabled: z.boolean(),
});

/** holdtime ≥ 3×keepalive (RFC 4271 recommendation, spec 2.6). Guarded so
 *  partial updates that omit either field still pass. */
const holdtimeMessage = "holdtime must be at least 3× keepalive";
const holdtimeOk = (keepaliveSec?: number, holdtimeSec?: number): boolean =>
  keepaliveSec === undefined || holdtimeSec === undefined || holdtimeSec >= 3 * keepaliveSec;

export const bgpNeighborCreateSchema = neighborBase
  .extend({
    keepaliveSec: neighborBase.shape.keepaliveSec.default(60),
    holdtimeSec: neighborBase.shape.holdtimeSec.default(180),
    gracefulRestart: neighborBase.shape.gracefulRestart.default(false),
    bfdEnabled: neighborBase.shape.bfdEnabled.default(false),
    ebgpMultihop: neighborBase.shape.ebgpMultihop.default(false),
    enabled: neighborBase.shape.enabled.default(true),
  })
  .refine((v) => holdtimeOk(v.keepaliveSec, v.holdtimeSec), {
    message: holdtimeMessage,
    path: ["holdtimeSec"],
  });

/** Partial update without defaults (zod 4: defaults survive .partial() and
 *  would clobber missing keys — see validators/logs.ts note). */
export const bgpNeighborUpdateSchema = neighborBase
  .partial()
  .refine((v) => holdtimeOk(v.keepaliveSec, v.holdtimeSec), {
    message: holdtimeMessage,
    path: ["holdtimeSec"],
  });

export const bgpSessionActionSchema = z.object({
  action: z.enum(["start", "stop"]),
});

// ── OSPF ─────────────────────────────────────────────────────────────────────

export const ospfSettingsUpdateSchema = z.object({
  routerId: ipv4Field,
  referenceBandwidth: z.coerce.number().int().min(1).max(100000),
  gracefulRestart: z.boolean(),
  enabled: z.boolean(),
});

const ospfIfaceBase = z.object({
  interfaceName: z.string().trim().min(1).max(32),
  area: z.string().trim().refine(isIpv4, "area must be 0.0.0.0-format"),
  helloSec: z.coerce.number().int().min(1).max(600),
  deadSec: z.coerce.number().int().min(2).max(65535),
  cost: z.coerce.number().int().min(1).max(65535),
  networkType: networkTypeSchema,
  passive: z.boolean(),
  enabled: z.boolean(),
});

export const ospfInterfaceCreateSchema = ospfIfaceBase
  .extend({
    helloSec: ospfIfaceBase.shape.helloSec.default(10),
    deadSec: ospfIfaceBase.shape.deadSec.default(40),
    cost: ospfIfaceBase.shape.cost.default(10),
    networkType: ospfIfaceBase.shape.networkType.default("broadcast"),
    passive: ospfIfaceBase.shape.passive.default(false),
    enabled: ospfIfaceBase.shape.enabled.default(true),
  })
  .refine((v) => v.deadSec >= 2 * v.helloSec, {
    message: "dead interval must be at least 2× hello",
    path: ["deadSec"],
  });

export const ospfInterfaceUpdateSchema = ospfIfaceBase
  .partial()
  .refine(
    (v) =>
      v.helloSec === undefined ||
      v.deadSec === undefined ||
      v.deadSec >= 2 * v.helloSec,
    { message: "dead interval must be at least 2× hello", path: ["deadSec"] },
  );

// ── prefix lists ─────────────────────────────────────────────────────────────

export const prefixListEntrySchema = z.object({
  seq: z.coerce.number().int().min(1).max(4294967295),
  action: pfaActionSchema,
  prefix: z.string().trim().min(1),
  ge: z.coerce.number().int().min(0).max(128).optional().nullable(),
  le: z.coerce.number().int().min(0).max(128).optional().nullable(),
});

const prefixListBase = z.object({
  name: z.string().trim().min(1).max(64),
  family: prefixListFamilySchema,
  entries: z.array(prefixListEntrySchema).max(200),
});

/** Entries validated as a whole: CIDR matches family, seq unique, ge ≤ le. */
const refinePrefixList = (data: { family: "ipv4" | "ipv6"; entries: Array<{ seq: number; prefix: string; ge?: number | null; le?: number | null }> }): boolean => {
  const seqs = new Set<number>();
  for (const e of data.entries) {
    if (seqs.has(e.seq)) return false;
    seqs.add(e.seq);
    const ok = data.family === "ipv4" ? isIpv4Cidr(e.prefix) : isIpv6Cidr(e.prefix);
    if (!ok) return false;
    if (e.ge != null && e.le != null && e.ge > e.le) return false;
  }
  return true;
};

export const prefixListCreateSchema = prefixListBase.refine(refinePrefixList, {
  message: "entries must have unique seq, valid CIDR for the list family and ge ≤ le",
  path: ["entries"],
});

export const prefixListUpdateSchema = prefixListBase.partial().refine(
  (v) => {
    if (v.family === undefined || v.entries === undefined) return true;
    return refinePrefixList({ family: v.family, entries: v.entries });
  },
  { message: "entries must have unique seq, valid CIDR for the list family and ge ≤ le", path: ["entries"] },
);

// ── route maps ───────────────────────────────────────────────────────────────

export const routeMapEntrySchema = z
  .object({
    seq: z.coerce.number().int().min(1).max(4294967295),
    action: pfaActionSchema,
    matchPrefixListId: z.coerce.number().int().positive().optional().nullable(),
    matchCommunity: communityTagField.optional().nullable(),
    setLocalPref: z.coerce.number().int().min(0).max(65535).optional().nullable(),
    setMetric: z.coerce.number().int().min(0).max(4294967295).optional().nullable(),
    setCommunity: communityTagField.optional().nullable(),
  })
  .refine((e) => e.matchPrefixListId != null || e.matchCommunity != null, {
    message: "entry must match something (prefix list or community)",
    path: ["matchPrefixListId"],
  });

const routeMapBase = z.object({
  name: z.string().trim().min(1).max(64),
  entries: z.array(routeMapEntrySchema).max(200),
});

const seqsUnique = (entries: Array<{ seq: number }>): boolean => {
  const seen = new Set<number>();
  for (const e of entries) {
    if (seen.has(e.seq)) return false;
    seen.add(e.seq);
  }
  return true;
};

export const routeMapCreateSchema = routeMapBase.refine(
  (v) => seqsUnique(v.entries),
  { message: "entry seq must be unique within the route map", path: ["entries"] },
);

export const routeMapUpdateSchema = routeMapBase.partial().refine(
  (v) => v.entries === undefined || seqsUnique(v.entries),
  { message: "entry seq must be unique within the route map", path: ["entries"] },
);

// ── community lists ──────────────────────────────────────────────────────────

const communityListBase = z.object({
  name: z.string().trim().min(1).max(64),
  type: z.enum(["standard", "expanded"]),
  entries: z.array(z.string().trim().min(1).max(64)).max(200),
});

/** standard → strict AS:NN tags; expanded → each entry must compile as a regex. */
const refineCommunityEntries = (type: "standard" | "expanded", entries: string[]): boolean => {
  for (const e of entries) {
    if (type === "standard") {
      if (!/^\d{1,10}:\d{1,10}$/.test(e)) return false;
    } else {
      try {
        new RegExp(e);
      } catch {
        return false;
      }
    }
  }
  return true;
};

export const communityListCreateSchema = communityListBase.refine(
  (v) => refineCommunityEntries(v.type, v.entries),
  {
    message: 'standard entries must be "AS:NN"; expanded entries must be valid regex',
    path: ["entries"],
  },
);

export const communityListUpdateSchema = communityListBase.partial().refine(
  (v) => v.type === undefined || v.entries === undefined || refineCommunityEntries(v.type, v.entries),
  {
    message: 'standard entries must be "AS:NN"; expanded entries must be valid regex',
    path: ["entries"],
  },
);

// ── BFD profiles ─────────────────────────────────────────────────────────────

export const bfdProfileCreateSchema = z.object({
  name: z.string().trim().min(1).max(64),
  rxIntervalMs: z.coerce.number().int().min(50).max(60000).default(300),
  txIntervalMs: z.coerce.number().int().min(50).max(60000).default(300),
  detectMultiplier: z.coerce.number().int().min(2).max(50).default(3),
  enabled: z.boolean().default(true),
});

export const bfdProfileUpdateSchema = z
  .object({
    name: z.string().trim().min(1).max(64),
    rxIntervalMs: z.coerce.number().int().min(50).max(60000),
    txIntervalMs: z.coerce.number().int().min(50).max(60000),
    detectMultiplier: z.coerce.number().int().min(2).max(50),
    enabled: z.boolean(),
  })
  .partial()
  .refine((v) => Object.keys(v).length > 0, { message: "Empty update" });

// ── RIB list query ───────────────────────────────────────────────────────────

export const ribQuerySchema = z.object({
  protocol: ribProtocolSchema.optional(),
  q: z.string().max(64).optional(),
});

// ── inferred types (routes + client consume these) ───────────────────────────

export type BgpNeighborCreate = z.infer<typeof bgpNeighborCreateSchema>;
export type BgpNeighborUpdate = z.infer<typeof bgpNeighborUpdateSchema>;
export type OspfSettingsUpdate = z.infer<typeof ospfSettingsUpdateSchema>;
export type OspfInterfaceCreate = z.infer<typeof ospfInterfaceCreateSchema>;
export type OspfInterfaceUpdate = z.infer<typeof ospfInterfaceUpdateSchema>;
export type PrefixListCreate = z.infer<typeof prefixListCreateSchema>;
export type PrefixListUpdate = z.infer<typeof prefixListUpdateSchema>;
export type PrefixListEntry = z.infer<typeof prefixListEntrySchema>;
export type RouteMapCreate = z.infer<typeof routeMapCreateSchema>;
export type RouteMapUpdate = z.infer<typeof routeMapUpdateSchema>;
export type RouteMapEntry = z.infer<typeof routeMapEntrySchema>;
export type CommunityListCreate = z.infer<typeof communityListCreateSchema>;
export type CommunityListUpdate = z.infer<typeof communityListUpdateSchema>;
export type BfdProfileCreate = z.infer<typeof bfdProfileCreateSchema>;
export type BfdProfileUpdate = z.infer<typeof bfdProfileUpdateSchema>;
export type RibQuery = z.infer<typeof ribQuerySchema>;
