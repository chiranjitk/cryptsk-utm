/**
 * IPv6 Dual-Stack service (M21, spec 2.7) — settings singleton, NAT66 rules,
 * DHCPv6 servers, the computed dual-stack status and the SIMULATED IA_PD
 * prefix-delegation lease (the real appliance delegates via DHCPv6-PD on the
 * selected WAN interface; here the prefix is derived deterministically from
 * tenant + WAN interface via an FNV-1a hash). All queries are tenant-scoped;
 * mutations are audited by the route layer, which snapshots section `ipv6`.
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import type { Dhcpv6Server, Ipv6Settings, Nat66Rule } from "@prisma/client";
import type {
  Dhcpv6Create,
  Dhcpv6Update,
  Ipv6SettingsUpdate,
  Nat66Create,
  Nat66Update,
  RaMode,
} from "@/lib/validators/ipv6";
import { nat66Issues, dhcpv6Issues } from "@/lib/validators/ipv6";

// ── DTOs (mirrored in components/views/ipv6/ipv6-api.ts) ────────────────────

export interface Ipv6SettingsDTO {
  id: number;
  enabled: boolean;
  dhcpv6Enabled: boolean;
  slaacEnabled: boolean;
  rdnssEnabled: boolean;
  pdWanInterface: string;
  pdPrefixLength: number;
  raMode: RaMode;
  createdAt: string;
}

export interface Nat66RuleDTO {
  id: number;
  name: string;
  type: "nptv6" | "masquerade66" | "dnat66";
  sourcePrefix: string | null;
  translatedPrefix: string | null;
  destPort: number | null;
  interfaceName: string;
  enabled: boolean;
  hitCount: number;
  createdAt: string;
}

export interface Dhcpv6ServerDTO {
  id: number;
  interfaceName: string;
  poolStart: string;
  poolEnd: string;
  prefixLength: number;
  preferredLifetime: number;
  validLifetime: number;
  dnsServers: string[];
  domainSearch: string | null;
  enabled: boolean;
}

export interface Ipv6StatusDTO {
  enabled: boolean;
  delegatedPrefix: string;
  raMode: RaMode;
  dhcpv6Enabled: boolean;
  slaacEnabled: boolean;
  v6FirewallRules: number;
  nat66: { total: number; enabled: number };
  dhcpv6: { servers: number; enabledServers: number };
}

export interface PrefixDelegationDTO {
  prefix: string;
  validLifetime: number;
  preferredLifetime: number;
  iaId: string;
  lastRenew: string;
}

// ── mappers ─────────────────────────────────────────────────────────────────

export function toSettingsDTO(row: Ipv6Settings): Ipv6SettingsDTO {
  return {
    id: row.id,
    enabled: row.enabled,
    dhcpv6Enabled: row.dhcpv6Enabled,
    slaacEnabled: row.slaacEnabled,
    rdnssEnabled: row.rdnssEnabled,
    pdWanInterface: row.pdWanInterface,
    pdPrefixLength: row.pdPrefixLength,
    raMode: row.raMode as RaMode,
    createdAt: row.createdAt.toISOString(),
  };
}

export function toNat66DTO(row: Nat66Rule): Nat66RuleDTO {
  return {
    id: row.id,
    name: row.name,
    type: row.type as Nat66RuleDTO["type"],
    sourcePrefix: row.sourcePrefix,
    translatedPrefix: row.translatedPrefix,
    destPort: row.destPort,
    interfaceName: row.interfaceName,
    enabled: row.enabled,
    hitCount: row.hitCount,
    createdAt: row.createdAt.toISOString(),
  };
}

export function toDhcpv6DTO(row: Dhcpv6Server): Dhcpv6ServerDTO {
  let dnsServers: string[] = [];
  try {
    const parsed: unknown = JSON.parse(row.dnsServers);
    if (Array.isArray(parsed)) dnsServers = parsed.filter((s): s is string => typeof s === "string");
  } catch {
    dnsServers = [];
  }
  return {
    id: row.id,
    interfaceName: row.interfaceName,
    poolStart: row.poolStart,
    poolEnd: row.poolEnd,
    prefixLength: row.prefixLength,
    preferredLifetime: row.preferredLifetime,
    validLifetime: row.validLifetime,
    dnsServers,
    domainSearch: row.domainSearch,
    enabled: row.enabled,
  };
}

// ── shared guards ───────────────────────────────────────────────────────────

/** Interface must exist for the tenant (db.networkInterface is the source of truth). */
export async function assertInterfaceExists(tenantId: number, name: string): Promise<void> {
  const iface = await db.networkInterface.findFirst({
    where: { tenantId, name },
    select: { id: true },
  });
  if (!iface) {
    throw ApiError.validation(`Interface '${name}' does not exist`, {
      fieldErrors: { interfaceName: [`Interface '${name}' does not exist`] },
    });
  }
}

async function interfaceNameSet(tenantId: number): Promise<Set<string>> {
  const rows = await db.networkInterface.findMany({ where: { tenantId }, select: { name: true } });
  return new Set(rows.map((r) => r.name));
}

/** FNV-1a 32-bit — deterministic demo hashing for the IA_PD lease. */
function fnv1a32(input: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

/** Zero-align the 4th hextet to the delegated prefix length boundary. */
function alignedGroup(h: number, prefixLength: number): string {
  if (prefixLength <= 48) return "0";
  if (prefixLength >= 64) return (h & 0xffff).toString(16).padStart(4, "0");
  const bits = prefixLength - 48; // 52→0xf000, 56→0xff00, 60→0xfff0
  const masked = (h >>> (16 - bits)) << (16 - bits);
  return (masked & 0xffff).toString(16).padStart(4, "0");
}

/**
 * Deterministic delegated prefix "2001:db8:xxxx(:yyyy)::/len" from
 * tenant + WAN interface + requested length (demo — no persistence).
 */
export function delegatedPrefixFor(tenantId: number, wanInterface: string, prefixLength: number): string {
  const h = fnv1a32(`${tenantId}:${wanInterface}:pd`);
  const g1 = ((h >>> 16) & 0xffff).toString(16).padStart(4, "0");
  const g2 = alignedGroup(h, prefixLength);
  return prefixLength <= 48
    ? `2001:db8:${g1}::/${prefixLength}`
    : `2001:db8:${g1}:${g2}::/${prefixLength}`;
}

// ── settings singleton ──────────────────────────────────────────────────────

/** First GET auto-creates the tenant row (spec defaults — no unique key, so find+create). */
export async function getOrCreateSettings(tenantId: number): Promise<Ipv6Settings> {
  const existing = await db.ipv6Settings.findFirst({ where: { tenantId } });
  if (existing) return existing;
  return db.ipv6Settings.create({
    data: {
      tenantId,
      enabled: true,
      dhcpv6Enabled: true,
      slaacEnabled: true,
      rdnssEnabled: true,
      pdWanInterface: "wan0",
      pdPrefixLength: 56,
      raMode: "slaac_dhcpv6",
    },
  });
}

export async function updateSettings(tenantId: number, body: Ipv6SettingsUpdate): Promise<Ipv6Settings> {
  await assertInterfaceExists(tenantId, body.pdWanInterface);
  const current = await getOrCreateSettings(tenantId);
  return db.ipv6Settings.update({ where: { id: current.id }, data: { ...body } });
}

// ── NAT66 rules ─────────────────────────────────────────────────────────────

export async function listNat66Rules(tenantId: number): Promise<Nat66RuleDTO[]> {
  const rows = await db.nat66Rule.findMany({ where: { tenantId }, orderBy: { id: "asc" } });
  return rows.map(toNat66DTO);
}

function validateNat66Values(v: {
  type: string;
  sourcePrefix: string | null | undefined;
  translatedPrefix: string | null | undefined;
  destPort: number | null | undefined;
}): void {
  for (const issue of nat66Issues({
    type: v.type as Nat66Create["type"],
    sourcePrefix: v.sourcePrefix ?? null,
    translatedPrefix: v.translatedPrefix ?? null,
    destPort: v.destPort ?? null,
  })) {
    throw ApiError.validation(issue.message, { fieldErrors: { [issue.path]: [issue.message] } });
  }
}

export async function createNat66Rule(tenantId: number, body: Nat66Create): Promise<Nat66RuleDTO> {
  await assertInterfaceExists(tenantId, body.interfaceName);
  validateNat66Values(body);
  const created = await db.nat66Rule.create({ data: { tenantId, ...body } });
  return toNat66DTO(created);
}

export async function updateNat66Rule(
  tenantId: number,
  id: number,
  body: Nat66Update,
): Promise<Nat66RuleDTO> {
  const current = await db.nat66Rule.findFirst({ where: { id, tenantId } });
  if (!current) throw ApiError.notFound("NAT66 rule not found");
  if (body.interfaceName !== undefined && body.interfaceName !== current.interfaceName) {
    await assertInterfaceExists(tenantId, body.interfaceName);
  }
  const merged = {
    type: body.type ?? current.type,
    sourcePrefix: body.sourcePrefix !== undefined ? body.sourcePrefix : current.sourcePrefix,
    translatedPrefix:
      body.translatedPrefix !== undefined ? body.translatedPrefix : current.translatedPrefix,
    destPort: body.destPort !== undefined ? body.destPort : current.destPort,
  };
  validateNat66Values(merged);
  const updated = await db.nat66Rule.update({ where: { id: current.id }, data: body });
  return toNat66DTO(updated);
}

export async function deleteNat66Rule(tenantId: number, id: number): Promise<void> {
  const existing = await db.nat66Rule.findFirst({ where: { id, tenantId }, select: { id: true } });
  if (!existing) throw ApiError.notFound("NAT66 rule not found");
  await db.nat66Rule.delete({ where: { id: existing.id } });
}

/**
 * Simulated hit counter — deterministic +1..5 per call (rule id + current hits
 * drive the bucket), so the demo counters move like live traffic.
 */
export async function simulateNat66Hit(tenantId: number, id: number): Promise<Nat66RuleDTO> {
  const rule = await db.nat66Rule.findFirst({ where: { id, tenantId } });
  if (!rule) throw ApiError.notFound("NAT66 rule not found");
  const delta = (((rule.hitCount + rule.id * 7) % 5) + (rule.enabled ? 0 : 2)) % 5;
  const updated = await db.nat66Rule.update({
    where: { id: rule.id },
    data: { hitCount: { increment: delta + 1 } },
  });
  return toNat66DTO(updated);
}

// ── DHCPv6 servers ──────────────────────────────────────────────────────────

export async function listDhcpv6Servers(tenantId: number): Promise<Dhcpv6ServerDTO[]> {
  const rows = await db.dhcpv6Server.findMany({ where: { tenantId }, orderBy: { id: "asc" } });
  return rows.map(toDhcpv6DTO);
}

function validateDhcpv6Values(v: {
  poolStart: string;
  poolEnd: string;
  preferredLifetime: number;
  validLifetime: number;
}): void {
  for (const issue of dhcpv6Issues(v)) {
    throw ApiError.validation(issue.message, { fieldErrors: { [issue.path]: [issue.message] } });
  }
}

export async function createDhcpv6Server(tenantId: number, body: Dhcpv6Create): Promise<Dhcpv6ServerDTO> {
  await assertInterfaceExists(tenantId, body.interfaceName);
  validateDhcpv6Values(body);
  const created = await db.dhcpv6Server.create({
    data: { tenantId, ...body, dnsServers: JSON.stringify(body.dnsServers) },
  });
  return toDhcpv6DTO(created);
}

export async function updateDhcpv6Server(
  tenantId: number,
  id: number,
  body: Dhcpv6Update,
): Promise<Dhcpv6ServerDTO> {
  const current = await db.dhcpv6Server.findFirst({ where: { id, tenantId } });
  if (!current) throw ApiError.notFound("DHCPv6 server not found");
  if (body.interfaceName !== undefined && body.interfaceName !== current.interfaceName) {
    await assertInterfaceExists(tenantId, body.interfaceName);
  }
  const merged = {
    poolStart: body.poolStart ?? current.poolStart,
    poolEnd: body.poolEnd ?? current.poolEnd,
    preferredLifetime: body.preferredLifetime ?? current.preferredLifetime,
    validLifetime: body.validLifetime ?? current.validLifetime,
  };
  validateDhcpv6Values(merged);
  const updated = await db.dhcpv6Server.update({
    where: { id: current.id },
    data: {
      ...body,
      ...(body.dnsServers !== undefined ? { dnsServers: JSON.stringify(body.dnsServers) } : {}),
    },
  });
  return toDhcpv6DTO(updated);
}

export async function deleteDhcpv6Server(tenantId: number, id: number): Promise<void> {
  const existing = await db.dhcpv6Server.findFirst({ where: { id, tenantId }, select: { id: true } });
  if (!existing) throw ApiError.notFound("DHCPv6 server not found");
  await db.dhcpv6Server.delete({ where: { id: existing.id } });
}

// ── status + prefix delegation ──────────────────────────────────────────────

export async function getIpv6Status(tenantId: number): Promise<Ipv6StatusDTO> {
  const settings = await getOrCreateSettings(tenantId);
  const [v6FirewallRules, natTotal, natEnabled, dhcpTotal, dhcpEnabled, ifaceNames] = await Promise.all([
    db.firewallRule.count({ where: { tenantId, family: { in: ["ipv6", "both"] } } }),
    db.nat66Rule.count({ where: { tenantId } }),
    db.nat66Rule.count({ where: { tenantId, enabled: true } }),
    db.dhcpv6Server.count({ where: { tenantId } }),
    db.dhcpv6Server.count({ where: { tenantId, enabled: true } }),
    interfaceNameSet(tenantId),
  ]);
  const wanIf = ifaceNames.has(settings.pdWanInterface) ? settings.pdWanInterface : "wan0";
  return {
    enabled: settings.enabled,
    delegatedPrefix: delegatedPrefixFor(tenantId, wanIf, settings.pdPrefixLength),
    raMode: settings.raMode as RaMode,
    dhcpv6Enabled: settings.dhcpv6Enabled,
    slaacEnabled: settings.slaacEnabled,
    v6FirewallRules,
    nat66: { total: natTotal, enabled: natEnabled },
    dhcpv6: { servers: dhcpTotal, enabledServers: dhcpEnabled },
  };
}

export async function getPrefixDelegation(tenantId: number): Promise<PrefixDelegationDTO> {
  const settings = await getOrCreateSettings(tenantId);
  const ifaceNames = await interfaceNameSet(tenantId);
  const wanIf = ifaceNames.has(settings.pdWanInterface) ? settings.pdWanInterface : "wan0";
  const iaHash = fnv1a32(`${tenantId}:iaid:${wanIf}`);
  return {
    prefix: delegatedPrefixFor(tenantId, wanIf, settings.pdPrefixLength),
    validLifetime: 86400,
    preferredLifetime: 43200,
    iaId: `IA_PD-${iaHash.toString(16).toUpperCase().padStart(8, "0")}`,
    lastRenew: new Date().toISOString(),
  };
}
