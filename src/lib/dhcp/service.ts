/**
 * DHCP service (M06) — subnets (IPv4 + basic DHCPv6), reservations, leases,
 * relay (ip-helper), and the engine runtime snapshot.
 * Per M06-DNS-DHCP.md §2/§3/§5 + SCHEMA.md §3. IP/CIDR math is family-aware
 * (v4 via 32-bit ints, v6 via BigInt) — overlap checks stay per-family
 * (M06 §5.3). Interface existence is a logical ref into interfaces.name.
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { parseJson, stringifyJson } from "@/lib/json";
import { assertIfacesExist } from "@/lib/network/iface-service";
import type {
  DhcpSubnetCreate,
  DhcpSubnetUpdate,
  DhcpReservationCreate,
  DhcpReservationUpdate,
  DhcpLeaseQuery,
  DhcpRelay,
} from "@/lib/validators/dns-dhcp";
import type { DhcpRuntime } from "@/lib/engine/generators/dhcp-leases";

export type { DhcpRelay };

// ── IP / CIDR math (family-aware) ───────────────────────────────────────────

const isV4 = (ip: string) => ip.includes(".") && !ip.includes(":");

export function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const v = Number(p);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = n * 256 + v;
  }
  return n >>> 0;
}

export function ipv6ToBigInt(ip: string): bigint | null {
  const halves = ip.split("::");
  if (halves.length > 2) return null;
  const groupsOf = (s: string): number[] | null => {
    if (s === "") return [];
    const out: number[] = [];
    for (const g of s.split(":")) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };
  let head: number[] | null, tail: number[] | null;
  if (halves.length === 2) {
    head = groupsOf(halves[0]);
    tail = groupsOf(halves[1]);
  } else {
    head = groupsOf(halves[0]);
    tail = [];
  }
  if (head === null || tail === null) return null;
  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 ? missing < 0 : missing !== 0) return null;
  const all = [...head, ...new Array(Math.max(0, missing)).fill(0), ...tail];
  let value = BigInt(0);
  const SIXTEEN = BigInt(16);
  for (const g of all) value = (value << SIXTEEN) | BigInt(g);
  return value;
}

type IpRange = { lo: bigint; hi: bigint };

export function cidrRange(cidr: string): IpRange | null {
  const [ipRaw, prefixRaw] = cidr.split("/");
  if (!ipRaw || prefixRaw === undefined) return null;
  const prefix = Number(prefixRaw);
  if (!Number.isInteger(prefix)) return null;
  if (isV4(ipRaw)) {
    if (prefix < 0 || prefix > 32) return null;
    const ip = ipv4ToInt(ipRaw);
    if (ip === null) return null;
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const lo = (ip & mask) >>> 0;
    const hi = (lo | (~mask >>> 0)) >>> 0;
    return { lo: BigInt(lo), hi: BigInt(hi) };
  }
  if (prefix < 0 || prefix > 128) return null;
  const ip = ipv6ToBigInt(ipRaw);
  if (ip === null) return null;
  const B0 = BigInt(0);
  const B1 = BigInt(1);
  const B128 = BigInt(128);
  const mask = prefix === 0 ? B0 : ((B1 << BigInt(prefix)) - B1) << BigInt(128 - prefix);
  const lo = ip & mask;
  const hi = lo | (~mask & ((B1 << B128) - B1));
  return { lo, hi };
}

export function ipInRange(ip: string, range: IpRange): boolean {
  const v = isV4(ip) ? (ipv4ToInt(ip) === null ? null : BigInt(ipv4ToInt(ip)!)) : ipv6ToBigInt(ip);
  return v !== null && v >= range.lo && v <= range.hi;
}

function rangesOverlap(a: IpRange, b: IpRange): boolean {
  return a.lo <= b.hi && b.lo <= a.hi;
}

const sameFamily = (a: string, b: string) => isV4(a) === isV4(b);

// ── DTOs ────────────────────────────────────────────────────────────────────

export type DhcpSubnetDTO = {
  id: number;
  interfaceName: string;
  family: string;
  subnetCidr: string;
  rangeStart: string;
  rangeEnd: string;
  gateway: string | null;
  dnsServers: string[];
  leaseTime: number;
  options: Record<string, string>;
  enabled: boolean;
  reservationCount: number;
  leaseCount: number;
  activeLeaseCount: number;
};

export type DhcpReservationDTO = {
  id: number;
  subnetId: number;
  mac: string;
  ip: string;
  hostname: string | null;
};

export type DhcpLeaseDTO = {
  id: number;
  subnetId: number;
  mac: string;
  ip: string;
  hostname: string | null;
  state: string;
  startsAt: string;
  endsAt: string;
};

function toSubnetDTO(
  row: {
    id: number;
    interfaceName: string;
    family: string;
    subnetCidr: string;
    rangeStart: string;
    rangeEnd: string;
    gateway: string | null;
    dnsServers: string;
    leaseTime: number;
    options: string;
    enabled: boolean;
  },
  counts: { reservations: number; leases: number; activeLeases: number },
): DhcpSubnetDTO {
  return {
    id: row.id,
    interfaceName: row.interfaceName,
    family: row.family,
    subnetCidr: row.subnetCidr,
    rangeStart: row.rangeStart,
    rangeEnd: row.rangeEnd,
    gateway: row.gateway,
    dnsServers: parseJson<string[]>(row.dnsServers, []),
    leaseTime: row.leaseTime,
    options: parseJson<Record<string, string>>(row.options, {}),
    enabled: row.enabled,
    reservationCount: counts.reservations,
    leaseCount: counts.leases,
    activeLeaseCount: counts.activeLeases,
  };
}

function toReservationDTO(row: { id: number; subnetId: number; mac: string; ip: string; hostname: string | null }): DhcpReservationDTO {
  return { id: row.id, subnetId: row.subnetId, mac: row.mac, ip: row.ip, hostname: row.hostname };
}

function toLeaseDTO(row: { id: number; subnetId: number; mac: string; ip: string; hostname: string | null; state: string; startsAt: Date; endsAt: Date }): DhcpLeaseDTO {
  return {
    id: row.id,
    subnetId: row.subnetId,
    mac: row.mac,
    ip: row.ip,
    hostname: row.hostname,
    state: row.state,
    startsAt: row.startsAt.toISOString(),
    endsAt: row.endsAt.toISOString(),
  };
}

const fieldErr = (field: string, message: string) =>
  ApiError.validation(message, { fieldErrors: { [field]: [message] } });

// ── Subnets ─────────────────────────────────────────────────────────────────

export async function listSubnets(tenantId: number): Promise<DhcpSubnetDTO[]> {
  const rows = await db.dhcpSubnet.findMany({ where: { tenantId }, orderBy: { id: "asc" } });
  const [activeBySubnet, resBySubnet, leaseBySubnet] = await Promise.all([
    db.dhcpLease.groupBy({ by: ["subnetId"], where: { tenantId, state: "active" }, _count: { _all: true } }),
    db.dhcpReservation.groupBy({ by: ["subnetId"], where: { tenantId }, _count: { _all: true } }),
    db.dhcpLease.groupBy({ by: ["subnetId"], where: { tenantId }, _count: { _all: true } }),
  ]);
  const activeMap = new Map(activeBySubnet.map((g) => [g.subnetId, g._count._all]));
  const resMap = new Map(resBySubnet.map((g) => [g.subnetId, g._count._all]));
  const leaseMap = new Map(leaseBySubnet.map((g) => [g.subnetId, g._count._all]));
  return rows.map((r) =>
    toSubnetDTO(r, {
      activeLeases: activeMap.get(r.id) ?? 0,
      reservations: resMap.get(r.id) ?? 0,
      leases: leaseMap.get(r.id) ?? 0,
    }),
  );
}

async function validateSubnetShape(tenantId: number, body: { interfaceName: string; family: string; subnetCidr: string; rangeStart: string; rangeEnd: string; gateway?: string | null | undefined }): Promise<void> {
  await assertIfacesExist(tenantId, [body.interfaceName]).catch(() => {
    throw fieldErr("interfaceName", `Interface "${body.interfaceName}" does not exist`);
  });
  const range = cidrRange(body.subnetCidr);
  if (!range) throw fieldErr("subnetCidr", `Not a valid ${body.family === "ipv6" ? "IPv6" : "IPv4"} CIDR`);
  const cidrIsV4 = isV4(body.subnetCidr.split("/")[0]);
  if ((body.family === "ipv4") !== cidrIsV4) {
    throw fieldErr("subnetCidr", `CIDR address family does not match family "${body.family}"`);
  }
  for (const [field, ip] of [["rangeStart", body.rangeStart], ["rangeEnd", body.rangeEnd]] as const) {
    if (!sameFamily(ip, body.subnetCidr) || !ipInRange(ip, range)) {
      throw fieldErr(field, `${ip} is outside ${body.subnetCidr}`);
    }
  }
  if (isV4(body.rangeStart) && isV4(body.rangeEnd)) {
    const s = ipv4ToInt(body.rangeStart)!;
    const e = ipv4ToInt(body.rangeEnd)!;
    if (s > e) throw fieldErr("rangeEnd", "rangeEnd must be ≥ rangeStart");
  } else if (!isV4(body.rangeStart)) {
    const s = ipv6ToBigInt(body.rangeStart)!;
    const e = ipv6ToBigInt(body.rangeEnd)!;
    if (s > e) throw fieldErr("rangeEnd", "rangeEnd must be ≥ rangeStart");
  }
  if (body.gateway) {
    if (!sameFamily(body.gateway, body.subnetCidr) || !ipInRange(body.gateway, range)) {
      throw fieldErr("gateway", `${body.gateway} is outside ${body.subnetCidr}`);
    }
  }
}

async function assertNoOverlap(tenantId: number, body: { interfaceName: string; family: string; subnetCidr: string; enabled: boolean }, excludeId?: number): Promise<void> {
  if (!body.enabled) return;
  const me = cidrRange(body.subnetCidr);
  if (!me) return;
  const others = await db.dhcpSubnet.findMany({
    where: { tenantId, interfaceName: body.interfaceName, family: body.family, enabled: true, ...(excludeId ? { NOT: { id: excludeId } } : {}) },
  });
  for (const other of others) {
    const their = cidrRange(other.subnetCidr);
    if (their && rangesOverlap(me, their)) {
      throw ApiError.conflict(`Overlaps enabled subnet "${other.subnetCidr}" on ${other.interfaceName} (id ${other.id})`);
    }
  }
}

export async function createSubnet(tenantId: number, body: DhcpSubnetCreate): Promise<DhcpSubnetDTO> {
  await validateSubnetShape(tenantId, body);
  await assertNoOverlap(tenantId, body);
  const row = await db.dhcpSubnet.create({
    data: {
      tenantId,
      interfaceName: body.interfaceName,
      family: body.family,
      subnetCidr: body.subnetCidr,
      rangeStart: body.rangeStart,
      rangeEnd: body.rangeEnd,
      gateway: body.gateway ?? null,
      dnsServers: stringifyJson(body.dnsServers),
      leaseTime: body.leaseTime,
      options: stringifyJson(body.options),
      enabled: body.enabled,
    },
  });
  return toSubnetDTO(row, { reservations: 0, leases: 0, activeLeases: 0 });
}

export async function updateSubnet(tenantId: number, id: number, body: DhcpSubnetUpdate): Promise<DhcpSubnetDTO> {
  const existing = await db.dhcpSubnet.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("Subnet not found");
  const merged = {
    interfaceName: body.interfaceName ?? existing.interfaceName,
    family: body.family ?? existing.family,
    subnetCidr: body.subnetCidr ?? existing.subnetCidr,
    rangeStart: body.rangeStart ?? existing.rangeStart,
    rangeEnd: body.rangeEnd ?? existing.rangeEnd,
    gateway: body.gateway !== undefined ? body.gateway : existing.gateway,
    enabled: body.enabled ?? existing.enabled,
  };
  await validateSubnetShape(tenantId, merged);
  await assertNoOverlap(tenantId, merged, id);
  const row = await db.dhcpSubnet.update({
    where: { id },
    data: {
      interfaceName: body.interfaceName ?? undefined,
      family: body.family ?? undefined,
      subnetCidr: body.subnetCidr ?? undefined,
      rangeStart: body.rangeStart ?? undefined,
      rangeEnd: body.rangeEnd ?? undefined,
      gateway: body.gateway !== undefined ? body.gateway : undefined,
      dnsServers: body.dnsServers ? stringifyJson(body.dnsServers) : undefined,
      leaseTime: body.leaseTime ?? undefined,
      options: body.options ? stringifyJson(body.options) : undefined,
      enabled: body.enabled ?? undefined,
    },
  });
  const [resCount, leaseCount, activeCount] = await Promise.all([
    db.dhcpReservation.count({ where: { subnetId: id } }),
    db.dhcpLease.count({ where: { subnetId: id } }),
    db.dhcpLease.count({ where: { subnetId: id, state: "active" } }),
  ]);
  return toSubnetDTO(row, { reservations: resCount, leases: leaseCount, activeLeases: activeCount });
}

export async function deleteSubnet(tenantId: number, id: number): Promise<{ reservations: number; leases: number }> {
  const existing = await db.dhcpSubnet.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("Subnet not found");
  const [reservations, leases] = await Promise.all([
    db.dhcpReservation.count({ where: { subnetId: id } }),
    db.dhcpLease.count({ where: { subnetId: id } }),
  ]);
  await db.dhcpSubnet.delete({ where: { id } }); // cascades reservations + leases (schema onDelete: Cascade)
  return { reservations, leases };
}

// ── Reservations ────────────────────────────────────────────────────────────

export async function listReservations(tenantId: number, subnetId?: number): Promise<DhcpReservationDTO[]> {
  const rows = await db.dhcpReservation.findMany({
    where: { tenantId, ...(subnetId ? { subnetId } : {}) },
    orderBy: { id: "asc" },
  });
  return rows.map(toReservationDTO);
}

async function assertReservationFits(tenantId: number, subnetId: number, ip: string): Promise<void> {
  const subnet = await db.dhcpSubnet.findFirst({ where: { tenantId, id: subnetId } });
  if (!subnet) throw fieldErr("subnetId", "Subnet not found");
  const range = cidrRange(subnet.subnetCidr);
  if (!range || !sameFamily(ip, subnet.subnetCidr) || !ipInRange(ip, range)) {
    throw fieldErr("ip", `${ip} is outside ${subnet.subnetCidr}`);
  }
}

export async function createReservation(tenantId: number, body: DhcpReservationCreate): Promise<DhcpReservationDTO> {
  await assertReservationFits(tenantId, body.subnetId, body.ip);
  const dup = await db.dhcpReservation.findFirst({ where: { tenantId, mac: body.mac } });
  if (dup) {
    throw ApiError.conflict(`MAC ${body.mac} is already reserved`, {
      conflicting: { id: dup.id, ip: dup.ip, hostname: dup.hostname },
    });
  }
  const row = await db.dhcpReservation.create({
    data: { tenantId, subnetId: body.subnetId, mac: body.mac, ip: body.ip, hostname: body.hostname ?? null },
  });
  return toReservationDTO(row);
}

export async function updateReservation(tenantId: number, id: number, body: DhcpReservationUpdate): Promise<DhcpReservationDTO> {
  const existing = await db.dhcpReservation.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("Reservation not found");
  const mergedSubnetId = body.subnetId ?? existing.subnetId;
  const mergedIp = body.ip ?? existing.ip;
  await assertReservationFits(tenantId, mergedSubnetId, mergedIp);
  const mergedMac = body.mac ?? existing.mac;
  if (mergedMac !== existing.mac) {
    const dup = await db.dhcpReservation.findFirst({ where: { tenantId, mac: mergedMac } });
    if (dup) {
      throw ApiError.conflict(`MAC ${mergedMac} is already reserved`, {
        conflicting: { id: dup.id, ip: dup.ip, hostname: dup.hostname },
      });
    }
  }
  const row = await db.dhcpReservation.update({
    where: { id },
    data: {
      subnetId: body.subnetId ?? undefined,
      mac: body.mac ?? undefined,
      ip: body.ip ?? undefined,
      hostname: body.hostname !== undefined ? body.hostname : undefined,
    },
  });
  return toReservationDTO(row);
}

export async function deleteReservation(tenantId: number, id: number): Promise<void> {
  const existing = await db.dhcpReservation.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("Reservation not found");
  await db.dhcpReservation.delete({ where: { id } });
}

// ── Leases ──────────────────────────────────────────────────────────────────

export async function listLeases(
  tenantId: number,
  query: DhcpLeaseQuery,
): Promise<{ data: DhcpLeaseDTO[]; meta: { page: number; limit: number; total: number; totalPages: number } }> {
  const where = {
    tenantId,
    ...(query.state ? { state: query.state } : {}),
    ...(query.subnetId ? { subnetId: query.subnetId } : {}),
    ...(query.q
      ? {
          OR: [
            { mac: { contains: query.q.toLowerCase() } },
            { ip: { contains: query.q } },
            { hostname: { contains: query.q } },
          ],
        }
      : {}),
  };
  const [total, rows] = await Promise.all([
    db.dhcpLease.count({ where }),
    db.dhcpLease.findMany({
      where,
      orderBy: [{ state: "asc" }, { endsAt: "desc" }],
      skip: (query.page - 1) * query.limit,
      take: query.limit,
    }),
  ]);
  return {
    data: rows.map(toLeaseDTO),
    meta: { page: query.page, limit: query.limit, total, totalPages: Math.max(1, Math.ceil(total / query.limit)) },
  };
}

/** Locked endpoint (ENDPOINTS §5) — force-release an active lease. */
export async function releaseLease(tenantId: number, id: number): Promise<DhcpLeaseDTO> {
  const existing = await db.dhcpLease.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("Lease not found");
  if (existing.state !== "active") {
    throw ApiError.conflict(`Lease ${id} is ${existing.state}, only active leases can be released`);
  }
  const row = await db.dhcpLease.update({ where: { id }, data: { state: "released" } });
  return toLeaseDTO(row);
}

// ── Relay (SystemSetting ("dhcp","relay")) ──────────────────────────────────

export async function getRelay(tenantId: number): Promise<DhcpRelay> {
  const row = await db.systemSetting.findUnique({
    where: { tenantId_category_key: { tenantId, category: "dhcp", key: "relay" } },
  });
  if (!row) return { enabled: false, servers: [], interfaces: [] };
  const parsed = parseJson<Partial<DhcpRelay>>(row.value, {});
  return { enabled: parsed.enabled ?? false, servers: parsed.servers ?? [], interfaces: parsed.interfaces ?? [] };
}

export async function putRelay(tenantId: number, relay: DhcpRelay): Promise<DhcpRelay> {
  await assertIfacesExist(tenantId, relay.interfaces).catch(() => {
    throw ApiError.validation("Unknown interface in relay interfaces list", {
      fieldErrors: { interfaces: ["One or more interfaces do not exist"] },
    });
  });
  await db.systemSetting.upsert({
    where: { tenantId_category_key: { tenantId, category: "dhcp", key: "relay" } },
    update: { value: stringifyJson(relay) },
    create: { tenantId, category: "dhcp", key: "relay", value: stringifyJson(relay) },
  });
  return relay;
}

// ── Engine runtime loader (lease churn input) ───────────────────────────────

export async function loadDhcpRuntime(tenantId: number): Promise<DhcpRuntime> {
  const subnets = await db.dhcpSubnet.findMany({
    where: { tenantId, enabled: true, family: "ipv4" }, // churn stays IPv4 (M06 §5.4)
    orderBy: { id: "asc" },
  });
  const reservations = await db.dhcpReservation.findMany({ where: { tenantId } });
  const leases = await db.dhcpLease.findMany({ where: { tenantId, state: "active" } });
  return {
    subnets: subnets.map((s) => ({
      id: s.id,
      subnetCidr: s.subnetCidr,
      rangeStart: s.rangeStart,
      rangeEnd: s.rangeEnd,
      leaseTime: s.leaseTime,
      dnsServers: parseJson<string[]>(s.dnsServers, []),
    })),
    reservations: reservations.map((r) => ({ subnetId: r.subnetId, mac: r.mac, ip: r.ip })),
    leases: leases.map((l) => ({
      id: l.id,
      subnetId: l.subnetId,
      mac: l.mac,
      ip: l.ip,
      hostname: l.hostname,
      endsAtMs: l.endsAt.getTime(),
      leaseTimeSec: subnets.find((s) => s.id === l.subnetId)?.leaseTime ?? 86400,
    })),
  };
}
