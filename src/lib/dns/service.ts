/**
 * DNS service (M06) — policies, records, resolver settings, engine runtime.
 * Per M06-DNS-DHCP.md §2/§3/§5 + SCHEMA.md §3 (names verbatim). JSON columns
 * are string-serialized in SQLite (ADR-005) — parseJson/stringifyJson only.
 * Format-level validation (per-type record grammar) is zod's job;
 * DB-dependent checks (duplicate names, exact-duplicate records) live here.
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { parseJson, stringifyJson } from "@/lib/json";
import { dnsRecordCreateSchema } from "@/lib/validators/dns-dhcp";
import type {
  DnsPolicyCreate,
  DnsPolicyUpdate,
  DnsRecordCreate,
  DnsRecordUpdate,
  DnsRecordQuery,
  ResolverSettings,
} from "@/lib/validators/dns-dhcp";
import type { DnsPolicyRuntime } from "@/lib/engine/generators/dns-queries";

// ── DTOs (API consumers see real arrays, never raw JSON strings) ────────────

export type DnsPolicyDTO = {
  id: number;
  name: string;
  enabled: boolean;
  blockCategories: string[];
  customBlock: string[];
  customAllow: string[];
  action: string;
  sinkholeIp: string;
};

export type DnsRecordDTO = {
  id: number;
  zone: string;
  name: string;
  type: string;
  value: string;
  ttl: number;
  priority: number | null;
  enabled: boolean;
};

export type ResolverSettingsDTO = ResolverSettings;

const DEFAULT_RESOLVER: ResolverSettings = {
  forwarders: ["1.1.1.1"],
  cacheSizeMb: 64,
  rrl: false,
  dot: false,
  forwardZones: [],
  doh: { enabled: false, port: 443 },
};

function toPolicyDTO(row: {
  id: number;
  name: string;
  enabled: boolean;
  blockCategories: string;
  customBlock: string;
  customAllow: string;
  action: string;
  sinkholeIp: string;
}): DnsPolicyDTO {
  return {
    id: row.id,
    name: row.name,
    enabled: row.enabled,
    blockCategories: parseJson<string[]>(row.blockCategories, []),
    customBlock: parseJson<string[]>(row.customBlock, []),
    customAllow: parseJson<string[]>(row.customAllow, []),
    action: row.action,
    sinkholeIp: row.sinkholeIp,
  };
}

function toRecordDTO(row: {
  id: number;
  zone: string;
  name: string;
  type: string;
  value: string;
  ttl: number;
  priority: number | null;
  enabled: boolean;
}): DnsRecordDTO {
  return {
    id: row.id,
    zone: row.zone,
    name: row.name,
    type: row.type,
    value: row.value,
    ttl: row.ttl,
    priority: row.priority,
    enabled: row.enabled,
  };
}

// ── Policies ────────────────────────────────────────────────────────────────

export async function listPolicies(tenantId: number): Promise<DnsPolicyDTO[]> {
  const rows = await db.dnsPolicy.findMany({ where: { tenantId }, orderBy: { id: "asc" } });
  return rows.map(toPolicyDTO);
}

export async function createPolicy(tenantId: number, body: DnsPolicyCreate): Promise<DnsPolicyDTO> {
  const dup = await db.dnsPolicy.findFirst({ where: { tenantId, name: body.name } });
  if (dup) throw ApiError.conflict(`A policy named "${body.name}" already exists`);
  const row = await db.dnsPolicy.create({
    data: {
      tenantId,
      name: body.name,
      enabled: body.enabled,
      blockCategories: stringifyJson(body.blockCategories),
      customBlock: stringifyJson(body.customBlock),
      customAllow: stringifyJson(body.customAllow),
      action: body.action,
      sinkholeIp: body.sinkholeIp,
    },
  });
  return toPolicyDTO(row);
}

export async function updatePolicy(tenantId: number, id: number, body: DnsPolicyUpdate): Promise<DnsPolicyDTO> {
  const existing = await db.dnsPolicy.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("Policy not found");
  if (body.name && body.name !== existing.name) {
    const dup = await db.dnsPolicy.findFirst({ where: { tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`A policy named "${body.name}" already exists`);
  }
  const row = await db.dnsPolicy.update({
    where: { id },
    data: {
      name: body.name ?? undefined,
      enabled: body.enabled ?? undefined,
      blockCategories: body.blockCategories ? stringifyJson(body.blockCategories) : undefined,
      customBlock: body.customBlock ? stringifyJson(body.customBlock) : undefined,
      customAllow: body.customAllow ? stringifyJson(body.customAllow) : undefined,
      action: body.action ?? undefined,
      sinkholeIp: body.sinkholeIp ?? undefined,
    },
  });
  return toPolicyDTO(row);
}

export async function deletePolicy(tenantId: number, id: number): Promise<void> {
  const existing = await db.dnsPolicy.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("Policy not found");
  await db.dnsPolicy.delete({ where: { id } });
}

// ── Records ─────────────────────────────────────────────────────────────────

export async function listRecords(
  tenantId: number,
  query: DnsRecordQuery,
): Promise<{ data: DnsRecordDTO[]; meta: { page: number; limit: number; total: number; totalPages: number } }> {
  const where = {
    tenantId,
    ...(query.zone ? { zone: query.zone } : {}),
    ...(query.type ? { type: query.type } : {}),
    ...(query.q
      ? {
          OR: [
            { name: { contains: query.q } },
            { value: { contains: query.q } },
            { zone: { contains: query.q } },
          ],
        }
      : {}),
  };
  const [total, rows] = await Promise.all([
    db.dnsRecord.count({ where }),
    db.dnsRecord.findMany({
      where,
      orderBy: [{ zone: "asc" }, { name: "asc" }, { id: "asc" }],
      skip: (query.page - 1) * query.limit,
      take: query.limit,
    }),
  ]);
  return {
    data: rows.map(toRecordDTO),
    meta: { page: query.page, limit: query.limit, total, totalPages: Math.max(1, Math.ceil(total / query.limit)) },
  };
}

export async function createRecord(tenantId: number, body: DnsRecordCreate): Promise<DnsRecordDTO> {
  const dup = await db.dnsRecord.findFirst({
    where: { tenantId, zone: body.zone, name: body.name, type: body.type, value: body.value },
  });
  if (dup) throw ApiError.conflict(`An identical ${body.type} record already exists in "${body.zone}"`);
  const row = await db.dnsRecord.create({
    data: {
      tenantId,
      zone: body.zone,
      name: body.name,
      type: body.type,
      value: body.value,
      ttl: body.ttl,
      priority: body.priority ?? null,
      enabled: body.enabled,
    },
  });
  return toRecordDTO(row);
}

export async function updateRecord(tenantId: number, id: number, body: DnsRecordUpdate): Promise<DnsRecordDTO> {
  const existing = await db.dnsRecord.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("Record not found");
  const merged = {
    zone: body.zone ?? existing.zone,
    name: body.name ?? existing.name,
    type: body.type ?? existing.type,
    value: body.value ?? existing.value,
  };
  const dup = await db.dnsRecord.findFirst({
    where: { tenantId, zone: merged.zone, name: merged.name, type: merged.type, value: merged.value, NOT: { id } },
  });
  if (dup) throw ApiError.conflict(`An identical ${merged.type} record already exists in "${merged.zone}"`);
  // re-run the full per-type grammar on the merged record (update schema is
  // intentionally refinement-free — see validators/dns-dhcp.ts)
  const revalidated = dnsRecordCreateSchema.safeParse({
    zone: merged.zone,
    name: merged.name,
    type: merged.type,
    value: merged.value,
    ttl: body.ttl ?? existing.ttl,
    priority: body.priority !== undefined ? body.priority : existing.priority,
    enabled: body.enabled ?? existing.enabled,
  });
  if (!revalidated.success) {
    const fieldErrors: Record<string, string[]> = {};
    for (const issue of revalidated.error.issues) {
      const key = String(issue.path[0] ?? "form");
      (fieldErrors[key] ??= []).push(issue.message);
    }
    throw ApiError.validation("Record failed per-type validation", { fieldErrors });
  }
  const row = await db.dnsRecord.update({
    where: { id },
    data: {
      zone: body.zone ?? undefined,
      name: body.name ?? undefined,
      type: body.type ?? undefined,
      value: body.value ?? undefined,
      ttl: body.ttl ?? undefined,
      priority: body.priority !== undefined ? body.priority : undefined,
      enabled: body.enabled ?? undefined,
    },
  });
  return toRecordDTO(row);
}

export async function deleteRecord(tenantId: number, id: number): Promise<void> {
  const existing = await db.dnsRecord.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("Record not found");
  await db.dnsRecord.delete({ where: { id } });
}

// ── Resolver settings (SystemSetting ("dns","resolver")) ────────────────────

export async function getResolverSettings(tenantId: number): Promise<ResolverSettingsDTO> {
  const row = await db.systemSetting.findUnique({
    where: { tenantId_category_key: { tenantId, category: "dns", key: "resolver" } },
  });
  if (!row) return { ...DEFAULT_RESOLVER };
  const parsed = parseJson<Partial<ResolverSettings>>(row.value, {});
  return { ...DEFAULT_RESOLVER, ...parsed, doh: parsed.doh ?? DEFAULT_RESOLVER.doh };
}

export async function putResolverSettings(tenantId: number, settings: ResolverSettings): Promise<ResolverSettingsDTO> {
  await db.systemSetting.upsert({
    where: { tenantId_category_key: { tenantId, category: "dns", key: "resolver" } },
    update: { value: stringifyJson(settings) },
    create: { tenantId, category: "dns", key: "resolver", value: stringifyJson(settings) },
  });
  return settings;
}

// ── Engine runtime loader (mirrors loadIpsPolicyStates) ─────────────────────

export async function loadDnsRuntime(tenantId: number): Promise<DnsPolicyRuntime> {
  const [policies, resolver] = await Promise.all([
    db.dnsPolicy.findMany({ where: { tenantId, enabled: true }, orderBy: { id: "asc" } }),
    getResolverSettings(tenantId),
  ]);
  return {
    resolver,
    policies: policies.map((p) => ({
      id: p.id,
      name: p.name,
      action: p.action === "nxdomain" ? "nxdomain" : "sinkhole",
      sinkholeIp: p.sinkholeIp || "0.0.0.0",
      blockCategories: parseJson<string[]>(p.blockCategories, []).filter((c) =>
        ["ads", "malware", "phishing", "adult", "social", "gambling"].includes(c),
      ),
      customBlock: parseJson<string[]>(p.customBlock, []),
      customAllow: parseJson<string[]>(p.customAllow, []),
    })),
  };
}
