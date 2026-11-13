/**
 * IPS service layer (M04 §5) — business logic shared by the /api/v1/ips routes.
 * Handlers stay thin; RESTRICT checks, event filtering and the auto-update
 * simulation live here. ADR-017: sid:0 exceptions = any-SID capture bypass;
 * default policy = first enabled policy by id asc (seed order).
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { emitEvent } from "@/lib/engine/events";
import {
  PRESETS,
  categoryDef,
  parseJson,
  type ExceptionRow,
  type IpsPolicyDto,
  type PreprocessorMap,
  type ThresholdRow,
} from "./catalog";
import type { IpsEventsQuery, IpsPolicyCreateInput, IpsPolicyUpdateInput } from "@/lib/validators/ips";
import type { PageMeta } from "@/lib/api/envelope";

type PolicyRow = Awaited<ReturnType<typeof db.ipsPolicy.findFirst>>;

// ── shaping ─────────────────────────────────────────────────────────────────

export function shapePolicy(
  row: NonNullable<PolicyRow>,
  attached?: Array<{ id: number; name: string }>,
): IpsPolicyDto {
  return {
    id: row.id,
    name: row.name,
    mode: row.mode as IpsPolicyDto["mode"],
    enabled: row.enabled,
    ruleCategories: parseJson<Record<string, boolean>>(row.ruleCategories, {}),
    customRules: parseJson<string[]>(row.customRules, []),
    exceptions: parseJson<ExceptionRow[]>(row.exceptions, []),
    thresholds: parseJson<ThresholdRow[]>(row.thresholds, []),
    preprocessors: parseJson<Record<string, boolean>>(row.preprocessors, {}),
    tiBlocklist: row.tiBlocklist,
    attachedRuleCount: attached?.length ?? 0,
    attachedRuleNames: attached?.map((r) => r.name) ?? [],
  };
}

async function attachedRules(policyId: number): Promise<Array<{ id: number; name: string }>> {
  const rows = await db.firewallRule.findMany({
    where: { ipsPolicyId: policyId },
    select: { id: true, name: true },
    orderBy: { position: "asc" },
  });
  return rows;
}

// ── policy CRUD ─────────────────────────────────────────────────────────────

export async function listPolicies(tenantId: number): Promise<IpsPolicyDto[]> {
  const [rows, fwLinks] = await Promise.all([
    db.ipsPolicy.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
    db.firewallRule.findMany({
      where: { tenantId, ipsPolicyId: { not: null } },
      select: { id: true, name: true, ipsPolicyId: true },
      orderBy: { position: "asc" },
    }),
  ]);
  const byPolicy = new Map<number, Array<{ id: number; name: string }>>();
  for (const link of fwLinks) {
    if (link.ipsPolicyId == null) continue;
    const list = byPolicy.get(link.ipsPolicyId) ?? [];
    list.push({ id: link.id, name: link.name });
    byPolicy.set(link.ipsPolicyId, list);
  }
  return rows.map((r) => shapePolicy(r, byPolicy.get(r.id)));
}

export async function createPolicy(tenantId: number, body: IpsPolicyCreateInput): Promise<IpsPolicyDto> {
  const dup = await db.ipsPolicy.findFirst({ where: { tenantId, name: body.name } });
  if (dup) throw ApiError.conflict(`A policy named "${body.name}" already exists`);
  const created = await db.ipsPolicy.create({
    data: {
      tenantId,
      name: body.name,
      mode: body.mode,
      enabled: body.enabled,
      ruleCategories: JSON.stringify(body.ruleCategories),
      customRules: JSON.stringify(body.customRules),
      exceptions: JSON.stringify(body.exceptions),
      thresholds: JSON.stringify(body.thresholds),
      preprocessors: JSON.stringify(body.preprocessors),
      tiBlocklist: body.tiBlocklist,
    },
  });
  return shapePolicy(created);
}

export async function updatePolicy(
  tenantId: number,
  id: number,
  body: IpsPolicyUpdateInput,
): Promise<IpsPolicyDto> {
  const existing = await db.ipsPolicy.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("IPS policy not found");
  if (body.name !== undefined && body.name !== existing.name) {
    const dup = await db.ipsPolicy.findFirst({ where: { tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`A policy named "${body.name}" already exists`);
  }
  const updated = await db.ipsPolicy.update({
    where: { id },
    data: {
      ...(body.name !== undefined ? { name: body.name } : {}),
      ...(body.mode !== undefined ? { mode: body.mode } : {}),
      ...(body.enabled !== undefined ? { enabled: body.enabled } : {}),
      ...(body.ruleCategories !== undefined ? { ruleCategories: JSON.stringify(body.ruleCategories) } : {}),
      ...(body.customRules !== undefined ? { customRules: JSON.stringify(body.customRules) } : {}),
      ...(body.exceptions !== undefined ? { exceptions: JSON.stringify(body.exceptions) } : {}),
      ...(body.thresholds !== undefined ? { thresholds: JSON.stringify(body.thresholds) } : {}),
      ...(body.preprocessors !== undefined ? { preprocessors: JSON.stringify(body.preprocessors) } : {}),
      ...(body.tiBlocklist !== undefined ? { tiBlocklist: body.tiBlocklist } : {}),
    },
  });
  return shapePolicy(updated, await attachedRules(id));
}

/** M04 §3: delete RESTRICTs while any firewall rule references the policy. */
export async function deletePolicy(tenantId: number, id: number): Promise<void> {
  const existing = await db.ipsPolicy.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("IPS policy not found");
  const referencing = await db.firewallRule.findMany({
    where: { tenantId, ipsPolicyId: id },
    select: { id: true, name: true },
  });
  if (referencing.length > 0) {
    throw ApiError.conflict(
      `Policy is attached to ${referencing.length} firewall rule${referencing.length === 1 ? "" : "s"} — detach first`,
      {
        referencedBy: referencing.map((r) => ({ ruleId: r.id, ruleName: r.name, ruleType: "firewall" })),
      },
    );
  }
  await db.ipsPolicy.delete({ where: { id } });
}

// ── presets (DATA_PLANE §3.1) ───────────────────────────────────────────────

export async function applyPreset(
  tenantId: number,
  preset: keyof typeof PRESETS,
  name?: string,
  replacePolicyId?: number,
): Promise<IpsPolicyDto> {
  const bundle = PRESETS[preset];

  if (replacePolicyId) {
    const existing = await db.ipsPolicy.findFirst({ where: { tenantId, id: replacePolicyId } });
    if (!existing) throw ApiError.notFound("IPS policy not found");
    const updated = await db.ipsPolicy.update({
      where: { id: existing.id },
      data: {
        ruleCategories: JSON.stringify(bundle.categories),
        mode: bundle.mode,
      },
    });
    return shapePolicy(updated, await attachedRules(updated.id));
  }

  const finalName = (name ?? preset.toUpperCase()).trim();
  const dup = await db.ipsPolicy.findFirst({ where: { tenantId, name: finalName } });
  if (dup) throw ApiError.conflict(`A policy named "${finalName}" already exists`);
  const created = await db.ipsPolicy.create({
    data: {
      tenantId,
      name: finalName,
      mode: bundle.mode,
      enabled: true,
      ruleCategories: JSON.stringify(bundle.categories),
      preprocessors: JSON.stringify({ stream: true, http: true, tls: true, ssh: true }),
    },
  });
  return shapePolicy(created);
}

// ── events (M04 §3/§4) ──────────────────────────────────────────────────────

export interface IpsEventDto {
  id: number;
  timestamp: string;
  srcIp: string | null;
  srcPort: number | null;
  dstIp: string | null;
  dstPort: number | null;
  action: "alert" | "drop" | "reject" | "bypass" | "suppressed";
  sid: string | null;
  severity: "info" | "low" | "medium" | "high" | "critical";
  category: string | null;
  message: string | null;
  suppressedUntil: string | null;
}

function shapeEvent(row: Awaited<ReturnType<typeof db.ipsEvent.findFirst>>): IpsEventDto {
  return {
    id: row!.id,
    timestamp: row!.timestamp.toISOString(),
    srcIp: row!.srcIp,
    srcPort: row!.srcPort,
    dstIp: row!.dstIp,
    dstPort: row!.dstPort,
    action: row!.action as IpsEventDto["action"],
    sid: row!.sid,
    severity: row!.severity as IpsEventDto["severity"],
    category: row!.category,
    message: row!.message,
    suppressedUntil: row!.suppressedUntil ? row!.suppressedUntil.toISOString() : null,
  };
}

export async function queryEvents(
  tenantId: number,
  q: IpsEventsQuery,
): Promise<{ data: IpsEventDto[]; meta: PageMeta }> {
  const where = {
    tenantId,
    ...(q.sid ? { sid: q.sid } : {}),
    ...(q.category ? { category: q.category } : {}),
    ...(q.severity
      ? { severity: { in: q.severity.split(",").map((s) => s.trim()).filter(Boolean) } }
      : {}),
    ...(q.since || q.until
      ? {
          timestamp: {
            ...(q.since ? { gte: new Date(q.since) } : {}),
            ...(q.until ? { lte: new Date(q.until) } : {}),
          },
        }
      : {}),
    ...(q.q
      ? {
          OR: [
            { message: { contains: q.q } },
            { srcIp: { contains: q.q } },
            { dstIp: { contains: q.q } },
            { category: { contains: q.q } },
          ],
        }
      : {}),
  };

  const [rows, total] = await Promise.all([
    db.ipsEvent.findMany({
      where,
      orderBy: { timestamp: "desc" },
      skip: (q.page - 1) * q.limit,
      take: q.limit,
    }),
    db.ipsEvent.count({ where }),
  ]);

  return {
    data: rows.map(shapeEvent),
    meta: { page: q.page, limit: q.limit, total, totalPages: Math.max(1, Math.ceil(total / q.limit)) },
  };
}

/**
 * Suppress (M04 §5): `forever` → suppressedUntil stays null and action
 * carries the permanence (ENDPOINTS §3 convention); `24h`/`7d` set a
 * suppressedUntil deadline.
 */
export async function suppressEvent(tenantId: number, id: number, duration: "24h" | "7d" | "forever"): Promise<IpsEventDto> {
  const row = await db.ipsEvent.findFirst({ where: { tenantId, id } });
  if (!row) throw ApiError.notFound("IPS event not found");
  const now = new Date();
  const until = duration === "24h" ? new Date(now.getTime() + 24 * 3600_000)
    : duration === "7d" ? new Date(now.getTime() + 7 * 24 * 3600_000)
    : null;
  const updated = await db.ipsEvent.update({
    where: { id },
    data: { action: "suppressed", suppressedUntil: until },
  });
  return shapeEvent(updated);
}

// ── auto-update scheduler (M04 §4 Rule Updates card) ───────────────────────

export interface UpdateSettings {
  enabled: boolean;
  interval: "daily" | "weekly";
  time: string;
  source: string;
  lastUpdateAt: string | null;
  nextUpdateAt: string | null;
}

function settingKey(): { category: string; key: string } {
  return { category: "ips", key: "auto_update" };
}

function defaultSettings(): UpdateSettings {
  return {
    enabled: true, interval: "daily", time: "03:00", source: "et_free",
    lastUpdateAt: null, nextUpdateAt: null,
  };
}

export function computeNextUpdate(prev: UpdateSettings, from = new Date()): string | null {
  if (!prev.enabled) return null;
  const [hh, mm] = prev.time.split(":").map(Number);
  const next = new Date(from);
  next.setHours(hh, mm, 0, 0);
  if (next.getTime() <= from.getTime()) {
    if (prev.interval === "daily") next.setDate(next.getDate() + 1);
    else next.setDate(next.getDate() + (7 - ((next.getDay() + 6) % 7) || 7));
  }
  // weekly lands on the next Monday by convention
  if (prev.interval === "weekly" && next.getTime() <= from.getTime()) {
    next.setDate(next.getDate() + 7);
  }
  return next.toISOString();
}

export async function getUpdateSettings(tenantId: number): Promise<UpdateSettings> {
  const row = await db.systemSetting.findFirst({
    where: { tenantId, ...settingKey() },
  });
  const stored = row ? parseJson<Partial<UpdateSettings>>(row.value, {}) : {};
  const merged: UpdateSettings = { ...defaultSettings(), ...stored };
  // engine-side update-cycle simulation: when the window has passed, refresh
  if (merged.enabled && merged.nextUpdateAt && Date.parse(merged.nextUpdateAt) <= Date.now()) {
    merged.lastUpdateAt = new Date().toISOString();
    merged.nextUpdateAt = computeNextUpdate(merged);
    await db.systemSetting.update({ where: { id: row!.id }, data: { value: JSON.stringify(merged) } }).catch(() => {});
    emitEvent({ type: "config:updated", payload: { section: "ips" } });
  }
  return merged;
}

export async function putUpdateSettings(tenantId: number, body: { enabled: boolean; interval: "daily" | "weekly"; time: string }): Promise<UpdateSettings> {
  const row = await db.systemSetting.findFirst({ where: { tenantId, ...settingKey() } });
  const prev = row ? { ...defaultSettings(), ...parseJson<Partial<UpdateSettings>>(row.value, {}) } : defaultSettings();
  const next: UpdateSettings = { ...prev, enabled: body.enabled, interval: body.interval, time: body.time };
  // editing the schedule re-anchors nextUpdateAt from now
  const anchorChanged = prev.interval !== body.interval || prev.time !== body.time || !prev.enabled;
  next.nextUpdateAt = computeNextUpdate(next, anchorChanged ? new Date() : prev.lastUpdateAt ? new Date(Date.parse(prev.lastUpdateAt)) : new Date());
  if (!next.enabled) next.nextUpdateAt = null;
  if (row) {
    await db.systemSetting.update({ where: { id: row.id }, data: { value: JSON.stringify(next) } });
  } else {
    await db.systemSetting.create({ data: { tenantId, ...settingKey(), value: JSON.stringify(next) } });
  }
  return next;
}

export async function runUpdateNow(tenantId: number): Promise<UpdateSettings> {
  const row = await db.systemSetting.findFirst({ where: { tenantId, ...settingKey() } });
  const prev = row ? { ...defaultSettings(), ...parseJson<Partial<UpdateSettings>>(row.value, {}) } : defaultSettings();
  const next: UpdateSettings = { ...prev, lastUpdateAt: new Date().toISOString(), nextUpdateAt: computeNextUpdate(prev) };
  if (row) {
    await db.systemSetting.update({ where: { id: row.id }, data: { value: JSON.stringify(next) } });
  } else {
    await db.systemSetting.create({ data: { tenantId, ...settingKey(), value: JSON.stringify(next) } });
  }
  return next;
}

// ── generator state loader (engine) ─────────────────────────────────────────

export interface IpsPolicyState {
  id: number;
  name: string;
  mode: "inline_drop" | "inline_tap" | "passive";
  enabledCategories: string[];
  preprocessors: PreprocessorMap;
  tiBlocklist: boolean;
  exceptions: ExceptionRow[];
  thresholds: ThresholdRow[];
  /** true when attached to ≥1 enabled firewall rule (generator weighting) */
  attachedToEnabledRule: boolean;
}

export async function loadIpsPolicyStates(tenantId: number): Promise<IpsPolicyState[]> {
  const [policies, fwLinks] = await Promise.all([
    db.ipsPolicy.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
    db.firewallRule.findMany({
      where: { tenantId, ipsPolicyId: { not: null } },
      select: { ipsPolicyId: true, enabled: true },
    }),
  ]);
  const attachedEnabled = new Set(
    fwLinks.filter((l) => l.enabled && l.ipsPolicyId != null).map((l) => l.ipsPolicyId as number),
  );
  return policies
    .filter((p) => p.enabled)
    .map((p) => ({
      id: p.id,
      name: p.name,
      mode: p.mode as IpsPolicyState["mode"],
      enabledCategories: Object.entries(parseJson<Record<string, boolean>>(p.ruleCategories, {}))
        .filter(([, on]) => on)
        .map(([name]) => name),
      preprocessors: parseJson<PreprocessorMap>(p.preprocessors, {}),
      tiBlocklist: p.tiBlocklist,
      exceptions: parseJson<ExceptionRow[]>(p.exceptions, []),
      thresholds: parseJson<ThresholdRow[]>(p.thresholds, []),
      attachedToEnabledRule: attachedEnabled.has(p.id),
    }));
}

export { categoryDef };
