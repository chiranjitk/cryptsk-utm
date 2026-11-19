/**
 * Config anomaly service (spec §4.5 rule-based pass) — DB-backed half of the
 * module: loads enabled firewall rules + address/service objects (+ groups),
 * runs the pure detectors from anomaly.ts, and diffs the drafts against the
 * persisted ConfigAnomalyFinding rows.
 *
 * DEDUPE WINDOW (kind + subjectRef keying — documented contract):
 *   • A draft re-detected while its OPEN row exists never duplicates: the
 *     open row's detail/severity is refreshed in place (matches the DNS
 *     tunnel upsert contract — "updated, never duplicated").
 *   • A draft whose subject was already triaged (status resolved | ignored)
 *     is SKIPPED — manual triage is a standing suppression window keyed on
 *     kind+subjectRef, so "resolve then rescan" does not resurrect the same
 *     subject. A re-break of the SAME rule id stays suppressed (delete +
 *     recreate the rule to get a fresh subjectRef and fresh alerting).
 *   • OPEN rows the detectors no longer produce are auto-resolved
 *     (status=resolved + resolvedAt) — the config moved on, the finding dies.
 *
 * WAN zone classification (auto mode): zones named "WAN" (case-insensitive,
 * matching zone-service protected-zone semantics) OR zones holding an
 * interface whose role is "wan".
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { parseIdArray, parseJson, stringifyJson } from "@/lib/json";
import {
  detectAllAnomalies,
  KIND_SEVERITY,
  type AnomalyFindingDraft,
  type AnomalyFindingDetail,
  type AnomalyObjectRef,
  type AnomalyRule,
  type AnomalyServiceRef,
  type AnomalyKind,
  type AnomalySeverity,
} from "./anomaly";
import type {
  ConfigAnomalyFindingsQuery,
  ConfigAnomalyKind,
  ConfigAnomalySeverity,
  ConfigAnomalyStatus,
} from "@/lib/validators/config-anomaly";

// ── DTOs ────────────────────────────────────────────────────────────────────

export interface ConfigAnomalyFindingDTO {
  id: number;
  kind: ConfigAnomalyKind;
  severity: ConfigAnomalySeverity;
  subjectRef: string;
  detail: AnomalyFindingDetail;
  status: ConfigAnomalyStatus;
  detectedAt: string;
  resolvedAt: string | null;
}

export type ScanSummary = {
  /** total drafts produced by the rule-based detectors */
  detected: number;
  /** drafts persisted as NEW open findings */
  newOpen: number;
  /** open findings the detectors no longer produce → auto-resolved */
  autoResolved: number;
  /** detected drafts broken down per kind (persisted or not) */
  byKind: Record<ConfigAnomalyKind, number>;
};

export type ConfigAnomalyStats = {
  openTotal: number;
  openByKind: Record<ConfigAnomalyKind, number>;
  openBySeverity: Record<ConfigAnomalySeverity, number>;
  total: number;
  /** max detectedAt over ALL findings (any status) — last scan that found something */
  lastScanAt: string | null;
};

export type ScanInput = {
  /** override auto-derived WAN zones */
  wanZoneIds?: number[];
  /** gate the log_disabled detector (default true) */
  requireWanLogging?: boolean;
};

const KINDS: readonly ConfigAnomalyKind[] = [
  "any_any_rule",
  "wan_permissive",
  "unused_object",
  "shadowed_rule",
  "log_disabled",
  "duplicate_rule",
] as const;
const SEVERITIES: readonly ConfigAnomalySeverity[] = ["low", "medium", "high"] as const;

// ── row shaping ─────────────────────────────────────────────────────────────

function normalizeDetail(raw: string): AnomalyFindingDetail {
  const parsed = parseJson<Partial<AnomalyFindingDetail>>(raw, {});
  return {
    message: typeof parsed.message === "string" ? parsed.message : "",
    ruleIds: Array.isArray(parsed.ruleIds) ? parsed.ruleIds.filter((v): v is number => typeof v === "number") : [],
    suggestion: typeof parsed.suggestion === "string" ? parsed.suggestion : "",
  };
}

function toFindingDTO(row: {
  id: number;
  kind: string;
  severity: string;
  subjectRef: string;
  detail: string;
  status: string;
  detectedAt: Date;
  resolvedAt: Date | null;
}): ConfigAnomalyFindingDTO {
  return {
    id: row.id,
    kind: (KINDS as readonly string[]).includes(row.kind) ? (row.kind as ConfigAnomalyKind) : "any_any_rule",
    severity: (SEVERITIES as readonly string[]).includes(row.severity)
      ? (row.severity as ConfigAnomalySeverity)
      : "medium",
    subjectRef: row.subjectRef,
    detail: normalizeDetail(row.detail),
    status: row.status as ConfigAnomalyStatus,
    detectedAt: row.detectedAt.toISOString(),
    resolvedAt: row.resolvedAt ? row.resolvedAt.toISOString() : null,
  };
}

// ── WAN zones ───────────────────────────────────────────────────────────────

/** Zone ids classified WAN: name match (case-insensitive) or a member iface with role "wan". */
async function deriveWanZoneIds(tenantId: number): Promise<number[]> {
  const [zones, ifaces] = await Promise.all([
    db.zone.findMany({ where: { tenantId }, select: { id: true, name: true, interfaceNames: true } }),
    db.networkInterface.findMany({ where: { tenantId, role: "wan" }, select: { name: true } }),
  ]);
  const wanIfaceNames = new Set(ifaces.map((i) => i.name));
  const out: number[] = [];
  for (const z of zones) {
    if (z.name.toUpperCase() === "WAN") {
      out.push(z.id);
      continue;
    }
    // zone.interfaceNames holds iface NAME strings (not ids) — match them
    // against the wan-role interface names
    const memberNames = parseJson<string[]>(z.interfaceNames, []).filter((n): n is string => typeof n === "string");
    if (memberNames.some((n) => wanIfaceNames.has(n))) out.push(z.id);
  }
  return out;
}

// ── rule/object hydration ───────────────────────────────────────────────────

interface ServiceRow {
  id: number;
  protocol: string;
  dstPort: string | null;
}
interface GroupRow {
  id: number;
  memberIds: number[];
}

/**
 * Expand a rule's serviceIds to concrete service refs: direct service objects
 * plus members of referenced service groups (one-level — groups hold leaf ids).
 */
function expandServices(ids: number[], services: Map<number, ServiceRow>, groups: Map<number, GroupRow>): AnomalyServiceRef[] {
  const out: AnomalyServiceRef[] = [];
  const pushSvc = (id: number) => {
    const s = services.get(id);
    if (s) out.push({ protocol: s.protocol, dstPort: s.dstPort });
  };
  for (const id of ids) {
    const g = groups.get(id);
    if (g) {
      for (const m of g.memberIds) pushSvc(m);
    } else {
      pushSvc(id);
    }
  }
  return out;
}

async function loadAnomalyInputs(tenantId: number): Promise<{
  rules: AnomalyRule[];
  objects: AnomalyObjectRef[];
}> {
  const [fwRules, addressObjects, serviceObjects, addressGroups, serviceGroups] = await Promise.all([
    db.firewallRule.findMany({ where: { tenantId, enabled: true }, orderBy: [{ position: "asc" }, { id: "asc" }] }),
    db.addressObject.findMany({ where: { tenantId }, select: { id: true, name: true } }),
    db.serviceObject.findMany({ where: { tenantId }, select: { id: true, name: true, protocol: true, dstPort: true } }),
    db.addressGroup.findMany({ where: { tenantId }, select: { id: true, name: true, memberIds: true } }),
    db.serviceGroup.findMany({ where: { tenantId }, select: { id: true, name: true, memberIds: true } }),
  ]);

  const serviceMap = new Map<number, ServiceRow>(
    serviceObjects.map((s) => [s.id, { id: s.id, protocol: s.protocol, dstPort: s.dstPort }]),
  );
  const serviceGroupMap = new Map<number, GroupRow>(
    serviceGroups.map((g) => [g.id, { id: g.id, memberIds: parseIdArray(g.memberIds) }]),
  );

  const rules: AnomalyRule[] = fwRules.map((r) => ({
    id: r.id,
    name: r.name,
    enabled: r.enabled,
    position: r.position,
    action: r.action,
    logging: r.logging,
    srcZoneIds: parseIdArray(r.srcZoneIds),
    dstZoneIds: parseIdArray(r.dstZoneIds),
    srcAddrIds: parseIdArray(r.srcAddrIds),
    dstAddrIds: parseIdArray(r.dstAddrIds),
    serviceIds: parseIdArray(r.serviceIds),
    applicationIds: parseJson<string[]>(r.applicationIds, []).filter((v): v is string => typeof v === "string"),
    userIds: parseIdArray(r.userIds),
    srcMacs: parseJson<string[]>(r.srcMacs, []).filter((v): v is string => typeof v === "string"),
    scheduleId: r.scheduleId,
    family: r.family,
    services: expandServices(parseIdArray(r.serviceIds), serviceMap, serviceGroupMap),
  }));

  const objects: AnomalyObjectRef[] = [
    ...addressObjects.map((o) => ({ kind: "address" as const, id: o.id, name: o.name })),
    ...serviceObjects.map((o) => ({ kind: "service" as const, id: o.id, name: o.name })),
    ...addressGroups.map((g) => ({ kind: "address_group" as const, id: g.id, name: g.name, memberIds: parseIdArray(g.memberIds) })),
    ...serviceGroups.map((g) => ({ kind: "service_group" as const, id: g.id, name: g.name, memberIds: parseIdArray(g.memberIds) })),
  ];

  return { rules, objects };
}

// ── scan ────────────────────────────────────────────────────────────────────

/**
 * One rule-based scan pass: hydrate inputs → run all six pure detectors →
 * diff against persisted findings per the DEDUPE WINDOW contract (see file
 * docblock). Never resurrects triaged rows; auto-resolves stale open rows.
 */
export async function scanConfigAnomalies(tenantId: number, input: ScanInput = {}): Promise<ScanSummary> {
  const { rules, objects } = await loadAnomalyInputs(tenantId);
  const wanZones = input.wanZoneIds ?? (await deriveWanZoneIds(tenantId));

  const drafts: AnomalyFindingDraft[] = detectAllAnomalies(rules, {
    wanZones,
    objects,
    requireWanLogging: input.requireWanLogging ?? true,
  });

  const byKind = KINDS.reduce(
    (acc, k) => ({ ...acc, [k]: 0 }),
    {} as Record<ConfigAnomalyKind, number>,
  );
  for (const d of drafts) byKind[d.kind] += 1;

  const existing = await db.configAnomalyFinding.findMany({
    where: { tenantId },
    select: { id: true, kind: true, subjectRef: true, status: true, severity: true, detail: true },
  });
  interface ExistingRow {
    id: number;
    kind: string;
    subjectRef: string;
    status: string;
    severity: string;
    detail: string;
  }
  const openByKey = new Map<string, ExistingRow>();
  const triagedKeys = new Set<string>();
  for (const row of existing) {
    const key = `${row.kind}|${row.subjectRef}`;
    if (row.status === "open") openByKey.set(key, row);
    else triagedKeys.add(key);
  }

  let newOpen = 0;
  const detectedKeys = new Set<string>();
  for (const d of drafts) {
    const key = `${d.kind}|${d.subjectRef}`;
    detectedKeys.add(key);
    const open = openByKey.get(key);
    if (open) {
      // still real → refresh the persisted detail/severity in place, never duplicate
      if (open.detail !== stringifyJson(d.detail) || open.severity !== d.severity) {
        await db.configAnomalyFinding.update({
          where: { id: open.id },
          data: { detail: stringifyJson(d.detail), severity: d.severity },
        });
      }
      continue;
    }
    if (triagedKeys.has(key)) continue; // suppression window — no resurrection
    await db.configAnomalyFinding.create({
      data: {
        tenantId,
        kind: d.kind,
        severity: d.severity,
        subjectRef: d.subjectRef,
        detail: stringifyJson(d.detail),
        status: "open",
      },
    });
    newOpen += 1;
  }

  // open rows the detectors no longer produce → auto-resolve with resolvedAt
  const stale = existing.filter((row) => row.status === "open" && !detectedKeys.has(`${row.kind}|${row.subjectRef}`));
  const now = new Date();
  for (const row of stale) {
    await db.configAnomalyFinding.update({
      where: { id: row.id },
      data: { status: "resolved", resolvedAt: now },
    });
  }

  return { detected: drafts.length, newOpen, autoResolved: stale.length, byKind };
}

// ── findings listing / triage ───────────────────────────────────────────────

export async function listFindings(
  tenantId: number,
  filters: Partial<ConfigAnomalyFindingsQuery> = {},
): Promise<{ data: ConfigAnomalyFindingDTO[]; meta: { page: number; limit: number; total: number; totalPages: number } }> {
  const page = filters.page ?? 1;
  const limit = filters.limit ?? 50;
  const where = {
    tenantId,
    ...(filters.kind ? { kind: filters.kind } : {}),
    ...(filters.severity ? { severity: filters.severity } : {}),
    ...(filters.status ? { status: filters.status } : {}),
  };
  const [total, rows] = await Promise.all([
    db.configAnomalyFinding.count({ where }),
    db.configAnomalyFinding.findMany({
      where,
      orderBy: [{ detectedAt: "desc" }, { id: "desc" }],
      skip: (page - 1) * limit,
      take: limit,
    }),
  ]);
  return {
    data: rows.map(toFindingDTO),
    meta: { page, limit, total, totalPages: Math.max(1, Math.ceil(total / limit)) },
  };
}

const TRIAGE_STATUSES: readonly ConfigAnomalyStatus[] = ["resolved", "ignored"] as const;

/** Triage a finding — resolved (stamps resolvedAt) | ignored (clears it so the
 *  invariant "resolvedAt set iff resolved" holds). `open` is not settable here. */
export async function updateFindingStatus(tenantId: number, id: number, status: string): Promise<ConfigAnomalyFindingDTO> {
  if (!TRIAGE_STATUSES.includes(status as ConfigAnomalyStatus)) {
    throw ApiError.validation(`status must be one of ${TRIAGE_STATUSES.join(" | ")}`);
  }
  const existing = await db.configAnomalyFinding.findFirst({ where: { id, tenantId } });
  if (!existing) throw ApiError.notFound("Config anomaly finding not found");
  const row = await db.configAnomalyFinding.update({
    where: { id: existing.id },
    data: { status, ...(status === "resolved" ? { resolvedAt: new Date() } : { resolvedAt: null }) },
  });
  return toFindingDTO(row);
}

// ── stats (console strip) ───────────────────────────────────────────────────

export async function statsFindings(tenantId: number): Promise<ConfigAnomalyStats> {
  const [openGroupsByKind, openGroupsBySeverity, openTotal, total, lastRow] = await Promise.all([
    db.configAnomalyFinding.groupBy({ by: ["kind"], where: { tenantId, status: "open" }, _count: { _all: true } }),
    db.configAnomalyFinding.groupBy({ by: ["severity"], where: { tenantId, status: "open" }, _count: { _all: true } }),
    db.configAnomalyFinding.count({ where: { tenantId, status: "open" } }),
    db.configAnomalyFinding.count({ where: { tenantId } }),
    db.configAnomalyFinding.findFirst({
      where: { tenantId },
      orderBy: { detectedAt: "desc" },
      select: { detectedAt: true },
    }),
  ]);

  const openByKind = KINDS.reduce((acc, k) => ({ ...acc, [k]: 0 }), {} as Record<ConfigAnomalyKind, number>);
  for (const g of openGroupsByKind) {
    if ((KINDS as readonly string[]).includes(g.kind)) openByKind[g.kind as ConfigAnomalyKind] = g._count._all;
  }
  const openBySeverity = SEVERITIES.reduce((acc, s) => ({ ...acc, [s]: 0 }), {} as Record<ConfigAnomalySeverity, number>);
  for (const g of openGroupsBySeverity) {
    if ((SEVERITIES as readonly string[]).includes(g.severity)) openBySeverity[g.severity as ConfigAnomalySeverity] = g._count._all;
  }

  return {
    openTotal,
    openByKind,
    openBySeverity,
    total,
    lastScanAt: lastRow ? lastRow.detectedAt.toISOString() : null,
  };
}

// re-exported for API-layer typing convenience
export { KIND_SEVERITY };
export type { AnomalyKind, AnomalySeverity };
