/**
 * DLP service (Phase 3 §3.3) — patterns, policies, incidents, scan
 * orchestration and stats. Per SCHEMA §3, protocols/patternIds/fileTypes and
 * the incident detail are JSON-string columns parsed per column
 * (PROJECT_MEMORY §13); policyId/patternId on incidents are LOGICAL refs (no
 * FK) so names are resolved by map lookup and survive referenced-row deletes.
 *
 * Redaction (HARD CONSTRAINT): incidents store only engine-redacted excerpts
 * — the matched span is masked with █ before anything reaches the DB.
 *
 * Scan orchestration: load enabled policies whose protocols contain the scan
 * protocol → load their enabled patterns → engine.scanPayload (pure) → one
 * DlpIncident per (policy, matched pattern) with the policy's action →
 * notifyUser + block/quarantine also writes a Notification row (direct
 * db.notification write, read-style after lib/notifications/service.ts).
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { parseJson, stringifyJson } from "@/lib/json";
import { containsNestedQuantifier } from "@/lib/validators/dlp";
import { scanPayload, splitKeywords, type DlpMatch, type DlpPatternInput } from "./engine";
import type {
  DlpAction,
  DlpCategory,
  DlpIncidentStatus,
  DlpIncidentsQuery,
  DlpKind,
  DlpPatternCreate,
  DlpPatternUpdate,
  DlpPolicyCreate,
  DlpPolicyUpdate,
  DlpScanInput,
  DlpSeverity,
} from "@/lib/validators/dlp";

// ── DTOs ────────────────────────────────────────────────────────────────────

export interface DlpPatternDTO {
  id: number;
  name: string;
  kind: DlpKind;
  value: string;
  severity: DlpSeverity;
  category: DlpCategory;
  enabled: boolean;
  /** resolved keyword list (kind=keyword) — empty for regex patterns */
  keywords: string[];
  createdAt: string;
}

export interface DlpPolicyDTO {
  id: number;
  name: string;
  protocols: string[];
  patternIds: number[];
  /** resolved pattern names for the multi-select chips */
  patternNames: Record<number, string>;
  fileTypes: string[];
  action: DlpAction;
  notifyUser: boolean;
  enabled: boolean;
  createdAt: string;
}

export interface DlpIncidentDTO {
  id: number;
  policyId: number;
  policyName: string | null;
  patternId: number;
  patternName: string | null;
  severity: DlpSeverity;
  protocol: string;
  sourceIp: string;
  userName: string | null;
  /** engine-redacted excerpt — matched span is masked, never raw content */
  excerpt: string;
  status: DlpIncidentStatus;
  detail: { matchedPattern?: string; action?: DlpAction; offset?: number; fileTypeBlocked?: boolean };
  createdAt: string;
}

export interface DlpStats {
  totalIncidents: number;
  openIncidents: number;
  bySeverity: Record<DlpSeverity, number>;
  byStatus: Record<DlpIncidentStatus, number>;
  patterns: number;
  enabledPatterns: number;
  policies: number;
  enabledPolicies: number;
  /** per-day incident counts for the trailing 7 days (oldest first) */
  trend7d: Array<{ date: string; count: number }>;
}

const SEVERITIES: DlpSeverity[] = ["low", "medium", "high", "critical"];
const STATUSES: DlpIncidentStatus[] = ["new", "reviewing", "resolved", "false_positive"];

/**
 * Allowed incident status hops (audit fix F-d — mirrors the incidents
 * module's closed-transition map): new → reviewing → resolved|false_positive;
 * reviewing → new is NOT allowed; resolved and false_positive are terminal.
 * A direct new → resolved|false_positive triage decision stays legal (same
 * philosophy as incidents new → resolved); every other jump is a 400.
 */
const INCIDENT_TRANSITIONS: Record<DlpIncidentStatus, DlpIncidentStatus[]> = {
  new: ["reviewing", "resolved", "false_positive"],
  reviewing: ["resolved", "false_positive"],
  resolved: [],
  false_positive: [],
};

const fieldErr = (field: string, message: string) =>
  ApiError.validation(message, { fieldErrors: { [field]: [message] } });

function parseStringArray(raw: string): string[] {
  const v = parseJson<unknown>(raw, []);
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

function parseNumberArray(raw: string): number[] {
  const v = parseJson<unknown>(raw, []);
  return Array.isArray(v) ? v.filter((x): x is number => typeof x === "number") : [];
}

function parseDetail(raw: string): DlpIncidentDTO["detail"] {
  const v = parseJson<Record<string, unknown>>(raw, {});
  return v && typeof v === "object" ? v : {};
}

// ── patterns ────────────────────────────────────────────────────────────────

function patternDTO(row: {
  id: number;
  name: string;
  kind: string;
  value: string;
  severity: string;
  category: string;
  enabled: boolean;
  createdAt: Date;
}): DlpPatternDTO {
  return {
    id: row.id,
    name: row.name,
    kind: row.kind === "keyword" ? "keyword" : "regex",
    value: row.value,
    severity: (SEVERITIES as string[]).includes(row.severity) ? (row.severity as DlpSeverity) : "medium",
    category: (["pii", "financial", "credentials", "custom"] as string[]).includes(row.category)
      ? (row.category as DlpCategory)
      : "custom",
    enabled: row.enabled,
    keywords: row.kind === "keyword" ? splitKeywords(row.value) : [],
    createdAt: row.createdAt.toISOString(),
  };
}

export async function listPatterns(tenantId: number): Promise<DlpPatternDTO[]> {
  const rows = await db.dlpPattern.findMany({ where: { tenantId }, orderBy: { id: "asc" } });
  return rows.map(patternDTO);
}

export async function createPattern(tenantId: number, body: DlpPatternCreate): Promise<DlpPatternDTO> {
  const dup = await db.dlpPattern.findFirst({ where: { tenantId, name: body.name }, select: { id: true } });
  if (dup) throw ApiError.conflict(`DLP pattern '${body.name}' already exists`);
  // ReDoS guard (audit fix F-d) — defense in depth for service callers that
  // bypass the zod edge (tests, seeds, future internal paths)
  if (body.kind === "regex" && containsNestedQuantifier(body.value)) {
    throw ApiError.validation("nested quantifiers rejected (ReDoS guard)", {
      fieldErrors: { value: ["nested quantifiers rejected (ReDoS guard)"] },
    });
  }
  const row = await db.dlpPattern.create({
    data: {
      tenantId,
      name: body.name,
      kind: body.kind,
      value: body.value,
      severity: body.severity,
      category: body.category,
      enabled: body.enabled,
    },
  });
  return patternDTO(row);
}

export async function updatePattern(tenantId: number, id: number, body: DlpPatternUpdate): Promise<DlpPatternDTO> {
  const existing = await db.dlpPattern.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("DLP pattern not found");
  if (body.name && body.name !== existing.name) {
    const dup = await db.dlpPattern.findFirst({ where: { tenantId, name: body.name }, select: { id: true } });
    if (dup) throw ApiError.conflict(`DLP pattern '${body.name}' already exists`);
  }
  // ReDoS guard (audit fix F-d) — merged kind/value (update may set only one)
  const mergedKind = body.kind ?? existing.kind;
  const mergedValue = body.value ?? existing.value;
  if (mergedKind === "regex" && containsNestedQuantifier(mergedValue)) {
    throw ApiError.validation("nested quantifiers rejected (ReDoS guard)", {
      fieldErrors: { value: ["nested quantifiers rejected (ReDoS guard)"] },
    });
  }
  const row = await db.dlpPattern.update({
    where: { id },
    data: {
      name: body.name,
      kind: body.kind,
      value: body.value,
      severity: body.severity,
      category: body.category,
      enabled: body.enabled,
    },
  });
  return patternDTO(row);
}

/**
 * Deleting a pattern scrubs its id from any policy's patternIds (soft JSON
 * refs — dangling ids would otherwise surface as ghost chips in the UI).
 */
export async function deletePattern(tenantId: number, id: number): Promise<{ scrubbedPolicies: number }> {
  const existing = await db.dlpPattern.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("DLP pattern not found");
  await db.dlpPattern.delete({ where: { id } });
  const policies = await db.dlpPolicy.findMany({ where: { tenantId }, select: { id: true, patternIds: true } });
  let scrubbed = 0;
  for (const p of policies) {
    const ids = parseNumberArray(p.patternIds);
    if (!ids.includes(id)) continue;
    await db.dlpPolicy.update({
      where: { id: p.id },
      data: { patternIds: stringifyJson(ids.filter((x) => x !== id)) },
    });
    scrubbed += 1;
  }
  return { scrubbedPolicies: scrubbed };
}

// ── policies ────────────────────────────────────────────────────────────────

function policyDTO(row: {
  id: number;
  name: string;
  protocols: string;
  patternIds: string;
  fileTypes: string;
  action: string;
  notifyUser: boolean;
  enabled: boolean;
  createdAt: Date;
}, patternNames: Map<number, string>): DlpPolicyDTO {
  return {
    id: row.id,
    name: row.name,
    protocols: parseStringArray(row.protocols),
    patternIds: parseNumberArray(row.patternIds),
    patternNames: Object.fromEntries(parseNumberArray(row.patternIds).map((id) => [id, patternNames.get(id) ?? `#${id}`])),
    fileTypes: parseStringArray(row.fileTypes),
    action: (["alert", "block", "quarantine"] as string[]).includes(row.action)
      ? (row.action as DlpAction)
      : "alert",
    notifyUser: row.notifyUser,
    enabled: row.enabled,
    createdAt: row.createdAt.toISOString(),
  };
}

async function patternNameMap(tenantId: number, ids: number[]): Promise<Map<number, string>> {
  if (ids.length === 0) return new Map();
  const rows = await db.dlpPattern.findMany({
    where: { tenantId, id: { in: [...new Set(ids)] } },
    select: { id: true, name: true },
  });
  return new Map(rows.map((r) => [r.id, r.name]));
}

/**
 * Policy patternIds must reference existing in-tenant patterns — unknown ids
 * fail with a field error listing them (mirrors the QoS matcher checks).
 */
async function assertPatternIdsExist(tenantId: number, patternIds: number[]): Promise<void> {
  if (patternIds.length === 0) return;
  const unique = [...new Set(patternIds)];
  const found = await db.dlpPattern.findMany({ where: { tenantId, id: { in: unique } }, select: { id: true } });
  const known = new Set(found.map((p) => p.id));
  const unknown = unique.filter((id) => !known.has(id));
  if (unknown.length > 0) {
    throw fieldErr("patternIds", `Unknown pattern id(s): ${unknown.join(", ")}`);
  }
}

export async function listPolicies(tenantId: number): Promise<DlpPolicyDTO[]> {
  const rows = await db.dlpPolicy.findMany({ where: { tenantId }, orderBy: { id: "asc" } });
  const allIds = [...new Set(rows.flatMap((r) => parseNumberArray(r.patternIds)))];
  const names = await patternNameMap(tenantId, allIds);
  return rows.map((r) => policyDTO(r, names));
}

export async function createPolicy(tenantId: number, body: DlpPolicyCreate): Promise<DlpPolicyDTO> {
  const dup = await db.dlpPolicy.findFirst({ where: { tenantId, name: body.name }, select: { id: true } });
  if (dup) throw ApiError.conflict(`DLP policy '${body.name}' already exists`);
  await assertPatternIdsExist(tenantId, body.patternIds);
  const row = await db.dlpPolicy.create({
    data: {
      tenantId,
      name: body.name,
      protocols: stringifyJson(body.protocols),
      patternIds: stringifyJson([...new Set(body.patternIds)]),
      fileTypes: stringifyJson(body.fileTypes),
      action: body.action,
      notifyUser: body.notifyUser,
      enabled: body.enabled,
    },
  });
  const names = await patternNameMap(tenantId, body.patternIds);
  return policyDTO(row, names);
}

export async function updatePolicy(tenantId: number, id: number, body: DlpPolicyUpdate): Promise<DlpPolicyDTO> {
  const existing = await db.dlpPolicy.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("DLP policy not found");

  const mergedPatternIds = body.patternIds ?? parseNumberArray(existing.patternIds);
  if (body.name && body.name !== existing.name) {
    const dup = await db.dlpPolicy.findFirst({ where: { tenantId, name: body.name }, select: { id: true } });
    if (dup) throw ApiError.conflict(`DLP policy '${body.name}' already exists`);
  }
  await assertPatternIdsExist(tenantId, mergedPatternIds);

  const row = await db.dlpPolicy.update({
    where: { id },
    data: {
      name: body.name,
      protocols: body.protocols !== undefined ? stringifyJson(body.protocols) : undefined,
      patternIds: body.patternIds !== undefined ? stringifyJson([...new Set(body.patternIds)]) : undefined,
      fileTypes: body.fileTypes !== undefined ? stringifyJson(body.fileTypes) : undefined,
      action: body.action,
      notifyUser: body.notifyUser,
      enabled: body.enabled,
    },
  });
  return policyDTO(row, await patternNameMap(tenantId, mergedPatternIds));
}

export async function deletePolicy(tenantId: number, id: number): Promise<void> {
  const existing = await db.dlpPolicy.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("DLP policy not found");
  // incidents keep their logical policyId — historical audit trail survives
  await db.dlpPolicy.delete({ where: { id } });
}

// ── incidents ───────────────────────────────────────────────────────────────

async function toIncidentDTOs(
  tenantId: number,
  rows: Array<{
    id: number;
    tenantId: number;
    policyId: number;
    patternId: number;
    severity: string;
    protocol: string;
    sourceIp: string;
    userName: string | null;
    excerpt: string;
    status: string;
    detail: string;
    createdAt: Date;
  }>,
): Promise<DlpIncidentDTO[]> {
  if (rows.length === 0) return [];
  const [patterns, policies] = await Promise.all([
    patternNameMap(
      tenantId,
      rows.map((r) => r.patternId),
    ),
    db.dlpPolicy
      .findMany({
        where: { tenantId, id: { in: [...new Set(rows.map((r) => r.policyId))] } },
        select: { id: true, name: true },
      })
      .then((rs) => new Map(rs.map((r) => [r.id, r.name]))),
  ]);
  return rows.map((row) => ({
    id: row.id,
    policyId: row.policyId,
    policyName: policies.get(row.policyId) ?? null,
    patternId: row.patternId,
    patternName: patterns.get(row.patternId) ?? null,
    severity: (SEVERITIES as string[]).includes(row.severity) ? (row.severity as DlpSeverity) : "medium",
    protocol: row.protocol,
    sourceIp: row.sourceIp,
    userName: row.userName,
    excerpt: row.excerpt,
    status: (STATUSES as string[]).includes(row.status) ? (row.status as DlpIncidentStatus) : "new",
    detail: parseDetail(row.detail),
    createdAt: row.createdAt.toISOString(),
  }));
}

export async function listIncidents(
  tenantId: number,
  q: DlpIncidentsQuery,
): Promise<{ data: DlpIncidentDTO[]; meta: { page: number; limit: number; total: number; totalPages: number } }> {
  const where = {
    tenantId,
    ...(q.status ? { status: q.status } : {}),
    ...(q.severity ? { severity: q.severity } : {}),
    ...(q.q
      ? {
          OR: [{ sourceIp: { contains: q.q } }, { userName: { contains: q.q } }, { excerpt: { contains: q.q } }],
        }
      : {}),
  };
  const [total, rows] = await Promise.all([
    db.dlpIncident.count({ where }),
    db.dlpIncident.findMany({
      where,
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      skip: (q.page - 1) * q.limit,
      take: q.limit,
    }),
  ]);
  return {
    data: await toIncidentDTOs(tenantId, rows),
    meta: { page: q.page, limit: q.limit, total, totalPages: Math.max(1, Math.ceil(total / q.limit)) },
  };
}

export async function updateIncidentStatus(
  tenantId: number,
  id: number,
  status: DlpIncidentStatus,
): Promise<DlpIncidentDTO> {
  const existing = await db.dlpIncident.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("DLP incident not found");
  // Closed transition map (audit fix F-d) — illegal jumps are a 400
  const current = (STATUSES as string[]).includes(existing.status) ? (existing.status as DlpIncidentStatus) : "new";
  if (!INCIDENT_TRANSITIONS[current].includes(status)) {
    throw ApiError.validation(
      `Illegal transition ${current} → ${status} (allowed from '${current}': ${INCIDENT_TRANSITIONS[current].join(", ") || "none"})`,
    );
  }
  const row = await db.dlpIncident.update({ where: { id }, data: { status } });
  const [dto] = await toIncidentDTOs(tenantId, [row]);
  return dto;
}

// ── scan orchestration ──────────────────────────────────────────────────────

export interface ScanOutcome {
  incidents: number;
  /** engine matches enriched with the policy attribution that produced them */
  matches: Array<DlpMatch & { policyId: number; policyName: string; action: DlpAction }>;
  severity: DlpSeverity | null;
  warnings: string[];
  /**
   * Per-policy file-type control decisions (audit fix F-d) — computed for
   * EVERY scoped policy independent of pattern hits, so an extension-only
   * violation (zero matches) is still visible to callers. `fileName` is the
   * caller-supplied fileExtension (the scan API has no full file name).
   */
  fileTypeDecisions: Array<{ policyId: number; fileName: string | null; blocked: boolean }>;
}

/**
 * Protocol-aware scan (SPEC §3.3): only ENABLED policies scoped to the scan
 * protocol participate. A policy with no matching patterns contributes only
 * its fileTypes check — and since audit fix F-d that decision is reported
 * per policy in `fileTypeDecisions` and (block/quarantine + notifyUser) also
 * raises a Notification even with ZERO pattern hits: an extension-only
 * violation is a real policy decision, not silence.
 */
export async function scanTenant(tenantId: number, input: DlpScanInput): Promise<ScanOutcome> {
  const policies = await db.dlpPolicy.findMany({ where: { tenantId, enabled: true } });
  const scoped = policies.filter((p) => parseStringArray(p.protocols).includes(input.protocol));
  if (scoped.length === 0) {
    return { incidents: 0, matches: [], severity: null, warnings: [], fileTypeDecisions: [] };
  }

  const wantedIds = [...new Set(scoped.flatMap((p) => parseNumberArray(p.patternIds)))];
  const patterns = wantedIds.length
    ? await db.dlpPattern.findMany({ where: { tenantId, id: { in: wantedIds }, enabled: true } })
    : [];
  const byId = new Map(patterns.map((p) => [p.id, p]));

  const enginePatterns: DlpPatternInput[] = patterns.map((p) => ({
    id: p.id,
    kind: p.kind === "keyword" ? "keyword" : "regex",
    value: p.value,
    severity: (SEVERITIES as string[]).includes(p.severity) ? (p.severity as DlpSeverity) : "medium",
    category: (["pii", "financial", "credentials", "custom"] as string[]).includes(p.category)
      ? (p.category as DlpCategory)
      : "custom",
  }));
  const result = scanPayload({ text: input.text, fileExtension: input.fileExtension, patterns: enginePatterns });

  const matchesByPattern = new Map<number, DlpMatch[]>();
  for (const m of result.matches) {
    const list = matchesByPattern.get(m.patternId) ?? [];
    list.push(m);
    matchesByPattern.set(m.patternId, list);
  }

  let incidentCount = 0;
  const enriched: ScanOutcome["matches"] = [];
  const fileTypeDecisions: ScanOutcome["fileTypeDecisions"] = [];

  for (const policy of scoped) {
    const action = (["alert", "block", "quarantine"] as string[]).includes(policy.action)
      ? (policy.action as DlpAction)
      : "alert";
    const policyPatternIds = parseNumberArray(policy.patternIds);
    const ext = result.fileExtension?.replace(/^\./, "").toLowerCase() ?? null;
    // file-type control computed per policy INDEPENDENT of pattern hits
    // (audit fix F-d) — reported even when the scan finds nothing else
    const fileTypeBlocked =
      ext !== null && parseStringArray(policy.fileTypes).some((f) => f.replace(/^\./, "").toLowerCase() === ext);
    fileTypeDecisions.push({ policyId: policy.id, fileName: input.fileExtension ?? null, blocked: fileTypeBlocked });

    const hitPatterns = policyPatternIds.filter((id) => matchesByPattern.has(id));
    for (const patternId of hitPatterns) {
      const pattern = byId.get(patternId);
      const best = (matchesByPattern.get(patternId) ?? []).reduce((a, b) => (b.index < a.index ? b : a));
      if (pattern) {
        enriched.push({
          ...best,
          policyId: policy.id,
          policyName: policy.name,
          action,
        });
      }
      // severity is the PATTERN's severity (what matched) — engine carries it on the match
      await db.dlpIncident.create({
        data: {
          tenantId,
          policyId: policy.id,
          patternId,
          severity: best.severity,
          protocol: input.protocol,
          sourceIp: input.sourceIp,
          userName: input.userName || null,
          excerpt: best.excerpt, // already redacted by the engine — masked span
          status: "new",
          detail: stringifyJson({
            matchedPattern: pattern?.name ?? `#${patternId}`,
            action,
            offset: best.index,
            ...(fileTypeBlocked ? { fileTypeBlocked: true } : {}),
          }),
        },
      });
      incidentCount += 1;
    }

    // notifyUser + a blocking decision → Notification row (direct write,
    // read-style after lib/notifications/service.ts; excerpt stays redacted).
    // Audit fix F-d: a block/quarantine decision fires even with ZERO pattern
    // hits when the file-type control blocked the extension.
    if (policy.notifyUser && (action === "block" || action === "quarantine") && (hitPatterns.length > 0 || fileTypeBlocked)) {
      const patternPart = hitPatterns.length
        ? `Matched pattern(s): ${hitPatterns.map((id) => byId.get(id)?.name ?? `#${id}`).join(", ")}.`
        : "No pattern matched — file type blocked by policy.";
      await db.notification.create({
        data: {
          tenantId,
          type: "threat",
          severity: result.severity === "critical" || result.severity === "high" ? "critical" : "warning",
          title: `DLP ${action === "block" ? "block" : "quarantine"}: ${policy.name}`,
          message: `Sensitive data detected over ${input.protocol} from ${input.sourceIp}${input.userName ? ` (user ${input.userName})` : ""}${fileTypeBlocked && ext ? ` — file type '${ext}' blocked` : ""}. ${patternPart}`,
          sourceModule: "dlp",
          isRead: false,
        },
      });
    }
  }

  return {
    incidents: incidentCount,
    matches: enriched,
    severity: result.severity,
    warnings: result.warnings,
    fileTypeDecisions,
  };
}

// ── stats ───────────────────────────────────────────────────────────────────

export async function getStats(tenantId: number): Promise<DlpStats> {
  const [totalIncidents, bySeverityRaw, byStatusRaw, patternCount, enabledPatternCount, policyCount, enabledPolicyCount, recent] =
    await Promise.all([
      db.dlpIncident.count({ where: { tenantId } }),
      db.dlpIncident.groupBy({ by: ["severity"], where: { tenantId }, _count: { _all: true } }),
      db.dlpIncident.groupBy({ by: ["status"], where: { tenantId }, _count: { _all: true } }),
      db.dlpPattern.count({ where: { tenantId } }),
      db.dlpPattern.count({ where: { tenantId, enabled: true } }),
      db.dlpPolicy.count({ where: { tenantId } }),
      db.dlpPolicy.count({ where: { tenantId, enabled: true } }),
      db.dlpIncident.findMany({
        where: { tenantId, createdAt: { gte: new Date(Date.now() - 7 * 24 * 3600 * 1000) } },
        select: { createdAt: true },
      }),
    ]);

  const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<DlpSeverity, number>;
  for (const g of bySeverityRaw) bySeverity[g.severity as DlpSeverity] = g._count._all;
  const byStatus = Object.fromEntries(STATUSES.map((s) => [s, 0])) as Record<DlpIncidentStatus, number>;
  for (const g of byStatusRaw) byStatus[g.status as DlpIncidentStatus] = g._count._all;

  // 7-day trend buckets — computed in JS (SQLite date_trunc is unavailable)
  const days: Array<{ date: string; count: number }> = [];
  const counts = new Map<string, number>();
  for (const r of recent) {
    const key = r.createdAt.toISOString().slice(0, 10);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  for (let i = 6; i >= 0; i--) {
    const date = new Date(Date.now() - i * 24 * 3600 * 1000).toISOString().slice(0, 10);
    days.push({ date, count: counts.get(date) ?? 0 });
  }

  return {
    totalIncidents,
    openIncidents: byStatus.new + byStatus.reviewing,
    bySeverity,
    byStatus,
    patterns: patternCount,
    enabledPatterns: enabledPatternCount,
    policies: policyCount,
    enabledPolicies: enabledPolicyCount,
    trend7d: days,
  };
}
