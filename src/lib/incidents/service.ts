/**
 * Incident Response service (Phase 3 §3.5) — DB-backed workflow over the
 * Incident / IncidentTimelineEntry tables: INC- ref generation with a
 * collision-safe retry, the new → investigating → contained → resolved
 * state machine (each hop appends a timeline status_change; resolution
 * stamps resolvedAt), assignment + notes, alert ingestion with dedupe
 * against OPEN incidents sharing the same sourceRef, and the manual
 * block-source action that materializes an address object + deny rule
 * through the EXISTING rule-service create path (no rule-service changes).
 *
 * SQLite has no Prisma relation on IncidentTimelineEntry.incidentId (logical
 * ref), so timeline reads are explicit findMany calls — same pattern as the
 * M13 threat-intel module.
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import type { PageMeta } from "@/lib/api/envelope";
import { createRule } from "@/lib/firewall/rule-service";
import type {
  IncidentPatch,
  IncidentQuery,
  IncidentSeverity,
  IncidentSource,
  IncidentStatus,
} from "@/lib/validators/incidents";

// ── locked vocabularies (schema.prisma comments + spec §3.5) ────────────────

export const INCIDENT_SOURCES: IncidentSource[] = [
  "manual",
  "ips_event",
  "dlp_incident",
  "dns_tunnel",
  "threat_intel",
  "ai",
];

export const INCIDENT_SEVERITIES: IncidentSeverity[] = ["info", "low", "medium", "high", "critical"];

export const INCIDENT_STATUSES: IncidentStatus[] = ["new", "investigating", "contained", "resolved"];

export type TimelineAction =
  | "created"
  | "status_change"
  | "assigned"
  | "blocked"
  | "quarantine"
  | "note"
  | "resolved";

/** Allowed workflow hops — closed set; everything else is a 400. */
const TRANSITIONS: Record<IncidentStatus, IncidentStatus[]> = {
  new: ["investigating", "resolved"],
  investigating: ["contained"],
  contained: ["resolved"],
  resolved: [],
};

// ── DTOs ────────────────────────────────────────────────────────────────────

export interface IncidentDetail {
  description?: string | null;
  srcIps?: string[];
  tags?: string[];
  /** set by blockSource — ids of the materialized firewall artifacts */
  blockedRuleId?: number;
  blockedAddressId?: number;
  [key: string]: unknown;
}

export interface IncidentTimelineDTO {
  id: number;
  actor: string;
  action: TimelineAction;
  detail: string;
  createdAt: string;
}

export interface IncidentDTO {
  id: number;
  ref: string;
  title: string;
  source: IncidentSource;
  sourceRef: string | null;
  severity: IncidentSeverity;
  status: IncidentStatus;
  assignedTo: string | null;
  detail: IncidentDetail;
  resolvedAt: string | null;
  createdAt: string;
  /** present on getIncident only (list stays lean) */
  timeline?: IncidentTimelineDTO[];
}

/**
 * Creation input — optional fields here (source/severity have service-side
 * fallbacks) even though the zod create schema applies defaults at the route
 * boundary; service callers (tests, engine, webhooks) may omit them.
 */
export interface IncidentCreateInput {
  title: string;
  source?: IncidentSource;
  sourceRef?: string | null;
  severity?: IncidentSeverity;
  assignedTo?: string | null;
  detail?: Record<string, unknown>;
}

export interface AlertInput {
  source: IncidentSource;
  sourceRef: string;
  title: string;
  severity?: IncidentSeverity;
  detail?: Record<string, unknown>;
}

export interface IncidentStats {
  openTotal: number;
  openBySeverity: Record<IncidentSeverity, number>;
  created7d: number;
  resolvedTotal: number;
  /** mean hours from createdAt → resolvedAt over resolved incidents; null when none */
  mttrHours: number | null;
}

// ── shaping helpers ─────────────────────────────────────────────────────────

function parseDetail(raw: string | null | undefined): IncidentDetail {
  if (!raw) return {};
  try {
    const v = JSON.parse(raw);
    return v && typeof v === "object" && !Array.isArray(v) ? (v as IncidentDetail) : {};
  } catch {
    return {};
  }
}

function toDTO(
  row: {
    id: number;
    ref: string;
    title: string;
    source: string;
    sourceRef: string | null;
    severity: string;
    status: string;
    assignedTo: string | null;
    detail: string;
    resolvedAt: Date | null;
    createdAt: Date;
  },
  timeline?: Array<{ id: number; actor: string; action: string; detail: string; createdAt: Date }>,
): IncidentDTO {
  const dto: IncidentDTO = {
    id: row.id,
    ref: row.ref,
    title: row.title,
    source: row.source as IncidentSource,
    sourceRef: row.sourceRef,
    severity: row.severity as IncidentSeverity,
    status: row.status as IncidentStatus,
    assignedTo: row.assignedTo,
    detail: parseDetail(row.detail),
    resolvedAt: row.resolvedAt ? row.resolvedAt.toISOString() : null,
    createdAt: row.createdAt.toISOString(),
  };
  if (timeline) {
    dto.timeline = timeline.map((t) => ({
      id: t.id,
      actor: t.actor,
      action: t.action as TimelineAction,
      detail: t.detail,
      createdAt: t.createdAt.toISOString(),
    }));
  }
  return dto;
}

function isUniqueViolation(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { code?: unknown }).code === "P2002";
}

async function addTimelineEntry(
  incidentId: number,
  actor: string,
  action: TimelineAction,
  detail: string,
): Promise<void> {
  await db.incidentTimelineEntry.create({
    data: { incidentId, actor, action, detail },
  });
}

// ── ref generation (per-tenant counter from count, collision-safe) ──────────

function refForCount(count: number): string {
  return `INC-${String(count + 1).padStart(4, "0")}`;
}

// ── create ──────────────────────────────────────────────────────────────────

/**
 * Manual/service incident creation. The per-tenant `INC-####` ref is derived
 * from the tenant's row count; concurrent creates can race to the same ref,
 * so the unique (tenantId, ref) index is retried after a recount (P2002 →
 * up to 5 attempts) instead of failing the caller.
 */
export async function createIncident(
  tenantId: number,
  input: IncidentCreateInput,
  actor: string,
): Promise<IncidentDTO> {
  const detailJson = JSON.stringify(input.detail ?? {});
  const assignedTo = input.assignedTo?.trim() || null;

  for (let attempt = 0; attempt < 5; attempt++) {
    const count = await db.incident.count({ where: { tenantId } });
    // recount (race: the colliding row commits between attempts) + attempt
    // offset (holes: a deleted middle incident would otherwise wedge the
    // counter onto an occupied ref forever)
    const ref = refForCount(count + attempt);
    try {
      const row = await db.incident.create({
        data: {
          tenantId,
          ref,
          title: input.title.trim(),
          source: input.source ?? "manual",
          sourceRef: input.sourceRef ?? null,
          severity: input.severity ?? "medium",
          status: "new",
          assignedTo,
          detail: detailJson,
        },
      });
      await addTimelineEntry(
        row.id,
        actor,
        "created",
        `Incident opened (${input.source ?? "manual"}${input.sourceRef ? `, source ref ${input.sourceRef}` : ""})`,
      );
      return toDTO(row);
    } catch (err) {
      if (isUniqueViolation(err)) continue; // ref raced — recount and retry
      throw err;
    }
  }
  throw ApiError.conflict("Could not allocate a unique incident ref after several attempts");
}

// ── alert ingestion (from-alerts path with dedupe) ──────────────────────────

/**
 * Create an incident from an upstream alert. Dedupe: an OPEN (non-resolved)
 * incident with the same sourceRef short-circuits — the existing row is
 * returned unchanged with `deduped: true` (no timeline noise).
 */
export async function fromAlert(
  tenantId: number,
  input: AlertInput,
  actor = "system",
): Promise<{ incident: IncidentDTO; deduped: boolean }> {
  const sourceRef = input.sourceRef?.trim();
  if (!sourceRef) {
    throw ApiError.validation("fromAlert requires a sourceRef pointer to the originating alert");
  }
  const existing = await db.incident.findFirst({
    where: { tenantId, sourceRef, status: { not: "resolved" } },
    orderBy: { id: "desc" },
  });
  if (existing) {
    return { incident: toDTO(existing), deduped: true };
  }
  const incident = await createIncident(
    tenantId,
    {
      title: input.title,
      source: input.source,
      sourceRef,
      severity: input.severity ?? "medium",
      detail: input.detail ?? {},
    },
    actor,
  );
  return { incident, deduped: false };
}

// ── read ────────────────────────────────────────────────────────────────────

export async function listIncidents(
  tenantId: number,
  query: IncidentQuery,
): Promise<{ data: IncidentDTO[]; meta: PageMeta }> {
  const where = {
    tenantId,
    ...(query.status ? { status: query.status } : {}),
    ...(query.severity ? { severity: query.severity } : {}),
    ...(query.source ? { source: query.source } : {}),
    ...(query.q
      ? {
          OR: [
            { ref: { contains: query.q } },
            { title: { contains: query.q } },
            { assignedTo: { contains: query.q } },
          ],
        }
      : {}),
  };
  const [rows, total] = await Promise.all([
    db.incident.findMany({
      where,
      // id desc tiebreaker: same-millisecond creates (batch ingest) must keep
      // a stable page order instead of flipping between requests
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      skip: (query.page - 1) * query.limit,
      take: query.limit,
    }),
    db.incident.count({ where }),
  ]);
  return {
    data: rows.map((r) => toDTO(r)),
    meta: { page: query.page, limit: query.limit, total, totalPages: Math.max(1, Math.ceil(total / query.limit)) },
  };
}

export async function getIncident(tenantId: number, id: number): Promise<IncidentDTO> {
  const row = await db.incident.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Incident not found");
  const timeline = await db.incidentTimelineEntry.findMany({
    where: { incidentId: row.id },
    orderBy: { createdAt: "asc" },
  });
  return toDTO(row, timeline);
}

// ── workflow verbs ──────────────────────────────────────────────────────────

export async function transition(
  tenantId: number,
  id: number,
  body: Extract<IncidentPatch, { kind: "status" }>,
  actor: string,
): Promise<IncidentDTO> {
  const row = await db.incident.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Incident not found");
  const current = row.status as IncidentStatus;
  const next = body.status;
  if (!TRANSITIONS[current].includes(next)) {
    throw ApiError.validation(
      `Illegal transition ${current} → ${next} (allowed from '${current}': ${TRANSITIONS[current].join(", ") || "none"})`,
    );
  }
  const updated = await db.incident.update({
    where: { id: row.id },
    data: {
      status: next,
      ...(next === "resolved" ? { resolvedAt: new Date() } : {}),
    },
  });
  await addTimelineEntry(row.id, actor, "status_change", `Status ${current} → ${next}`);
  return toDTO(updated);
}

export async function assign(
  tenantId: number,
  id: number,
  body: Extract<IncidentPatch, { kind: "assign" }>,
  actor: string,
): Promise<IncidentDTO> {
  const row = await db.incident.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Incident not found");
  const assignee = body.assignedTo?.trim() || null;
  const updated = await db.incident.update({ where: { id: row.id }, data: { assignedTo: assignee } });
  await addTimelineEntry(
    row.id,
    actor,
    "assigned",
    assignee ? `Assigned to ${assignee}` : "Assignment cleared",
  );
  return toDTO(updated);
}

export async function addNote(tenantId: number, id: number, note: string, actor: string): Promise<IncidentDTO> {
  const row = await db.incident.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Incident not found");
  await addTimelineEntry(row.id, actor, "note", note.trim());
  return toDTO(row);
}

/**
 * DELETE — resolved incidents only (workflow history stays intact for open
 * ones). Timeline entries go first (logical ref, no FK cascade).
 */
export async function deleteIncident(tenantId: number, id: number): Promise<{ ok: true }> {
  const row = await db.incident.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Incident not found");
  if (row.status !== "resolved") {
    throw ApiError.conflict(`Only resolved incidents can be deleted (current status: ${row.status})`);
  }
  await db.incidentTimelineEntry.deleteMany({ where: { incidentId: row.id } });
  await db.incident.delete({ where: { id: row.id } });
  return { ok: true };
}

// ── manual block action (§3.5 — contain the source) ─────────────────────────

/**
 * IPv4 grammar for auto-blocking — rejects malformed quads AND the addresses
 * that are never a meaningful block target:
 *   • 0.0.0.0 (unspecified) and 255.255.255.255 (limited broadcast) —
 *     blocking either would wedge the whole data plane,
 *   • leading-zero octets ("010.1.2.3") — ambiguous parsing across stacks.
 */
function isBlockableIp(value: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value.trim());
  if (!m) return false;
  const octets = m.slice(1);
  if (octets.some((oct) => oct.length > 1 && oct.startsWith("0"))) return false;
  const nums = octets.map((oct) => Number(oct));
  if (nums.some((n) => n < 0 || n > 255)) return false;
  const isUnspecified = nums[0] === 0 && nums[1] === 0 && nums[2] === 0 && nums[3] === 0;
  const isLimitedBroadcast = nums[0] === 255 && nums[1] === 255 && nums[2] === 255 && nums[3] === 255;
  return !isUnspecified && !isLimitedBroadcast;
}

/**
 * Block the incident's source: creates an `ip` address object for
 * detail.srcIps[0] and a deny firewall rule referencing it — via the
 * EXISTING rule-service create path (validation, dup-name guard, position
 * append) — then records the artifact ids on the incident detail and appends
 * a `blocked` timeline entry. Re-blocking is rejected (conflict).
 */
export async function blockSource(
  tenantId: number,
  id: number,
  actor: string,
): Promise<{ incident: IncidentDTO; addressObjectId: number; firewallRuleId: number }> {
  const row = await db.incident.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Incident not found");

  const detail = parseDetail(row.detail);
  const ip = Array.isArray(detail.srcIps) ? detail.srcIps[0] : undefined;
  if (typeof ip !== "string" || !ip.trim() || !isBlockableIp(ip)) {
    throw ApiError.validation("Incident has no blockable srcIps[0] IPv4 address in its detail");
  }
  if (detail.blockedRuleId || detail.blockedAddressId) {
    throw ApiError.conflict(
      `Incident ${row.ref} source is already blocked (rule #${detail.blockedRuleId ?? "?"}, object #${detail.blockedAddressId ?? "?"})`,
    );
  }

  const addrName = `inc-${row.ref}-block`;
  const addrDup = await db.addressObject.findFirst({ where: { tenantId, name: addrName } });
  if (addrDup) {
    throw ApiError.conflict(`Address object '${addrName}' already exists`);
  }

  // ATOMICITY NOTE (audit fix F-d): the previous non-atomic sequence could
  // WEDGE a re-block — an address object created and then a rule-service
  // failure (validation drift, dup race) left the object orphaned while the
  // incident detail stayed un-stamped, so every retry died on the unique
  // name guard above. The rule service (lib/firewall/rule-service.createRule)
  // manages its OWN db.$transaction and cannot join an outer tx client, so a
  // single db.$transaction wrapping all three writes is impossible without
  // touching that module. Chosen approach: COMPENSATING CLEANUP — create the
  // address object, create the rule, stamp the detail; ANY failure after a
  // write deletes everything written so far before rethrowing, leaving the
  // block fully retryable (no half-materialized artifacts, no wedge).
  const ao = await db.addressObject.create({
    data: {
      tenantId,
      name: addrName,
      type: "ip",
      value: ip.trim(),
      description: `Auto-blocked source from incident ${row.ref}`,
    },
  });

  // Reuse the firewall rule-service create path — id validation, duplicate
  // name guard and position append stay in one place (no rule-service edits).
  let rule: Awaited<ReturnType<typeof createRule>>;
  try {
    rule = await createRule(tenantId, {
      name: `INC ${row.ref} auto-block`,
      description: `Auto-block of ${ip.trim()} — incident ${row.ref}`,
      enabled: true,
      srcZoneIds: [],
      dstZoneIds: [],
      srcAddrIds: [ao.id],
      dstAddrIds: [],
      serviceIds: [],
      applicationIds: [],
      userIds: [],
      srcMacs: [],
      action: "deny",
      logging: "detail",
      synProtection: false,
      tags: ["incident", "auto-block"],
      comment: `Created by incident response (${actor}) for ${row.ref}`,
    });
  } catch (err) {
    // rule create failed → remove the just-created address object (retryable)
    await db.addressObject.delete({ where: { id: ao.id } }).catch(() => {});
    throw err;
  }

  const nextDetail: IncidentDetail = {
    ...detail,
    blockedRuleId: rule.id,
    blockedAddressId: ao.id,
  };
  let updated: Awaited<ReturnType<typeof db.incident.update>>;
  try {
    updated = await db.incident.update({
      where: { id: row.id },
      data: { detail: JSON.stringify(nextDetail) },
    });
  } catch (err) {
    // detail stamp failed → roll back BOTH artifacts so the retry is clean
    await db.firewallRule.delete({ where: { id: rule.id } }).catch(() => {});
    await db.addressObject.delete({ where: { id: ao.id } }).catch(() => {});
    throw err;
  }
  await addTimelineEntry(
    row.id,
    actor,
    "blocked",
    `Blocked source ${ip.trim()} — address object #${ao.id} '${addrName}', firewall rule #${rule.id} 'INC ${row.ref} auto-block' (deny)`,
  );
  return { incident: toDTO(updated), addressObjectId: ao.id, firewallRuleId: rule.id };
}

// ── stats (console strip) ───────────────────────────────────────────────────

export async function getStats(tenantId: number): Promise<IncidentStats> {
  const weekAgo = new Date(Date.now() - 7 * 24 * 3600_000);
  const [openGroups, created7d, resolvedRows] = await Promise.all([
    db.incident.groupBy({
      by: ["severity"],
      where: { tenantId, status: { not: "resolved" } },
      _count: { _all: true },
    }),
    db.incident.count({ where: { tenantId, createdAt: { gte: weekAgo } } }),
    db.incident.findMany({
      where: { tenantId, status: "resolved", resolvedAt: { not: null } },
      select: { createdAt: true, resolvedAt: true },
    }),
  ]);

  const openBySeverity: Record<IncidentSeverity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  let openTotal = 0;
  for (const g of openGroups) {
    const key = g.severity as IncidentSeverity;
    if (key in openBySeverity) {
      openBySeverity[key] = g._count._all;
      openTotal += g._count._all;
    }
  }

  const durations = resolvedRows
    .map((r) => (r.resolvedAt ? r.resolvedAt.getTime() - r.createdAt.getTime() : NaN))
    .filter((ms) => Number.isFinite(ms) && ms >= 0);
  const mttrHours = durations.length
    ? Math.round((durations.reduce((a, b) => a + b, 0) / durations.length / 3600_000) * 10) / 10
    : null;

  return {
    openTotal,
    openBySeverity,
    created7d,
    resolvedTotal: durations.length,
    mttrHours,
  };
}
