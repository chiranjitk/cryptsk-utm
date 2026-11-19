/**
 * SOAR service (Phase 4 §4.6) — DB orchestration over SoarPlaybook /
 * SoarPlaybookRun: trigger ingestion (the entrypoint other modules call),
 * per-playbook execution with SEQUENTIAL action steps, and CRUD + runs list +
 * stats for the console.
 *
 * Execution semantics:
 *   • runPlaybookForTrigger loads every ENABLED playbook of the trigger kind,
 *     applies the pure engine (matchesTrigger) and executes the survivors —
 *     one SoarPlaybookRun row per playbook.
 *   • Dedupe: a playbook with a non-empty dedupeKey skips when an OPEN run
 *     (running | success — engine DEDUPE_OPEN_STATUSES) shares the key + the
 *     triggerRef across every playbook holding the same key; the skip is
 *     recorded as a `skipped` run row. Failed runs never block (retryable).
 *   • Steps run strictly in order; the first throwing step marks the run
 *     failed and the remaining actions are recorded as skipped steps.
 *   • Actions reuse existing subsystem paths only: block_ip materializes an
 *     address object + deny FirewallRule through createRule (mirroring
 *     incidents blockSource), create_incident goes through the incidents
 *     service fromAlert path (sourceRef = triggerRef → dedupe against open
 *     incidents for free), webhook fans out via the webhook dispatcher's
 *     deliverEvent (fire-and-forget; no dispatcher edits), notify writes a
 *     Notification row, delay is a recorded no-op.
 *
 * triggerIngest(tenantId, trigger) is the stable entrypoint for incidents/DLP
 * wiring (coordinator-owned) — it throws on programmer errors so callers can
 * `void triggerIngest(...).catch(log)`.
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import type { PageMeta } from "@/lib/api/envelope";
import { parseJson } from "@/lib/json";
import { createRule } from "@/lib/firewall/rule-service";
import { fromAlert, type IncidentSource } from "@/lib/incidents/service";
import { deliverEvent } from "@/lib/webhooks/dispatcher";
import {
  dedupeBlocks,
  evaluateActions,
  matchesTrigger,
  parseFilter,
  DEDUPE_OPEN_STATUSES,
  SOAR_TRIGGER_KINDS,
  type SoarAction,
  type SoarActionKind,
  type SoarTrigger,
  type SoarTriggerFilter,
  type SoarTriggerKind,
} from "@/lib/soar/engine";

// ── DTOs ────────────────────────────────────────────────────────────────────

export interface SoarStep {
  kind: string;
  status: string; // success | failed | skipped
  detail: string;
}

export interface SoarPlaybookDTO {
  id: number;
  name: string;
  enabled: boolean;
  triggerKind: SoarTriggerKind;
  triggerFilter: SoarTriggerFilter;
  actions: SoarAction[];
  dedupeKey: string;
  lastRunAt: string | null;
  createdAt: string;
}

export interface SoarRunDTO {
  id: number;
  playbookId: number;
  playbookName: string;
  triggerRef: string;
  status: "running" | "success" | "failed" | "skipped";
  steps: SoarStep[];
  startedAt: string;
  finishedAt: string | null;
  durationMs: number | null;
}

export interface SoarTriggerResult {
  /** one run row per considered playbook — skipped (dedupe) runs included */
  runs: SoarRunDTO[];
}

export interface SoarStats {
  playbooks: { total: number; enabled: number };
  runs: {
    total: number;
    success: number;
    failed: number;
    skipped: number;
    running: number;
    last7d: number;
    /** success / (success + failed) over terminal runs — null when none */
    successRate: number | null;
  };
  byTriggerKind: Record<SoarTriggerKind, number>;
}

const STEP_DETAIL_MAX = 300;

function clip(text: string): string {
  return text.length > STEP_DETAIL_MAX ? `${text.slice(0, STEP_DETAIL_MAX - 3)}...` : text;
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// ── shaping helpers ─────────────────────────────────────────────────────────

type PlaybookRow = {
  id: number;
  name: string;
  enabled: boolean;
  triggerKind: string;
  triggerFilter: string;
  actions: string;
  dedupeKey: string;
  lastRunAt: Date | null;
  createdAt: Date;
};

function toPlaybookDTO(row: PlaybookRow): SoarPlaybookDTO {
  return {
    id: row.id,
    name: row.name,
    enabled: row.enabled,
    triggerKind: row.triggerKind as SoarTriggerKind,
    triggerFilter: parseFilter(row.triggerFilter),
    actions: parseJson<SoarAction[]>(row.actions, []),
    dedupeKey: row.dedupeKey,
    lastRunAt: row.lastRunAt ? row.lastRunAt.toISOString() : null,
    createdAt: row.createdAt.toISOString(),
  };
}

type RunRow = {
  id: number;
  playbookId: number;
  triggerRef: string;
  status: string;
  steps: string;
  startedAt: Date;
  finishedAt: Date | null;
};

function toRunDTO(row: RunRow, playbookName: string): SoarRunDTO {
  const finishedMs = row.finishedAt ? row.finishedAt.getTime() : null;
  return {
    id: row.id,
    playbookId: row.playbookId,
    playbookName,
    triggerRef: row.triggerRef,
    status: row.status as SoarRunDTO["status"],
    steps: parseJson<SoarStep[]>(row.steps, []),
    startedAt: row.startedAt.toISOString(),
    finishedAt: row.finishedAt ? row.finishedAt.toISOString() : null,
    durationMs: finishedMs !== null ? Math.max(0, finishedMs - row.startedAt.getTime()) : null,
  };
}

/** Validate the trigger envelope shared by ingest + manual fire. */
function assertValidTrigger(trigger: SoarTrigger): void {
  if (!(SOAR_TRIGGER_KINDS as string[]).includes(trigger.kind)) {
    throw ApiError.validation(`Unknown trigger kind '${trigger.kind}' (allowed: ${SOAR_TRIGGER_KINDS.join(" | ")})`);
  }
  if (typeof trigger.triggerRef !== "string" || !trigger.triggerRef.trim()) {
    throw ApiError.validation("triggerRef is required (e.g. 'incident:INC-0007')");
  }
}

// ── playbook CRUD ───────────────────────────────────────────────────────────

export async function listPlaybooks(tenantId: number): Promise<{ data: SoarPlaybookDTO[] }> {
  const rows = await db.soarPlaybook.findMany({ where: { tenantId }, orderBy: { createdAt: "desc" } });
  return { data: rows.map(toPlaybookDTO) };
}

export async function getPlaybook(tenantId: number, id: number): Promise<SoarPlaybookDTO> {
  const row = await db.soarPlaybook.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Playbook not found");
  return toPlaybookDTO(row);
}

export interface PlaybookCreateInput {
  name: string;
  enabled: boolean;
  triggerKind: SoarTriggerKind;
  triggerFilter: SoarTriggerFilter;
  actions: SoarAction[];
  dedupeKey: string;
}

export async function createPlaybook(tenantId: number, input: PlaybookCreateInput): Promise<SoarPlaybookDTO> {
  const dup = await db.soarPlaybook.findFirst({ where: { tenantId, name: input.name.trim() } });
  if (dup) throw ApiError.conflict(`Playbook name '${input.name.trim()}' already exists`);
  // actions/triggerFilter already zod-validated at the edge — re-check the
  // action grammar here so service callers cannot store garbage either.
  const evalRes = evaluateActions(input.actions);
  if (!evalRes.ok) throw ApiError.validation(`Invalid actions: ${evalRes.errors.join("; ")}`);
  const row = await db.soarPlaybook.create({
    data: {
      tenantId,
      name: input.name.trim(),
      enabled: input.enabled,
      triggerKind: input.triggerKind,
      triggerFilter: JSON.stringify(input.triggerFilter ?? {}),
      actions: JSON.stringify(evalRes.actions),
      dedupeKey: input.dedupeKey?.trim() ?? "",
    },
  });
  return toPlaybookDTO(row);
}

export interface PlaybookUpdateInput {
  name?: string;
  enabled?: boolean;
  triggerKind?: SoarTriggerKind;
  triggerFilter?: SoarTriggerFilter;
  actions?: SoarAction[];
  dedupeKey?: string;
}

export async function updatePlaybook(
  tenantId: number,
  id: number,
  input: PlaybookUpdateInput,
): Promise<SoarPlaybookDTO> {
  const row = await db.soarPlaybook.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Playbook not found");
  if (input.actions !== undefined) {
    const evalRes = evaluateActions(input.actions);
    if (!evalRes.ok) throw ApiError.validation(`Invalid actions: ${evalRes.errors.join("; ")}`);
  }
  if (input.name !== undefined && input.name.trim() !== row.name) {
    const dup = await db.soarPlaybook.findFirst({ where: { tenantId, name: input.name.trim() } });
    if (dup) throw ApiError.conflict(`Playbook name '${input.name.trim()}' already exists`);
  }
  const updated = await db.soarPlaybook.update({
    where: { id: row.id },
    data: {
      ...(input.name !== undefined ? { name: input.name.trim() } : {}),
      ...(input.enabled !== undefined ? { enabled: input.enabled } : {}),
      ...(input.triggerKind !== undefined ? { triggerKind: input.triggerKind } : {}),
      ...(input.triggerFilter !== undefined ? { triggerFilter: JSON.stringify(input.triggerFilter) } : {}),
      ...(input.actions !== undefined ? { actions: JSON.stringify(input.actions) } : {}),
      ...(input.dedupeKey !== undefined ? { dedupeKey: input.dedupeKey.trim() } : {}),
    },
  });
  return toPlaybookDTO(updated);
}

/**
 * DELETE — runs go first (logical playbookId ref, no FK cascade; a run
 * without its playbook is unrenderable in the console).
 */
export async function deletePlaybook(tenantId: number, id: number): Promise<{ ok: true }> {
  const row = await db.soarPlaybook.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Playbook not found");
  await db.soarPlaybookRun.deleteMany({ where: { tenantId, playbookId: row.id } });
  await db.soarPlaybook.delete({ where: { id: row.id } });
  return { ok: true };
}

// ── dedupe ──────────────────────────────────────────────────────────────────

/**
 * A non-empty dedupeKey suppresses a fire when an OPEN run (running|success)
 * with the same key + triggerRef exists — across every playbook sharing the
 * key (the key is a coordination token, so the check is NOT scoped to the
 * firing playbook alone). Failed runs never block.
 */
async function dedupeBlocked(tenantId: number, playbookId: number, dedupeKey: string, triggerRef: string): Promise<{
  blocked: boolean;
  openRunId: number | null;
}> {
  if (!dedupeKey) return { blocked: false, openRunId: null };
  const siblings = await db.soarPlaybook.findMany({
    where: { tenantId, dedupeKey },
    select: { id: true },
  });
  const candidates = await db.soarPlaybookRun.findMany({
    where: {
      tenantId,
      playbookId: { in: siblings.map((s) => s.id) },
      triggerRef,
      status: { in: [...DEDUPE_OPEN_STATUSES] },
    },
    select: { id: true, status: true },
    orderBy: { id: "desc" },
  });
  return {
    blocked: dedupeBlocks(candidates),
    openRunId: candidates[0]?.id ?? null,
  };
}

// ── action execution (one step each) ────────────────────────────────────────

/** Trigger kind → incident source when a natural mapping exists. */
function sourceForTrigger(kind: SoarTriggerKind): IncidentSource {
  switch (kind) {
    case "dlp_incident":
      return "dlp_incident";
    case "dns_tunnel":
      return "dns_tunnel";
    default:
      return "manual";
  }
}

async function runBlockIp(
  tenantId: number,
  runId: number,
  params: Record<string, unknown>,
): Promise<SoarStep> {
  const ip = String(params.ip).trim();
  const direction = params.direction === undefined ? "both" : String(params.direction);
  const addrName = `soar-block-${ip.replace(/\./g, "-")}`;
  const ruleName = `SOAR auto-block ${ip}`;

  // Idempotent re-runs: reuse the object / recognize the existing rule instead
  // of tripping the unique-name guards (an automated response may re-fire).
  let addr = await db.addressObject.findFirst({ where: { tenantId, name: addrName } });
  if (!addr) {
    addr = await db.addressObject.create({
      data: {
        tenantId,
        name: addrName,
        type: "ip",
        value: ip,
        description: `Auto-blocked by SOAR run #${runId} (${direction})`,
      },
    });
  }

  const existingRule = await db.firewallRule.findFirst({ where: { tenantId, name: ruleName } });
  if (existingRule) {
    return {
      kind: "block_ip",
      status: "success",
      detail: `deny rule already present (#${existingRule.id} '${ruleName}') — object #${addr.id} (${ip}, ${direction})`,
    };
  }

  // EXISTING rule-service create path (validation, position append) — mirrors
  // incidents blockSource; direction: in → source block, out → destination
  // block, both → source-side (covers the host's own traffic, same as INC).
  const rule = await createRule(tenantId, {
    name: ruleName,
    description: `Auto-block of ${ip} — SOAR run #${runId} (${direction})`,
    enabled: true,
    srcZoneIds: [],
    dstZoneIds: [],
    srcAddrIds: direction === "out" ? [] : [addr.id],
    dstAddrIds: direction === "out" ? [addr.id] : [],
    serviceIds: [],
    applicationIds: [],
    userIds: [],
    srcMacs: [],
    action: "deny",
    logging: "detail",
    synProtection: false,
    tags: ["soar", "auto-block"],
    comment: `Created by SOAR playbook response (run #${runId}) for ${ip}`,
  });
  return {
    kind: "block_ip",
    status: "success",
    detail: `blocked ${ip} (${direction}) — address object #${addr.id} '${addrName}', deny rule #${rule.id} '${ruleName}'`,
  };
}

async function runNotify(tenantId: number, params: Record<string, unknown>, playbookName: string): Promise<SoarStep> {
  const title = String(params.title).trim();
  const message = String(params.message).trim();
  const notification = await db.notification.create({
    data: {
      tenantId,
      type: "threat",
      severity: "warning",
      title: clip(title),
      message: clip(message),
      sourceModule: "soar",
    },
  });
  return {
    kind: "notify",
    status: "success",
    detail: `notification #${notification.id} raised by playbook '${playbookName}': ${title}`,
  };
}

async function runCreateIncident(
  tenantId: number,
  trigger: SoarTrigger,
  params: Record<string, unknown>,
  playbookName: string,
): Promise<SoarStep> {
  const title = String(params.title).trim();
  const severity = String(params.severity);
  const srcIps = Array.isArray(trigger.payload.srcIps)
    ? trigger.payload.srcIps.filter((x): x is string => typeof x === "string")
    : undefined;
  const created = await fromAlert(
    tenantId,
    {
      source: sourceForTrigger(trigger.kind),
      sourceRef: trigger.triggerRef,
      title: clip(title),
      severity: severity as "info" | "low" | "medium" | "high" | "critical",
      detail: {
        description: `Opened by SOAR playbook '${playbookName}' in response to ${trigger.triggerRef}`,
        ...(srcIps?.length ? { srcIps } : {}),
        playbook: playbookName,
        triggerKind: trigger.kind,
        payload: trigger.payload,
      },
    },
    `soar:${playbookName}`,
  );
  return {
    kind: "create_incident",
    status: "success",
    detail: created.deduped
      ? `incident ${created.incident.ref} already open for ${trigger.triggerRef} — deduped`
      : `incident ${created.incident.ref} opened (${created.incident.severity}) for ${trigger.triggerRef}`,
  };
}

async function runWebhook(tenantId: number, trigger: SoarTrigger, params: Record<string, unknown>, playbookName: string): Promise<SoarStep> {
  const endpoints = await db.webhook.count({ where: { tenantId, enabled: true } });
  if (endpoints === 0) {
    return { kind: "webhook", status: "skipped", detail: "no webhook endpoint configured — nothing dispatched" };
  }
  // EXISTING dispatcher fan-out (fire-and-forget, never throws). Endpoints
  // subscribed to `soar.playbook.run` or `*` receive the payload.
  void deliverEvent(
    "soar.playbook.run",
    {
      playbook: playbookName,
      triggerRef: trigger.triggerRef,
      triggerKind: trigger.kind,
      payload: params.payload,
    },
    { tenantId },
  );
  return {
    kind: "webhook",
    status: "success",
    detail: `payload dispatched to ${endpoints} enabled webhook endpoint${endpoints === 1 ? "" : "s"} (event soar.playbook.run)`,
  };
}

async function executeAction(
  tenantId: number,
  runId: number,
  playbookName: string,
  trigger: SoarTrigger,
  action: SoarAction,
): Promise<SoarStep> {
  switch (action.kind as SoarActionKind) {
    case "block_ip":
      return runBlockIp(tenantId, runId, action.params);
    case "notify":
      return runNotify(tenantId, action.params, playbookName);
    case "create_incident":
      return runCreateIncident(tenantId, trigger, action.params, playbookName);
    case "delay": {
      const seconds = Number(action.params.seconds);
      return {
        kind: "delay",
        status: "success",
        detail: `delay ${seconds}s (no-op in console runtime — step recorded for ordering/audit)`,
      };
    }
    case "webhook":
      return runWebhook(tenantId, trigger, action.params, playbookName);
    default:
      throw ApiError.internal(`Unknown action kind '${action.kind}'`);
  }
}

// ── run execution ───────────────────────────────────────────────────────────

/**
 * Execute ONE playbook for a trigger: dedupe check → run row (`running`) →
 * sequential steps → terminal status + lastRunAt. Dedupe hits create a
 * `skipped` run row (with the blocking run's id) and leave lastRunAt alone.
 */
async function executePlaybook(
  tenantId: number,
  playbook: PlaybookRow,
  trigger: SoarTrigger,
): Promise<SoarRunDTO> {
  const dedupe = await dedupeBlocked(tenantId, playbook.id, playbook.dedupeKey, trigger.triggerRef);
  if (dedupe.blocked) {
    const skipped = await db.soarPlaybookRun.create({
      data: {
        tenantId,
        playbookId: playbook.id,
        triggerRef: trigger.triggerRef,
        status: "skipped",
        steps: JSON.stringify([
          {
            kind: "skip",
            status: "skipped",
            detail: `dedupeKey '${playbook.dedupeKey}' — open run #${dedupe.openRunId ?? "?"} already handled ${trigger.triggerRef}`,
          },
        ]),
        finishedAt: new Date(),
      },
    });
    return toRunDTO(skipped, playbook.name);
  }

  const run = await db.soarPlaybookRun.create({
    data: { tenantId, playbookId: playbook.id, triggerRef: trigger.triggerRef, status: "running", steps: "[]" },
  });

  const steps: SoarStep[] = [];
  let status: "success" | "failed" = "success";

  const evalRes = evaluateActions(parseJson<unknown>(playbook.actions, []));
  if (!evalRes.ok) {
    // Stored actions are stale/invalid (validator drift, manual DB edit) —
    // fail the run with a validation step instead of executing garbage.
    steps.push({ kind: "actions", status: "failed", detail: clip(`invalid stored actions: ${evalRes.errors.join("; ")}`) });
    status = "failed";
  } else {
    for (let i = 0; i < evalRes.actions.length; i++) {
      const action = evalRes.actions[i];
      try {
        steps.push(await executeAction(tenantId, run.id, playbook.name, trigger, action));
      } catch (err) {
        steps.push({ kind: action.kind, status: "failed", detail: clip(errMessage(err)) });
        status = "failed";
        for (const rest of evalRes.actions.slice(i + 1)) {
          steps.push({ kind: rest.kind, status: "skipped", detail: "not executed — previous step failed" });
        }
        break;
      }
    }
  }

  const finishedAt = new Date();
  const [updatedRun] = await Promise.all([
    db.soarPlaybookRun.update({
      where: { id: run.id },
      data: { status, steps: JSON.stringify(steps), finishedAt },
    }),
    db.soarPlaybook.update({ where: { id: playbook.id }, data: { lastRunAt: finishedAt } }),
  ]);
  return toRunDTO(updatedRun, playbook.name);
}

/**
 * Fire every enabled playbook matching the trigger (kind + filter). Never
 * fails a whole batch because one playbook errored — executePlaybook records
 * step failures on the run row; only infrastructure errors propagate.
 */
export async function runPlaybookForTrigger(tenantId: number, trigger: SoarTrigger): Promise<SoarTriggerResult> {
  assertValidTrigger(trigger);
  const playbooks = await db.soarPlaybook.findMany({
    where: { tenantId, enabled: true, triggerKind: trigger.kind },
    orderBy: { id: "asc" },
  });
  const runs: SoarRunDTO[] = [];
  for (const playbook of playbooks) {
    if (!matchesTrigger(playbook, trigger)) continue;
    runs.push(await executePlaybook(tenantId, playbook, trigger));
  }
  return { runs };
}

/**
 * Stable entrypoint for other modules (coordinator wires incidents/DLP later):
 * `void triggerIngest(tenant, { kind, triggerRef, payload })` from the
 * incident/DLP creation paths.
 */
export async function triggerIngest(tenantId: number, trigger: SoarTrigger): Promise<SoarTriggerResult> {
  return runPlaybookForTrigger(tenantId, trigger);
}

/**
 * Manual fire (POST /api/v1/soar/playbooks/{id}/run) — runs the chosen
 * playbook regardless of `enabled`/filter (operator override), but the same
 * dedupe + step semantics apply so a repeated triggerRef is skipped.
 */
export async function runPlaybookById(
  tenantId: number,
  playbookId: number,
  input: { triggerRef: string; payload?: Record<string, unknown> },
): Promise<SoarRunDTO> {
  const row = await db.soarPlaybook.findFirst({ where: { id: playbookId, tenantId } });
  if (!row) throw ApiError.notFound("Playbook not found");
  const trigger: SoarTrigger = {
    kind: row.triggerKind as SoarTriggerKind,
    triggerRef: input.triggerRef.trim(),
    payload: input.payload ?? {},
  };
  assertValidTrigger(trigger);
  return executePlaybook(tenantId, row, trigger);
}

// ── runs list (join playbook names via the logical ref) ─────────────────────

export async function listRuns(
  tenantId: number,
  query: { playbookId?: number; status?: string; page: number; limit: number },
): Promise<{ data: SoarRunDTO[]; meta: PageMeta }> {
  const where = {
    tenantId,
    ...(query.playbookId !== undefined ? { playbookId: query.playbookId } : {}),
    ...(query.status ? { status: query.status } : {}),
  };
  const [rows, total, playbooks] = await Promise.all([
    db.soarPlaybookRun.findMany({
      where,
      orderBy: { startedAt: "desc" },
      skip: (query.page - 1) * query.limit,
      take: query.limit,
    }),
    db.soarPlaybookRun.count({ where }),
    db.soarPlaybook.findMany({ where: { tenantId }, select: { id: true, name: true } }),
  ]);
  const names = new Map(playbooks.map((p) => [p.id, p.name]));
  return {
    data: rows.map((r) => toRunDTO(r, names.get(r.playbookId) ?? `#${r.playbookId} (deleted)`)),
    meta: {
      page: query.page,
      limit: query.limit,
      total,
      totalPages: Math.max(1, Math.ceil(total / query.limit)),
    },
  };
}

// ── stats ───────────────────────────────────────────────────────────────────

export async function getStats(tenantId: number): Promise<SoarStats> {
  const weekAgo = new Date(Date.now() - 7 * 24 * 3600_000);
  const [playbookRows, statusGroups, runsTotal, runs7d] = await Promise.all([
    db.soarPlaybook.groupBy({
      by: ["triggerKind", "enabled"],
      where: { tenantId },
      _count: { _all: true },
    }),
    db.soarPlaybookRun.groupBy({
      by: ["status"],
      where: { tenantId },
      _count: { _all: true },
    }),
    db.soarPlaybookRun.count({ where: { tenantId } }),
    db.soarPlaybookRun.count({ where: { tenantId, startedAt: { gte: weekAgo } } }),
  ]);

  const byTriggerKind: Record<SoarTriggerKind, number> = {
    incident_created: 0,
    incident_severity: 0,
    dlp_incident: 0,
    dns_tunnel: 0,
    ioc_hit: 0,
  };
  let playbooksTotal = 0;
  let playbooksEnabled = 0;
  for (const g of playbookRows) {
    const kind = g.triggerKind as SoarTriggerKind;
    if (kind in byTriggerKind) byTriggerKind[kind] += g._count._all;
    playbooksTotal += g._count._all;
    if (g.enabled) playbooksEnabled += g._count._all;
  }

  const byStatus: Record<string, number> = { success: 0, failed: 0, skipped: 0, running: 0 };
  for (const g of statusGroups) {
    if (g.status in byStatus) byStatus[g.status] = g._count._all;
  }
  const terminal = byStatus.success + byStatus.failed;

  return {
    playbooks: { total: playbooksTotal, enabled: playbooksEnabled },
    runs: {
      total: runsTotal,
      success: byStatus.success,
      failed: byStatus.failed,
      skipped: byStatus.skipped,
      running: byStatus.running,
      last7d: runs7d,
      successRate: terminal > 0 ? Math.round((byStatus.success / terminal) * 100) : null,
    },
    byTriggerKind,
  };
}
