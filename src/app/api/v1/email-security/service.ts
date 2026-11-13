/**
 * Email Security service (M22, spec 2.8) — gateways (proxy/relay listeners),
 * the per-tenant policy SINGLETON (GET auto-creates defaults), routing rules
 * (per-tenant unique priority → 409), the SIMULATED Rspamd+ClamAV test
 * pipeline (engine.ts), paged-lite mail logs, 24h stats and quarantine
 * release. All queries are tenant-scoped; mutations are audited by the route
 * layer which snapshots section `email_security`.
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import type { EmailGateway, EmailLog, EmailPolicy, EmailRoutingRule, Prisma } from "@prisma/client";
import type {
  EmailLogQuery,
  EmailTestInput,
  GatewayCreate,
  GatewayUpdate,
  PolicyUpdate,
  RoutingAction,
  RoutingRuleCreate,
  RoutingRuleUpdate,
  EmailVerdict,
  GatewayMode,
  TlsMode,
  DmarcPolicy,
} from "@/lib/validators/email-security";
import { scanMessage, type AuthResult, type ScanVerdict } from "./engine";

// ── DTOs (mirrored in components/views/email-security/email-security-api.ts) ─

const POLICY_NAME = "Default Email Policy";

export interface EmailGatewayDTO {
  id: number;
  name: string;
  mode: GatewayMode;
  listenPort: number;
  relayDomains: string[];
  upstreamHost: string | null;
  tlsMode: TlsMode;
  enabled: boolean;
  createdAt: string;
}

export interface EmailPolicyDTO {
  id: number;
  name: string;
  spamThreshold: number;
  blockPhishing: boolean;
  blockMalware: boolean;
  scanArchives: boolean;
  maxMessageSizeMb: number;
  blockedExtensions: string[];
  spfVerify: boolean;
  dkimVerify: boolean;
  dmarcPolicy: DmarcPolicy;
  quarantineRetentionDays: number;
  enabled: boolean;
}

export interface EmailRoutingRuleDTO {
  id: number;
  name: string;
  matchDomain: string;
  action: RoutingAction;
  targetHost: string | null;
  priority: number;
  enabled: boolean;
}

export interface EmailLogDTO {
  id: number;
  fromAddr: string;
  toAddr: string;
  subject: string | null;
  spamScore: number;
  verdict: EmailVerdict;
  reasons: string[];
  spfResult: AuthResult | null;
  dkimResult: AuthResult | null;
  dmarcResult: AuthResult | null;
  attachmentsScanned: number;
  sizeKb: number;
  createdAt: string;
}

export type EmailTestResultDTO = ScanVerdict;

export interface EmailStatsDTO {
  delivered24h: number;
  quarantined24h: number;
  rejected24h: number;
  avgSpamScore: number;
  topReasons: Array<{ reason: string; count: number }>;
  quarantineRetentionDays: number;
}

// ── helpers ─────────────────────────────────────────────────────────────────

/** Parse a JSON string column defensively — bad payload → []. */
function parseJsonArray(json: string): string[] {
  try {
    const parsed: unknown = JSON.parse(json);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((v): v is string => typeof v === "string");
  } catch {
    return [];
  }
}

function toGatewayDTO(row: EmailGateway): EmailGatewayDTO {
  return {
    id: row.id,
    name: row.name,
    mode: row.mode as GatewayMode,
    listenPort: row.listenPort,
    relayDomains: parseJsonArray(row.relayDomains),
    upstreamHost: row.upstreamHost,
    tlsMode: row.tlsMode as TlsMode,
    enabled: row.enabled,
    createdAt: row.createdAt.toISOString(),
  };
}

function toPolicyDTO(row: EmailPolicy): EmailPolicyDTO {
  return {
    id: row.id,
    name: row.name,
    spamThreshold: row.spamThreshold,
    blockPhishing: row.blockPhishing,
    blockMalware: row.blockMalware,
    scanArchives: row.scanArchives,
    maxMessageSizeMb: row.maxMessageSizeMb,
    blockedExtensions: parseJsonArray(row.blockedExtensions),
    spfVerify: row.spfVerify,
    dkimVerify: row.dkimVerify,
    dmarcPolicy: row.dmarcPolicy as DmarcPolicy,
    quarantineRetentionDays: row.quarantineRetentionDays,
    enabled: row.enabled,
  };
}

function toRuleDTO(row: EmailRoutingRule): EmailRoutingRuleDTO {
  return {
    id: row.id,
    name: row.name,
    matchDomain: row.matchDomain,
    action: row.action as RoutingAction,
    targetHost: row.targetHost,
    priority: row.priority,
    enabled: row.enabled,
  };
}

function toLogDTO(row: EmailLog): EmailLogDTO {
  return {
    id: row.id,
    fromAddr: row.fromAddr,
    toAddr: row.toAddr,
    subject: row.subject,
    spamScore: row.spamScore,
    verdict: row.verdict as EmailVerdict,
    reasons: parseJsonArray(row.reasons),
    spfResult: (row.spfResult as AuthResult | null) ?? null,
    dkimResult: (row.dkimResult as AuthResult | null) ?? null,
    dmarcResult: (row.dmarcResult as AuthResult | null) ?? null,
    attachmentsScanned: row.attachmentsScanned,
    sizeKb: row.sizeKb,
    createdAt: row.createdAt.toISOString(),
  };
}

function parseId(raw: string): number {
  const id = Number(raw);
  if (!Number.isInteger(id) || id <= 0) throw ApiError.notFound("Resource not found");
  return id;
}

/** mode=relay requires an upstream host — re-checked after partial merges. */
function assertUpstreamForRelay(mode: string, upstreamHost: string | null | undefined) {
  if (mode === "relay" && (upstreamHost === undefined || upstreamHost === null || upstreamHost.trim() === "")) {
    throw ApiError.validation("upstreamHost is required when mode is relay", {
      fieldErrors: { upstreamHost: ["upstreamHost is required when mode is relay"] },
    });
  }
}

/** action=relay requires a target host — re-checked after partial merges. */
function assertTargetForRelay(action: string, targetHost: string | null | undefined) {
  if (action === "relay" && (targetHost === undefined || targetHost === null || targetHost.trim() === "")) {
    throw ApiError.validation("targetHost is required when action is relay", {
      fieldErrors: { targetHost: ["targetHost is required when action is relay"] },
    });
  }
}

// ── gateways (spec 2.8.1) ───────────────────────────────────────────────────

export async function listGateways(tenantId: number): Promise<EmailGatewayDTO[]> {
  const rows = await db.emailGateway.findMany({ where: { tenantId }, orderBy: { name: "asc" } });
  return rows.map(toGatewayDTO);
}

export async function createGateway(tenantId: number, input: GatewayCreate): Promise<EmailGatewayDTO> {
  assertUpstreamForRelay(input.mode, input.upstreamHost ?? null);
  const created = await db.emailGateway.create({
    data: {
      tenantId,
      name: input.name,
      mode: input.mode,
      listenPort: input.listenPort,
      relayDomains: JSON.stringify(input.relayDomains),
      upstreamHost: input.upstreamHost?.trim() || null,
      tlsMode: input.tlsMode,
      enabled: input.enabled,
    },
  });
  return toGatewayDTO(created);
}

export async function updateGateway(
  tenantId: number,
  id: number,
  input: GatewayUpdate,
): Promise<EmailGatewayDTO> {
  const existing = await db.emailGateway.findFirst({ where: { id, tenantId } });
  if (!existing) throw ApiError.notFound("Email gateway not found");
  const merged = {
    mode: input.mode ?? existing.mode,
    upstreamHost: input.upstreamHost !== undefined ? input.upstreamHost : existing.upstreamHost,
  };
  assertUpstreamForRelay(merged.mode, merged.upstreamHost);
  const data: Prisma.EmailGatewayUpdateInput = {};
  if (input.name !== undefined) data.name = input.name;
  if (input.mode !== undefined) data.mode = input.mode;
  if (input.listenPort !== undefined) data.listenPort = input.listenPort;
  if (input.relayDomains !== undefined) data.relayDomains = JSON.stringify(input.relayDomains);
  if (input.upstreamHost !== undefined) data.upstreamHost = input.upstreamHost?.trim() || null;
  if (input.tlsMode !== undefined) data.tlsMode = input.tlsMode;
  if (input.enabled !== undefined) data.enabled = input.enabled;
  const updated = await db.emailGateway.update({ where: { id }, data });
  return toGatewayDTO(updated);
}

export async function deleteGateway(tenantId: number, id: number): Promise<{ ok: true }> {
  const row = await db.emailGateway.findFirst({ where: { id, tenantId }, select: { id: true } });
  if (!row) throw ApiError.notFound("Email gateway not found");
  await db.emailGateway.delete({ where: { id } });
  return { ok: true };
}

// ── policy singleton (spec 2.8.2) ───────────────────────────────────────────

export async function getOrCreatePolicy(tenantId: number): Promise<EmailPolicyDTO> {
  const existing = await db.emailPolicy.findFirst({ where: { tenantId }, orderBy: { id: "asc" } });
  if (existing) return toPolicyDTO(existing);
  const created = await db.emailPolicy.create({
    data: {
      tenantId,
      name: POLICY_NAME,
      spamThreshold: 6.0,
      blockPhishing: true,
      blockMalware: true,
      scanArchives: true,
      maxMessageSizeMb: 25,
      blockedExtensions: JSON.stringify(["exe", "js", "vbs", "scr", "bat"]),
      spfVerify: true,
      dkimVerify: true,
      dmarcPolicy: "quarantine",
      quarantineRetentionDays: 14,
      enabled: true,
    },
  });
  return toPolicyDTO(created);
}

export async function updatePolicy(tenantId: number, input: PolicyUpdate): Promise<EmailPolicyDTO> {
  const current = await getOrCreatePolicy(tenantId);
  const updated = await db.emailPolicy.update({
    where: { id: current.id },
    data: {
      spamThreshold: input.spamThreshold,
      blockPhishing: input.blockPhishing,
      blockMalware: input.blockMalware,
      scanArchives: input.scanArchives,
      maxMessageSizeMb: input.maxMessageSizeMb,
      blockedExtensions: JSON.stringify(input.blockedExtensions),
      spfVerify: input.spfVerify,
      dkimVerify: input.dkimVerify,
      dmarcPolicy: input.dmarcPolicy,
      quarantineRetentionDays: input.quarantineRetentionDays,
      enabled: input.enabled,
    },
  });
  return toPolicyDTO(updated);
}

// ── routing rules (spec 2.8.3 — priority unique per tenant → 409) ───────────

async function assertPriorityFree(tenantId: number, priority: number, excludeId?: number) {
  const clash = await db.emailRoutingRule.findFirst({
    where: { tenantId, priority, ...(excludeId !== undefined ? { id: { not: excludeId } } : {}) },
    select: { id: true, name: true },
  });
  if (clash) {
    throw ApiError.conflict(`Priority ${priority} is already used by rule "${clash.name}"`, {
      fieldErrors: { priority: [`Priority ${priority} is already used by rule "${clash.name}"`] },
    });
  }
}

export async function listRoutingRules(tenantId: number): Promise<EmailRoutingRuleDTO[]> {
  const rows = await db.emailRoutingRule.findMany({
    where: { tenantId },
    orderBy: [{ priority: "asc" }, { id: "asc" }],
  });
  return rows.map(toRuleDTO);
}

export async function createRoutingRule(
  tenantId: number,
  input: RoutingRuleCreate,
): Promise<EmailRoutingRuleDTO> {
  assertTargetForRelay(input.action, input.targetHost ?? null);
  await assertPriorityFree(tenantId, input.priority);
  const created = await db.emailRoutingRule.create({
    data: {
      tenantId,
      name: input.name,
      matchDomain: input.matchDomain,
      action: input.action,
      targetHost: input.targetHost?.trim() || null,
      priority: input.priority,
      enabled: input.enabled,
    },
  });
  return toRuleDTO(created);
}

export async function updateRoutingRule(
  tenantId: number,
  id: number,
  input: RoutingRuleUpdate,
): Promise<EmailRoutingRuleDTO> {
  const existing = await db.emailRoutingRule.findFirst({ where: { id, tenantId } });
  if (!existing) throw ApiError.notFound("Routing rule not found");
  const merged = {
    action: input.action ?? existing.action,
    targetHost: input.targetHost !== undefined ? input.targetHost : existing.targetHost,
    priority: input.priority ?? existing.priority,
  };
  assertTargetForRelay(merged.action, merged.targetHost);
  if (merged.priority !== existing.priority) {
    await assertPriorityFree(tenantId, merged.priority, id);
  }
  const data: Prisma.EmailRoutingRuleUpdateInput = {};
  if (input.name !== undefined) data.name = input.name;
  if (input.matchDomain !== undefined) data.matchDomain = input.matchDomain;
  if (input.action !== undefined) data.action = input.action;
  if (input.targetHost !== undefined) data.targetHost = input.targetHost?.trim() || null;
  if (input.priority !== undefined) data.priority = input.priority;
  if (input.enabled !== undefined) data.enabled = input.enabled;
  const updated = await db.emailRoutingRule.update({ where: { id }, data });
  return toRuleDTO(updated);
}

export async function deleteRoutingRule(tenantId: number, id: number): Promise<{ ok: true }> {
  const row = await db.emailRoutingRule.findFirst({ where: { id, tenantId }, select: { id: true } });
  if (!row) throw ApiError.notFound("Routing rule not found");
  await db.emailRoutingRule.delete({ where: { id } });
  return { ok: true };
}

// ── simulated test (spec 2.8.4 — persists an EmailLog row) ──────────────────

export async function testMessage(tenantId: number, input: EmailTestInput): Promise<EmailTestResultDTO> {
  const policy = await getOrCreatePolicy(tenantId);
  const result = scanMessage(policy, input);
  const row = await db.emailLog.create({
    data: {
      tenantId,
      fromAddr: input.from,
      toAddr: input.to,
      subject: input.subject ?? null,
      spamScore: result.spamScore,
      verdict: result.verdict,
      reasons: JSON.stringify(result.reasons),
      spfResult: result.spfResult,
      dkimResult: result.dkimResult,
      dmarcResult: result.dmarcResult,
      attachmentsScanned: result.attachmentsScanned,
      sizeKb: input.sizeKb ?? 0,
    },
  });
  return { ...result, spamScore: row.spamScore };
}

// ── mail log (paged-lite, spec 2.8.5) ───────────────────────────────────────

export async function listLogs(
  tenantId: number,
  q: EmailLogQuery,
): Promise<{ data: EmailLogDTO[]; meta: { page: number; limit: number; total: number; totalPages: number } }> {
  const where: Prisma.EmailLogWhereInput = {
    tenantId,
    ...(q.verdict !== undefined ? { verdict: q.verdict } : {}),
    ...(q.q
      ? {
          OR: [
            { fromAddr: { contains: q.q } },
            { toAddr: { contains: q.q } },
            { subject: { contains: q.q } },
          ],
        }
      : {}),
  };
  const [rows, total] = await Promise.all([
    db.emailLog.findMany({ where, orderBy: { createdAt: "desc" }, take: q.limit }),
    db.emailLog.count({ where }),
  ]);
  return { data: rows.map(toLogDTO), meta: { page: 1, limit: q.limit, total, totalPages: 1 } };
}

// ── stats (spec 2.8.6) ──────────────────────────────────────────────────────

export async function getStats(tenantId: number): Promise<EmailStatsDTO> {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const range = { tenantId, createdAt: { gte: since } };

  const [byVerdict, agg, reasonRows, policy] = await Promise.all([
    db.emailLog.groupBy({ by: ["verdict"], where: range, _count: { _all: true } }),
    db.emailLog.aggregate({ where: range, _avg: { spamScore: true } }),
    db.emailLog.findMany({ where: range, select: { reasons: true } }),
    getOrCreatePolicy(tenantId),
  ]);

  const verdictCount = (v: string) => byVerdict.find((r) => r.verdict === v)?._count._all ?? 0;

  const reasonCounts = new Map<string, number>();
  for (const row of reasonRows) {
    for (const reason of parseJsonArray(row.reasons)) {
      reasonCounts.set(reason, (reasonCounts.get(reason) ?? 0) + 1);
    }
  }
  const topReasons = [...reasonCounts.entries()]
    .map(([reason, count]) => ({ reason, count }))
    .sort((a, b) => b.count - a.count || a.reason.localeCompare(b.reason))
    .slice(0, 5);

  return {
    delivered24h: verdictCount("delivered"),
    quarantined24h: verdictCount("quarantined"),
    rejected24h: verdictCount("rejected"),
    avgSpamScore: Math.round((agg._avg.spamScore ?? 0) * 10) / 10,
    topReasons,
    quarantineRetentionDays: policy.quarantineRetentionDays,
  };
}

// ── quarantine release (spec 2.8.7) ─────────────────────────────────────────

export async function releaseQuarantined(tenantId: number, rawId: string): Promise<EmailLogDTO> {
  const id = parseId(rawId);
  const original = await db.emailLog.findFirst({ where: { id, tenantId } });
  if (!original) throw ApiError.notFound("Mail log entry not found");
  if (original.verdict !== "quarantined") {
    throw ApiError.conflict("Only quarantined messages can be released");
  }
  const released = await db.emailLog.create({
    data: {
      tenantId,
      fromAddr: original.fromAddr,
      toAddr: original.toAddr,
      subject: original.subject,
      spamScore: original.spamScore,
      verdict: "delivered",
      reasons: JSON.stringify([`released:${original.id}`]),
      spfResult: original.spfResult,
      dkimResult: original.dkimResult,
      dmarcResult: original.dmarcResult,
      attachmentsScanned: 0,
      sizeKb: original.sizeKb,
    },
  });
  return toLogDTO(released);
}
