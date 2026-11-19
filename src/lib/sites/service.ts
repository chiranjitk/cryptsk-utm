/**
 * Multi-Site Central Manager service (Phase 4 §4.1) — DB-backed fleet
 * operations over ManagedSite / SiteTemplate / SiteDeployment /
 * FirmwareCatalog: site CRUD with per-tenant name uniqueness, the
 * plan → push → applied deployment flow (policy/template/firmware bundles),
 * site templates ("deploy new site from template") and the per-channel
 * firmware catalog with checksummed releases.
 *
 * Push transport simulation — remote push transport (API + WebSocket to the
 * site agent, spec §4.1) is OUT OF SCOPE for the console: after recording the
 * deployment in `pushing`, the service resolves it immediately —
 *   site.status === "never_seen" → status "failed", result.errors
 *     ["site has never connected"] (transport never had a target session),
 *   otherwise → status "applied" with pushedAt/appliedAt stamped.
 * The row stays the immutable audit trail of what the central manager sent.
 * A successful firmware push also stamps the reported console version on the
 * site (the version the site will run after the upgrade), keeping the fleet
 * table coherent with the deployment history.
 *
 * SQLite has no Prisma relations on SiteDeployment.siteId/templateId (logical
 * refs), so cross-table reads are explicit findMany calls — same pattern as
 * the incident timeline module.
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import type { PageMeta } from "@/lib/api/envelope";
import type {
  DeploymentKind,
  DeploymentQuery,
  DeploymentStatus,
  FirmwareCreate,
  SiteCreate,
  SitePush,
  SiteQuery,
  SiteRole,
  SiteStatus,
  SiteUpdate,
  TemplateCreate,
  TemplateUpdate,
} from "@/lib/validators/sites";

// ── locked vocabularies (schema.prisma comments + spec §4.1) ────────────────

export const SITE_ROLES: SiteRole[] = ["hub", "spoke", "standalone"];

export const SITE_STATUSES: SiteStatus[] = ["online", "offline", "degraded", "never_seen"];

export const DEPLOYMENT_KINDS: DeploymentKind[] = ["policy", "template", "firmware"];

export const DEPLOYMENT_STATUSES: DeploymentStatus[] = ["pending", "pushing", "applied", "failed"];

// ── DTOs ────────────────────────────────────────────────────────────────────

export interface SiteLimits {
  maxRules?: number;
  maxCpuPct?: number;
  maxTunnelCount?: number;
  [key: string]: unknown;
}

export interface SiteDTO {
  id: number;
  name: string;
  region: string;
  role: SiteRole;
  publicEndpoint: string;
  version: string;
  status: SiteStatus;
  lastSeenAt: string | null;
  resourceLimits: SiteLimits;
  notes: string;
  createdAt: string;
}

export interface TemplateDTO {
  id: number;
  name: string;
  description: string;
  version: string;
  payload: Record<string, unknown>;
  createdAt: string;
}

export interface DeploymentResult {
  applied: string[];
  skipped: string[];
  errors: string[];
}

export interface DeploymentDTO {
  id: number;
  siteId: number;
  siteName: string | null;
  templateId: number | null;
  kind: DeploymentKind;
  status: DeploymentStatus;
  payload: Record<string, unknown>;
  result: DeploymentResult;
  pushedAt: string | null;
  appliedAt: string | null;
  createdAt: string;
}

export interface FirmwareDTO {
  id: number;
  version: string;
  channel: "stable" | "beta";
  sha256: string;
  releaseNotes: string;
  releasedAt: string | null;
  createdAt: string;
}

export interface SiteStats {
  total: number;
  byStatus: Record<SiteStatus, number>;
  byRole: Record<SiteRole, number>;
  deployments7d: number;
}

// ── shaping helpers ─────────────────────────────────────────────────────────

function parseObject(raw: string | null | undefined): Record<string, unknown> {
  if (!raw) return {};
  try {
    const v = JSON.parse(raw);
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

function parseResult(raw: string | null | undefined): DeploymentResult {
  const obj = parseObject(raw);
  const arr = (key: string): string[] =>
    Array.isArray(obj[key]) ? (obj[key] as unknown[]).filter((x): x is string => typeof x === "string") : [];
  return { applied: arr("applied"), skipped: arr("skipped"), errors: arr("errors") };
}

function toSiteDTO(row: {
  id: number;
  name: string;
  region: string;
  role: string;
  publicEndpoint: string;
  version: string;
  status: string;
  lastSeenAt: Date | null;
  resourceLimits: string;
  notes: string;
  createdAt: Date;
}): SiteDTO {
  return {
    id: row.id,
    name: row.name,
    region: row.region,
    role: row.role as SiteRole,
    publicEndpoint: row.publicEndpoint,
    version: row.version,
    status: row.status as SiteStatus,
    lastSeenAt: row.lastSeenAt ? row.lastSeenAt.toISOString() : null,
    resourceLimits: parseObject(row.resourceLimits),
    notes: row.notes,
    createdAt: row.createdAt.toISOString(),
  };
}

function toTemplateDTO(row: {
  id: number;
  name: string;
  description: string;
  version: string;
  payload: string;
  createdAt: Date;
}): TemplateDTO {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    version: row.version,
    payload: parseObject(row.payload),
    createdAt: row.createdAt.toISOString(),
  };
}

function toDeploymentDTO(
  row: {
    id: number;
    siteId: number;
    templateId: number | null;
    kind: string;
    status: string;
    payload: string;
    result: string;
    pushedAt: Date | null;
    appliedAt: Date | null;
    createdAt: Date;
  },
  siteName: string | null,
): DeploymentDTO {
  return {
    id: row.id,
    siteId: row.siteId,
    siteName,
    templateId: row.templateId,
    kind: row.kind as DeploymentKind,
    status: row.status as DeploymentStatus,
    payload: parseObject(row.payload),
    result: parseResult(row.result),
    pushedAt: row.pushedAt ? row.pushedAt.toISOString() : null,
    appliedAt: row.appliedAt ? row.appliedAt.toISOString() : null,
    createdAt: row.createdAt.toISOString(),
  };
}

function toFirmwareDTO(row: {
  id: number;
  version: string;
  channel: string;
  sha256: string;
  releaseNotes: string;
  releasedAt: Date | null;
  createdAt: Date;
}): FirmwareDTO {
  return {
    id: row.id,
    version: row.version,
    channel: row.channel as "stable" | "beta",
    sha256: row.sha256,
    releaseNotes: row.releaseNotes,
    releasedAt: row.releasedAt ? row.releasedAt.toISOString() : null,
    createdAt: row.createdAt.toISOString(),
  };
}

function isUniqueViolation(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { code?: unknown }).code === "P2002";
}

/** Deployments wedged in `pushing` longer than this are swept to failed. */
const STUCK_PUSH_MS = 10 * 60 * 1000;

const STUCK_PUSH_RESULT = JSON.stringify({
  applied: [],
  skipped: [],
  errors: ["stuck in 'pushing' > 10min — marked failed by the console sweep"],
});

/**
 * Best-effort stuck-push sweep (audit fix F-d): deployments whose transport
 * resolution never ran (process crash between create and the terminal
 * update) would otherwise sit in `pushing` forever. Any listSites pass sweeps
 * rows older than STUCK_PUSH_MS to failed; failures are swallowed (the list
 * must keep working even if the sweep write loses a race with a live push).
 */
async function sweepStuckPushes(tenantId: number): Promise<void> {
  const cutoff = new Date(Date.now() - STUCK_PUSH_MS);
  // audit fix L19 — tenant-scoped: a GET from tenant A must never mutate
  // tenant B's deployment rows (the sweep previously ran cross-tenant as a
  // side effect of listSites, making the read non-idempotent and leaky).
  await db.siteDeployment
    .updateMany({
      where: { tenantId, status: "pushing", pushedAt: { lt: cutoff } },
      data: { status: "failed", result: STUCK_PUSH_RESULT },
    })
    .catch(() => {});
}

// ── sites ───────────────────────────────────────────────────────────────────

export async function listSites(
  tenantId: number,
  query: SiteQuery,
): Promise<{ data: SiteDTO[]; meta: PageMeta }> {
  // best-effort sweep of wedged `pushing` deployments (audit fix F-d; scoped
  // to the caller's tenant per audit fix L19)
  await sweepStuckPushes(tenantId);
  const where = {
    tenantId,
    ...(query.status ? { status: query.status } : {}),
    ...(query.role ? { role: query.role } : {}),
    ...(query.q
      ? {
          OR: [
            { name: { contains: query.q } },
            { region: { contains: query.q } },
            { publicEndpoint: { contains: query.q } },
          ],
        }
      : {}),
  };
  const [rows, total] = await Promise.all([
    db.managedSite.findMany({
      where,
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      skip: (query.page - 1) * query.limit,
      take: query.limit,
    }),
    db.managedSite.count({ where }),
  ]);
  return {
    data: rows.map(toSiteDTO),
    meta: { page: query.page, limit: query.limit, total, totalPages: Math.max(1, Math.ceil(total / query.limit)) },
  };
}

export async function getSite(tenantId: number, id: number): Promise<SiteDTO> {
  const row = await db.managedSite.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Site not found");
  return toSiteDTO(row);
}

async function assertSiteNameFree(tenantId: number, name: string, excludeId?: number): Promise<void> {
  const dup = await db.managedSite.findFirst({ where: { tenantId, name } });
  if (dup && dup.id !== excludeId) {
    throw ApiError.conflict(`Site '${name}' already exists`);
  }
}

export async function createSite(tenantId: number, input: SiteCreate, _actor: string): Promise<SiteDTO> {
  await assertSiteNameFree(tenantId, input.name);
  const row = await db.managedSite
    .create({
      data: {
        tenantId,
        name: input.name,
        region: input.region,
        role: input.role,
        publicEndpoint: input.publicEndpoint,
        version: input.version,
        status: input.status,
        resourceLimits: JSON.stringify(input.resourceLimits ?? {}),
        notes: input.notes,
      },
    })
    .catch((err) => {
      if (isUniqueViolation(err)) throw ApiError.conflict(`Site '${input.name}' already exists`);
      throw err;
    });
  return toSiteDTO(row);
}

export async function updateSite(tenantId: number, id: number, patch: SiteUpdate): Promise<SiteDTO> {
  const row = await db.managedSite.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Site not found");
  if (patch.name && patch.name !== row.name) {
    await assertSiteNameFree(tenantId, patch.name, id);
  }
  const updated = await db.managedSite
    .update({
      where: { id: row.id },
      data: {
        ...(patch.name !== undefined ? { name: patch.name } : {}),
        ...(patch.region !== undefined ? { region: patch.region } : {}),
        ...(patch.role !== undefined ? { role: patch.role } : {}),
        ...(patch.publicEndpoint !== undefined ? { publicEndpoint: patch.publicEndpoint } : {}),
        ...(patch.version !== undefined ? { version: patch.version } : {}),
        ...(patch.status !== undefined ? { status: patch.status } : {}),
        ...(patch.resourceLimits !== undefined ? { resourceLimits: JSON.stringify(patch.resourceLimits) } : {}),
        ...(patch.notes !== undefined ? { notes: patch.notes } : {}),
      },
    })
    .catch((err) => {
      if (isUniqueViolation(err)) throw ApiError.conflict(`Site '${patch.name ?? row.name}' already exists`);
      throw err;
    });
  return toSiteDTO(updated);
}

/**
 * DELETE — removes the site and its deployment history (transport audit
 * trail of a removed instance is meaningless; central audit_log entries
 * stay). SiteDeployments reference sites logically (no FK cascade), so the
 * cleanup is explicit.
 */
export async function deleteSite(tenantId: number, id: number): Promise<{ ok: true }> {
  const row = await db.managedSite.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Site not found");
  await db.siteDeployment.deleteMany({ where: { tenantId, siteId: id } });
  await db.managedSite.delete({ where: { id: row.id } });
  return { ok: true };
}

// ── push (plan → push → applied) ────────────────────────────────────────────

/**
 * Push a bundle to a site. Validates the target site (and the referenced
 * template / catalog firmware release), records the SiteDeployment in
 * `pushing` with pushedAt, then resolves the simulated transport in place —
 * see the module docstring for why the remote hop is out of scope.
 */
export async function pushToSite(
  tenantId: number,
  siteId: number,
  input: SitePush,
  _actor: string,
): Promise<DeploymentDTO> {
  const site = await db.managedSite.findFirst({ where: { id: siteId, tenantId } });
  if (!site) throw ApiError.notFound("Site not found");

  let payload: Record<string, unknown> = input.payload ?? {};
  let templateId: number | null = null;

  if (input.kind === "template") {
    const template = await db.siteTemplate.findFirst({ where: { id: input.templateId!, tenantId } });
    if (!template) throw ApiError.notFound("Site template not found");
    templateId = template.id;
    payload = {
      templateName: template.name,
      templateVersion: template.version,
      bundle: parseObject(template.payload),
    };
  } else if (input.kind === "firmware") {
    const release = await db.firmwareCatalog.findFirst({
      where: { tenantId, version: input.firmwareVersion! },
    });
    if (!release) {
      throw ApiError.notFound(`Firmware release '${input.firmwareVersion}' is not in the catalog`);
    }
    payload = { firmwareVersion: release.version, channel: release.channel, sha256: release.sha256 };
  }

  // ATOMICITY (audit fix F-d): deployment create + terminal update + the
  // firmware version stamp run in ONE transaction — the previous sequence
  // could persist a `pushing` row (or a stamped version) without its terminal
  // state on a mid-flight failure. The simulated transport is pure
  // computation, so the whole push fits a single tx; genuinely long remote
  // transports would keep the create-then-resolve shape + the stuck sweep.
  const final = await db.$transaction(async (tx) => {
    const row = await tx.siteDeployment.create({
      data: {
        tenantId,
        siteId,
        templateId,
        kind: input.kind,
        status: "pushing",
        payload: JSON.stringify(payload),
        result: JSON.stringify({ applied: [], skipped: [], errors: [] }),
        pushedAt: new Date(),
      },
    });

    // ── simulated transport (remote push out of scope — module docstring) ──
    const neverConnected = site.status === "never_seen";
    const applied: string[] = [];
    if (!neverConnected) {
      if (input.kind === "policy") {
        applied.push("policy bundle");
      } else if (input.kind === "template") {
        applied.push(`template bundle ${String(payload.templateName)} v${String(payload.templateVersion)}`);
      } else {
        applied.push(`firmware ${input.firmwareVersion}`);
      }
    }
    const result: DeploymentResult = neverConnected
      ? { applied: [], skipped: [], errors: ["site has never connected"] }
      : { applied, skipped: [], errors: [] };

    const updated = await tx.siteDeployment.update({
      where: { id: row.id },
      data: {
        status: neverConnected ? "failed" : "applied",
        result: JSON.stringify(result),
        ...(neverConnected ? {} : { appliedAt: new Date() }),
      },
    });

    // Successful firmware upgrade → the site now reports the pushed version.
    if (input.kind === "firmware" && !neverConnected) {
      await tx.managedSite.update({ where: { id: site.id }, data: { version: input.firmwareVersion! } });
    }
    return updated;
  });

  return toDeploymentDTO(final, site.name);
}

// ── deployments ─────────────────────────────────────────────────────────────

export async function listDeployments(
  tenantId: number,
  query: DeploymentQuery,
): Promise<{ data: DeploymentDTO[]; meta: PageMeta }> {
  const where = {
    tenantId,
    ...(query.siteId ? { siteId: query.siteId } : {}),
    ...(query.kind ? { kind: query.kind } : {}),
    ...(query.status ? { status: query.status } : {}),
  };
  const [rows, total, sites] = await Promise.all([
    db.siteDeployment.findMany({
      where,
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      skip: (query.page - 1) * query.limit,
      take: query.limit,
    }),
    db.siteDeployment.count({ where }),
    db.managedSite.findMany({ where: { tenantId }, select: { id: true, name: true } }),
  ]);
  const names = new Map(sites.map((s) => [s.id, s.name]));
  return {
    data: rows.map((r) => toDeploymentDTO(r, names.get(r.siteId) ?? null)),
    meta: { page: query.page, limit: query.limit, total, totalPages: Math.max(1, Math.ceil(total / query.limit)) },
  };
}

// ── site templates ──────────────────────────────────────────────────────────

export async function listTemplates(tenantId: number): Promise<TemplateDTO[]> {
  const rows = await db.siteTemplate.findMany({
    where: { tenantId },
    orderBy: [{ name: "asc" }, { id: "asc" }],
  });
  return rows.map(toTemplateDTO);
}

export async function getTemplate(tenantId: number, id: number): Promise<TemplateDTO> {
  const row = await db.siteTemplate.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Site template not found");
  return toTemplateDTO(row);
}

async function assertTemplateNameFree(tenantId: number, name: string, excludeId?: number): Promise<void> {
  const dup = await db.siteTemplate.findFirst({ where: { tenantId, name } });
  if (dup && dup.id !== excludeId) {
    throw ApiError.conflict(`Site template '${name}' already exists`);
  }
}

export async function createTemplate(tenantId: number, input: TemplateCreate): Promise<TemplateDTO> {
  await assertTemplateNameFree(tenantId, input.name);
  const row = await db.siteTemplate
    .create({
      data: {
        tenantId,
        name: input.name,
        description: input.description,
        version: input.version,
        payload: JSON.stringify(input.payload),
      },
    })
    .catch((err) => {
      if (isUniqueViolation(err)) throw ApiError.conflict(`Site template '${input.name}' already exists`);
      throw err;
    });
  return toTemplateDTO(row);
}

export async function updateTemplate(tenantId: number, id: number, patch: TemplateUpdate): Promise<TemplateDTO> {
  const row = await db.siteTemplate.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Site template not found");
  if (patch.name && patch.name !== row.name) {
    await assertTemplateNameFree(tenantId, patch.name, id);
  }
  const updated = await db.siteTemplate
    .update({
      where: { id: row.id },
      data: {
        ...(patch.name !== undefined ? { name: patch.name } : {}),
        ...(patch.description !== undefined ? { description: patch.description } : {}),
        ...(patch.version !== undefined ? { version: patch.version } : {}),
        ...(patch.payload !== undefined ? { payload: JSON.stringify(patch.payload) } : {}),
      },
    })
    .catch((err) => {
      if (isUniqueViolation(err)) throw ApiError.conflict(`Site template '${patch.name ?? row.name}' already exists`);
      throw err;
    });
  return toTemplateDTO(updated);
}

/**
 * DELETE — deployments already pushed from this template keep their payload
 * snapshot (logical templateId ref), so removal never rewrites history.
 */
export async function deleteTemplate(tenantId: number, id: number): Promise<{ ok: true }> {
  const row = await db.siteTemplate.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Site template not found");
  await db.siteTemplate.delete({ where: { id: row.id } });
  return { ok: true };
}

// ── firmware catalog ────────────────────────────────────────────────────────

export async function listFirmware(tenantId: number): Promise<FirmwareDTO[]> {
  const rows = await db.firmwareCatalog.findMany({
    where: { tenantId },
    orderBy: [{ createdAt: "desc" }, { id: "desc" }],
  });
  return rows.map(toFirmwareDTO);
}

export async function addFirmware(tenantId: number, input: FirmwareCreate): Promise<FirmwareDTO> {
  const dup = await db.firmwareCatalog.findFirst({
    where: { tenantId, channel: input.channel, version: input.version },
  });
  if (dup) {
    throw ApiError.conflict(`Firmware '${input.version}' already exists on the ${input.channel} channel`);
  }
  const row = await db.firmwareCatalog
    .create({
      data: {
        tenantId,
        version: input.version,
        channel: input.channel,
        sha256: input.sha256.toLowerCase(),
        releaseNotes: input.releaseNotes,
        releasedAt: new Date(),
      },
    })
    .catch((err) => {
      if (isUniqueViolation(err)) {
        throw ApiError.conflict(`Firmware '${input.version}' already exists on the ${input.channel} channel`);
      }
      throw err;
    });
  return toFirmwareDTO(row);
}

// ── stats (fleet strip) ─────────────────────────────────────────────────────

export async function getSiteStats(tenantId: number): Promise<SiteStats> {
  const weekAgo = new Date(Date.now() - 7 * 24 * 3600_000);
  const [statusGroups, roleGroups, total, deployments7d] = await Promise.all([
    db.managedSite.groupBy({ by: ["status"], where: { tenantId }, _count: { _all: true } }),
    db.managedSite.groupBy({ by: ["role"], where: { tenantId }, _count: { _all: true } }),
    db.managedSite.count({ where: { tenantId } }),
    db.siteDeployment.count({ where: { tenantId, createdAt: { gte: weekAgo } } }),
  ]);

  const byStatus: Record<SiteStatus, number> = { online: 0, offline: 0, degraded: 0, never_seen: 0 };
  for (const g of statusGroups) {
    const key = g.status as SiteStatus;
    if (key in byStatus) byStatus[key] = g._count._all;
  }
  const byRole: Record<SiteRole, number> = { hub: 0, spoke: 0, standalone: 0 };
  for (const g of roleGroups) {
    const key = g.role as SiteRole;
    if (key in byRole) byRole[key] = g._count._all;
  }

  return { total, byStatus, byRole, deployments7d };
}
