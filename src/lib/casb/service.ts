/**
 * CASB service (Phase 4 §4.3) — SaaS visibility over the nDPI-derived
 * app-control log ring, shadow-IT classification against the tenant SaaS
 * catalog, and the API-based connector CONFIG shell for the top vendors
 * (Google Workspace, Microsoft 365, Salesforce, Dropbox, Slack).
 *
 * Scan semantics:
 *   • app_control_logs carry one directionless `bytes` counter per event —
 *     the scan accounts it as bytesIn (bytesOut stays 0) until
 *     direction-aware nDPI logs exist;
 *   • events aggregate per (clientIp, appHint) into SaasDiscovery rows
 *     (upsert accumulates sessions/bytes, tracks first/lastSeen) with the
 *     verdict re-classified on every scan via lib/casb/matcher;
 *   • appId is a LOGICAL ref to saas_app_catalog (null = unknown/shadow-IT
 *     candidate), mirroring the schema (no FK on SQLite).
 *
 * Connector shell: NO vendor network calls anywhere (spec §4.3 note — full
 * CASB needs 50+ SaaS API integrations; live sync is DEFERRED). testConnector
 * validates the stored configJson against a per-vendor required-key map and
 * requires at least one secret-store ref (`*SecretRef`/`*TokenRef`) — secrets
 * are never stored plaintext in configJson.
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import type { PageMeta } from "@/lib/api/envelope";
import { ensureSaasCatalog } from "@/lib/casb/catalog";
import { classifyVerdict, matchHint, type MatchCatalogEntry } from "@/lib/casb/matcher";
import type {
  CasbVendor,
  ConnectorPatch,
  ConnectorStatus,
  DiscoveryQuery,
  SaasAppCategory,
  SaasAppQuery,
  SaasAppUpdate,
  SaasVerdict,
} from "@/lib/validators/casb";

// ── locked vocabularies ─────────────────────────────────────────────────────

export const SAAS_CATEGORIES: SaasAppCategory[] = [
  "collaboration",
  "storage",
  "crm",
  "productivity",
  "devops",
  "other",
];

export const SAAS_VERDICTS: SaasVerdict[] = ["sanctioned", "shadow", "unknown"];

export const CASB_VENDORS: CasbVendor[] = [
  "google_workspace",
  "microsoft_365",
  "salesforce",
  "dropbox",
  "slack",
];

/**
 * Required config keys per vendor (shape validation only — the referenced
 * secrets are resolved by the vendor integration when live sync lands).
 * Every vendor's map includes at least one `*SecretRef`/`*TokenRef` entry.
 */
export const CONNECTOR_REQUIRED_KEYS: Record<CasbVendor, string[]> = {
  google_workspace: ["domain", "serviceAccountSecretRef"],
  microsoft_365: ["tenantId", "clientSecretRef"],
  salesforce: ["instanceUrl", "consumerSecretRef"],
  dropbox: ["accessTokenRef"],
  slack: ["botTokenRef"],
};

export const CONNECTOR_VENDOR_LABELS: Record<CasbVendor, string> = {
  google_workspace: "Google Workspace",
  microsoft_365: "Microsoft 365",
  salesforce: "Salesforce",
  dropbox: "Dropbox",
  slack: "Slack",
};

// ── DTOs ────────────────────────────────────────────────────────────────────

export interface SaasAppDTO {
  id: number;
  name: string;
  vendor: string;
  category: SaasAppCategory;
  domains: string[];
  riskScore: number;
  createdAt: string;
}

export interface SaasDiscoveryDTO {
  id: number;
  clientIp: string;
  appId: number | null;
  /** catalog name when attributed, else null */
  appName: string | null;
  appHint: string;
  verdict: SaasVerdict;
  sessions: number;
  bytesIn: number;
  bytesOut: number;
  category: SaasAppCategory | null;
  riskScore: number | null;
  firstSeenAt: string;
  lastSeenAt: string;
}

export interface CasbConnectorDTO {
  id: number;
  vendor: CasbVendor;
  vendorLabel: string;
  status: ConnectorStatus;
  config: Record<string, unknown>;
  requiredKeys: string[];
  missingKeys: string[];
  lastSyncAt: string | null;
  createdAt: string;
}

export interface ScanSummary {
  /** app-control log rows read inside the window */
  scanned: number;
  /** distinct (clientIp, appHint) discovery rows created or updated */
  upserted: number;
  sanctioned: number;
  shadow: number;
  unknown: number;
}

export interface CasbStats {
  total: number;
  byVerdict: Record<SaasVerdict, number>;
  topShadowApps: Array<{ appHint: string; sessions: number; bytes: number }>;
  topTalkers: Array<{ clientIp: string; sessions: number; bytes: number }>;
}

export interface ConnectorTestResult {
  id: number;
  vendor: CasbVendor;
  status: ConnectorStatus;
  ok: boolean;
  message: string;
  missingKeys: string[];
}

// ── shaping helpers ─────────────────────────────────────────────────────────

/** Parse the JSON domains column defensively — bad payload → []. */
function parseDomains(raw: string): string[] {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((v): v is string => typeof v === "string" && v.length > 0);
  } catch {
    return [];
  }
}

function parseConfig(raw: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // fall through
  }
  return {};
}

function toAppDTO(row: {
  id: number;
  name: string;
  vendor: string;
  category: string;
  domains: string;
  riskScore: number;
  createdAt: Date;
}): SaasAppDTO {
  return {
    id: row.id,
    name: row.name,
    vendor: row.vendor,
    category: row.category as SaasAppCategory,
    domains: parseDomains(row.domains),
    riskScore: row.riskScore,
    createdAt: row.createdAt.toISOString(),
  };
}

function missingConfigKeys(vendor: CasbVendor, config: Record<string, unknown>): string[] {
  const required = CONNECTOR_REQUIRED_KEYS[vendor] ?? [];
  return required.filter((key) => {
    const v = config[key];
    return typeof v !== "string" || v.trim().length === 0;
  });
}

function hasSecretRefKey(config: Record<string, unknown>): boolean {
  for (const [key, v] of Object.entries(config)) {
    const k = key.toLowerCase();
    if ((k.endsWith("secretref") || k.endsWith("tokenref")) && typeof v === "string" && v.trim().length > 0) {
      return true;
    }
  }
  return false;
}

function toConnectorDTO(row: {
  id: number;
  vendor: string;
  status: string;
  configJson: string;
  lastSyncAt: Date | null;
  createdAt: Date;
}): CasbConnectorDTO {
  const vendor = row.vendor as CasbVendor;
  const config = parseConfig(row.configJson);
  return {
    id: row.id,
    vendor,
    vendorLabel: CONNECTOR_VENDOR_LABELS[vendor] ?? vendor,
    status: row.status as ConnectorStatus,
    config,
    requiredKeys: CONNECTOR_REQUIRED_KEYS[vendor] ?? [],
    missingKeys: missingConfigKeys(vendor, config),
    lastSyncAt: row.lastSyncAt ? row.lastSyncAt.toISOString() : null,
    createdAt: row.createdAt.toISOString(),
  };
}

// ── catalog CRUD ────────────────────────────────────────────────────────────

export async function listSaasApps(
  tenantId: number,
  query: SaasAppQuery,
): Promise<{ data: SaasAppDTO[]; meta: PageMeta }> {
  const where = {
    tenantId,
    ...(query.category ? { category: query.category } : {}),
    ...(query.q
      ? {
          OR: [{ name: { contains: query.q } }, { vendor: { contains: query.q } }],
        }
      : {}),
  };
  const [rows, total] = await Promise.all([
    db.saasAppCatalog.findMany({
      where,
      orderBy: [{ name: "asc" }],
      skip: (query.page - 1) * query.limit,
      take: query.limit,
    }),
    db.saasAppCatalog.count({ where }),
  ]);
  return {
    data: rows.map(toAppDTO),
    meta: {
      page: query.page,
      limit: query.limit,
      total,
      totalPages: Math.max(1, Math.ceil(total / query.limit)),
    },
  };
}

export async function createSaasApp(
  tenantId: number,
  input: { name: string; vendor: string; category: SaasAppCategory; domains: string[]; riskScore: number },
): Promise<SaasAppDTO> {
  const dup = await db.saasAppCatalog.findFirst({ where: { tenantId, name: input.name } });
  if (dup) {
    throw ApiError.conflict(`SaaS app '${input.name}' already exists in the catalog`);
  }
  const created = await db.saasAppCatalog.create({
    data: {
      tenantId,
      name: input.name,
      vendor: input.vendor,
      category: input.category,
      domains: JSON.stringify(input.domains),
      riskScore: input.riskScore,
    },
  });
  return toAppDTO(created);
}

export async function updateSaasApp(tenantId: number, id: number, input: SaasAppUpdate): Promise<SaasAppDTO> {
  const row = await db.saasAppCatalog.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("SaaS app not found");
  if (input.name !== undefined && input.name !== row.name) {
    const dup = await db.saasAppCatalog.findFirst({ where: { tenantId, name: input.name } });
    if (dup) throw ApiError.conflict(`SaaS app '${input.name}' already exists in the catalog`);
  }
  const updated = await db.saasAppCatalog.update({
    where: { id: row.id },
    data: {
      ...(input.name !== undefined ? { name: input.name } : {}),
      ...(input.vendor !== undefined ? { vendor: input.vendor } : {}),
      ...(input.category !== undefined ? { category: input.category } : {}),
      ...(input.domains !== undefined ? { domains: JSON.stringify(input.domains) } : {}),
      ...(input.riskScore !== undefined ? { riskScore: input.riskScore } : {}),
    },
  });
  return toAppDTO(updated);
}

/**
 * Delete a catalog app. Discoveries keep their raw appHint (they are the
 * observation record) but lose the logical appId ref — the next scan
 * re-classifies them as unknown.
 */
export async function deleteSaasApp(tenantId: number, id: number): Promise<{ ok: true }> {
  const row = await db.saasAppCatalog.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("SaaS app not found");
  await db.saasDiscovery.updateMany({ where: { tenantId, appId: id }, data: { appId: null } });
  await db.saasAppCatalog.delete({ where: { id: row.id } });
  return { ok: true };
}

// ── discoveries ─────────────────────────────────────────────────────────────

export async function listDiscoveries(
  tenantId: number,
  query: DiscoveryQuery,
): Promise<{ data: SaasDiscoveryDTO[]; meta: PageMeta }> {
  // category is a catalog-side attribute — resolve matching app ids first
  let appIds: number[] | null = null;
  if (query.category) {
    const apps = await db.saasAppCatalog.findMany({
      where: { tenantId, category: query.category },
      select: { id: true },
    });
    appIds = apps.map((a) => a.id);
    if (appIds.length === 0) {
      return {
        data: [],
        meta: {
          page: query.page,
          limit: query.limit,
          total: 0,
          totalPages: Math.max(1, 0),
        },
      };
    }
  }
  const where = {
    tenantId,
    ...(query.verdict ? { verdict: query.verdict } : {}),
    ...(appIds ? { appId: { in: appIds } } : {}),
    ...(query.q
      ? {
          OR: [{ clientIp: { contains: query.q } }, { appHint: { contains: query.q } }],
        }
      : {}),
  };
  const [rows, total, apps] = await Promise.all([
    db.saasDiscovery.findMany({
      where,
      orderBy: [{ lastSeenAt: "desc" }],
      skip: (query.page - 1) * query.limit,
      take: query.limit,
    }),
    db.saasDiscovery.count({ where }),
    db.saasAppCatalog.findMany({
      where: { tenantId },
      select: { id: true, name: true, category: true, riskScore: true },
    }),
  ]);
  const appMap = new Map(apps.map((a) => [a.id, a]));
  return {
    data: rows.map((r) => {
      const app = r.appId !== null ? appMap.get(r.appId) : undefined;
      return {
        id: r.id,
        clientIp: r.clientIp,
        appId: r.appId,
        appName: app?.name ?? null,
        appHint: r.appHint,
        verdict: r.verdict as SaasVerdict,
        sessions: r.sessions,
        bytesIn: r.bytesIn,
        bytesOut: r.bytesOut,
        category: (app?.category as SaasAppCategory | undefined) ?? null,
        riskScore: app?.riskScore ?? null,
        firstSeenAt: r.firstSeenAt.toISOString(),
        lastSeenAt: r.lastSeenAt.toISOString(),
      };
    }),
    meta: {
      page: query.page,
      limit: query.limit,
      total,
      totalPages: Math.max(1, Math.ceil(total / query.limit)),
    },
  };
}

// ── scan (nDPI log aggregation → SaasDiscovery upserts) ─────────────────────

/**
 * Aggregate app-control logs inside `windowMinutes` (default 24h) into
 * SaasDiscovery rows keyed (tenantId, clientIp, appHint): sessions/bytes
 * ACCUMULATE across scans, first/lastSeen track the log timestamps and the
 * verdict is re-classified against the (auto-seeded) catalog. Returns the
 * honest zero summary when the window holds no log rows.
 */
export async function runScan(tenantId: number, opts?: { windowMinutes?: number }): Promise<ScanSummary> {
  const windowMinutes = opts?.windowMinutes ?? 1440;
  const since = new Date(Date.now() - windowMinutes * 60_000);

  await ensureSaasCatalog(tenantId);

  const [logs, catalogRows] = await Promise.all([
    db.appControlLog.findMany({
      where: { tenantId, createdAt: { gte: since } },
      orderBy: { createdAt: "asc" },
    }),
    db.saasAppCatalog.findMany({ where: { tenantId } }),
  ]);

  if (logs.length === 0) {
    return { scanned: 0, upserted: 0, sanctioned: 0, shadow: 0, unknown: 0 };
  }

  const catalog: MatchCatalogEntry[] = catalogRows.map((r) => ({
    id: r.id,
    name: r.name,
    vendor: r.vendor,
    category: r.category,
    domains: parseDomains(r.domains),
    riskScore: r.riskScore,
  }));

  // group per (clientIp, appHint) — the discovery unique key
  const groups = new Map<string, { clientIp: string; appHint: string; sessions: number; bytes: number; first: Date; last: Date }>();
  for (const log of logs) {
    const key = `${log.clientIp}\u0000${log.appName}`;
    const g = groups.get(key);
    if (g) {
      g.sessions += 1;
      g.bytes += log.bytes;
      if (log.createdAt < g.first) g.first = log.createdAt;
      if (log.createdAt > g.last) g.last = log.createdAt;
    } else {
      groups.set(key, {
        clientIp: log.clientIp,
        appHint: log.appName,
        sessions: 1,
        bytes: log.bytes,
        first: log.createdAt,
        last: log.createdAt,
      });
    }
  }

  const summary: ScanSummary = { scanned: logs.length, upserted: 0, sanctioned: 0, shadow: 0, unknown: 0 };

  for (const g of groups.values()) {
    const match = matchHint(g.appHint, catalog);
    const verdict = classifyVerdict(match);
    const appId = match ? match.app.id : null;
    summary.upserted += 1;
    summary[verdict] += 1;

    const existing = await db.saasDiscovery.findFirst({
      where: { tenantId, clientIp: g.clientIp, appHint: g.appHint },
    });
    if (existing) {
      await db.saasDiscovery.update({
        where: { id: existing.id },
        data: {
          appId,
          verdict,
          sessions: { increment: g.sessions },
          bytesIn: { increment: g.bytes },
          firstSeenAt: g.first < existing.firstSeenAt ? g.first : existing.firstSeenAt,
          lastSeenAt: g.last > existing.lastSeenAt ? g.last : existing.lastSeenAt,
        },
      });
    } else {
      await db.saasDiscovery.create({
        data: {
          tenantId,
          clientIp: g.clientIp,
          appId,
          appHint: g.appHint,
          verdict,
          sessions: g.sessions,
          bytesIn: g.bytes,
          bytesOut: 0,
          firstSeenAt: g.first,
          lastSeenAt: g.last,
        },
      });
    }
  }

  return summary;
}

// ── connectors (config shell — live vendor sync deferred, spec §4.3) ────────

export async function listConnectors(tenantId: number): Promise<CasbConnectorDTO[]> {
  const rows = await db.casbConnector.findMany({ where: { tenantId }, orderBy: { id: "asc" } });
  return rows.map(toConnectorDTO);
}

export async function createConnector(
  tenantId: number,
  input: { vendor: CasbVendor; config: Record<string, unknown> },
): Promise<CasbConnectorDTO> {
  const dup = await db.casbConnector.findFirst({ where: { tenantId, vendor: input.vendor } });
  if (dup) {
    throw ApiError.conflict(
      `A ${CONNECTOR_VENDOR_LABELS[input.vendor]} connector already exists — PATCH its config instead`,
    );
  }
  const created = await db.casbConnector.create({
    data: {
      tenantId,
      vendor: input.vendor,
      status: "disconnected",
      configJson: JSON.stringify(input.config),
    },
  });
  return toConnectorDTO(created);
}

export async function updateConnector(
  tenantId: number,
  id: number,
  input: ConnectorPatch,
): Promise<CasbConnectorDTO> {
  const row = await db.casbConnector.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Connector not found");
  const updated = await db.casbConnector.update({
    where: { id: row.id },
    data: {
      ...(input.config !== undefined ? { configJson: JSON.stringify(input.config) } : {}),
      ...(input.status !== undefined ? { status: input.status } : {}),
    },
  });
  return toConnectorDTO(updated);
}

export async function deleteConnector(tenantId: number, id: number): Promise<{ ok: true }> {
  const row = await db.casbConnector.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Connector not found");
  await db.casbConnector.delete({ where: { id: row.id } });
  return { ok: true };
}

/**
 * Shape-only connector test — NO network calls. Status flips to `connected`
 * only when every required key for the vendor holds a non-empty string AND a
 * secret-store ref (`*SecretRef`/`*TokenRef`) is present; anything else is an
 * `error` with the missing keys listed. `lastSyncAt` stamps the successful
 * shape validation (live vendor sync remains deferred per spec §4.3).
 */
export async function testConnector(tenantId: number, id: number): Promise<ConnectorTestResult> {
  const row = await db.casbConnector.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Connector not found");
  const vendor = row.vendor as CasbVendor;
  const config = parseConfig(row.configJson);

  const missingKeys = missingConfigKeys(vendor, config);
  const secretRef = hasSecretRefKey(config);
  const ok = missingKeys.length === 0 && secretRef;

  const message = ok
    ? "Config shape valid — secret ref present (live vendor sync deferred)"
    : missingKeys.length > 0
      ? `Missing or empty config keys: ${missingKeys.join(", ")}`
      : "No secret-store ref (*SecretRef/*TokenRef) in config — plaintext secrets are not accepted";

  const status: ConnectorStatus = ok ? "connected" : "error";
  await db.casbConnector.update({
    where: { id: row.id },
    data: { status, ...(ok ? { lastSyncAt: new Date() } : {}) },
  });

  return { id: row.id, vendor, status, ok, message, missingKeys };
}

// ── stats (console strip) ───────────────────────────────────────────────────

export async function getCasbStats(tenantId: number): Promise<CasbStats> {
  const [byVerdictRows, shadowRows, talkerRows, total] = await Promise.all([
    db.saasDiscovery.groupBy({ by: ["verdict"], where: { tenantId }, _count: { _all: true } }),
    db.saasDiscovery.groupBy({
      by: ["appHint"],
      where: { tenantId, verdict: "shadow" },
      _sum: { sessions: true, bytesIn: true, bytesOut: true },
      orderBy: { _sum: { sessions: "desc" } },
      take: 5,
    }),
    db.saasDiscovery.groupBy({
      by: ["clientIp"],
      where: { tenantId },
      _sum: { sessions: true, bytesIn: true, bytesOut: true },
      orderBy: { _sum: { bytesIn: "desc" } },
      take: 5,
    }),
    db.saasDiscovery.count({ where: { tenantId } }),
  ]);

  const byVerdict: Record<SaasVerdict, number> = { sanctioned: 0, shadow: 0, unknown: 0 };
  for (const r of byVerdictRows) {
    const key = r.verdict as SaasVerdict;
    if (key in byVerdict) byVerdict[key] = r._count._all;
  }

  return {
    total,
    byVerdict,
    topShadowApps: shadowRows.map((r) => ({
      appHint: r.appHint,
      sessions: r._sum.sessions ?? 0,
      bytes: (r._sum.bytesIn ?? 0) + (r._sum.bytesOut ?? 0),
    })),
    topTalkers: talkerRows.map((r) => ({
      clientIp: r.clientIp,
      sessions: r._sum.sessions ?? 0,
      bytes: (r._sum.bytesIn ?? 0) + (r._sum.bytesOut ?? 0),
    })),
  };
}
