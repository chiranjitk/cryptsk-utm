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
 *   • a per-tenant scan WATERMARK (audit fix F-d — SystemSetting category
 *     "casb" key "scan_watermark_<tenantId>") records the max AppControlLog
 *     id already aggregated, so re-scans count only NEW rows — the previous
 *     fixed-window re-ingest double-counted sessions/bytes on every run;
 *     a `{reset: true}` scan body re-aggregates from scratch (watermark
 *     cleared for that run, then re-stamped);
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
import { getSetting, putSettingsBatch } from "@/lib/system/service";
import type { SettingsEntry } from "@/lib/validators/system";
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

/**
 * audit fix M5 — secret-shaped config keys may only carry secret-STORE
 * REFERENCES, never plaintext credentials. A key named like a secret
 * (secret/token/password/credential/apikey/api_key, case-insensitive) must
 * either end in `Ref` (the documented *SecretRef/*TokenRef convention) or
 * carry a `scheme://` store-URI value (vault://, sm://, …). Plaintext API
 * tokens used to be accepted silently AND echoed back in cleartext by every
 * read — dead-guard removed, enforcement now runs at every write.
 */
const SECRET_KEY_RE = /(secret|token|password|credential|apikey|api_key|clientsecret)/i;
const STORE_URI_RE = /^[a-z][a-z0-9._-]{1,31}:\/\//i;

export function isPlaintextSecretValue(key: string, value: unknown): boolean {
  if (!SECRET_KEY_RE.test(key)) return false;
  if (typeof value !== "string" || value.trim().length === 0) return false;
  if (/ref$/i.test(key)) return false; // *SecretRef/*TokenRef — reference by name
  if (STORE_URI_RE.test(value)) return false; // store URI — reference by value
  return true;
}

/** audit fix M5 — sentinel for masking legacy plaintext secrets in DTOs. */
export const CASB_SECRET_MASK = "__STORED_SECRET__";

/** Reject config objects carrying plaintext secret values (create + update). */
function assertNoPlaintextSecrets(config: Record<string, unknown>): void {
  for (const [key, value] of Object.entries(config)) {
    if (isPlaintextSecretValue(key, value)) {
      throw ApiError.validation(
        `Config key "${key}" looks like a plaintext secret — store the credential in the secret store and pass a reference (*SecretRef/*TokenRef or scheme:// URI)`,
      );
    }
  }
}

/** True when the patch carries the DTO mask back — treated as keep-stored. */
function containsMaskedSecret(config: Record<string, unknown>): boolean {
  return Object.values(config).some((v) => v === CASB_SECRET_MASK);
}

/** Mask legacy plaintext secret values for API responses (values stay intact in the DB). */
function maskSecretsForDTO(config: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(config)) {
    out[key] = isPlaintextSecretValue(key, value) ? CASB_SECRET_MASK : value;
  }
  return out;
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
    // audit fix M5 — legacy plaintext secret values never leave the server
    config: maskSecretsForDTO(config),
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
 * Scan watermark (audit fix F-d): the max AppControlLog id already aggregated
 * for the tenant, stored under SystemSetting category "casb", key
 * "scan_watermark_<tenantId>" (the M10 settings category enum predates the
 * casb category — the DB column is a plain string and putSettingsBatch applies
 * no per-key runtime schema, so the SASE-module cast convention applies and
 * ONE settings write path is reused instead of a parallel helper).
 */
const CASB_SETTINGS_CATEGORY = "casb";
const scanWatermarkKey = (tenantId: number): string => `scan_watermark_${tenantId}`;

async function readScanWatermark(tenantId: number): Promise<number> {
  const stored = await getSetting<{ maxLogId?: unknown }>(tenantId, CASB_SETTINGS_CATEGORY, scanWatermarkKey(tenantId), {});
  return typeof stored?.maxLogId === "number" && Number.isFinite(stored.maxLogId) ? stored.maxLogId : 0;
}

async function writeScanWatermark(tenantId: number, maxLogId: number): Promise<void> {
  await putSettingsBatch(tenantId, [
    { category: CASB_SETTINGS_CATEGORY, key: scanWatermarkKey(tenantId), value: { maxLogId } } as unknown as SettingsEntry,
  ]);
}

/**
 * Aggregate app-control logs newer than the per-tenant scan watermark (and
 * inside `windowMinutes`, default 24h) into SaasDiscovery rows keyed
 * (tenantId, clientIp, appHint): sessions/bytes ACCUMULATE across scans,
 * first/lastSeen track the log timestamps and the verdict is re-classified
 * against the (auto-seeded) catalog. `{reset: true}` clears the watermark for
 * that run so the whole window is re-aggregated. Returns the honest zero
 * summary when no NEW log rows are in scope.
 */
export async function runScan(tenantId: number, opts?: { windowMinutes?: number; reset?: boolean }): Promise<ScanSummary> {
  const windowMinutes = opts?.windowMinutes ?? 1440;
  const since = new Date(Date.now() - windowMinutes * 60_000);

  await ensureSaasCatalog(tenantId);

  // watermark: only rows the tenant has NEVER scanned participate (audit fix
  // F-d — repeated scans no longer double-count sessions/bytes); reset → 0
  const watermark = opts?.reset ? 0 : await readScanWatermark(tenantId);

  const [logs, catalogRows] = await Promise.all([
    db.appControlLog.findMany({
      where: {
        tenantId,
        createdAt: { gte: since },
        ...(watermark > 0 ? { id: { gt: watermark } } : {}),
      },
      orderBy: { createdAt: "asc" },
      // audit fix M6 — bounded aggregation: select only the grouped columns
      // and cap the window materialization; a 30-day scan over a huge log
      // table can no longer pin memory with an unbounded findMany.
      take: 10_000,
      select: { id: true, clientIp: true, appName: true, bytes: true, createdAt: true },
    }),
    db.saasAppCatalog.findMany({ where: { tenantId } }),
  ]);

  // stamp the new high-water id even when nothing new was scanned (cheap
  // upsert; keeps the watermark monotonic with the log table)
  const maxScannedId = logs.reduce((max, l) => Math.max(max, l.id), watermark);
  await writeScanWatermark(tenantId, maxScannedId);

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

    // UPSERT on the @@unique([tenantId, clientIp, appHint]) key (audit fix
    // F-d): the old findFirst→update/create pair raced under concurrent scans
    // (two creates → P2002 crash). The read below only feeds the min/max
    // merge; the WRITE is a single atomic prisma upsert, so a concurrent
    // scan cannot wedge the row.
    const existing = await db.saasDiscovery.findFirst({
      where: { tenantId, clientIp: g.clientIp, appHint: g.appHint },
    });
    await db.saasDiscovery.upsert({
      where: { tenantId_clientIp_appHint: { tenantId, clientIp: g.clientIp, appHint: g.appHint } },
      update: {
        appId,
        verdict,
        sessions: { increment: g.sessions },
        bytesIn: { increment: g.bytes },
        ...(existing && g.first < existing.firstSeenAt ? { firstSeenAt: g.first } : {}),
        lastSeenAt: !existing || g.last > existing.lastSeenAt ? g.last : existing.lastSeenAt,
      },
      create: {
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
  assertNoPlaintextSecrets(input.config); // audit fix M5
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
  let configJson: string | undefined;
  if (input.config !== undefined) {
    // audit fix M5 — the DTO mask round-trips as "keep the stored value";
    // plaintext secrets are hard-rejected.
    if (containsMaskedSecret(input.config)) {
      const stored = parseConfig(row.configJson);
      for (const [key, value] of Object.entries(input.config)) {
        if (value === CASB_SECRET_MASK) {
          const storedValue = stored[key];
          if (storedValue === undefined) {
            throw ApiError.validation(`Config key "${key}" has no stored value to keep — provide a real value`);
          }
          input.config[key] = storedValue;
        }
      }
    }
    assertNoPlaintextSecrets(input.config);
    configJson = JSON.stringify(input.config);
  }
  const updated = await db.casbConnector.update({
    where: { id: row.id },
    data: {
      ...(configJson !== undefined ? { configJson } : {}),
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
