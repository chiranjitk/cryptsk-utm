/**
 * System service (M10) — settings store, appliance health, backups/restore
 * (JSON files under db/backups — NOT a Prisma model, SCHEMA.md §6), firmware
 * state machine (advanced/firmware setting), SSH keys, policy templates,
 * service restart simulation and the setup gate.
 * Per M10-SYSTEM.md §5.2-§5.8.
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { parseJson, stringifyJson } from "@/lib/json";
import { ulid } from "@/lib/ulid";
import { emitEvent } from "@/lib/engine/events";
import { getMockEngine } from "@/lib/engine/mock-engine";
import { MASK } from "@/lib/identity/service";
import type { SettingsEntry, BackupCreateInput, SshKeyCreateInput } from "@/lib/validators/system";
import { RETENTION_HARD_CAPS } from "@/lib/validators/system";

// ── Settings (M10 §5.2) ─────────────────────────────────────────────────────

/** Grouped settings map: { [category]: { [key]: parsedValue } } — all rows. */
export async function getSettingsGrouped(
  tenantId: number,
): Promise<Record<string, Record<string, unknown>>> {
  const rows = await db.systemSetting.findMany({ where: { tenantId } });
  const out: Record<string, Record<string, unknown>> = {};
  for (const r of rows) {
    out[r.category] ??= {};
    out[r.category][r.key] = parseJson<unknown>(r.value, null);
  }
  return out;
}

/**
 * Batch upsert (tx). Write-only masking rule (M10 §8 / M07 §5.3): the
 * fixed-length MASK literal on `advanced/snmp`.community means "keep the
 * stored value" — the masked form never overwrites the real secret.
 */
export async function putSettingsBatch(tenantId: number, entries: SettingsEntry[]): Promise<number> {
  await db.$transaction(async (tx) => {
    for (const entry of entries) {
      let value = entry.value;
      if (entry.category === "advanced" && entry.key === "snmp") {
        const snmp = { ...(value as Record<string, unknown>) };
        if (snmp.community === MASK) {
          const stored = await tx.systemSetting
            .findUnique({ where: { tenantId_category_key: { tenantId, category: "advanced", key: "snmp" } } })
            .catch(() => null);
          const storedCommunity = stored ? (parseJson<Record<string, unknown>>(stored.value, {}).community as string | undefined) : undefined;
          if (storedCommunity) snmp.community = storedCommunity;
          else delete snmp.community;
        }
        value = snmp;
      }
      await tx.systemSetting.upsert({
        where: { tenantId_category_key: { tenantId, category: entry.category, key: entry.key } },
        update: { value: stringifyJson(value) },
        create: { tenantId, category: entry.category, key: entry.key, value: stringifyJson(value) },
      });
    }
  });
  return entries.length;
}

export async function getSetting<T>(tenantId: number, category: string, key: string, fallback: T): Promise<T> {
  const row = await db.systemSetting
    .findUnique({ where: { tenantId_category_key: { tenantId, category, key } } })
    .catch(() => null);
  if (!row) return fallback;
  return parseJson<T>(row.value, fallback);
}

export async function getHostname(tenantId: number): Promise<string> {
  const v = await getSetting<{ value?: string }>(tenantId, "general", "hostname", {});
  return v.value ?? "cryptsk";
}

// ── Appliance health (M10 §4 card 1) ────────────────────────────────────────

export type ServiceStateDTO = {
  name: string;
  label: string;
  state: "running" | "restarting" | "stopped";
};

export type SystemStatusDTO = {
  cpuPct: number;
  memPct: number;
  diskPct: number;
  tempC: number;
  uptimeSec: number;
  hostname: string;
  firmwareVersion: string;
  mockProfile: string;
  conntrackCount: number;
  services: ServiceStateDTO[];
};

/** restart-in-progress markers (simulated ~2 s apply — M10 §3) */
const restartingUntil = new Map<string, number>();
const RESTART_MS = 2000;

function serviceCatalog(cfg: {
  ntpEnabled: boolean;
  snmpEnabled: boolean;
  haSessionSync: boolean;
}): Array<{ name: string; label: string; running: boolean }> {
  return [
    { name: "nftables", label: "Firewall (nftables)", running: true },
    { name: "suricata", label: "IPS (Suricata)", running: true },
    { name: "sshd", label: "SSH (sshd)", running: true },
    { name: "strongswan", label: "VPN (strongSwan)", running: true },
    { name: "dnsmasq", label: "DNS/DHCP (dnsmasq)", running: true },
    { name: "chronyd", label: "NTP (chronyd)", running: cfg.ntpEnabled },
    { name: "snmpd", label: "SNMP (snmpd)", running: cfg.snmpEnabled },
    { name: "conntrackd", label: "Session sync (conntrackd)", running: cfg.haSessionSync },
    { name: "rsyslogd", label: "Syslog (rsyslogd)", running: true },
  ];
}

export function knownServiceNames(): string[] {
  return serviceCatalog({ ntpEnabled: true, snmpEnabled: true, haSessionSync: true }).map((s) => s.name);
}

export async function restartService(tenantId: number, name: string): Promise<ServiceStateDTO> {
  const [ntp, snmp] = await Promise.all([
    getSetting<{ enabled?: boolean }>(tenantId, "general", "ntp", {}),
    getSetting<{ enabled?: boolean }>(tenantId, "advanced", "snmp", {}),
  ]);
  const haConfig = await db.haConfig.findFirst({ where: { tenantId } }).catch(() => null);
  const catalog = serviceCatalog({
    ntpEnabled: ntp.enabled ?? false,
    snmpEnabled: snmp.enabled ?? false,
    haSessionSync: haConfig?.sessionSync ?? false,
  });
  const svc = catalog.find((s) => s.name === name);
  if (!svc) throw ApiError.notFound(`Unknown service "${name}"`);
  restartingUntil.set(name, Date.now() + RESTART_MS);
  // simulated 2 s apply — status flips back to "running" on the next read
  setTimeout(() => restartingUntil.delete(name), RESTART_MS + 250).unref?.();
  return { name: svc.name, label: svc.label, state: "restarting" };
}

export async function getSystemStatus(tenantId: number): Promise<SystemStatusDTO> {
  await getMockEngine().start().catch(() => {});
  const engine = getMockEngine();
  const latest = engine.metricsRing[engine.metricsRing.length - 1];
  const vitals = engine.systemVitals();

  const [hostname, firmware, ntp, snmp, haConfig] = await Promise.all([
    getHostname(tenantId),
    getSetting<{ current?: string }>(tenantId, "advanced", "firmware", {}),
    getSetting<{ enabled?: boolean }>(tenantId, "general", "ntp", {}),
    getSetting<{ enabled?: boolean }>(tenantId, "advanced", "snmp", {}),
    db.haConfig.findFirst({ where: { tenantId } }).catch(() => null),
  ]);

  const now = Date.now();
  const services: ServiceStateDTO[] = serviceCatalog({
    ntpEnabled: ntp.enabled ?? false,
    snmpEnabled: snmp.enabled ?? false,
    haSessionSync: haConfig?.enabled === true && haConfig.sessionSync,
  }).map((s) => {
    const until = restartingUntil.get(s.name);
    if (until && now < until) return { name: s.name, label: s.label, state: "restarting" as const };
    return { name: s.name, label: s.label, state: s.running ? ("running" as const) : ("stopped" as const) };
  });

  return {
    cpuPct: latest?.cpuPct ?? vitals.cpuPct,
    memPct: latest?.memPct ?? vitals.memPct,
    diskPct: vitals.diskPct,
    tempC: vitals.tempC,
    uptimeSec: engine.uptimeSec,
    hostname,
    firmwareVersion: firmware.current ?? "1.0.0",
    mockProfile: process.env.MOCK_PROFILE ?? "office", // read-only label (DATA_LIFECYCLE §3)
    conntrackCount: latest?.conntrackCount ?? 0,
    services,
  };
}

// ── Backups (M10 §5.3 — JSON files under db/backups) ────────────────────────

export type BackupDTO = {
  id: string;
  createdAt: string;
  sizeBytes: number;
  type: "config" | "full";
  note: string | null;
};

type BackupFile = BackupDTO & {
  schemaVersion: number;
  payload: { config: Record<string, unknown[]>; volatile?: Record<string, unknown[]> };
};

const BACKUPS_DIR = path.join(process.cwd(), "db", "backups");
const BACKUP_SCHEMA_VERSION = 1;

/** Config tables (restored through validation-lite upsert) in FK-safe order. */
const CONFIG_TABLES = [
  "zone",
  "networkInterface",
  "wanPolicy",
  "addressObject",
  "addressGroup",
  "serviceObject",
  "serviceGroup",
  "scheduleObject",
  "radiusProfile",
  "captivePortalProfile",
  "ipsPolicy",
  "qosPolicy",
  "qosRule",
  "dnsPolicy",
  "dnsRecord",
  "dhcpSubnet",
  "dhcpReservation",
  "vpnConfig",
  "vpnUserGroup",
  "userGroup",
  "user",
  "firewallRule",
  "natRule",
  "pbrRule",
  "portMirror",
  "directorySource",
  "syslogTarget",
  "netflowTarget",
  "reportSchedule",
  "webhook",
  "haConfig",
  "systemSetting",
] as const;

/** Volatile tables — only embedded in `full` backups (DATA_LIFECYCLE §5). */
const VOLATILE_TABLES = ["firewallLog", "ipsEvent", "dhcpLease", "vpnSession", "identitySession", "notification"] as const;

function backupPath(id: string): string {
  if (!/^[a-z0-9-]+$/i.test(id)) throw ApiError.notFound("Backup not found");
  return path.join(BACKUPS_DIR, `${id}.json`);
}

async function dumpTable(model: string, tenantId: number): Promise<unknown[]> {
  const delegate = (db as unknown as Record<string, { findMany: (a: unknown) => Promise<unknown[]> }>)[model];
  if (!delegate?.findMany) return [];
  return delegate.findMany({ where: { tenantId } }).catch(() => []);
}

export async function createBackup(tenantId: number, body: BackupCreateInput): Promise<BackupDTO> {
  await fs.mkdir(BACKUPS_DIR, { recursive: true });
  const includeVolatile = body.type === "full";

  const config: Record<string, unknown[]> = {};
  for (const table of CONFIG_TABLES) {
    config[table] = await dumpTable(table, tenantId);
  }
  let volatile: Record<string, unknown[]> | undefined;
  if (includeVolatile) {
    volatile = {};
    for (const table of VOLATILE_TABLES) {
      volatile[table] = await dumpTable(table, tenantId);
    }
  }

  const id = `bk-${ulid().toLowerCase()}`;
  const createdAt = new Date().toISOString();
  const file: BackupFile = {
    id,
    createdAt,
    sizeBytes: 0,
    type: body.type,
    note: body.note ?? null,
    schemaVersion: BACKUP_SCHEMA_VERSION,
    payload: { config, ...(volatile ? { volatile } : {}) },
  };
  const json = JSON.stringify(file);
  file.sizeBytes = Buffer.byteLength(json, "utf8");
  await fs.writeFile(backupPath(id), JSON.stringify(file), "utf8");

  return { id, createdAt, sizeBytes: file.sizeBytes, type: body.type, note: body.note ?? null };
}

export async function listBackups(tenantId: number): Promise<BackupDTO[]> {
  await fs.mkdir(BACKUPS_DIR, { recursive: true });
  const names = (await fs.readdir(BACKUPS_DIR)).filter((n) => n.endsWith(".json"));
  const rows: BackupDTO[] = [];
  for (const n of names) {
    try {
      const raw = await fs.readFile(path.join(BACKUPS_DIR, n), "utf8");
      const parsed = JSON.parse(raw) as BackupFile;
      rows.push({
        id: parsed.id,
        createdAt: parsed.createdAt,
        sizeBytes: parsed.sizeBytes,
        type: parsed.type,
        note: parsed.note ?? null,
      });
    } catch {
      // unreadable file — skip rather than fail the whole listing
    }
  }
  rows.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
  return rows;
}

/** Raw backup file — served by the download endpoint. */
export async function readBackupFile(tenantId: number, id: string): Promise<BackupFile> {
  try {
    const raw = await fs.readFile(backupPath(id), "utf8");
    return JSON.parse(raw) as BackupFile;
  } catch {
    throw ApiError.notFound("Backup not found");
  }
}

/** JSON round-trips turn Date columns into ISO strings — revive them for Prisma. */
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
function reviveDates<T extends Record<string, unknown>>(row: T): T {
  const out: Record<string, unknown> = { ...row };
  for (const [k, v] of Object.entries(out)) {
    if (typeof v === "string" && ISO_RE.test(v)) out[k] = new Date(v);
  }
  return out as T;
}

/**
 * Restore (M10 §5.3): config rows re-applied through validation-lite upserts
 * (by id, per-row best-effort — FK-referencing rows are ordered first);
 * `full` resets volatile tables via delete+recreate. Never a raw SQL
 * overwrite for config (ADR-011 — rollback = restore through the pipeline).
 */
export async function restoreBackup(tenantId: number, id: string): Promise<{ safetyBackupId: string; tables: number; rows: number; skipped: number }> {
  const file = await readBackupFile(tenantId, id);
  if (file.schemaVersion > BACKUP_SCHEMA_VERSION) {
    throw ApiError.conflict("Backup was taken on a newer schema version — upgrade the appliance before restoring");
  }

  // safety backup BEFORE restore (listed in the table, M10 §4)
  const safety = await createBackup(tenantId, { type: "config", note: `Safety backup before restoring ${id}` });

  let rows = 0;
  let skipped = 0;

  for (const table of CONFIG_TABLES) {
    const list = file.payload.config[table];
    if (!Array.isArray(list) || list.length === 0) continue;
    const delegate = (db as unknown as Record<string, {
      findFirst: (a: unknown) => Promise<unknown>;
      create: (a: unknown) => Promise<unknown>;
      update: (a: unknown) => Promise<unknown>;
    }>)[table];
    if (!delegate) continue;
    for (const raw of list) {
      if (!raw || typeof raw !== "object") continue;
      const row = raw as Record<string, unknown>;
      if (typeof row.id !== "number") continue;
      const data: Record<string, unknown> = reviveDates({ ...row, tenantId });
      delete data.id;
      try {
        const existing = await delegate.findFirst({ where: { id: row.id } });
        if (existing) await delegate.update({ where: { id: row.id }, data });
        else await delegate.create({ data: { ...data, id: row.id } });
        rows += 1;
      } catch {
        skipped += 1; // FK-referencing row whose target vanished — best-effort
      }
    }
  }

  if (file.payload.volatile) {
    for (const table of VOLATILE_TABLES) {
      const list = file.payload.volatile[table];
      if (!Array.isArray(list)) continue;
      const delegate = (db as unknown as Record<string, {
        deleteMany: (a: unknown) => Promise<unknown>;
        createMany: (a: unknown) => Promise<unknown>;
      }>)[table];
      if (!delegate) continue;
      try {
        await delegate.deleteMany({ where: { tenantId } });
        const chunkSize = 200;
        for (let i = 0; i < list.length; i += chunkSize) {
          const chunk = list.slice(i, i + chunkSize).map((r) => reviveDates(r as Record<string, unknown>));
          await delegate.createMany({ data: chunk }).catch(() => {});
        }
        rows += list.length;
      } catch {
        skipped += 1;
      }
    }
  }

  // restore completion notice — arrives via alerts:new (type config, M10 §6)
  await db.notification
    .create({
      data: {
        tenantId,
        type: "config",
        severity: "info",
        title: `Backup restored: ${id}`,
        message: `Configuration snapshot re-applied (${rows} rows${skipped ? `, ${skipped} skipped` : ""}). A safety backup was taken first.`,
        sourceModule: "system",
      },
    })
    .then((n) => {
      emitEvent({
        type: "alerts:new",
        payload: {
          notification: {
            id: n.id,
            type: n.type,
            severity: n.severity,
            title: n.title,
            message: n.message,
            sourceModule: n.sourceModule,
            createdAt: n.createdAt.toISOString(),
            isRead: n.isRead,
          },
        },
      });
    })
    .catch(() => {});

  return { safetyBackupId: safety.id, tables: CONFIG_TABLES.length, rows, skipped };
}

// ── Firmware (M10 §5.6 — advanced/firmware setting) ─────────────────────────

export type FirmwareStateDTO = {
  current: string;
  channel: "stable";
  lastCheckAt: string | null;
  available: string | null;
  history: Array<{ version: string; appliedAt: string; note?: string }>;
};

type FirmwareSetting = {
  current: string;
  channel: "stable";
  lastCheckAt?: string | null;
  available?: string | null;
  history?: Array<{ version: string; appliedAt: string; note?: string }>;
};

const FIRMWARE_CATALOG = ["1.0.1", "1.0.2"];

function versionGt(a: string, b: string): boolean {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x > y;
  }
  return false;
}

async function writeFirmware(tenantId: number, value: FirmwareSetting): Promise<FirmwareStateDTO> {
  await db.systemSetting.upsert({
    where: { tenantId_category_key: { tenantId, category: "advanced", key: "firmware" } },
    update: { value: stringifyJson(value) },
    create: { tenantId, category: "advanced", key: "firmware", value: stringifyJson(value) },
  });
  return {
    current: value.current,
    channel: "stable",
    lastCheckAt: value.lastCheckAt ?? null,
    available: value.available ?? null,
    history: value.history ?? [],
  };
}

export async function getFirmware(tenantId: number): Promise<FirmwareStateDTO> {
  const fw = await getSetting<FirmwareSetting>(tenantId, "advanced", "firmware", {
    current: "1.0.0",
    channel: "stable",
    history: [],
  });
  return {
    current: fw.current,
    channel: "stable",
    lastCheckAt: fw.lastCheckAt ?? null,
    available: fw.available ?? null,
    history: fw.history ?? [],
  };
}

export async function checkFirmware(tenantId: number): Promise<FirmwareStateDTO> {
  const fw = await getFirmware(tenantId);
  const available = FIRMWARE_CATALOG.find((v) => versionGt(v, fw.current)) ?? null;
  return writeFirmware(tenantId, { ...fw, lastCheckAt: new Date().toISOString(), available });
}

export async function upgradeFirmware(tenantId: number): Promise<{ firmware: FirmwareStateDTO; safetyBackupId: string }> {
  const fw = await getFirmware(tenantId);
  if (!fw.available) {
    throw ApiError.conflict("No upgrade staged — run 'Check for updates' first");
  }
  // mandatory safety backup first (M10 §4/§5.6)
  const safety = await createBackup(tenantId, { type: "config", note: `Safety backup before firmware upgrade to ${fw.available}` });
  const next: FirmwareSetting = {
    ...fw,
    current: fw.available,
    available: null,
    history: [...(fw.history ?? []), { version: fw.available, appliedAt: new Date().toISOString() }],
  };
  const firmware = await writeFirmware(tenantId, next);
  await notify(tenantId, "config", "info", `Firmware upgraded to ${firmware.current}`, "A safety backup was created before the upgrade (see #/system/backups).");
  return { firmware, safetyBackupId: safety.id };
}

export async function rollbackFirmware(tenantId: number): Promise<FirmwareStateDTO> {
  const fw = await getFirmware(tenantId);
  if ((fw.history?.length ?? 0) < 2) {
    throw ApiError.conflict("Rollback requires at least 2 history entries");
  }
  if (fw.available) {
    throw ApiError.conflict("An upgrade is already staged — complete or discard it before rolling back");
  }
  const previous = fw.history[fw.history.length - 2];
  const next: FirmwareSetting = {
    ...fw,
    current: previous.version,
    history: [...(fw.history ?? []), { version: previous.version, appliedAt: new Date().toISOString(), note: "rollback" }],
  };
  const firmware = await writeFirmware(tenantId, next);
  await notify(tenantId, "system", "info", `Firmware rolled back to ${firmware.current}`, "Previous version restored (simulated staged apply).");
  return firmware;
}

// ── SSH keys (M10 §5.7) ─────────────────────────────────────────────────────

export type SshKeyDTO = {
  id: number;
  name: string;
  publicKey: string;
  fingerprint: string;
  addedBy: string | null;
  enabled: boolean;
  createdAt: string;
};

/**
 * Server-derived fingerprint (M10 §5.7): sha256 over the key material (the
 * base64 blob), first 16 hex chars, rendered `SHA256:xxxx`. Never
 * client-supplied.
 */
function deriveFingerprint(publicKey: string): string {
  const material = publicKey.trim().split(/\s+/)[1] ?? publicKey;
  const hex = createHash("sha256").update(material).digest("hex");
  return `SHA256:${hex.slice(0, 16)}`;
}

function toSshKeyDTO(row: {
  id: number;
  name: string;
  publicKey: string;
  fingerprint: string | null;
  addedBy: string | null;
  enabled: boolean;
  createdAt: Date;
}): SshKeyDTO {
  return {
    id: row.id,
    name: row.name,
    publicKey: row.publicKey,
    fingerprint: row.fingerprint ?? "",
    addedBy: row.addedBy,
    enabled: row.enabled,
    createdAt: row.createdAt.toISOString(),
  };
}

export async function listSshKeys(tenantId: number): Promise<SshKeyDTO[]> {
  const rows = await db.sshKey.findMany({ where: { tenantId }, orderBy: { createdAt: "desc" } });
  return rows.map(toSshKeyDTO);
}

export async function createSshKey(tenantId: number, body: SshKeyCreateInput, addedBy: string): Promise<SshKeyDTO> {
  const row = await db.sshKey.create({
    data: {
      tenantId,
      name: body.name,
      publicKey: body.publicKey,
      fingerprint: deriveFingerprint(body.publicKey),
      addedBy,
    },
  });
  return toSshKeyDTO(row);
}

export async function deleteSshKey(tenantId: number, id: number): Promise<void> {
  const row = await db.sshKey.findFirst({ where: { tenantId, id } });
  if (!row) throw ApiError.notFound("SSH key not found");
  await db.sshKey.delete({ where: { id } });
}

// ── Policy templates (M10 §5.8) ─────────────────────────────────────────────

export type PolicyTemplateDTO = {
  id: string;
  name: string;
  vertical: string;
  description: string;
  sections: Record<string, string>;
};

export const POLICY_TEMPLATES: PolicyTemplateDTO[] = [
  {
    id: "tpl-office",
    name: "Office",
    vertical: "office",
    description: "Productivity-first starter: outbound allowed, ads/trackers filtered, VoIP prioritized.",
    sections: {
      firewall: "Allow LAN→WAN outbound; deny DMZ→LAN; implicit deny preserved",
      nat: "SNAT masquerade on WAN egress",
      ips: "Balanced inline_drop (trojan, malware, scan)",
      dns: "Block ads, malware, phishing",
      qos: "VoIP priority + bulk shaper at 100 Mbps",
    },
  },
  {
    id: "tpl-hospitality",
    name: "Hospitality",
    vertical: "hospitality",
    description: "Guest-isolation starter: client isolation, adult/gambling filtering, video-friendly QoS.",
    sections: {
      firewall: "Guest→LAN blocked; LAN→WAN allowed; DMZ services exposed",
      nat: "SNAT masquerade on WAN egress",
      ips: "Conservative inline_tap (noise-tolerant for guest networks)",
      dns: "Block adult, gambling, malware, phishing",
      qos: "Video/streaming guaranteed share + bulk cap",
    },
  },
  {
    id: "tpl-msp-branch",
    name: "MSP Branch",
    vertical: "msp_branch",
    description: "Managed-branch starter: tight mgmt-plane, aggressive IPS, VoIP-first shaper.",
    sections: {
      firewall: "MGMT→any allowed; LAN→WAN allowed; north-south denies tightened",
      nat: "SNAT masquerade on WAN egress",
      ips: "Aggressive inline_drop (trojan, malware, scan, web_attack)",
      dns: "Block malware, phishing, ads",
      qos: "VoIP + management traffic prioritized at 200 Mbps",
    },
  },
];

type PlainDelegate = {
  findFirst: (a: unknown) => Promise<unknown>;
  create: (a: unknown) => Promise<unknown>;
  update: (a: unknown) => Promise<unknown>;
};

function templateById(id: string): PolicyTemplateDTO | null {
  return POLICY_TEMPLATES.find((t) => t.id === id) ?? null;
}

type UpsertResult = { created: number; updated: number };

/** Idempotent-by-replace: named seed rows are updated to template values on every apply. */
export async function applyTemplate(tenantId: number, id: string): Promise<{ template: PolicyTemplateDTO; summary: UpsertResult & { sections: string[] } }> {
  const tpl = templateById(id);
  if (!tpl) throw ApiError.notFound(`Unknown template "${id}"`);

  const summary: UpsertResult & { sections: string[] } = { created: 0, updated: 0, sections: [] };
  const zones = await db.zone.findMany({ where: { tenantId }, select: { id: true, name: true } });
  const zoneId = (name: string) => zones.find((z) => z.name === name)?.id;
  const wanIface = await db.networkInterface.findFirst({ where: { tenantId, role: "wan" }, select: { name: true } });

  const upsertNamed = async (
    delegate: PlainDelegate,
    uniqueField: string,
    name: string,
    data: Record<string, unknown>,
  ): Promise<void> => {
    const existing = await delegate.findFirst({ where: { tenantId, [uniqueField]: name } });
    if (existing) {
      await delegate.update({ where: { id: (existing as { id: number }).id }, data });
      summary.updated += 1;
    } else {
      await delegate.create({ data: { tenantId, [uniqueField]: name, ...data } });
      summary.created += 1;
    }
  };

  // ── firewall ──
  const maxPos = await db.firewallRule.aggregate({ where: { tenantId }, _max: { position: true } });
  const nextPos = (maxPos._max.position ?? 0) + 1;
  const fwByTpl: Record<string, Array<Record<string, unknown>>> = {
    "tpl-office": [
      { name: "tpl-office-allow-outbound", action: "allow", srcZoneIds: JSON.stringify([zoneId("LAN")].filter(Boolean)), dstZoneIds: JSON.stringify([zoneId("WAN")].filter(Boolean)), comment: "Template: office outbound" },
      { name: "tpl-office-deny-dmz-lan", action: "deny", srcZoneIds: JSON.stringify([zoneId("DMZ")].filter(Boolean)), dstZoneIds: JSON.stringify([zoneId("LAN")].filter(Boolean)), comment: "Template: office DMZ isolation" },
    ],
    "tpl-hospitality": [
      { name: "tpl-hosp-deny-guest-lan", action: "deny", srcZoneIds: JSON.stringify([zoneId("DMZ")].filter(Boolean)), dstZoneIds: JSON.stringify([zoneId("LAN")].filter(Boolean)), comment: "Template: guest isolation" },
      { name: "tpl-hosp-allow-outbound", action: "allow", srcZoneIds: JSON.stringify([zoneId("LAN")].filter(Boolean)), dstZoneIds: JSON.stringify([zoneId("WAN")].filter(Boolean)), comment: "Template: guest outbound" },
    ],
    "tpl-msp-branch": [
      { name: "tpl-msp-allow-mgmt", action: "allow", srcZoneIds: JSON.stringify([zoneId("MGMT")].filter(Boolean)), dstZoneIds: JSON.stringify([zoneId("WAN"), zoneId("LAN")].filter(Boolean)), comment: "Template: mgmt plane" },
      { name: "tpl-msp-allow-outbound", action: "allow", srcZoneIds: JSON.stringify([zoneId("LAN")].filter(Boolean)), dstZoneIds: JSON.stringify([zoneId("WAN")].filter(Boolean)), comment: "Template: branch outbound" },
    ],
  };
  const fwRules = fwByTpl[id] ?? [];
  for (const [i, data] of fwRules.entries()) {
    await upsertNamed(db.firewallRule as unknown as PlainDelegate, "name", String(data.name), { ...data, position: nextPos + i, enabled: true });
  }
  if (fwRules.length) summary.sections.push("firewall");

  // ── nat ──
  await upsertNamed(db.natRule as unknown as PlainDelegate, "name", `nat-${id}`, {
    type: "snat",
    enabled: true,
    outgoingIface: wanIface?.name ?? "wan0",
    translatedSrc: "masq",
    comment: `Template: ${tpl.name} egress`,
  });
  summary.sections.push("nat");

  // ── ips ──
  const ipsByTpl: Record<string, { mode: string; categories: string[] }> = {
    "tpl-office": { mode: "inline_drop", categories: ["trojan", "malware", "scan"] },
    "tpl-hospitality": { mode: "inline_tap", categories: ["trojan", "malware"] },
    "tpl-msp-branch": { mode: "inline_drop", categories: ["trojan", "malware", "scan", "web_attack"] },
  };
  const ips = ipsByTpl[id];
  if (ips) {
    const cats: Record<string, boolean> = {};
    for (const c of ips.categories) cats[c] = true;
    await upsertNamed(db.ipsPolicy as unknown as PlainDelegate, "name", `ips-${id}`, { mode: ips.mode, enabled: true, ruleCategories: JSON.stringify(cats) });
    summary.sections.push("ips");
  }

  // ── dns ──
  const dnsByTpl: Record<string, string[]> = {
    "tpl-office": ["ads", "malware", "phishing"],
    "tpl-hospitality": ["adult", "gambling", "malware", "phishing"],
    "tpl-msp-branch": ["malware", "phishing", "ads"],
  };
  await upsertNamed(db.dnsPolicy as unknown as PlainDelegate, "name", `dns-${id}`, {
    enabled: true,
    blockCategories: JSON.stringify(dnsByTpl[id] ?? ["malware"]),
    action: "sinkhole",
  });
  summary.sections.push("dns");

  // ── qos ──
  const qosByTpl: Record<string, { bandwidth: number; template: string }> = {
    "tpl-office": { bandwidth: 100_000, template: "voip" },
    "tpl-hospitality": { bandwidth: 200_000, template: "video" },
    "tpl-msp-branch": { bandwidth: 200_000, template: "voip" },
  };
  const qos = qosByTpl[id];
  if (qos) {
    const existing = await db.qosPolicy.findFirst({ where: { tenantId, name: `qos-${id}` } });
    const policy =
      existing
        ? await db.qosPolicy.update({ where: { id: existing.id }, data: { enabled: true, bandwidthKbps: qos.bandwidth, template: qos.template } })
        : await db.qosPolicy.create({ data: { tenantId, name: `qos-${id}`, enabled: true, bandwidthKbps: qos.bandwidth, template: qos.template } });
    if (existing) summary.updated += 1;
    else summary.created += 1;
    const rule = await db.qosRule.findFirst({ where: { tenantId, policyId: policy.id, name: `priority-${id}` } });
    if (rule) await db.qosRule.update({ where: { id: rule.id }, data: { priority: 0, guaranteedKbps: Math.round(qos.bandwidth * 0.2) } });
    else await db.qosRule.create({ data: { tenantId, policyId: policy.id, name: `priority-${id}`, priority: 0, guaranteedKbps: Math.round(qos.bandwidth * 0.2) } });
    summary.sections.push("qos");
  }

  await notify(tenantId, "config", "info", `Policy template applied: ${tpl.name}`, `Starter rows replaced for: ${summary.sections.join(", ")}.`);
  return { template: tpl, summary };
}

// ── Setup gate (M10 §5.8) ───────────────────────────────────────────────────

export async function getSetupCompleted(tenantId: number): Promise<boolean> {
  const v = await getSetting<{ completed?: boolean }>(tenantId, "system", "setup", {});
  return v.completed ?? true; // unset = don't trap the operator behind the gate
}

export async function completeSetup(tenantId: number): Promise<boolean> {
  const current = await getSetting<Record<string, unknown>>(tenantId, "system", "setup", {});
  await db.systemSetting.upsert({
    where: { tenantId_category_key: { tenantId, category: "system", key: "setup" } },
    update: { value: stringifyJson({ ...current, completed: true }) },
    create: { tenantId, category: "system", key: "setup", value: stringifyJson({ ...current, completed: true }) },
  });
  return true;
}

// ── shared helper ───────────────────────────────────────────────────────────

async function notify(tenantId: number, type: string, severity: string, title: string, message: string): Promise<void> {
  await db.notification
    .create({ data: { tenantId, type, severity, title, message, sourceModule: "system" } })
    .then((n) => {
      emitEvent({
        type: "alerts:new",
        payload: {
          notification: {
            id: n.id,
            type: n.type,
            severity: n.severity,
            title: n.title,
            message: n.message,
            sourceModule: n.sourceModule,
            createdAt: n.createdAt.toISOString(),
            isRead: n.isRead,
          },
        },
      });
    })
    .catch(() => {});
}

export { RETENTION_HARD_CAPS };
