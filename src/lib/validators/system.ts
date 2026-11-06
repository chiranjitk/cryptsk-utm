/**
 * System / HA / notifications validators (M10) — per M10-SYSTEM.md §3/§5 and
 * SCHEMA.md §4. zod is the single source of allowed values at the edge
 * (API_STANDARDS §3); locked enums from PROJECT_MEMORY §6 via validators/enums.
 *
 * Format-level grammar lives here (zod). Cross-field / DB-dependent checks
 * (peerIp ≠ local iface IP, iface existence) live in lib/ha/service.ts and
 * lib/system/service.ts and throw ApiError.
 */

import { z } from "zod";
import {
  haRoleSchema,
  notificationSeveritySchema,
  snmpVersionSchema,
} from "./enums";

// ── primitive grammars ──────────────────────────────────────────────────────

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IPV4_CIDR_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\/(3[0-2]|[12]?\d)$/;
const IP_OR_CIDR_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(\/(3[0-2]|[12]?\d))?$/;
const HOST_RE = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.?$/;
const IFNAME_RE = /^[a-zA-Z0-9._-]{1,15}$/;
/** IANA-ish tz shape: Area/Location (e.g. Asia/Calcutta, America/New_York, Etc/GMT+5, UTC). */
const IANA_TZ_RE = /^(UTC|Etc\/GMT[+-]\d{1,2}|[A-Za-z]+\/[A-Za-z_]+(\/[A-Za-z_+0-9-]+)?)$/;

export const ipv4Schema = z.string().regex(IPV4_RE, "Must be a valid IPv4 address");
export const ipv4CidrSchema = z.string().regex(IPV4_CIDR_RE, "Must be a valid IPv4 CIDR (e.g. 192.168.10.254/24)");
export const ipOrCidrSchema = z.string().regex(IP_OR_CIDR_RE, "Must be a valid IPv4 address or CIDR");
export const hostOrIpSchema = z
  .string()
  .trim()
  .min(1)
  .max(253)
  .refine((v) => HOST_RE.test(v) || IPV4_RE.test(v) || v.includes(":"), "Must be a hostname or IP address");
const ifaceNameSchema = z.string().regex(IFNAME_RE, "Interface name looks like lan0 / eth0.100");
const portSchema = z.number().int().min(1, "Port must be 1-65535").max(65535, "Port must be 1-65535");

const isoDate = z
  .string()
  .refine((v) => !Number.isNaN(Date.parse(v)), "Must be an ISO timestamp");

// ── HA config (M10 §5.1) ────────────────────────────────────────────────────

export const haConfigSchema = z
  .object({
    enabled: z.boolean().default(false),
    role: haRoleSchema.default("disabled"),
    priority: z.number().int().min(1, "Priority must be 1-255").max(255, "Priority must be 1-255").default(100),
    virtualIp: ipv4CidrSchema.nullish(),
    ifaceName: ifaceNameSchema,
    peerIp: ipv4Schema.nullish(),
    syncConfig: z.boolean().default(true),
    sessionSync: z.boolean().default(true),
    trackedInterfaces: z.array(ifaceNameSchema).max(16).default([]),
    failAfterSec: z.number().int().min(3, "failAfterSec must be ≥ 3").max(3600).default(10),
    holdDownSec: z.number().int().min(0).max(86400).default(60),
  })
  .superRefine((cfg, ctx) => {
    if (cfg.holdDownSec < cfg.failAfterSec) {
      ctx.addIssue({
        code: "custom",
        path: ["holdDownSec"],
        message: "holdDownSec must be ≥ failAfterSec (failback waits at least as long as detection)",
      });
    }
    if (cfg.enabled) {
      if (cfg.role === "disabled") {
        ctx.addIssue({ code: "custom", path: ["role"], message: "Enabling HA requires a role (active or standby)" });
      }
      if (!cfg.peerIp) {
        ctx.addIssue({ code: "custom", path: ["peerIp"], message: "Enabling HA requires a peer IP" });
      }
    }
  });

export type HaConfigInput = z.infer<typeof haConfigSchema>;

// ── System settings batch (M10 §5.2) ────────────────────────────────────────

const SNMP_COMMUNITY_MASK = "••••••••";

export const hostnameSchema = z
  .object({
    value: z
      .string()
      .trim()
      .min(3, "Hostname must be 3-63 chars")
      .max(63, "Hostname must be 3-63 chars")
      .regex(HOST_RE, "DNS-safe hostname (letters, digits, hyphens, dots)"),
  })
  .strict();

export const timezoneSchema = z
  .object({
    value: z.string().regex(IANA_TZ_RE, "Must be an IANA timezone (e.g. Asia/Calcutta)").max(64),
  })
  .strict();

export const ntpSchema = z
  .object({
    enabled: z.boolean(),
    servers: z.array(hostOrIpSchema).min(1, "At least one NTP server").max(8),
    synced: z.boolean().optional(),
    lastSyncAt: isoDate.optional().nullable(),
  })
  .strict();

export const snmpSchema = z
  .object({
    enabled: z.boolean(),
    version: snmpVersionSchema,
    community: z.string().max(128).optional(),
    v3User: z.string().max(64).optional(),
    authProtocol: z.enum(["sha", "sha256"]).optional(),
    privProtocol: z.enum(["aes", "des"]).optional(),
    port: portSchema.default(161),
    allowedIps: z.array(ipOrCidrSchema).max(32).default([]),
  })
  .strict()
  .superRefine((v, ctx) => {
    if (v.enabled && v.version === "v2c" && v.community !== undefined && v.community !== SNMP_COMMUNITY_MASK && v.community.trim().length < 8) {
      ctx.addIssue({ code: "custom", path: ["community"], message: "Community must be at least 8 characters" });
    }
    if (v.enabled && v.version === "v3" && !v.v3User) {
      ctx.addIssue({ code: "custom", path: ["v3User"], message: "v3 requires a username" });
    }
  });

export const hardeningSchema = z
  .object({
    sshPasswordAuth: z.boolean(),
    managementAllowlist: z.array(ipOrCidrSchema).max(32).default([]),
    stopUnusedServices: z.boolean(),
  })
  .strict();

export const thresholdsSchema = z
  .object({
    cpuPct: z.number().int().min(1).max(100),
    memPct: z.number().int().min(1).max(100),
    diskPct: z.number().int().min(1).max(100),
    tempC: z.number().int().min(20).max(120),
  })
  .strict();

export const emailPrefsSchema = z
  .object({
    enabled: z.boolean(),
    recipient: z.string().max(254).optional(),
  })
  .strict();

export const severityPrefsSchema = z
  .object({
    threshold: notificationSeveritySchema,
  })
  .strict();

const DAYS_MAX = 3650;
const retentionShape = (maxRows: number) =>
  z
    .object({
      days: z.number().int().min(1).max(DAYS_MAX).optional(),
      maxRows: z.number().int().min(500).max(maxRows).optional(),
    })
    .strict();

export const RETENTION_HARD_CAPS = { firewall_logs: 50_000, ips_events: 5_000, audit_log: 20_000 } as const;

export const retentionTableSchema = z.enum(["firewall_logs", "ips_events", "audit_log"]);

export function retentionSchemaFor(table: z.infer<typeof retentionTableSchema>) {
  return retentionShape(RETENTION_HARD_CAPS[table]);
}

export const diagnosticsSchema = z
  .object({
    verbosity: z.enum(["standard", "verbose"]),
  })
  .strict();

export const apiKeysEnabledSchema = z
  .object({
    enabled: z.boolean(),
  })
  .strict();

export const setupSchema = z
  .object({
    completed: z.boolean(),
  })
  .strict();

/** Per-key value shapes (M10 §4 settings cards + §5.2). Keys not listed here are rejected. */
const SETTING_SCHEMAS: Record<string, z.ZodType> = {
  "general/hostname": hostnameSchema,
  "general/timezone": timezoneSchema,
  "general/ntp": ntpSchema,
  "advanced/snmp": snmpSchema,
  "advanced/hardening": hardeningSchema,
  "advanced/firmware": z
    .object({
      current: z.string().max(32),
      channel: z.literal("stable"),
      lastCheckAt: isoDate.optional().nullable(),
      available: z.string().max(32).optional().nullable(),
      history: z.array(z.object({ version: z.string().max(32), appliedAt: isoDate, note: z.string().max(64).optional() })).max(32).optional(),
    })
    .strict(),
  "advanced/diagnostics": diagnosticsSchema,
  "advanced/apiKeysEnabled": apiKeysEnabledSchema,
  "notifications/thresholds": thresholdsSchema,
  "notifications/email": emailPrefsSchema,
  "notifications/severity_threshold": severityPrefsSchema,
  "logging/retention.firewall_logs": retentionShape(RETENTION_HARD_CAPS.firewall_logs),
  "logging/retention.ips_events": retentionShape(RETENTION_HARD_CAPS.ips_events),
  "logging/retention.audit_log": retentionShape(RETENTION_HARD_CAPS.audit_log),
  "system/setup": setupSchema,
};

export const settingsCategorySchema = z.enum([
  "general",
  "auth",
  "logging",
  "notifications",
  "dns",
  "dhcp",
  "ips",
  "advanced",
  "system",
]);

export const settingsEntrySchema = z.object({
  category: settingsCategorySchema,
  key: z.string().min(1).max(64),
  value: z.unknown(),
});

/** Batch PUT body — entries validated against the per-key shapes above. */
export const settingsBatchSchema = z
  .array(settingsEntrySchema)
  .min(1, "Batch must contain at least one setting")
  .max(32)
  .superRefine((entries, ctx) => {
    entries.forEach((e, i) => {
      const schema = SETTING_SCHEMAS[`${e.category}/${e.key}`];
      if (!schema) {
        ctx.addIssue({
          code: "custom",
          path: [i, "key"],
          message: `Unknown setting key "${e.category}/${e.key}"`,
        });
        return;
      }
      const r = schema.safeParse(e.value);
      if (!r.success) {
        for (const issue of r.error.issues) {
          ctx.addIssue({
            code: "custom",
            path: [i, "value", ...(issue.path.length ? issue.path.map(String) : [])],
            message: issue.message,
          });
        }
      }
    });
  });

export type SettingsEntry = z.infer<typeof settingsEntrySchema>;
export { SNMP_COMMUNITY_MASK };

// ── Backups (M10 §5.3) ──────────────────────────────────────────────────────

export const backupCreateSchema = z
  .object({
    type: z.enum(["config", "full"]),
    note: z.string().trim().max(200).optional(),
  })
  .strict();

export type BackupCreateInput = z.infer<typeof backupCreateSchema>;

// ── SSH keys (M10 §5.7) ─────────────────────────────────────────────────────

/** OpenSSH authorized_keys line: <keytype> <base64-blob> [comment]. */
const SSH_PUBKEY_RE =
  /^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/=]+( [\x20-\x7e]{0,254})?$/;

export const sshKeyCreateSchema = z
  .object({
    name: z.string().trim().min(1, "Name is required").max(64),
    publicKey: z
      .string()
      .trim()
      .min(1)
      .max(4096)
      .refine((v) => !/PRIVATE KEY/i.test(v), "Private keys are never accepted — upload the public key only")
      .refine((v) => SSH_PUBKEY_RE.test(v), "Must be an OpenSSH public-key line: <type> <base64> [comment]"),
  })
  .strict();

export type SshKeyCreateInput = z.infer<typeof sshKeyCreateSchema>;

// ── Notifications ───────────────────────────────────────────────────────────

export const notificationListQuery = z.object({
  unread: z
    .enum(["true", "false"])
    .optional()
    .transform((v) => (v === undefined ? undefined : v === "true")),
  type: z.enum(["threat", "system", "vpn", "ha", "config"]).optional(),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(25),
});

export const notificationReadSchema = z
  .object({
    isRead: z.boolean().default(true),
  })
  .strict();

// ── Config versions ─────────────────────────────────────────────────────────

export const configVersionListQuery = z.object({
  section: z.string().max(32).optional(),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(25),
});

// ── Firmware / services / setup / templates (empty or near-empty bodies) ────

export const firmwareCheckSchema = z.object({}).strict();
export const firmwareUpgradeSchema = z.object({}).strict();
export const firmwareRollbackSchema = z.object({}).strict();
export const serviceRestartSchema = z.object({}).strict();
export const setupCompleteSchema = z.object({}).strict();
export const templateApplySchema = z.object({}).strict();
