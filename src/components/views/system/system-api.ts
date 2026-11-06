/**
 * System typed client (M10 §3) — module-local envelope unwrapping that
 * preserves zod `details` (lib/realtime's fetchApi drops them), flat endpoint
 * object, DTO types imported from the server services (type-only).
 */

import type {
  SystemStatusDTO,
  ServiceStateDTO,
  BackupDTO,
  FirmwareStateDTO,
  SshKeyDTO,
  PolicyTemplateDTO,
} from "@/lib/system/service";
import type { HaConfigDTO, HaStatusDTO } from "@/lib/ha/service";
import type { NotificationDTO } from "@/lib/notifications/service";
import type { ConfigVersionDTO, ConfigVersionDetailDTO } from "@/lib/config-versions/service";

export type {
  SystemStatusDTO,
  ServiceStateDTO,
  BackupDTO,
  FirmwareStateDTO,
  SshKeyDTO,
  PolicyTemplateDTO,
  HaConfigDTO,
  HaStatusDTO,
  NotificationDTO,
  ConfigVersionDTO,
  ConfigVersionDetailDTO,
};

export interface PageMeta {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

const JSON_HEADERS = { "Content-Type": "application/json" };

export class SystemApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "SystemApiError";
    this.code = code;
    this.details = details;
  }
}

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { ...init, credentials: "same-origin" });
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    throw new SystemApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new SystemApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

async function fetchJsonList<T>(path: string, params: string): Promise<{ data: T[]; meta: PageMeta }> {
  const res = await fetch(`${path}${params ? `?${params}` : ""}`, { credentials: "same-origin" });
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    throw new SystemApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as {
    data?: T[];
    meta?: PageMeta;
    error?: { code: string; message?: string; details?: unknown };
  };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new SystemApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return {
    data: (body.data as T[]) ?? [],
    meta: body.meta ?? { page: 1, limit: 25, total: 0, totalPages: 1 },
  };
}

/** Extract zod fieldErrors from a SystemApiError (handler details shape). */
export function fieldErrorsOf(err: unknown): Record<string, string[]> {
  if (err instanceof SystemApiError && err.details && typeof err.details === "object") {
    const fe = (err.details as { fieldErrors?: Record<string, string[]> }).fieldErrors;
    if (fe) return fe;
  }
  return {};
}

export type SettingsMap = Record<string, Record<string, unknown>>;
export type SettingsEntry = { category: string; key: string; value: unknown };

export const systemApi = {
  // ── status + settings ──
  getStatus: () => fetchJson<SystemStatusDTO>("/api/v1/system/status"),
  getSettings: () => fetchJson<SettingsMap>("/api/v1/system/settings"),
  putSettings: (entries: SettingsEntry[]) =>
    fetchJson<{ updated: number }>("/api/v1/system/settings", {
      method: "PUT",
      headers: JSON_HEADERS,
      body: JSON.stringify(entries),
    }),

  // ── backups ──
  listBackups: () => fetchJsonList<BackupDTO>("/api/v1/system/backups", "").then((r) => r.data),
  createBackup: (body: { type: "config" | "full"; note?: string }) =>
    fetchJson<BackupDTO>("/api/v1/system/backups", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  restoreBackup: (id: string) =>
    fetchJson<{ ok: boolean; restored: string; safetyBackupId: string; rows: number; skipped: number }>(
      `/api/v1/system/backups/${id}/restore`,
      { method: "POST", headers: JSON_HEADERS, body: "{}" },
    ),
  backupDownloadUrl: (id: string) => `/api/v1/system/backups/${id}/download`,

  // ── notifications ──
  listNotifications: (params: string) => fetchJsonList<NotificationDTO>("/api/v1/notifications", params),
  markNotificationRead: (id: number) =>
    fetchJson<NotificationDTO>(`/api/v1/notifications/${id}/read`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ isRead: true }),
    }),
  markAllNotificationsRead: () =>
    fetchJson<{ ok: boolean; marked: number }>("/api/v1/notifications/read-all", {
      method: "POST",
      headers: JSON_HEADERS,
      body: "{}",
    }),

  // ── config versions ──
  listConfigVersions: (params: string) => fetchJsonList<ConfigVersionDTO>("/api/v1/config-versions", params),
  getConfigVersion: (id: number) => fetchJson<ConfigVersionDetailDTO>(`/api/v1/config-versions/${id}`),

  // ── services / firmware / templates / setup ──
  restartService: (name: string) =>
    fetchJson<ServiceStateDTO>(`/api/v1/system/services/${name}/restart`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: "{}",
    }),
  getFirmware: () => fetchJson<FirmwareStateDTO>("/api/v1/system/firmware"),
  checkFirmware: () =>
    fetchJson<FirmwareStateDTO>("/api/v1/system/firmware/check", { method: "POST", headers: JSON_HEADERS, body: "{}" }),
  upgradeFirmware: () =>
    fetchJson<FirmwareStateDTO>("/api/v1/system/firmware/upgrade", { method: "POST", headers: JSON_HEADERS, body: "{}" }),
  rollbackFirmware: () =>
    fetchJson<FirmwareStateDTO>("/api/v1/system/firmware/rollback", { method: "POST", headers: JSON_HEADERS, body: "{}" }),
  listTemplates: () => fetchJsonList<PolicyTemplateDTO>("/api/v1/system/policy-templates", "").then((r) => r.data),
  applyTemplate: (id: string) =>
    fetchJson<{ template: PolicyTemplateDTO; summary: { created: number; updated: number; sections: string[] } }>(
      `/api/v1/system/policy-templates/${id}/apply`,
      { method: "POST", headers: JSON_HEADERS, body: "{}" },
    ),
  completeSetup: () =>
    fetchJson<{ completed: boolean }>("/api/v1/system/setup/complete", { method: "POST", headers: JSON_HEADERS, body: "{}" }),

  // ── ssh keys ──
  listSshKeys: () => fetchJsonList<SshKeyDTO>("/api/v1/system/ssh-keys", "").then((r) => r.data),
  createSshKey: (body: { name: string; publicKey: string }) =>
    fetchJson<SshKeyDTO>("/api/v1/system/ssh-keys", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteSshKey: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/system/ssh-keys/${id}`, { method: "DELETE" }),
};

// ── shared formatters re-exports live in system-ui.tsx ──────────────────────
