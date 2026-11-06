/**
 * Logging & Reporting typed client (M09) — mirrors the dns-dhcp-api.ts
 * contract: module-local envelope unwrapping that preserves zod `details`
 * (lib/realtime's fetchApi drops them), flat endpoint object, DTO types
 * imported from the server service (type-only — erased before bundling).
 */

import type {
  AuditLogDTO,
  FirewallLogDTO,
  IpsEventDTO,
  LogStats,
  NetflowTargetDTO,
  ReportScheduleDTO,
  SyslogTargetDTO,
} from "@/lib/logs/service";
import type { StatsRange } from "@/lib/validators/logs";

export type {
  AuditLogDTO,
  FirewallLogDTO,
  IpsEventDTO,
  LogStats,
  NetflowTargetDTO,
  ReportScheduleDTO,
  SyslogTargetDTO,
};
export type { StatsRange };

export interface PageMeta {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

export interface Paged<T> {
  data: T[];
  meta: PageMeta;
}

const JSON_HEADERS = { "Content-Type": "application/json" };

export class LogsApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "LogsApiError";
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
    throw new LogsApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new LogsApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

async function fetchJsonList<T>(path: string, params: string): Promise<Paged<T>> {
  const res = await fetch(`${path}${params ? `?${params}` : ""}`, { credentials: "same-origin" });
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    throw new LogsApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as {
    data?: T[];
    meta?: PageMeta;
    error?: { code: string; message?: string; details?: unknown };
  };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new LogsApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return {
    data: (body.data as T[]) ?? [],
    meta: body.meta ?? { page: 1, limit: 25, total: 0, totalPages: 1 },
  };
}

/** Extract zod fieldErrors from a LogsApiError (handler details shape). */
export function fieldErrorsOf(err: unknown): Record<string, string[]> {
  if (err instanceof LogsApiError && err.details && typeof err.details === "object") {
    const fe = (err.details as { fieldErrors?: Record<string, string[]> }).fieldErrors;
    if (fe) return fe;
  }
  return {};
}

// ── download helper (CSV/JSON exports) ──────────────────────────────────────

/** Blob-download a GET endpoint; returns data rows parsed from the payload for cap toasts. */
async function downloadGet(path: string, fallbackName: string): Promise<{ filename: string; rows: number }> {
  const res = await fetch(path, { credentials: "same-origin" });
  if (!res.ok) {
    let message = `HTTP ${res.status}`;
    try {
      const body = (await res.json()) as { error?: { message?: string } };
      if (body?.error?.message) message = body.error.message;
    } catch {
      /* non-JSON error body */
    }
    throw new LogsApiError("INTERNAL", message);
  }
  const blob = await res.blob();
  const disposition = res.headers.get("Content-Disposition") ?? "";
  const match = /filename="?([^";]+)"?/.exec(disposition);
  const filename = match?.[1] ?? fallbackName;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  const text = await blob.text();
  const rows = Math.max(0, text.split("\n").filter((l) => l.trim().length > 0).length - 1);
  return { filename, rows };
}

// ── log list endpoints ──────────────────────────────────────────────────────

export const logsApi = {
  listFirewall: (params: string) => fetchJsonList<FirewallLogDTO>("/api/v1/logs/firewall", params),
  exportFirewallCsv: (params: string) =>
    downloadGet(`/api/v1/logs/firewall/export${params ? `?${params}` : ""}`, "firewall-logs.csv"),

  listIps: (params: string) => fetchJsonList<IpsEventDTO>("/api/v1/logs/ips", params),

  listAudit: (params: string) => fetchJsonList<AuditLogDTO>("/api/v1/logs/audit", params),
  auditObjectTypes: () =>
    fetchJson<{ objectTypes: string[] }>("/api/v1/logs/audit?facets=objectTypes").then((r) => r.objectTypes),
  listUsers: (limit = 100) =>
    fetchJson<Array<{ id: number; username: string }>>(`/api/v1/users?limit=${limit}`),

  getStats: (range: StatsRange) => fetchJson<LogStats>(`/api/v1/logs/stats?range=${range}`),
  exportReport: (range: StatsRange, format: "csv" | "json") =>
    downloadGet(`/api/v1/logs/reports/export?range=${range}&format=${format}`, `traffic-report-${range}.${format}`),

  // ── syslog targets ──────────────────────────────────────────────────────
  listSyslogTargets: () => fetchJson<SyslogTargetDTO[]>("/api/v1/logs/syslog-targets"),
  createSyslogTarget: (body: Record<string, unknown>) =>
    fetchJson<SyslogTargetDTO>("/api/v1/logs/syslog-targets", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateSyslogTarget: (id: number, body: Record<string, unknown>) =>
    fetchJson<SyslogTargetDTO>(`/api/v1/logs/syslog-targets/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteSyslogTarget: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/logs/syslog-targets/${id}`, { method: "DELETE" }),

  // ── netflow targets ─────────────────────────────────────────────────────
  listNetflowTargets: () => fetchJson<NetflowTargetDTO[]>("/api/v1/logs/netflow-targets"),
  createNetflowTarget: (body: Record<string, unknown>) =>
    fetchJson<NetflowTargetDTO>("/api/v1/logs/netflow-targets", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateNetflowTarget: (id: number, body: Record<string, unknown>) =>
    fetchJson<NetflowTargetDTO>(`/api/v1/logs/netflow-targets/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteNetflowTarget: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/logs/netflow-targets/${id}`, { method: "DELETE" }),

  // ── report schedules ────────────────────────────────────────────────────
  listSchedules: () => fetchJson<ReportScheduleDTO[]>("/api/v1/logs/report-schedules"),
  createSchedule: (body: Record<string, unknown>) =>
    fetchJson<ReportScheduleDTO>("/api/v1/logs/report-schedules", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateSchedule: (id: number, body: Record<string, unknown>) =>
    fetchJson<ReportScheduleDTO>(`/api/v1/logs/report-schedules/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteSchedule: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/logs/report-schedules/${id}`, { method: "DELETE" }),
  runSchedule: (id: number) =>
    fetchJson<{ ok: true; lastRunAt: string }>(`/api/v1/logs/report-schedules/${id}/run`, { method: "POST", headers: JSON_HEADERS, body: "{}" }),

  // ── M04 reuse — suppress an IPS event (endpoint owned by M04, do not duplicate) ──
  suppressIpsEvent: (id: number, duration: "24h" | "7d" | "forever") =>
    fetchJson<IpsEventDTO>(`/api/v1/ips/events/${id}/suppress`, { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ duration }) }),
};

// ── shared param builder ────────────────────────────────────────────────────

/** URLSearchParams joiner that skips empty values — keeps query keys stable. */
export function qs(params: Record<string, string | number | undefined | null>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    sp.set(k, String(v));
  }
  return sp.toString();
}
