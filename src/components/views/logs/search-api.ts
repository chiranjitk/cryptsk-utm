/**
 * M12 Logging & Reporting typed client (spec 2.13) — mirrors logs-api.ts:
 * module-local envelope unwrapping that preserves zod `details`, flat endpoint
 * object, JSON_HEADERS, credentials same-origin. DTOs are defined here
 * (server mappers live inside the route modules — type-only duplication kept
 * in sync by the shared validators).
 */

export type SearchDataset = "firewall" | "ips" | "audit";

export interface SearchRow {
  id: number;
  dataset: SearchDataset;
  ts: string;
  headline: string;
  detail: string;
  severity?: string;
}

export interface SavedSearchDTO {
  id: number;
  name: string;
  dataset: SearchDataset;
  queryText: string;
  filters: Record<string, string>;
  createdAt: string;
}

export interface ChecklistRow {
  control: string;
  pass: boolean;
  detail: string;
}

export interface ReportRunListItem {
  id: number;
  name: string;
  source: string; // ad-hoc | schedule | compliance
  templateId: number | null;
  range: string;
  format: string; // html | pdf
  sections: string[];
  status: string; // pending | running | done | failed
  summary: {
    meta?: { generatedAt: string; range: string; since: string; until: string; pdfViaPrint: boolean };
    framework?: string;
    checklist?: ChecklistRow[];
    passRate?: number;
  } | null;
  error: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  createdAt: string;
}

export interface ReportRunDetail extends ReportRunListItem {
  contentHtml: string | null;
}

export interface ComplianceTemplateDTO {
  id: number;
  name: string;
  framework: string; // PCI | HIPAA | GDPR | ISO27001 | SOC2
  sections: string[];
  range: string;
  enabled: boolean;
  lastRunAt: string | null;
  createdAt: string;
}

export interface AnonymizationRuleDTO {
  id: number;
  name: string;
  dataset: string;
  field: string;
  strategy: string; // hash | mask | pseudonymize
  enabled: boolean;
  createdAt: string;
}

export type AnonPreviewRow = Record<string, string | number | null>;

export interface AnonPreview {
  before: AnonPreviewRow[];
  after: AnonPreviewRow[];
}

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

export class SearchApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "SearchApiError";
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
    throw new SearchApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new SearchApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

async function fetchJsonList<T>(path: string, params: string): Promise<Paged<T>> {
  const res = await fetch(`${path}${params ? `?${params}` : ""}`, { credentials: "same-origin" });
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    throw new SearchApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as {
    data?: T[];
    meta?: PageMeta;
    error?: { code: string; message?: string; details?: unknown };
  };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new SearchApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return {
    data: (body.data as T[]) ?? [],
    meta: body.meta ?? { page: 1, limit: 25, total: 0, totalPages: 1 },
  };
}

/** Extract zod fieldErrors from a SearchApiError (handler details shape). */
export function fieldErrorsOf(err: unknown): Record<string, string[]> {
  if (err instanceof SearchApiError && err.details && typeof err.details === "object") {
    const fe = (err.details as { fieldErrors?: Record<string, string[]> }).fieldErrors;
    if (fe) return fe;
  }
  return {};
}

// ── text export download (CEF / LEEF) ───────────────────────────────────────

/** Blob-download a text/plain GET endpoint; returns the served filename. */
export async function downloadText(path: string, fallbackName: string): Promise<{ filename: string; lines: number }> {
  const res = await fetch(path, { credentials: "same-origin" });
  if (!res.ok) {
    let message = `HTTP ${res.status}`;
    try {
      const body = (await res.json()) as { error?: { message?: string } };
      if (body?.error?.message) message = body.error.message;
    } catch {
      /* non-JSON error body */
    }
    throw new SearchApiError("INTERNAL", message);
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
  const lines = text.split("\n").filter((l) => l.trim().length > 0).length;
  return { filename, lines };
}

// ── endpoints ───────────────────────────────────────────────────────────────

export const searchApi = {
  // unified search (area logs — read)
  search: (params: string) => fetchJsonList<SearchRow>("/api/v1/logs/search", params),
  exportLogs: (dataset: "firewall" | "ips", format: "cef" | "leef", limit = 100) =>
    downloadText(`/api/v1/logs/export?dataset=${dataset}&format=${format}&limit=${limit}`, `${dataset}-${format}-export.txt`),

  // saved searches (reads: logs / writes: reports)
  listSaved: () => fetchJson<SavedSearchDTO[]>("/api/v1/logs/search/saved"),
  createSaved: (body: Record<string, unknown>) =>
    fetchJson<SavedSearchDTO>("/api/v1/logs/search/saved", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteSaved: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/logs/search/saved/${id}`, { method: "DELETE" }),

  // report runs
  listRuns: (params = "") => fetchJsonList<ReportRunListItem>("/api/v1/reports/runs", params),
  getRun: (id: number) => fetchJson<ReportRunDetail>(`/api/v1/reports/runs/${id}`),
  createRun: (body: Record<string, unknown>) =>
    fetchJson<ReportRunListItem>("/api/v1/reports/runs", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteRun: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/reports/runs/${id}`, { method: "DELETE" }),

  // compliance templates + run-now
  listTemplates: () => fetchJson<ComplianceTemplateDTO[]>("/api/v1/logs/compliance/templates"),
  createTemplate: (body: Record<string, unknown>) =>
    fetchJson<ComplianceTemplateDTO>("/api/v1/logs/compliance/templates", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateTemplate: (id: number, body: Record<string, unknown>) =>
    fetchJson<ComplianceTemplateDTO>(`/api/v1/logs/compliance/templates/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteTemplate: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/logs/compliance/templates/${id}`, { method: "DELETE" }),
  runCompliance: (templateId: number) =>
    fetchJson<ReportRunListItem>("/api/v1/logs/compliance/run", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ templateId }) }),

  // anonymization
  listAnonRules: () => fetchJson<AnonymizationRuleDTO[]>("/api/v1/logs/anonymization"),
  createAnonRule: (body: Record<string, unknown>) =>
    fetchJson<AnonymizationRuleDTO>("/api/v1/logs/anonymization", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateAnonRule: (id: number, body: Record<string, unknown>) =>
    fetchJson<AnonymizationRuleDTO>(`/api/v1/logs/anonymization/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteAnonRule: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/logs/anonymization/${id}`, { method: "DELETE" }),
  anonPreview: (dataset: string) =>
    fetchJson<AnonPreview>(`/api/v1/logs/anonymization/preview?dataset=${encodeURIComponent(dataset)}`),
};

// ── shared param builder (same contract as logs-api.qs) ─────────────────────

/** URLSearchParams joiner that skips empty values — keeps query keys stable. */
export function qs(params: Record<string, string | number | undefined | null>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    sp.set(k, String(v));
  }
  return sp.toString();
}
