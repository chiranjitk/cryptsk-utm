"use client";

/**
 * ZTNA typed client (Phase 4 §4.4) — mirrors the incidents-api contract:
 * module-local envelope unwrapping that preserves zod `details`, DTO types
 * declared here (server routes live under /api/v1/ztna/*, service DTOs are
 * structurally identical).
 */

// ── DTOs (mirror lib/ztna/service.ts) ────────────────────────────────────────

export type ZtnaProtocol = "tcp" | "udp";
export type ZtnaSubjectType = "user" | "group" | "device";
export type ZtnaAction = "allow" | "deny";
export type PostureVerdict = "compliant" | "non_compliant" | "unknown";
export type CheckKey = "osPatch" | "av" | "diskEncrypt" | "firewall";

export interface ZtnaAppDTO {
  id: number;
  name: string;
  host: string;
  port: number;
  protocol: ZtnaProtocol;
  group: string;
  policyCount: number;
  createdAt: string;
}

export interface ZtnaPolicyDTO {
  id: number;
  appId: number;
  appName: string;
  subjectType: ZtnaSubjectType;
  subjectRef: string;
  action: ZtnaAction;
  postureProfileId: number | null;
  postureProfileName: string | null;
  schedule: string;
  enabled: boolean;
  createdAt: string;
}

export interface PostureChecks {
  osPatchMaxAgeDays?: number;
  avRequired?: boolean;
  diskEncryptRequired?: boolean;
  firewallRequired?: boolean;
}

export interface PostureProfileDTO {
  id: number;
  name: string;
  checks: PostureChecks;
  policyCount: number;
  createdAt: string;
}

export interface PostureCheckDTO {
  id: number;
  deviceId: string;
  profileId: number;
  profileName: string;
  results: Partial<Record<CheckKey, "pass" | "fail" | "unknown">>;
  verdict: PostureVerdict;
  failedChecks: CheckKey[];
  unknownChecks: CheckKey[];
  checkedAt: string;
  nextCheckAt: string | null;
}

export interface ZtnaStats {
  apps: number;
  policies: number;
  enabledPolicies: number;
  profiles: number;
  compliance: { compliant: number; nonCompliant: number; unknown: number };
  staleChecks: number;
  recentDenials: Array<{
    at: string;
    user: string | null;
    deviceId: string | null;
    appName: string | null;
    matchedPolicyId: number | null;
    reason: string;
  }>;
}

export interface ZtnaEvaluation {
  appId: number;
  appName: string;
  decision: ZtnaAction;
  matchedPolicyId: number | null;
  matchedPolicyRef: string | null;
  postureVerdict: PostureVerdict;
  reason: string;
  evaluatedAt: string;
}

/** Continuous-validation sweep result (POST /posture-checks/validate). */
export interface ContinuousValidationDTO {
  rechecked: number;
  changed: number;
  results: Array<{
    deviceId: string;
    profileId: number;
    previousVerdict: PostureVerdict;
    verdict: PostureVerdict;
    changed: boolean;
  }>;
}

// ── request bodies ───────────────────────────────────────────────────────────

export interface CreateAppBody {
  name: string;
  host: string;
  port?: number;
  protocol?: ZtnaProtocol;
  group?: string;
}

export interface CreatePolicyBody {
  appId: number;
  subjectType?: ZtnaSubjectType;
  subjectRef: string;
  action?: ZtnaAction;
  postureProfileId?: number | null;
  schedule?: string;
  enabled?: boolean;
}

export interface CreateProfileBody {
  name: string;
  checks?: PostureChecks;
}

export interface RecordCheckBody {
  deviceId: string;
  profileId: number;
  results?: Partial<Record<CheckKey, "pass" | "fail" | "unknown">>;
}

export interface EvaluateBody {
  appId: number;
  subject: { user?: string; groups?: string[]; deviceId?: string };
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

// ── fetch plumbing (same shape as incidents-api.ts) ──────────────────────────

const JSON_HEADERS = { "Content-Type": "application/json" };

export class ZtnaApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "ZtnaApiError";
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
    throw new ZtnaApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new ZtnaApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

async function fetchJsonList<T>(path: string, params: string): Promise<Paged<T>> {
  const res = await fetch(`${path}${params ? `?${params}` : ""}`, { credentials: "same-origin" });
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    throw new ZtnaApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as {
    data?: T[];
    meta?: PageMeta;
    error?: { code: string; message?: string; details?: unknown };
  };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new ZtnaApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return {
    data: (body.data as T[]) ?? [],
    meta: body.meta ?? { page: 1, limit: 25, total: 0, totalPages: 1 },
  };
}

function send<T>(path: string, method: "POST" | "PATCH" | "DELETE", body?: unknown): Promise<T> {
  return fetchJson<T>(path, {
    method,
    headers: JSON_HEADERS,
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
}

// ── endpoints ────────────────────────────────────────────────────────────────

export const ztnaApi = {
  // applications
  listApps: () => fetchJson<ZtnaAppDTO[]>("/api/v1/ztna/apps"),
  createApp: (body: CreateAppBody) => send<ZtnaAppDTO>("/api/v1/ztna/apps", "POST", body),
  updateApp: (id: number, body: Partial<CreateAppBody>) => send<ZtnaAppDTO>(`/api/v1/ztna/apps/${id}`, "PATCH", body),
  deleteApp: (id: number) => send<{ ok: boolean }>(`/api/v1/ztna/apps/${id}`, "DELETE"),

  // access policies
  listPolicies: (appId?: number) =>
    fetchJson<ZtnaPolicyDTO[]>("/api/v1/ztna/policies", appId ? `?${qs({ appId })}` : ""),
  createPolicy: (body: CreatePolicyBody) => send<ZtnaPolicyDTO>("/api/v1/ztna/policies", "POST", body),
  updatePolicy: (id: number, body: Partial<CreatePolicyBody>) =>
    send<ZtnaPolicyDTO>(`/api/v1/ztna/policies/${id}`, "PATCH", body),
  deletePolicy: (id: number) => send<{ ok: boolean }>(`/api/v1/ztna/policies/${id}`, "DELETE"),

  // posture profiles
  listProfiles: () => fetchJson<PostureProfileDTO[]>("/api/v1/ztna/posture-profiles"),
  createProfile: (body: CreateProfileBody) => send<PostureProfileDTO>("/api/v1/ztna/posture-profiles", "POST", body),
  updateProfile: (id: number, body: Partial<CreateProfileBody>) =>
    send<PostureProfileDTO>(`/api/v1/ztna/posture-profiles/${id}`, "PATCH", body),
  deleteProfile: (id: number) => send<{ ok: boolean }>(`/api/v1/ztna/posture-profiles/${id}`, "DELETE"),

  // posture checks (latest per device, paged)
  listChecks: (page: number, limit: number, deviceId?: string) =>
    fetchJsonList<PostureCheckDTO>("/api/v1/ztna/posture-checks", qs({ page, limit, deviceId })),
  recordCheck: (body: RecordCheckBody) => send<PostureCheckDTO>("/api/v1/ztna/posture-checks", "POST", body),
  /** explicit continuous-validation sweep (audit fix F-d — GET no longer mutates) */
  runValidation: () => send<ContinuousValidationDTO>("/api/v1/ztna/posture-checks/validate", "POST"),

  // access evaluation (simulator)
  evaluate: (body: EvaluateBody) => send<ZtnaEvaluation>("/api/v1/ztna/evaluate", "POST", body),

  // stats strip
  getStats: () => fetchJson<ZtnaStats>("/api/v1/ztna/stats"),
};

// ── shared param builder (skips empty values — keeps query keys stable) ─────

export function qs(params: Record<string, string | number | undefined | null>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    sp.set(k, String(v));
  }
  return sp.toString();
}

// ── time formatting (console-side, avoids pulling date-fns into views) ──────

export function fmtDateTime(value: string | null): string {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// ── display constants ────────────────────────────────────────────────────────

export const SUBJECT_TYPES: ZtnaSubjectType[] = ["user", "group", "device"];
export const CHECK_LABELS: Record<CheckKey, string> = {
  osPatch: "OS patch age",
  av: "Antivirus",
  diskEncrypt: "Disk encryption",
  firewall: "Host firewall",
};
