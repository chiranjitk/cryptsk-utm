"use client";

/**
 * Email Security typed client (M22) — mirrors the url-filter-api.ts contract:
 * module-local envelope unwrapping that preserves zod `details`, flat endpoint
 * object, DTO types declared here (server routes live under
 * /api/v1/email-security/*, service DTOs are structurally identical).
 */

// ── DTOs (mirror app/api/v1/email-security/service.ts) ──────────────────────

export type GatewayMode = "proxy" | "relay";
export type TlsMode = "none" | "starttls" | "wrapper";
export type DmarcPolicy = "none" | "quarantine" | "reject";
export type RoutingAction = "deliver" | "relay" | "reject" | "quarantine";
export type EmailVerdict = "delivered" | "quarantined" | "rejected";
export type AuthResult = "pass" | "fail" | "softfail" | "none";

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

export interface EmailTestInput {
  from: string;
  to: string;
  subject?: string;
  body?: string;
  attachments?: string[];
  sizeKb?: number;
}

export interface EmailTestResultDTO {
  verdict: EmailVerdict;
  spamScore: number;
  reasons: string[];
  spfResult: AuthResult;
  dkimResult: AuthResult;
  dmarcResult: AuthResult;
  attachmentsScanned: number;
}

export interface EmailStatsDTO {
  delivered24h: number;
  quarantined24h: number;
  rejected24h: number;
  avgSpamScore: number;
  topReasons: Array<{ reason: string; count: number }>;
  quarantineRetentionDays: number;
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

// ── fetch plumbing (same shape as url-filter-api.ts) ────────────────────────

const JSON_HEADERS = { "Content-Type": "application/json" };

export class EmailSecurityApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "EmailSecurityApiError";
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
    throw new EmailSecurityApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new EmailSecurityApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

async function fetchJsonList<T>(path: string, params: string): Promise<Paged<T>> {
  const res = await fetch(`${path}${params ? `?${params}` : ""}`, { credentials: "same-origin" });
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    throw new EmailSecurityApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as {
    data?: T[];
    meta?: PageMeta;
    error?: { code: string; message?: string; details?: unknown };
  };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new EmailSecurityApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return {
    data: (body.data as T[]) ?? [],
    meta: body.meta ?? { page: 1, limit: 25, total: 0, totalPages: 1 },
  };
}

/** Extract zod fieldErrors from an EmailSecurityApiError (handler details shape). */
export function fieldErrorsOf(err: unknown): Record<string, string[]> {
  if (err instanceof EmailSecurityApiError && err.details && typeof err.details === "object") {
    const fe = (err.details as { fieldErrors?: Record<string, string[]> }).fieldErrors;
    if (fe) return fe;
  }
  return {};
}

// ── endpoints ───────────────────────────────────────────────────────────────

export const emailSecurityApi = {
  // gateways
  listGateways: () => fetchJson<EmailGatewayDTO[]>("/api/v1/email-security/gateways"),
  createGateway: (body: Record<string, unknown>) =>
    fetchJson<EmailGatewayDTO>("/api/v1/email-security/gateways", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateGateway: (id: number, body: Record<string, unknown>) =>
    fetchJson<EmailGatewayDTO>(`/api/v1/email-security/gateways/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteGateway: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/email-security/gateways/${id}`, { method: "DELETE" }),

  // policy singleton
  getPolicy: () => fetchJson<EmailPolicyDTO>("/api/v1/email-security/policy"),
  updatePolicy: (body: Record<string, unknown>) =>
    fetchJson<EmailPolicyDTO>("/api/v1/email-security/policy", { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),

  // routing rules
  listRoutingRules: () => fetchJson<EmailRoutingRuleDTO[]>("/api/v1/email-security/routing-rules"),
  createRoutingRule: (body: Record<string, unknown>) =>
    fetchJson<EmailRoutingRuleDTO>("/api/v1/email-security/routing-rules", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateRoutingRule: (id: number, body: Record<string, unknown>) =>
    fetchJson<EmailRoutingRuleDTO>(`/api/v1/email-security/routing-rules/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteRoutingRule: (id: number) =>
    fetchJson<{ ok: boolean }>(`/api/v1/email-security/routing-rules/${id}`, { method: "DELETE" }),

  // simulated scan
  testMessage: (body: EmailTestInput) =>
    fetchJson<EmailTestResultDTO>("/api/v1/email-security/test", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),

  // mail log
  listLogs: (params: string) => fetchJsonList<EmailLogDTO>("/api/v1/email-security/logs", params),
  releaseLog: (id: number) =>
    fetchJson<EmailLogDTO>(`/api/v1/email-security/logs/${id}/release`, { method: "POST", headers: JSON_HEADERS, body: "{}" }),

  // stats
  getStats: () => fetchJson<EmailStatsDTO>("/api/v1/email-security/stats"),
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

export function fmtRelative(value: string | null): string {
  if (!value) return "never";
  const ts = Date.parse(value);
  if (Number.isNaN(ts)) return value;
  const diff = Date.now() - ts;
  if (diff < 0) return "just now";
  const sec = Math.floor(diff / 1000);
  if (sec < 45) return "just now";
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hrs = Math.floor(min / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

// ── display constants ───────────────────────────────────────────────────────

export const GATEWAY_MODES: GatewayMode[] = ["proxy", "relay"];
export const TLS_MODES: TlsMode[] = ["none", "starttls", "wrapper"];
export const DMARC_POLICIES: DmarcPolicy[] = ["none", "quarantine", "reject"];
export const ROUTING_ACTIONS: RoutingAction[] = ["deliver", "relay", "reject", "quarantine"];
export const VERDICTS: EmailVerdict[] = ["delivered", "quarantined", "rejected"];

/** Quick-add extensions for the blocked-extensions chip editor. */
export const COMMON_EXTENSIONS: string[] = ["exe", "js", "vbs", "scr", "bat", "com", "cmd", "pif"];

/** Scale max of the simulated Rspamd score (engine.ts). */
export const SPAM_SCORE_MAX = 12;
