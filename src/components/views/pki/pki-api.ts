/**
 * PKI typed client (M14) — mirrors the logs-api.ts contract: module-local
 * envelope unwrapping that preserves zod `details`, flat endpoint object,
 * PEM download helper (blob + anchor). DTOs mirror the server sanitizer
 * shapes in src/app/api/v1/pki/shared.ts — keyPem NEVER exists on any DTO;
 * private keys only ever flow through download?part=key (admin-only, 403
 * surfaces as code FORBIDDEN).
 */

export interface PkiStatusInfo {
  status: "active" | "revoked" | "expired";
  daysUntilExpiry: number | null;
}

export interface CaDto extends PkiStatusInfo {
  id: number;
  name: string;
  type: "root" | "subordinate";
  commonName: string;
  org: string | null;
  keyType: string;
  validityDays: number;
  parentCaId: number | null;
  parentName: string | null;
  serial: string;
  certPem: string;
  keyFingerprint: string | null;
  hasKey: boolean;
  crlUrl: string | null;
  ocspUrl: string | null;
  autoRenew: boolean;
  notBefore: string | null;
  notAfter: string | null;
  issuedCount: number;
  createdAt: string;
}

export interface CertDto extends PkiStatusInfo {
  id: number;
  caId: number;
  caName: string | null;
  name: string;
  commonName: string;
  sans: string[];
  type: "server" | "client" | "device" | "user";
  issuedFor: "ssl_inspect" | "waf" | "vpn" | "email" | "general";
  keyType: string;
  validityDays: number;
  serial: string;
  certPem: string;
  keyFingerprint: string | null;
  hasKey: boolean;
  revocationReason: string | null;
  autoRenew: boolean;
  notBefore: string | null;
  notAfter: string | null;
  createdAt: string;
}

export type CertType = CertDto["type"];
export type IssuedFor = CertDto["issuedFor"];
export type PkiKeyType = "rsa2048" | "rsa4096";
export type RevocationReason = "unspecified" | "keyCompromise" | "caCompromise" | "superseded" | "ceaseOfOperation";

export class PkiApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "PkiApiError";
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
    throw new PkiApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new PkiApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

/** Extract zod fieldErrors from a PkiApiError (handler details shape). */
export function fieldErrorsOf(err: unknown): Record<string, string[]> {
  if (err instanceof PkiApiError && err.details && typeof err.details === "object") {
    const fe = (err.details as { fieldErrors?: Record<string, string[]> }).fieldErrors;
    if (fe) return fe;
  }
  return {};
}

/** Blob-download a PEM/CRL endpoint; throws PkiApiError with the server code on failure. */
async function downloadPem(path: string, fallbackName: string): Promise<{ filename: string }> {
  const res = await fetch(path, { credentials: "same-origin" });
  if (!res.ok) {
    let code = "INTERNAL";
    let message = `HTTP ${res.status}`;
    try {
      const body = (await res.json()) as { error?: { code?: string; message?: string } };
      if (body?.error?.code) code = body.error.code;
      if (body?.error?.message) message = body.error.message;
    } catch {
      /* non-JSON error body */
    }
    throw new PkiApiError(code, message);
  }
  const blob = await res.blob();
  const match = /filename="?([^";]+)"?/.exec(res.headers.get("Content-Disposition") ?? "");
  const filename = match?.[1] ?? fallbackName;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  return { filename };
}

const JSON_HEADERS = { "Content-Type": "application/json" };

export const pkiApi = {
  // ── CAs ──────────────────────────────────────────────────────────────────
  listCas: () => fetchJson<CaDto[]>("/api/v1/pki/cas"),
  createCa: (body: Record<string, unknown>) =>
    fetchJson<CaDto>("/api/v1/pki/cas", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateCa: (id: number, body: Record<string, unknown>) =>
    fetchJson<CaDto>(`/api/v1/pki/cas/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteCa: (id: number) => fetchJson<{ ok: boolean }>(`/api/v1/pki/cas/${id}`, { method: "DELETE" }),
  revokeCa: (id: number) =>
    fetchJson<CaDto>(`/api/v1/pki/cas/${id}/revoke`, { method: "POST", headers: JSON_HEADERS, body: "{}" }),
  exportCa: (id: number, part: "cert" | "key" | "chain", fallback: string) =>
    downloadPem(`/api/v1/pki/cas/${id}/export?part=${part}`, fallback),
  downloadCrl: (id: number, fallback: string) => downloadPem(`/api/v1/pki/cas/${id}/crl`, fallback),

  // ── certificates ─────────────────────────────────────────────────────────
  listCerts: (params: string) => fetchJson<CertDto[]>(`/api/v1/pki/certificates${params ? `?${params}` : ""}`),
  listExpiring: (days = 30) => fetchJson<CertDto[]>(`/api/v1/pki/certificates/expiring?days=${days}`),
  issueCert: (body: Record<string, unknown>) =>
    fetchJson<CertDto>("/api/v1/pki/certificates", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteCert: (id: number) => fetchJson<{ ok: boolean }>(`/api/v1/pki/certificates/${id}`, { method: "DELETE" }),
  revokeCert: (id: number, reason: RevocationReason) =>
    fetchJson<CertDto>(`/api/v1/pki/certificates/${id}/revoke`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ reason }),
    }),
  downloadCert: (id: number, part: "cert" | "key" | "chain", fallback: string) =>
    downloadPem(`/api/v1/pki/certificates/${id}/download?part=${part}`, fallback),
};

/** URLSearchParams joiner that skips empty values — keeps query keys stable. */
export function qs(params: Record<string, string | number | undefined | null>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    sp.set(k, String(v));
  }
  return sp.toString();
}

// ── display helpers ─────────────────────────────────────────────────────────

export function fmtDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

/** Expiry pill tone: blue >90d, amber 31–90d, red ≤30d / expired. */
export function expiryTone(days: number | null, expired: boolean): "blue" | "amber" | "red" {
  if (expired || days === null || days <= 30) return "red";
  if (days <= 90) return "amber";
  return "blue";
}

export const KEY_TYPE_LABELS: Record<string, string> = {
  rsa2048: "RSA 2048",
  rsa4096: "RSA 4096",
};

export const ISSUED_FOR_LABELS: Record<IssuedFor, string> = {
  ssl_inspect: "SSL Inspect",
  waf: "WAF",
  vpn: "VPN",
  email: "Email",
  general: "General",
};
