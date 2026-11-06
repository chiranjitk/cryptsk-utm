/**
 * API Platform typed client (M11 / M10 §4 `#/system/api-keys`) — mirrors the
 * dns-dhcp-api.ts contract: module-local envelope unwrapping that preserves
 * zod `details` (lib/realtime's fetchApi drops them), flat endpoint object,
 * DTO types imported from the server service (type-only — erased at build).
 */

import type { ApiKeyDTO, ApiKeyCreatedDTO, WebhookDTO, WebhookTestResult } from "@/lib/api-keys/service";

export type { ApiKeyDTO, ApiKeyCreatedDTO, WebhookDTO, WebhookTestResult };

const JSON_HEADERS = { "Content-Type": "application/json" };

export class ApiKeysApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "ApiKeysApiError";
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
    throw new ApiKeysApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new ApiKeysApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

/** Extract zod fieldErrors from an ApiKeysApiError (handler details shape). */
export function fieldErrorsOf(err: unknown): Record<string, string[]> {
  if (err instanceof ApiKeysApiError && err.details && typeof err.details === "object") {
    const fe = (err.details as { fieldErrors?: Record<string, string[]> }).fieldErrors;
    if (fe) return fe;
  }
  return {};
}

export const apiKeysApi = {
  // keys
  listKeys: () => fetchJson<ApiKeyDTO[]>("/api/v1/api-keys"),
  createKey: (body: Record<string, unknown>) =>
    fetchJson<ApiKeyCreatedDTO>("/api/v1/api-keys", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  revokeKey: (id: number) => fetchJson<ApiKeyDTO>(`/api/v1/api-keys/${id}`, { method: "DELETE" }),

  // webhooks
  listWebhooks: () => fetchJson<WebhookDTO[]>("/api/v1/webhooks"),
  createWebhook: (body: Record<string, unknown>) =>
    fetchJson<WebhookDTO>("/api/v1/webhooks", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  updateWebhook: (id: number, body: Record<string, unknown>) =>
    fetchJson<WebhookDTO>(`/api/v1/webhooks/${id}`, { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
  deleteWebhook: (id: number) => fetchJson<{ ok: boolean }>(`/api/v1/webhooks/${id}`, { method: "DELETE" }),
  testWebhook: (id: number) =>
    fetchJson<WebhookTestResult>(`/api/v1/webhooks/${id}/test`, { method: "POST", headers: JSON_HEADERS, body: "{}" }),
};

// ── formatters ──────────────────────────────────────────────────────────────

export function fmtDateTime(ts: string | null): string {
  if (!ts) return "never";
  return new Date(ts).toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

/** Relative time for lastUsedAt / lastDeliveryAt ("never", "3m ago", "2h ago", "5d ago"). */
export function fmtRelative(ts: string | null): string {
  if (!ts) return "never";
  const ms = Date.now() - new Date(ts).getTime();
  if (ms < 0) return "just now";
  const min = Math.floor(ms / 60_000);
  if (min < 1) return "just now";
  if (min < 60) return `${min}m ago`;
  const h = Math.floor(min / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

/** Clipboard copy with a document.execCommand fallback (non-secure contexts). */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      const ok = document.execCommand("copy");
      ta.remove();
      return ok;
    } catch {
      return false;
    }
  }
}
