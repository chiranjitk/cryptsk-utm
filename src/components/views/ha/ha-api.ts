/**
 * HA typed client (M10 §3) — mirrors the dns-dhcp-api.ts contract:
 * module-local envelope unwrapping that preserves zod `details`, DTO types
 * imported from the server services (type-only — erased before bundling).
 */

import type { HaConfigDTO, HaStatusDTO } from "@/lib/ha/service";

export type { HaConfigDTO, HaStatusDTO };

export interface PageMeta {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

const JSON_HEADERS = { "Content-Type": "application/json" };

export class HaApiError extends Error {
  readonly code: string;
  readonly details?: unknown;
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = "HaApiError";
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
    throw new HaApiError("INTERNAL", `HTTP ${res.status}`);
  }
  const body = json as { data?: T; error?: { code: string; message?: string; details?: unknown } };
  if (body && typeof body === "object" && "error" in body && body.error) {
    throw new HaApiError(body.error.code, body.error.message || body.error.code, body.error.details);
  }
  return (body as { data: T }).data;
}

/** Extract zod fieldErrors from a HaApiError (handler details shape). */
export function fieldErrorsOf(err: unknown): Record<string, string[]> {
  if (err instanceof HaApiError && err.details && typeof err.details === "object") {
    const fe = (err.details as { fieldErrors?: Record<string, string[]> }).fieldErrors;
    if (fe) return fe;
  }
  return {};
}

export const haApi = {
  getStatus: () => fetchJson<HaStatusDTO>("/api/v1/ha/status"),
  getConfig: () => fetchJson<HaConfigDTO>("/api/v1/ha/config"),
  putConfig: (body: Record<string, unknown>) =>
    fetchJson<HaConfigDTO>("/api/v1/ha/config", { method: "PUT", headers: JSON_HEADERS, body: JSON.stringify(body) }),
};
