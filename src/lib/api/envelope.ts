/**
 * Response envelope (LOCKED) — docs/04-API/API_STANDARDS.md §4.
 * Success: { data, meta? } · Error: { error: { code, message, details?, requestId? } }
 */

import { NextResponse } from "next/server";
import { ERROR_CODES, type ErrorCode } from "./errors";

export interface PageMeta {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

export interface EnvelopeSuccess<T> {
  data: T;
  meta?: PageMeta;
  /** optional OS-convergence outcome (network write paths — iface-apply.ts) */
  os?: unknown;
}

export interface EnvelopeError {
  error: {
    code: ErrorCode;
    message: string;
    details?: unknown;
    requestId?: string;
  };
}

export function ok<T>(data: T, meta?: PageMeta, requestId?: string, os?: unknown): NextResponse {
  const body: EnvelopeSuccess<T> = meta ? { data, meta } : { data };
  if (os !== undefined) body.os = os;
  const res = NextResponse.json(body);
  if (requestId) res.headers.set("x-request-id", requestId);
  return res;
}

export function fail(
  code: ErrorCode,
  message: string,
  opts?: { details?: unknown; requestId?: string; retryAfter?: number },
): NextResponse {
  const body: EnvelopeError = {
    error: {
      code,
      message,
      ...(opts?.details !== undefined ? { details: opts.details } : {}),
      ...(opts?.requestId ? { requestId: opts.requestId } : {}),
    },
  };
  const res = NextResponse.json(body, { status: ERROR_CODES[code] });
  if (opts?.retryAfter) res.headers.set("Retry-After", String(opts.retryAfter));
  if (opts?.requestId) res.headers.set("x-request-id", opts.requestId);
  return res;
}
