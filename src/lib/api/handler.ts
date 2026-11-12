/**
 * Shared API route handler — the single enforcement point for the LOCKED API
 * contract (PROJECT_MEMORY §7.1, API_STANDARDS §2/§4/§5/§7):
 *   requestId (ULID) → rate limit → auth → RBAC matrix → zod validation
 *   → business fn → audit_log + config_versions snapshot → envelope.
 * Routes NEVER hand-roll auth, envelope shaping, RBAC or audit.
 */

import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { z, ZodError, type ZodType } from "zod";
import { ulid } from "@/lib/ulid";
import { ApiError } from "./errors";
import { fail, ok, type PageMeta } from "./envelope";
import { hit } from "./rate-limit";
import { authenticate } from "@/lib/auth/session";
import { can, type AuthContext, type CapabilityArea } from "@/lib/auth/rbac";
import { writeAudit, snapshotConfigVersion, type AuditInfo } from "./audit";

export interface HandlerCtx<TBody, TQuery> {
  req: NextRequest;
  requestId: string;
  auth: AuthContext;
  body: TBody;
  query: TQuery;
  params: Record<string, string>;
  ip: string;
}

export interface HandlerResult<T> {
  data: T;
  meta?: PageMeta;
  audit?: AuditInfo;
  /** optional OS-convergence outcome (network write paths — iface-apply.ts) */
  os?: unknown;
}

export interface RouteOptions<TBody, TQuery> {
  /** RBAC capability area — omit only for public endpoints (login). */
  area?: CapabilityArea;
  /** Skip authentication entirely (auth/login only). */
  isPublic?: boolean;
  /** Admin-class endpoint (system settings, restore, …) — matrix admin column. */
  admin?: boolean;
  bodySchema?: ZodType<TBody>;
  querySchema?: ZodType<TQuery>;
  /** Config section to snapshot + broadcast after a successful mutation. */
  section?: string;
}

type RouteFn<TBody, TQuery, TResult> = (
  ctx: HandlerCtx<TBody, TQuery>,
) => Promise<TResult | HandlerResult<TResult>>;

function clientIp(req: NextRequest): string {
  return (
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    req.headers.get("x-real-ip") ??
    "127.0.0.1"
  );
}

function zodIssues(err: ZodError): Record<string, string[]> {
  const fieldErrors: Record<string, string[]> = {};
  for (const issue of err.issues) {
    const path = issue.path.join(".") || "_";
    (fieldErrors[path] ??= []).push(issue.message);
  }
  return { fieldErrors };
}

function prismaToApiError(err: unknown): ApiError | null {
  if (typeof err === "object" && err !== null && "code" in err) {
    const code = String((err as { code: unknown }).code);
    if (code === "P2002") return ApiError.conflict("Unique constraint violated — the resource already exists");
    if (code === "P2025") return ApiError.notFound("Resource not found");
  }
  return null;
}

export function route<TBody = undefined, TQuery = undefined, TResult = unknown>(
  opts: RouteOptions<TBody, TQuery>,
  fn: RouteFn<TBody, TQuery, TResult>,
) {
  return async (
    req: NextRequest,
    routeCtx?: { params?: Promise<Record<string, string | string[]>> },
  ): Promise<NextResponse> => {
    const requestId = ulid();
    const ip = clientIp(req);
    const isMutation = req.method !== "GET" && req.method !== "HEAD";
    const op: "read" | "write" | "admin" = opts.admin && isMutation ? "admin" : isMutation ? "write" : "read";

    try {
      // ── rate limiting (session 300/min, key 60/min — API_STANDARDS §9) ──
      // Applied pre-auth where possible using IP as coarse key for public routes.
      let auth: AuthContext | null = null;
      if (!opts.isPublic) {
        auth = await authenticate(req);
        const rlKey = auth.kind === "key" ? `key:${auth.username}` : `session:${auth.userId ?? auth.username}`;
        const rl = hit(rlKey, auth.kind === "key" ? 60 : 300);
        if (!rl.allowed) {
          return fail("RATE_LIMITED", `Rate limit exceeded, retry after ${rl.retryAfterSec} seconds`, {
            requestId,
            retryAfter: rl.retryAfterSec,
          });
        }
      } else {
        const rl = hit(`ip:${ip}`, 600);
        if (!rl.allowed) {
          return fail("RATE_LIMITED", "Too many requests", { requestId, retryAfter: rl.retryAfterSec });
        }
      }
      const effectiveAuth: AuthContext =
        auth ?? { kind: "user", role: "helpdesk", tenantId: 1, username: "anonymous" };

      // ── RBAC matrix (single enforcement point) ──
      if (!opts.isPublic && opts.area) {
        if (!can(effectiveAuth, opts.area, op)) {
          if (isMutation) {
            // denied mutations are audited (API_STANDARDS §7)
            await writeAudit({
              tenantId: effectiveAuth.tenantId,
              userId: effectiveAuth.userId,
              username: effectiveAuth.username,
              sourceIp: ip,
              info: {
                action: `${opts.area}.denied`,
                objectType: opts.area,
                result: "denied",
              },
            }).catch(() => {});
          }
          return fail(
            "FORBIDDEN",
            `Role '${effectiveAuth.role}' may not ${op} ${opts.area.replace(/_/g, " ")}`,
            { requestId },
          );
        }
      }

      // ── validation ──
      let parsedBody: TBody = undefined as TBody;
      if (opts.bodySchema) {
        let raw: unknown = undefined;
        try {
          raw = await req.json();
        } catch {
          return fail("VALIDATION_ERROR", "Request body must be valid JSON", { requestId });
        }
        const r = opts.bodySchema.safeParse(raw);
        if (!r.success) {
          return fail("VALIDATION_ERROR", "Request body failed validation", {
            requestId,
            details: zodIssues(r.error),
          });
        }
        parsedBody = r.data;
      }

      let parsedQuery: TQuery = undefined as TQuery;
      if (opts.querySchema) {
        const rawQ: Record<string, string> = {};
        req.nextUrl.searchParams.forEach((v, k) => {
          rawQ[k] = v;
        });
        const r = opts.querySchema.safeParse(rawQ);
        if (!r.success) {
          return fail("VALIDATION_ERROR", "Query parameters failed validation", {
            requestId,
            details: zodIssues(r.error),
          });
        }
        parsedQuery = r.data;
      }

      // ── path params ──
      const params: Record<string, string> = {};
      if (routeCtx?.params) {
        const resolved = await routeCtx.params;
        for (const [k, v] of Object.entries(resolved)) params[k] = Array.isArray(v) ? v[0] : v;
      }

      // ── business logic ──
      const result = await fn({
        req,
        requestId,
        auth: effectiveAuth,
        body: parsedBody,
        query: parsedQuery,
        params,
        ip,
      });

      const isResult = typeof result === "object" && result !== null && "data" in (result as HandlerResult<TResult>);
      const payload = (isResult ? result : { data: result }) as HandlerResult<TResult>;

      // Routes that must shape their own response (Set-Cookie flows) return a
      // NextResponse directly — audit still applies.
      if (payload.data instanceof NextResponse) {
        const res = payload.data as unknown as NextResponse;
        if (isMutation && payload.audit) {
          await writeAudit({
            tenantId: effectiveAuth.tenantId,
            userId: effectiveAuth.userId,
            username: effectiveAuth.username,
            sourceIp: ip,
            info: { ...payload.audit, result: payload.audit.result ?? "success" },
          }).catch(() => {});
        }
        res.headers.set("x-request-id", requestId);
        return res;
      }

      // ── audit + config version snapshot for mutations ──
      if (isMutation) {
        if (payload.audit) {
          await writeAudit({
            tenantId: effectiveAuth.tenantId,
            userId: effectiveAuth.userId,
            username: effectiveAuth.username,
            sourceIp: ip,
            info: { ...payload.audit, result: payload.audit.result ?? "success" },
          }).catch(() => {});
        }
        if (opts.section) {
          await snapshotConfigVersion({
            tenantId: effectiveAuth.tenantId,
            section: opts.section,
            changeSummary: payload.audit
              ? `${payload.audit.action}${payload.audit.objectName ? `: ${payload.audit.objectName}` : ""}`
              : `${req.method} ${req.nextUrl.pathname}`,
            userId: effectiveAuth.userId,
          }).catch(() => {});
        }
      }

      return ok(payload.data, payload.meta, requestId, payload.os);
    } catch (err) {
      if (err instanceof ZodError) {
        return fail("VALIDATION_ERROR", "Request failed validation", { requestId, details: zodIssues(err) });
      }
      if (err instanceof ApiError) {
        // 401 must never leak whether the principal existed
        return fail(err.code, err.message, { requestId, details: err.details });
      }
      const prismaErr = prismaToApiError(err);
      if (prismaErr) return fail(prismaErr.code, prismaErr.message, { requestId });
      console.error(`[api] ${requestId} unhandled error:`, err instanceof Error ? err.message : err);
      return fail("INTERNAL", "Internal server error", { requestId });
    }
  };
}

export { z };

/**
 * Parse an integer path param ([id], [ruleId], …). Invalid values (missing,
 * "null", NaN, ≤0) must fail as 400 VALIDATION_ERROR — letting them reach
 * Prisma renders a 500 "Invalid findFirst invocation" instead.
 */
export function numericId(params: Record<string, string>, key = "id"): number {
  const n = Number(params[key]);
  if (!Number.isInteger(n) || n < 1) {
    throw ApiError.validation(`Invalid path parameter '${key}'`);
  }
  return n;
}
