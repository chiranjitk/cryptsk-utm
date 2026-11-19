/**
 * Webhook delivery engine (T1-e, spec §1.15 — REVIEW-4B "webhook real delivery
 * → build decision" divergence closed). Performs REAL outbound HTTPS POSTs to
 * registered webhook endpoints: HMAC-SHA256-signed JSON, bounded retries, one
 * `WebhookDelivery` ledger row per final outcome.
 *
 * Public surface:
 *   - deliverEvent(event, data, opts?)   fire-and-forget fan-out — NEVER throws
 *     and NEVER blocks the caller (call sites use `void deliverEvent(...)`).
 *   - deliverWebhookTest(tenantId, id)   synchronous "Send test" delivery
 *     (event `webhook.test`, forced past the events filter), awaited by
 *     POST /api/v1/webhooks/{id}/test.
 *   - listRecentDeliveries(...)          delivery ledger for the Webhooks tab.
 *
 * Wire contract (LOCKED):
 *   POST {event, tenantId, ts, data} with headers
 *     Content-Type: application/json
 *     X-Cryptsk-Event: <event>
 *     X-Cryptsk-Signature: sha256=<HMAC-SHA256 hex of the RAW body, keyed with
 *     the webhook secret> — header omitted when no secret is stored.
 *   Up to 3 attempts with 500 ms / 2000 ms backoff on TRANSIENT failures
 *   (timeout, network error, 5xx, 429); other 4xx are permanent and stop after
 *   one attempt. Outbound fetch targets the registered https URL only — never
 *   internal admin endpoints (registrations are https-only by validator).
 */

import { createHmac } from "node:crypto";
import { lookup } from "node:dns/promises";
import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { parseJson } from "@/lib/json";

const TIMEOUT_MS = 6000;
const MAX_ATTEMPTS = 3;
const BACKOFF_MS = [500, 2000];
const ERROR_MAX = 300;
const SIGNATURE_SCHEME = "sha256=";
const SIGNATURE_PREFIX_CHARS = 16; // ledger column stores the hex prefix only

// ── SSRF guard (F-e #3) ─────────────────────────────────────────────────────

/** Error prefix for guard-refused targets — terminal, never retried. */
export const SSRF_REFUSAL_PREFIX = "refused by SSRF guard";

/**
 * Private/loopback/link-local/metadata IP refusal (F-e #3). IPv4: 127/8
 * loopback, 10/8 + 172.16/12 + 192.168/16 (RFC1918), 169.254/16 link-local
 * (covers the 169.254.169.254 cloud-metadata endpoint), 0.0.0.0/8 "this
 * network". IPv6: ::1 loopback, :: unspecified, fe80::/10 link-local,
 * fc00::/7 unique-local (the v6 RFC1918 analog), v4-mapped ::ffff: delegates.
 */
export function isRefusedIp(ip: string): boolean {
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (v4) {
    const a = Number(v4[1]);
    const b = Number(v4[2]);
    if (a === 127) return true; // loopback 127/8
    if (a === 10) return true; // RFC1918 10/8
    if (a === 172 && b >= 16 && b <= 31) return true; // RFC1918 172.16/12
    if (a === 192 && b === 168) return true; // RFC1918 192.168/16
    if (a === 169 && b === 254) return true; // link-local 169.254/16 (incl. metadata 169.254.169.254)
    if (a === 0) return true; // "this network" 0.0.0.0/8 (incl. 0.0.0.0)
    return false;
  }
  let h = ip.toLowerCase();
  if (h.includes("%")) h = h.split("%")[0]; // strip IPv6 zone id
  if (h.startsWith("::ffff:")) return isRefusedIp(h.slice("::ffff:".length)); // v4-mapped
  if (h === "::1" || h === "::") return true; // loopback / unspecified
  if (/^f[cd]/.test(h)) return true; // fc00::/7 unique-local
  if (/^fe[89ab]/.test(h)) return true; // fe80::/10 link-local
  return false;
}

/**
 * Pre-delivery SSRF guard (F-e #3 + audit fix L21): https-only (the sandbox
 * override CONSOLE_WEBHOOK_ALLOW_PRIVATE=1 also relaxes the scheme for
 * internal test receivers), then resolve the URL hostname via dns.lookup and
 * refuse private/loopback/link-local/metadata addresses. Returns null when
 * the target is acceptable; unresolvable hostnames pass through so fetch
 * surfaces the real DNS error (retry semantics apply).
 */
export async function ssrfGuard(url: string): Promise<string | null> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return `${SSRF_REFUSAL_PREFIX}: not an absolute URL`;
  }
  // sandbox override first: internal test receivers may use plain http with
  // any scheme — the address refusal is what the override is about.
  if (process.env.CONSOLE_WEBHOOK_ALLOW_PRIVATE === "1") return null;
  if (parsed.protocol !== "https:") {
    // audit fix L21 — https-only in production, matching the registration
    // contract (validators/api-keys.ts enforces https at create/update).
    // HMAC-signed payloads must never transit cleartext http.
    return `${SSRF_REFUSAL_PREFIX}: only https webhook targets are allowed (got ${parsed.protocol})`;
  }
  let host = parsed.hostname;
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  try {
    const resolved = await lookup(host, { all: true, verbatim: true });
    for (const { address } of resolved) {
      if (isRefusedIp(address)) {
        return `${SSRF_REFUSAL_PREFIX}: ${host} resolves to a private/loopback/link-local address (${address})`;
      }
    }
    return null;
  } catch {
    // cannot resolve here — let fetch produce the real DNS error
    return null;
  }
}

export interface DeliverOpts {
  /** Restrict fan-out to webhooks of this tenant (event-side isolation). */
  tenantId?: number;
  /** Per-attempt abort timeout (ms) — default 6000. Test override only. */
  timeoutMs?: number;
  /** Backoff sleeps between attempts (ms) — default [500, 2000]. Test override only. */
  backoffMs?: number[];
}

export type WebhookTestOutcome = {
  ok: boolean;
  statusCode: number | null;
  durationMs: number;
  attempts: number;
  error: string | null;
  signaturePrefix: string | null;
  deliveryId: number;
};

export type WebhookDeliveryDTO = {
  id: number;
  event: string;
  ok: boolean;
  statusCode: number | null;
  durationMs: number | null;
  attempts: number;
  error: string | null;
  signature: string | null;
  createdAt: string;
};

/** Minimal shape the engine needs from a webhook row (Prisma row fits). */
export type WebhookTarget = {
  id: number;
  tenantId: number;
  name: string;
  url: string;
  events: string;
  secret: string | null;
  enabled: boolean;
  failureCount: number;
};

// ── pure helpers (exported for tests) ───────────────────────────────────────

/** `sha256=<HMAC-SHA256 hex of raw body keyed with the webhook secret>`. */
export function signBody(secret: string, body: string): string {
  return SIGNATURE_SCHEME + createHmac("sha256", secret).update(body).digest("hex");
}

/** Stable JSON body — {event, tenantId, ts, data}. */
export function buildEventBody(event: string, tenantId: number, data: unknown): string {
  return JSON.stringify({ event, tenantId, ts: new Date().toISOString(), data });
}

/** Subscription match: explicit event or the `*` wildcard. */
export function eventMatches(subscribed: string[], event: string): boolean {
  return subscribed.includes("*") || subscribed.includes(event);
}

function isTransient(statusCode: number | null): boolean {
  return statusCode === null || statusCode === 429 || statusCode >= 500;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ── attempt loop ────────────────────────────────────────────────────────────

type AttemptOutcome = {
  ok: boolean;
  statusCode: number | null;
  attempts: number;
  error: string | null;
  durationMs: number;
};

/** POST one body with up to MAX_ATTEMPTS bounded attempts + backoff. */
async function attemptDelivery(
  url: string,
  body: string,
  headers: Record<string, string>,
  timeoutMs: number,
  backoffMs: number[],
): Promise<AttemptOutcome> {
  const started = Date.now();
  let attempts = 0;
  let statusCode: number | null = null;
  let lastError: string | null = null;

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    attempts = attempt;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      // redirect: "error" (F-e #3) — a redirect must never silently retarget a
      // validated https endpoint to an unvalidated (possibly internal) URL.
      const res = await fetch(url, { method: "POST", headers, body, signal: controller.signal, redirect: "error" });
      statusCode = res.status;
      if (res.ok) {
        lastError = null;
        break;
      }
      lastError = `HTTP ${res.status}`;
    } catch (err) {
      statusCode = null;
      lastError = controller.signal.aborted
        ? `timeout after ${timeoutMs} ms`
        : err instanceof Error
          ? err.message
          : String(err);
    } finally {
      clearTimeout(timer);
    }
    if (attempt < MAX_ATTEMPTS) {
      if (!isTransient(statusCode)) break; // permanent 4xx — stop after one attempt
      await sleep(backoffMs[attempt - 1] ?? BACKOFF_MS[0]);
    }
  }

  return {
    ok: lastError === null,
    statusCode,
    attempts,
    error: lastError === null ? null : lastError.slice(0, ERROR_MAX),
    durationMs: Date.now() - started,
  };
}

// ── ledger + registration status ────────────────────────────────────────────

/**
 * ONE WebhookDelivery row per final outcome, then refresh the registration's
 * lastDeliveryAt / lastStatus / failureCount (mirrors the legacy simulated
 * fields so the Webhooks tab keeps working unchanged).
 */
async function recordOutcome(
  row: WebhookTarget,
  event: string,
  body: string,
  signaturePrefix: string | null,
  outcome: AttemptOutcome,
): Promise<WebhookTestOutcome> {
  const lastStatus = outcome.ok
    ? String(outcome.statusCode ?? 0)
    : outcome.error !== null && outcome.error.startsWith("timeout")
      ? "timeout"
      : "error";
  const delivery = await db.webhookDelivery.create({
    data: {
      tenantId: row.tenantId,
      webhookId: row.id,
      event,
      payload: body, // JSON body actually POSTed
      ok: outcome.ok,
      statusCode: outcome.statusCode,
      durationMs: outcome.durationMs,
      attempts: outcome.attempts,
      error: outcome.error,
      signature: signaturePrefix,
    },
  });
  await db.webhook.update({
    where: { id: row.id },
    data: {
      lastDeliveryAt: new Date(),
      lastStatus,
      // atomic increment (F-e #13) — concurrent deliveries never clobber each other
      failureCount: outcome.ok ? 0 : { increment: 1 },
    },
  });
  return {
    ok: outcome.ok,
    statusCode: outcome.statusCode,
    durationMs: outcome.durationMs,
    attempts: outcome.attempts,
    error: outcome.error,
    signaturePrefix,
    deliveryId: delivery.id,
  };
}

async function deliverToTarget(
  row: WebhookTarget,
  event: string,
  data: unknown,
  opts: DeliverOpts,
): Promise<WebhookTestOutcome> {
  const body = buildEventBody(event, row.tenantId, data);
  const signature = row.secret ? signBody(row.secret, body) : null;
  const signaturePrefix = signature
    ? signature.slice(SIGNATURE_SCHEME.length, SIGNATURE_SCHEME.length + SIGNATURE_PREFIX_CHARS)
    : null;
  // SSRF guard (F-e #3): refused targets are a TERMINAL failure — recorded
  // once in the ledger with a clear error, no fetch, no retries.
  const refusal = await ssrfGuard(row.url);
  if (refusal) {
    return recordOutcome(
      row,
      event,
      body,
      signaturePrefix,
      { ok: false, statusCode: null, attempts: 0, error: refusal, durationMs: 0 },
    );
  }
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Cryptsk-Event": event,
    ...(signature ? { "X-Cryptsk-Signature": signature } : {}),
  };
  const outcome = await attemptDelivery(
    row.url,
    body,
    headers,
    opts.timeoutMs ?? TIMEOUT_MS,
    opts.backoffMs ?? BACKOFF_MS,
  );
  return recordOutcome(row, event, body, signaturePrefix, outcome);
}

// ── public API ──────────────────────────────────────────────────────────────

/**
 * Fan one event out to every enabled webhook subscribed to it (explicit event
 * or `*`). Fire-and-forget by contract: catches everything internally, so
 * callers can simply `void deliverEvent(...)`.
 */
export async function deliverEvent(event: string, data: unknown, opts: DeliverOpts = {}): Promise<void> {
  try {
    const rows = await db.webhook.findMany({
      where: { enabled: true, ...(opts.tenantId === undefined ? {} : { tenantId: opts.tenantId }) },
    });
    const targets = rows.filter((row) => eventMatches(parseJson<string[]>(row.events, []), event));
    await Promise.all(
      targets.map((row) =>
        deliverToTarget(row, event, data, opts).catch((err: unknown) => {
          console.error(
            `[webhooks] delivery to webhook ${row.id} failed:`,
            err instanceof Error ? err.message : err,
          );
        }),
      ),
    );
  } catch (err) {
    console.error(`[webhooks] deliverEvent(${event}) failed:`, err instanceof Error ? err.message : err);
  }
}

/**
 * "Send test" (POST /api/v1/webhooks/{id}/test): a REAL signed delivery of the
 * `webhook.test` event with a sample payload — forced past the subscription
 * filter, awaited synchronously by the route.
 */
export async function deliverWebhookTest(
  tenantId: number,
  webhookId: number,
  opts: DeliverOpts = {},
): Promise<WebhookTestOutcome> {
  const row = await db.webhook.findFirst({ where: { id: webhookId, tenantId } });
  if (!row) throw ApiError.notFound("Webhook not found");
  return deliverToTarget(
    row,
    "webhook.test",
    {
      name: row.name,
      url: row.url,
      events: parseJson<string[]>(row.events, []),
      note: "Test delivery from Cryptsk — verify this payload's X-Cryptsk-Signature with your stored secret.",
    },
    opts,
  );
}

/** Delivery ledger rows (Webhooks tab dialog) — newest first, bounded. */
export async function listRecentDeliveries(
  tenantId: number,
  webhookId: number,
  take = 50,
): Promise<WebhookDeliveryDTO[]> {
  const rows = await db.webhookDelivery.findMany({
    where: { tenantId, webhookId },
    orderBy: { createdAt: "desc" },
    take,
  });
  return rows.map((row) => ({
    id: row.id,
    event: row.event,
    ok: row.ok,
    statusCode: row.statusCode,
    durationMs: row.durationMs,
    attempts: row.attempts,
    error: row.error,
    signature: row.signature,
    createdAt: (row.createdAt instanceof Date ? row.createdAt : new Date(row.createdAt)).toISOString(),
  }));
}
