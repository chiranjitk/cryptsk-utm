/**
 * Webhook delivery engine (M11 §5.6, Phase-1 tail) — genuine outbound HTTPS
 * with HMAC-SHA256 signing, bounded retries, and a full delivery ledger.
 * Shared by the console test endpoint; the Appliance-Mode Go agent reuses the
 * same envelope contract (see docs/04-API/ENDPOINTS.md §webhooks).
 */

import { createHmac } from "node:crypto";
import { db } from "@/lib/db";
import { ulid } from "@/lib/ulid";

export interface WebhookRow {
  id: number;
  tenantId: number;
  name: string;
  url: string;
  secret: string | null;
}

export interface DeliveryAttemptInput {
  event: string;
  data: Record<string, unknown>;
}

export interface DeliveryResult {
  ok: boolean;
  statusCode: number | null;
  durationMs: number | null;
  attempts: number;
  error: string | null;
  signaturePrefix: string | null;
  deliveryId: number;
}

const MAX_ATTEMPTS = 3;
const TIMEOUT_MS = 10_000;
const BACKOFF_MS = [300, 900];

function signedPayload(
  secret: string | null,
  body: string,
): { signature: string | null; headers: Record<string, string> } {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "User-Agent": "Cryptsk-Console/1.0 (+webhook-delivery)",
  };
  if (secret) {
    const sig = createHmac("sha256", secret).update(body).digest("hex");
    headers["X-Cryptsk-Signature"] = `sha256=${sig}`;
    return { signature: sig.slice(0, 16), headers };
  }
  return { signature: null, headers };
}

async function attemptOnce(
  url: string,
  body: string,
  headers: Record<string, string>,
): Promise<{ ok: boolean; statusCode: number | null; error: string | null }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers,
      body,
      signal: controller.signal,
      redirect: "manual",
    });
    // Drain a bounded amount of the body so sockets close cleanly.
    try {
      await res.text();
    } catch {
      /* body read errors don't affect delivery status */
    }
    const ok = res.status >= 200 && res.status < 300;
    return { ok, statusCode: res.status, error: ok ? null : `HTTP ${res.status}` };
  } catch (err) {
    const message =
      err instanceof Error
        ? err.name === "AbortError"
          ? `timeout after ${TIMEOUT_MS}ms`
          : err.message
        : String(err);
    return { ok: false, statusCode: null, error: message };
  } finally {
    clearTimeout(timer);
  }
}

export async function deliverWebhook(
  tenantId: number,
  webhook: WebhookRow,
  input: DeliveryAttemptInput,
): Promise<DeliveryResult> {
  const deliveryUlid = ulid();
  const body = JSON.stringify({
    event: input.event,
    tenantId: webhook.tenantId,
    deliveryId: deliveryUlid,
    timestamp: new Date().toISOString(),
    data: input.data,
  });
  const { signature, headers } = signedPayload(webhook.secret, body);
  headers["X-Cryptsk-Event"] = input.event;
  headers["X-Cryptsk-Delivery"] = deliveryUlid;

  let attempts = 0;
  let lastOk = false;
  let lastStatus: number | null = null;
  let lastError: string | null = null;
  const startedAll = Date.now();

  for (let i = 0; i < MAX_ATTEMPTS; i++) {
    attempts++;
    const t0 = Date.now();
    const res = await attemptOnce(webhook.url, body, headers);
    lastOk = res.ok;
    lastStatus = res.statusCode;
    lastError = res.error;
    if (res.ok || (res.statusCode !== null && res.statusCode < 500)) break; // 4xx: don't retry
    if (i < MAX_ATTEMPTS - 1) {
      await new Promise((r) => setTimeout(r, BACKOFF_MS[i] ?? 900));
    }
  }
  const durationMs = Date.now() - startedAll;

  const row = await db.webhookDelivery.create({
    data: {
      tenantId,
      webhookId: webhook.id,
      event: input.event,
      payload: body.slice(0, 8192),
      ok: lastOk,
      statusCode: lastStatus,
      durationMs,
      attempts,
      error: lastError,
      signature,
    },
  });

  await db.webhook.update({
    where: { id: webhook.id },
    data: {
      lastDeliveryAt: new Date(),
      lastStatus: lastOk ? String(lastStatus ?? "ok") : (lastError ?? "failed").slice(0, 64),
      failureCount: lastOk ? 0 : { increment: 1 },
    },
  });

  return {
    ok: lastOk,
    statusCode: lastStatus,
    durationMs,
    attempts,
    error: lastError,
    signaturePrefix: signature,
    deliveryId: row.id,
  };
}
