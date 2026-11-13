/**
 * API Platform service (M11) — API-key lifecycle (§5.1) and webhook
 * registrations with simulated delivery (§5.6). SCHEMA.md §3:
 *
 *   ApiKey   — prefix ("ck_" + 8 chars, stored for lookup) + hashedKey
 *              (sha256 of the full key); the full key is returned EXACTLY
 *              ONCE by createKey and never persisted or serialized again.
 *   Webhook  — secret is write-only: never returned by any DTO below.
 *
 * Delivery is a simulated stub per ROADMAP §5 / M11 §5.6: sandbox MARKS
 * deliveries (lastDeliveryAt/lastStatus/failureCount) with seeded outcomes;
 * the appliance sender performs real HMAC-signed HTTP (not console work).
 */

import { createHash, randomBytes } from "node:crypto";
import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { parseJson, stringifyJson } from "@/lib/json";
import type { ApiKeyCreate, WebhookCreate, WebhookEvent, WebhookUpdate } from "@/lib/validators/api-keys";

// ── DTOs (hashedKey / secret are structurally absent — never serialized) ────

export type ApiKeyDTO = {
  id: number;
  tenantId: number;
  name: string;
  prefix: string; // "ck_" + 8 chars — the only surviving trace of the key
  scopes: string[];
  lastUsedAt: string | null;
  expiresAt: string | null;
  revoked: boolean;
  createdAt: string;
};

export type ApiKeyCreatedDTO = ApiKeyDTO & { key: string }; // full key, exactly once

export type WebhookDTO = {
  id: number;
  tenantId: number;
  name: string;
  url: string;
  events: string[];
  enabled: boolean;
  lastDeliveryAt: string | null;
  lastStatus: string | null; // "200" | "timeout" (simulated)
  failureCount: number;
  createdAt: string;
};

export type WebhookTestResult = { ok: boolean; status: "200" | "timeout"; latencyMs: number };

function sha256(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

type ApiKeyRow = {
  id: number;
  tenantId: number;
  name: string;
  prefix: string;
  scopes: string;
  lastUsedAt: Date | null;
  expiresAt: Date | null;
  revoked: boolean;
  createdAt: Date;
};

function toApiKeyDTO(row: ApiKeyRow): ApiKeyDTO {
  return {
    id: row.id,
    tenantId: row.tenantId,
    name: row.name,
    prefix: row.prefix,
    scopes: parseJson<string[]>(row.scopes, ["read"]),
    lastUsedAt: row.lastUsedAt?.toISOString() ?? null,
    expiresAt: row.expiresAt?.toISOString() ?? null,
    revoked: row.revoked,
    createdAt: row.createdAt.toISOString(),
  };
}

type WebhookRow = {
  id: number;
  tenantId: number;
  name: string;
  url: string;
  events: string;
  enabled: boolean;
  lastDeliveryAt: Date | null;
  lastStatus: string | null;
  failureCount: number;
  createdAt: Date;
};

function toWebhookDTO(row: WebhookRow): WebhookDTO {
  return {
    id: row.id,
    tenantId: row.tenantId,
    name: row.name,
    url: row.url,
    events: parseJson<string[]>(row.events, []),
    enabled: row.enabled,
    lastDeliveryAt: row.lastDeliveryAt?.toISOString() ?? null,
    lastStatus: row.lastStatus,
    failureCount: row.failureCount,
    createdAt: row.createdAt.toISOString(),
  };
}

// ── API keys (M11 §5.1) ─────────────────────────────────────────────────────

export async function listKeys(tenantId: number): Promise<ApiKeyDTO[]> {
  const rows = await db.apiKey.findMany({ where: { tenantId }, orderBy: { createdAt: "desc" } });
  return rows.map(toApiKeyDTO);
}

/**
 * Generate + store a key. Full key shape: `ck_<prefix8>_<secret32>` (40
 * url-safe random chars total, node:crypto CSPRNG base64url) — the split is
 * exactly what lib/auth/session.ts parses (prefix "ck_" + 8 chars, then "_",
 * then the 32-char secret). hashedKey = sha256(full); prefix is unique.
 */
export async function createKey(tenantId: number, input: ApiKeyCreate): Promise<ApiKeyCreatedDTO> {
  for (let attempt = 0; attempt < 3; attempt++) {
    const rnd = randomBytes(30).toString("base64url"); // exactly 40 url-safe chars
    const prefix = `ck_${rnd.slice(0, 8)}`;
    const fullKey = `ck_${rnd.slice(0, 8)}_${rnd.slice(8, 40)}`;
    try {
      const row = await db.apiKey.create({
        data: {
          tenantId,
          name: input.name,
          prefix,
          hashedKey: sha256(fullKey),
          scopes: stringifyJson(input.scopes),
          expiresAt: input.expiresAt ? new Date(input.expiresAt) : null,
        },
      });
      // The ONLY place the full key leaves the server (POST response → M10
      // show-secret-once dialog). hashedKey is never serialized.
      return { ...toApiKeyDTO(row), key: fullKey };
    } catch (err) {
      // P2002 on prefix collision → re-roll; anything else (or exhausted) bubbles.
      if (
        attempt < 2 &&
        typeof err === "object" &&
        err !== null &&
        "code" in err &&
        (err as { code: unknown }).code === "P2002"
      ) {
        continue;
      }
      throw err;
    }
  }
  throw ApiError.internal("Unable to allocate a unique key prefix");
}

/** Soft revoke (M11 §5.1): revoked = true; the row remains for audit/history. */
export async function revokeKey(tenantId: number, id: number): Promise<ApiKeyDTO> {
  const row = await db.apiKey.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("API key not found");
  const updated = await db.apiKey.update({ where: { id: row.id }, data: { revoked: true } });
  return toApiKeyDTO(updated);
}

// ── Webhooks (M11 §5.6) ─────────────────────────────────────────────────────

export async function listWebhooks(tenantId: number): Promise<WebhookDTO[]> {
  const rows = await db.webhook.findMany({ where: { tenantId }, orderBy: { createdAt: "desc" } });
  return rows.map(toWebhookDTO);
}

export async function createWebhook(tenantId: number, input: WebhookCreate): Promise<WebhookDTO> {
  const dup = await db.webhook.findFirst({ where: { tenantId, name: input.name } });
  if (dup) throw ApiError.conflict(`Webhook name '${input.name}' already exists`);
  const row = await db.webhook.create({
    data: {
      tenantId,
      name: input.name,
      url: input.url,
      events: stringifyJson(input.events),
      secret: input.secret ?? null, // write-only: set on POST, never read back into a DTO
      enabled: input.enabled,
    },
  });
  return toWebhookDTO(row);
}

/** Omit `secret` to keep the stored value (M11 §5.6 masking rule). */
export async function updateWebhook(tenantId: number, id: number, input: WebhookUpdate): Promise<WebhookDTO> {
  const row = await db.webhook.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Webhook not found");
  if (input.name !== undefined && input.name !== row.name) {
    const dup = await db.webhook.findFirst({ where: { tenantId, name: input.name } });
    if (dup && dup.id !== row.id) throw ApiError.conflict(`Webhook name '${input.name}' already exists`);
  }
  const updated = await db.webhook.update({
    where: { id: row.id },
    data: {
      ...(input.name !== undefined ? { name: input.name } : {}),
      ...(input.url !== undefined ? { url: input.url } : {}),
      ...(input.events !== undefined ? { events: stringifyJson(input.events) } : {}),
      ...(input.secret !== undefined ? { secret: input.secret } : {}), // undefined → keep
      ...(input.enabled !== undefined ? { enabled: input.enabled } : {}),
    },
  });
  return toWebhookDTO(updated);
}

export async function deleteWebhook(tenantId: number, id: number): Promise<{ ok: boolean }> {
  const row = await db.webhook.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Webhook not found");
  await db.webhook.delete({ where: { id: row.id } });
  return { ok: true };
}

/**
 * Seeded deterministic delivery outcome (M11 §5.6): ~85% deliver as "200"
 * with a plausible latency, the rest "timeout". Deterministic per
 * (webhookId, second-bucket) so rapid double-clicks are reproducible.
 */
function seededDeliveryOutcome(id: number, atMs: number): WebhookTestResult {
  const bucket = Math.floor(atMs / 1000);
  const digest = createHash("sha256").update(`webhook:${id}:${bucket}`).digest();
  const ok = digest[0] % 100 < 85;
  if (ok) {
    const latencyMs = 18 + (((digest[1] << 8) | digest[2]) % 470); // 18–487 ms
    return { ok: true, status: "200", latencyMs };
  }
  return { ok: false, status: "timeout", latencyMs: 5000 };
}

/** "Send test" (M10 §4): one marked delivery → {ok, status, latencyMs} + row refresh. */
export async function testWebhookDelivery(tenantId: number, id: number): Promise<WebhookTestResult> {
  const row = await db.webhook.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Webhook not found");
  const now = new Date();
  const result = seededDeliveryOutcome(row.id, now.getTime());
  await db.webhook.update({
    where: { id: row.id },
    data: {
      lastDeliveryAt: now,
      lastStatus: result.status, // "200" | "timeout"
      failureCount: result.ok ? row.failureCount : row.failureCount + 1,
    },
  });
  return result;
}

/**
 * Simulated-delivery hook for future engine wiring (M11 §5.6): when a
 * matching event fires, enabled registrations subscribed to it get their
 * delivery fields MARKED with seeded outcomes — no real HTTP egress in
 * sandbox (the appliance sender performs real signed POSTs). Deliberately
 * NOT called anywhere in Phase 1 (engine wiring is out of this task's
 * scope); never throws so engine call-sites can stay fire-and-forget.
 */
export async function markWebhookDelivery(event: WebhookEvent, data: Record<string, unknown> = {}): Promise<void> {
  try {
    const rows = await db.webhook.findMany({
      where: { enabled: true, events: { contains: event } },
    });
    const matching = rows.filter((r) => parseJson<string[]>(r.events, []).includes(event));
    if (matching.length === 0) return;
    const now = new Date();
    await Promise.all(
      matching.map(async (row) => {
        const result = seededDeliveryOutcome(row.id, now.getTime());
        await db.webhook.update({
          where: { id: row.id },
          data: {
            lastDeliveryAt: now,
            lastStatus: result.status,
            failureCount: result.ok ? row.failureCount : row.failureCount + 1,
          },
        });
        void data; // payload {event, ts, data} matters only to the real appliance sender
      }),
    );
  } catch {
    // no-op-safe: delivery marking must never break the emitting code path
  }
}
