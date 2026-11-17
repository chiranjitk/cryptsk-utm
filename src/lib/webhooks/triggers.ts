/**
 * Webhook triggers (T1-e, spec §1.15) — thin, fire-and-forget bridges from the
 * EXISTING pipelines into the delivery engine (lib/webhooks/dispatcher.ts):
 *
 *   1. Audit pipeline — lib/api/audit.ts writeAudit() calls auditTrigger() for
 *      every audited mutation → one `audit.<objectType>` event with a compact
 *      summary. before/after snapshots are DELIBERATELY excluded: audit states
 *      can embed secrets (e.g. ApiKeyCreatedDTO carries the full key).
 *   2. Realtime engine bus — registerWebhookTriggers() installs a hook on
 *      emitEvent (lib/engine/events.ts) mapping the locked socket events to
 *      their dot-form webhook events (alerts:new → `alerts.new` with the
 *      notification payload, config:updated → `config.updated`, …). That bus
 *      is the single broadcast point every notification creation flows through
 *      (MockEngine / HostCollector / restore flows), so `alerts.new` fires
 *      from wherever notifications are created.
 *
 * registerWebhookTriggers() is invoked ONCE from instrumentation register()
 * (server boot); the once-guard and the engine-bus hook list live on globalThis
 * so the instrumentation- and route-graph module instances agree. Everything
 * here must never throw and never block the emitting pipeline.
 */

import { addEngineEventHook, type EngineEvent } from "@/lib/engine/events";
import type { AuditInfo } from "@/lib/api/audit";
import { deliverEvent } from "./dispatcher";

/** Locked socket event → dot-form webhook event (PROJECT_MEMORY §7.3 + §6). */
const REALTIME_TO_WEBHOOK: Partial<Record<EngineEvent["type"], string>> = {
  "alerts:new": "alerts.new",
  "config:updated": "config.updated",
  "wan:status": "wan.status",
  "vpn:status": "vpn.status",
  "sessions:update": "sessions.update",
  // metrics:tick / logs:tail deliberately excluded — not webhooks.events values
};

function engineEventTrigger(evt: EngineEvent): void {
  try {
    const event = REALTIME_TO_WEBHOOK[evt.type];
    if (!event) return;
    const data = evt.type === "alerts:new" ? evt.payload.notification : evt.payload;
    // The locked realtime payloads carry no tenantId — fan-out is bus-wide.
    void deliverEvent(event, data);
  } catch {
    // trigger must never break the realtime event bus
  }
}

/** Idempotent one-time wiring — safe to call repeatedly (and across graphs). */
export function registerWebhookTriggers(): void {
  const g = globalThis as unknown as { __cryptskWebhookTriggersInstalled?: boolean };
  if (g.__cryptskWebhookTriggersInstalled) return;
  g.__cryptskWebhookTriggersInstalled = true;
  addEngineEventHook(engineEventTrigger);
}

/** Audited mutation → `audit.<objectType>` webhook, tenant-scoped. */
export function auditTrigger(tenantId: number, info: AuditInfo): void {
  try {
    void deliverEvent(
      `audit.${info.objectType}`,
      {
        action: info.action,
        objectType: info.objectType,
        objectId: info.objectId ?? null,
        objectName: info.objectName ?? null,
        result: info.result ?? "success",
      },
      { tenantId }, // tenant-scoped: never leak mutation events across tenants
    );
  } catch {
    // fire-and-forget — must never break the audit write
  }
}
