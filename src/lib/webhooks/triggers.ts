/**
 * Webhook triggers (T1-e, spec §1.15) — thin, fire-and-forget bridges from the
 * EXISTING pipelines into the delivery engine (lib/webhooks/dispatcher.ts):
 *
 *   1. Audit pipeline — lib/api/audit.ts writeAudit() calls auditTrigger() for
 *      every audited mutation → one `audit.mutation` event (F-e #7: the
 *      per-object `audit.<objectType>` event was outside the LOCKED
 *      webhooks.events enum; the object type travels in the payload instead).
 *      before/after snapshots are DELIBERATELY excluded: audit states can
 *      embed secrets (e.g. ApiKeyCreatedDTO carries the full key).
 *   2. Realtime engine bus — registerWebhookTriggers() installs a hook on
 *      emitEvent (lib/engine/events.ts) mapping the locked socket events to
 *      their dot-form webhook events (alerts:new → `alerts.new` with the
 *      notification payload, config:updated → `config.updated`, …). That bus
 *      is the single broadcast point every notification creation flows through
 *      (MockEngine / HostCollector / restore flows), so `alerts.new` fires
 *      from wherever notifications are created.
 *
 * Tenant isolation (F-e #2): the fan-out is ALWAYS tenant-scoped. The tenant
 * is resolved from the event payload (notification rows carry tenantId; when
 * the payload lacks it, the notification row is looked up by id). If no
 * tenant can be resolved the event is NOT fanned out at all — a bus-wide
 * broadcast would leak events across tenants.
 *
 * registerWebhookTriggers() is invoked ONCE from instrumentation register()
 * (server boot); the once-guard and the engine-bus hook list live on globalThis
 * so the instrumentation- and route-graph module instances agree. Everything
 * here must never throw and never block the emitting pipeline.
 */

import { db } from "@/lib/db";
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

/**
 * Resolve the owning tenant for a bus event. Priority: an explicit tenantId on
 * the payload (engine emit sites + notification rows carry it), then — for
 * alerts:new only — the stored notification row looked up by id (notification
 * rows carry tenantId, F-e #2). Null ⇒ unresolvable ⇒ no fan-out.
 */
async function resolveEventTenantId(evt: EngineEvent, data: unknown): Promise<number | null> {
  if (data && typeof data === "object" && typeof (data as { tenantId?: unknown }).tenantId === "number") {
    return (data as { tenantId: number }).tenantId;
  }
  if (evt.type === "alerts:new") {
    const id = evt.payload.notification?.id;
    if (typeof id === "number") {
      const row = await db.notification
        .findUnique({ where: { id }, select: { tenantId: true } })
        .catch(() => null);
      return row?.tenantId ?? null;
    }
  }
  return null;
}

function engineEventTrigger(evt: EngineEvent): void {
  const event = REALTIME_TO_WEBHOOK[evt.type];
  if (!event) return;
  // fire-and-forget: the hook itself stays synchronous, the resolution +
  // delivery run detached so the realtime bus is never blocked or broken.
  void (async () => {
    try {
      const data = evt.type === "alerts:new" ? evt.payload.notification : evt.payload;
      const tenantId = await resolveEventTenantId(evt, data);
      if (tenantId === null) {
        console.warn(
          `[webhooks] ${event}: no tenantId resolvable from the event payload — fan-out skipped (cross-tenant broadcast is not allowed)`,
        );
        return;
      }
      await deliverEvent(event, data, { tenantId });
    } catch (err) {
      // trigger must never break the realtime event bus
      console.error("[webhooks] engine event fan-out failed:", err instanceof Error ? err.message : err);
    }
  })();
}

/** Idempotent one-time wiring — safe to call repeatedly (and across graphs). */
export function registerWebhookTriggers(): void {
  const g = globalThis as unknown as { __cryptskWebhookTriggersInstalled?: boolean };
  if (g.__cryptskWebhookTriggersInstalled) return;
  g.__cryptskWebhookTriggersInstalled = true;
  addEngineEventHook(engineEventTrigger);
}

/** Audited mutation → `audit.mutation` webhook, tenant-scoped (F-e #7). */
export function auditTrigger(tenantId: number, info: AuditInfo): void {
  try {
    void deliverEvent(
      "audit.mutation", // single LOCKED enum value — object type kept in payload
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
