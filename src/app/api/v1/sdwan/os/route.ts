/**
 * /api/v1/sdwan/os — the SD-WAN GUI↔WireGuard OS integration endpoint
 * (spec 2.5 — wg-quick overlay configs per enabled overlay).
 *
 * GET   — live OS status: gate (CONSOLE_OS_APPLY + data-plane mode), wg/wg-quick
 *         availability, per-overlay file state (missing / in-sync / matches-plan
 *         / drift), running utm-sdwan-* interfaces (wg show parse), pending
 *         commit-confirm window and the full redacted plan preview.
 *
 * POST  — { action, confirmSec?, ts?, bringUp? }:
 *           "plan"     — redacted plan preview (no side effects)
 *           "apply"    — CONFIRM STEP-GUARD (firewall confirm flow): without
 *                        confirmSec the call returns {confirmed:false, ts} and
 *                        NOTHING is written; re-issue with confirmSec (15..600)
 *                        to execute: snapshot-first → write files (private key
 *                        materialized server-side only) → `wg-quick strip`
 *                        validation (pure parse, never brings up) → armed
 *                        commit-confirm rollback timer → state.json. A call
 *                        with ts of the pending window CONFIRMS it.
 *           "rollback" — restore the newest pre-apply snapshot (files only)
 *           "up"       — `wg-quick up utm-sdwan-<slug>` ONLY with
 *                        bringUp=true AND confirmSec; enabled overlays only;
 *                        a successful up confirms the pending window
 *           "down"     — `wg-quick down` for running utm-sdwan-* interfaces
 *                        (confirmSec step-guard applies — traffic-affecting)
 *
 * Audit actions: sdwan.os-apply.exec | os-apply.plan | os-apply.failed |
 * os-apply.confirmed | os-apply.confirm-required | os-apply.rolled-back |
 * os-up.exec | os-down.exec (objectType sdwan_overlay).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { z } from "zod";
import {
  applySdwanToOs,
  buildSdwanPlan,
  confirmSdwanApply,
  downSdwanOverlays,
  readSdwanStatus,
  rollbackSdwan,
  upSdwanOverlays,
  type SdwanApplyOutcome,
  type SdwanDownOutcome,
  type SdwanUpOutcome,
} from "@/lib/sdwan/os-service";
import { sdwanApplyMode, sdwanApplyTs } from "@/lib/sdwan/os";

export const dynamic = "force-dynamic";

const bodySchema = z.object({
  action: z.enum(["plan", "apply", "rollback", "up", "down"]),
  confirmSec: z.number().int().min(15).max(600).optional(),
  ts: z.string().max(64).optional(),
  bringUp: z.boolean().optional(),
});

export const GET = route({ area: "sdwan" }, async ({ auth }) => {
  const status = await readSdwanStatus(auth.tenantId);
  return { data: status };
});

type SdwanOsPostResult =
  | SdwanApplyOutcome
  | SdwanUpOutcome
  | SdwanDownOutcome
  | Awaited<ReturnType<typeof confirmSdwanApply>>
  | Awaited<ReturnType<typeof rollbackSdwan>>
  | { confirmed: false; ts: string }
  | { plan: Awaited<ReturnType<typeof buildSdwanPlan>> };

export const POST = route<z.infer<typeof bodySchema>, undefined, SdwanOsPostResult>(
  { area: "sdwan", bodySchema },
  async ({ auth, body }) => {
    switch (body.action) {
      case "plan": {
        const plan = await buildSdwanPlan(auth.tenantId);
        return {
          data: { plan },
          audit: { action: "sdwan.os-apply.plan", objectType: "sdwan_overlay" },
        };
      }

      case "apply": {
        // confirm step-guard — mirrors the firewall os confirm flow
        const mode = sdwanApplyMode(body);
        if (mode === "step-guard") {
          return {
            data: { confirmed: false, ts: sdwanApplyTs() },
            audit: { action: "sdwan.os-apply.confirm-required", objectType: "sdwan_overlay" },
          };
        }
        if (mode === "confirm") {
          const r = await confirmSdwanApply(body.ts as string);
          if (!r.confirmed) throw ApiError.notFound("no pending apply window for this ts (already confirmed or expired)");
          return {
            data: r,
            audit: { action: "sdwan.os-apply.confirmed", objectType: "sdwan_overlay", objectName: body.ts },
          };
        }
        const outcome = await applySdwanToOs(auth.tenantId, { confirmSec: body.confirmSec });
        const auditAction = !outcome.applied
          ? outcome.gate === "off"
            ? "sdwan.os-apply.plan"
            : "sdwan.os-apply.failed"
          : outcome.rolledBack
            ? "sdwan.os-apply.rolled-back"
            : "sdwan.os-apply.exec";
        return {
          data: outcome,
          audit: {
            action: auditAction,
            objectType: "sdwan_overlay",
            objectName: `${outcome.files.length} file(s)`,
            result: outcome.applied && !outcome.rolledBack ? "success" : "failure",
          },
        };
      }

      case "rollback": {
        const r = await rollbackSdwan(body.ts);
        return {
          data: r,
          audit: {
            action: "sdwan.os-apply.rolled-back",
            objectType: "sdwan_overlay",
            objectName: r.dir ?? undefined,
            result: r.rolledBack ? "success" : "failure",
          },
        };
      }

      case "up": {
        // tunnels affect live traffic — bringUp must be EXPLICITLY confirmed
        if (body.bringUp !== true) {
          throw ApiError.validation("up requires bringUp=true — bringing overlay tunnels up affects live traffic");
        }
        const mode = sdwanApplyMode(body);
        if (mode === "step-guard") {
          return {
            data: { confirmed: false, ts: sdwanApplyTs() },
            audit: { action: "sdwan.os-apply.confirm-required", objectType: "sdwan_overlay" },
          };
        }
        const outcome = await upSdwanOverlays(auth.tenantId, { confirmSec: body.confirmSec });
        return {
          data: outcome,
          audit: {
            action: outcome.broughtUp > 0 ? "sdwan.os-up.exec" : "sdwan.os-up.failed",
            objectType: "sdwan_overlay",
            objectName: `${outcome.broughtUp}/${outcome.requested} up`,
            result: outcome.broughtUp > 0 ? "success" : "failure",
          },
        };
      }

      case "down": {
        // tearing down running tunnels affects live traffic — same step-guard
        const mode = sdwanApplyMode(body);
        if (mode === "step-guard") {
          return {
            data: { confirmed: false, ts: sdwanApplyTs() },
            audit: { action: "sdwan.os-apply.confirm-required", objectType: "sdwan_overlay" },
          };
        }
        const outcome = await downSdwanOverlays();
        return {
          data: outcome,
          audit: {
            action: outcome.broughtDown > 0 || outcome.requested === 0 ? "sdwan.os-down.exec" : "sdwan.os-down.failed",
            objectType: "sdwan_overlay",
            objectName: `${outcome.broughtDown}/${outcome.requested} down`,
            result: outcome.broughtDown > 0 || outcome.requested === 0 ? "success" : "failure",
          },
        };
      }
    }
  },
);
