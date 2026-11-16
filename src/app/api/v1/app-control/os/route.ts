/**
 * /api/v1/app-control/os — the App Control GUI↔nftables integration endpoint.
 *
 * GET   — live OS status: gate (CONSOLE_OS_APPLY + data-plane mode), nft
 *         availability, utm_appctl table presence, drift (applied / in-sync /
 *         reasons), generated plan (counts, warnings, skipped DPI-only apps,
 *         full file), kernel per-rule counters, pending commit-confirm window.
 *         Honest when the host tools are unavailable (sandbox → preview data).
 *
 * POST  — { action }:
 *           "apply"     — plan → `nft -c` check → full-ruleset backup (flush
 *                         prologue) → arm commit-confirm rollback timer →
 *                         `nft -f` → WAN-health probe (auto-restore on
 *                         regression) → persistence. mode "auto" self-confirms
 *                         after health; "manual" leaves the window open.
 *           "confirm"   — confirms the pending apply (cancels the rollback)
 *           "rollback"  — restores the newest backup immediately
 *           "sync-hits" — pushes kernel counters into AppControlRule.hitCount
 *
 * Audit actions: app_control.os-apply.exec | os-apply.plan | os-apply.failed |
 * os-apply.confirmed | os-apply.rolled-back (objectType app_control_policy).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { z } from "zod";
import {
  buildAppctlPlan,
  readApplyState,
  readAppctlTableDump,
  applyAppctlToOs,
  confirmAppctlApply,
  rollbackAppctl,
  syncAppctlHitsFromKernel,
} from "@/lib/app-control/os-service";
import { parseAppctlRuleCounters } from "@/lib/app-control/os";

export const dynamic = "force-dynamic";

const bodySchema = z.object({
  action: z.enum(["apply", "confirm", "rollback", "sync-hits"]),
  mode: z.enum(["manual", "auto"]).optional(),
  confirmSec: z.number().int().min(15).max(600).optional(),
  ts: z.string().max(64).optional(),
});

export const GET = route({ area: "app_control" }, async ({ auth }) => {
  const plan = await buildAppctlPlan(auth.tenantId);
  const [liveDump, pending] = await Promise.all([readAppctlTableDump(), readApplyState()]);
  const counters = liveDump ? parseAppctlRuleCounters(liveDump) : [];
  return {
    data: {
      gate: process.env.CONSOLE_OS_APPLY === "1" ? "on" : "off",
      mode: plan.facts.mode,
      available: plan.facts.nftAvailable,
      nftVersion: plan.facts.nftVersion,
      tablePresent: plan.drift.applied,
      drift: plan.drift,
      counts: plan.gen.counts,
      warnings: plan.gen.warnings,
      skippedApps: plan.gen.skippedApps,
      statements: plan.gen.statements,
      file: plan.file,
      counters,
      pendingConfirm: pending,
      tableDump: liveDump,
    },
  };
});

export const POST = route({ area: "app_control", bodySchema }, async ({ auth, body }) => {
  switch (body.action) {
    case "apply": {
      const outcome = await applyAppctlToOs(auth.tenantId, { mode: body.mode ?? "manual", confirmSec: body.confirmSec });
      const auditAction = !outcome.applied
        ? outcome.gate === "off"
          ? "app_control.os-apply.plan"
          : "app_control.os-apply.failed"
        : outcome.rolledBack
          ? "app_control.os-apply.rolled-back"
          : "app_control.os-apply.exec";
      return {
        data: outcome,
        audit: {
          action: auditAction,
          objectType: "app_control_policy",
          objectName: `mode=${body.mode ?? "manual"}`,
          result: outcome.applied && !outcome.rolledBack ? "success" : "failure",
        },
      };
    }
    case "confirm": {
      if (!body.ts) throw ApiError.validation("confirm requires ts of the pending apply");
      const r = await confirmAppctlApply(body.ts);
      if (!r.confirmed) throw ApiError.notFound("no pending apply window for this ts (already confirmed or expired)");
      return {
        data: r,
        audit: { action: "app_control.os-apply.confirmed", objectType: "app_control_policy", objectName: body.ts },
      };
    }
    case "rollback": {
      const r = await rollbackAppctl(body.ts);
      return {
        data: r,
        audit: {
          action: "app_control.os-apply.rolled-back",
          objectType: "app_control_policy",
          objectName: r.file ?? undefined,
          result: r.rolledBack ? "success" : "failure",
        },
      };
    }
    case "sync-hits": {
      const r = await syncAppctlHitsFromKernel(auth.tenantId);
      return { data: r, audit: { action: "app_control.os-sync-hits", objectType: "app_control_policy" } };
    }
  }
});
