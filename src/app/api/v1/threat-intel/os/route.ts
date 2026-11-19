/**
 * /api/v1/threat-intel/os — the Threat Intel auto-block GUI↔nftables
 * integration endpoint (spec §2.11 "Auto-block malicious IPs (feed →
 * firewall)").
 *
 * GET   — live OS status: gate (CONSOLE_OS_APPLY + data-plane mode), nft
 *         availability, utm_ti_block table presence, confHash (current
 *         render + last-apply state.json), drift (applied / in-sync /
 *         reasons), per-rule element presence, live drop counters, plan
 *         preview (counts, warnings, statements, full file). Honest when
 *         the host tools are unavailable (sandbox → preview data,
 *         available:false).
 *
 * POST  — { action }:
 *           "apply"     — plan → `nft -c` check → snapshot-first full
 *                         ruleset backup (flush prologue, backup-<ts>/) →
 *                         arm commit-confirm rollback timer → `nft -f` →
 *                         WAN-health probe (auto-restore on regression) →
 *                         state.json {confHash, appliedAt}. Gate off →
 *                         plan preview only.
 *           "confirm"   — confirms the pending apply (cancels rollback)
 *           "rollback"  — restores the newest backup immediately
 *           "sync-hits" — pushes kernel element/drop counters into
 *                         AutoBlockRule.hitCount
 *
 * Audit actions: threat_intel.os-apply.exec | os-apply.plan |
 * os-apply.failed | os-apply.confirmed | os-apply.rolled-back |
 * os-sync-hits (objectType auto_block_rule).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { z } from "zod";
import {
  buildTiPlan,
  readTiState,
  readTiTableDump,
  applyTiToOs,
  confirmTiApply,
  rollbackTi,
  syncTiHitsFromKernel,
  type TiApplyOutcome,
} from "@/lib/threat-intel/os-service";
import { parseTiDropCounters, parseTiElements } from "@/lib/threat-intel/os";

export const dynamic = "force-dynamic";

const bodySchema = z.object({
  action: z.enum(["apply", "confirm", "rollback", "sync-hits"]),
  mode: z.enum(["manual", "auto"]).optional(),
  confirmSec: z.number().int().min(15).max(600).optional(),
  ts: z.string().max(64).optional(),
});

export const GET = route({ area: "threat_intel" }, async ({ auth }) => {
  const plan = await buildTiPlan(auth.tenantId);
  const [liveDump, snapshot] = await Promise.all([readTiTableDump(), readTiState()]);
  const dropCounters = liveDump ? parseTiDropCounters(liveDump) : plan.dropCounters;
  const elementCounters = liveDump ? parseTiElements(liveDump) : plan.elementCounters;
  return {
    data: {
      gate: process.env.CONSOLE_OS_APPLY === "1" ? "on" : "off",
      mode: plan.facts.mode,
      available: plan.facts.nftAvailable,
      nftVersion: plan.facts.nftVersion,
      tablePresent: plan.drift.applied,
      /** sha256 of the CURRENT render (comment-stripped canonical body) */
      confHash: plan.gen.confHash,
      /** sha256 + appliedAt of the LAST successful apply (state.json) */
      stateConfHash: snapshot.state?.confHash ?? null,
      appliedAt: snapshot.state?.appliedAt ?? null,
      drift: plan.drift,
      counts: plan.gen.counts,
      warnings: plan.gen.warnings,
      statements: plan.gen.statements,
      perRule: plan.perRule,
      dropCounters,
      elementCounters,
      file: plan.file,
      pendingConfirm: snapshot.pending,
      tableDump: liveDump,
    },
  };
});

type TiPostResult =
  | TiApplyOutcome
  | Awaited<ReturnType<typeof confirmTiApply>>
  | Awaited<ReturnType<typeof rollbackTi>>
  | Awaited<ReturnType<typeof syncTiHitsFromKernel>>;

export const POST = route<z.infer<typeof bodySchema>, undefined, TiPostResult>(
  // audit fix L8 — kernel-mutating OS actions snapshot a config version like
  // every other mutation route (audit contract "every mutation snapshots").
  { area: "threat_intel", bodySchema, section: "threat_intel" },
  async ({ auth, body }) => {
    switch (body.action) {
      case "apply": {
        const outcome = await applyTiToOs(auth.tenantId, { mode: body.mode ?? "manual", confirmSec: body.confirmSec });
        const auditAction = !outcome.applied
          ? outcome.gate === "off"
            ? "threat_intel.os-apply.plan"
            : "threat_intel.os-apply.failed"
          : outcome.rolledBack
            ? "threat_intel.os-apply.rolled-back"
            : "threat_intel.os-apply.exec";
        return {
          data: outcome,
          audit: {
            action: auditAction,
            objectType: "auto_block_rule",
            objectName: `mode=${body.mode ?? "manual"}`,
            result: outcome.applied && !outcome.rolledBack ? "success" : "failure",
          },
        };
      }
      case "confirm": {
        if (!body.ts) throw ApiError.validation("confirm requires ts of the pending apply");
        const r = await confirmTiApply(auth.tenantId, body.ts);
        if (!r.confirmed) throw ApiError.notFound("no pending apply window for this ts (already confirmed or expired)");
        return {
          data: r,
          audit: { action: "threat_intel.os-apply.confirmed", objectType: "auto_block_rule", objectName: body.ts },
        };
      }
      case "rollback": {
        const r = await rollbackTi(auth.tenantId, body.ts);
        return {
          data: r,
          audit: {
            action: "threat_intel.os-apply.rolled-back",
            objectType: "auto_block_rule",
            objectName: r.file ?? undefined,
            result: r.rolledBack ? "success" : "failure",
          },
        };
      }
      case "sync-hits": {
        const r = await syncTiHitsFromKernel(auth.tenantId);
        return { data: r, audit: { action: "threat_intel.os-sync-hits", objectType: "auto_block_rule" } };
      }
    }
  },
);
