/**
 * /api/v1/identity/os — the GUI↔FreeRADIUS integration endpoint (IMPL-8).
 *
 * GET   — live OS status: freeradius/ss availability (honest false in the
 *         sandbox), unit state, udp/1812 bound probe, drift (clients.conf
 *         hash vs render + unit expectation), per-profile render slugs/
 *         hashes, last-apply state.json, gate (CONSOLE_OS_APPLY).
 *
 * POST  — { action }:
 *           "apply"    — converge /etc/freeradius/3.0/clients.conf onto the
 *                        console RadiusProfile rows (one client block per
 *                        profile = NAS client): backup stock → install render
 *                        → `freeradius -CX` → restart (or stop when NO
 *                        profiles: console-off) → verify unit + port + re-
 *                        validate → state.json LAST. Snapshot-first with
 *                        auto-restore on any post-install failure.
 *           "rollback" — restore the newest backup-<ts>/clients.conf (the
 *                        stock Debian file), re-validate, restart/stop.
 *
 * Gate model (identical to logs/qos/ha): CONSOLE_OS_APPLY=1 and data plane in
 * host mode → execute; otherwise plan preview only. Never radtest — probing
 * an external server is the client-side testRadiusProfile, not OS apply.
 */

import { route } from "@/lib/api/handler";
import { z } from "zod";
import { applyRadiusToOs, readRadiusOsStatus, rollbackRadiusToOs } from "@/lib/identity/os-service";

export const dynamic = "force-dynamic";

const bodySchema = z.object({
  action: z.enum(["apply", "rollback"]),
});

export const GET = route({ area: "identity" }, async ({ auth }) => {
  return { data: await readRadiusOsStatus(auth.tenantId) };
});

export const POST = route({ area: "identity", bodySchema, section: "identity" }, async ({ auth, body }) => {
  if (body.action === "rollback") {
    const outcome = await rollbackRadiusToOs(process.env.CONSOLE_OS_APPLY === "1");
    return {
      data: outcome,
      audit: {
        action: "radius.os-rollback",
        objectType: "radius_profile",
        objectName: "freeradius",
        result: outcome.rolledBack ? "success" : "failure",
        after: outcome,
      },
    };
  }

  const gateOn = process.env.CONSOLE_OS_APPLY === "1";
  const outcome = await applyRadiusToOs(auth.tenantId, gateOn);
  return {
    data: outcome,
    audit: {
      action: outcome.applied
        ? "radius.os-apply.exec"
        : outcome.refused
          ? "radius.os-apply.plan"
          : "radius.os-apply.failed",
      objectType: "radius_profile",
      objectName: "freeradius",
      after: {
        applied: outcome.applied,
        skipped: outcome.skipped,
        confHash: outcome.confHash,
        rolledBack: outcome.rolledBack,
        results: outcome.results,
      },
    },
  };
});
