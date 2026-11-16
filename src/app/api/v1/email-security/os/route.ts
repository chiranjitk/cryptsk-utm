/**
 * /api/v1/email-security/os — the GUI↔Postfix+Rspamd(+ClamAV) integration
 * endpoint (M22, mirrors /api/v1/logs/apply + /api/v1/waf/os):
 *
 * GET   — live OS status: availability (postfix + rspamadm + ss, host data
 *         plane), gate (CONSOLE_OS_APPLY), postfix/rspamd unit states, clamd
 *         reachability probe (clamdscan --ping 1, informational), listener
 *         ports (:25 / :11332 / :11334), managed-file facts + hashes, drift
 *         (in-sync / managed-by-console / reasons), last apply state, per-
 *         gateway render preview (transport lines, render hash), policy
 *         summary and renderer warnings (master.cf red line, retention scope).
 *
 * POST  — { action }:
 *           "apply"    — backup → stage/install managed files → postmap →
 *                        rspamadm configtest → postfix check → enable/restart
 *                        rspamd → start/reload postfix → verify (units + ports
 *                        + re-hash) → state.json LAST (auto-restore + service
 *                        restarts on failure). Gated by CONSOLE_OS_APPLY=1 +
 *                        host data plane; otherwise the exact plan is returned
 *                        as a preview. No enabled gateways → teardown (stop
 *                        postfix + rspamd).
 *           "rollback" — restore the newest /var/lib/console/email/backup-<ts>/
 *                        and re-run postmap + service restarts.
 *
 * Audit actions: email_security.os-apply.exec | os-apply.plan | os-apply.failed
 * | os-rollback (objectType email_gateway, section email_security).
 */

import { route } from "@/lib/api/handler";
import { z } from "zod";
import { applyEmailToOs, getEmailOsStatus, rollbackEmailOs } from "@/lib/email-security/os-service";

export const dynamic = "force-dynamic";

const bodySchema = z.object({
  action: z.enum(["apply", "rollback"]),
});

export const GET = route({ area: "email_security" }, async ({ auth }) => {
  return { data: await getEmailOsStatus(auth.tenantId) };
});

export const POST = route({ area: "email_security", bodySchema, section: "email_security" }, async ({ auth, body }) => {
  switch (body.action) {
    case "rollback": {
      const r = await rollbackEmailOs();
      return {
        data: r,
        audit: {
          action: "email_security.os-rollback",
          objectType: "email_gateway",
          objectName: r.backupDir ?? undefined,
          result: r.rolledBack ? "success" : "failure",
        },
      };
    }
    case "apply": {
      const outcome = await applyEmailToOs(auth.tenantId);
      const auditAction = outcome.applied
        ? "email_security.os-apply.exec"
        : outcome.refused || outcome.gate === "off"
          ? "email_security.os-apply.plan"
          : "email_security.os-apply.failed";
      return {
        data: outcome,
        audit: {
          action: auditAction,
          objectType: "email_gateway",
          objectName: outcome.plan.gatewayIds.length > 0 ? `gateways=${outcome.plan.gatewayIds.join(",")}` : "none",
          after: {
            applied: outcome.applied,
            skipped: outcome.skipped,
            confHash: outcome.confHash,
            rolledBack: outcome.rolledBack,
            results: outcome.results,
          },
        },
      };
    }
  }
});
