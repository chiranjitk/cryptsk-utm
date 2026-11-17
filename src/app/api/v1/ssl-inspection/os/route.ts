/**
 * /api/v1/ssl-inspection/os — GUI↔OS honesty view + gated convergence for the
 * Squid ssl-bump integration (M15 §2.1, fragment-file pattern — mirrors
 * /api/v1/waf/os + /api/v1/url-filter/os):
 *
 *   GET  — real host facts (squid binary, ssl-crtd CAPABILITY via `squid -v`
 *          configure flag + ssl_crtd fallback, unit state, live fragment hash,
 *          :3129 probe), the effective policy + PKI signing-CA info, drift
 *          reasons, plan preview (fragment text + step list) and renderer
 *          warnings (conf.d include-order, pinning/HSTS, generated-CA notes).
 *
 *   POST {action: "apply"|"rollback"} — gated on CONSOLE_OS_APPLY=1 AND host
 *          data plane; otherwise plan preview only. Apply REFUSES with an
 *          actionable error when the host squid lacks ssl-crtd (install /
 *          compile squid with ssl-crtd, or cert-pinning-bypass-only mode) —
 *          honest degradation, spec §6. Steps: backup → stage
 *          /etc/squid/conf.d/utm-ssl.conf → sslcrtd init (when missing) →
 *          squid -k parse → systemctl reload|start squid → verify, auto-restore
 *          from /var/lib/console/ssl-inspection/backup-<ts>/ on failure.
 *          Audit: ssl_inspection.os-apply.exec|plan|failed and
 *          ssl_inspection.os-rollback.exec|plan, objectType ssl_policy.
 */

import { route, z } from "@/lib/api/handler";
import { getDataPlaneMode } from "@/lib/engine";
import {
  buildSslPlan,
  execSslApplyPlan,
  getSslOsStatus,
  rollbackSslOs,
  type SslApplyOutcome,
  type SslRollbackResult,
} from "@/lib/ssl-inspection/os-service";

export const dynamic = "force-dynamic";

const osActionSchema = z.object({
  action: z.enum(["apply", "rollback"]).default("apply"),
});

export const GET = route({ area: "ssl_inspection" }, async ({ auth }) => {
  return { data: await getSslOsStatus(auth.tenantId) };
});

type SslPostResult = SslApplyOutcome | SslRollbackResult;

export const POST = route<z.infer<typeof osActionSchema>, undefined, SslPostResult>(
  { area: "ssl_inspection", bodySchema: osActionSchema, section: "ssl_inspection" },
  async ({ auth, body }) => {
    const gateOn = process.env.CONSOLE_OS_APPLY === "1";

    if (body.action === "rollback") {
      const r = await rollbackSslOs(gateOn && getDataPlaneMode() === "host");
      return {
        data: r,
        audit: {
          action: r.rolledBack ? "ssl_inspection.os-rollback.exec" : "ssl_inspection.os-rollback.plan",
          objectType: "ssl_policy",
          objectName: r.backupDir ?? undefined,
          result: r.rolledBack ? "success" : undefined,
          after: { rolledBack: r.rolledBack, backupDir: r.backupDir, revalidated: r.revalidated, reloaded: r.reloaded },
        },
      };
    }

    // apply — build the plan (facts include the ssl-crtd capability), then run
    // the guarded executor; gate off → plan preview, capability missing → the
    // actionable refusal string (never a fabricated step list).
    const ts = new Date().toISOString().replace(/[:.]/g, "-");
    const plan = await buildSslPlan(auth.tenantId, gateOn && getDataPlaneMode() === "host" ? "exec" : "plan", ts);
    const outcome = await execSslApplyPlan(plan);

    const auditAction = outcome.applied
      ? "ssl_inspection.os-apply.exec"
      : outcome.gate === "off" || outcome.refused
        ? "ssl_inspection.os-apply.plan"
        : "ssl_inspection.os-apply.failed";

    return {
      data: outcome,
      audit: {
        action: auditAction,
        objectType: "ssl_policy",
        objectName: outcome.plan.policyId ? `policy=${outcome.plan.policyId}` : "no-mitm-policy",
        result: outcome.applied ? "success" : outcome.gate === "off" || outcome.refused ? undefined : "failure",
        after: {
          applied: outcome.applied,
          refused: outcome.refused ?? null,
          confHash: outcome.confHash ?? null,
          rolledBack: outcome.rolledBack,
          results: outcome.results,
        },
      },
    };
  },
);
