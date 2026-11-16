/**
 * /api/v1/url-filter/os — GUI↔OS honesty view + gated convergence for the
 * Squid URL-filter integration (full /etc/squid/squid.conf management).
 *
 *   GET  — real host facts (squid binary, unit state, :3128, live conf hash),
 *          rendered per-policy hashes, drift reasons + plan-relevant warnings.
 *   POST {action: "apply"|"rollback"} — CONSOLE_OS_APPLY=1 + host data plane
 *          executes (stage → squid -k parse → install → reconfigure/restart →
 *          verify, auto-rollback from backup-<ts>/); anything else returns the
 *          plan preview. Audit: url_filter.os-apply.exec|plan|failed and
 *          url_filter.os-rollback.exec|plan|failed, objectType url_filter_policy.
 */

import { route, z } from "@/lib/api/handler";
import { execUrlFilterApplyPlan, getUrlFilterOsStatus, rollbackUrlFilterOs } from "@/lib/url-filter/os-service";

export const dynamic = "force-dynamic";

const osActionSchema = z.object({
  action: z.enum(["apply", "rollback"]).default("apply"),
});

export const GET = route({ area: "url_filter" }, async ({ auth }) => {
  return { data: await getUrlFilterOsStatus(auth.tenantId) };
});

export const POST = route(
  { area: "url_filter", bodySchema: osActionSchema, section: "url_filter" },
  async ({ auth, body }) => {
    const gateOn = process.env.CONSOLE_OS_APPLY === "1";
    const outcome =
      body.action === "rollback"
        ? await rollbackUrlFilterOs(auth.tenantId, gateOn)
        : await execUrlFilterApplyPlan(auth.tenantId, gateOn);

    const verb = body.action === "rollback" ? "os-rollback" : "os-apply";
    const action = outcome.applied
      ? `url_filter.${verb}.exec`
      : outcome.refused
        ? `url_filter.${verb}.plan`
        : `url_filter.${verb}.failed`;

    return {
      data: outcome,
      audit: {
        action,
        objectType: "url_filter_policy",
        objectName: `${outcome.action}:${outcome.applied ? "ok" : outcome.refused ? "refused" : "failed"}`,
        after: { applied: outcome.applied, confHash: outcome.confHash, rolledBack: outcome.rolledBack, results: outcome.results },
      },
    };
  },
);
