/**
 * /api/v1/waf/os — the GUI↔nginx(+ModSecurity 3 / OWASP CRS) integration
 * endpoint (M17 §2.4, mirrors /api/v1/ha/apply + /api/v1/ips/os):
 *
 * GET   — live OS status: availability (nginx + modsecurity module), data
 *         plane mode, gate, unit state, managed files (+ hashes), listener
 *         probe, drift (in-sync/managed-by-console/reasons), CRS layout,
 *         last apply state and the per-vhost render preview (policy summary,
 *         exclusions, renderer warnings).
 *
 * POST  — { action }:
 *           "apply"    — backup → stage conf.d/utm-waf.conf + /etc/nginx/
 *                        utm-waf/<id>*.conf + PEM material → `nginx -t`
 *                        → systemctl start|reload nginx → verify (auto-restore
 *                        on validate/activate failure). Gated by
 *                        CONSOLE_OS_APPLY=1 + host data plane; otherwise the
 *                        exact plan is returned as a preview.
 *           "rollback" — restore the newest /var/lib/console/waf/backup-<ts>/
 *                        and revalidate + reload.
 */

import { route } from "@/lib/api/handler";
import { z } from "zod";
import {
  applyWafOs,
  getWafOsStatus,
  rollbackWafOs,
  type WafApplyOutcome,
  type WafRollbackResult,
} from "@/lib/waf/os-service";

export const dynamic = "force-dynamic";

const bodySchema = z.object({
  action: z.enum(["apply", "rollback"]),
});

export const GET = route({ area: "waf" }, async ({ auth }) => {
  return { data: await getWafOsStatus(auth.tenantId) };
});

type WafPostResult = WafApplyOutcome | WafRollbackResult;

export const POST = route<z.infer<typeof bodySchema>, undefined, WafPostResult>(
  { area: "waf", bodySchema, section: "waf" },
  async ({ auth, body }) => {
  switch (body.action) {
    case "apply": {
      const outcome = await applyWafOs(auth.tenantId);
      const auditAction = outcome.applied
        ? "waf.os-apply.exec"
        : outcome.gate === "off" || outcome.refused
          ? "waf.os-apply.plan"
          : "waf.os-apply.failed";
      return {
        data: outcome,
        audit: {
          action: auditAction,
          objectType: "waf_vhost",
          objectName: outcome.plan.managedVhostIds.length > 0 ? `vhosts=${outcome.plan.managedVhostIds.join(",")}` : "empty",
          result: outcome.applied ? "success" : outcome.gate === "off" ? undefined : "failure",
        },
      };
    }
    case "rollback": {
      const r = await rollbackWafOs();
      return {
        data: r,
        audit: {
          action: "waf.os-rollback",
          objectType: "waf_vhost",
          objectName: r.backupDir ?? undefined,
          result: r.rolledBack ? "success" : "failure",
        },
      };
    }
  }
});
