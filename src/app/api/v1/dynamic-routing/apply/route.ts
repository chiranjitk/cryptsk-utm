/**
 * POST /api/v1/dynamic-routing/apply — converge /etc/frr/frr.conf +
 * /etc/frr/daemons onto the console routing config (validate-first with
 * `vtysh -C -f`, backup, auto-restore on failure).
 *
 * Gate model (identical to HA / logs / qos):
 *   • CONSOLE_OS_APPLY=1 AND data plane in host mode → execute the plan;
 *   • otherwise → plan preview only (no exec, no OS change).
 *
 * Red lines enforced here (via buildDrApplyPlan + drStepGuarded):
 *   • `vtysh -C -f <stage>` must parse BEFORE the live conf moves;
 *   • a daemon-set change restarts frr (reload cannot start daemons);
 *   • failed reload/restart/verify → both timestamped backups are restored
 *     and frr restarted again (auto-rollback);
 *   • the whitelist never allows vtysh configure/write — the conf is
 *     installed as a file (`install -m 0640 -o frr -g frr …`).
 */

import { route } from "@/lib/api/handler";
import { applyDynamicRoutingToOs } from "@/lib/dynamic-routing/os-service";

export const dynamic = "force-dynamic";

export const POST = route({ area: "dynamic_routing", section: "dynamic_routing" }, async ({ auth }) => {
  const gateOn = process.env.CONSOLE_OS_APPLY === "1";
  const outcome = await applyDynamicRoutingToOs(auth.tenantId, gateOn);
  return {
    data: outcome,
    audit: {
      action: outcome.applied
        ? "dynamic_routing.os-apply.exec"
        : outcome.refused
          ? "dynamic_routing.os-apply.plan"
          : "dynamic_routing.os-apply.failed",
      objectType: "bgp_settings",
      objectName: "dynamic-routing",
      after: {
        applied: outcome.applied,
        skipped: outcome.skipped,
        confHash: outcome.confHash,
        daemonsChanged: outcome.daemonsChanged,
        rolledBack: outcome.rolledBack,
        results: outcome.results,
      },
    },
  };
});
