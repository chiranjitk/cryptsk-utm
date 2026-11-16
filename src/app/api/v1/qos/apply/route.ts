/**
 * POST /api/v1/qos/apply — converge the kernel tc shaper onto the console
 * QoS policies (HTB root + fq_codel leaves + u32 classification).
 *
 * Gate model (identical to interfaces/firewall/ha):
 *   • CONSOLE_OS_APPLY=1 and data plane in host mode → execute;
 *   • otherwise → plan preview only (tc command sequence attached).
 *
 * Red lines enforced here:
 *   • protected ifaces (CONSOLE_PROTECTED_IFACES, default ens32) and lo are
 *     hard-refused by hardQosRefusal() — shaping a protected uplink is never
 *     attempted;
 *   • every step passes the tc command whitelist (qosStepGuarded);
 *   • snapshot-first per iface; failed install/verify auto-rolls back by
 *     re-attaching the pre-apply root qdisc from the captured snapshot.
 */

import { route } from "@/lib/api/handler";
import { applyQosToOs } from "@/lib/qos/os-service";

export const dynamic = "force-dynamic";

export const POST = route({ area: "qos", section: "qos" }, async ({ auth }) => {
  const gateOn = process.env.CONSOLE_OS_APPLY === "1";
  const outcome = await applyQosToOs(auth.tenantId, gateOn);
  return {
    data: outcome,
    audit: {
      action: outcome.applied
        ? "qos.os-apply.exec"
        : outcome.refused
          ? "qos.os-apply.plan"
          : "qos.os-apply.failed",
      objectType: "qos_policy",
      objectName: "qos",
      after: { applied: outcome.applied, confHash: outcome.confHash, rolledBack: outcome.rolledBack, results: outcome.results },
    },
  };
});
