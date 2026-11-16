/**
 * POST /api/v1/logs/apply — converge /etc/rsyslog.d/99-utm-console.conf onto
 * the console syslog targets (one omfwd action per enabled target behind a
 * severity gate).
 *
 * Gate model (identical to qos/ha):
 *   • CONSOLE_OS_APPLY=1 and data plane in host mode → execute;
 *   • otherwise → plan preview only (rsyslog command sequence attached).
 *
 * Red lines enforced here:
 *   • loopback/localhost targets are hard-refused by hardRsyslogRefusal() —
 *     forwarding to ourselves would feed rsyslog its own output (self-loop);
 *   • every step passes the rsyslog command whitelist (rsyslogStepGuarded);
 *   • snapshot-first: the pre-apply managed file is copied into backup-<ts>/
 *     and auto-restored (with a restart) if any step after the install fails.
 */

import { route } from "@/lib/api/handler";
import { applyRsyslogToOs } from "@/lib/logs/os-service";

export const dynamic = "force-dynamic";

export const POST = route({ area: "log_forwarding", section: "system" }, async ({ auth }) => {
  const gateOn = process.env.CONSOLE_OS_APPLY === "1";
  const outcome = await applyRsyslogToOs(auth.tenantId, gateOn);
  return {
    data: outcome,
    audit: {
      action: outcome.applied
        ? "syslog.os-apply.exec"
        : outcome.refused
          ? "syslog.os-apply.plan"
          : "syslog.os-apply.failed",
      objectType: "syslog_target",
      objectName: "syslog",
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
