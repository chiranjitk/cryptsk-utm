/**
 * GET /api/v1/logs/os-status — live rsyslog forwarding state per syslog
 * target: expected render hash vs live managed-file hash, unit state, socket
 * reachability (informational), state-file info, tool availability and
 * data-plane mode. Read-only, area `log_forwarding`.
 */

import { route } from "@/lib/api/handler";
import { readRsyslogOsStatus } from "@/lib/logs/os-service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "log_forwarding" }, async ({ auth }) => {
  return { data: await readRsyslogOsStatus(auth.tenantId) };
});
