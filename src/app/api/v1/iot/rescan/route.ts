/**
 * IoT profiling rescan (Phase 3 §3.6) — re-profiles every NAC device from the
 * curated OUI map + hostname/DHCP signals, recomputes risk scores and
 * onboards the newest DHCP leases that have no NAC device row yet as pending
 * devices (500-row cap). Audits `iot.rescan`. Guard area `nac` (audit fix
 * #11 — was `identity`; the IoT surface IS the NAC device table).
 */

import { route } from "@/lib/api/handler";
import { rescanProfile } from "@/lib/iot/service";

export const dynamic = "force-dynamic";

export const POST = route({ area: "nac" }, async ({ auth }) => {
  const summary = await rescanProfile(auth.tenantId);
  return {
    data: summary,
    audit: {
      action: "iot.rescan",
      objectType: "nac_device",
      objectName: `${summary.rescanned} re-profiled, ${summary.created} onboarded`,
    },
  };
});
