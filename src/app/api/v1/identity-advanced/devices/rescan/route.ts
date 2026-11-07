/**
 * Profiling rescan (M23, spec 2.9) — SIMULATED endpoint-profiler sweep (the
 * appliance runs the real probe). Every "unknown" device gets a deterministic
 * type from its OUI/vendor fnv-1a hash; some devices get an osGuess refresh;
 * lastSeen is refreshed fleet-wide. Audits `nac.rescan`.
 */

import { route } from "@/lib/api/handler";
import { db } from "@/lib/db";
import { fnv1a } from "@/app/api/v1/identity-advanced/_lib/server";

export const dynamic = "force-dynamic";

const PROFILER_TYPES = ["printer", "phone", "camera", "workstation", "mobile", "iot"] as const;
type ProfilerType = (typeof PROFILER_TYPES)[number];

const OS_GUESSES: Record<ProfilerType, string> = {
  printer: "embedded print server",
  phone: "IP phone firmware",
  camera: "camera firmware 10.x",
  workstation: "Windows 11 Pro",
  mobile: "Android 14",
  iot: "embedded Linux",
};

export const POST = route({ area: "identity", section: "identity" }, async ({ auth }) => {
  const devices = await db.nacDevice.findMany({ where: { tenantId: auth.tenantId } });
  const unknown = devices.filter((d) => d.deviceType === "unknown");

  let typed = 0;
  for (const device of unknown) {
    // OUI = first 3 octets of the MAC; hash OUI + vendor for a stable type.
    const oui = device.macAddress.split(":").slice(0, 3).join(":").toUpperCase();
    const hash = fnv1a(`${oui}|${device.vendor ?? ""}`);
    const type: ProfilerType = PROFILER_TYPES[hash % PROFILER_TYPES.length];
    const osGuess = hash % 2 === 0 ? OS_GUESSES[type] : device.osGuess;
    await db.nacDevice.update({
      where: { id: device.id },
      data: { deviceType: type, osGuess, lastSeen: new Date() },
    });
    typed += 1;
  }

  // The sweep also refreshes reachability for every known device.
  const refreshed = await db.nacDevice.updateMany({
    where: { tenantId: auth.tenantId },
    data: { lastSeen: new Date() },
  });

  return {
    data: { rescanned: refreshed.count, typed },
    audit: { action: "nac.rescan", objectType: "nac_device" },
  };
});
