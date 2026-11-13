/**
 * POST /api/v1/wan-policies/{id}/probe — force probe now (M02 §4 "Probe now"
 * button). Disabled policies are rejected (M02 §3 error table). Policies the
 * engine does not know (created after bootstrap) get a one-shot fallback
 * evaluation using the policy's OWN probe type/target/timeout (G1 fix) —
 * never the old hardcoded gateway TCP:53 check.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { getEngine } from "@/lib/engine";
import { runWanProbe } from "@/lib/network/wan-probe";
import { readInterfaces } from "@/lib/host/proc";
import { idParamSchema } from "@/lib/validators/network";
import { shapeWanPolicy } from "@/lib/network/shapes";

export const dynamic = "force-dynamic";

export const POST = route({ area: "network", section: "routing" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  const policy = await db.wanPolicy.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!policy) throw ApiError.notFound(`WAN policy ${id} not found`);
  if (!policy.enabled) throw ApiError.validation("Cannot probe a disabled policy");

  // REAL probe: tracked policies run an immediate engine probe (authoritative
  // one-shot, resets threshold runs); policies the engine has not picked up
  // yet get a real one-shot probe from the policy's own definition.
  let state = await getEngine().forceProbe(policy.interfaceName);
  let live: { state: string; latencyMs: number | null; detail: string | null } | undefined;
  if (state === null) {
    let ifaceIp: string | null = null;
    try {
      const real = await readInterfaces();
      const os = real.find((r) => r.name === policy.interfaceName);
      const primary = os?.ipv4[0] ?? null;
      ifaceIp = primary ? primary.split("/")[0] : null;
    } catch {
      // probe leaves via the main table
    }
    const outcome = await runWanProbe({
      ifaceName: policy.interfaceName,
      ifaceIp,
      probeType: (policy.probeType as "icmp" | "tcp" | "dns" | "http") ?? "icmp",
      probeTarget: policy.probeTarget,
      timeoutMs: policy.timeoutMs,
    });
    state = outcome.state;
    live = { state: outcome.state, latencyMs: outcome.latencyMs, detail: outcome.detail };
  } else {
    // engine probe — surface its telemetry from the live map
    const w = getEngine().wanStates.find((x) => x.iface === policy.interfaceName);
    if (w) live = { state: w.state, latencyMs: w.latencyMs ?? null, detail: w.detail ?? null };
  }

  const updated = await db.wanPolicy.update({ where: { id: policy.id }, data: { state } });
  return {
    data: shapeWanPolicy(updated, live),
    audit: {
      action: "wan.probe",
      objectType: "wan_policy",
      objectId: policy.id,
      objectName: policy.interfaceName,
    },
  };
});
