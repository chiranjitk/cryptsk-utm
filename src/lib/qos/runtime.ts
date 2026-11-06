/**
 * QoS engine runtime (M08 §5.4) — enabled policies with their rules for the
 * metrics generator. Mirrors loadDhcpRuntime style: a plain read, no internal
 * cache (the engine throttles reloads to 3 s). Only enabled policies are
 * returned — disabling a policy removes its classes on the next tick.
 */

import { db } from "@/lib/db";
import { parseJson } from "@/lib/json";

export interface QosRuleRuntime {
  id: number;
  name: string;
  priority: number; // 0 highest .. 7 lowest
  guaranteedKbps: number | null;
  maxKbps: number | null;
  hardLimit: boolean;
  matchApps: string[];
  matchUsers: string[];
  matchAddresses: string[];
}

export interface QosPolicyRuntime {
  id: number;
  name: string;
  bandwidthKbps: number;
  /** attached iface, or null = aggregate shaper across wan-role egress */
  ifaceName: string | null;
  /** ordered priority asc (0 first), ties by id asc (M08 §5.3) */
  rules: QosRuleRuntime[];
}

export interface QosRuntime {
  policies: QosPolicyRuntime[];
}

function isHardLimit(
  matchApps: string[],
  matchUsers: string[],
  matchAddresses: string[],
  guaranteedKbps: number | null,
  maxKbps: number | null,
): boolean {
  if (matchAddresses.length > 0) return false;
  if (guaranteedKbps != null || maxKbps == null) return false;
  const dims = (matchUsers.length > 0 ? 1 : 0) + (matchApps.length > 0 ? 1 : 0);
  return dims === 1;
}

export async function loadQosRuntime(tenantId: number): Promise<QosRuntime> {
  const [policies, rules] = await Promise.all([
    db.qosPolicy.findMany({
      where: { tenantId, enabled: true },
      orderBy: { id: "asc" },
      select: { id: true, name: true, bandwidthKbps: true, ifaceName: true },
    }),
    db.qosRule.findMany({
      where: { tenantId },
      orderBy: [{ priority: "asc" }, { id: "asc" }],
      select: {
        id: true,
        policyId: true,
        name: true,
        priority: true,
        guaranteedKbps: true,
        maxKbps: true,
        matchApps: true,
        matchUsers: true,
        matchAddresses: true,
      },
    }),
  ]);
  const byPolicy = new Map<number, QosRuleRuntime[]>();
  for (const r of rules) {
    const matchApps = parseJson<string[]>(r.matchApps, []).filter((a) => typeof a === "string");
    const matchUsers = parseJson<string[]>(r.matchUsers, []).filter((a) => typeof a === "string");
    const matchAddresses = parseJson<string[]>(r.matchAddresses, []).filter((a) => typeof a === "string");
    const dto: QosRuleRuntime = {
      id: r.id,
      name: r.name,
      priority: r.priority,
      guaranteedKbps: r.guaranteedKbps,
      maxKbps: r.maxKbps,
      hardLimit: isHardLimit(matchApps, matchUsers, matchAddresses, r.guaranteedKbps, r.maxKbps),
      matchApps,
      matchUsers,
      matchAddresses,
    };
    let bucket = byPolicy.get(r.policyId);
    if (!bucket) {
      bucket = [];
      byPolicy.set(r.policyId, bucket);
    }
    bucket.push(dto);
  }
  return {
    policies: policies.map((p) => ({
      id: p.id,
      name: p.name,
      bandwidthKbps: p.bandwidthKbps,
      ifaceName: p.ifaceName,
      rules: byPolicy.get(p.id) ?? [],
    })),
  };
}
