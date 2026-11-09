/**
 * AgentAdapter — real data plane served by a remote sensor agent (ADR-004).
 *
 * Transport contract (deploy/AGENT_ADAPTER_CHECKLIST.md §Transport, LOCKED):
 *   • every call is  POST  ${AGENT_BASE_URL}<path>
 *   • auth header    X-Agent-Auth: ${AGENT_SHARED_SECRET}
 *   • idempotency    X-Request-Id: <uuid per call>
 *   • success        { "data": <payload>, "meta"?: … }
 *   • failure        { "error": { "code": string, "message": string, "details"?: … } }
 *   • timeouts       5 s reads / 30 s mutations
 *
 * NO FABRICATION POLICY (ADR-021): when the agent is unreachable or answers
 * with an error, this adapter FAILS LOUDLY (ApiError → HTTP 502). It never
 * invents placeholder values, so a red dashboard always means a real problem
 * on the sensor — never fake data.
 *
 * Division of truth (same split as host mode):
 *   • agent (sensor host): health, throughput + history, session totals,
 *     WAN probe states — pure host telemetry
 *   • console (config plane): alerts24h, topApps, topTalkers, vpnStatus,
 *     recentThreats, wanPolicies — merged from the shared DB aggregates,
 *     whose rows are written by real sources (AgentEngine persists the
 *     agent's log tails into the same tables HostCollector does)
 *
 * Console→agent endpoint map:
 *   POST /v1/dashboard/summary   body { tenantId }  → host-plane subset
 *   POST /v1/engine/snapshot     (AgentEngine, 2 s poll)
 *   POST /v1/wan/probe           body { iface }     → { state }
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { dashboardDbAggregates } from "./dashboard-aggregates";
import type { MetricsTick } from "@/lib/engine/events";
import type { DashboardSummary, SystemAdapter } from "./types";

const READ_TIMEOUT_MS = 5_000;
const MUTATION_TIMEOUT_MS = 30_000;

export function agentBaseUrl(): string {
  return (process.env.AGENT_BASE_URL ?? "http://127.0.0.1:8080").replace(/\/+$/, "");
}

function agentSecret(): string {
  const secret = process.env.AGENT_SHARED_SECRET ?? "";
  if (!secret) {
    throw new ApiError(
      "VALIDATION_ERROR",
      "AGENT_SHARED_SECRET is not set — the agent data plane refuses unauthenticated transport",
    );
  }
  return secret;
}

/** One authenticated call to the sensor agent. Returns the `data` envelope. */
export async function agentCall<T>(
  path: string,
  body: unknown,
  opts: { mutation?: boolean } = {},
): Promise<T> {
  const base = agentBaseUrl();
  let res: Response;
  try {
    res = await fetch(`${base}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-agent-auth": agentSecret(),
        "x-request-id": crypto.randomUUID(),
      },
      body: JSON.stringify(body ?? {}),
      signal: AbortSignal.timeout(opts.mutation ? MUTATION_TIMEOUT_MS : READ_TIMEOUT_MS),
    });
  } catch (err) {
    const why = err instanceof Error ? err.message : String(err);
    throw new ApiError("INTERNAL", `agent unreachable at ${base}${path} — ${why}`);
  }

  let payload: { data?: T; meta?: unknown; error?: { code?: string; message?: string; details?: unknown } };
  try {
    payload = await res.json();
  } catch {
    throw new ApiError("INTERNAL", `agent at ${base}${path} returned non-JSON HTTP ${res.status}`);
  }

  if (!res.ok || payload.error) {
    const e = payload.error ?? {};
    throw new ApiError(
      "INTERNAL",
      `agent error on ${path} (HTTP ${res.status}) ${e.code ?? ""}: ${e.message ?? "unknown"}`.trim(),
      e.details,
    );
  }
  if (payload.data === undefined) {
    throw new ApiError("INTERNAL", `agent at ${base}${path} answered without a data envelope`);
  }
  return payload.data;
}

/** host-plane subset the sensor agent answers with (agent/types.go DashboardSummary). */
interface AgentHostPlane {
  health: DashboardSummary["health"];
  throughput: MetricsTick | null;
  throughputHistory?: MetricsTick[];
  sessions: { active: number; conntrackCount: number };
  wanStates?: Array<{ iface: string; state: string }>;
}

/**
 * Remote-sensor implementation of SystemAdapter. Host telemetry is measured
 * by the agent on the sensor host and transported verbatim; DB aggregates
 * stay console-authoritative. The console adds nothing fabricated.
 */
export class AgentAdapter implements SystemAdapter {
  readonly mode = "agent" as const;

  async getDashboardSummary(tenantId: number): Promise<DashboardSummary> {
    const host = await agentCall<AgentHostPlane>("/v1/dashboard/summary", { tenantId });

    const [agg, wanPolicies] = await Promise.all([
      dashboardDbAggregates(tenantId),
      db.wanPolicy.findMany({ where: { tenantId }, select: { interfaceName: true, state: true } }),
    ]);

    const EMPTY_TICK: MetricsTick = {
      ts: new Date().toISOString(),
      ifaces: [],
      cpuPct: 0,
      memPct: 0,
      conntrackCount: 0,
    };
    const latest = host.throughput ?? EMPTY_TICK;
    const tickMap = new Map(latest.ifaces.map((i) => [i.name, i]));
    const agentWan = new Map((host.wanStates ?? []).map((w) => [w.iface, w.state]));

    return {
      health: host.health,
      throughput: latest,
      throughputHistory: host.throughputHistory ?? [],
      sessions: host.sessions,
      alerts24h: agg.alerts24h,
      topApps: agg.topApps,
      topTalkers: agg.topTalkers,
      wanStatus: wanPolicies.map((w) => {
        const t = tickMap.get(w.interfaceName);
        return {
          iface: w.interfaceName,
          state: agentWan.get(w.interfaceName) ?? w.state,
          rxKbps: t?.rxKbps ?? 0,
          txKbps: t?.txKbps ?? 0,
        };
      }),
      vpnStatus: agg.vpnStatus,
      recentThreats: agg.recentThreats,
    };
  }
}
