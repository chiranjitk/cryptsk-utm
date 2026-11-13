/**
 * Multi-WAN SLA accounting (M02 §4 enterprise gap — spec L657 "Multi-WAN SLA
 * monitoring (latency, jitter, loss)").
 *
 * The engine records every REAL probe outcome in a bounded per-WAN ring;
 * `computeWanSla` folds that ring into the three numbers an operator needs
 * before trusting a link:
 *
 *   • avgLatencyMs — mean round-trip of answering probes (up + degraded)
 *   • jitterMs     — mean |Δ| between consecutive answering probes (RFC-ish
 *                    latency variation; a link that answers but flaps ±200 ms
 *                    is NOT a healthy failover target)
 *   • lossPct      — share of DEFINED verdicts that came back down ("unknown"
 *                    probes are tool/target errors and would poison the ratio)
 *
 * Pure module — unit tested, no OS or DB access.
 */

export interface WanProbeSample {
  /** epoch ms of the probe */
  ts: number;
  /** defined verdict of the probe (never "unknown" — those are not recorded) */
  verdict: "up" | "degraded" | "down";
  /** measured latency, null when the probe did not answer */
  latencyMs: number | null;
}

export interface WanSlaStats {
  /** samples folded into this window (defined verdicts only) */
  samples: number;
  /** epoch ms of the newest sample in the window (null = empty ring) */
  lastTs: number | null;
  avgLatencyMs: number | null;
  jitterMs: number | null;
  /** 0..100, one decimal */
  lossPct: number;
  upCount: number;
  degradedCount: number;
  downCount: number;
}

/** bounded per-WAN history (≈ last N probes ≈ 10 min at the default interval) */
export const WAN_HISTORY_CAP = 120;
/** engine-side failover event log cap */
export const WAN_EVENTS_CAP = 50;

export function pushWanSample(ring: WanProbeSample[], s: WanProbeSample): WanProbeSample[] {
  const next = [...ring, s];
  return next.length > WAN_HISTORY_CAP ? next.slice(next.length - WAN_HISTORY_CAP) : next;
}

export interface WanTransitionEvent {
  /** epoch ms of the transition */
  ts: number;
  iface: string;
  from: string;
  to: string;
  latencyMs: number | null;
}

export function pushWanEvent(ring: WanTransitionEvent[], e: WanTransitionEvent): WanTransitionEvent[] {
  const next = [e, ...ring];
  return next.length > WAN_EVENTS_CAP ? next.slice(0, WAN_EVENTS_CAP) : next;
}

const r1 = (n: number): number => Math.round(n * 10) / 10;

/**
 * Fold a probe ring into SLA stats. Never throws; an empty/absent ring yields
 * an honest zero-window result (samples 0, nulls everywhere).
 */
export function computeWanSla(samples: WanProbeSample[] | undefined | null): WanSlaStats {
  const defined = (samples ?? []).filter(
    (s) => s.verdict === "up" || s.verdict === "degraded" || s.verdict === "down",
  );
  const out: WanSlaStats = {
    samples: defined.length,
    lastTs: defined.length > 0 ? defined[defined.length - 1].ts : null,
    avgLatencyMs: null,
    jitterMs: null,
    lossPct: 0,
    upCount: 0,
    degradedCount: 0,
    downCount: 0,
  };
  if (defined.length === 0) return out;

  const answered: number[] = [];
  for (const s of defined) {
    if (s.verdict === "up") out.upCount++;
    else if (s.verdict === "degraded") out.degradedCount++;
    else out.downCount++;
    if (s.latencyMs != null) answered.push(s.latencyMs);
  }

  out.lossPct = r1((out.downCount / defined.length) * 100);
  if (answered.length > 0) {
    out.avgLatencyMs = r1(answered.reduce((a, b) => a + b, 0) / answered.length);
    if (answered.length >= 2) {
      let dev = 0;
      for (let i = 1; i < answered.length; i++) dev += Math.abs(answered[i] - answered[i - 1]);
      out.jitterMs = r1(dev / (answered.length - 1));
    }
  }
  return out;
}
