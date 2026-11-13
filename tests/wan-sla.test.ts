import { describe, it, expect } from "vitest";
import {
  computeWanSla,
  pushWanSample,
  pushWanEvent,
  WAN_HISTORY_CAP,
  WAN_EVENTS_CAP,
  type WanProbeSample,
  type WanTransitionEvent,
} from "@/lib/network/wan-sla";

const s = (verdict: WanProbeSample["verdict"], latencyMs: number | null, ts = 1000): WanProbeSample => ({ ts, verdict, latencyMs });

describe("computeWanSla — window folding", () => {
  it("returns an honest zero window for empty/absent rings", () => {
    for (const input of [undefined, null, []]) {
      const st = computeWanSla(input);
      expect(st).toEqual({
        samples: 0,
        lastTs: null,
        avgLatencyMs: null,
        jitterMs: null,
        lossPct: 0,
        upCount: 0,
        degradedCount: 0,
        downCount: 0,
      });
    }
  });

  it("averages latency across up + degraded probes", () => {
    const st = computeWanSla([s("up", 10), s("up", 20), s("degraded", 30)]);
    expect(st.samples).toBe(3);
    expect(st.avgLatencyMs).toBe(20);
    expect(st.upCount).toBe(2);
    expect(st.degradedCount).toBe(1);
    expect(st.downCount).toBe(0);
    expect(st.lossPct).toBe(0);
    expect(st.lastTs).toBe(1000);
  });

  it("computes jitter as mean |Δ| of consecutive answered probes", () => {
    const st = computeWanSla([s("up", 10), s("up", 30), s("up", 20)]);
    // |30-10| + |20-30| = 20+10 = 30 over 2 gaps → 15
    expect(st.jitterMs).toBe(15);
  });

  it("jitter is null with fewer than 2 answered probes", () => {
    expect(computeWanSla([s("up", 10)]).jitterMs).toBeNull();
    expect(computeWanSla([s("down", null)]).jitterMs).toBeNull();
  });

  it("counts loss over DEFINED verdicts only", () => {
    const st = computeWanSla([s("up", 10), s("down", null), s("down", null), s("degraded", 40)]);
    expect(st.samples).toBe(4);
    expect(st.downCount).toBe(2);
    expect(st.lossPct).toBe(50);
    // unanswered probes contribute no latency
    expect(st.avgLatencyMs).toBe(25);
  });

  it("a fully dead link reports 100% loss with null latency", () => {
    const st = computeWanSla([s("down", null), s("down", null)]);
    expect(st.lossPct).toBe(100);
    expect(st.avgLatencyMs).toBeNull();
  });

  it("ignores unknown verdicts (probe tool/target errors) — they poison SLA", () => {
    const st = computeWanSla([s("up", 10), { ts: 2, verdict: "unknown" as never, latencyMs: null }]);
    expect(st.samples).toBe(1);
    expect(st.lossPct).toBe(0);
  });
});

describe("pushWanSample — bounded ring", () => {
  it("caps the ring at WAN_HISTORY_CAP and keeps the NEWEST samples", () => {
    let ring: WanProbeSample[] = [];
    for (let i = 0; i < WAN_HISTORY_CAP + 25; i++) {
      ring = pushWanSample(ring, s("up", i, i));
    }
    expect(ring).toHaveLength(WAN_HISTORY_CAP);
    expect(ring[0].ts).toBe(25); // oldest kept is cap-25 offset
    expect(ring[ring.length - 1].ts).toBe(WAN_HISTORY_CAP + 24);
  });

  it("does not mutate the input ring", () => {
    const ring = [s("up", 1)];
    const next = pushWanSample(ring, s("down", null));
    expect(ring).toHaveLength(1);
    expect(next).toHaveLength(2);
  });
});

describe("pushWanEvent — newest-first event log", () => {
  const e = (ts: number, iface = "ens32", from = "up", to = "down"): WanTransitionEvent => ({ ts, iface, from, to, latencyMs: null });

  it("prepends and caps at WAN_EVENTS_CAP", () => {
    let ring: WanTransitionEvent[] = [];
    for (let i = 0; i < WAN_EVENTS_CAP + 10; i++) ring = pushWanEvent(ring, e(i));
    expect(ring).toHaveLength(WAN_EVENTS_CAP);
    expect(ring[0].ts).toBe(WAN_EVENTS_CAP + 9); // newest first
    expect(ring[ring.length - 1].ts).toBe(10);
  });

  it("keeps full transition context (from → to, iface, latency)", () => {
    const ring = pushWanEvent([], { ts: 1, iface: "ens34", from: "up", to: "down", latencyMs: null });
    expect(ring[0]).toMatchObject({ iface: "ens34", from: "up", to: "down" });
  });
});
