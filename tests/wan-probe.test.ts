import { describe, it, expect } from "vitest";
import { nextWanState, parseTcpTarget, type WanHysteresis } from "@/lib/network/wan-probe";

const start = (state: WanHysteresis["state"] = "unknown"): WanHysteresis => ({ state, failRun: 0, okRun: 0 });

describe("nextWanState — threshold hysteresis", () => {
  it("goes down only after failThreshold consecutive failures", () => {
    let s = start();
    s = nextWanState(s, "down", 3, 3); // fail 1
    expect(s.state).toBe("unknown");
    s = nextWanState(s, "down", 3, 3); // fail 2
    expect(s.state).toBe("unknown");
    s = nextWanState(s, "down", 3, 3); // fail 3
    expect(s.state).toBe("down");
    expect(s.failRun).toBe(3);
    expect(s.changed).toBe(true);
  });

  it("never flaps down→up on a single good probe", () => {
    let s = start("down");
    s = nextWanState(s, "up", 3, 3);
    expect(s.state).toBe("down");
    s = nextWanState(s, "up", 3, 3);
    expect(s.state).toBe("down");
    s = nextWanState(s, "up", 3, 3);
    expect(s.state).toBe("up");
  });

  it("a failure during recovery resets the ok run", () => {
    let s = start("down");
    s = nextWanState(s, "up", 3, 3);
    s = nextWanState(s, "up", 3, 3);
    s = nextWanState(s, "down", 3, 3); // blip
    expect(s.state).toBe("down");
    expect(s.okRun).toBe(0);
    expect(s.failRun).toBe(1);
    // one more failure completes the fail threshold → still down (already down)
    s = nextWanState(s, "down", 3, 3);
    s = nextWanState(s, "down", 3, 3);
    expect(s.state).toBe("down");
  });

  it("unknown stays unknown until a threshold is crossed", () => {
    let s = start();
    s = nextWanState(s, "up", 3, 2);
    expect(s.state).toBe("unknown"); // 1/2
    s = nextWanState(s, "up", 3, 2);
    expect(s.state).toBe("up"); // 2/2 → recovered
  });

  it("up↔degraded flips immediately (telemetry, not a routing decision)", () => {
    let s = start("up");
    s = nextWanState(s, "degraded", 3, 3);
    expect(s.state).toBe("degraded");
    s = nextWanState(s, "up", 3, 3);
    expect(s.state).toBe("up");
  });

  it("changed flag is false while hysteresis holds the previous state", () => {
    let s = start("up");
    const held = nextWanState(s, "down", 3, 3);
    expect(held.state).toBe("up");
    expect(held.changed).toBe(false);
    expect(held.failRun).toBe(1);
  });

  it("fail run resets after a success", () => {
    let s = start("up");
    s = nextWanState(s, "down", 3, 3);
    s = nextWanState(s, "down", 3, 3);
    s = nextWanState(s, "up", 3, 3); // success resets
    expect(s.failRun).toBe(0);
    s = nextWanState(s, "down", 3, 3);
    s = nextWanState(s, "down", 3, 3);
    expect(s.state).toBe("up"); // only 2 consecutive fails
    s = nextWanState(s, "down", 3, 3);
    expect(s.state).toBe("down"); // third consecutive fail
  });
});

describe("parseTcpTarget", () => {
  it("parses host:port", () => {
    expect(parseTcpTarget("1.1.1.1:443")).toEqual({ host: "1.1.1.1", port: 443 });
    expect(parseTcpTarget("gw.example.net:53")).toEqual({ host: "gw.example.net", port: 53 });
  });

  it("rejects malformed targets", () => {
    expect(parseTcpTarget("1.1.1.1")).toBeNull();
    expect(parseTcpTarget("1.1.1.1:")).toBeNull();
    expect(parseTcpTarget("1.1.1.1:0")).toBeNull();
    expect(parseTcpTarget("1.1.1.1:99999")).toBeNull();
    expect(parseTcpTarget("")).toBeNull();
  });
});
