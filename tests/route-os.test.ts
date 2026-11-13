import { describe, it, expect } from "vitest";
import {
  parseKernelRoutes,
  kernelRouteState,
  buildRouteApplyPlan,
  buildRouteDeletePlan,
  type KernelRoute,
} from "@/lib/network/route-os";
import type { RouteRuleView } from "@/lib/network/route-rules";

const view = (over: Partial<RouteRuleView> = {}): RouteRuleView => ({
  id: 1,
  destinationCidr: "10.99.99.0/24",
  gateway: "20.20.30.254",
  interfaceName: "ens34",
  distance: 5,
  blackhole: false,
  enabled: true,
  ...over,
});

const SAMPLE = `default via 103.244.7.217 dev ens32 onlink
20.20.30.0/24 dev ens34 proto kernel scope link src 20.20.30.1
103.244.7.216/29 dev ens32 proto kernel scope link src 103.244.7.219
10.99.99.0/24 via 20.20.30.254 dev ens34 metric 5
blackhole 10.88.0.0/16 metric 9
unreachable 10.77.0.0/16`;

describe("parseKernelRoutes", () => {
  it("parses via/dev/metric entries", () => {
    const k = parseKernelRoutes(SAMPLE);
    const hit = k.find((r) => r.dest === "10.99.99.0/24");
    expect(hit).toMatchObject({ via: "20.20.30.254", dev: "ens34", metric: 5, blackhole: false });
  });
  it("parses the default route with no metric as 0", () => {
    const k = parseKernelRoutes(SAMPLE);
    const def = k.find((r) => r.dest === "default");
    expect(def).toMatchObject({ via: "103.244.7.217", dev: "ens32", metric: 0 });
  });
  it("parses blackhole + unreachable as blackhole-type entries", () => {
    const k = parseKernelRoutes(SAMPLE);
    expect(k.find((r) => r.dest === "10.88.0.0/16")).toMatchObject({ blackhole: true, metric: 9, dev: null });
    expect(k.find((r) => r.dest === "10.77.0.0/16")?.blackhole).toBe(true);
  });
  it("handles empty output", () => {
    expect(parseKernelRoutes("")).toEqual([]);
  });
});

describe("kernelRouteState", () => {
  const kernel = parseKernelRoutes(SAMPLE) as KernelRoute[];

  it("in-kernel when via+dev+metric all match", () => {
    expect(kernelRouteState(view(), kernel)).toBe("in-kernel");
  });
  it("drifted when the dest exists with a different next-hop", () => {
    expect(kernelRouteState(view({ gateway: "20.20.30.1" }), kernel)).toBe("drifted");
  });
  it("drifted when only the metric differs", () => {
    expect(kernelRouteState(view({ distance: 6 }), kernel)).toBe("drifted");
  });
  it("missing when the dest is absent", () => {
    expect(kernelRouteState(view({ destinationCidr: "172.16.0.0/12" }), kernel)).toBe("missing");
  });
  it("disabled rows with no kernel residue report disabled", () => {
    expect(kernelRouteState(view({ enabled: false }), kernel.filter((k) => k.dest !== "10.99.99.0/24"))).toBe("disabled");
  });
  it("disabled rows with stale kernel entries report drifted", () => {
    expect(kernelRouteState(view({ enabled: false }), kernel)).toBe("drifted");
  });
  it("null kernel → null (honest unknown)", () => {
    expect(kernelRouteState(view(), null)).toBeNull();
  });
  it("blackhole rows match blackhole entries", () => {
    const bh = view({ destinationCidr: "10.88.0.0/16", blackhole: true, gateway: null, interfaceName: null, distance: 9 });
    expect(kernelRouteState(bh, kernel)).toBe("in-kernel");
  });
});

describe("buildRouteApplyPlan", () => {
  it("emits ip route replace with metric = distance", () => {
    const plan = buildRouteApplyPlan(view(), null);
    expect(plan.steps).toHaveLength(1);
    expect(plan.steps[0].cmd).toBe("ip route replace 10.99.99.0/24 via 20.20.30.254 dev ens34 metric 5");
  });

  it("never emits metric 0 — a static 0.0.0.0/0 can never shadow the primary default", () => {
    const plan = buildRouteApplyPlan(view({ destinationCidr: "0.0.0.0/0", distance: 1, gateway: "103.244.7.217", interfaceName: null }), null);
    expect(plan.steps[0].cmd).toBe("ip route replace 0.0.0.0/0 via 103.244.7.217 metric 1");
  });

  it("blackhole plans use the blackhole verb", () => {
    const plan = buildRouteApplyPlan(view({ blackhole: true, gateway: null, interfaceName: null, distance: 9, destinationCidr: "10.88.0.0/16" }), null);
    expect(plan.steps[0].cmd).toBe("ip route replace blackhole 10.88.0.0/16 metric 9");
  });

  it("interface-only plans install dev routes", () => {
    const plan = buildRouteApplyPlan(view({ gateway: null }), null);
    expect(plan.steps[0].cmd).toBe("ip route replace 10.99.99.0/24 dev ens34 metric 5");
  });

  it("removes drifted entries but is SIBLING-AWARE (ECMP member survives)", () => {
    const kernel = parseKernelRoutes(`
10.99.99.0/24 via 20.20.30.1 dev ens34 metric 5
10.99.99.0/24 via 20.20.30.9 dev ens34 metric 5
10.99.99.0/24 via 20.20.30.254 dev ens34 metric 5`) as KernelRoute[];
    const ecmpSibling: RouteRuleView = { id: 2, destinationCidr: "10.99.99.0/24", gateway: "20.20.30.9", interfaceName: "ens34", distance: 5, blackhole: false, enabled: true };
    const plan = buildRouteApplyPlan(view(), kernel, [view(), ecmpSibling]);
    // stale: .1 entry (not owned by anyone); kept: .9 (owned by the sibling); install: .254
    expect(plan.steps.map((s) => s.cmd)).toEqual([
      "ip route del 10.99.99.0/24 via 20.20.30.1 dev ens34 metric 5",
      "ip route replace 10.99.99.0/24 via 20.20.30.254 dev ens34 metric 5",
    ]);
  });

  it("disabled rows only withdraw their own entries", () => {
    const kernel = parseKernelRoutes(`
10.99.99.0/24 via 20.20.30.254 dev ens34 metric 5
10.99.99.0/24 via 20.20.30.1 dev ens34 metric 5`) as KernelRoute[];
    const plan = buildRouteApplyPlan(view({ enabled: false }), kernel, [view({ enabled: false })]);
    expect(plan.steps.map((s) => s.cmd)).toEqual(["ip route del 10.99.99.0/24 via 20.20.30.254 dev ens34 metric 5"]);
  });

  it("inert rows (no gw, no dev) produce no steps", () => {
    const plan = buildRouteApplyPlan(view({ gateway: null, interfaceName: null }), null);
    expect(plan.steps).toHaveLength(0);
  });
});

describe("buildRouteDeletePlan", () => {
  it("withdraws exactly the entries the row owns", () => {
    const kernel = parseKernelRoutes(`
10.99.99.0/24 via 20.20.30.254 dev ens34 metric 5
10.99.99.0/24 via 20.20.30.254 dev ens34 metric 6`) as KernelRoute[];
    const plan = buildRouteDeletePlan(view(), kernel);
    expect(plan.steps.map((s) => s.cmd)).toEqual(["ip route del 10.99.99.0/24 via 20.20.30.254 dev ens34 metric 5"]);
  });

  it("falls back to a best-effort del when the kernel is unreadable", () => {
    const plan = buildRouteDeletePlan(view(), null);
    expect(plan.steps.map((s) => s.cmd)).toEqual(["ip route del 10.99.99.0/24 via 20.20.30.254 dev ens34 metric 5"]);
  });
});
