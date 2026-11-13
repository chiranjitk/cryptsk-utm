import { describe, it, expect } from "vitest";
import {
  validateRouteMutation,
  ipInCidr,
  hardRouteIssues,
  conflictRouteIssues,
  type RouteRuleView,
} from "@/lib/network/route-rules";

const row = (over: Partial<RouteRuleView> = {}): RouteRuleView => ({
  id: 2,
  destinationCidr: "10.20.0.0/16",
  gateway: "192.168.10.254",
  interfaceName: "ens34",
  distance: 1,
  blackhole: false,
  enabled: true,
  ...over,
});

describe("ipInCidr", () => {
  it("matches inside the prefix", () => {
    expect(ipInCidr("10.20.5.9", "10.20.0.0/16")).toBe(true);
  });
  it("rejects outside the prefix", () => {
    expect(ipInCidr("10.21.0.1", "10.20.0.0/16")).toBe(false);
  });
  it("handles /0 and /32", () => {
    expect(ipInCidr("1.2.3.4", "0.0.0.0/0")).toBe(true);
    expect(ipInCidr("1.2.3.4", "1.2.3.4/32")).toBe(true);
    expect(ipInCidr("1.2.3.5", "1.2.3.4/32")).toBe(false);
  });
  it("rejects garbage", () => {
    expect(ipInCidr("not-an-ip", "10.0.0.0/8")).toBe(false);
    expect(ipInCidr("10.0.0.1", "bogus")).toBe(false);
  });
});

describe("validateRouteMutation — hard invalids", () => {
  it("BR-ROUTE-BLACKHOLE-GW rejects blackhole with gateway", () => {
    const issues = validateRouteMutation(row({ blackhole: true }), []);
    expect(hardRouteIssues(issues).map((i) => i.code)).toContain("BR-ROUTE-BLACKHOLE-GW");
  });

  it("BR-ROUTE-SELF-GW rejects a recursive next-hop inside the destination", () => {
    const issues = validateRouteMutation(row({ gateway: "10.20.44.1" }), []);
    expect(hardRouteIssues(issues).map((i) => i.code)).toContain("BR-ROUTE-SELF-GW");
  });

  it("BR-ROUTE-SELF-GW allows /32 host routes to their own address", () => {
    const issues = validateRouteMutation(row({ destinationCidr: "10.20.44.1/32", gateway: "10.20.44.1" }), []);
    expect(hardRouteIssues(issues)).toHaveLength(0);
  });

  it("accepts a normal gateway outside the destination", () => {
    const issues = validateRouteMutation(row(), []);
    expect(hardRouteIssues(issues)).toHaveLength(0);
    expect(conflictRouteIssues(issues)).toHaveLength(0);
  });
});

describe("validateRouteMutation — conflicts (409 + force)", () => {
  const sibling = row({ id: 1, name: "existing" });

  it("BR-ROUTE-DUP on an exact duplicate (all match fields equal)", () => {
    const issues = validateRouteMutation(row({ id: 2 }), [sibling]);
    expect(conflictRouteIssues(issues).map((i) => i.code)).toContain("BR-ROUTE-DUP");
  });

  it("different distance is NOT a duplicate (floating route)", () => {
    const issues = validateRouteMutation(row({ id: 2, distance: 5 }), [sibling]);
    expect(conflictRouteIssues(issues)).toHaveLength(0);
  });

  it("different gateway at the same distance is NOT a duplicate (ECMP info)", () => {
    const issues = validateRouteMutation(row({ id: 2, gateway: "192.168.10.253" }), [sibling]);
    expect(conflictRouteIssues(issues)).toHaveLength(0);
    expect(issues.find((i) => i.code === "BR-ROUTE-ECMP")).toBeDefined();
  });

  it("excludeId lets a row save against itself", () => {
    const issues = validateRouteMutation(row({ id: 1 }), [sibling], { excludeId: 1 });
    expect(conflictRouteIssues(issues)).toHaveLength(0);
  });

  it("BR-ROUTE-DEFAULT-PRIMARY on 0.0.0.0/0 distance 1", () => {
    const issues = validateRouteMutation(row({ destinationCidr: "0.0.0.0/0", gateway: "103.244.7.217" }), []);
    expect(conflictRouteIssues(issues).map((i) => i.code)).toContain("BR-ROUTE-DEFAULT-PRIMARY");
  });

  it("0.0.0.0/0 with distance ≥ 2 is a legal floating default", () => {
    const issues = validateRouteMutation(row({ destinationCidr: "0.0.0.0/0", gateway: "103.244.7.217", distance: 5 }), []);
    expect(conflictRouteIssues(issues)).toHaveLength(0);
    expect(hardRouteIssues(issues)).toHaveLength(0);
  });
});
