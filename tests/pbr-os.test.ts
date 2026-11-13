import { describe, it, expect } from "vitest";
import {
  buildPbrApplyPlan,
  buildPbrTeardownPlan,
  parseKernelPbrRules,
  pbrKernelState,
  PBR_PRIO_BASE,
  PBR_TABLE_BASE,
  type PbrRuleView,
} from "@/lib/network/pbr-os";

const rule = (over: Partial<PbrRuleView> = {}): PbrRuleView => ({
  id: 1,
  name: "test-pbr",
  position: 1,
  enabled: true,
  srcAddrIds: [],
  dstAddrIds: [],
  serviceIds: [],
  outgoingIface: "ens34",
  gateway: null,
  ...over,
});

describe("buildPbrApplyPlan", () => {
  it("installs a default dev route into the dedicated table", () => {
    const plan = buildPbrApplyPlan(rule(), [], []);
    expect(plan.configOnly).toBe(false);
    expect(plan.table).toBe(PBR_TABLE_BASE + 1);
    expect(plan.steps[0].cmd).toBe(`ip route replace default dev ens34 table ${PBR_TABLE_BASE + 1}`);
    expect(plan.steps[1].cmd).toBe(`ip rule add priority ${PBR_PRIO_BASE + 10} table ${PBR_TABLE_BASE + 1}`);
  });

  it("gateway + iface egress uses via … dev … onlink", () => {
    const plan = buildPbrApplyPlan(rule({ gateway: "20.20.30.254" }), [], []);
    expect(plan.steps[0].cmd).toBe(`ip route replace default via 20.20.30.254 dev ens34 onlink table ${PBR_TABLE_BASE + 1}`);
  });

  it("from/to selectors expand per CIDR pair", () => {
    const src = [
      { id: 1, cidr: "10.99.99.0/24" },
      { id: 2, cidr: "10.99.98.0/24" },
    ];
    const dst = [{ id: 3, cidr: "20.20.30.0/24" }];
    const plan = buildPbrApplyPlan(rule({ position: 3 }), src, dst);
    const ruleCmds = plan.steps.slice(1).map((s) => s.cmd);
    expect(ruleCmds).toEqual([
      `ip rule add priority ${PBR_PRIO_BASE + 30} from 10.99.99.0/24 to 20.20.30.0/24 table ${PBR_TABLE_BASE + 3}`,
      `ip rule add priority ${PBR_PRIO_BASE + 31} from 10.99.98.0/24 to 20.20.30.0/24 table ${PBR_TABLE_BASE + 3}`,
    ]);
  });

  it("service-matched rules are honest config-only (no kernel steps)", () => {
    const plan = buildPbrApplyPlan(rule({ serviceIds: [7] }), [{ id: 1, cidr: "10.0.0.0/8" }], []);
    expect(plan.configOnly).toBe(true);
    expect(plan.steps).toHaveLength(0);
    expect(plan.reason).toMatch(/fwmark/i);
  });

  it("disabled rules produce no kernel steps", () => {
    const plan = buildPbrApplyPlan(rule({ enabled: false }), [], []);
    expect(plan.table).toBeNull();
    expect(plan.steps).toHaveLength(0);
  });

  it("huge fan-outs are refused as config-only", () => {
    const src = Array.from({ length: 10 }, (_, i) => ({ id: i + 1, cidr: `10.0.${i}.0/24` }));
    const dst = Array.from({ length: 10 }, (_, i) => ({ id: 100 + i, cidr: `20.0.${i}.0/24` }));
    const plan = buildPbrApplyPlan(rule(), src, dst);
    expect(plan.configOnly).toBe(true);
  });
});

describe("buildPbrTeardownPlan", () => {
  it("drops priorities then flushes the table", () => {
    const plan = buildPbrTeardownPlan(rule({ position: 2 }), 1, 0);
    expect(plan.steps).toEqual([
      { cmd: `ip rule del priority ${PBR_PRIO_BASE + 20}`, summary: expect.any(String) },
      { cmd: `ip route flush table ${PBR_TABLE_BASE + 2}`, summary: expect.any(String) },
    ]);
  });
});

describe("parseKernelPbrRules + pbrKernelState", () => {
  const kernel = parseKernelPbrRules(`
0:      from all lookup local
220:    from all lookup 220
5010:   from 10.99.99.0/24 lookup 10001
32766:  from all lookup main
32767:  from all lookup default`);

  it("parses priorities/from/table", () => {
    expect(kernel).toHaveLength(5);
    expect(kernel[2]).toMatchObject({ priority: 5010, from: "10.99.99.0/24", table: 10001 });
  });

  it("in-kernel when the rule's table+priority window matches", () => {
    const r = rule({ position: 1 });
    expect(pbrKernelState(r, kernel)).toBe("in-kernel");
  });

  it("missing when no ip rule carries the table", () => {
    expect(pbrKernelState(rule({ position: 7 }), kernel)).toBe("missing");
  });

  it("config-only for service-matched rules", () => {
    expect(pbrKernelState(rule({ serviceIds: [5] }), kernel)).toBe("config-only");
  });

  it("disabled rules report disabled", () => {
    expect(pbrKernelState(rule({ enabled: false }), kernel)).toBe("disabled");
  });

  it("null kernel → null", () => {
    expect(pbrKernelState(rule(), null)).toBeNull();
  });
});
