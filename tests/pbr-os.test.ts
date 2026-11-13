import { describe, it, expect } from "vitest";
import {
  buildPbrApplyPlan,
  buildPbrCombos,
  buildPbrTeardownPlan,
  parseEgressGateway,
  parseFirstDefaultGateway,
  parseKernelPbrRules,
  pbrCombosHaveCatchAll,
  pbrHealthRegressed,
  pbrKernelState,
  PBR_PRIO_BASE,
  PBR_TABLE_BASE,
  type PbrRuleView,
  type PbrWanHealth,
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

const health = (over: Partial<PbrWanHealth>): PbrWanHealth => ({
  gateway: "103.244.7.217",
  gatewayOk: true,
  internetOk: true,
  checkedAt: "2026-11-14T00:00:00.000Z",
  ...over,
});

describe("buildPbrApplyPlan — match-all guard", () => {
  it("match-all rules are config-only without explicit confirmation", () => {
    const plan = buildPbrApplyPlan(rule(), [], []);
    expect(plan.configOnly).toBe(true);
    expect(plan.table).toBeNull();
    expect(plan.steps).toHaveLength(0);
    expect(plan.reason).toMatch(/match-all/i);
    expect(plan.reason).toMatch(/confirmation/i);
  });

  it("confirmed match-all + resolved next-hop installs a via-route policy", () => {
    const plan = buildPbrApplyPlan(rule(), [], [], [], {
      confirmMatchAll: true,
      egressGateway: "20.20.30.254",
      egressDev: "ens34",
    });
    expect(plan.configOnly).toBe(false);
    expect(plan.table).toBe(PBR_TABLE_BASE + 1);
    expect(plan.steps[0].cmd).toBe(`ip route replace default via 20.20.30.254 dev ens34 onlink metric 1 table ${PBR_TABLE_BASE + 1}`);
    expect(plan.steps[1].cmd).toBe(`ip rule add priority ${PBR_PRIO_BASE + 10} table ${PBR_TABLE_BASE + 1}`);
    expect(plan.reason).toMatch(/auto-resolved/);
  });

  it("confirmed match-all without a resolvable next-hop stays config-only (device-route blackhole guard)", () => {
    const plan = buildPbrApplyPlan(rule(), [], [], [], { confirmMatchAll: true });
    expect(plan.configOnly).toBe(true);
    expect(plan.reason).toMatch(/no resolvable next-hop/i);
    expect(plan.reason).toMatch(/blackhole/i);
  });
});

describe("buildPbrApplyPlan — iface-only egress next-hop resolution", () => {
  it("iface-only scoped rules install the auto-resolved via-route (never a device-only default)", () => {
    const src = [{ id: 5, cidr: "192.168.20.0/24" }];
    const plan = buildPbrApplyPlan(rule({ srcAddrIds: [5] }), src, [], [], {
      egressGateway: "103.244.7.217",
      egressDev: "ens32",
    });
    expect(plan.configOnly).toBe(false);
    expect(plan.steps[0].cmd).toBe(`ip route replace default via 103.244.7.217 dev ens34 onlink metric 1 table ${PBR_TABLE_BASE + 1}`);
    expect(plan.steps[1].cmd).toBe(`ip rule add priority ${PBR_PRIO_BASE + 10} from 192.168.20.0/24 table ${PBR_TABLE_BASE + 1}`);
    expect(plan.reason).toMatch(/auto-resolved from ens34/);
  });

  it("iface-only scoped rules without a resolvable next-hop stay config-only", () => {
    const src = [{ id: 5, cidr: "192.168.20.0/24" }];
    const plan = buildPbrApplyPlan(rule({ srcAddrIds: [5] }), src, []);
    expect(plan.configOnly).toBe(true);
    expect(plan.reason).toMatch(/no resolvable next-hop/i);
  });

  it("an explicit gateway always wins over the resolved next-hop", () => {
    const plan = buildPbrApplyPlan(rule({ srcAddrIds: [5], gateway: "10.9.9.1" }), [{ id: 5, cidr: "192.168.20.0/24" }], []);
    expect(plan.steps[0].cmd).toBe(`ip route replace default via 10.9.9.1 dev ens34 onlink metric 1 table ${PBR_TABLE_BASE + 1}`);
  });

  it("gateway + iface egress uses via … dev … onlink", () => {
    const plan = buildPbrApplyPlan(rule({ gateway: "20.20.30.254" }), [], [], [], { confirmMatchAll: true });
    expect(plan.steps[0].cmd).toBe(`ip route replace default via 20.20.30.254 dev ens34 onlink metric 1 table ${PBR_TABLE_BASE + 1}`);
  });
});

describe("buildPbrApplyPlan — selectors and fan-out", () => {
  it("from/to selectors expand per CIDR pair", () => {
    const src = [
      { id: 1, cidr: "10.99.99.0/24" },
      { id: 2, cidr: "10.99.98.0/24" },
    ];
    const dst = [{ id: 3, cidr: "20.20.30.0/24" }];
    const plan = buildPbrApplyPlan(rule({ position: 3, outgoingIface: null, gateway: "20.20.30.254" }), src, dst);
    const ruleCmds = plan.steps.slice(1).map((s) => s.cmd);
    expect(ruleCmds).toEqual([
      `ip rule add priority ${PBR_PRIO_BASE + 30} from 10.99.99.0/24 to 20.20.30.0/24 table ${PBR_TABLE_BASE + 3}`,
      `ip rule add priority ${PBR_PRIO_BASE + 31} from 10.99.98.0/24 to 20.20.30.0/24 table ${PBR_TABLE_BASE + 3}`,
    ]);
  });

  it("service-matched rules with unresolved ids are honest config-only", () => {
    const plan = buildPbrApplyPlan(rule({ serviceIds: [7] }), [{ id: 1, cidr: "10.0.0.0/8" }], []);
    expect(plan.configOnly).toBe(true);
    expect(plan.steps).toHaveLength(0);
    expect(plan.reason).toMatch(/unresolved/i);
  });

  it("service-matched rules compile to ipproto/dport selectors (kernel enforcement)", () => {
    const plan = buildPbrApplyPlan(
      rule({ serviceIds: [7], outgoingIface: null, gateway: "20.20.30.254" }),
      [{ id: 1, cidr: "10.99.99.0/24" }],
      [],
      [
        { id: 7, cidr: null, protocol: "tcp", srcPorts: [], dstPorts: [{ lo: 443, hi: 443 }], expressible: true },
      ],
    );
    expect(plan.configOnly).toBe(false);
    expect(plan.steps).toHaveLength(2);
    expect(plan.steps[1].cmd).toBe(
      `ip rule add priority ${PBR_PRIO_BASE + 10} from 10.99.99.0/24 ipproto tcp dport 443 table ${PBR_TABLE_BASE + 1}`,
    );
  });

  it("port-range service selectors compile to dport lo-hi", () => {
    const plan = buildPbrApplyPlan(
      rule({ serviceIds: [8], outgoingIface: null, gateway: "20.20.30.254" }),
      [],
      [],
      [
        { id: 8, cidr: null, protocol: "udp", srcPorts: [{ lo: 5000, hi: 5100 }], dstPorts: [], expressible: true },
      ],
    );
    expect(plan.configOnly).toBe(false);
    expect(plan.steps[1].cmd).toBe(`ip rule add priority ${PBR_PRIO_BASE + 10} ipproto udp sport 5000-5100 table ${PBR_TABLE_BASE + 1}`);
  });

  it("malformed port tokens stay config-only", () => {
    const plan = buildPbrApplyPlan(
      rule({ serviceIds: [9] }),
      [],
      [],
      [{ id: 9, cidr: null, protocol: "tcp", srcPorts: [], dstPorts: [], expressible: false }],
    );
    expect(plan.configOnly).toBe(true);
    expect(plan.reason).toMatch(/not kernel-expressible/i);
  });

  it("cidr × service fan-out over the cap stays config-only", () => {
    const src = Array.from({ length: 5 }, (_, i) => ({ id: i + 1, cidr: `10.1.${i}.0/24` }));
    const svc = Array.from({ length: 20 }, (_, i) => ({
      id: 100 + i,
      cidr: null,
      protocol: "tcp" as const,
      srcPorts: [],
      dstPorts: [{ lo: 1000 + i, hi: 1000 + i }],
      expressible: true,
    }));
    const plan = buildPbrApplyPlan(rule({ outgoingIface: null, gateway: "20.20.30.254" }), src, [], svc);
    expect(plan.configOnly).toBe(true);
  });

  it("disabled rules produce no kernel steps", () => {
    const plan = buildPbrApplyPlan(rule({ enabled: false }), [], []);
    expect(plan.table).toBeNull();
    expect(plan.steps).toHaveLength(0);
  });

  it("huge fan-outs are refused as config-only", () => {
    const src = Array.from({ length: 10 }, (_, i) => ({ id: i + 1, cidr: `10.0.${i}.0/24` }));
    const dst = Array.from({ length: 10 }, (_, i) => ({ id: 100 + i, cidr: `20.0.${i}.0/24` }));
    const plan = buildPbrApplyPlan(rule({ outgoingIface: null, gateway: "20.20.30.254" }), src, dst);
    expect(plan.configOnly).toBe(true);
  });
});

describe("pbrCombosHaveCatchAll", () => {
  it("detects a from/to-less combo with any-protocol selector", () => {
    expect(pbrCombosHaveCatchAll([[null, null]], [{}])).toBe(true);
    expect(pbrCombosHaveCatchAll([[null, null]], [])).toBe(true);
  });

  it("scoped combos are not catch-all", () => {
    expect(pbrCombosHaveCatchAll([["10.0.0.0/8", null]], [{}])).toBe(false);
    expect(pbrCombosHaveCatchAll([[null, "20.0.0.0/8"]], [{}])).toBe(false);
    expect(pbrCombosHaveCatchAll([["10.0.0.0/8", "20.0.0.0/8"]], [{}])).toBe(false);
  });

  it("a protocol selector narrows a from/to-less combo (not full catch-all)", () => {
    expect(pbrCombosHaveCatchAll([[null, null]], [{ ipproto: "icmp" }])).toBe(false);
  });
});

describe("buildPbrCombos", () => {
  it("empty match sides mean all", () => {
    expect(buildPbrCombos([], [])).toEqual([[null, null]]);
    expect(buildPbrCombos(["10.0.0.0/8"], [])).toEqual([["10.0.0.0/8", null]]);
    expect(buildPbrCombos(["10.0.0.0/8"], ["20.0.0.0/8", "30.0.0.0/8"])).toEqual([
      ["10.0.0.0/8", "20.0.0.0/8"],
      ["10.0.0.0/8", "30.0.0.0/8"],
    ]);
  });
});

describe("parseEgressGateway + parseFirstDefaultGateway", () => {
  const routeShow = [
    "default via 103.244.7.217 dev ens32 onlink ",
    "default dev ens34 metric 1",
    "default via 192.168.20.1 dev ens35",
  ].join("\n");

  it("resolves the via for the matching dev", () => {
    expect(parseEgressGateway(routeShow, "ens32")).toEqual({ gateway: "103.244.7.217", dev: "ens32" });
    expect(parseEgressGateway(routeShow, "ens35")).toEqual({ gateway: "192.168.20.1", dev: "ens35" });
  });

  it("a device-only default surfaces as gateway null (not resolvable)", () => {
    expect(parseEgressGateway(routeShow, "ens34")).toEqual({ gateway: null, dev: "ens34" });
    expect(parseEgressGateway(routeShow, "ens99")).toEqual({ gateway: null, dev: null });
  });

  it("parseFirstDefaultGateway returns the first via across devices", () => {
    expect(parseFirstDefaultGateway(routeShow)).toBe("103.244.7.217");
    expect(parseFirstDefaultGateway("default dev ens32")).toBeNull();
    expect(parseFirstDefaultGateway("")).toBeNull();
  });
});

describe("pbrHealthRegressed — commit-confirm rollback decision", () => {
  it("no rollback when the baseline was already unhealthy", () => {
    const baseline = health({ gatewayOk: false, internetOk: false });
    const after = health({ gatewayOk: false, internetOk: false });
    expect(pbrHealthRegressed(baseline, after)).toBe(false);
  });

  it("no rollback when nothing regressed", () => {
    expect(pbrHealthRegressed(health({}), health({}))).toBe(false);
  });

  it("internet probe regression triggers rollback (device-route blackhole class)", () => {
    // gateway ARP still answers on-link, but everything beyond the /29 dies
    expect(pbrHealthRegressed(health({}), health({ internetOk: false }))).toBe(true);
  });

  it("gateway loss triggers rollback", () => {
    expect(pbrHealthRegressed(health({}), health({ gatewayOk: false, internetOk: false }))).toBe(true);
  });

  it("unknown post-apply probes (tool missing) do not churn", () => {
    expect(pbrHealthRegressed(health({}), health({ gatewayOk: null, internetOk: null }))).toBe(false);
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

  it("config-only for service-matched rules (compiled plan reports it)", () => {
    // service rules whose ids resolve nowhere → plan.configOnly → state
    expect(pbrKernelState(rule({ serviceIds: [5] }), kernel, { configOnly: true })).toBe("config-only");
  });

  it("parses ipproto/sport/dport selectors + counter stats", () => {
    const rows = parseKernelPbrRules(
      `5010: from 10.99.99.0/24 ipproto tcp dport 443 lookup 10001\n5011: from all ipproto udp sport 5000-5100 lookup 10002 [hit_count 12 ref_count 1]`,
    );
    expect(rows[0]).toMatchObject({ priority: 5010, ipproto: "tcp", dport: "443", table: 10001 });
    expect(rows[1]).toMatchObject({ priority: 5011, ipproto: "udp", sport: "5000-5100", table: 10002 });
    expect(rows[1].stats).toContain("hit_count 12");
  });

  it("disabled rules report disabled", () => {
    expect(pbrKernelState(rule({ enabled: false }), kernel)).toBe("disabled");
  });

  it("null kernel → null", () => {
    expect(pbrKernelState(rule(), null)).toBeNull();
  });
});
