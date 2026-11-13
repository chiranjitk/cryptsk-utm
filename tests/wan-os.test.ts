import { describe, it, expect } from "vitest";
import {
  buildWanOsConvergePlan,
  buildWanOsTeardownPlan,
  wanStepGuarded,
  filterWanBandRules,
  parseRouteTableDump,
  parseMultipathNexthops,
  WAN_EGRESS_TABLE,
  WAN_TABLE_BASE,
  WAN_PRIO_BASE,
  type WanOsInput,
  type WanOsWanView,
} from "@/lib/network/wan-os";
import type { KernelPbrRule } from "@/lib/network/pbr-os";

const wan = (over: Partial<WanOsWanView> = {}): WanOsWanView => ({
  id: 2,
  iface: "ens34",
  ifaceIp: "20.20.30.1",
  ifaceCidr: "20.20.30.0/24",
  gateway: "20.20.30.254",
  mode: "failover",
  weight: 50,
  priority: 2,
  state: "up",
  enabled: true,
  ...over,
});

const input = (wans: WanOsWanView[], primaryIface: string | null = "ens32"): WanOsInput => ({ primaryIface, wans });

const rule = (priority: number, table: number | null, from: string | null = null): KernelPbrRule => ({
  priority,
  from,
  to: null,
  table,
  raw: `${priority}:\tfrom ${from ?? "all"} ${table ? `lookup ${table}` : ""}`,
});

describe("buildWanOsConvergePlan — primary protection (red line)", () => {
  it("never installs a per-WAN table or source rule for the default-route owner", () => {
    const primary = wan({ id: 1, iface: "ens32", ifaceIp: "103.244.7.219", ifaceCidr: "103.244.7.216/29", gateway: "103.244.7.217", priority: 1, state: "up" });
    const plan = buildWanOsConvergePlan(input([primary]), []);
    const perWan = plan.steps.filter((s) => /table 26\d/.test(s.cmd) || /ip rule/.test(s.cmd));
    expect(perWan).toHaveLength(0);
    // primary still appears as the egress decision in table 240
    expect(plan.activeEgress).toEqual({ iface: "ens32", style: "primary" });
    expect(plan.steps.at(-1)?.cmd).toBe(`ip route replace default via 103.244.7.217 dev ens32 src 103.244.7.219 metric 1 table ${WAN_EGRESS_TABLE}`);
  });

  it("keeps the main table out of every command", () => {
    const plan = buildWanOsConvergePlan(input([wan(), wan({ id: 3, iface: "ens35", gateway: "10.9.9.1", ifaceIp: "10.9.9.2", ifaceCidr: "10.9.9.0/24", state: "down" })]), null);
    for (const s of plan.steps) {
      expect(s.cmd).not.toMatch(/\btable (253|254|255|main|local)\b/);
    }
  });
});

describe("buildWanOsConvergePlan — secondary WAN source routing", () => {
  it("installs connected route + default + source rule for an up secondary WAN", () => {
    const plan = buildWanOsConvergePlan(input([wan()]), []);
    expect(plan.steps).toEqual([
      { cmd: `ip route replace 20.20.30.0/24 dev ens34 src 20.20.30.1 table ${WAN_TABLE_BASE}`, summary: expect.any(String) },
      { cmd: `ip route replace default via 20.20.30.254 dev ens34 src 20.20.30.1 metric 1 table ${WAN_TABLE_BASE}`, summary: expect.any(String) },
      { cmd: `ip rule add priority ${WAN_PRIO_BASE} from 20.20.30.1 table ${WAN_TABLE_BASE}`, summary: expect.any(String) },
      { cmd: `ip route flush table ${WAN_EGRESS_TABLE}`, summary: expect.any(String) },
      { cmd: `ip route replace default via 20.20.30.254 dev ens34 src 20.20.30.1 metric 1 table ${WAN_EGRESS_TABLE}`, summary: expect.any(String) },
    ]);
    expect(plan.activeEgress).toEqual({ iface: "ens34", style: "priority" });
  });

  it("is idempotent — an existing matching rule is not re-added", () => {
    const kernel = [rule(WAN_PRIO_BASE, WAN_TABLE_BASE, "20.20.30.1")];
    const plan = buildWanOsConvergePlan(input([wan()]), kernel);
    expect(plan.steps.filter((s) => /ip rule add/.test(s.cmd))).toHaveLength(0);
    expect(plan.reasons.some((r) => /already in kernel/.test(r))).toBe(true);
  });

  it("replaces a stale rule (wrong table/source) instead of stacking duplicates", () => {
    const kernel = [rule(WAN_PRIO_BASE, 999, "1.2.3.4")];
    const plan = buildWanOsConvergePlan(input([wan()]), kernel);
    const ruleCmds = plan.steps.filter((s) => /ip rule/.test(s.cmd)).map((s) => s.cmd);
    expect(ruleCmds).toEqual([
      `ip rule del priority ${WAN_PRIO_BASE}`,
      `ip rule add priority ${WAN_PRIO_BASE} from 20.20.30.1 table ${WAN_TABLE_BASE}`,
    ]);
  });

  it("withdraws rule + table when the WAN goes down", () => {
    const kernel = [rule(WAN_PRIO_BASE, WAN_TABLE_BASE, "20.20.30.1")];
    const plan = buildWanOsConvergePlan(input([wan({ state: "down" })]), kernel);
    const cmds = plan.steps.map((s) => s.cmd);
    expect(cmds).toContain(`ip rule del priority ${WAN_PRIO_BASE}`);
    expect(cmds).toContain(`ip route flush table ${WAN_TABLE_BASE}`);
    // the only WAN is down → no default anywhere, egress table emptied honestly
    expect(cmds.filter((c) => /replace default/.test(c))).toHaveLength(0);
    expect(cmds).toContain(`ip route flush table ${WAN_EGRESS_TABLE}`);
  });

  it("withdraws when the policy is disabled", () => {
    const plan = buildWanOsConvergePlan(input([wan({ enabled: false })]), []);
    const cmds = plan.steps.map((s) => s.cmd);
    expect(cmds).toContain(`ip route flush table ${WAN_TABLE_BASE}`);
    expect(cmds.some((c) => /ip rule add/.test(c))).toBe(false);
  });

  it("honestly skips a secondary WAN without a kernel gateway", () => {
    const plan = buildWanOsConvergePlan(input([wan({ gateway: null })]), []);
    expect(plan.steps.filter((s) => /table 26\d/.test(s.cmd))).toHaveLength(0);
    expect(plan.reasons.some((r) => /no kernel gateway/.test(r))).toBe(true);
  });

  it("sweeps orphaned kernel artifacts of a DELETED policy (idx 1)", () => {
    // kernel still holds rule 3210/table 261 from a policy that no longer exists
    const kernel = [rule(WAN_PRIO_BASE + 10, WAN_TABLE_BASE + 1, "20.20.30.1")];
    const plan = buildWanOsConvergePlan(input([wan({ id: 7, iface: "ens35", ifaceIp: "10.9.9.2", ifaceCidr: "10.9.9.0/24", gateway: "10.9.9.1" })]), kernel);
    const cmds = plan.steps.map((s) => s.cmd);
    expect(cmds).toContain(`ip rule del priority ${WAN_PRIO_BASE + 10}`);
    expect(cmds).toContain(`ip route flush table ${WAN_TABLE_BASE + 1}`);
    // the surviving policy's own rule is installed normally
    expect(cmds.some((c) => /ip rule add.*table 260/.test(c))).toBe(true);
  });

  it("sweeps when the deleted policy was the only secondary (prod case)", () => {
    const kernel = [rule(WAN_PRIO_BASE, WAN_TABLE_BASE, "20.20.30.1")];
    const primary = wan({ id: 1, iface: "ens32", ifaceIp: "103.244.7.219", ifaceCidr: "103.244.7.216/29", gateway: "103.244.7.217", priority: 1 });
    const plan = buildWanOsConvergePlan(input([primary]), kernel);
    const cmds = plan.steps.map((s) => s.cmd);
    expect(cmds).toContain(`ip rule del priority ${WAN_PRIO_BASE}`);
    expect(cmds).toContain(`ip route flush table ${WAN_TABLE_BASE}`);
    // primary never gets per-WAN artifacts, so nothing else lands in the band
    expect(cmds.filter((c) => /ip rule add/.test(c))).toHaveLength(0);
  });
});

describe("buildWanOsConvergePlan — egress decision", () => {
  it("fails over: primary down flips table 240 to the standby", () => {
    const primary = wan({ id: 1, iface: "ens32", ifaceIp: "103.244.7.219", ifaceCidr: "103.244.7.216/29", gateway: "103.244.7.217", priority: 1, state: "down" });
    const plan = buildWanOsConvergePlan(input([primary, wan()]), []);
    expect(plan.activeEgress).toEqual({ iface: "ens34", style: "failover" });
    expect(plan.steps.at(-1)?.cmd).toBe(`ip route replace default via 20.20.30.254 dev ens34 src 20.20.30.1 metric 1 table ${WAN_EGRESS_TABLE}`);
  });

  it("weighted ECMP when every active WAN is load_balance", () => {
    const a = wan({ id: 1, iface: "ens33", ifaceIp: "10.8.0.2", ifaceCidr: "10.8.0.0/24", gateway: "10.8.0.1", mode: "load_balance", weight: 70 });
    const b = wan({ id: 2, iface: "ens34", ifaceIp: "20.20.30.1", gateway: "20.20.30.254", mode: "load_balance", weight: 30 });
    const plan = buildWanOsConvergePlan(input([a, b]), null);
    const egress = plan.steps.at(-1)?.cmd ?? "";
    expect(plan.activeEgress).toEqual({ iface: "ens33+ens34", style: "ecmp" });
    expect(egress).toContain(`nexthop via 10.8.0.1 dev ens33 weight 70`);
    expect(egress).toContain(`nexthop via 20.20.30.254 dev ens34 weight 30`);
    expect(egress.startsWith(`ip route replace default table ${WAN_EGRESS_TABLE} `)).toBe(true);
  });

  it("mixed modes never ECMP — best priority wins", () => {
    const a = wan({ id: 1, iface: "ens33", ifaceIp: "10.8.0.2", ifaceCidr: "10.8.0.0/24", gateway: "10.8.0.1", mode: "load_balance", weight: 70, priority: 2 });
    const b = wan({ id: 2, iface: "ens34", gateway: "20.20.30.254", mode: "failover", priority: 3 });
    const plan = buildWanOsConvergePlan(input([a, b]), null);
    expect(plan.activeEgress).toEqual({ iface: "ens33", style: "priority" });
    expect(plan.steps.at(-1)?.cmd).toBe(`ip route replace default via 10.8.0.1 dev ens33 src 10.8.0.2 metric 1 table ${WAN_EGRESS_TABLE}`);
  });

  it("no up WAN → honest offline (egress table emptied)", () => {
    const plan = buildWanOsConvergePlan(input([wan({ state: "down" })]), []);
    expect(plan.egressTable).toBeNull();
    expect(plan.steps).toContainEqual({ cmd: `ip route flush table ${WAN_EGRESS_TABLE}`, summary: expect.any(String) });
  });
});

describe("buildWanOsTeardownPlan", () => {
  it("drops only the multi-WAN rule band and flushes managed tables", () => {
    const kernel = [rule(3200, WAN_TABLE_BASE), rule(3210, WAN_TABLE_BASE + 1), rule(5000, 10001), rule(220, 220)];
    const plan = buildWanOsTeardownPlan(kernel);
    const ruleCmds = plan.steps.filter((s) => /ip rule del/.test(s.cmd)).map((s) => s.cmd);
    expect(ruleCmds).toEqual([`ip rule del priority 3200`, `ip rule del priority 3210`]);
    expect(plan.steps.some((s) => s.cmd === `ip route flush table ${WAN_EGRESS_TABLE}`)).toBe(true);
    expect(plan.steps.some((s) => s.cmd === `ip route flush table ${WAN_TABLE_BASE + 11}`)).toBe(true);
    // never touches strongSwan 220 or PBR 5000 band
    expect(plan.steps.some((s) => /priority (220|5000)\b/.test(s.cmd))).toBe(false);
  });
});

describe("wanStepGuarded — executor red-line guard", () => {
  it("accepts managed-table route and rule steps", () => {
    expect(wanStepGuarded(`ip route replace default via 20.20.30.254 dev ens34 metric 1 table ${WAN_EGRESS_TABLE}`)).toBe(true);
    expect(wanStepGuarded(`ip route replace 20.20.30.0/24 dev ens34 src 20.20.30.1 table ${WAN_TABLE_BASE}`)).toBe(true);
    expect(wanStepGuarded(`ip rule add priority ${WAN_PRIO_BASE} from 20.20.30.1 table ${WAN_TABLE_BASE}`)).toBe(true);
    expect(wanStepGuarded(`ip rule del priority ${WAN_PRIO_BASE}`)).toBe(true);
    expect(wanStepGuarded(`ip route flush table ${WAN_EGRESS_TABLE}`)).toBe(true);
  });

  it("refuses main-table / unmanaged-table route steps", () => {
    expect(wanStepGuarded("ip route replace default via 1.2.3.4 dev ens32")).toBe(false); // bare main default
    expect(wanStepGuarded(`ip route replace default via 1.2.3.4 dev ens32 metric 1 table main`)).toBe(false);
    expect(wanStepGuarded(`ip route replace default via 1.2.3.4 dev ens32 metric 1 table 253`)).toBe(false);
    expect(wanStepGuarded(`ip route replace default via 1.2.3.4 dev ens32 metric 1 table 10001`)).toBe(false);
    expect(wanStepGuarded(`ip route flush table main`)).toBe(false);
  });

  it("refuses rules outside the 3200 band and loopback devices", () => {
    expect(wanStepGuarded(`ip rule add priority 5000 table ${WAN_TABLE_BASE}`)).toBe(false);
    expect(wanStepGuarded(`ip rule add priority ${WAN_PRIO_BASE} table 10001`)).toBe(false);
    expect(wanStepGuarded(`ip rule add from all table ${WAN_TABLE_BASE}`)).toBe(false);
    expect(wanStepGuarded(`ip route replace default dev lo table ${WAN_TABLE_BASE}`)).toBe(false);
    expect(wanStepGuarded("nft add table inet evil")).toBe(false);
  });
});

describe("kernel visibility helpers (GUI↔OS status)", () => {
  it("filterWanBandRules keeps only the 3200..3319 managed band (12 policies × 10)", () => {
    const rules = [
      rule(0, null),
      rule(220, 220),
      rule(3200, 260, "20.20.30.1"),
      rule(3210, 261),
      rule(3310, 271),
      rule(3320, 10001),
      rule(5000, 10001),
    ];
    const band = filterWanBandRules(rules);
    expect(band.map((r) => r.priority)).toEqual([3200, 3210, 3310]);
  });

  it("filterWanBandRules tolerates null kernel output", () => {
    expect(filterWanBandRules([])).toEqual([]);
  });

  it("parseRouteTableDump cleans whitespace and drops empties", () => {
    const out = "\n  default via 103.244.7.217 dev ens32 src 103.244.7.219 metric 1  \n\n  10.99.99.0/24 dev ens34 proto kernel scope link \n";
    expect(parseRouteTableDump(out)).toEqual([
      "default via 103.244.7.217 dev ens32 src 103.244.7.219 metric 1",
      "10.99.99.0/24 dev ens34 proto kernel scope link",
    ]);
    expect(parseRouteTableDump("")).toEqual([]);
    expect(parseRouteTableDump("\n \n")).toEqual([]);
  });
});

describe("in-sync detection — zero-step convergence (no kernel churn)", () => {
  const primary = wan({ id: 1, iface: "ens32", ifaceIp: "103.244.7.219", ifaceCidr: null, gateway: "103.244.7.217", priority: 1, state: "up" });

  it("table 240 already holding the exact single-path decision → zero steps", () => {
    const inp: WanOsInput = {
      ...input([primary], "ens32"),
      currentEgressRoutes: ["default via 103.244.7.217 dev ens32 src 103.244.7.219 metric 1"],
    };
    const plan = buildWanOsConvergePlan(inp, []);
    expect(plan.steps).toHaveLength(0);
    expect(plan.activeEgress).toEqual({ iface: "ens32", style: "primary" });
    expect(plan.reasons.some((r) => /idempotent skip/.test(r))).toBe(true);
  });

  it("kernel route drifted (missing src) → rebuild with flush+replace", () => {
    const inp: WanOsInput = {
      ...input([primary], "ens32"),
      currentEgressRoutes: ["default via 103.244.7.217 dev ens32 metric 1"],
    };
    const plan = buildWanOsConvergePlan(inp, []);
    expect(plan.steps.map((s) => s.cmd)).toEqual([
      `ip route flush table ${WAN_EGRESS_TABLE}`,
      `ip route replace default via 103.244.7.217 dev ens32 src 103.244.7.219 metric 1 table ${WAN_EGRESS_TABLE}`,
    ]);
  });

  it("no dump info (undefined) → conservative rebuild (legacy behavior)", () => {
    const plan = buildWanOsConvergePlan(input([primary], "ens32"), []);
    expect(plan.steps).toHaveLength(2);
  });

  it("offline + table already empty → zero steps (no pointless flush)", () => {
    const down = wan({ state: "down" });
    const inp: WanOsInput = { ...input([down]), currentEgressRoutes: [], currentPerWanRoutes: { [WAN_TABLE_BASE]: [] } };
    const plan = buildWanOsConvergePlan(inp, []);
    expect(plan.steps).toHaveLength(0);
    expect(plan.activeEgress).toBeNull();
  });

  it("offline + stale route present → single flush", () => {
    const down = wan({ state: "down" });
    const inp: WanOsInput = { ...input([down]), currentEgressRoutes: ["default via 1.2.3.4 dev ens34"], currentPerWanRoutes: { [WAN_TABLE_BASE]: [] } };
    const plan = buildWanOsConvergePlan(inp, []);
    expect(plan.steps).toHaveLength(1);
    expect(plan.steps[0].cmd).toBe(`ip route flush table ${WAN_EGRESS_TABLE}`);
  });

  it("per-WAN table already installed → only missing ip rule is added", () => {
    const sec = wan();
    const inp: WanOsInput = {
      ...input([sec]),
      currentEgressRoutes: ["default via 20.20.30.254 dev ens34 src 20.20.30.1 metric 1"],
      currentPerWanRoutes: {
        [WAN_TABLE_BASE]: ["20.20.30.0/24 dev ens34 proto kernel scope link src 20.20.30.1", "default via 20.20.30.254 dev ens34 src 20.20.30.1 metric 1"],
      },
    };
    const plan = buildWanOsConvergePlan(inp, []);
    // routes are in-sync (egress + per-WAN) → the ONLY step is the missing ip rule
    expect(plan.steps.filter((s) => /ip route/.test(s.cmd))).toHaveLength(0);
    expect(plan.steps.filter((s) => /ip rule add/.test(s.cmd))).toHaveLength(1);
    expect(plan.reasons.some((r) => /table .* already matches the kernel/.test(r))).toBe(true);
  });

  it("per-WAN table in-sync AND rule in kernel → fully zero steps", () => {
    const sec = wan();
    const inp: WanOsInput = {
      ...input([sec]),
      currentEgressRoutes: ["default via 20.20.30.254 dev ens34 src 20.20.30.1 metric 1"],
      currentPerWanRoutes: {
        [WAN_TABLE_BASE]: [
          "20.20.30.0/24 dev ens34 proto kernel scope link src 20.20.30.1",
          "default via 20.20.30.254 dev ens34 src 20.20.30.1 metric 1",
        ],
      },
    };
    const kernel = [rule(WAN_PRIO_BASE, WAN_TABLE_BASE, "20.20.30.1")];
    const plan = buildWanOsConvergePlan(inp, kernel);
    expect(plan.steps).toHaveLength(0);
  });

  it("per-WAN withdraw skips the flush when the table dump is already empty", () => {
    const down = wan({ state: "down" });
    const inp: WanOsInput = { ...input([down]), currentEgressRoutes: [], currentPerWanRoutes: { [WAN_TABLE_BASE]: [] } };
    const plan = buildWanOsConvergePlan(inp, []);
    expect(plan.steps).toHaveLength(0);
  });
});

describe("parseMultipathNexthops + ECMP in-sync detection", () => {
  const a = wan({ id: 1, iface: "ens32", ifaceIp: "1.1.1.2", ifaceCidr: null, gateway: "1.1.1.1", mode: "load_balance", weight: 70, priority: 1 });
  const b = wan({ iface: "ens34", ifaceIp: "20.20.30.1", ifaceCidr: null, gateway: "20.20.30.254", mode: "load_balance", weight: 30, priority: 2 });

  it("parses nexthop triples from a kernel dump (split lines)", () => {
    const nh = parseMultipathNexthops(["default", "  nexthop via 1.1.1.1 dev ens32 weight 70", "  nexthop via 20.20.30.254 dev ens34 weight 30"]);
    expect(nh).toEqual([
      { via: "1.1.1.1", dev: "ens32", weight: "70" },
      { via: "20.20.30.254", dev: "ens34", weight: "30" },
    ]);
  });

  it("ECMP in-sync → zero steps", () => {
    const inp: WanOsInput = {
      ...input([a, b]),
      currentEgressRoutes: ["default", "  nexthop via 1.1.1.1 dev ens32 weight 70", "  nexthop via 20.20.30.254 dev ens34 weight 30"],
      currentPerWanRoutes: { [WAN_TABLE_BASE]: ["default via 20.20.30.254 dev ens34 src 20.20.30.1 metric 1"] },
    };
    const kernel = [rule(WAN_PRIO_BASE, WAN_TABLE_BASE, "20.20.30.1")];
    const plan = buildWanOsConvergePlan(inp, kernel);
    expect(plan.steps).toHaveLength(0);
    expect(plan.activeEgress).toEqual({ iface: "ens32+ens34", style: "ecmp" });
  });

  it("ECMP weight drift → flush + replace", () => {
    const inp: WanOsInput = {
      ...input([a, b]),
      currentEgressRoutes: ["default", "  nexthop via 1.1.1.1 dev ens32 weight 50", "  nexthop via 20.20.30.254 dev ens34 weight 30"],
    };
    const plan = buildWanOsConvergePlan(inp, []);
    const egressSteps = plan.steps.filter((s) => s.cmd.includes(`table ${WAN_EGRESS_TABLE}`));
    expect(egressSteps).toHaveLength(2);
    expect(egressSteps[0].cmd).toBe(`ip route flush table ${WAN_EGRESS_TABLE}`);
    expect(egressSteps[1].cmd).toContain("nexthop via 1.1.1.1 dev ens32 weight 70");
  });
});
