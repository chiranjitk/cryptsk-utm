/**
 * Unit tests for the pure interface business-rules engine
 * (src/lib/network/iface-rules.ts) — bun test.
 *
 * Each BR-* code is pinned: positive case (rule fires) and negative case
 * (valid config passes clean).
 */
import { describe, expect, test } from "vitest";

import {
  gatewayInSubnet,
  groupIssues,
  ipInSubnet,
  ipv4ToInt,
  lintIface,
  prefixToMask,
  primarySubnetOf,
  readMembers,
  readSecondaryIps,
  subnetsOverlap,
  suggestMssClamp,
  type IfaceRuleView,
} from "@/lib/network/iface-rules";

function view(overrides: Partial<IfaceRuleView> & { name: string }): IfaceRuleView {
  return {
    type: "physical",
    mode: "l3",
    role: "lan",
    mtu: 1500,
    enabled: true,
    config: {},
    ...overrides,
  };
}

// ── IPv4 math ───────────────────────────────────────────────────────────────

describe("IPv4 math", () => {
  test("ipv4ToInt round-trips the octets", () => {
    expect(ipv4ToInt("10.0.0.1")).toBe((10 << 24) | 1);
    expect(ipv4ToInt("255.255.255.255")).toBe(0xffffffff);
    expect(ipv4ToInt("999.0.0.1")).toBeNull();
  });

  test("prefixToMask builds the right mask", () => {
    expect(prefixToMask(24)).toBe(0xffffff00);
    expect(prefixToMask(0)).toBe(0);
    expect(prefixToMask(32)).toBe(0xffffffff);
    expect(prefixToMask(33)).toBeNull();
  });

  test("ipInSubnet respects network/broadcast bounds", () => {
    const s = { ip: "10.0.0.0", prefix: 24 };
    expect(ipInSubnet("10.0.0.1", s)).toBe(true);
    expect(ipInSubnet("10.0.0.255", s)).toBe(true);
    expect(ipInSubnet("10.0.1.1", s)).toBe(false);
  });

  test("subnetsOverlap detects crossing ranges", () => {
    expect(subnetsOverlap({ ip: "10.0.0.0", prefix: 24 }, { ip: "10.0.0.128", prefix: 25 })).toBe(true);
    expect(subnetsOverlap({ ip: "10.0.0.0", prefix: 24 }, { ip: "10.0.1.0", prefix: 24 })).toBe(false);
    expect(subnetsOverlap({ ip: "10.0.0.5", prefix: 32 }, { ip: "10.0.0.5", prefix: 32 })).toBe(true);
    expect(subnetsOverlap({ ip: "10.0.0.5", prefix: 32 }, { ip: "10.0.0.6", prefix: 32 })).toBe(false);
  });

  test("gatewayInSubnet", () => {
    expect(gatewayInSubnet("10.0.0.254", { ip: "10.0.0.1", prefix: 24 })).toBe(true);
    expect(gatewayInSubnet("10.0.1.254", { ip: "10.0.0.1", prefix: 24 })).toBe(false);
  });

  test("suggestMssClamp: mtu-40 clamped into [536,1460]", () => {
    expect(suggestMssClamp(1500)).toBe(1460);
    expect(suggestMssClamp(1400)).toBe(1360);
    expect(suggestMssClamp(600)).toBe(560);
    expect(suggestMssClamp(68)).toBe(536);
    expect(suggestMssClamp(9000)).toBe(1460);
    expect(suggestMssClamp(67)).toBeNull();
  });
});

// ── config readers ──────────────────────────────────────────────────────────

describe("config readers", () => {
  test("primarySubnetOf reads physical/loopback/logical L3", () => {
    expect(primarySubnetOf(view({ name: "wan0", config: { ip: "10.1.1.5", cidrPrefix: 24 } }))).toEqual({
      ip: "10.1.1.5",
      prefix: 24,
    });
    expect(primarySubnetOf(view({ name: "lan0", mode: "l2", config: { ip: "10.1.1.5", cidrPrefix: 24 } }))).toBeNull();
    expect(primarySubnetOf(view({ name: "lan0", config: { wanType: "dhcp" } }))).toBeNull();
  });

  test("readSecondaryIps / readMembers tolerate garbage", () => {
    expect(readSecondaryIps({ secondaryIps: [{ ip: "10.0.0.2", cidrPrefix: 24 }, "junk"] })).toEqual([
      { ip: "10.0.0.2", cidrPrefix: 24 },
    ]);
    expect(readSecondaryIps({})).toEqual([]);
    expect(readMembers({ members: ["eth0", 5, "eth1"] })).toEqual(["eth0", "eth1"]);
  });
});

// ── BR-GW-SUBNET ────────────────────────────────────────────────────────────

describe("BR-GW-SUBNET", () => {
  test("gateway outside the subnet errors", () => {
    const issues = lintIface({
      self: view({ name: "lan0", config: { ip: "192.168.10.1", cidrPrefix: 24, gateway: "192.168.20.1" } }),
      others: [],
    });
    expect(issues.some((i) => i.code === "BR-GW-SUBNET" && i.severity === "error")).toBe(true);
  });

  test("gateway inside the subnet passes", () => {
    const issues = lintIface({
      self: view({ name: "lan0", config: { ip: "192.168.10.1", cidrPrefix: 24, gateway: "192.168.10.254" } }),
      others: [],
    });
    expect(issues.filter((i) => i.code === "BR-GW-SUBNET")).toHaveLength(0);
  });

  test("point-to-point /31 skips the check", () => {
    const issues = lintIface({
      self: view({ name: "wan0", config: { ip: "10.0.0.2", cidrPrefix: 31, gateway: "10.1.1.1" } }),
      others: [],
    });
    expect(issues.filter((i) => i.code === "BR-GW-SUBNET")).toHaveLength(0);
  });
});

// ── BR-OVERLAP / BR-SECIP ───────────────────────────────────────────────────

describe("BR-OVERLAP", () => {
  test("primary subnet overlapping another interface errors", () => {
    const issues = lintIface({
      self: view({ name: "lan1", config: { ip: "192.168.10.5", cidrPrefix: 24 } }),
      others: [view({ name: "lan0", id: 1, config: { ip: "192.168.10.1", cidrPrefix: 24 } })],
    });
    expect(issues.some((i) => i.code === "BR-OVERLAP" && i.field === "ip")).toBe(true);
  });

  test("secondary overlapping another interface errors on the alias field", () => {
    const issues = lintIface({
      self: view({ name: "lan1", config: { ip: "10.9.0.1", cidrPrefix: 24, secondaryIps: [{ ip: "192.168.10.9", cidrPrefix: 24 }] } }),
      others: [view({ name: "lan0", id: 1, config: { ip: "192.168.10.1", cidrPrefix: 24 } })],
    });
    expect(issues.some((i) => i.code === "BR-OVERLAP" && i.field === "secondaryIps")).toBe(true);
  });

  test("distinct subnets pass", () => {
    const issues = lintIface({
      self: view({ name: "lan1", config: { ip: "192.168.11.1", cidrPrefix: 24 } }),
      others: [view({ name: "lan0", id: 1, config: { ip: "192.168.10.1", cidrPrefix: 24 } })],
    });
    expect(issues.filter((i) => i.code === "BR-OVERLAP")).toHaveLength(0);
  });
});

describe("BR-SECIP", () => {
  test("duplicate aliases error", () => {
    const issues = lintIface({
      self: view({
        name: "lan0",
        config: {
          ip: "10.0.0.1",
          cidrPrefix: 24,
          secondaryIps: [
            { ip: "10.0.0.2", cidrPrefix: 24 },
            { ip: "10.0.0.2", cidrPrefix: 24 },
          ],
        },
      }),
      others: [],
    });
    expect(issues.some((i) => i.code === "BR-SECIP" && i.message.includes("Duplicate"))).toBe(true);
  });

  test("bad prefix errors", () => {
    const issues = lintIface({
      self: view({
        name: "lan0",
        config: { ip: "10.0.0.1", cidrPrefix: 24, secondaryIps: [{ ip: "10.0.0.2", cidrPrefix: 0 }] },
      }),
      others: [],
    });
    expect(issues.some((i) => i.code === "BR-SECIP" && i.message.includes("1 and 32"))).toBe(true);
  });
});

// ── MTU chain ───────────────────────────────────────────────────────────────

describe("MTU chain", () => {
  test("BR-MTU-VLAN: vlan MTU above parent errors", () => {
    const issues = lintIface({
      self: view({ name: "vlan10", type: "vlan", mtu: 1500, parentName: "eth0", vlanId: 10 }),
      others: [view({ name: "eth0", id: 1, type: "physical", mtu: 1400 })],
    });
    expect(issues.some((i) => i.code === "BR-MTU-VLAN")).toBe(true);
  });

  test("BR-MTU-PARENT: shrinking parent below an existing vlan child errors", () => {
    const issues = lintIface({
      self: view({ name: "eth0", type: "physical", mtu: 1300 }),
      others: [view({ name: "vlan10", id: 1, type: "vlan", mtu: 1400, parentName: "eth0", vlanId: 10 })],
    });
    expect(issues.some((i) => i.code === "BR-MTU-PARENT" && i.message.includes("vlan10"))).toBe(true);
  });

  test("BR-MTU-MEMBER: bridge MTU above smallest member errors", () => {
    const issues = lintIface({
      self: view({ name: "br0", type: "bridge", mtu: 9000, config: { members: ["eth0", "eth1"] } }),
      others: [view({ name: "eth0", id: 1, mtu: 9000 }), view({ name: "eth1", id: 2, mtu: 1500 })],
    });
    expect(issues.some((i) => i.code === "BR-MTU-MEMBER" && i.message.includes("1500"))).toBe(true);
  });

  test("BR-MTU-MASTER: member MTU below its master errors", () => {
    const issues = lintIface({
      self: view({ name: "eth0", type: "physical", mtu: 1400 }),
      others: [view({ name: "br0", id: 1, type: "bridge", mtu: 1500, config: { members: ["eth0"] } })],
    });
    expect(issues.some((i) => i.code === "BR-MTU-MASTER" && i.message.includes("br0"))).toBe(true);
  });
});

// ── BR-MSS ──────────────────────────────────────────────────────────────────

describe("BR-MSS", () => {
  test("clamp above mtu-40 errors", () => {
    const issues = lintIface({ self: view({ name: "wan0", mtu: 1400, mssClamp: 1400 }), others: [] });
    expect(issues.some((i) => i.code === "BR-MSS")).toBe(true);
  });

  test("wan with small MTU and no clamp warns", () => {
    const issues = lintIface({ self: view({ name: "wan0", role: "wan", mtu: 1492 }), others: [] });
    const warn = issues.find((i) => i.code === "BR-MSS-HINT");
    expect(warn?.severity).toBe("warning");
  });
});

// ── BR-MGMT-LOCKOUT ─────────────────────────────────────────────────────────

describe("BR-MGMT-LOCKOUT", () => {
  const mgmt = view({ name: "eth0", role: "mgmt" });

  test("disabling the last enabled mgmt interface errors", () => {
    const issues = lintIface({ self: { ...mgmt, enabled: true }, others: [], action: "disable" });
    expect(issues.some((i) => i.code === "BR-MGMT-LOCKOUT")).toBe(true);
  });

  test("disable action judges CURRENT state even when candidate is enabled=false", () => {
    // service passes candidate enabled=false when disabling — the lockout must still fire
    const issues = lintIface({ self: { ...mgmt, enabled: false }, others: [], action: "disable" });
    expect(issues.some((i) => i.code === "BR-MGMT-LOCKOUT")).toBe(true);
  });

  test("deleting an already-disabled mgmt interface is not a lockout", () => {
    const issues = lintIface({ self: { ...mgmt, enabled: false }, others: [], action: "delete" });
    expect(issues.filter((i) => i.code === "BR-MGMT-LOCKOUT")).toHaveLength(0);
  });

  test("deleting the last mgmt errors", () => {
    const issues = lintIface({ self: mgmt, others: [], action: "delete" });
    expect(issues.some((i) => i.code === "BR-MGMT-LOCKOUT")).toBe(true);
  });

  test("demoting the last mgmt errors", () => {
    const issues = lintIface({ self: { ...mgmt, role: "lan" }, others: [], roleFrom: "mgmt" });
    expect(issues.some((i) => i.code === "BR-MGMT-LOCKOUT" && i.field === "role")).toBe(true);
  });

  test("a second enabled mgmt interface unlocks the action", () => {
    const issues = lintIface({
      self: mgmt,
      others: [view({ name: "eth1", id: 2, role: "mgmt", enabled: true })],
      action: "disable",
    });
    expect(issues.filter((i) => i.code === "BR-MGMT-LOCKOUT")).toHaveLength(0);
  });

  test("plain role change of a disabled mgmt iface is not a lockout", () => {
    const issues = lintIface({ self: { ...mgmt, enabled: false, role: "lan" }, others: [], roleFrom: "mgmt" });
    expect(issues.filter((i) => i.code === "BR-MGMT-LOCKOUT")).toHaveLength(0);
  });
});

// ── BR-MEMBER ───────────────────────────────────────────────────────────────

describe("BR-MEMBER", () => {
  test("member already enslaved elsewhere errors", () => {
    const issues = lintIface({
      self: view({ name: "br1", type: "bridge", config: { members: ["eth0"] } }),
      others: [
        view({ name: "eth0", id: 1 }),
        view({ name: "br0", id: 2, type: "bridge", config: { members: ["eth0"] } }),
      ],
    });
    expect(issues.some((i) => i.code === "BR-MEMBER" && i.message.includes("enslaved to br0"))).toBe(true);
  });

  test("member with L3 addressing errors", () => {
    const issues = lintIface({
      self: view({ name: "br0", type: "bridge", config: { members: ["eth0"] } }),
      others: [view({ name: "eth0", id: 1, config: { ip: "10.0.0.1", cidrPrefix: 24 } })],
    });
    expect(issues.some((i) => i.code === "BR-MEMBER" && i.message.includes("L3 addressing"))).toBe(true);
  });

  test("non-eligible member type errors", () => {
    const issues = lintIface({
      self: view({ name: "br0", type: "bridge", config: { members: ["br1"] } }),
      others: [view({ name: "br1", id: 1, type: "bridge", config: { members: ["eth9"] } })],
    });
    expect(issues.some((i) => i.code === "BR-MEMBER" && i.message.includes("only physical or vlan"))).toBe(true);
  });

  test("self-membership and duplicates error", () => {
    const issues = lintIface({
      self: view({ name: "br0", type: "bridge", config: { members: ["br0", "eth0", "eth0"] } }),
      others: [view({ name: "eth0", id: 1 })],
    });
    expect(issues.filter((i) => i.code === "BR-MEMBER").length).toBeGreaterThanOrEqual(2);
  });

  test("bond below 2 members errors, bridge needs >= 1", () => {
    const bond = lintIface({ self: view({ name: "bond0", type: "bond", config: { members: ["eth0"] } }), others: [view({ name: "eth0", id: 1 })] });
    const bridge = lintIface({ self: view({ name: "br0", type: "bridge", config: { members: [] } }), others: [] });
    expect(bond.some((i) => i.code === "BR-MEMBER" && i.message.includes("at least 2"))).toBe(true);
    expect(bridge.some((i) => i.code === "BR-MEMBER" && i.message.includes("at least 1"))).toBe(true);
  });

  test("clean bridge passes", () => {
    const issues = lintIface({
      self: view({ name: "br0", type: "bridge", mode: "l3", mtu: 1500, config: { members: ["eth0"] } }),
      others: [view({ name: "eth0", id: 1, mtu: 1500 })],
    });
    expect(issues.filter((i) => i.code === "BR-MEMBER")).toHaveLength(0);
  });
});

// ── BR-VLAN-PARENT / BR-VLAN-UNIQ ───────────────────────────────────────────

describe("VLAN rules", () => {
  test("vlan-over-vlan errors", () => {
    const issues = lintIface({
      self: view({ name: "vlan20", type: "vlan", parentName: "vlan10", vlanId: 20 }),
      others: [view({ name: "vlan10", id: 1, type: "vlan", parentName: "eth0", vlanId: 10 })],
    });
    expect(issues.some((i) => i.code === "BR-VLAN-PARENT" && i.message.includes("physical, bridge or bond"))).toBe(true);
  });

  test("duplicate vlan id on the same parent errors", () => {
    const issues = lintIface({
      self: view({ name: "vlan10b", type: "vlan", parentName: "eth0", vlanId: 10 }),
      others: [view({ name: "vlan10", id: 1, type: "vlan", parentName: "eth0", vlanId: 10 })],
    });
    expect(issues.some((i) => i.code === "BR-VLAN-UNIQ" && i.message.includes("vlan10"))).toBe(true);
  });

  test("same vlan id on a different parent passes", () => {
    const issues = lintIface({
      self: view({ name: "vlan10b", type: "vlan", parentName: "eth1", vlanId: 10 }),
      others: [
        view({ name: "vlan10", id: 1, type: "vlan", parentName: "eth0", vlanId: 10 }),
        view({ name: "eth1", id: 2, type: "physical" }),
      ],
    });
    expect(issues.filter((i) => i.code === "BR-VLAN-UNIQ")).toHaveLength(0);
  });

  test("disabled parent warns", () => {
    const issues = lintIface({
      self: view({ name: "vlan10", type: "vlan", parentName: "eth0", vlanId: 10 }),
      others: [view({ name: "eth0", id: 1, type: "physical", enabled: false })],
    });
    const warn = issues.find((i) => i.code === "BR-VLAN-PARENT");
    expect(warn?.severity).toBe("warning");
  });
});

// ── BR-L2-L3 / BR-WAN-ADDR / BR-TUNNEL / BR-LOOP-PREFIX / BR-NAME ──────────

describe("misc rules", () => {
  test("L2 mode with an IP errors", () => {
    const issues = lintIface({
      self: view({ name: "lan0", mode: "l2", config: { ip: "10.0.0.1", cidrPrefix: 24 } }),
      others: [],
    });
    expect(issues.some((i) => i.code === "BR-L2-L3")).toBe(true);
  });

  test("static WAN without an IP errors", () => {
    const issues = lintIface({
      self: view({ name: "wan0", role: "wan", config: { wanType: "static" } }),
      others: [],
    });
    expect(issues.some((i) => i.code === "BR-WAN-ADDR")).toBe(true);
  });

  test("tunnel endpoints identical errors", () => {
    const issues = lintIface({
      self: view({ name: "gre1", type: "gre", config: { local: "10.0.0.1", remote: "10.0.0.1" } }),
      others: [],
    });
    expect(issues.some((i) => i.code === "BR-TUNNEL")).toBe(true);
  });

  test("loopback with prefix < 32 warns", () => {
    const issues = lintIface({
      self: view({ name: "lo1", type: "loopback", config: { ip: "10.255.0.1", cidrPrefix: 24 } }),
      others: [],
    });
    expect(issues.find((i) => i.code === "BR-LOOP-PREFIX")?.severity).toBe("warning");
  });

  test("bad name errors", () => {
    const issues = lintIface({ self: view({ name: "Bad_Name!" }), others: [] });
    expect(issues.some((i) => i.code === "BR-NAME")).toBe(true);
  });

  test("MTU out of bounds errors", () => {
    const issues = lintIface({ self: view({ name: "eth0", mtu: 9001 }), others: [] });
    expect(issues.some((i) => i.code === "BR-MTU-BOUNDS")).toBe(true);
  });
});

// ── grouping ────────────────────────────────────────────────────────────────

describe("groupIssues", () => {
  test("splits errors and warnings per field", () => {
    const g = groupIssues([
      { code: "A", field: "ip", severity: "error", message: "a1" },
      { code: "B", field: "ip", severity: "error", message: "a2" },
      { code: "C", field: "mtu", severity: "warning", message: "w1" },
    ]);
    expect(g.errors["ip"]).toEqual(["a1", "a2"]);
    expect(g.warnings["mtu"]).toEqual(["w1"]);
    expect(Object.keys(g.errors)).toHaveLength(1);
  });
});
