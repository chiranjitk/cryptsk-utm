/**
 * NAT/Objects/Zones enterprise upgrade tests — pool enforcement, hairpin
 * fidelity, NAT logging, multi-range DNAT, counter families, response
 * shapers, and the NAT conflict validator.
 */

import { describe, it, expect } from "vitest";
import { generateNftRuleset, poolRange, type NftGenNatRule } from "@/lib/firewall/nft-gen";
import { parseRuleCounters } from "@/lib/firewall/firewall-os";
import { shapeNatRule } from "@/lib/firewall/rule-shape";
import {
  detectNatConflicts,
  natAdvisories,
  natLegs,
  natTranslationKey,
  type NatCandidate,
} from "@/lib/firewall/nat-validate";
import { parseAddrMatcher, parsePortList } from "@/lib/firewall/rule-match";

const natRule = (over: Partial<NftGenNatRule> = {}): NftGenNatRule => ({
  id: 7,
  name: "nat-test",
  position: 1,
  enabled: true,
  type: "snat",
  srcAddrs: [],
  dstAddrs: [],
  services: [],
  outgoingIface: null,
  translatedSrc: "masq",
  translatedSrcPool: [],
  translatedDst: null,
  translatedPort: null,
  translatedPortRange: null,
  logging: "none",
  ...over,
});

const gen = (natRules: NftGenNatRule[]) =>
  generateNftRuleset({ rules: [], natRules, zones: [], generatedAt: new Date("2026-01-01T00:00:00Z") });

describe("NAT pool enforcement", () => {
  it("contiguous pool compiles to a kernel round-robin range", () => {
    expect(poolRange(["203.0.113.5", "203.0.113.6", "203.0.113.7"])).toEqual({ lo: "203.0.113.5", hi: "203.0.113.7" });
    const res = gen([natRule({ translatedSrc: null, translatedSrcPool: ["203.0.113.5", "203.0.113.6", "203.0.113.7"] })]);
    expect(res.file).toContain("snat to 203.0.113.5-203.0.113.7");
    expect(res.warnings.find((w) => w.code === "nat-pool-unsupported")).toBeUndefined();
  });

  it("non-contiguous pool is excluded with a loud warning (never widened)", () => {
    expect(poolRange(["203.0.113.5", "203.0.113.9"])).toBeNull();
    const res = gen([natRule({ translatedSrc: null, translatedSrcPool: ["203.0.113.5", "203.0.113.9"] })]);
    expect(res.file).not.toContain("snat to");
    expect(res.warnings.some((w) => w.code === "nat-pool-unsupported")).toBe(true);
  });

  it("out-of-order pool input still produces the ordered range", () => {
    expect(poolRange(["203.0.113.7", "203.0.113.5", "203.0.113.6"])).toEqual({ lo: "203.0.113.5", hi: "203.0.113.7" });
  });
});

describe("hairpin NAT fidelity", () => {
  it("honors translatedSrc as a static snat on the hairpin leg", () => {
    const res = gen([
      natRule({
        type: "hairpin",
        translatedSrc: "192.168.10.1",
        translatedDst: "10.99.99.5",
        dstAddrs: [parseAddrMatcher("ip", "203.0.113.50")],
      }),
    ]);
    const post = res.file.split("chain postrouting")[1] ?? "";
    expect(post).toContain("snat to 192.168.10.1");
    expect(post).not.toContain("masquerade");
  });

  it("falls back to masquerade when no hairpin translatedSrc is set", () => {
    const res = gen([
      natRule({
        type: "hairpin",
        translatedSrc: null,
        translatedDst: "10.99.99.5",
        dstAddrs: [parseAddrMatcher("ip", "203.0.113.50")],
      }),
    ]);
    const post = res.file.split("chain postrouting")[1] ?? "";
    expect(post).toContain("masquerade");
    expect(res.warnings.some((w) => w.code === "nat-hairpin-masq")).toBe(true);
  });

  it("splits translatedPortRange into one prerouting rule per token", () => {
    const res = gen([
      natRule({
        type: "hairpin",
        translatedDst: "10.99.99.5",
        translatedPortRange: "5000-5100,6000",
        dstAddrs: [parseAddrMatcher("ip", "203.0.113.50")],
      }),
    ]);
    const pre = res.file.split("chain prerouting")[1]?.split("chain")[0] ?? "";
    expect(pre).toContain("dnat to 10.99.99.5:5000-5100");
    expect(pre).toContain("dnat to 10.99.99.5:6000");
    expect(res.counts.prerouting).toBe(2);
  });
});

describe("multi-range DNAT", () => {
  it("emits one prerouting rule per validated port token", () => {
    const res = gen([
      natRule({
        type: "dnat",
        translatedDst: "172.16.20.5",
        translatedPortRange: "80,443,8000-8010",
        dstAddrs: [parseAddrMatcher("ip", "203.0.113.50")],
      }),
    ]);
    const pre = res.file.split("chain prerouting")[1]?.split("chain")[0] ?? "";
    expect(pre).toContain("dnat to 172.16.20.5:80");
    expect(pre).toContain("dnat to 172.16.20.5:443");
    expect(pre).toContain("dnat to 172.16.20.5:8000-8010");
    expect(res.counts.prerouting).toBe(3);
  });

  it("invalid port ranges exclude the rule (never a broken statement)", () => {
    const res = gen([
      natRule({
        type: "dnat",
        translatedDst: "172.16.20.5",
        translatedPortRange: "99999,80",
        dstAddrs: [parseAddrMatcher("ip", "203.0.113.50")],
      }),
    ]);
    expect(res.counts.prerouting).toBe(0);
    expect(res.warnings.some((w) => w.code === "nat-port-unsupported")).toBe(true);
  });

  it("warns (but still enforces) a DMZ-style unconstrained DNAT", () => {
    const res = gen([
      natRule({
        type: "dnat",
        translatedDst: "172.16.20.5",
        dstAddrs: [parseAddrMatcher("ip", "203.0.113.50")],
      }),
    ]);
    expect(res.counts.prerouting).toBe(1);
    expect(res.warnings.some((w) => w.code === "nat-dnat-unconstrained")).toBe(true);
  });
});

describe("NAT logging", () => {
  it("summary logging emits a rate-limited nat: log prefix", () => {
    const res = gen([natRule({ logging: "summary" })]);
    expect(res.file).toContain('log prefix "nat:7:nat-test"');
    expect(res.file).toContain("limit rate 10/second");
  });

  it("detail logging raises the rate and adds flags all", () => {
    const res = gen([natRule({ logging: "detail" })]);
    expect(res.file).toContain("limit rate 100/second");
    expect(res.file).toContain("flags all");
  });

  it("none logging emits no log fragments", () => {
    const res = gen([natRule({ logging: "none" })]);
    expect(res.file).not.toContain("log prefix");
  });
});

describe("kernel counter families", () => {
  it("parses fw: and nat: comment counters into distinct kinds", () => {
    const dump = [
      "table inet console-firewall {",
      "  chain forward {",
      '    ip saddr 10.0.0.0/8 accept counter packets 42 bytes 4200 comment "fw:3:LAN-OUT"',
      "  }",
      "  chain postrouting {",
      '    oifname "ens32" masquerade counter packets 99 bytes 9900 comment "nat:5:MASQ_LAN"',
      "  }",
      "}",
    ].join("\n");
    const counters = parseRuleCounters(dump);
    const fw = counters.find((c) => c.ruleKind === "firewall");
    const nat = counters.find((c) => c.ruleKind === "nat");
    expect(fw).toMatchObject({ ruleId: 3, packets: 42 });
    expect(nat).toMatchObject({ ruleId: 5, packets: 99 });
  });
});

describe("response shaper — NAT pool round-trip", () => {
  it("keeps string IP pools intact on read (previously emptied → data loss)", () => {
    const shaped = shapeNatRule({
      id: 1,
      tenantId: 1,
      name: "pool-snat",
      position: 1,
      type: "snat",
      enabled: true,
      srcAddrIds: "[2,3]",
      dstAddrIds: "[]",
      serviceIds: "[]",
      outgoingIface: "ens32",
      translatedSrc: null,
      translatedSrcPool: '["203.0.113.5","203.0.113.6"]',
      overload: true,
      translatedDst: null,
      translatedPort: null,
      translatedPortRange: null,
      logging: "none",
      comment: null,
      hitCount: 5,
      lastHitAt: null,
      createdAt: new Date(),
    });
    expect(shaped.translatedSrcPool).toEqual(["203.0.113.5", "203.0.113.6"]);
    expect(shaped.srcAddrIds).toEqual([2, 3]);
    expect(shaped.lastHitAt).toBeNull();
  });
});

// ── NAT conflict validator ──────────────────────────────────────────────────

const candidate = (over: Partial<NatCandidate> = {}): NatCandidate => ({
  id: null,
  name: "candidate",
  position: 99,
  enabled: true,
  type: "snat",
  srcAddrs: [],
  dstAddrs: [],
  services: [],
  outgoingIface: null,
  translatedSrc: "masq",
  translatedSrcPool: [],
  translatedDst: null,
  translatedPort: null,
  translatedPortRange: null,
  logging: "none",
  ...over,
});

const ip = (v: string) => [parseAddrMatcher("ip", v)];
const anyTcp443 = [{ protocol: "tcp" as const, srcPorts: [], dstPorts: parsePortList("443") }];

describe("natLegs", () => {
  it("maps rule types to their chain legs", () => {
    expect(natLegs("snat")).toEqual(["postrouting"]);
    expect(natLegs("dnat")).toEqual(["prerouting"]);
    expect(natLegs("hairpin")).toEqual(["prerouting", "postrouting"]);
    expect(natLegs("exempt")).toEqual(["postrouting"]);
  });
});

describe("detectNatConflicts", () => {
  it("an earlier broader snat shadows a later narrower snat with a different target", () => {
    const conflicts = detectNatConflicts(
      candidate({ srcAddrs: ip("10.0.0.5"), translatedSrc: "203.0.113.99" }),
      [candidate({ id: 1, name: "wide", position: 1, srcAddrs: [ip("10.0.0.5")[0], ip("10.0.0.6")[0]], translatedSrc: "203.0.113.1" })],
    );
    expect(conflicts).toHaveLength(1);
    expect(conflicts[0]).toMatchObject({ reason: "shadowed_by", withRuleId: 1, leg: "postrouting" });
  });

  it("identical scope + different translation conflicts_with (same match surface, two targets)", () => {
    const conflicts = detectNatConflicts(candidate({ srcAddrs: ip("10.0.0.5") }), [
      candidate({ id: 2, name: "same-scope", position: 1, srcAddrs: ip("10.0.0.5"), translatedSrc: "203.0.113.2" }),
    ]);
    expect(conflicts[0]).toMatchObject({ reason: "conflicts_with", withRuleId: 2 });
  });

  it("identical scope + translation is redundant (non-blocking)", () => {
    const conflicts = detectNatConflicts(candidate({ srcAddrs: ip("10.0.0.5") }), [
      candidate({ id: 3, name: "twin", position: 1, srcAddrs: ip("10.0.0.5") }),
    ]);
    expect(conflicts[0]).toMatchObject({ reason: "redundant", withRuleId: 3 });
  });

  it("exempt shadows postrouting legs regardless of position, never prerouting", () => {
    const conflicts = detectNatConflicts(
      candidate({ type: "snat", srcAddrs: ip("10.0.0.5"), translatedSrc: "203.0.113.77" }),
      [candidate({ id: 4, name: "no-nat", position: 50, type: "exempt", translatedSrc: null })],
    );
    expect(conflicts[0]).toMatchObject({ reason: "shadowed_by", withRuleId: 4, leg: "postrouting" });
  });

  it("hairpin legs only interact with the same leg of the existing rule", () => {
    // existing dnat shares ONLY the prerouting leg
    const conflicts = detectNatConflicts(
      candidate({
        type: "hairpin",
        translatedDst: "10.0.0.9",
        dstAddrs: ip("203.0.113.50"),
      }),
      [
        candidate({
          id: 5,
          name: "existing-dnat",
          position: 1,
          type: "dnat",
          translatedDst: "10.0.0.8",
          dstAddrs: ip("203.0.113.50"),
        }),
      ],
    );
    expect(conflicts).toHaveLength(1);
    expect(conflicts[0].leg).toBe("prerouting");
  });

  it("service dimension participates: narrower service escapes the wider shadow", () => {
    const conflicts = detectNatConflicts(candidate({ services: anyTcp443, translatedSrc: "203.0.113.99" }), [
      candidate({ id: 6, name: "wide", position: 1, translatedSrc: "203.0.113.1", services: [] }),
    ]);
    // wide match-all earlier rule DOES cover the 443-only candidate → shadow
    expect(conflicts[0].reason).toBe("shadowed_by");
  });

  it("disabled or later existing rules do not shadow", () => {
    const conflicts = detectNatConflicts(candidate({ translatedSrc: "203.0.113.99" }), [
      candidate({ id: 7, name: "later", position: 200, translatedSrc: "203.0.113.1" }),
      candidate({ id: 8, name: "off", position: 1, enabled: false, translatedSrc: "203.0.113.1" }),
    ]);
    expect(conflicts).toHaveLength(0);
  });
});

describe("natTranslationKey", () => {
  it("normalizes equivalent translations", () => {
    expect(natTranslationKey(candidate({ translatedSrc: "masq" }))).toBe("masquerade");
    expect(natTranslationKey(candidate({ translatedSrc: "ens32" }))).toBe("masquerade");
    expect(natTranslationKey(candidate({ translatedSrc: "203.0.113.1" }))).toBe("snat:203.0.113.1");
    expect(natTranslationKey(candidate({ type: "dnat", translatedDst: "10.0.0.5", translatedPort: 8080 }))).toBe(
      "dnat:10.0.0.5:8080",
    );
    expect(natTranslationKey(candidate({ type: "exempt", translatedSrc: null }))).toBe("accept");
  });
});

describe("natAdvisories", () => {
  it("flags fqdn/geo matches as unenforceable", () => {
    const adv = natAdvisories(candidate({ srcAddrs: [parseAddrMatcher("fqdn", "portal.example.com")] }));
    expect(adv.some((a) => a.code === "nat-match-not-expressible")).toBe(true);
  });

  it("flags a DMZ-style dnat", () => {
    const adv = natAdvisories(candidate({ type: "dnat", translatedDst: "10.0.0.5" }));
    expect(adv.some((a) => a.code === "nat-dnat-unconstrained")).toBe(true);
  });

  it("contiguous pools report the enforced range", () => {
    const adv = natAdvisories(
      candidate({ type: "snat", translatedSrc: null, translatedSrcPool: ["203.0.113.5", "203.0.113.6", "203.0.113.7"] }),
    );
    const poolAdv = adv.find((a) => a.code === "nat-pool-range");
    expect(poolAdv?.message).toContain("203.0.113.5-203.0.113.7");
  });
});
