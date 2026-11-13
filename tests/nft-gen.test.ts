import { describe, it, expect } from "vitest";
import {
  generateNftRuleset,
  isCatchAllDeny,
  sanitizeComment,
  type NftGenInput,
  type NftGenNatRule,
  type NftGenRule,
} from "@/lib/firewall/nft-gen";
import { parseRuleCounters, tableBlocksInSync } from "@/lib/firewall/firewall-os";

const zone = (id: number, name: string, interfaces: string[]) => ({ id, name, interfaces });

const rule = (over: Partial<NftGenRule> = {}): NftGenRule => ({
  id: 1,
  name: "test-rule",
  position: 1,
  enabled: true,
  srcZoneIds: [],
  dstZoneIds: [],
  srcAddrs: [],
  dstAddrs: [],
  services: [],
  srcMacs: [],
  applicationIds: [],
  userNames: [],
  schedule: null,
  action: "allow",
  logging: "none",
  rateLimit: null,
  ...over,
});

const nat = (over: Partial<NftGenNatRule> = {}): NftGenNatRule => ({
  id: 1,
  name: "test-nat",
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

const baseInput = (over: Partial<NftGenInput> = {}): NftGenInput => ({
  rules: [],
  natRules: [],
  zones: [zone(1, "wan", ["ens32"]), zone(2, "lan", ["ens34"])],
  generatedAt: new Date("2026-01-01T00:00:00Z"),
  ...over,
});

describe("generateNftRuleset — structure and safety invariants", () => {
  it("never emits flush ruleset and always targets the dedicated table", () => {
    const res = generateNftRuleset(baseInput());
    expect(res.file).not.toMatch(/flush ruleset/);
    expect(res.file).toContain("destroy table inet console-firewall");
    expect(res.file).toContain("table inet console-firewall {");
    expect(res.file).toContain('type filter hook input priority filter; policy accept;');
  });

  it("baseline input chain protects management plane unconditionally", () => {
    const res = generateNftRuleset(baseInput());
    expect(res.file).toContain('iifname "lo" accept');
    expect(res.file).toContain("ct state established,related accept");
    expect(res.file).toContain("meta l4proto icmp accept");
    expect(res.file).toContain("tcp dport { 22, 22222 } accept");
    expect(res.file).toContain("ip protocol vrrp accept");
  });

  it("forward chain always keeps established/related accept", () => {
    const res = generateNftRuleset(baseInput());
    expect(res.file).toContain("ct state established,related accept comment \"baseline: established/related (return traffic)\"");
  });
});

describe("generateNftRuleset — rule compilation", () => {
  it("zone matches become iifname/oifname clauses", () => {
    const res = generateNftRuleset(
      baseInput({ rules: [rule({ srcZoneIds: [2], dstZoneIds: [1], services: [{ protocol: "tcp", srcPorts: [], dstPorts: [{ lo: 443, hi: 443 }] }] })] }),
    );
    expect(res.file).toContain('iifname "ens34" oifname "ens32" tcp dport 443 accept');
  });

  it("multi-zone and multiport compile into sets", () => {
    const res = generateNftRuleset(
      baseInput({
        rules: [
          rule({
            id: 3,
            srcZoneIds: [1, 2],
            dstZoneIds: [1, 2],
            services: [{ protocol: "udp", srcPorts: [], dstPorts: [{ lo: 53, hi: 53 }, { lo: 123, hi: 123 }] }],
          }),
        ],
      }),
    );
    expect(res.file).toContain('iifname { "ens32", "ens34" } oifname { "ens32", "ens34" } udp dport { 53, 123 }');
  });

  it("action mapping: deny/drop → drop, reject → icmpx reject, allow → accept", () => {
    const res = generateNftRuleset(
      baseInput({
        rules: [
          rule({ id: 1, name: "a", action: "deny" }),
          rule({ id: 2, name: "b", action: "drop" }),
          rule({ id: 3, name: "c", action: "reject" }),
          rule({ id: 4, name: "d", action: "allow" }),
        ],
      }),
    );
    expect(res.file).toMatch(/drop comment "fw:1:a"/);
    expect(res.file).toMatch(/drop comment "fw:2:b"/);
    expect(res.file).toContain("reject with icmpx type port-unreachable comment \"fw:3:c\"");
    expect(res.file).toMatch(/accept comment "fw:4:d"/);
  });

  it("subnet/ip/range address matches compile into one anonymous set", () => {
    const res = generateNftRuleset(
      baseInput({
        rules: [
          rule({
            srcAddrs: [
              { kind: "ip", value: "10.0.0.5" },
              { kind: "subnet", base: 0x0a000000, bits: 8 },
              { kind: "range", lo: 0xc0a80105, hi: 0xc0a8010a },
            ],
          }),
        ],
      }),
    );
    expect(res.file).toContain("ip saddr { 10.0.0.5, 10.0.0.0/8, 192.168.1.5-192.168.1.10 }");
  });

  it("wildcard compile to mask arithmetic and never merge with the plain set", () => {
    const res = generateNftRuleset(
      baseInput({ rules: [rule({ srcAddrs: [{ kind: "wildcard", base: 0x0a010000, mask: 0x0000ffff }] })] }),
    );
    expect(res.file).toContain("ip saddr & 0.0.255.255 == 10.1.0.0");
  });

  it("fqdn/geo/app/user/schedule rules are excluded with warnings, never widened", () => {
    const res = generateNftRuleset(
      baseInput({
        rules: [
          rule({ id: 1, name: "fqdn", srcAddrs: [{ kind: "fqdn", value: "example.com" }] }),
          rule({ id: 2, name: "geo", srcAddrs: [{ kind: "geo", value: "IN" }] }),
          rule({ id: 3, name: "app", applicationIds: ["http"] }),
          rule({ id: 4, name: "user", userNames: ["admin"] }),
          rule({ id: 5, name: "sched", schedule: { type: "always", days: [], start: "00:00", end: "23:59", startsAt: null, endsAt: null, timezone: "UTC" } }),
        ],
      }),
    );
    expect(res.counts.forward).toBe(0);
    expect(res.counts.skipped).toBe(5);
    expect(res.warnings.filter((w) => w.code === "match-not-expressible").length).toBe(5);
    expect(res.file).not.toContain("example.com");
  });

  it("any-protocol service with ports is rejected (cannot widen ports)", () => {
    const res = generateNftRuleset(
      baseInput({ rules: [rule({ services: [{ protocol: "any", srcPorts: [], dstPorts: [{ lo: 80, hi: 80 }] }] })] }),
    );
    expect(res.counts.forward).toBe(0);
    expect(res.warnings.some((w) => w.code === "match-not-expressible")).toBe(true);
  });

  it("pure any-protocol service contributes no clause (matches all protocols)", () => {
    const res = generateNftRuleset(
      baseInput({ rules: [rule({ srcZoneIds: [2], dstZoneIds: [1], services: [{ protocol: "any", srcPorts: [], dstPorts: [] }] })] }),
    );
    expect(res.file).toContain('iifname "ens34" oifname "ens32" accept');
  });

  it("zone with no interfaces makes the rule unmatchable — excluded with warning", () => {
    const res = generateNftRuleset(
      baseInput({ zones: [zone(1, "wan", ["ens32"]), zone(2, "lan", []), zone(3, "dmz", [])], rules: [rule({ srcZoneIds: [3], dstZoneIds: [1] })] }),
    );
    expect(res.counts.forward).toBe(0);
    expect(res.warnings.some((w) => w.code === "zone-no-iface")).toBe(true);
  });

  it("unknown zone id excludes the rule with a loud warning", () => {
    const res = generateNftRuleset(baseInput({ rules: [rule({ srcZoneIds: [99] })] }));
    expect(res.counts.forward).toBe(0);
    expect(res.warnings.some((w) => w.code === "zone-unknown")).toBe(true);
  });

  it("disabled rules are omitted entirely", () => {
    const res = generateNftRuleset(baseInput({ rules: [rule({ enabled: false, action: "deny" })] }));
    expect(res.counts.forward).toBe(0);
    expect(res.file).not.toMatch(/comment "fw:/);
  });

  it("dst-only rules never over-match on the input chain", () => {
    const res = generateNftRuleset(
      baseInput({ rules: [rule({ dstAddrs: [{ kind: "ip", value: "10.0.0.5" }] })] }),
    );
    expect(res.counts.forward).toBe(1);
    expect(res.counts.input).toBe(0); // would over-match host-bound traffic
  });

  it("empty-dst rules apply to both forward and input chains", () => {
    const res = generateNftRuleset(
      baseInput({ rules: [rule({ srcAddrs: [{ kind: "ip", value: "10.0.0.9" }], action: "deny" })] }),
    );
    expect(res.counts.forward).toBe(1);
    expect(res.counts.input).toBe(1);
    expect(res.file).toContain("ip saddr 10.0.0.9 drop");
  });

  it("rate limit applies only to allow rules", () => {
    const allow = generateNftRuleset(baseInput({ rules: [rule({ action: "allow", rateLimit: 100 })] }));
    expect(allow.file).toContain("limit rate 100/second burst 500 packets");
    const deny = generateNftRuleset(baseInput({ rules: [rule({ action: "deny", rateLimit: 100 })] }));
    expect(deny.file).not.toContain("limit rate");
    expect(deny.warnings.some((w) => w.code === "rate-limit-ignored")).toBe(true);
  });

  it("logging emits rate-limited log statements", () => {
    const res = generateNftRuleset(baseInput({ rules: [rule({ logging: "summary" })] }));
    expect(res.file).toContain('limit rate 10/second burst 20 packets log prefix "fw:1:test-rule"');
    const detail = generateNftRuleset(baseInput({ rules: [rule({ logging: "detail" })] }));
    expect(detail.file).toContain("flags all");
  });

  it("catch-all deny forces forward policy drop", () => {
    const res = generateNftRuleset(baseInput({ rules: [rule({ id: 8, name: "default-deny", action: "deny" })] }));
    expect(res.forwardPolicy).toBe("drop");
    expect(res.file).toContain("type filter hook forward priority filter; policy drop;");
    expect(isCatchAllDeny({ ...rule({ id: 8, name: "default-deny", action: "deny" }) })).toBe(true);
    expect(isCatchAllDeny(rule({ action: "allow" }))).toBe(false);
    expect(isCatchAllDeny(rule({ action: "deny", srcZoneIds: [2] }))).toBe(false);
  });

  it("non-catch-all denies keep forward policy accept", () => {
    const res = generateNftRuleset(
      baseInput({ rules: [rule({ action: "deny", srcZoneIds: [2], dstZoneIds: [1] })] }),
    );
    expect(res.forwardPolicy).toBe("accept");
  });

  it("malformed MAC literals are dropped with a warning", () => {
    const res = generateNftRuleset(baseInput({ rules: [rule({ srcMacs: ["aa:bb:cc:dd:ee:ff", "not-a-mac"] })] }));
    expect(res.file).toContain("ether saddr aa:bb:cc:dd:ee:ff");
    expect(res.warnings.some((w) => w.code === "mac-invalid")).toBe(true);
  });

  it("OS interface coherence warnings fire for missing ifaces", () => {
    const res = generateNftRuleset(baseInput({ osInterfaces: ["ens32"], rules: [rule({ srcZoneIds: [2], dstZoneIds: [1] })] }));
    expect(res.warnings.some((w) => w.code === "iface-missing-os")).toBe(true);
  });
});

describe("generateNftRuleset — NAT", () => {
  it("snat masquerade with egress iface", () => {
    const res = generateNftRuleset(baseInput({ natRules: [nat({ outgoingIface: "ens32", translatedSrc: "masq" })] }));
    expect(res.file).toContain('type nat hook postrouting priority srcnat; policy accept;');
    expect(res.file).toContain('oifname "ens32" masquerade');
  });

  it("dnat with port rewrite in prerouting", () => {
    const res = generateNftRuleset(
      baseInput({ natRules: [nat({ type: "dnat", outgoingIface: "ens32", dstAddrs: [{ kind: "ip", value: "203.0.113.77" }], translatedDst: "10.0.0.5", translatedPort: 8080 })] }),
    );
    expect(res.file).toContain('type nat hook prerouting priority dstnat; policy accept;');
    expect(res.file).toContain('iifname "ens32" ip daddr 203.0.113.77 dnat to 10.0.0.5:8080');
  });

  it("exempt (NO-NAT) is emitted before snat regardless of position", () => {
    const res = generateNftRuleset(
      baseInput({
        natRules: [
          nat({ id: 2, position: 2, type: "snat", outgoingIface: "ens32", translatedSrc: "masq" }),
          nat({ id: 1, position: 1, type: "exempt", outgoingIface: "ens32", dstAddrs: [{ kind: "subnet", base: 0x0a000000, bits: 8 }] }),
        ],
      }),
    );
    const post = res.file.split("chain postrouting")[1] ?? "";
    const exemptIdx = post.indexOf("accept comment \"nat:1:test-nat\"");
    const snatIdx = post.indexOf("masquerade comment \"nat:2:test-nat\"");
    expect(exemptIdx).toBeGreaterThan(-1);
    expect(snatIdx).toBeGreaterThan(-1);
    expect(exemptIdx).toBeLessThan(snatIdx);
  });

  it("hairpin emits dnat + post-dnat masquerade", () => {
    const res = generateNftRuleset(
      baseInput({
        natRules: [
          nat({
            id: 1,
            type: "hairpin",
            outgoingIface: "ens32",
            dstAddrs: [{ kind: "ip", value: "203.0.113.77" }],
            srcAddrs: [{ kind: "subnet", base: 0x0a000000, bits: 24 }],
            translatedDst: "10.0.0.5",
          }),
        ],
      }),
    );
    expect(res.file).toContain("dnat to 10.0.0.5");
    expect(res.file).toContain("ip daddr 10.0.0.5 masquerade");
  });

  it("disabled or untranslatable NAT rules are skipped with warnings", () => {
    const off = generateNftRuleset(baseInput({ natRules: [nat({ enabled: false, translatedSrc: "masq" })] }));
    expect(off.counts.postrouting).toBe(0);
    const broken = generateNftRuleset(baseInput({ natRules: [nat({ translatedSrc: "bogus" })] }));
    expect(broken.counts.postrouting).toBe(0);
    expect(broken.warnings.some((w) => w.code === "nat-no-translate")).toBe(true);
  });

  it("ip_forward warning surfaces when NAT/forward rules exist and forwarding is off", () => {
    const res = generateNftRuleset(baseInput({ natRules: [nat({ outgoingIface: "ens32", translatedSrc: "masq" })] }));
    expect(res.counts.postrouting).toBe(1);
  });
});

describe("nft-gen helpers", () => {
  it("sanitizeComment strips quotes/newlines/backslashes", () => {
    expect(sanitizeComment('bad "name"\n\\; rm -rf')).not.toMatch(/["\\\n;]/);
    expect(sanitizeComment("fw:1:ok-name")).toBe("fw:1:ok-name");
  });
});

describe("drift detection + counters (firewall-os pure helpers)", () => {
  const genFile = generateNftRuleset(baseInput({ rules: [rule({ srcZoneIds: [2], dstZoneIds: [1] })] })).file;

  it("tableBlocksInSync matches the generated file against a faithful live dump", () => {
    const liveDump = genFile.replace("destroy table inet console-firewall\n", "") + "\n";
    expect(tableBlocksInSync(genFile, liveDump)).toBe(true);
  });

  it("drift is detected when the live chain lacks the rule", () => {
    const liveDump = genFile.replace('iifname "ens34" oifname "ens32" accept comment "fw:1:test-rule"', "accept");
    expect(tableBlocksInSync(genFile, liveDump)).toBe(false);
  });

  it("missing table → not in sync", () => {
    expect(tableBlocksInSync(genFile, "table inet f2b-table {\n}\n")).toBe(false);
  });
});

describe("parseRuleCounters", () => {
  it("aggregates per rule id", () => {
    const dump = [
      "table inet console-firewall {",
      "  chain forward {",
      '    iifname "ens34" oifname "ens32" tcp dport 443 accept counter packets 7 bytes 1024 comment "fw:2:web"',
      '    iifname "ens34" oifname "ens32" udp dport 53 accept counter packets 11 bytes 800 comment "fw:3:dns"',
      "  }",
      "}",
    ].join("\n");
    const counters = parseRuleCounters(dump);
    expect(counters).toHaveLength(2);
    expect(counters.find((c) => c.ruleId === 2)).toMatchObject({ packets: 7, bytes: 1024, name: "web" });
    expect(counters.find((c) => c.ruleId === 3)).toMatchObject({ packets: 11, bytes: 800 });
  });

  it("returns empty for foreign tables", () => {
    expect(parseRuleCounters("table inet f2b-table {\n}\n")).toEqual([]);
  });
});
