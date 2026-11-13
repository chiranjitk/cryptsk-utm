import { describe, it, expect } from "vitest";
import { ipsPolicyCreateSchema, ipsPolicyUpdateSchema } from "@/lib/validators/ips";
import { vpnUserGroupCreateSchema, vpnUserGroupUpdateSchema } from "@/lib/validators/vpn";
import { dhcpSubnetCreateSchema, dhcpSubnetUpdateSchema } from "@/lib/validators/dns-dhcp";

/**
 * Regression: zod v4 `.partial()` still fires field defaults for ABSENT keys,
 * which silently reset policy fields on every PATCH-style PUT (observed live:
 * an exceptions-only edit force-reset policy mode to inline_drop). Update
 * schemas must inject NOTHING for absent keys while create schemas keep
 * their defaults.
 */

describe("ipsPolicyUpdateSchema — PATCH semantics (no default injection)", () => {
  it("create schema keeps its defaults", () => {
    const created = ipsPolicyCreateSchema.parse({ name: "p1" });
    expect(created.mode).toBe("inline_drop");
    expect(created.enabled).toBe(true);
    expect(created.tiBlocklist).toBe(false);
  });

  it("absent keys stay absent on a partial update", () => {
    const parsed = ipsPolicyUpdateSchema.parse({ exceptions: [{ sid: 1000001 }] });
    expect(parsed.mode).toBeUndefined();
    expect(parsed.enabled).toBeUndefined();
    expect(parsed.ruleCategories).toBeUndefined();
    expect(parsed.customRules).toBeUndefined();
    expect(parsed.thresholds).toBeUndefined();
    expect(parsed.preprocessors).toBeUndefined();
    expect(parsed.tiBlocklist).toBeUndefined();
    expect(parsed.name).toBeUndefined();
    expect(parsed.exceptions).toEqual([{ sid: 1000001 }]);
  });

  it("an exceptions-only edit does not force-reset the policy mode", () => {
    const parsed = ipsPolicyUpdateSchema.parse({ exceptions: [], customRules: [] });
    expect("mode" in parsed).toBe(false);
    expect(parsed.mode).toBeUndefined();
  });

  it("explicit values still validate and pass through", () => {
    const parsed = ipsPolicyUpdateSchema.parse({ mode: "passive", enabled: false });
    expect(parsed.mode).toBe("passive");
    expect(parsed.enabled).toBe(false);
  });

  it("rejects an empty update", () => {
    expect(ipsPolicyUpdateSchema.safeParse({}).success).toBe(false);
  });
});

describe("vpnUserGroupUpdateSchema — membership is not wiped by a name edit", () => {
  it("absent memberUsernames stays absent", () => {
    const parsed = vpnUserGroupUpdateSchema.parse({ name: "renamed" });
    expect(parsed.memberUsernames).toBeUndefined();
    expect(parsed.name).toBe("renamed");
  });

  it("explicit memberUsernames still validate", () => {
    const parsed = vpnUserGroupUpdateSchema.parse({ memberUsernames: ["alice"] });
    expect(parsed.memberUsernames).toEqual(["alice"]);
  });

  it("create schema keeps its empty-membership default", () => {
    expect(vpnUserGroupCreateSchema.parse({ name: "g1" }).memberUsernames).toEqual([]);
  });
});

describe("dhcpSubnetUpdateSchema — partial update preserves lease/dns/options", () => {
  it("absent fields stay absent (no leaseTime 86400 reset, no dns/options wipe)", () => {
    const parsed = dhcpSubnetUpdateSchema.parse({ enabled: false });
    expect(parsed.leaseTime).toBeUndefined();
    expect(parsed.dnsServers).toBeUndefined();
    expect(parsed.options).toBeUndefined();
    expect(parsed.family).toBeUndefined();
    expect(parsed.enabled).toBe(false);
  });

  it("create schema keeps its defaults", () => {
    const created = dhcpSubnetCreateSchema.parse({
      interfaceName: "ens34",
      subnetCidr: "10.99.99.0/24",
      rangeStart: "10.99.99.100",
      rangeEnd: "10.99.99.200",
    });
    expect(created.leaseTime).toBe(86400);
    expect(created.family).toBe("ipv4");
    expect(created.dnsServers).toEqual([]);
  });
});
