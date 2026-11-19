/**
 * DNS/DHCP validator regression tests (audit F-a fixes 11 + 12):
 *   • DNS record names get an owner-name grammar (letters/digits/dots/hyphens/
 *     underscores, ≤ 253) — quotes and spaces are rejected outright;
 *   • TXT values reject `"`, `'` and `\` — the unbound renderer escapes `"`
 *     but then wraps the local-data line in SINGLE quotes, so a `'` (or a
 *     bare `\`) corrupts the directive;
 *   • DHCP option codes outside 1-254 are rejected per-key (0 = pad, 255 =
 *     END) instead of being silently dropped by the kea renderer.
 */

import { describe, expect, it } from "vitest";
import {
  dnsRecordCreateSchema,
  dhcpSubnetCreateSchema,
  dhcpSubnetUpdateSchema,
} from "@/lib/validators/dns-dhcp";

const baseRecord = {
  zone: "corp.local",
  name: "web",
  type: "A",
  value: "10.99.99.10",
  ttl: 3600,
};

describe("dns record owner-name grammar", () => {
  it.each(["web", "_sip._tcp", "a.b-c.example", "host-1.sub_zone"])("accepts %s", (name) => {
    expect(dnsRecordCreateSchema.safeParse({ ...baseRecord, name }).success).toBe(true);
  });

  it.each(["bad name", "na'me", 'na"me', "na\\me", "na/me", ""])("rejects %s", (name) => {
    expect(dnsRecordCreateSchema.safeParse({ ...baseRecord, name }).success).toBe(false);
  });

  it("rejects names over 253 chars", () => {
    expect(dnsRecordCreateSchema.safeParse({ ...baseRecord, name: "a".repeat(254) }).success).toBe(false);
    expect(dnsRecordCreateSchema.safeParse({ ...baseRecord, name: "a".repeat(253) }).success).toBe(true);
  });
});

describe("dns TXT value grammar (renderer-safe)", () => {
  const txt = (value: string) => dnsRecordCreateSchema.safeParse({ ...baseRecord, type: "TXT", value });

  it("accepts plain SPF-like strings", () => {
    expect(txt("v=spf1 ip4:10.0.0.0/8 -all").success).toBe(true);
  });

  it.each(['has "double quotes"', "has 'single quotes'", "has \\backslash"])("rejects %j", (value) => {
    expect(txt(value).success).toBe(false);
  });

  it("still enforces the 255-char TXT limit", () => {
    expect(txt("x".repeat(256)).success).toBe(false);
    expect(txt("x".repeat(255)).success).toBe(true);
  });
});

describe("dhcp option codes are 1-254", () => {
  const subnet = {
    interfaceName: "lan0",
    subnetCidr: "10.99.99.0/24",
    rangeStart: "10.99.99.100",
    rangeEnd: "10.99.99.200",
  };

  it("accepts valid option codes", () => {
    const parsed = dhcpSubnetCreateSchema.parse({ ...subnet, options: { "1": "255.255.255.0", "254": "x" } });
    expect(parsed.options).toEqual({ "1": "255.255.255.0", "254": "x" });
  });

  it("rejects 0 (pad) and 255 (END) and non-numeric keys", () => {
    expect(dhcpSubnetCreateSchema.safeParse({ ...subnet, options: { "0": "x" } }).success).toBe(false);
    expect(dhcpSubnetCreateSchema.safeParse({ ...subnet, options: { "255": "x" } }).success).toBe(false);
    expect(dhcpSubnetCreateSchema.safeParse({ ...subnet, options: { "abc": "x" } }).success).toBe(false);
  });

  it("the PATCH schema validates options the same way without injecting defaults", () => {
    const bad = dhcpSubnetUpdateSchema.safeParse({ options: { "255": "x" } });
    expect(bad.success).toBe(false);
    const ok = dhcpSubnetUpdateSchema.parse({ options: { "42": "ntp.corp.local" } });
    expect(ok.options).toEqual({ "42": "ntp.corp.local" });
    expect("leaseTime" in ok).toBe(false);
  });

  it("absent options default to {}", () => {
    expect(dhcpSubnetCreateSchema.parse(subnet).options).toEqual({});
  });
});
