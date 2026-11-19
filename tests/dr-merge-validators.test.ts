/**
 * Dynamic-routing merge-then-revalidate regression tests (audit F-a fix 4).
 * The partial-update route files merge the PATCH with the stored row and
 * re-run the cross-field rules via these now-exported validators — pins the
 * guard semantics the routes rely on:
 *   • holdtimeOk: holdtime ≥ 3×keepalive, undefined-tolerant (merge fills both);
 *   • refinePrefixList: CIDR matches family, unique seq, ge ≤ le;
 *   • refineCommunityEntries: standard = AS:NN, expanded = compilable regex.
 */

import { describe, expect, it } from "vitest";
import {
  holdtimeOk,
  holdtimeMessage,
  refinePrefixList,
  refineCommunityEntries,
} from "@/lib/validators/dynamic-routing";

describe("holdtimeOk (BGP neighbor timers)", () => {
  it("passes when holdtime ≥ 3× keepalive", () => {
    expect(holdtimeOk(60, 180)).toBe(true);
    expect(holdtimeOk(3, 9)).toBe(true);
  });

  it("fails when holdtime < 3× keepalive (the merge-then-revalidate field error)", () => {
    expect(holdtimeOk(60, 120)).toBe(false);
  });

  it("is undefined-tolerant — a partial patch that omits either side passes the schema", () => {
    expect(holdtimeOk(undefined, 180)).toBe(true);
    expect(holdtimeOk(60, undefined)).toBe(true);
  });

  it("message stays stable for the route field errors", () => {
    expect(holdtimeMessage).toBe("holdtime must be at least 3× keepalive");
  });
});

describe("refinePrefixList (family / seq / ge ≤ le)", () => {
  const entry = (over: Partial<{ seq: number; prefix: string; ge: number | null; le: number | null }> = {}) => ({
    seq: 10,
    prefix: "10.0.0.0/8",
    ge: null,
    le: null,
    ...over,
  });

  it("accepts ipv4 CIDRs matching the list family", () => {
    expect(refinePrefixList({ family: "ipv4", entries: [entry(), entry({ seq: 20, prefix: "192.168.0.0/16" })] })).toBe(true);
  });

  it("rejects a family mismatch (e.g. ipv6 CIDR on an ipv4 list)", () => {
    expect(refinePrefixList({ family: "ipv4", entries: [entry({ prefix: "2001:db8::/32" })] })).toBe(false);
    expect(refinePrefixList({ family: "ipv6", entries: [entry()] })).toBe(false);
    expect(refinePrefixList({ family: "ipv6", entries: [entry({ prefix: "2001:db8::/32" })] })).toBe(true);
  });

  it("rejects duplicate seq and ge > le", () => {
    expect(refinePrefixList({ family: "ipv4", entries: [entry(), entry()] })).toBe(false);
    expect(refinePrefixList({ family: "ipv4", entries: [entry({ ge: 24, le: 16 })] })).toBe(false);
    expect(refinePrefixList({ family: "ipv4", entries: [entry({ ge: 16, le: 24 })] })).toBe(true);
  });
});

describe("refineCommunityEntries (AS:NN grammar / regex)", () => {
  it("standard lists require strict AS:NN", () => {
    expect(refineCommunityEntries("standard", ["65000:100", "64512:42"])).toBe(true);
    expect(refineCommunityEntries("standard", ["65000:100", "not-a-tag"])).toBe(false);
  });

  it("expanded lists require each entry to compile as a regex", () => {
    expect(refineCommunityEntries("expanded", ["^65000:", ".*"])).toBe(true);
    expect(refineCommunityEntries("expanded", ["^65000:("])).toBe(false); // invalid regex
  });
});
