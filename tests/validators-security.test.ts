/**
 * Validator security regressions (audit F-b):
 *   • IPS exception source/dest must match the strict IPv4/CIDR grammar — both
 *     fields are interpolated verbatim into suricata threshold.config, so an
 *     injection string must be rejected at the edge (validators/ips.ts).
 *   • Custom IPS rules must be single-line — CR/LF inside a rule would inject
 *     additional lines into the managed rules file.
 *   • The IPS events severity csv filter only accepts the locked severity vocab.
 */

import { describe, it, expect } from "vitest";
import {
  customRulesSchema,
  exceptionSchema,
  ipsEventsQuerySchema,
  IPS_IPV4_CIDR_RE,
  ipsPolicyCreateSchema,
} from "@/lib/validators/ips";

describe("IPS exception scope grammar (threshold.config injection guard)", () => {
  it("accepts IPv4 addresses and CIDRs (0-32) for source/dest", () => {
    expect(
      exceptionSchema.safeParse({ sid: 2200001, source: "10.0.0.5", dest: "192.168.10.0/24" }).success,
    ).toBe(true);
    expect(exceptionSchema.safeParse({ sid: 2200001, source: "203.0.113.9/32" }).success).toBe(true);
    expect(exceptionSchema.safeParse({ sid: 2200001, source: "0.0.0.0/0" }).success).toBe(true);
    // absent / null / empty stay valid (no scope)
    expect(exceptionSchema.safeParse({ sid: 2200001 }).success).toBe(true);
    expect(exceptionSchema.safeParse({ sid: 2200001, source: null, dest: "" }).success).toBe(true);
  });

  it("rejects injection strings, hostnames and malformed values", () => {
    for (const bad of ["10.0.0.5; drop", "10.0.0.5\nsuppress", "$(id)", "any", "example.com", "10.0.0", "10.0.0.5/33", "999.1.2.3"]) {
      const res = exceptionSchema.safeParse({ sid: 2200002, source: bad });
      expect(res.success).toBe(false);
    }
    // dest gets the same grammar
    expect(exceptionSchema.safeParse({ sid: 2200003, dest: "10.0.0.5; drop" }).success).toBe(false);
  });

  it("exports the shared grammar regex and it agrees with the schema", () => {
    expect(IPS_IPV4_CIDR_RE.test("10.0.0.1")).toBe(true);
    expect(IPS_IPV4_CIDR_RE.test("10.0.0.1/24")).toBe(true);
    expect(IPS_IPV4_CIDR_RE.test("10.0.0.1/33")).toBe(false);
    expect(IPS_IPV4_CIDR_RE.test("256.0.0.1")).toBe(false);
    expect(IPS_IPV4_CIDR_RE.test("10.0.0.1 drop")).toBe(false);
  });

  it("create schema surfaces the field error through ipsPolicyCreateSchema", () => {
    const res = ipsPolicyCreateSchema.safeParse({
      name: "p",
      exceptions: [{ sid: 1, source: "evil;drop" }],
    });
    expect(res.success).toBe(false);
  });
});

describe("customRulesSchema — CR/LF injection rejected", () => {
  const goodRule = "alert tcp any any -> any any (msg:\"x\"; sid:1000001;)";
  it("accepts a clean single-line rule", () => {
    expect(customRulesSchema.safeParse([goodRule]).success).toBe(true);
  });
  it("rejects embedded newlines / carriage returns (rule-injection into managed file)", () => {
    expect(customRulesSchema.safeParse([`${goodRule}\ndrop tcp any any -> any any (sid:1000002;)`]).success).toBe(false);
    expect(customRulesSchema.safeParse([`${goodRule}\r`]).success).toBe(false);
  });
});

describe("ipsEventsQuerySchema — severity csv is locked-vocab", () => {
  it("accepts a csv of valid severities (and empty)", () => {
    expect(ipsEventsQuerySchema.safeParse({ severity: "high,critical" }).success).toBe(true);
    expect(ipsEventsQuerySchema.safeParse({ severity: "" }).success).toBe(true);
  });
  it("rejects unknown severity tokens with a field error", () => {
    const res = ipsEventsQuerySchema.safeParse({ severity: "high,severe" });
    expect(res.success).toBe(false);
    // "warning" is the THREAT-INTEL scale — not the locked IPS vocab (info|low|medium|high|critical)
    expect(ipsEventsQuerySchema.safeParse({ severity: "warning" }).success).toBe(false);
    expect(ipsEventsQuerySchema.safeParse({ severity: "medium" }).success).toBe(true);
  });
});
