/**
 * DLP engine + service tests (Phase 3 §3.3) — vitest.
 *
 * Part 1 exercises the PURE engine (no db): Aho-Corasick keyword matching
 * (multi-keyword, overlapping terms, case-insensitivity), guarded regex
 * build (invalid sources warn, never throw), and the redaction contract
 * (matched span masked with █ at preserved length, ≤16+16 context chars,
 * 120-char cap, raw content never present).
 *
 * Part 2 runs scan orchestration + policy validation against a MOCKED
 * @/lib/db (in-memory rows) — harness style mirrors tests/webhook-dispatcher
 * .test.ts (vi.hoisted state + vi.mock; mock only what the unit touches).
 * Covers: incidents created per (policy, pattern) with the PATTERN's
 * severity and the POLICY's action, protocol scoping, notifyUser+block
 * Notification fan-out, and patternIds validation rejecting unknown ids.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── fake db state (vi.hoisted so the vi.mock factory can see it) ────────────

interface FakePattern {
  id: number;
  tenantId: number;
  name: string;
  kind: string;
  value: string;
  severity: string;
  category: string;
  enabled: boolean;
}

interface FakePolicy {
  id: number;
  tenantId: number;
  name: string;
  protocols: string;
  patternIds: string;
  fileTypes: string;
  action: string;
  notifyUser: boolean;
  enabled: boolean;
}

interface FakeIncident {
  id: number;
  tenantId: number;
  policyId: number;
  patternId: number;
  severity: string;
  protocol: string;
  sourceIp: string;
  userName: string | null;
  excerpt: string;
  status: string;
  detail: string;
}

const h = vi.hoisted(() => ({
  patterns: [] as FakePattern[],
  policies: [] as FakePolicy[],
  incidents: [] as FakeIncident[],
  notifications: [] as Array<Record<string, unknown> & { id: number }>,
  nextId: 10,
}));

function inTenant(row: { tenantId: number }, tenantId?: number): boolean {
  return tenantId === undefined || row.tenantId === tenantId;
}

function idsIn(rawIds: string, wanted: number[]): boolean {
  const parsed: number[] = JSON.parse(rawIds) as number[];
  return parsed.some((id) => wanted.includes(id));
}

vi.mock("@/lib/db", () => ({
  db: {
    dlpPattern: {
      findMany: async (args?: {
        where?: { tenantId?: number; id?: { in: number[] }; enabled?: boolean };
      }) => {
        let rows = h.patterns.filter((p) => inTenant(p, args?.where?.tenantId));
        if (args?.where?.id?.in) rows = rows.filter((p) => args.where!.id!.in.includes(p.id));
        if (args?.where?.enabled !== undefined) rows = rows.filter((p) => p.enabled === args.where!.enabled);
        return rows;
      },
      findFirst: async (args?: { where?: { tenantId?: number; name?: string } }) =>
        h.patterns.find(
          (p) => inTenant(p, args?.where?.tenantId) && (args?.where?.name === undefined || p.name === args.where!.name),
        ) ?? null,
      create: async ({ data }: { data: Omit<FakePattern, "id"> }) => {
        const row: FakePattern = { ...data, id: ++h.nextId };
        h.patterns.push(row);
        return row;
      },
    },
    dlpPolicy: {
      findMany: async (args?: { where?: { tenantId?: number; enabled?: boolean } }) => {
        let rows = h.policies.filter((p) => inTenant(p, args?.where?.tenantId));
        if (args?.where?.enabled !== undefined) rows = rows.filter((p) => p.enabled === args.where!.enabled);
        return rows;
      },
      findFirst: async (args: { where: { tenantId?: number; name?: string } }) =>
        h.policies.find((p) => inTenant(p, args.where.tenantId) && (args.where.name === undefined || p.name === args.where.name)) ?? null,
      create: async ({ data }: { data: Omit<FakePolicy, "id"> }) => {
        const row: FakePolicy & { createdAt: Date } = { ...data, id: ++h.nextId, createdAt: new Date() };
        h.policies.push(row);
        return row;
      },
    },
    dlpIncident: {
      create: async ({ data }: { data: Omit<FakeIncident, "id"> }) => {
        const row: FakeIncident = { ...data, id: ++h.nextId };
        h.incidents.push(row);
        return row;
      },
    },
    notification: {
      create: async ({ data }: { data: Record<string, unknown> }) => {
        const row = { ...data, id: ++h.nextId };
        h.notifications.push(row);
        return row;
      },
    },
  },
}));

// ── imports under test (after the db mock is registered) ────────────────────

import { ApiError } from "@/lib/api/errors";
import {
  buildKeywordAutomaton,
  buildRegexMatchers,
  redactExcerpt,
  scanPayload,
  splitKeywords,
} from "@/lib/dlp/engine";
import { createPattern, createPolicy, scanTenant } from "@/lib/dlp/service";
import { dlpPatternCreateSchema } from "@/lib/validators/dlp";

// ── engine: keyword / Aho-Corasick ──────────────────────────────────────────

describe("scanPayload — keyword matcher (Aho-Corasick, SPEC §3.3)", () => {
  const kw = (id: number, value: string, severity = "medium") => ({
    id,
    kind: "keyword" as const,
    value,
    severity: severity as "low" | "medium" | "high" | "critical",
    category: "pii" as const,
  });

  it("finds every keyword of a comma-separated list, with correct spans", () => {
    const r = scanPayload({ text: "alpha BETA delta gamma", patterns: [kw(1, "alpha,beta,gamma")] });
    expect(r.matches).toHaveLength(3);
    expect(r.matches.map((m) => m.index).sort((a, b) => a - b)).toEqual([0, 6, 17]);
    expect(r.severity).toBe("medium");
    expect(r.warnings).toEqual([]);
  });

  it("matches overlapping terms (she/he/hers in 'ushers') without losing hits", () => {
    const r = scanPayload({ text: "ushers", patterns: [kw(1, "he,she,his,hers")] });
    expect(r.matches).toHaveLength(3); // she(1), he(2), hers(2) — 'his' absent
    const spans = r.matches
      .map((m) => [m.index, m.end])
      .sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    expect(spans).toEqual([
      [1, 4], // she
      [2, 4], // he
      [2, 6], // hers
    ]);
  });

  it("matches across patterns sharing terms (dedupe per patternId+span)", () => {
    const r = scanPayload({ text: "secret data", patterns: [kw(1, "secret"), kw(2, "secret data")] });
    const ids = r.matches.map((m) => m.patternId).sort((a, b) => a - b);
    expect(ids).toEqual([1, 2]);
  });

  it("is case-insensitive in both keywords and text", () => {
    const r = scanPayload({ text: "CONFIDENTIAL memo — cOnFiDeNtIaL again", patterns: [kw(1, "confidential")] });
    expect(r.matches).toHaveLength(2);
    expect(r.matches.every((m) => m.excerpt.includes("\u2588"))).toBe(true);
  });

  it("carries per-pattern severity/category and computes max severity", () => {
    const r = scanPayload({
      text: "internal use only and criticalstuff",
      patterns: [kw(1, "internal use only", "high"), kw(2, "criticalstuff", "critical")],
    });
    expect(r.matches.find((m) => m.patternId === 1)?.severity).toBe("high");
    expect(r.matches.find((m) => m.patternId === 2)?.severity).toBe("critical");
    expect(r.severity).toBe("critical");
  });

  it("reports nothing for non-matching text and empty pattern sets", () => {
    expect(scanPayload({ text: "all clear", patterns: [kw(1, "confidential")] }).matches).toEqual([]);
    expect(scanPayload({ text: "all clear", patterns: [] }).severity).toBeNull();
    expect(splitKeywords("a, b ,,c")).toEqual(["a", "b", "c"]);
  });

  it("caps keyword hit collection at MAX_MATCHES (100) and stops scanning", () => {
    const text = Array.from({ length: 150 }, () => "secret").join(" ");
    const r = scanPayload({ text, patterns: [kw(1, "secret")] });
    expect(r.matches).toHaveLength(100);
  });

  it("builds a deduplicated automaton (buildKeywordAutomaton)", () => {
    const { automaton, owners } = buildKeywordAutomaton([kw(1, "dup,dup,other")]);
    expect(owners.map((o) => o[0].term)).toEqual(["dup", "other"]);
    expect(automaton.terms).toEqual(["dup", "other"]);
  });

  it("keeps ALL owners for a shared term and fans hits out to every owner pattern", () => {
    // pattern 1 and pattern 2 both declare "secret" — the hit must be
    // attributed to BOTH (audit fix F-d: previously only the first pattern
    // was credited, silently starving policies that shared a keyword)
    const { automaton, owners } = buildKeywordAutomaton([kw(1, "secret,inner"), kw(2, "SECRET,data")]);
    expect(automaton.terms).toEqual(["secret", "inner", "data"]);
    expect(owners[0].map((o) => o.patternId)).toEqual([1, 2]); // shared term
    expect(owners[1].map((o) => o.patternId)).toEqual([1]);
    expect(owners[2].map((o) => o.patternId)).toEqual([2]);

    const r = scanPayload({ text: "secret data", patterns: [kw(1, "secret,data"), kw(2, "secret,data")] });
    const ids = r.matches.map((m) => m.patternId).sort((a, b) => a - b);
    expect(ids).toEqual([1, 1, 2, 2]); // both spans × both owners
    expect(r.matches.filter((m) => m.patternId === 1)).toHaveLength(2);
    expect(r.matches.filter((m) => m.patternId === 2)).toHaveLength(2);
  });
});

// ── engine: regex + invalid-pattern warnings ────────────────────────────────

describe("scanPayload — regex matcher (guarded build)", () => {
  const rx = (id: number, value: string, severity = "high") => ({
    id,
    kind: "regex" as const,
    value,
    severity: severity as "low" | "medium" | "high" | "critical",
    category: "financial" as const,
  });

  it("matches every occurrence of a valid regex", () => {
    const r = scanPayload({
      text: "ssn 123-45-6789 and again 987-65-4321",
      patterns: [rx(7, "\\b\\d{3}-\\d{2}-\\d{4}\\b")],
    });
    expect(r.matches).toHaveLength(2);
    expect(r.matches[0].severity).toBe("high");
    expect(r.matches[0].kind).toBe("regex");
  });

  it("collects a build warning for invalid regex and still matches the rest", () => {
    const r = scanPayload({
      text: "ssn 123-45-6789",
      patterns: [rx(1, "([unclosed"), rx(2, "\\d{3}-\\d{2}-\\d{4}")],
    });
    expect(r.matches).toHaveLength(1);
    expect(r.matches[0].patternId).toBe(2);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings[0]).toContain("Pattern #1");
    expect(r.warnings[0]).toContain("invalid regular expression");
  });

  it("aborts remaining regex work and records the budget warning past the deadline", () => {
    // drive the wall-clock deadline without a genuinely slow regex: each mock
    // call advances the clock +5s over the previous one, so scanStart's
    // (first) call and the per-chunk guard's call are always > 2000ms apart —
    // independent of any vitest-internal Date.now consumers in between
    const realNow = Date.now.bind(Date);
    let calls = 0;
    const spy = vi.spyOn(Date, "now").mockImplementation(() => {
      calls += 1;
      return realNow() + (calls - 1) * 5000;
    });
    try {
      const r = scanPayload({ text: "abcdef", patterns: [rx(1, "abc")] });
      expect(r.matches).toHaveLength(0);
      expect(r.warnings.some((w) => w.includes("scan budget exceeded"))).toBe(true);
    } finally {
      spy.mockRestore();
    }
  });

  it("buildRegexMatchers never throws at build or scan time", () => {
    const warnings: string[] = [];
    expect(buildRegexMatchers([rx(3, "*bad*"), rx(4, "(?P<name>x)")], warnings)).toHaveLength(0);
    expect(warnings).toHaveLength(2);
    // zero-width regex must not hang the scan
    const r = scanPayload({ text: "abc", patterns: [rx(5, "x*")] });
    expect(r.matches.every((m) => m.index >= 0 && m.excerpt.length > 0)).toBe(true);
  });
});

// ── engine: redaction contract ──────────────────────────────────────────────

describe("redaction — span masked, length preserved, 16+16 context, 120 cap", () => {
  const kw = (value: string, severity = "critical") => ({
    id: 1,
    kind: "keyword" as const,
    value,
    severity: severity as "low" | "medium" | "high" | "critical",
    category: "credentials" as const,
  });

  it("replaces the matched span with █ at preserved length (16+16 context)", () => {
    const text = `${"a".repeat(20)}TOPSECRET${"b".repeat(20)}`;
    const r = scanPayload({ text, patterns: [kw("topsecret")] });
    expect(r.matches).toHaveLength(1);
    const ex = r.matches[0].excerpt;
    // 16 a's + 9 blocks + 16 b's = 41
    expect(ex.length).toBe(41);
    expect(ex).toBe(`${"a".repeat(16)}${"\u2588".repeat(9)}${"b".repeat(16)}`);
    expect(ex).not.toContain("TOPSECRET");
  });

  it("clamps context at text boundaries", () => {
    expect(redactExcerpt("topsecret", 0, 9)).toBe("\u2588".repeat(9));
    const ex = redactExcerpt(`${"x".repeat(30)}token${"y".repeat(2)}`, 30, 35);
    expect(ex).toBe(`${"x".repeat(16)}${"\u2588".repeat(5)}yy`); // 16 context + mask + short tail
    expect(ex.length).toBe(16 + 5 + 2);
  });

  it("caps the excerpt at 120 chars even for huge matches", () => {
    const ex = redactExcerpt(`${"p".repeat(10)}${"z".repeat(200)}q`, 10, 210);
    expect(ex.length).toBeLessThanOrEqual(120);
    expect(ex).toContain("\u2588");
    expect(ex).toContain("p".repeat(10)); // leading context survives the cap
  });

  it("keeps the raw match out of the DB-bound excerpt for long regex hits", () => {
    const secret = `${"k".repeat(80)}-9`;
    // kind=keyword matches literals — "k{80}-9" is NOT a quantifier there (honest behavior)
    const r = scanPayload({ text: `${"pad ".repeat(5)}${secret}`, patterns: [kw("k{80}-9")] });
    expect(r.matches).toHaveLength(0);
    const rx = scanPayload({
      text: `${"pad ".repeat(5)}${secret}`,
      patterns: [{ id: 9, kind: "regex", value: "k{80}-9", severity: "high", category: "custom" }],
    });
    expect(rx.matches).toHaveLength(1);
    expect(rx.matches[0].end - rx.matches[0].index).toBe(82);
    expect(rx.matches[0].excerpt).not.toContain(secret);
    expect(rx.matches[0].excerpt).toContain("\u2588");
  });
});

// ── service: DB harness — patternIds validation + scan orchestration ────────

describe("ReDoS guard — nested quantifiers rejected at create (audit fix F-d)", () => {
  beforeEach(() => seedIncidentTables());

  it("the zod edge rejects classic catastrophic shapes with the documented message", () => {
    for (const bad of ["(a+)+", "(\\w*)*", "(?:x+){2,}", "^([a-z]+)*$"]) {
      const r = dlpPatternCreateSchema.safeParse({ name: "boom", kind: "regex", value: bad });
      expect(r.success).toBe(false);
      if (!r.success) {
        expect(JSON.stringify(r.error.issues)).toContain("nested quantifiers rejected (ReDoS guard)");
      }
    }
    // keywords are literals — the same shape is legal there
    expect(dlpPatternCreateSchema.safeParse({ name: "kw", kind: "keyword", value: "(a+)+,x" }).success).toBe(true);
    // and ordinary regexes are unaffected
    expect(dlpPatternCreateSchema.safeParse({ name: "ok", kind: "regex", value: "\\b\\d{3}-\\d{2}-\\d{4}\\b" }).success).toBe(true);
  });

  it("the service throws (nothing written) for service callers bypassing zod", async () => {
    const before = h.patterns.length;
    const err: unknown = await createPattern(1, {
      name: "redos-bomb",
      kind: "regex",
      value: "(a+)+",
      severity: "high",
      category: "pii",
      enabled: true,
    }).then(
      () => null,
      (e) => e,
    );
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).message).toContain("nested quantifiers rejected (ReDoS guard)");
    expect(h.patterns.length).toBe(before); // nothing written
  });
});

function seedPattern(over: Partial<FakePattern> = {}): FakePattern {
  const row: FakePattern = {
    id: over.id ?? 11,
    tenantId: 1,
    name: "keywords-pii",
    kind: "keyword",
    value: "confidential,internal use only",
    severity: "high",
    category: "pii",
    enabled: true,
    ...over,
  };
  h.patterns.push(row);
  return row;
}

function seedPolicy(over: Partial<FakePolicy> = {}): FakePolicy {
  const row: FakePolicy = {
    id: over.id ?? 21,
    tenantId: 1,
    name: "egress-dlp",
    protocols: '["http","smtp"]',
    patternIds: "[11]",
    fileTypes: "[]",
    action: "block",
    notifyUser: true,
    enabled: true,
    ...over,
  };
  h.policies.push(row);
  return row;
}

function seedIncidentTables(): void {
  h.patterns.length = 0;
  h.policies.length = 0;
  h.incidents.length = 0;
  h.notifications.length = 0;
}

describe("service — policy patternIds validation (mocked db)", () => {
  beforeEach(() => seedIncidentTables());

  it("rejects unknown pattern ids with a field error listing them", async () => {
    const err: unknown = await createPolicy(1, {
      name: "bad-policy",
      protocols: ["http"],
      patternIds: [999, 777],
      fileTypes: [],
      action: "alert",
      notifyUser: false,
      enabled: true,
    }).then(
      () => null,
      (e) => e,
    );
    expect(err).toBeInstanceOf(ApiError);
    const apiErr = err as ApiError;
    expect(apiErr.code).toBe("VALIDATION_ERROR");
    const fe = (apiErr.details as { fieldErrors?: Record<string, string[]> }).fieldErrors;
    expect(fe?.patternIds?.[0]).toContain("999");
    expect(fe?.patternIds?.[0]).toContain("777");
    expect(h.policies).toHaveLength(0); // nothing written
  });

  it("accepts ids that exist in-tenant and dedupes them", async () => {
    seedPattern({ id: 11, name: "p1" });
    const created = await createPolicy(1, {
      name: "ok-policy",
      protocols: ["http"],
      patternIds: [11, 11],
      fileTypes: [],
      action: "alert",
      notifyUser: false,
      enabled: true,
    });
    expect(created.patternIds).toEqual([11]);
    expect(JSON.parse(h.policies[0].patternIds)).toEqual([11]);
  });
});

describe("service — scanTenant orchestration (mocked db)", () => {
  beforeEach(() => seedIncidentTables());

  it("creates incidents per (policy, matched pattern) with pattern severity + policy action, redacted excerpts", async () => {
    seedPattern({ id: 11, name: "kw-pii", kind: "keyword", value: "confidential,internal use only", severity: "high" });
    seedPattern({ id: 12, name: "rx-ssn", kind: "regex", value: "\\b\\d{3}-\\d{2}-\\d{4}\\b", severity: "critical", category: "pii" });
    seedPolicy({ id: 21, name: "block-http", protocols: '["http"]', patternIds: "[11,12]", action: "block", notifyUser: true });
    seedPolicy({ id: 22, name: "alert-http", protocols: '["http"]', patternIds: "[11]", action: "alert", notifyUser: false });

    const outcome = await scanTenant(1, {
      protocol: "http",
      sourceIp: "10.0.20.15",
      userName: "jdoe",
      text: "internal use only — send SSN 123-45-6789 tonight",
    });

    // 2 patterns matched under policy 21 + 1 pattern under policy 22
    expect(outcome.incidents).toBe(3);
    expect(outcome.severity).toBe("critical");
    expect(h.incidents).toHaveLength(3);
    expect(h.notifications).toHaveLength(1); // only policy 21 (notifyUser && block)

    const p21 = h.incidents.filter((i) => i.policyId === 21);
    expect(p21.map((i) => i.patternId).sort((a, b) => a - b)).toEqual([11, 12]);
    expect(p21.find((i) => i.patternId === 11)!.severity).toBe("high");
    expect(p21.find((i) => i.patternId === 12)!.severity).toBe("critical");
    for (const inc of p21) {
      const detail = JSON.parse(inc.detail) as { matchedPattern?: string; action?: string; fileTypeBlocked?: boolean };
      expect(detail.action).toBe("block");
      expect(detail.matchedPattern).toMatch(/kw-pii|rx-ssn/);
    }

    const kwIncident = p21.find((i) => i.patternId === 11)!;
    expect(kwIncident.excerpt).toContain("\u2588");
    expect(kwIncident.excerpt).not.toContain("internal use only"); // raw text never stored
    expect(kwIncident.status).toBe("new");
    expect(kwIncident.sourceIp).toBe("10.0.20.15");
    expect(kwIncident.userName).toBe("jdoe");
    expect(h.notifications[0].sourceModule).toBe("dlp");
    expect(String(h.notifications[0].title)).toContain("block-http");
  });

  it("scopes policies by protocol and skips disabled patterns", async () => {
    seedPattern({ id: 11, name: "kw", value: "confidential", severity: "medium" });
    seedPattern({ id: 12, name: "off", value: "confidential", enabled: false });
    seedPolicy({ id: 21, protocols: '["smtp"]', patternIds: "[11,12]", action: "alert", notifyUser: false });
    seedPolicy({ id: 22, protocols: '["ftp"]', patternIds: "[11]", enabled: false });

    const outcome = await scanTenant(1, {
      protocol: "smtp",
      sourceIp: "10.0.0.9",
      text: "confidential attachment",
    });
    expect(outcome.incidents).toBe(1); // only policy 21 (smtp) × pattern 11 (enabled)
    expect(h.incidents[0].policyId).toBe(21);
    expect(h.incidents[0].protocol).toBe("smtp");
    expect(h.notifications).toHaveLength(0); // action alert — no notification
  });

  it("no scan when no enabled policy covers the protocol", async () => {
    seedPattern({ id: 11, name: "kw", value: "confidential" });
    seedPolicy({ id: 21, protocols: '["smtp"]' });
    const outcome = await scanTenant(1, { protocol: "http", sourceIp: "10.0.0.9", text: "confidential" });
    expect(outcome.incidents).toBe(0);
    expect(outcome.matches).toEqual([]);
    expect(h.incidents).toHaveLength(0);
  });

  it("flags fileTypeBlocked in the detail when the extension is on the block list", async () => {
    seedPattern({ id: 11, name: "kw", value: "confidential", severity: "high" });
    seedPolicy({ id: 21, patternIds: "[11]", fileTypes: '["pdf"]', action: "quarantine", notifyUser: true });
    const outcome = await scanTenant(1, {
      protocol: "http",
      sourceIp: "10.0.0.9",
      text: "confidential",
      fileExtension: ".PDF",
    });
    expect(outcome.incidents).toBe(1);
    const detail = JSON.parse(h.incidents[0].detail) as { fileTypeBlocked?: boolean; action?: string };
    expect(detail.fileTypeBlocked).toBe(true);
    expect(detail.action).toBe("quarantine");
    expect(h.notifications).toHaveLength(1); // notifyUser && quarantine
  });

  it("idsIn helper sanity (mocked-db JSON column shape)", () => {
    expect(idsIn("[11,12]", [12])).toBe(true);
    expect(idsIn("[11,12]", [99])).toBe(false);
  });
});
