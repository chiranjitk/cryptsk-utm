import { describe, it, expect } from "vitest";
import {
  MARKER_BEGIN,
  MARKER_END,
  MANAGED_RULES_NAME,
  normalizeIpsAction,
  countRulesInText,
  generateManagedRules,
  buildThresholdEntries,
  generateThresholdBlock,
  replaceManagedBlock,
  yamlAppendRuleFile,
  yamlEnsureThresholdFile,
  computeIpsDrift,
  type IpsGenInput,
} from "@/lib/ips/ips-os";

// ── fixtures ────────────────────────────────────────────────────────────────

const policyInput = (over: Partial<NonNullable<IpsGenInput["policy"]>> = {}): IpsGenInput => ({
  policy: {
    id: 7,
    name: "wan-guard",
    mode: "inline_drop",
    customRules: [],
    exceptions: [],
    thresholds: [],
    ...over,
  },
});

const noPolicy: IpsGenInput = { policy: null };

// ── normalizeIpsAction ──────────────────────────────────────────────────────

describe("normalizeIpsAction", () => {
  it("passes through valid enum values", () => {
    expect(normalizeIpsAction("alert")).toBe("alert");
    expect(normalizeIpsAction("drop")).toBe("drop");
    expect(normalizeIpsAction("reject")).toBe("reject");
    expect(normalizeIpsAction("bypass")).toBe("bypass");
    expect(normalizeIpsAction("suppressed")).toBe("suppressed");
  });

  it("maps legacy EVE parser values onto the locked enum", () => {
    expect(normalizeIpsAction("allowed")).toBe("alert"); // passive IDS verdict
    expect(normalizeIpsAction("blocked")).toBe("drop"); // inline drop verdict
  });

  it("falls back to alert for unknown values", () => {
    expect(normalizeIpsAction("weird")).toBe("alert");
    expect(normalizeIpsAction(null)).toBe("alert");
    expect(normalizeIpsAction(undefined)).toBe("alert");
  });
});

// ── countRulesInText ────────────────────────────────────────────────────────

describe("countRulesInText", () => {
  it("counts actions and unique sids, skipping comments", () => {
    const text = [
      "# comment line",
      "alert tcp any any -> any 80 (msg:\"a\"; sid:1;)",
      "alert tcp any any -> any 443 (msg:\"b\"; sid:2;)",
      "drop tcp any any -> any 22 (msg:\"c\"; sid:2;)", // duplicate sid counted once
      "pass ip any any -> any (msg:\"d\"; sid:3;)",
      "",
    ].join("\n");
    expect(countRulesInText(text)).toEqual({ sids: 3, alert: 2, drop: 1, pass: 1, reject: 0 });
  });

  it("handles empty text", () => {
    expect(countRulesInText("")).toEqual({ sids: 0, alert: 0, drop: 0, pass: 0, reject: 0 });
  });
});

// ── generateManagedRules ────────────────────────────────────────────────────

describe("generateManagedRules", () => {
  it("writes custom rules verbatim under a generated header", () => {
    const gen = policyInput({
      customRules: ["alert tcp $HOME_NET any -> any 443 (msg:\"custom\"; sid:9000001; rev:1;)"],
    });
    const out = generateManagedRules(gen, "2026-01-01T00:00:00.000Z");
    expect(out).toContain(MANAGED_RULES_NAME);
    expect(out).toContain("policy: wan-guard (id=7, mode=inline_drop)");
    expect(out).toContain("alert tcp $HOME_NET any -> any 443 (msg:\"custom\"; sid:9000001; rev:1;)");
  });

  it("emits a placeholder when the policy has no custom rules", () => {
    const out = generateManagedRules(policyInput(), "2026-01-01T00:00:00.000Z");
    expect(out).toContain("(no custom rules in the active policy)");
  });

  it("notes the absence of any enabled policy", () => {
    const out = generateManagedRules(noPolicy, "2026-01-01T00:00:00.000Z");
    expect(out).toContain("policy: (none enabled)");
    expect(out).toContain("(no custom rules in the active policy)");
  });
});

// ── buildThresholdEntries ───────────────────────────────────────────────────

describe("buildThresholdEntries", () => {
  it("converts sid-scoped exceptions into suppress lines", () => {
    const { lines } = buildThresholdEntries(
      policyInput({ exceptions: [{ sid: 2200001, source: "10.0.0.5", comment: "false positive" }] }),
    );
    expect(lines).toContain("suppress gen_id 1, sig_id 2200001, track by_src, ip 10.0.0.5;");
  });

  it("uses by_dst tracking when only dest is set", () => {
    const { lines } = buildThresholdEntries(policyInput({ exceptions: [{ sid: 2200002, dest: "192.168.10.0/24" }] }));
    expect(lines).toContain("suppress gen_id 1, sig_id 2200002, track by_dst, ip 192.168.10.0/24;");
  });

  it("suppresses a scoped sid globally when neither source nor dest is set", () => {
    const { lines } = buildThresholdEntries(policyInput({ exceptions: [{ sid: 2200003 }] }));
    expect(lines).toContain("suppress gen_id 1, sig_id 2200003;");
  });

  it("converts sid 0 bypasses into any-SID suppress lines scoped by source", () => {
    const { lines } = buildThresholdEntries(policyInput({ exceptions: [{ sid: 0, source: "10.0.0.0/24" }] }));
    expect(lines).toContain("suppress gen_id 1, sig_id 0, track by_src, ip 10.0.0.0/24;");
  });

  it("refuses an unscoped sid 0 bypass with a warning (would silence the whole ruleset)", () => {
    const { lines, warnings } = buildThresholdEntries(policyInput({ exceptions: [{ sid: 0 }] }));
    expect(lines).toHaveLength(0);
    expect(warnings.some((w) => w.includes("ENTIRE ruleset"))).toBe(true);
  });

  it("converts thresholds into threshold lines with track/count/seconds", () => {
    const { lines } = buildThresholdEntries(policyInput({ thresholds: [{ sid: 2100005, track: "by_src", count: 10, seconds: 60 }] }));
    expect(lines).toContain("threshold gen_id 1, sig_id 2100005, track by_src, count 10, seconds 60;");
  });

  it("handles exceptions and thresholds together", () => {
    const { lines } = buildThresholdEntries(
      policyInput({
        exceptions: [{ sid: 1000001 }],
        thresholds: [{ sid: 2100005, track: "by_dst", count: 4, seconds: 30 }],
      }),
    );
    expect(lines).toHaveLength(2);
  });
});

// ── generateThresholdBlock ──────────────────────────────────────────────────

describe("generateThresholdBlock", () => {
  it("wraps entries between the managed markers", () => {
    const block = generateThresholdBlock(policyInput({ thresholds: [{ sid: 1, track: "by_src", count: 1, seconds: 1 }] }), "2026-01-01T00:00:00.000Z");
    expect(block.startsWith(MARKER_BEGIN)).toBe(true);
    expect(block.endsWith(MARKER_END)).toBe(true);
    expect(block).toContain("threshold gen_id 1, sig_id 1, track by_src, count 1, seconds 1;");
  });

  it("keeps a placeholder so an empty policy still produces a valid block", () => {
    const block = generateThresholdBlock(noPolicy, "2026-01-01T00:00:00.000Z");
    expect(block).toContain("(no thresholds / exceptions in the active policy)");
  });
});

// ── replaceManagedBlock ─────────────────────────────────────────────────────

describe("replaceManagedBlock", () => {
  const foreign = "# vendor sample threshold entries\n# keep me\n";

  it("replaces the previous block and preserves foreign content", () => {
    const prev = `${foreign}\n${MARKER_BEGIN}\nsuppress gen_id 1, sig_id 111;\n${MARKER_END}\n`;
    const next = replaceManagedBlock(prev, `${MARKER_BEGIN}\nthreshold gen_id 1, sig_id 2, track by_src, count 5, seconds 10;\n${MARKER_END}`);
    expect(next).toContain("# keep me");
    expect(next).not.toContain("sig_id 111");
    expect(next).toContain("sig_id 2, track by_src, count 5");
  });

  it("is idempotent — re-inserting the same block yields identical output", () => {
    const base = foreign;
    const block = `${MARKER_BEGIN}\nsuppress gen_id 1, sig_id 9;\n${MARKER_END}`;
    const once = replaceManagedBlock(base, block);
    const twice = replaceManagedBlock(once, block);
    expect(twice).toBe(once);
  });

  it("removes the block when an empty replacement is given", () => {
    const prev = `${foreign}\n${MARKER_BEGIN}\nsuppress gen_id 1, sig_id 111;\n${MARKER_END}\n`;
    const next = replaceManagedBlock(prev, "");
    expect(next).toContain("# keep me");
    expect(next).not.toContain(MARKER_BEGIN);
    expect(next).not.toContain("sig_id 111");
  });
});

// ── yamlAppendRuleFile / yamlEnsureThresholdFile ────────────────────────────

describe("yamlAppendRuleFile", () => {
  const yaml = ["default-rule-path: /var/lib/suricata/rules", "rule-files:", "  - suricata.rules", "", "classification-file: /etc/suricata/classification.config"].join("\n");

  it("appends the managed file after the existing rule list", () => {
    const { content, changed } = yamlAppendRuleFile(yaml, MANAGED_RULES_NAME);
    expect(changed).toBe(true);
    expect(content).toContain("  - suricata.rules");
    expect(content).toContain("  - utm-managed.rules");
    // managed entry must come after the vendor entry
    expect(content.indexOf("suricata.rules")).toBeLessThan(content.indexOf(MANAGED_RULES_NAME));
  });

  it("is idempotent — a second append does not duplicate the entry", () => {
    const once = yamlAppendRuleFile(yaml, MANAGED_RULES_NAME).content;
    const twice = yamlAppendRuleFile(once, MANAGED_RULES_NAME);
    expect(twice.changed).toBe(false);
    expect(twice.content).toBe(once);
    expect(once.match(/utm-managed\.rules/g)).toHaveLength(1);
  });
});

describe("yamlEnsureThresholdFile", () => {
  it("uncomments the Debian sample line", () => {
    const yaml = "default-rule-path: /var/lib/suricata/rules\n# threshold-file: /etc/suricata/threshold.config\n";
    const { content, changed } = yamlEnsureThresholdFile(yaml, "/etc/suricata/threshold.config");
    expect(changed).toBe(true);
    expect(content).toContain("\nthreshold-file: /etc/suricata/threshold.config");
    expect(content).not.toContain("# threshold-file");
  });

  it("leaves an already-active correct line untouched", () => {
    const yaml = "threshold-file: /etc/suricata/threshold.config\n";
    const { content, changed } = yamlEnsureThresholdFile(yaml, "/etc/suricata/threshold.config");
    expect(changed).toBe(false);
    expect(content).toBe(yaml);
  });

  it("rewrites an active line pointing elsewhere", () => {
    const yaml = "threshold-file: /etc/wrong.config\n";
    const { content, changed } = yamlEnsureThresholdFile(yaml, "/etc/suricata/threshold.config");
    expect(changed).toBe(true);
    expect(content).toBe("threshold-file: /etc/suricata/threshold.config\n");
  });
});

// ── computeIpsDrift ─────────────────────────────────────────────────────────

describe("computeIpsDrift", () => {
  const genManaged = `# header\n# generated 2026\nalert tcp any any -> any 80 (sid:9000001;)\n`;
  const liveManaged = `# different header timestamp\nalert tcp any any -> any 80 (sid:9000001;)\n`;
  const block = `${MARKER_BEGIN}\nthreshold gen_id 1, sig_id 5, track by_src, count 1, seconds 1;\n${MARKER_END}`;
  const emptyBlock = `${MARKER_BEGIN}\n# policy: (none enabled)\n${MARKER_END}`;
  const liveThreshold = `# vendor part\n${block}\n`;
  const liveThresholdEmpty = `# vendor part\n${emptyBlock}\n`;

  it("ignores header comments when comparing managed rules", () => {
    const d = computeIpsDrift(genManaged, liveManaged, generateThresholdBlock(noPolicy, "x"), liveThresholdEmpty, false, false);
    expect(d.managedRulesInSync).toBe(true);
    expect(d.thresholdInSync).toBe(true);
    expect(d.inSync).toBe(true);
  });

  it("flags rule drift when the live file misses a rule", () => {
    const d = computeIpsDrift(genManaged, "", generateThresholdBlock(noPolicy, "x"), liveThreshold, false, false);
    expect(d.managedRulesInSync).toBe(false);
    expect(d.inSync).toBe(false);
  });

  it("flags threshold drift when the managed block is missing", () => {
    const d = computeIpsDrift(genManaged, liveManaged, block, "# vendor part only", false, false);
    expect(d.thresholdInSync).toBe(false);
    expect(d.inSync).toBe(false);
  });

  it("counts empty desired block with no live block as in sync", () => {
    const d = computeIpsDrift(genManaged, liveManaged, generateThresholdBlock(noPolicy, "x"), "# vendor only", false, false);
    expect(d.thresholdInSync).toBe(true);
  });

  it("flags yaml drift when the managed rule file is not registered", () => {
    const d = computeIpsDrift(genManaged, liveManaged, generateThresholdBlock(noPolicy, "x"), liveThreshold, true, false);
    expect(d.yamlInSync).toBe(false);
    expect(d.inSync).toBe(false);
  });
});
