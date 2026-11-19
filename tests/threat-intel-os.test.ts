/**
 * Threat Intel OS layer tests (spec §2.11 auto-block → firewall) — renderer
 * determinism + confHash stability, table/chain safety invariants, L3-only
 * honesty warnings, drift parsers (skeleton compare + element attribution),
 * whitelist guard, apply-plan ordering, backup restore point, and the exec
 * glue against a stubbed child_process (mocked exec, mocked db + engine).
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import fs from "fs";
import path from "path";
import {
  TI_DIR_NAME_BACKUP_RE,
  TI_POSTROUTING_CHAIN,
  TI_PREROUTING_CHAIN,
  TI_PRIORITY,
  TI_SET_NAME,
  TI_TABLE,
  TI_TABLE_NAME,
  buildTiApplySteps,
  buildTiRollbackScript,
  composeBackupFile,
  extractTiTableBlock,
  generateTiBlockRuleset,
  isRestoreFileContent,
  parseIpv4Element,
  parseTiDropCounters,
  parseTiElements,
  sanitizeComment,
  tiConfHash,
  tiStepGuarded,
  tiTableBlocksInSync,
  type TiBlockRuleShape,
} from "@/lib/threat-intel/os";

// ── shared stubbed-exec state (read by the vi.mock factories) ───────────────

interface DbRow {
  id: number;
  tenantId: number;
  name: string;
  matchType: string;
  matchValue: string;
  action: string;
  direction: string;
  enabled: boolean;
}

const h = vi.hoisted(() => ({
  calls: [] as string[],
  failCheck: false,
  failApply: false,
  rulesetDump: "table inet console-firewall {\n}\n",
  tableDump: null as string | null,
  dbRows: [] as DbRow[],
  updates: [] as Array<{ id: number; data: Record<string, unknown> }>,
  dataPlaneMode: "host",
}));

vi.mock("child_process", () => ({
  exec: (cmd: string, opts: unknown, cb: (e: Error | null, out?: { stdout: string; stderr: string }) => void) => {
    void opts;
    const c = String(cmd);
    h.calls.push(c);
    const ok = (stdout = "") => cb(null, { stdout, stderr: "" });
    const fail = (stderr: string) => cb(new Error(stderr), { stdout: "", stderr });
    const bin = /^command -v "([^"]+)"/.exec(c);
    if (bin) {
      if (bin[1] === "nft" || bin[1] === "systemctl") return ok();
      return fail(`/bin/sh: 1: ${bin[1]}: not found`);
    }
    if (c === "nft --version") return ok("nftables v1.1.0 (laramie)");
    if (c === "nft list ruleset") return ok(h.rulesetDump);
    if (c === "nft list table inet utm_ti_block 2>/dev/null") return ok(h.tableDump ?? "");
    if (/^nft -c -f "[^"]+"$/.test(c)) return h.failCheck ? fail("syntax error in the staged fragment") : ok();
    if (/^nft -f "[^"]+"$/.test(c)) return h.failApply ? fail("Operation not permitted") : ok();
    if (/^nohup \/bin\/sh "[^"]+" >\/dev\/null 2>&1 &$/.test(c)) return ok();
    if (c === "systemctl enable nftables >/dev/null 2>&1") return ok();
    return fail(`stubbed exec has no route for: ${c}`);
  },
}));

vi.mock("@/lib/db", () => ({
  db: {
    autoBlockRule: {
      findMany: async () => h.dbRows.map((r) => ({ ...r })),
      findFirst: async ({ where }: { where: { id: number; tenantId: number } }) =>
        h.dbRows.find((r) => r.id === where.id && r.tenantId === where.tenantId) ?? null,
      update: async ({ where, data }: { where: { id: number }; data: Record<string, unknown> }) => {
        h.updates.push({ id: where.id, data });
        return { id: where.id, ...data };
      },
    },
  },
}));

vi.mock("@/lib/engine", () => ({
  getDataPlaneMode: () => h.dataPlaneMode,
}));

// ── fixtures (pure renderer) ────────────────────────────────────────────────

const rule = (over: Partial<TiBlockRuleShape> = {}): TiBlockRuleShape => ({
  id: 1,
  name: "botnet-c2",
  matchType: "ip",
  matchValue: "45.155.205.233",
  action: "drop",
  direction: "both",
  enabled: true,
  ...over,
});

const gen = (rules: TiBlockRuleShape[], generatedAt?: Date) =>
  generateTiBlockRuleset({ rules, generatedAt: generatedAt ?? new Date("2026-01-01T00:00:00Z") });

// ── structure + safety invariants ───────────────────────────────────────────

describe("generateTiBlockRuleset — structure and safety invariants", () => {
  const res = gen([rule()]);

  it("never emits flush ruleset and always targets the dedicated table", () => {
    expect(res.file).not.toMatch(/flush ruleset/);
    expect(res.file).toContain(`destroy table inet ${TI_TABLE_NAME}`);
    expect(res.file).toContain(`table inet ${TI_TABLE_NAME} {`);
    expect(res.file).toContain("#!/usr/sbin/nft -f");
    // no other table is ever touched
    expect(res.file).not.toMatch(/table inet console-firewall/);
    expect(res.file).not.toMatch(/table inet utm_appctl/);
  });

  it("renders the interval set ti_block_v4 with the exact declared attributes", () => {
    expect(res.file).toContain(`set ${TI_SET_NAME} {`);
    expect(res.file).toContain("type ipv4_addr");
    expect(res.file).toContain("flags interval");
    expect(res.file).toContain("auto-merge");
  });

  it("renders both chains at priority -105 with permanent accept policies", () => {
    expect(res.file).toContain(`chain ${TI_PREROUTING_CHAIN} {`);
    expect(res.file).toContain(`chain ${TI_POSTROUTING_CHAIN} {`);
    expect(res.file).toContain(`type filter hook prerouting priority ${TI_PRIORITY}; policy accept;`);
    expect(res.file).toContain(`type filter hook postrouting priority ${TI_PRIORITY}; policy accept;`);
    // no input/output chain mutation, no catch-all drop of unmatched traffic
    expect(res.file).not.toMatch(/hook input/);
    expect(res.file).not.toMatch(/hook output/);
    const drops = res.file.match(/drop/g) ?? [];
    expect(drops).toHaveLength(2); // exactly the two set-based drop rules
    expect(res.statements).toEqual([`ip saddr @${TI_SET_NAME} counter drop`, `ip daddr @${TI_SET_NAME} counter drop`]);
  });

  it("is deterministic — same input + generatedAt → byte-identical file", () => {
    const a = gen([rule(), rule({ id: 2, name: "ransomware", matchType: "cidr", matchValue: "185.222.57.0/24" })]);
    const b = gen([rule({ id: 2, name: "ransomware", matchType: "cidr", matchValue: "185.222.57.0/24" }), rule()]);
    expect(a.file).toBe(b.file);
    expect(a.elements).toEqual(b.elements);
    expect(a.confHash).toBe(b.confHash);
  });

  it("every element carries a counter and a ti:<ruleId>:<name> comment", () => {
    const res2 = gen([rule(), rule({ id: 2, name: "ransomware net!", matchType: "cidr", matchValue: "185.222.57.0/24" })]);
    expect(res2.elements).toEqual([
      '45.155.205.233 counter comment "ti:1:botnet-c2"',
      '185.222.57.0/24 counter comment "ti:2:ransomware-net"',
    ]);
    for (const e of res2.elements) expect(e).toMatch(/counter comment "ti:\d+:/);
  });

  it("sorts elements by numeric start address (kernel interval-set order)", () => {
    const res2 = gen([
      rule({ id: 1, matchValue: "103.244.7.217" }),
      rule({ id: 2, matchValue: "9.9.9.9" }),
      rule({ id: 3, matchValue: "185.222.57.0/24" }),
    ]);
    expect(res2.elements.map((e) => e.split(" ")[0])).toEqual(["9.9.9.9", "103.244.7.217", "185.222.57.0/24"]);
  });
});

// ── confHash stability ──────────────────────────────────────────────────────

describe("confHash — sha256 over the comment-stripped canonical body", () => {
  it("is stable across renders with different generated timestamps", () => {
    const a = gen([rule()], new Date("2026-01-01T00:00:00Z"));
    const b = gen([rule()], new Date("2026-06-13T10:30:00Z"));
    expect(a.file).not.toBe(b.file); // the # generated: comment differs
    expect(a.confHash).toBe(b.confHash);
  });

  it("is a full sha256 hex digest and changes when the policy changes", () => {
    const a = gen([rule()]);
    expect(a.confHash).toMatch(/^[0-9a-f]{64}$/);
    expect(a.confHash).toBe(tiConfHash(a.file));
    const b = gen([rule({ matchValue: "1.2.3.4" })]);
    expect(b.confHash).not.toBe(a.confHash);
  });

  it("does not embed the hash input in comment lines (comments stripped first)", () => {
    const file = gen([rule()]).file;
    const canonical = file
      .split("\n")
      .filter((l) => !l.trimStart().startsWith("#"))
      .join("\n")
      .trim();
    expect(canonical).not.toMatch(/^#/);
    expect(canonical).toContain(`table inet ${TI_TABLE_NAME} {`);
  });
});

// ── element validation + honesty warnings ───────────────────────────────────

describe("parseIpv4Element — strict L3 validation", () => {
  it("accepts bare hosts, prefix-aligned CIDRs and normalizes /32", () => {
    expect(parseIpv4Element("45.155.205.233")).toEqual({ ok: true, text: "45.155.205.233", num: 0x2d9bcde9 });
    expect(parseIpv4Element("185.222.57.0/24")).toEqual({ ok: true, text: "185.222.57.0/24", num: expect.any(Number) });
    expect(parseIpv4Element("1.2.3.4/32")).toEqual({ ok: true, text: "1.2.3.4", num: expect.any(Number) });
  });

  it("rejects IPv6 (warn-not-fail path), malformed values and host-bit CIDRs", () => {
    expect(parseIpv4Element("2001:db8::1")).toMatchObject({ ok: false, reason: "ipv6" });
    expect(parseIpv4Element("not-an-ip")).toMatchObject({ ok: false, reason: "malformed" });
    expect(parseIpv4Element("999.1.1.1")).toMatchObject({ ok: false, reason: "malformed" });
    expect(parseIpv4Element("1.2.3.4/33")).toMatchObject({ ok: false, reason: "malformed" });
    expect(parseIpv4Element("1.2.3.1/24")).toMatchObject({ ok: false, reason: "cidr-host-bits" });
    expect(parseIpv4Element("45.0.0.0/0")).toMatchObject({ ok: false, reason: "cidr-host-bits" }); // only 0.0.0.0/0 is a valid /0
    expect(parseIpv4Element("0.0.0.0/0")).toMatchObject({ ok: true, text: "0.0.0.0/0" });
  });
});

describe("honesty warnings — never silently pretend enforcement", () => {
  it("warns (not fails) on IPv6 rules and renders v4 only", () => {
    const res = gen([
      rule({ id: 1, matchValue: "2001:db8::1" }),
      rule({ id: 2, matchValue: "1.2.3.4" }),
    ]);
    const w = res.warnings.find((x) => x.code === "ipv6-not-rendered");
    expect(w?.ruleId).toBe(1);
    expect(w?.message).toContain("IPv6");
    expect(w?.message).toContain("renders v4 only");
    expect(res.counts.skipped).toBe(1);
    expect(res.elements).toEqual(['1.2.3.4 counter comment "ti:2:botnet-c2"']);
    expect(res.file).not.toContain("2001:db8");
  });

  it("skips L7 indicators (domain/url/hash) with a loud warning", () => {
    const res = gen([rule({ matchType: "domain", matchValue: "evil.example" })]);
    expect(res.elements).toHaveLength(0);
    expect(res.counts.skipped).toBe(1);
    expect(res.warnings[0].code).toBe("l7-not-l3-enforceable");
    expect(res.warnings[0].message).toContain("matchType=domain");
    expect(res.warnings[0].message).toContain("L7");
  });

  it("skips reject/quarantine_vlan actions (no prerouting nft equivalent)", () => {
    const res = gen([rule({ action: "reject" }), rule({ id: 2, action: "quarantine_vlan", name: "vlan" })]);
    expect(res.elements).toHaveLength(0);
    expect(res.warnings.filter((w) => w.code === "action-not-kernel-enforceable")).toHaveLength(2);
    expect(res.warnings[0].message).toContain("action=reject");
    expect(res.file).toContain("policy accept;"); // no drop substituted
    expect(res.file).not.toMatch(/ip saddr @ti_block_v4 counter drop\n {4}ip daddr/);
  });

  it("warns on invalid values and CIDRs with host bits set", () => {
    const res = gen([rule({ matchValue: "1.2.3.999" }), rule({ id: 2, matchValue: "10.0.0.5/8", name: "bad-cidr" })]);
    expect(res.warnings.map((w) => w.code)).toEqual(["invalid-address", "invalid-cidr"]);
  });

  it("collapses exact duplicate values with a duplicate-element warning", () => {
    const res = gen([rule({ id: 1 }), rule({ id: 2, name: "same-ip", matchValue: "45.155.205.233" })]);
    expect(res.counts.elements).toBe(1);
    expect(res.counts.skipped).toBe(1);
    const w = res.warnings.find((x) => x.code === "duplicate-element");
    expect(w?.ruleId).toBe(2);
    expect(w?.message).toContain("already in the blocklist via rule 1");
    // overlapping (non-identical) CIDRs are NOT deduped — interval set handles it
    const overlap = gen([rule({ matchType: "cidr", matchValue: "10.0.0.0/8" }), rule({ id: 2, matchType: "cidr", matchValue: "10.1.2.0/24" })]);
    expect(overlap.counts.elements).toBe(2);
    expect(overlap.warnings.some((x) => x.code === "duplicate-element")).toBe(false);
  });

  it("warns on per-rule direction deviation (single shared set blocks both ways)", () => {
    const inOnly = gen([rule({ direction: "in" })]);
    expect(inOnly.warnings.find((w) => w.code === "direction-unscoped")?.message).toContain("direction=in");
    const outOnly = gen([rule({ direction: "out" })]);
    expect(outOnly.warnings.find((w) => w.code === "direction-unscoped")?.message).toContain("direction=out");
    expect(gen([rule({ direction: "both" })]).warnings.some((w) => w.code === "direction-unscoped")).toBe(false);
  });

  it("warns loudly when a /0 element would drop everything", () => {
    const res = gen([rule({ matchType: "cidr", matchValue: "0.0.0.0/0" })]);
    expect(res.warnings.find((w) => w.code === "default-route-element")?.message).toContain("drops ALL traffic");
  });

  it("empty rules → empty-blocklist warning, no elements line, chains still render", () => {
    const res = gen([]);
    expect(res.counts).toEqual({ rules: 0, elements: 0, skipped: 0, chains: 2 });
    expect(res.warnings).toHaveLength(1);
    expect(res.warnings[0].code).toBe("empty-blocklist");
    expect(res.warnings[0].message).toContain("applies empty");
    expect(res.file).not.toContain("elements ="); // kernel dumps empty sets without elements
    expect(res.file).toContain(`type filter hook prerouting priority ${TI_PRIORITY}; policy accept;`);
    expect(res.file).toContain(`type filter hook postrouting priority ${TI_PRIORITY}; policy accept;`);
  });

  it("disabled rules contribute nothing (silently, like firewall)", () => {
    const res = gen([rule({ enabled: false }), rule({ id: 2 })]);
    expect(res.counts.rules).toBe(1);
    expect(res.counts.elements).toBe(1);
    expect(res.elements[0]).toContain("ti:2:");
  });
});

// ── drift parsers (pure) ────────────────────────────────────────────────────

const kernelDump = () =>
  [
    "table ip fail2ban {", // foreign table must be ignored
    "}",
    `table inet ${TI_TABLE_NAME} {`,
    `\tset ${TI_SET_NAME} {`,
    "\t\ttype ipv4_addr",
    "\t\tflags interval",
    "\t\tauto-merge",
    '\t\telements = { 9.9.9.9 counter packets 3 bytes 180 comment "ti:2:scanner", 45.155.205.233 counter packets 12 bytes 960 comment "ti:1:botnet-c2" }',
    "\t}",
    "",
    `\tchain ${TI_PREROUTING_CHAIN} {`,
    `\t\ttype filter hook prerouting priority ${TI_PRIORITY}; policy accept;`,
    "\t\tip saddr @ti_block_v4 counter packets 12 bytes 960 drop",
    "\t}",
    "",
    `\tchain ${TI_POSTROUTING_CHAIN} {`,
    `\t\ttype filter hook postrouting priority ${TI_PRIORITY}; policy accept;`,
    "\t\tip daddr @ti_block_v4 counter packets 0 bytes 0 drop",
    "\t}",
    "}",
  ].join("\n");

describe("tiTableBlocksInSync — normalized skeleton compare", () => {
  const file = gen([rule(), rule({ id: 2, name: "scanner", matchValue: "9.9.9.9" })]).file;

  it("matches when only counters/comments/element wrapping differ", () => {
    expect(tiTableBlocksInSync(file, kernelDump())).toBe(true);
  });

  it("ignores element payload changes (interval sets auto-merge/adjacent-coalesce)", () => {
    // kernel merged 9.9.9.9 into an adjacent range — skeleton stays in sync,
    // data drift is surfaced by per-rule element presence instead
    const merged = kernelDump().replace(
      'elements = { 9.9.9.9 counter packets 3 bytes 180 comment "ti:2:scanner", 45.155.205.233 counter packets 12 bytes 960 comment "ti:1:botnet-c2" }',
      'elements = { 9.9.9.9-9.9.9.10 counter packets 4 bytes 240 comment "ti:2:scanner" }',
    );
    expect(tiTableBlocksInSync(file, merged)).toBe(true);
  });

  it("reports drift when a chain statement changes", () => {
    expect(tiTableBlocksInSync(file, kernelDump().replace("priority -105", "priority -100"))).toBe(false);
    expect(tiTableBlocksInSync(file, kernelDump().replace("policy accept;", "policy drop;"))).toBe(false);
  });

  it("reports not-in-sync when the table is absent", () => {
    expect(tiTableBlocksInSync(file, "table inet console-firewall { }")).toBe(false);
    expect(tiTableBlocksInSync(file, "")).toBe(false);
    expect(extractTiTableBlock("table inet console-firewall { }")).toBeNull();
  });

  it("extracts and normalizes the block (comments + counters stripped)", () => {
    const block = extractTiTableBlock(kernelDump()) ?? "";
    expect(block).toContain(`table inet ${TI_TABLE_NAME} {`);
    expect(block).toContain("elements = { }"); // payload replaced for skeleton compare
    expect(block).toContain("ip saddr @ti_block_v4 drop");
    expect(block).not.toContain("packets");
    expect(block).not.toContain("comment");
  });
});

describe("parseTiElements + parseTiDropCounters — attribution parsing", () => {
  it("parses element comments with per-element counters from a live dump", () => {
    const els = parseTiElements(kernelDump());
    expect(els).toEqual([
      { address: "9.9.9.9", ruleId: 2, name: "scanner", packets: 3, bytes: 180 },
      { address: "45.155.205.233", ruleId: 1, name: "botnet-c2", packets: 12, bytes: 960 },
    ]);
  });

  it("parses the generated fragment too (counters at zero before first hit)", () => {
    const els = parseTiElements(gen([rule({ id: 7, name: "feed:spamhaus" })]).file);
    expect(els).toEqual([{ address: "45.155.205.233", ruleId: 7, name: "feed:spamhaus", packets: 0, bytes: 0 }]);
  });

  it("returns [] for a foreign dump", () => {
    expect(parseTiElements("table inet console-firewall { chain forward { } }")).toEqual([]);
    expect(parseTiElements("")).toEqual([]);
  });

  it("parses both chain drop counters", () => {
    const drops = parseTiDropCounters(kernelDump());
    expect(drops.prerouting).toEqual({ packets: 12, bytes: 960 });
    expect(drops.postrouting).toEqual({ packets: 0, bytes: 0 });
  });

  it("returns null chains when the table is absent", () => {
    expect(parseTiDropCounters("table inet console-firewall { }")).toEqual({ prerouting: null, postrouting: null });
  });
});

// ── sanitize + restore point + whitelist ────────────────────────────────────

describe("sanitizeComment", () => {
  it("keeps the comment-safe subset and bounds the length", () => {
    expect(sanitizeComment("feed:spamhaus")).toBe("feed:spamhaus");
    expect(sanitizeComment("ransom ware/net!")).toBe("ransom-ware-net");
    expect(sanitizeComment("x".repeat(80), 32)).toHaveLength(32);
  });
});

describe("backup restore point", () => {
  // audit fix M3 — backups are TABLE-SCOPED: only utm_ti_block is snapshotted
  // and restored; other modules' tables (console-firewall, fail2ban) survive
  // a rollback untouched.
  it("composeBackupFile snapshots ONLY the utm_ti_block table behind the scoped prologue", () => {
    const backup = composeBackupFile(
      `table inet console-firewall { }\ntable inet ${TI_TABLE_NAME} {\n  set blocklist {\n    type ipv4_addr\n  }\n}\ntable ip fail2ban { }`,
    );
    expect(isRestoreFileContent(backup)).toBe(true);
    expect(backup.startsWith(`#!/usr/sbin/nft -f\ntable inet ${TI_TABLE_NAME} {}\nflush table inet ${TI_TABLE_NAME}\n`)).toBe(true);
    expect(backup).toContain("set blocklist");
    expect(backup).toContain(`table inet ${TI_TABLE_NAME} {`);
    // cross-module isolation: no other table leaks into the restore file
    expect(backup).not.toContain("console-firewall");
    expect(backup).not.toContain("fail2ban");
    expect(backup).not.toContain("flush ruleset");
  });

  it("refuses restore files without the table-scoped prologue (would merge, not restore)", () => {
    expect(isRestoreFileContent("#!/usr/sbin/nft -f\nflush ruleset\n")).toBe(false);
    expect(isRestoreFileContent(`#!/usr/sbin/nft -f\ntable inet ${TI_TABLE_NAME} { }`)).toBe(false);
    expect(isRestoreFileContent("")).toBe(false);
    // absent-table backup is still a valid restore point (empty table after)
    expect(isRestoreFileContent(composeBackupFile(""))).toBe(true);
    expect(composeBackupFile("")).toContain(`# ${TI_TABLE_NAME} absent at backup time`);
  });
});

describe("tiStepGuarded — exec command whitelist", () => {
  it("accepts exactly the pipeline commands", () => {
    expect(tiStepGuarded(`nft -c -f "${TI_DIR_NAME_BACKUP_RE}x.nft"`)).toBe(true);
    expect(tiStepGuarded('nft -f "/var/lib/console/threat-intel/backup-2026/ruleset.nft"')).toBe(true);
    expect(tiStepGuarded('nohup /bin/sh "/var/lib/console/threat-intel/rollback-2026.sh" >/dev/null 2>&1 &')).toBe(true);
    expect(tiStepGuarded("nft list ruleset")).toBe(true);
    expect(tiStepGuarded(`nft list table inet ${TI_TABLE_NAME} 2>/dev/null`)).toBe(true);
    expect(tiStepGuarded("nft --version")).toBe(true);
    expect(tiStepGuarded("systemctl enable nftables >/dev/null 2>&1")).toBe(true);
  });

  it("rejects anything else (rm, flush, foreign tables, injection)", () => {
    expect(tiStepGuarded("nft flush ruleset")).toBe(false);
    expect(tiStepGuarded("rm -rf /")).toBe(false);
    expect(tiStepGuarded("nft delete table inet console-firewall")).toBe(false);
    expect(tiStepGuarded("nft delete table inet utm_appctl")).toBe(false);
    expect(tiStepGuarded('nft -f "x"; rm -rf /')).toBe(false);
    expect(tiStepGuarded("ip rule del priority 5010")).toBe(false);
    expect(tiStepGuarded("tc qdisc add dev ens32 root htb")).toBe(false);
    expect(tiStepGuarded("")).toBe(false);
  });
});

describe("buildTiApplySteps + rollback script", () => {
  const steps = buildTiApplySteps({
    file: "/var/lib/console/threat-intel/ti-block-1.nft",
    backupFile: "/var/lib/console/threat-intel/backup-1/ruleset.nft",
    rollbackScript: "/var/lib/console/threat-intel/rollback-1.sh",
  });

  it("plans ordered steps: check → arm → apply → restore → persist", () => {
    expect(steps.map((s) => s.kind)).toEqual(["check", "arm", "apply", "restore", "persist"]);
    expect(steps.map((s) => s.step)).toEqual([
      "nft -c check",
      "rollback timer",
      "apply",
      "restore backup",
      "systemctl enable nftables",
    ]);
  });

  it("every planned command passes the whitelist guard", () => {
    for (const s of steps) {
      expect(tiStepGuarded(s.cmd), `step '${s.step}' cmd must be whitelisted: ${s.cmd}`).toBe(true);
    }
  });

  it("check runs before apply; restore targets the snapshot ruleset.nft", () => {
    const check = steps.find((s) => s.kind === "check")!;
    const apply = steps.find((s) => s.kind === "apply")!;
    const restore = steps.find((s) => s.kind === "restore")!;
    expect(steps.indexOf(check)).toBeLessThan(steps.indexOf(apply));
    expect(check.cmd).toBe('nft -c -f "/var/lib/console/threat-intel/ti-block-1.nft"');
    expect(apply.cmd).toBe('nft -f "/var/lib/console/threat-intel/ti-block-1.nft"');
    expect(restore.cmd).toBe('nft -f "/var/lib/console/threat-intel/backup-1/ruleset.nft"');
  });

  it("rollback script sleeps, honors the confirm flag, restores the snapshot and self-cleans", () => {
    const script = buildTiRollbackScript({
      ts: "2026-01-01T00-00-00-000Z",
      confirmSec: 60,
      confirmFile: "/var/lib/console/threat-intel/confirm-1",
      backupFile: "/var/lib/console/threat-intel/backup-1/ruleset.nft",
      scriptFile: "/var/lib/console/threat-intel/rollback-1.sh",
      stateFile: "/var/lib/console/threat-intel/state.json",
    });
    expect(script).toContain("#!/bin/sh");
    expect(script).toContain("sleep 60");
    expect(script).toContain('if [ -f "/var/lib/console/threat-intel/confirm-1" ]; then exit 0; fi');
    expect(script).toContain('/usr/sbin/nft -f "/var/lib/console/threat-intel/backup-1/ruleset.nft"');
    expect(script).toContain('rm -f "/var/lib/console/threat-intel/rollback-1.sh"');
    expect(script).toContain('grep -qF "\\"ts\\": \\"2026-01-01T00-00-00-000Z\\""');
    expect(script).not.toContain("flush ruleset"); // restore = replay snapshot, never a bare flush
  });
});

// ── exec glue (stubbed child_process + mocked db/engine) ────────────────────

const TMP = path.join("/tmp", `ti-os-test-${process.pid}`);

function writeKernelDumpFile(dir: string, file: string, dump: string): void {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, file), dump, "utf8");
}

async function freshModules(env: Record<string, string | undefined>) {
  vi.resetModules();
  for (const [k, v] of Object.entries(env)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  return {
    os: await import("@/lib/threat-intel/os"),
    svc: await import("@/lib/threat-intel/os-service"),
  };
}

function envFor(gate: "on" | "off"): Record<string, string | undefined> {
  return {
    CONSOLE_OS_APPLY: gate === "on" ? "1" : "0",
    CONSOLE_TI_DIR: path.join(TMP, "state"),
    CONSOLE_NFT_CONFIRM_SEC: "15",
  };
}

function dbRow(over: Partial<DbRow> = {}): DbRow {
  return {
    id: 1,
    tenantId: 1,
    name: "botnet-c2",
    matchType: "ip",
    matchValue: "45.155.205.233",
    action: "drop",
    direction: "both",
    enabled: true,
    ...over,
  };
}

/** A kernel-style dump matching the CURRENT db fixture render (in sync). */
function kernelDumpForDbRows(): string {
  const shapes = h.dbRows.map((r) => ({
    id: r.id,
    name: r.name,
    matchType: r.matchType,
    matchValue: r.matchValue,
    action: r.action,
    direction: r.direction,
    enabled: r.enabled,
  }));
  const elements = shapes
    .filter((s) => s.enabled && s.action === "drop" && (s.matchType === "ip" || s.matchType === "cidr"))
    .map((s) => `45.155.205.233 counter packets 0 bytes 0 comment "ti:${s.id}:${s.name}"`);
  return [
    "table inet console-firewall {",
    "}",
    `table inet ${TI_TABLE_NAME} {`,
    `\tset ${TI_SET_NAME} {`,
    "\t\ttype ipv4_addr",
    "\t\tflags interval",
    "\t\tauto-merge",
    `\t\telements = { ${elements.join(", ")} }`,
    "\t}",
    "",
    `\tchain ${TI_PREROUTING_CHAIN} {`,
    `\t\ttype filter hook prerouting priority ${TI_PRIORITY}; policy accept;`,
    "\t\tip saddr @ti_block_v4 counter packets 7 bytes 420 drop",
    "\t}",
    "",
    `\tchain ${TI_POSTROUTING_CHAIN} {`,
    `\t\ttype filter hook postrouting priority ${TI_PRIORITY}; policy accept;`,
    "\t\tip daddr @ti_block_v4 counter packets 2 bytes 120 drop",
    "\t}",
    "}",
  ].join("\n");
}

beforeEach(() => {
  h.calls.length = 0;
  h.updates.length = 0;
  h.failCheck = false;
  h.failApply = false;
  h.rulesetDump = "table inet console-firewall {\n}\n";
  h.tableDump = null;
  h.dataPlaneMode = "host";
  h.dbRows = [dbRow()];
  fs.rmSync(TMP, { recursive: true, force: true });
});

describe("applyTiToOs — gate off → plan preview only (no fs writes)", () => {
  it("returns the preview plan and never creates the state dir", async () => {
    const { svc } = await freshModules(envFor("off"));
    const outcome = await svc.applyTiToOs(1);
    expect(outcome.gate).toBe("off");
    expect(outcome.applied).toBe(false);
    expect(outcome.rolledBack).toBe(false);
    expect(outcome.results).toHaveLength(1);
    expect(outcome.results[0].step).toBe("gate");
    expect(outcome.results[0].detail).toContain("preview only");
    // the full generated fragment is still surfaced for the preview dialog
    expect(outcome.file).toContain(`table inet ${TI_TABLE_NAME} {`);
    expect(outcome.counts).toEqual({ rules: 1, elements: 1, skipped: 0, chains: 2 });
    expect(fs.existsSync(path.join(TMP, "state"))).toBe(false);
  });

  it("degrades honestly when the data plane is not in host mode", async () => {
    h.dataPlaneMode = "simulated";
    const { svc } = await freshModules(envFor("on"));
    const outcome = await svc.applyTiToOs(1);
    expect(outcome.applied).toBe(false);
    expect(outcome.results.map((r) => r.step)).toEqual(["mode"]);
    expect(fs.existsSync(path.join(TMP, "state"))).toBe(false);
  });
});

describe("applyTiToOs — green path (stubbed appliance)", () => {
  it("validates → snapshots → applies → records confHash + appliedAt in state.json", async () => {
    const { svc } = await freshModules(envFor("on"));
    const outcome = await svc.applyTiToOs(1);

    expect(outcome.gate).toBe("on");
    expect(outcome.applied).toBe(true);
    expect(outcome.rolledBack).toBe(false);
    expect(outcome.results.map((r) => r.step)).toEqual(["nft -c check", "backup", "bank hit counters", "rollback timer", "apply"]);

    // pre-check runs BEFORE any mutation; only whitelisted commands ran
    const checkIdx = h.calls.findIndex((c) => /^nft -c -f "/.test(c));
    const applyIdx = h.calls.findIndex((c) => /^nft -f "/.test(c));
    expect(checkIdx).toBeGreaterThan(-1);
    expect(applyIdx).toBeGreaterThan(checkIdx);

    // the staged fragment is the generated file (idempotent replace prologue)
    const staged = h.calls.find((c) => /^nft -c -f "/.test(c))!.match(/"([^"]+)"/)![1];
    const stagedBody = fs.readFileSync(staged, "utf8");
    expect(stagedBody).toContain(`destroy table inet ${TI_TABLE_NAME}`);
    expect(stagedBody).not.toContain("flush ruleset");

    // snapshot-first: backup-<ts>/ruleset.nft as a TABLE-SCOPED restore point
    // (audit fix M3 — only utm_ti_block inside, never flush ruleset)
    const backupDirs = fs.readdirSync(path.join(TMP, "state")).filter((d) => /^backup-/.test(d));
    expect(backupDirs).toHaveLength(1);
    const backupBody = fs.readFileSync(path.join(path.join(TMP, "state"), backupDirs[0], "ruleset.nft"), "utf8");
    expect(backupBody.startsWith(`#!/usr/sbin/nft -f\ntable inet ${TI_TABLE_NAME} {}\nflush table inet ${TI_TABLE_NAME}\n`)).toBe(true);
    expect(backupBody).not.toContain("console-firewall");
    expect(backupBody).not.toContain("flush ruleset");

    // state.json LAST: confHash + appliedAt of the now-live fragment
    const state = JSON.parse(fs.readFileSync(path.join(TMP, "state", "state.json"), "utf8")) as Record<string, unknown>;
    const rendered = svc.generateTiBlockRuleset({
      rules: h.dbRows.map((r) => ({ id: r.id, name: r.name, matchType: r.matchType, matchValue: r.matchValue, action: r.action, direction: r.direction, enabled: r.enabled })),
    });
    expect(state.confHash).toBe(rendered.confHash);
    expect(state.appliedAt).toEqual(expect.any(String));
    expect(state.confHash).toBe(outcome.confHash);

    // manual mode leaves the commit-confirm window open (confirm file absent)
    const snap = await svc.readTiState();
    expect(snap.pending).not.toBeNull();
    expect(snap.state?.confHash).toBe(rendered.confHash);

    // persistence recorded (systemctl enable)
    expect(outcome.persistence.map((p) => p.step)).toContain("systemctl enable nftables");
  }, 30000);
});

describe("applyTiToOs — failure paths", () => {
  it("nft -c failure aborts BEFORE any snapshot or kernel mutation", async () => {
    h.failCheck = true;
    const { svc } = await freshModules(envFor("on"));
    const outcome = await svc.applyTiToOs(1);
    expect(outcome.applied).toBe(false);
    expect(outcome.results.find((r) => r.step === "nft -c check")?.ok).toBe(false);
    expect(h.calls.some((c) => /^nft -f "/.test(c))).toBe(false);
    expect(fs.existsSync(path.join(TMP, "state", "state.json"))).toBe(false);
    expect(fs.readdirSync(path.join(TMP, "state")).some((d) => /^backup-/.test(d))).toBe(false);
  });

  it("apply failure restores the backup automatically (auto-restore)", async () => {
    h.failApply = true;
    const { svc } = await freshModules(envFor("on"));
    const outcome = await svc.applyTiToOs(1);
    expect(outcome.applied).toBe(false);
    expect(outcome.rolledBack).toBe(true);
    expect(outcome.rollbackReason).toContain("backup restored");
    // two nft -f runs: the failed apply + the defensive restore of the snapshot
    const applies = h.calls.filter((c) => /^nft -f "/.test(c));
    expect(applies).toHaveLength(2);
    expect(applies[1]).toContain("backup-");
    // failed state is honest — no confHash recorded
    const state = JSON.parse(fs.readFileSync(path.join(TMP, "state", "state.json"), "utf8")) as unknown;
    expect(state).toBeNull();
  });
});

describe("rollbackTi + confirmTiApply", () => {
  it("confirms the pending window and KEEPS confHash for drift compare", async () => {
    const { svc } = await freshModules(envFor("on"));
    await svc.applyTiToOs(1);
    const pending = (await svc.readTiState()).pending;
    expect(pending).not.toBeNull();
    const r = await svc.confirmTiApply(1, pending!.ts); // audit M2 — caller tenant now explicit
    expect(r.confirmed).toBe(true);
    const snap = await svc.readTiState();
    expect(snap.pending).toBeNull();
    expect(snap.state?.confHash).toEqual(expect.any(String));
    expect(snap.state?.appliedAt).toEqual(expect.any(String));
  });

  it("restores the newest snapshot on rollback and clears the state record", async () => {
    const { svc } = await freshModules(envFor("on"));
    await svc.applyTiToOs(1);
    const r = await svc.rollbackTi(1);
    expect(r.rolledBack).toBe(true);
    expect(r.file).toContain("backup-");
    expect(r.file?.endsWith("ruleset.nft")).toBe(true);
    expect((await svc.readTiState()).state).toBeNull();
  });

  it("refuses when no snapshot exists (honest failure)", async () => {
    const { svc } = await freshModules(envFor("on"));
    const r = await svc.rollbackTi(1);
    expect(r.rolledBack).toBe(false);
    expect(r.detail).toContain("no backup available");
  });

  it("refuses paths outside the console threat-intel directory", async () => {
    const { svc } = await freshModules(envFor("on"));
    await expect(svc.rollbackTi(1, "../../etc")).rejects.toThrow(/outside the console threat-intel directory/);
  });
});

describe("buildTiPlan — drift, per-rule presence and counters (stubbed kernel)", () => {
  it("reports applied + in-sync with per-rule presence and drop counters", async () => {
    h.rulesetDump = kernelDumpForDbRows();
    const { svc } = await freshModules(envFor("on"));
    const plan = await svc.buildTiPlan(1);
    expect(plan.facts.nftAvailable).toBe(true);
    expect(plan.facts.nftVersion).toContain("nftables v1.1.0");
    expect(plan.facts.mode).toBe("host");
    expect(plan.drift.applied).toBe(true);
    expect(plan.drift.inSync).toBe(true);
    expect(plan.drift.reasons).toEqual([]);
    expect(plan.perRule).toEqual([
      { ruleId: 1, name: "botnet-c2", matchValue: "45.155.205.233", enabled: true, expected: true, present: true },
    ]);
    expect(plan.dropCounters).toEqual({
      prerouting: { packets: 7, bytes: 420 },
      postrouting: { packets: 2, bytes: 120 },
    });
    expect(plan.elementCounters).toHaveLength(1);
    expect(plan.elementCounters[0].ruleId).toBe(1);
  });

  it("reports not-applied with honest reasons when the table is absent", async () => {
    const { svc } = await freshModules(envFor("on"));
    const plan = await svc.buildTiPlan(1);
    expect(plan.drift.applied).toBe(false);
    expect(plan.drift.inSync).toBe(false);
    expect(plan.drift.reasons[0]).toContain("utm_ti_block is not present");
    expect(plan.perRule[0].present).toBe(false);
    expect(plan.dropCounters).toBeNull();
  });

  it("surfaces missing elements as per-rule drift when the kernel was edited", async () => {
    h.rulesetDump = kernelDumpForDbRows().replace('comment "ti:1:botnet-c2"', "comment 'foreign'");
    const { svc } = await freshModules(envFor("on"));
    const plan = await svc.buildTiPlan(1);
    expect(plan.drift.applied).toBe(true);
    expect(plan.drift.inSync).toBe(true); // skeleton unchanged (element payload ignored)
    expect(plan.perRule[0].expected).toBe(true);
    expect(plan.perRule[0].present).toBe(false); // element gone kernel-side
  });
});

describe("syncTiHitsFromKernel — real counters into rule stats", () => {
  it("attributes element counters to rule ids and reports the drop totals", async () => {
    h.rulesetDump = kernelDumpForDbRows()
      .replace("counter packets 0 bytes 0 comment \"ti:1:", "counter packets 42 bytes 2688 comment \"ti:1:")
      .replace("ip saddr @ti_block_v4 counter packets 7 bytes 420 drop", "ip saddr @ti_block_v4 counter packets 42 bytes 2688 drop");
    const { svc } = await freshModules(envFor("on"));
    const r = await svc.syncTiHitsFromKernel(1);
    expect(r.updated).toBe(1);
    expect(r.preroutingDrops).toBe(42);
    expect(r.postroutingDrops).toBe(2);
    expect(r.elements).toBe(1);
    expect(h.updates).toEqual([{ id: 1, data: { hitCount: 42 } }]);
  });

  it("is a no-op when the table is absent", async () => {
    const { svc } = await freshModules(envFor("on"));
    const r = await svc.syncTiHitsFromKernel(1);
    expect(r).toEqual({ updated: 0, preroutingDrops: 0, postroutingDrops: 0, elements: 0 });
    expect(h.updates).toEqual([]);
  });
});

describe("readTiTableDump — guarded single-table read", () => {
  it("returns the live utm_ti_block dump when present", async () => {
    h.tableDump = `table inet ${TI_TABLE_NAME} { }`;
    const { svc } = await freshModules(envFor("on"));
    expect(await svc.readTiTableDump()).toBe(`table inet ${TI_TABLE_NAME} { }`);
    expect(h.calls).toContain(`nft list table inet ${TI_TABLE_NAME} 2>/dev/null`);
  });

  it("returns null when the table is absent (not a fake empty dump)", async () => {
    const { svc } = await freshModules(envFor("on"));
    expect(await svc.readTiTableDump()).toBeNull();
  });
});
