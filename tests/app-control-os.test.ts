import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "fs";
import path from "path";
import {
  APPCTL_CHAIN,
  APPCTL_TABLE_NAME,
  APP_PORT_MAP,
  DPI_ONLY_APPS,
  appctlStepGuarded,
  appctlTableBlocksInSync,
  appPortClass,
  buildAppctlApplySteps,
  buildAppctlRollbackScript,
  composeBackupFile,
  extractAppctlTableBlock,
  generateAppctlRuleset,
  isRestoreFileContent,
  parseAppctlRuleCounters,
  type AppCtlPolicyShape,
  type AppCtlRuleShape,
} from "@/lib/app-control/os";

// ── fixtures ────────────────────────────────────────────────────────────────

const rule = (over: Partial<AppCtlRuleShape> = {}): AppCtlRuleShape => ({
  id: 1,
  appName: "ssh",
  action: "block",
  bandwidthLimitMbps: null,
  direction: "both",
  userGroupIds: [],
  enabled: true,
  ...over,
});

const policy = (over: Partial<AppCtlPolicyShape> = {}): AppCtlPolicyShape => ({
  id: 1,
  name: "corp",
  defaultAction: "allow",
  unknownAppAction: "log",
  enabled: true,
  rules: [rule()],
  ...over,
});

const gen = (policies: AppCtlPolicyShape[], generatedAt?: Date) =>
  generateAppctlRuleset({ policies, generatedAt: generatedAt ?? new Date("2026-01-01T00:00:00Z") });

// ── file structure + safety invariants ──────────────────────────────────────

describe("generateAppctlRuleset — structure and safety invariants", () => {
  it("never emits flush ruleset and always targets the dedicated table", () => {
    const res = gen([policy()]);
    expect(res.file).not.toMatch(/flush ruleset/);
    expect(res.file).toContain(`destroy table inet ${APPCTL_TABLE_NAME}`);
    expect(res.file).toContain(`table inet ${APPCTL_TABLE_NAME} {`);
    expect(res.file).toContain("#!/usr/sbin/nft -f");
    // no other table is ever touched
    expect(res.file).not.toMatch(/table inet console-firewall/);
    expect(res.file).not.toMatch(/table inet f2b-table/);
  });

  it("renders one forward chain at priority -10 with permanent accept policy", () => {
    const res = gen([policy()]);
    expect(res.file).toMatch(
      new RegExp(`chain ${APPCTL_CHAIN} \\{`),
    );
    expect(res.file).toContain(`type filter hook forward priority -10; policy accept;`);
    // no input-chain mutation, no catch-all drop of unmatched traffic
    expect(res.file).not.toMatch(/hook input/);
    expect(res.file).not.toMatch(/hook output/);
    expect(res.file.match(/drop/g)!.every((d) => res.statements.some((s) => s.includes(d)))).toBe(true);
  });

  it("is deterministic — same input + generatedAt → byte-identical file", () => {
    const a = gen([policy({ rules: [rule(), rule({ id: 2, appName: "rdp" })] })]);
    const b = gen([policy({ rules: [rule(), rule({ id: 2, appName: "rdp" })] })]);
    expect(a.file).toBe(b.file);
    expect(a.statements).toEqual(b.statements);
  });

  it("every statement carries a counter and an appctl:<ruleId> comment", () => {
    const res = gen([policy({ rules: [rule(), rule({ id: 2, appName: "vnc" })] })]);
    for (const s of res.statements) {
      expect(s).toContain("counter");
      expect(s).toMatch(/comment "appctl:\d+:/);
    }
  });
});

// ── APP_PORT_MAP strictness ─────────────────────────────────────────────────

describe("APP_PORT_MAP — strict under-match port map", () => {
  it("maps exactly the widely-documented, stable port sets", () => {
    expect(APP_PORT_MAP.ssh).toEqual([{ proto: "tcp", ports: [{ lo: 22, hi: 22 }] }]);
    expect(APP_PORT_MAP.rdp).toEqual([{ proto: "tcp", ports: [{ lo: 3389, hi: 3389 }] }]);
    expect(APP_PORT_MAP.vnc).toEqual([{ proto: "tcp", ports: [{ lo: 5900, hi: 5902 }] }]);
    expect(APP_PORT_MAP.teamviewer).toEqual([
      { proto: "tcp", ports: [{ lo: 5938, hi: 5938 }] },
      { proto: "udp", ports: [{ lo: 5938, hi: 5938 }] },
    ]);
    expect(APP_PORT_MAP.bittorrent).toEqual([
      { proto: "tcp", ports: [{ lo: 6881, hi: 6889 }] },
      { proto: "udp", ports: [{ lo: 6881, hi: 6889 }] },
    ]);
  });

  it("leaves DPI-only apps unmapped (never port-approximated)", () => {
    for (const app of ["youtube", "netflix", "tiktok", "instagram", "facebook", "spotify", "steam", "teams", "zoom", "slack", "webex", "dropbox", "googledrive", "onedrive", "twitter", "twitch", "epicgames", "xboxlive"]) {
      expect(APP_PORT_MAP[app], `${app} must not get invented ports`).toBeUndefined();
      expect(DPI_ONLY_APPS).toContain(app);
      expect(appPortClass(app)).toBe("dpi-only");
    }
  });

  it("DPI-only rules produce NO kernel statements + the loud skip warning", () => {
    const res = gen([
      policy({
        rules: [
          rule({ id: 1, appName: "netflix" }),
          rule({ id: 2, appName: "tiktok" }),
        ],
      }),
    ]);
    expect(res.statements).toHaveLength(0);
    expect(res.counts.skipped).toBe(2);
    expect(res.skippedApps).toEqual(["netflix", "tiktok"]);
    const codes = res.warnings.filter((w) => w.code === "dpi-required");
    expect(codes).toHaveLength(2);
    for (const w of codes) {
      expect(w.message).toContain("DPI-required — port approximation would over-block; rule skipped");
    }
    expect(res.file).toContain("policy accept;"); // accept policy intact — no drop substituted
    expect(res.file).not.toMatch(/\sdrop\s/);
  });

  it("renders the port-identifiable apps with their exact L4 tuples", () => {
    const res = gen([
      policy({
        rules: [
          rule({ id: 1, appName: "ssh" }),
          rule({ id: 2, appName: "rdp" }),
          rule({ id: 3, appName: "vnc" }),
          rule({ id: 4, appName: "teamviewer" }),
          rule({ id: 5, appName: "bittorrent" }),
        ],
      }),
    ]);
    expect(res.statements).toEqual([
      `meta l4proto tcp tcp sport 22 counter drop comment "appctl:1:ssh"`,
      `meta l4proto tcp tcp dport 22 counter drop comment "appctl:1:ssh"`,
      `meta l4proto tcp tcp sport 3389 counter drop comment "appctl:2:rdp"`,
      `meta l4proto tcp tcp dport 3389 counter drop comment "appctl:2:rdp"`,
      `meta l4proto tcp tcp sport 5900-5902 counter drop comment "appctl:3:vnc"`,
      `meta l4proto tcp tcp dport 5900-5902 counter drop comment "appctl:3:vnc"`,
      `meta l4proto tcp tcp sport 5938 counter drop comment "appctl:4:teamviewer"`,
      `meta l4proto tcp tcp dport 5938 counter drop comment "appctl:4:teamviewer"`,
      `meta l4proto udp udp sport 5938 counter drop comment "appctl:4:teamviewer"`,
      `meta l4proto udp udp dport 5938 counter drop comment "appctl:4:teamviewer"`,
      `meta l4proto tcp tcp sport 6881-6889 counter drop comment "appctl:5:bittorrent"`,
      `meta l4proto tcp tcp dport 6881-6889 counter drop comment "appctl:5:bittorrent"`,
      `meta l4proto udp udp sport 6881-6889 counter drop comment "appctl:5:bittorrent"`,
      `meta l4proto udp udp dport 6881-6889 counter drop comment "appctl:5:bittorrent"`,
    ]);
    expect(res.counts.statements).toBe(14);
  });
});

// ── direction / action semantics ────────────────────────────────────────────

describe("direction rendering — sport vs dport", () => {
  const statementsFor = (direction: AppCtlRuleShape["direction"]) =>
    gen([policy({ rules: [rule({ appName: "ssh", direction })] })]).statements;

  it("upload → sport only", () => {
    expect(statementsFor("upload")).toEqual([`meta l4proto tcp tcp sport 22 counter drop comment "appctl:1:ssh"`]);
  });

  it("download → dport only", () => {
    expect(statementsFor("download")).toEqual([`meta l4proto tcp tcp dport 22 counter drop comment "appctl:1:ssh"`]);
  });

  it("both → two statements (nft cannot OR sport/dport in one rule)", () => {
    const s = statementsFor("both");
    expect(s).toHaveLength(2);
    expect(s[0]).toContain("sport 22");
    expect(s[1]).toContain("dport 22");
  });
});

describe("action semantics", () => {
  it("limit → counter accept + :limit comment suffix + tc warning", () => {
    const res = gen([policy({ rules: [rule({ appName: "ssh", action: "limit", bandwidthLimitMbps: 10 })] })]);
    expect(res.statements[0]).toContain("counter accept");
    expect(res.statements[0]).toContain(`comment "appctl:1:ssh:limit"`);
    expect(res.statements.join("\n")).not.toContain("drop");
    const w = res.warnings.find((x) => x.code === "limit-tc-required");
    expect(w?.message).toContain("limit action requires tc/HTB — counter-only at nft layer (v1)");
  });

  it("allow → explicit accept, never drop", () => {
    const res = gen([policy({ rules: [rule({ appName: "ssh", action: "allow" })] })]);
    expect(res.statements[0]).toContain("counter accept");
    expect(res.file).not.toMatch(/\sdrop\s/);
  });
});

describe("policy-level honesty (no catch-all drop ever)", () => {
  it("unknownAppAction=block emits a warning and NO catch-all drop", () => {
    const res = gen([policy({ unknownAppAction: "block" })]);
    expect(res.warnings.some((w) => w.code === "unknown-app-block-unenforceable")).toBe(true);
    // only the explicit ssh port class drops — unmatched traffic still hits policy accept
    expect(res.statements.every((s) => s.includes("appctl:"))).toBe(true);
    expect(res.file).not.toMatch(/meta l4proto .*counter drop comment "appctl:unknown/);
  });

  it("defaultAction=block emits the terminal partial-enforcement warning", () => {
    const res = gen([policy({ defaultAction: "block" })]);
    const w = res.warnings.find((x) => x.code === "default-block-partial");
    expect(w?.message).toContain("defaultAction=block enforced only for port-identifiable apps (v1)");
    expect(res.file).toContain("policy accept;");
    expect(res.statements).toHaveLength(2); // ssh sport+dport only
  });

  it("user-group scoped rules keep ports enforced + emit the L7 scoping warning", () => {
    const res = gen([policy({ rules: [rule({ userGroupIds: [7, 9] })] })]);
    expect(res.statements).toHaveLength(2);
    expect(res.statements[0]).toContain("sport 22");
    const w = res.warnings.find((x) => x.code === "user-group-scope-l7");
    expect(w?.message).toBe(
      "app 'ssh': user-group scoping applied at L7 engine — port class applies to all sources (v1)",
    );
  });

  it("github renders tcp { 443, 22 } with the port-shared honesty warning", () => {
    const res = gen([policy({ rules: [rule({ appName: "github" })] })]);
    expect(res.statements).toEqual([
      `meta l4proto tcp tcp sport { 443, 22 } counter drop comment "appctl:1:github"`,
      `meta l4proto tcp tcp dport { 443, 22 } counter drop comment "appctl:1:github"`,
    ]);
    const w = res.warnings.filter((x) => x.code === "port-shared");
    expect(w).toHaveLength(1);
    expect(w[0].message).toContain("port-level only — tcp/443 is shared with general HTTPS");
  });

  it("docker-registry renders tcp 443 only (no invented git port)", () => {
    const res = gen([policy({ rules: [rule({ appName: "docker-registry" })] })]);
    expect(res.statements).toHaveLength(2);
    expect(res.statements.every((s) => s.includes(" 443 "))).toBe(true);
    expect(res.warnings.some((w) => w.code === "port-shared")).toBe(true);
  });

  it("disabled policies and rules contribute nothing (silently, like firewall)", () => {
    const res = gen([
      policy({ id: 1, enabled: false, rules: [rule()] }),
      policy({ id: 2, rules: [rule({ id: 9, enabled: false }), rule({ id: 10, appName: "rdp" })] }),
    ]);
    expect(res.counts.policies).toBe(1);
    expect(res.counts.rules).toBe(1);
    expect(res.statements.every((s) => s.includes("appctl:10:"))).toBe(true);
  });
});

// ── drift / counters (pure parsers) ─────────────────────────────────────────

describe("appctlTableBlocksInSync — normalized drift compare", () => {
  const file = gen([policy({ rules: [rule(), rule({ id: 2, appName: "rdp", direction: "download" })] })]).file;

  const liveDump = (counters: string) => [
    "table ip fail2ban {", // foreign table must be ignored
    "}",
    `table inet ${APPCTL_TABLE_NAME} {`,
    `  chain ${APPCTL_CHAIN} {`,
    `    type filter hook forward priority -10; policy accept;`,
    `        meta l4proto tcp tcp sport 22 counter packets 12 bytes 960 counter drop comment "appctl:1:ssh" ${counters}`,
    `        meta l4proto tcp tcp dport 22 counter packets 0 bytes 0 drop comment "appctl:1:ssh"`,
    `        meta l4proto tcp tcp dport 3389 counter packets 0 bytes 0 drop comment "appctl:2:rdp"`,
    "  }",
    "}",
  ].join("\n");

  it("matches when only counters/comments differ (normalized compare)", () => {
    expect(appctlTableBlocksInSync(file, liveDump("counter packets 5 bytes 400"))).toBe(true);
  });

  it("reports drift when a statement changes", () => {
    const drifted = liveDump("").replace("dport 3389", "dport 3390");
    expect(appctlTableBlocksInSync(file, drifted)).toBe(false);
  });

  it("reports not-in-sync when the table is absent", () => {
    expect(appctlTableBlocksInSync(file, "table inet console-firewall { }")).toBe(false);
    expect(appctlTableBlocksInSync(file, "")).toBe(false);
  });

  it("extractAppctlTableBlock strips counters/comments/whitespace", () => {
    const block = extractAppctlTableBlock(liveDump("counter packets 5 bytes 400"));
    expect(block[0]).toBe(`chain ${APPCTL_CHAIN} {`);
    expect(block[1]).toBe("type filter hook forward priority -10; policy accept;");
    // kernel dump `counter packets 5 bytes 400 drop` and generated `counter drop`
    // normalize to the SAME statement (counter token collapsed before verdict)
    expect(block[2]).toBe("meta l4proto tcp tcp sport 22 drop");
  });
});

describe("parseAppctlRuleCounters — comment → DB rule id", () => {
  it("sums sport+dport counters per rule id and parses the app name", () => {
    const dump = [
      `table inet ${APPCTL_TABLE_NAME} {`,
      `  chain ${APPCTL_CHAIN} {`,
      `        meta l4proto tcp tcp sport 22 counter packets 3 bytes 240 drop comment "appctl:11:ssh"`,
      `        meta l4proto tcp tcp dport 22 counter packets 4 bytes 320 drop comment "appctl:11:ssh"`,
      `        meta l4proto tcp tcp dport 3389 counter packets 0 bytes 0 drop comment "appctl:12:rdp"`,
      `        meta l4proto tcp tcp dport 8443 counter packets 7 bytes 560 accept comment "appctl:13:ssh:limit"`,
      `        meta l4proto tcp tcp dport 80 counter packets 99 bytes 8000 drop comment "fw:5:web"`, // foreign prefix ignored
      "  }",
      "}",
    ].join("\n");
    const counters = parseAppctlRuleCounters(dump);
    expect(counters).toEqual([
      { ruleId: 11, appName: "ssh", packets: 7, bytes: 560 },
      { ruleId: 12, appName: "rdp", packets: 0, bytes: 0 },
      { ruleId: 13, appName: "ssh:limit", packets: 7, bytes: 560 },
    ]);
  });

  it("returns [] for an empty/foreign dump", () => {
    expect(parseAppctlRuleCounters("")).toEqual([]);
    expect(parseAppctlRuleCounters('table inet console-firewall { chain forward { } }')).toEqual([]);
  });
});

// ── restore-point guards + whitelist ────────────────────────────────────────

describe("backup restore point", () => {
  // audit fix M3 — backups are TABLE-SCOPED: only utm_appctl is snapshotted
  // and restored; console-firewall / fail2ban tables survive a rollback.
  it("composeBackupFile snapshots ONLY the utm_appctl table behind the scoped prologue", () => {
    const backup = composeBackupFile(
      `table inet console-firewall { }\ntable inet ${APPCTL_TABLE_NAME} {\n  chain appctl_filter {\n    type filter hook input priority -10;\n  }\n}\ntable inet f2b-table { }`,
    );
    expect(isRestoreFileContent(backup)).toBe(true);
    expect(backup.startsWith(`#!/usr/sbin/nft -f\ntable inet ${APPCTL_TABLE_NAME} {}\nflush table inet ${APPCTL_TABLE_NAME}\n`)).toBe(true);
    expect(backup).toContain("appctl_filter");
    expect(backup).not.toContain("console-firewall");
    expect(backup).not.toContain("f2b-table");
    expect(backup).not.toContain("flush ruleset");
  });

  it("refuses restore files without the table-scoped prologue (would merge, not restore)", () => {
    expect(isRestoreFileContent("#!/usr/sbin/nft -f\nflush ruleset\n")).toBe(false);
    expect(isRestoreFileContent("#!/usr/sbin/nft -f\ntable inet utm_appctl { }")).toBe(false);
    expect(isRestoreFileContent("")).toBe(false);
    // absent-table backup is still a valid restore point (empty table after)
    expect(isRestoreFileContent(composeBackupFile(""))).toBe(true);
    expect(composeBackupFile("")).toContain(`# ${APPCTL_TABLE_NAME} absent at backup time`);
  });
});

describe("appctlStepGuarded — exec command whitelist", () => {
  it("accepts exactly the pipeline commands", () => {
    expect(appctlStepGuarded('nft -c -f "/var/lib/console/appctl/appctl-2026.nft"')).toBe(true);
    expect(appctlStepGuarded('nft -f "/var/lib/console/appctl/backup-2026.nft"')).toBe(true);
    expect(appctlStepGuarded('nohup /bin/sh "/var/lib/console/appctl/rollback-2026.sh" >/dev/null 2>&1 &')).toBe(true);
    expect(appctlStepGuarded("nft list ruleset")).toBe(true);
    expect(appctlStepGuarded(`nft list table inet ${APPCTL_TABLE_NAME} 2>/dev/null`)).toBe(true);
    expect(appctlStepGuarded("nft --version")).toBe(true);
    expect(appctlStepGuarded("systemctl enable nftables >/dev/null 2>&1")).toBe(true);
  });

  it("rejects anything else (rm, flush, foreign tables, injection)", () => {
    expect(appctlStepGuarded("nft flush ruleset")).toBe(false);
    expect(appctlStepGuarded('nft -f "/etc/nftables.conf"')).toBe(true); // path is service-controlled, form is whitelisted
    expect(appctlStepGuarded("rm -rf /")).toBe(false);
    expect(appctlStepGuarded("nft delete table inet console-firewall")).toBe(false);
    expect(appctlStepGuarded('nft -f "x"; rm -rf /')).toBe(false);
    expect(appctlStepGuarded("tc qdisc add dev ens32 root htb")).toBe(false);
    expect(appctlStepGuarded("")).toBe(false);
  });
});

// ── apply plan (pure) ───────────────────────────────────────────────────────

describe("buildAppctlApplySteps + rollback script", () => {
  const steps = buildAppctlApplySteps({
    file: "/var/lib/console/appctl/appctl-1.nft",
    backupFile: "/var/lib/console/appctl/backup-1.nft",
    rollbackScript: "/var/lib/console/appctl/rollback-1.sh",
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
      expect(appctlStepGuarded(s.cmd), `step '${s.step}' cmd must be whitelisted: ${s.cmd}`).toBe(true);
    }
  });

  it("check runs before apply; restore targets the backup file", () => {
    const check = steps.find((s) => s.kind === "check")!;
    const apply = steps.find((s) => s.kind === "apply")!;
    const restore = steps.find((s) => s.kind === "restore")!;
    expect(steps.indexOf(check)).toBeLessThan(steps.indexOf(apply));
    expect(check.cmd).toBe('nft -c -f "/var/lib/console/appctl/appctl-1.nft"');
    expect(apply.cmd).toBe('nft -f "/var/lib/console/appctl/appctl-1.nft"');
    expect(restore.cmd).toBe('nft -f "/var/lib/console/appctl/backup-1.nft"');
  });

  it("rollback script sleeps, honors the confirm flag, restores the backup and self-cleans", () => {
    const script = buildAppctlRollbackScript({
      ts: "2026-01-01T00-00-00-000Z",
      confirmSec: 60,
      confirmFile: "/var/lib/console/appctl/confirm-1",
      backupFile: "/var/lib/console/appctl/backup-1.nft",
      scriptFile: "/var/lib/console/appctl/rollback-1.sh",
      stateFile: "/var/lib/console/appctl/state.json",
    });
    expect(script).toContain("#!/bin/sh");
    expect(script).toContain("sleep 60");
    expect(script).toContain('if [ -f "/var/lib/console/appctl/confirm-1" ]; then exit 0; fi');
    expect(script).toContain('/usr/sbin/nft -f "/var/lib/console/appctl/backup-1.nft"');
    expect(script).toContain('rm -f "/var/lib/console/appctl/rollback-1.sh"');
    expect(script).toContain('grep -qF "\\"ts\\": \\"2026-01-01T00-00-00-000Z\\""');
    expect(script).not.toContain("flush ruleset"); // restore = replay backup, never a bare flush
  });
});

// ── test route wiring (MISSING ROUTE BUG regression guard) ──────────────────

describe("POST /api/v1/app-control/policies/[id]/test route", () => {
  const routePath = path.join(
    process.cwd(),
    "src/app/api/v1/app-control/policies/[id]/test/route.ts",
  );

  it("exists and is wired to the existing testApp service via appTestSchema", () => {
    expect(existsSync(routePath)).toBe(true);
    const src = readFileSync(routePath, "utf8");
    expect(src).toContain('appTestSchema } from "@/lib/validators/app-control"');
    expect(src).toContain('testApp } from "@/app/api/v1/app-control/service"');
    expect(src).toContain("bodySchema: appTestSchema");
    expect(src).toContain("testApp(auth.tenantId, policyId, body, ip)");
    expect(src).toContain('numericId(params, "id")');
    expect(src).toContain('area: "app_control"');
  });

  it("validates the app-test payload shape the route accepts (decision JSON)", () => {
    // appTestSchema: appName (nDPI label) + optional clientIp + direction default
    const schemaSrc = readFileSync(
      path.join(process.cwd(), "src/lib/validators/app-control.ts"),
      "utf8",
    );
    expect(schemaSrc).toContain("appNameSchema");
    expect(schemaSrc).toMatch(/export const appTestSchema = z\.object\(\{[\s\S]*?clientIp[\s\S]*?direction/);
  });
});
