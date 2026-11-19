/**
 * SSL Inspection OS layer tests — pure core of lib/ssl-inspection/os.ts
 * (renderer determinism + hash, bypass-before-bump ordering, pinning
 * terminate vs splice, sslproxy_cert_error per sslErrorHandling, conf.d
 * include-order warning, command whitelist, plan ordering, refusal when the
 * host squid lacks ssl-crtd, drift) plus executor tests against STUBBED
 * appliance binaries in a tmp root (backup → stage → squid -k parse → reload
 * → verify → state.json LAST; gate off → preview with zero fs writes).
 *
 * /etc/squid/squid.conf is NEVER a managed output here — the write whitelist
 * test pins that red line (URL-Filter module owns the main conf full-file).
 */

import fs from "node:fs";
import path from "node:path";
import { beforeAll, describe, expect, it, vi } from "vitest";
import {
  buildSslApplyPlan,
  bypassToDstdomain,
  bypassToDst,
  computeSslDrift,
  effectivePolicy,
  hardSslRefusal,
  interpretSquidParse,
  isSslBackupDir,
  MANAGED_FOOTER,
  MANAGED_HEADER,
  renderSslFragment,
  sha256_16,
  SQUID_MAIN_CONF,
  SSL_BUMP_PORT,
  SSL_CRTD_LEGACY_BINARY,
  SSL_CRTD_PROGRAM,
  SSL_MANAGED_FILE,
  sslCrtdFromVersionOutput,
  sslStepGuarded,
  SSL_STATE_DIR,
  type SslBypassRuleInput,
  type SslOsFacts,
  type SslPolicyInput,
  type SslRenderInput,
} from "@/lib/ssl-inspection/os";

// ── fixtures ────────────────────────────────────────────────────────────────

const policy = (over: Partial<SslPolicyInput> = {}): SslPolicyInput => ({
  id: 1,
  name: "corp-tls",
  mode: "selective",
  signingCaId: 11,
  signingCaName: "corp-root-ca",
  signingCaStatus: "active",
  hstsHandling: "honor",
  certPinningAction: "bypass",
  invalidCertAction: "block",
  minTlsVersion: "1.2",
  enabled: true,
  ...over,
});

const rule = (over: Partial<SslBypassRuleInput> = {}): SslBypassRuleInput => ({
  id: 1,
  policyId: 1,
  matchType: "domain",
  matchValue: "bank.example",
  reason: "banking",
  enabled: true,
  ...over,
});

const input = (over: Partial<SslRenderInput> = {}): SslRenderInput => ({
  policies: [policy()],
  bypassRules: [],
  ...over,
});

const facts = (over: Partial<SslOsFacts> = {}): SslOsFacts => ({
  available: true,
  unitState: "active",
  running: true,
  sslCrtdSupported: true,
  sslCrtdMethod: "configure-flag",
  version: "6.13",
  managedFilePresent: false,
  managedByConsole: false,
  liveHash: null,
  port3129Bound: null,
  sslDbPresent: false,
  ...over,
});

// ── renderer ────────────────────────────────────────────────────────────────

describe("renderSslFragment — determinism + hash", () => {
  const base = input();

  it("is byte-stable and hash-stable (sha256[:16] over the fragment)", () => {
    const a = renderSslFragment(base);
    const b = renderSslFragment(base);
    expect(a.conf).toBe(b.conf);
    expect(a.confHash).toBe(b.confHash);
    expect(a.confHash).toMatch(/^[0-9a-f]{16}$/);
    expect(a.confHash).toBe(sha256_16(a.conf));
    expect(a.needsSslBump).toBe(true);
    expect(a.policy?.id).toBe(1);
  });

  it("carries the console managed markers and never the main conf as an output", () => {
    const r = renderSslFragment(base);
    expect(r.conf.startsWith(MANAGED_HEADER)).toBe(true);
    expect(r.conf.trimEnd().endsWith(MANAGED_FOOTER)).toBe(true);
    // red line: squid.conf appears only in comments, never as a directive target
    const directiveLines = r.conf.split("\n").filter((l) => l && !l.startsWith("#"));
    expect(directiveLines.join("\n")).not.toContain(SQUID_MAIN_CONF);
  });

  it("always surfaces the conf.d include-order warning (deny-all ordering)", () => {
    const r = renderSslFragment(base);
    expect(
      r.warnings.some((w) => w.includes("conf.d include order") && w.includes("deny all") && w.includes("URL-Filter")),
    ).toBe(true);
  });

  it("warns about the generated-CA requirement and pinning/HSTS limits", () => {
    const r = renderSslFragment(base);
    expect(r.warnings.some((w) => w.includes("GENERATED CA") && w.includes("PKI module") && w.includes("trusted root"))).toBe(
      true,
    );
    expect(r.warnings.some((w) => w.includes("cannot DETECT certificate pinning"))).toBe(true);
    expect(r.warnings.some((w) => w.includes("sslcrtd certificate cache"))).toBe(true);
  });

  it("missing signingCaId → honest CA warning (PKI module reference)", () => {
    const r = renderSslFragment(input({ policies: [policy({ signingCaId: null, signingCaName: null })] }));
    expect(r.warnings.some((w) => w.includes("no signing CA") && w.includes("PKI module"))).toBe(true);
    expect(r.conf).toContain("# WARNING: no signing CA configured");
  });

  it("inactive signing CA → warning (squid would serve certs clients reject)", () => {
    const r = renderSslFragment(input({ policies: [policy({ signingCaStatus: "revoked" })] }));
    expect(r.warnings.some((w) => w.includes("revoked") && w.includes("activate or replace"))).toBe(true);
  });
});

describe("renderSslFragment — ssl_bump flow (bypass BEFORE bump)", () => {
  const full = renderSslFragment(
    input({
      bypassRules: [
        rule({ id: 1, matchType: "domain", matchValue: "bank.example" }),
        rule({ id: 2, matchType: "wildcard", matchValue: "*.portal.example" }),
        rule({ id: 3, matchType: "ip", matchValue: "10.0.0.5" }),
        rule({ id: 4, matchType: "cidr", matchValue: "10.0.0.0/8" }),
        rule({ id: 5, matchType: "category", matchValue: "banking" }),
      ],
    }),
  );

  it("groups domain/wildcard into one dstdomain ACL and ip/cidr into dst", () => {
    expect(full.conf).toContain("acl utm_ssl_dom_1 dstdomain .bank.example .portal.example");
    expect(full.conf).toContain("acl utm_ssl_dst_1 dst 10.0.0.5 10.0.0.0/8");
    expect(bypassToDstdomain("domain", "bank.example")).toBe(".bank.example");
    expect(bypassToDstdomain("wildcard", "*.cdn.example")).toBe(".cdn.example");
    expect(bypassToDst("cidr", "10.0.0.0/8")).toBe("10.0.0.0/8");
    expect(bypassToDstdomain("ip", "10.0.0.5")).toBeNull();
  });

  it("category bypass rules are skipped with a warning, never rendered as ACLs", () => {
    expect(full.conf).not.toMatch(/^acl .*banking/m);
    expect(full.conf).toContain('# skipped bypass rule #5: category "banking"');
    expect(full.warnings.some((w) => w.includes("category-based"))).toBe(true);
    expect(full.skipped.some((s) => s.name.includes("#5"))).toBe(true);
  });

  it("splice lines (incl. pinning list) come BEFORE the bump lines", () => {
    const conf = full.conf;
    const firstSplice = conf.indexOf("ssl_bump splice ");
    const pinSplice = conf.indexOf("ssl_bump splice utm_ssl_pin_1");
    const bump = conf.indexOf("ssl_bump bump all");
    const peek = conf.indexOf("ssl_bump peek utm_ssl_step_1");
    expect(firstSplice).toBeGreaterThan(-1);
    expect(pinSplice).toBeGreaterThan(firstSplice);
    expect(bump).toBeGreaterThan(firstSplice);
    expect(bump).toBeGreaterThan(pinSplice);
    expect(peek).toBeGreaterThan(firstSplice); // selective mode peeks after splices
    expect(peek).toBeLessThan(bump);
    expect(full.spliceAcls).toEqual(["utm_ssl_dom_1", "utm_ssl_dst_1", "utm_ssl_pin_1"]);
  });

  it("selective mode renders peek + bump, sslcrtd_program and the dedicated :3129 ssl-bump listener", () => {
    const conf = full.conf;
    expect(conf).toContain("ssl_bump peek utm_ssl_step_1");
    expect(conf).toContain("ssl_bump bump all");
    expect(conf).toContain("acl utm_ssl_step_1 at_step SslBump1");
    expect(conf).toContain(`sslcrtd_program ${SSL_CRTD_PROGRAM} -s /var/spool/squid/ssl_db -M 4MB`);
    expect(conf).toContain(`http_port ${SSL_BUMP_PORT} ssl-bump`);
    expect(conf).not.toContain("http_port 3128"); // :3128 belongs to URL-Filter
  });

  it("invalidCertAction=block → sslproxy_cert_error deny all (with warn note absent)", () => {
    expect(full.conf).toContain("sslproxy_cert_error deny all");
    expect(full.conf).not.toContain("sslproxy_cert_error allow all");
  });

  it("invalidCertAction=warn_bypass → sslproxy_cert_error allow all + honest no-warn-step note", () => {
    const r = renderSslFragment(input({ policies: [policy({ invalidCertAction: "warn_bypass" })] }));
    expect(r.conf).toContain("sslproxy_cert_error allow all");
    expect(r.warnings.some((w) => w.includes("no warn-only step"))).toBe(true);
  });

  it("certPinningAction=block → ssl_bump terminate (pinning SNIs fail, not MITM'd)", () => {
    const r = renderSslFragment(input({ policies: [policy({ certPinningAction: "block" })] }));
    expect(r.conf).toContain("ssl_bump terminate utm_ssl_pin_1");
    expect(r.conf).not.toContain("ssl_bump splice utm_ssl_pin_1");
    expect(r.warnings.some((w) => w.includes("ssl_bump terminate"))).toBe(true);
  });

  it("full mode: no peek step — bump all directly after the splices", () => {
    const r = renderSslFragment(input({ policies: [policy({ mode: "full" })] }));
    expect(r.conf).not.toContain("ssl_bump peek");
    const bump = r.conf.indexOf("ssl_bump bump all");
    const splice = r.conf.indexOf("ssl_bump splice utm_ssl_pin_1");
    expect(splice).toBeGreaterThan(-1);
    expect(bump).toBeGreaterThan(splice);
  });

  it("no enabled selective/full policy → empty fragment, no bump flow, no listener, no sslcrtd", () => {
    const r = renderSslFragment(input({ policies: [policy({ mode: "none" })] }));
    expect(r.needsSslBump).toBe(false);
    expect(r.policy).toBeNull();
    // no DIRECTIVE lines at all (comments may mention the disabled directives)
    expect(r.conf).not.toMatch(/^ssl_bump /m);
    expect(r.conf).not.toMatch(/^sslcrtd_program /m);
    expect(r.conf).not.toMatch(/^http_port /m);
    expect(r.conf).not.toMatch(/^acl /m);
    expect(r.conf).toContain("MITM is OFF");
    expect(r.conf).toContain("# skipped: policy \"corp-tls\" (db id 1)");
  });

  it("engine parity: first ENABLED selective/full policy by id wins; others skipped honestly", () => {
    const r = renderSslFragment(
      input({
        policies: [
          policy({ id: 3, name: "second", enabled: true }),
          policy({ id: 7, name: "third", enabled: true }),
          policy({ id: 9, name: "disabled", enabled: false }),
        ],
        bypassRules: [
          rule({ id: 2, policyId: 3, matchValue: "bank.example" }),
          rule({ id: 3, policyId: 7, matchValue: "wrong.example" }),
        ],
      }),
    );
    expect(r.policy?.id).toBe(3);
    expect(r.conf).toContain('acl utm_ssl_dom_3 dstdomain .bank.example');
    expect(r.conf).not.toContain("wrong.example"); // other policy's rules never leak
    expect(r.skipped.some((s) => s.name.includes("third") && s.name.includes("db id 7"))).toBe(true);
    expect(effectivePolicy(input({ policies: [policy({ enabled: false })] })).needsSslBump).toBe(false);
  });
});

// ── red lines: whitelist + refusals ────────────────────────────────────────

describe("sslStepGuarded (command whitelist)", () => {
  it("allows the exact plan commands", () => {
    expect(sslStepGuarded("squid -k parse")).toBe(true);
    expect(sslStepGuarded("squid -v")).toBe(true);
    expect(sslStepGuarded("systemctl reload squid")).toBe(true);
    expect(sslStepGuarded("systemctl start squid")).toBe(true);
    expect(sslStepGuarded("systemctl is-active squid")).toBe(true);
    expect(sslStepGuarded(`ss -ltn '( sport = :3129 )'`)).toBe(true);
    expect(sslStepGuarded(`mkdir -p ${SSL_STATE_DIR}`)).toBe(true);
    expect(sslStepGuarded(`write-file ${SSL_MANAGED_FILE}`)).toBe(true);
    expect(sslStepGuarded(`cp ${SSL_MANAGED_FILE} ${SSL_STATE_DIR}/backup-20261118T00-00-00-000Z${SSL_MANAGED_FILE}`)).toBe(true);
    expect(sslStepGuarded(`rm -f ${SSL_MANAGED_FILE}`)).toBe(true); // rollback only
    expect(sslStepGuarded(`ls ${SSL_CRTD_LEGACY_BINARY}`)).toBe(true);
    expect(sslStepGuarded(`${SSL_CRTD_PROGRAM} -c -s /var/spool/squid/ssl_db -M 4MB`)).toBe(true);
  });

  it("rejects arbitrary / injected / out-of-namespace commands — squid.conf is NOT writable", () => {
    expect(sslStepGuarded("rm -rf /")).toBe(false);
    expect(sslStepGuarded("systemctl restart sshd")).toBe(false);
    expect(sslStepGuarded("squid -k reconfigure")).toBe(false);
    expect(sslStepGuarded("squid -k parse -f /tmp/evil.conf")).toBe(false);
    // RED LINE: the URL-Filter module owns squid.conf full-file — no writes, no rm
    expect(sslStepGuarded("write-file /etc/squid/squid.conf")).toBe(false);
    expect(sslStepGuarded("rm -f /etc/squid/squid.conf")).toBe(false);
    expect(sslStepGuarded("cp /etc/squid/squid.conf /tmp/x")).toBe(false);
    expect(sslStepGuarded(`write-file ${SSL_MANAGED_FILE} extra`)).toBe(false);
    expect(sslStepGuarded(`write-file /etc/squid/conf.d/evil.conf`)).toBe(false);
    expect(sslStepGuarded("nft flush ruleset")).toBe(false);
    expect(sslStepGuarded("")).toBe(false);
    expect(sslStepGuarded("bash -c 'echo hi'")).toBe(false);
  });

  it("backup dirs must live in SSL_STATE_DIR with backup-<ts> names", () => {
    expect(isSslBackupDir(`${SSL_STATE_DIR}/backup-20261118T00-00-00-000Z`)).toBe(true);
    expect(isSslBackupDir(`${SSL_STATE_DIR}/evil`)).toBe(false);
    expect(isSslBackupDir(`${SSL_STATE_DIR}/../elsewhere/backup-x`)).toBe(false);
    expect(isSslBackupDir("/tmp/backup-1")).toBe(false);
  });
});

describe("hardSslRefusal", () => {
  it("refuses shell-breaking matchValue / policy names (validator bypass)", () => {
    expect(hardSslRefusal(input({ bypassRules: [rule({ matchValue: "a; rm -rf /" })] }))).toContain("refused");
    expect(hardSslRefusal(input({ policies: [policy({ name: 'evil"conf' })] }))).toContain("refused");
  });
  it("passes a legitimate config", () => {
    expect(hardSslRefusal(input())).toBeNull();
  });
  it("REFUSES a needsSslBump policy with no signing CA (hard, not warning)", () => {
    const r = hardSslRefusal(input({ policies: [policy({ signingCaId: null, signingCaName: null })] }));
    expect(r).toContain("refused");
    expect(r).toContain("no signing CA");
    expect(r).toContain("select an active signing CA");
    // the apply plan carries the refusal → executor must never run
    const plan = buildSslApplyPlan(input({ policies: [policy({ signingCaId: null, signingCaName: null })] }), facts(), "exec", "t");
    expect(plan.refused).toContain("select an active signing CA");
  });
  it("REFUSES a needsSslBump policy whose signing CA is not active", () => {
    const r = hardSslRefusal(input({ policies: [policy({ signingCaStatus: "revoked" })] }));
    expect(r).toContain("refused");
    expect(r).toContain("revoked");
    expect(r).toContain("select an active signing CA");
    const plan = buildSslApplyPlan(input({ policies: [policy({ signingCaStatus: "pending" })] }), facts(), "exec", "t");
    expect(plan.refused).toContain("pending");
    expect(plan.refused).toContain("select an active signing CA");
  });
  it("mode none (no MITM) does not require a signing CA", () => {
    expect(hardSslRefusal(input({ policies: [policy({ mode: "none", signingCaId: null })] }))).toBeNull();
  });
});

// ── plan: ordering, guard, ssl-crtd refusal ────────────────────────────────

describe("buildSslApplyPlan", () => {
  it("builds a fully guarded plan: backup → write → sslcrtd init → validate → reload → verify", () => {
    const plan = buildSslApplyPlan(input(), facts({ managedFilePresent: true }), "exec", "20261118T00-00-00-000Z");
    expect(plan.guarded).toBe(true);
    expect(plan.refused).toBeNull();
    const cmds = plan.steps.map((s) => s.cmd);
    const idx = (c: string) => cmds.indexOf(c);
    // backup of the existing fragment BEFORE staging
    expect(cmds).toContain(`cp ${SSL_MANAGED_FILE} ${SSL_STATE_DIR}/backup-20261118T00-00-00-000Z${SSL_MANAGED_FILE}`);
    expect(idx(`cp ${SSL_MANAGED_FILE} ${SSL_STATE_DIR}/backup-20261118T00-00-00-000Z${SSL_MANAGED_FILE}`)).toBeLessThan(
      idx(`write-file ${SSL_MANAGED_FILE}`),
    );
    // validate AFTER staging, BEFORE reload
    const validateIdx = idx("squid -k parse");
    const reloadIdx = idx("systemctl reload squid");
    const initIdx = cmds.findIndex((c) => c.startsWith(`${SSL_CRTD_PROGRAM} -c`));
    expect(Math.max(idx(`write-file ${SSL_MANAGED_FILE}`), initIdx)).toBeLessThan(validateIdx);
    expect(validateIdx).toBeLessThan(reloadIdx);
    expect(cmds).toContain("systemctl is-active squid");
    expect(cmds).toContain(`ss -ltn '( sport = :3129 )'`);
    expect(plan.confHash).toBe(renderSslFragment(input()).confHash);
    expect(plan.backupDir.startsWith(`${SSL_STATE_DIR}/backup-`)).toBe(true);
    expect(plan.needsSslBump).toBe(true);
    expect(plan.policyId).toBe(1);
  });

  it("unit inactive → start (not reload); probe is optional", () => {
    const plan = buildSslApplyPlan(input(), facts({ unitState: "inactive" }), "exec", "t");
    expect(plan.steps.find((s) => s.kind === "reload")?.cmd).toBe("systemctl start squid");
    const probe = plan.steps.find((s) => s.kind === "probe");
    expect(probe?.optional).toBe(true);
  });

  it("sslcrtd init step only when the cache dir is missing and capability is proven", () => {
    const withInit = buildSslApplyPlan(input(), facts({ sslDbPresent: false }), "exec", "t");
    expect(withInit.steps.some((s) => s.kind === "init")).toBe(true);
    const withoutInit = buildSslApplyPlan(input(), facts({ sslDbPresent: true }), "exec", "t");
    expect(withoutInit.steps.some((s) => s.kind === "init")).toBe(false);
  });

  it("REFUSES with the actionable message when sslCrtdSupported=false and MITM is required", () => {
    const plan = buildSslApplyPlan(input(), facts({ sslCrtdSupported: false, sslCrtdMethod: null }), "exec", "t");
    expect(plan.refused).toBeTruthy();
    expect(plan.refused).toContain("ssl-crtd");
    expect(plan.refused).toContain("--enable-ssl-crtd");
    expect(plan.refused).toContain("install or compile squid with ssl-crtd");
    expect(plan.refused).toContain("cert-pinning-bypass-only mode (mode none)");
    // plan is still fully described (preview honesty) but nothing will execute
    expect(plan.guarded).toBe(true);
    expect(plan.confText).toContain("ssl_bump");
  });

  it("mode none → empty plan: write only, NO init/validate-less reload/verify steps", () => {
    const plan = buildSslApplyPlan(input({ policies: [policy({ mode: "none" })] }), facts(), "exec", "t");
    expect(plan.empty).toBe(true);
    const cmds = plan.steps.map((s) => s.cmd);
    expect(cmds).toContain(`write-file ${SSL_MANAGED_FILE}`);
    expect(cmds).not.toContain("systemctl start squid");
    expect(cmds).not.toContain("systemctl reload squid");
    expect(plan.refused).toBeNull();
  });

  it("empty render over an INSTALLED fragment still reloads (unload the old bump flow)", () => {
    const plan = buildSslApplyPlan(
      input({ policies: [policy({ mode: "none" })] }),
      facts({ managedFilePresent: true, unitState: "active" }),
      "exec",
      "t",
    );
    const cmds = plan.steps.map((s) => s.cmd);
    expect(cmds).toContain("systemctl reload squid");
  });
});

// ── capability parse + validate interpretation ─────────────────────────────

describe("sslCrtdFromVersionOutput + interpretSquidParse", () => {
  it("detects --enable-ssl-crtd in the configure line (and rejects stock Debian builds)", () => {
    expect(sslCrtdFromVersionOutput("configure options: '--enable-ssl-crtd' '--with-openssl'")).toBe(true);
    expect(
      sslCrtdFromVersionOutput(
        "configure options: '--build=x86_64-linux-gnu' '--prefix=/usr' '--enable-auth' --enable-ssl", // no crtd
      ),
    ).toBe(false);
  });

  it("squid -k parse passes on rc=0 with no output; FATAL lines fail it", () => {
    expect(interpretSquidParse("", true).ok).toBe(true);
    const bad = interpretSquidParse("2026/11/18 00:00:00 kid1| FATAL: Can't parse", true);
    expect(bad.ok).toBe(false);
    expect(bad.detail).toContain("FATAL");
    expect(interpretSquidParse("WARNING: cache_peer has no name", true).ok).toBe(true);
    expect(interpretSquidParse("", false).ok).toBe(false);
  });
});

// ── drift ──────────────────────────────────────────────────────────────────

describe("computeSslDrift", () => {
  const hash = "a".repeat(16);

  it("in-sync: fragment deployed, hash matches state AND render, unit active, ssl-crtd ok", () => {
    const d = computeSslDrift(
      { available: true, unitState: "active", liveHash: hash, managedByConsole: true, sslCrtdSupported: true, stateHash: hash },
      hash,
      true,
    );
    expect(d.inSync).toBe(true);
    expect(d.managedByConsole).toBe(true);
    expect(d.reasons).toEqual([]);
  });

  it("not deployed / capability missing / unit down → honest drift reasons", () => {
    const notDeployed = computeSslDrift(
      { available: true, unitState: "active", liveHash: null, managedByConsole: false, sslCrtdSupported: true },
      hash,
      true,
    );
    expect(notDeployed.reasons.some((r) => r.includes("not deployed"))).toBe(true);

    const noCrtd = computeSslDrift(
      { available: true, unitState: "active", liveHash: hash, managedByConsole: true, sslCrtdSupported: false, stateHash: hash },
      hash,
      true,
    );
    expect(noCrtd.reasons.some((r) => r.includes("lacks ssl-crtd"))).toBe(true);
    expect(noCrtd.inSync).toBe(false);

    const down = computeSslDrift(
      { available: true, unitState: "inactive", liveHash: hash, managedByConsole: true, sslCrtdSupported: true, stateHash: hash },
      hash,
      true,
    );
    expect(down.reasons.some((r) => r.includes("squid service is inactive"))).toBe(true);
  });

  it("hand-edited fragment → not managed by console; console edit after apply → drift", () => {
    const edited = computeSslDrift(
      { available: true, unitState: "active", liveHash: "b".repeat(16), managedByConsole: false, sslCrtdSupported: true, stateHash: hash },
      hash,
      true,
    );
    expect(edited.reasons.some((r) => r.includes("outside the console"))).toBe(true);

    const stale = computeSslDrift(
      { available: true, unitState: "active", liveHash: hash, managedByConsole: true, sslCrtdSupported: true, stateHash: hash },
      "c".repeat(16),
      true,
    );
    expect(stale.reasons.some((r) => r.includes("changed since last apply"))).toBe(true);
  });

  it("mode none (no MITM) does not require an active unit or ssl-crtd", () => {
    const d = computeSslDrift(
      { available: true, unitState: "inactive", liveHash: hash, managedByConsole: true, sslCrtdSupported: false, stateHash: hash },
      hash,
      false,
    );
    expect(d.inSync).toBe(true);
  });

  it("squid unavailable → drift with availability reason", () => {
    const d = computeSslDrift(
      { available: false, unitState: null, liveHash: hash, managedByConsole: true, sslCrtdSupported: true, stateHash: hash },
      hash,
      true,
    );
    expect(d.reasons[0]).toContain("not available");
  });
});

// ── executor (stubbed binaries, real fs, real tmp state dir) ───────────────

const TMP = path.join("/tmp", `ssl-os-test-${process.pid}`);

function writeStub(bin: string, body: string): void {
  const p = path.join(TMP, "bin", bin);
  fs.writeFileSync(p, `#!/bin/sh\n${body}\n`, { mode: 0o755 });
}

function envFor(): Record<string, string> {
  return {
    CONSOLE_OS_APPLY: "1",
    ADAPTER_MODE: "host",
    CONSOLE_SSL_INSPECTION_DIR: path.join(TMP, "var", "lib", "console", "ssl-inspection"),
    CONSOLE_SQUID_CONF_D: path.join(TMP, "etc", "squid", "conf.d"),
    CONSOLE_SQUID_SSL_CRTD: path.join(TMP, "bin", "security_file_certgen"),
  };
}

async function freshModules(env: Record<string, string>) {
  vi.resetModules();
  for (const [k, v] of Object.entries(env)) process.env[k] = v;
  return {
    os: await import("@/lib/ssl-inspection/os"),
    svc: await import("@/lib/ssl-inspection/os-service"),
  };
}

describe("execSslApplyPlan (executor)", () => {
  beforeAll(() => {
    fs.rmSync(TMP, { recursive: true, force: true });
    fs.mkdirSync(path.join(TMP, "bin"), { recursive: true });
    // appliance stubs — squid is ssl-crtd CAPABLE here, systemctl/ss work
    writeStub("squid", `case "$1" in
  -v) echo "Squid Cache: Version 6.13"; echo "configure options: '--prefix=/usr' '--enable-ssl-crtd' '--with-openssl'"; exit 0 ;;
  -k) exit 0 ;;
esac
exit 0`);
    writeStub("systemctl", `case "$1" in
  is-active) echo active; exit 0 ;;
  reload|start|restart) exit 0 ;;
esac
exit 0`);
    writeStub("ss", `echo "LISTEN 0 128 0.0.0.0:3129 0.0.0.0:*"; exit 0`);
    writeStub("security_file_certgen", `exit 0`);
    // stubs must win over the real PATH for hasTool()
    process.env.PATH = `${path.join(TMP, "bin")}:${process.env.PATH ?? ""}`;
  });

  it("green path: backup → stage → sslcrtd init → validate → reload → verify, state.json LAST", async () => {
    const { os, svc } = await freshModules(envFor());
    fs.rmSync(path.join(TMP, "var"), { recursive: true, force: true });
    fs.rmSync(path.join(TMP, "etc"), { recursive: true, force: true });
    // pre-existing fragment must be backed up verbatim and restored on rollback
    fs.mkdirSync(path.dirname(os.SSL_MANAGED_FILE), { recursive: true });
    fs.writeFileSync(os.SSL_MANAGED_FILE, "# pre-apply fragment\n");

    const plan = os.buildSslApplyPlan(input(), facts({ managedFilePresent: true, sslDbPresent: false }), "exec", "TS1");
    expect(plan.guarded).toBe(true);
    const outcome = await svc.execSslApplyPlan(plan);

    expect(outcome.gate).toBe("on");
    expect(outcome.applied).toBe(true);
    expect(outcome.rolledBack).toBe(false);
    expect(outcome.reason).toContain("reload");

    // installed fragment matches the render byte-for-byte (hash-stable)
    expect(fs.readFileSync(os.SSL_MANAGED_FILE, "utf8")).toBe(plan.confText);
    // pre-apply bytes captured in backup-<TS1>/ (layout: backupDir + abs path)
    expect(fs.readFileSync(`${plan.backupDir}${os.SSL_MANAGED_FILE}`, "utf8")).toBe("# pre-apply fragment\n");

    const results = Object.fromEntries(outcome.results.map((r) => [r.step, r]));
    expect(results["validate config"]?.ok).toBe(true);
    expect(results["validate config"]?.detail).toContain("squid -k parse passed");
    expect(results["init sslcrtd cache"]?.ok).toBe(true);
    expect(results["reload squid"]?.ok).toBe(true);
    expect(results["verify unit"]?.ok).toBe(true);

    // state.json LAST: confHash + appliedAt + full step results
    const state = JSON.parse(fs.readFileSync(path.join(os.SSL_STATE_DIR, "state.json"), "utf8")) as Record<string, unknown>;
    expect(state.confHash).toBe(plan.confHash);
    expect((state.lastApply as { applied: boolean }).applied).toBe(true);
    expect(((state.results as unknown[]) ?? []).length).toBe(outcome.results.length);

    // rollback: hand-edited fragment → restore pre-apply bytes + revalidate
    fs.writeFileSync(os.SSL_MANAGED_FILE, "# hand-edited after apply\n");
    const rb = await svc.rollbackSslOs(true);
    expect(rb.rolledBack).toBe(true);
    expect(rb.revalidated).toBe(true);
    expect(fs.readFileSync(os.SSL_MANAGED_FILE, "utf8")).toBe("# pre-apply fragment\n");
    const stateAfter = JSON.parse(fs.readFileSync(path.join(os.SSL_STATE_DIR, "state.json"), "utf8")) as {
      lastApply?: { action?: string };
    };
    expect(stateAfter.lastApply?.action).toBe("rollback");
  }, 30000);

  it("refusal: sslCrtdSupported=false → actionable refusal, zero exec, zero writes", async () => {
    const { os, svc } = await freshModules(envFor());
    fs.rmSync(path.join(TMP, "var"), { recursive: true, force: true });
    fs.rmSync(path.join(TMP, "etc"), { recursive: true, force: true });
    const plan = os.buildSslApplyPlan(
      input(),
      { ...facts({ sslCrtdSupported: false, sslCrtdMethod: null, sslDbPresent: false }) },
      "exec",
      "TS2",
    );
    expect(plan.refused).toBeTruthy();
    const outcome = await svc.execSslApplyPlan(plan);
    expect(outcome.gate).toBe("on");
    expect(outcome.applied).toBe(false);
    expect(outcome.refused).toContain("install or compile squid with ssl-crtd");
    expect(outcome.refused).toContain("cert-pinning-bypass-only mode (mode none)");
    expect(outcome.results).toHaveLength(0); // nothing executed — honest refusal
    expect(fs.existsSync(os.SSL_MANAGED_FILE)).toBe(false);
    expect(fs.existsSync(path.join(os.SSL_STATE_DIR, "state.json"))).toBe(false);
  }, 30000);

  it("gate off: plan preview only — no fs writes at all", async () => {
    const { os, svc } = await freshModules({ ...envFor(), CONSOLE_OS_APPLY: "0" });
    fs.rmSync(path.join(TMP, "var"), { recursive: true, force: true });
    fs.rmSync(path.join(TMP, "etc"), { recursive: true, force: true });
    const plan = os.buildSslApplyPlan(input(), facts(), "plan", "TS3");
    const outcome = await svc.execSslApplyPlan(plan);
    expect(outcome.gate).toBe("off");
    expect(outcome.applied).toBe(false);
    expect(outcome.results).toHaveLength(0);
    expect(outcome.plan.confText).toContain("ssl_bump");
    expect(fs.existsSync(path.join(os.SSL_STATE_DIR, "state.json"))).toBe(false);
    expect(fs.existsSync(os.SSL_MANAGED_FILE)).toBe(false);
  }, 30000);
});
