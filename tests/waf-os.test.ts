/**
 * WAF OS layer tests — pure core of lib/waf/os.ts: renderer determinism,
 * SecRuleEngine mode (learning vs enforcing), CRS setup tx values, exclusion
 * rendering (rule_id / param / url), geo map, limit_req math (rpm → r/m zone
 * rate + burst = rpm/60 default), command whitelist, plan ordering (nginx -t
 * AFTER staging BEFORE reload), empty-vhost behavior (no start step) and
 * drift. Filesystem/exec boundaries are NOT exercised here (prod E2E covers
 * them on the appliance); everything below is deterministic.
 */

import { describe, it, expect } from "vitest";
import {
  buildWafApplyPlan,
  burstForPolicy,
  certPathsFor,
  computeWafDrift,
  hardWafRefusal,
  interpretNginxTest,
  isWafBackupDir,
  paramTargetFromMatchValue,
  renderModsecSetup,
  renderModsecVhost,
  renderWafManaged,
  rpmToRps,
  wafConfHash,
  wafHash,
  wafStepGuarded,
  CRS_BASE_DIR,
  INSTALLED_CRS_VERSION,
  WAF_MANAGED_FILE,
  WAF_RULES_DIR,
  WAF_SSL_DIR,
  WAF_STATE_DIR,
  type WafExclusionInput,
  type WafInputs,
  type WafOsFacts,
  type WafPolicyInput,
  type WafVhostInput,
} from "@/lib/waf/os";

// ── fixtures ────────────────────────────────────────────────────────────────

const vhost = (over: Partial<WafVhostInput> = {}): WafVhostInput => ({
  id: 7,
  name: "app",
  hostname: "app.corp.local",
  backendHost: "127.0.0.1",
  backendPort: 8080,
  listenPort: 443,
  tls: true,
  certId: null,
  mode: "waf",
  enabled: true,
  ...over,
});

const policy = (over: Partial<WafPolicyInput> = {}): WafPolicyInput => ({
  id: 3,
  name: "edge-policy",
  vhostId: 7,
  owaspCrsEnabled: true,
  crsVersion: "3.3",
  paranoiaLevel: 2,
  anomalyInThreshold: 6,
  anomalyOutThreshold: 4,
  learningMode: false,
  geoBlockCountries: [],
  rateLimitRpm: null,
  rateLimitBurst: null,
  apiProtection: false,
  enabled: true,
  ...over,
});

const exclusion = (over: Partial<WafExclusionInput> = {}): WafExclusionInput => ({
  id: 1,
  policyId: 3,
  scope: "rule_id",
  matchValue: "942100",
  ruleId: null,
  enabled: true,
  ...over,
});

const inputs = (over: Partial<WafInputs> = {}): WafInputs => ({
  vhosts: [vhost()],
  policies: [policy()],
  exclusions: [],
  certs: [],
  ...over,
});

const facts = (over: Partial<WafOsFacts> = {}): WafOsFacts => ({
  available: true,
  unitState: "inactive",
  managedFiles: [],
  confHash: null,
  stateHash: null,
  portBound: null,
  crsDir: CRS_BASE_DIR,
  ...over,
});

const pem = (tag: string) => `-----BEGIN CERTIFICATE-----\n${tag}\n-----END CERTIFICATE-----\n`;

// ── renderer: ModSecurity per-vhost ruleset ────────────────────────────────

describe("renderModsecVhost (engine mode + CRS layout)", () => {
  it("renders SecRuleEngine On with CRS include glob from the constant root", () => {
    const r = renderModsecVhost(vhost(), policy(), []);
    expect(r.conf).toContain("SecRuleEngine On");
    expect(r.conf).toContain("SecRequestBodyAccess On");
    expect(r.conf).toContain("SecResponseBodyAccess Off");
    expect(r.conf).toContain(`Include ${WAF_RULES_DIR}/7-setup.conf`);
    expect(r.conf).toContain(`Include ${CRS_BASE_DIR}/rules/*.conf`);
    expect(r.crsIncluded).toBe(true);
    expect(r.warnings).toEqual([]);
  });

  it("learningMode → DetectionOnly (log-only), no downgrade warnings", () => {
    const r = renderModsecVhost(vhost(), policy({ learningMode: true }), []);
    expect(r.conf).toContain("SecRuleEngine DetectionOnly");
    expect(r.conf).not.toContain("SecRuleEngine On");
  });

  it("owaspCrsEnabled=false → engine + setup only, no CRS include", () => {
    const r = renderModsecVhost(vhost(), policy({ owaspCrsEnabled: false }), []);
    expect(r.conf).not.toContain("Include /usr/share");
    expect(r.conf).toContain("OWASP CRS disabled");
    expect(r.crsIncluded).toBe(false);
  });

  it("crsVersion 4.0 is downgraded with an honest warning (Debian ships 3.3.7)", () => {
    const r = renderModsecVhost(vhost(), policy({ crsVersion: "4.0" }), []);
    expect(r.warnings.some((w) => w.includes("CRS 4.0") && w.includes(INSTALLED_CRS_VERSION))).toBe(true);
    expect(r.conf).toContain(`Include ${CRS_BASE_DIR}/rules/*.conf`);
  });

  it("honors a detected CRS root (alternate layout) instead of the constant", () => {
    const r = renderModsecVhost(vhost(), policy(), [], "/etc/modsecurity/crs");
    expect(r.conf).toContain("Include /etc/modsecurity/crs/rules/*.conf");
  });
});

describe("renderModsecSetup (tx values)", () => {
  it("carries paranoia level + anomaly thresholds on SecAction id:900000", () => {
    const s = renderModsecSetup(policy());
    expect(s).toContain('id:900000');
    expect(s).toContain("setvar:tx.paranoia_level=2");
    expect(s).toContain("setvar:tx.executing_paranoia_level=2");
    expect(s).toContain("setvar:tx.inbound_anomaly_score_threshold=6");
    expect(s).toContain("setvar:tx.outbound_anomaly_score_threshold=4,");
    // CRS 901001 500-fails without it ("CRS deployed without configuration")
    expect(s).toContain("setvar:tx.crs_setup_version=333");
  });

  it("is deterministic", () => {
    expect(renderModsecSetup(policy())).toBe(renderModsecSetup(policy()));
  });
});

// ── exclusions ──────────────────────────────────────────────────────────────

describe("exclusion rendering (rule_id / param / url)", () => {
  it("rule_id → SecRuleRemoveById", () => {
    const r = renderModsecVhost(vhost(), policy(), [exclusion({ scope: "rule_id", matchValue: "942100" })]);
    expect(r.conf).toContain("SecRuleRemoveById 942100");
    expect(r.warnings).toEqual([]);
  });

  it("param with ruleId → SecRuleUpdateTargetById on the mapped target collection", () => {
    const r = renderModsecVhost(vhost(), policy(), [exclusion({ scope: "param", matchValue: "arg:password", ruleId: 942100 })]);
    expect(r.conf).toContain('SecRuleUpdateTargetById 942100 "!ARGS:password"');
    expect(paramTargetFromMatchValue("cookie:session")).toBe("REQUEST_COOKIES");
    expect(paramTargetFromMatchValue("header:X-Api-Key")).toBe("REQUEST_HEADERS");
    expect(paramTargetFromMatchValue("password")).toBeNull();
  });

  it("param without ruleId → warning, directive skipped", () => {
    const r = renderModsecVhost(vhost(), policy(), [exclusion({ scope: "param", matchValue: "arg:password", ruleId: null })]);
    expect(r.conf).not.toContain("SecRuleUpdateTargetById");
    expect(r.warnings.some((w) => w.includes("needs a target ruleId"))).toBe(true);
  });

  it("url → ctl:ruleEngine=Off bypass rule with deterministic per-vhost id", () => {
    const r = renderModsecVhost(
      vhost(),
      policy(),
      [
        exclusion({ id: 2, scope: "url", matchValue: "/api/login" }),
        exclusion({ id: 3, scope: "url", matchValue: '/api/"evil"' }),
      ],
    );
    expect(r.conf).toContain(`SecRule REQUEST_URI "@beginsWith /api/login" "id:100071,phase:1,pass,nolog,ctl:ruleEngine=Off"`);
    // quotes stripped from the literal; seq increments
    expect(r.conf).toContain(`"@beginsWith /api/evil" "id:100072`);
    expect(r.conf.match(/ctl:ruleEngine=Off/g)?.length).toBe(2);
  });

  it("non-numeric rule_id matchValue → warning + skipped; disabled exclusion ignored", () => {
    const r = renderModsecVhost(
      vhost(),
      policy(),
      [
        exclusion({ id: 4, scope: "rule_id", matchValue: "drop tables" }),
        exclusion({ id: 5, scope: "rule_id", matchValue: "981172", enabled: false }),
      ],
    );
    expect(r.conf).not.toContain("SecRuleRemoveById");
    expect(r.warnings.some((w) => w.includes("not a numeric CRS rule id"))).toBe(true);
  });
});

// ── full render: main conf.d file + per-vhost chunks ───────────────────────

describe("renderWafManaged", () => {
  it("renders limit_req_zone + geo map + server block for an enabled waf vhost", () => {
    const r = renderWafManaged(
      inputs({
        vhosts: [vhost({ certId: 21 })],
        policies: [policy({ rateLimitRpm: 600, rateLimitBurst: 40, geoBlockCountries: ["CN", "RU"] })],
        certs: [{ certId: 21, certPem: pem("CERT"), keyPem: pem("KEY") }],
      }),
    );
    expect(r.files.some((f) => f.path === WAF_MANAGED_FILE)).toBe(true);
    const main = r.mainConf;
    expect(main).toContain(`limit_req_zone $binary_remote_addr zone=utm_waf_7:10m rate=600r/m;`);
    expect(main).toContain("geo $utm_geo_7 {");
    expect(main).toContain("\tdefault 0;");
    expect(main).toContain("\tCN 1;");
    expect(main).toContain("\tRU 1;");
    expect(main).toContain("listen 443 ssl;");
    expect(main).toContain("server_name app.corp.local;");
    expect(main).toContain("if ($utm_geo_7) { return 403; }");
    expect(main).toContain("limit_req zone=utm_waf_7 burst=40 nodelay;");
    expect(main).toContain("modsecurity on;");
    expect(main).toContain(`modsecurity_rules_file ${WAF_RULES_DIR}/7.conf;`);
    expect(main).toContain("proxy_pass http://127.0.0.1:8080;");
    expect(main).toContain("proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;");
    // per-vhost modsec files staged
    expect(r.files.some((f) => f.path === `${WAF_RULES_DIR}/7.conf`)).toBe(true);
    expect(r.files.some((f) => f.path === `${WAF_RULES_DIR}/7-setup.conf`)).toBe(true);
    expect(r.managedVhostIds).toEqual([7]);
    expect(r.empty).toBe(false);
  });

  it("is deterministic (byte-identical files → hash-stable confHash)", () => {
    const a = renderWafManaged(inputs());
    const b = renderWafManaged(inputs());
    expect(a.mainConf).toBe(b.mainConf);
    expect(a.confHash).toBe(b.confHash);
    expect(a.confHash).toMatch(/^[0-9a-f]{16}$/);
    expect(a.confHash).toBe(wafConfHash(a.files.map((f) => ({ path: f.path, content: f.content }))));
  });

  it("reverse_proxy mode → no modsecurity directives, no modsec files", () => {
    const r = renderWafManaged(inputs({ vhosts: [vhost({ mode: "reverse_proxy" })] }));
    expect(r.mainConf).not.toContain("modsecurity on;");
    expect(r.files.some((f) => f.path === `${WAF_RULES_DIR}/7.conf`)).toBe(false);
    expect(r.vhosts[0].modsec).toBeNull();
  });

  it("disabled vhost → skipped (commented), disabled policy → plain proxy", () => {
    const r = renderWafManaged(
      inputs({
        vhosts: [vhost({ id: 8, hostname: "old.corp.local", enabled: false }), vhost({ id: 9 })],
        policies: [policy({ id: 4, vhostId: 9, enabled: false })],
      }),
    );
    expect(r.mainConf).toContain("# skipped: old.corp.local (vhost disabled in console)");
    expect(r.mainConf).toContain("server_name app.corp.local;");
    expect(r.mainConf).toContain("# policy disabled in console — plain reverse proxy");
    expect(r.files.some((f) => f.path === `${WAF_RULES_DIR}/9.conf`)).toBe(false);
    expect(r.managedVhostIds).toEqual([9]);
  });

  it("TLS without usable cert → plaintext listener + warning; with PEM → ssl paths staged", () => {
    const missing = renderWafManaged(inputs({ vhosts: [vhost({ certId: 21 })] }));
    expect(missing.mainConf).toContain("listen 443;");
    expect(missing.mainConf).not.toContain("ssl_certificate");
    expect(missing.warnings.some((w) => w.includes("certificate 21"))).toBe(true);

    const staged = renderWafManaged(
      inputs({
        vhosts: [vhost({ certId: 21 })],
        certs: [{ certId: 21, certPem: pem("CERT"), keyPem: pem("KEY") }],
      }),
    );
    expect(staged.mainConf).toContain("listen 443 ssl;");
    expect(staged.mainConf).toContain(`ssl_certificate ${WAF_SSL_DIR}/utm-7.crt;`);
    expect(staged.mainConf).toContain(`ssl_certificate_key ${WAF_SSL_DIR}/utm-7.key;`);
    expect(staged.mainConf).toContain("ssl_protocols TLSv1.2 TLSv1.3;");
    const keyFile = staged.files.find((f) => f.path === certPathsFor(7).key);
    expect(keyFile?.content).toBe(pem("KEY"));
    expect(keyFile?.kind).toBe("pki");
  });

  it("empty enabled-vhost set → header-only managed conf, empty=true", () => {
    const r = renderWafManaged(inputs({ vhosts: [vhost({ enabled: false })] }));
    expect(r.empty).toBe(true);
    expect(r.mainConf).toContain("No ENABLED vhosts");
    expect(r.mainConf).toContain("does NOT");
    expect(r.managedVhostIds).toEqual([]);
    expect(r.files).toHaveLength(1); // just the empty conf.d file
  });
});

// ── limit_req math ──────────────────────────────────────────────────────────

describe("limit_req math (rpm ↔ r/s, burst default)", () => {
  it("maps rpm/60 to r/s (2 dp) and defaults burst to the per-second equivalent", () => {
    expect(rpmToRps(600)).toBe(10);
    expect(rpmToRps(90)).toBe(1.5);
    expect(rpmToRps(10)).toBe(0.17);
    expect(burstForPolicy({ rateLimitRpm: 600, rateLimitBurst: null })).toBe(10);
    expect(burstForPolicy({ rateLimitRpm: 100, rateLimitBurst: null })).toBe(2);
    expect(burstForPolicy({ rateLimitRpm: 50, rateLimitBurst: null })).toBe(1); // min 1
    expect(burstForPolicy({ rateLimitRpm: 600, rateLimitBurst: 25 })).toBe(25);
    expect(burstForPolicy({ rateLimitRpm: null, rateLimitBurst: null })).toBeNull();
  });

  it("no rateLimitRpm → no zone, no limit_req directive", () => {
    const r = renderWafManaged(inputs());
    expect(r.mainConf).not.toContain("limit_req_zone");
    expect(r.mainConf).not.toContain("limit_req zone=");
  });
});

// ── red lines: whitelist + refusals + backup path ───────────────────────────

describe("wafStepGuarded (command whitelist)", () => {
  it("allows the exact plan commands", () => {
    expect(wafStepGuarded("nginx -t")).toBe(true);
    expect(wafStepGuarded("systemctl start nginx")).toBe(true);
    expect(wafStepGuarded("systemctl reload nginx")).toBe(true);
    expect(wafStepGuarded("systemctl is-active nginx")).toBe(true);
    expect(wafStepGuarded("ss -ltn '( sport = :443 or sport = :80 )'")).toBe(true);
    expect(wafStepGuarded(`mkdir -p ${WAF_STATE_DIR}`)).toBe(true);
    expect(wafStepGuarded(`mkdir -p ${WAF_RULES_DIR}`)).toBe(true);
    expect(wafStepGuarded(`rmdir ${WAF_RULES_DIR}`)).toBe(true);
    expect(wafStepGuarded(`cp ${WAF_MANAGED_FILE} ${WAF_STATE_DIR}/backup-20261118T00-00-00-000Z${WAF_MANAGED_FILE}`)).toBe(true);
    expect(wafStepGuarded(`cp ${WAF_RULES_DIR}/7.conf ${WAF_STATE_DIR}/backup-x${WAF_RULES_DIR}/7.conf`)).toBe(true);
    expect(wafStepGuarded(`write-file ${WAF_MANAGED_FILE}`)).toBe(true);
    expect(wafStepGuarded(`write-file ${WAF_RULES_DIR}/7.conf`)).toBe(true);
    expect(wafStepGuarded(`write-file ${WAF_SSL_DIR}/utm-7.crt`)).toBe(true);
    expect(wafStepGuarded(`write-file ${WAF_SSL_DIR}/utm-7.key`)).toBe(true);
    expect(wafStepGuarded(`rm -f ${WAF_RULES_DIR}/9.conf`)).toBe(true);
  });

  it("rejects arbitrary / injected / out-of-namespace commands", () => {
    expect(wafStepGuarded("rm -rf /")).toBe(false);
    expect(wafStepGuarded("systemctl restart sshd")).toBe(false);
    expect(wafStepGuarded("systemctl stop nginx")).toBe(false);
    expect(wafStepGuarded("nginx -t -c /tmp/evil.conf")).toBe(false);
    expect(wafStepGuarded("nginx -s stop")).toBe(false);
    expect(wafStepGuarded(`write-file /etc/nginx/nginx.conf`)).toBe(false);
    expect(wafStepGuarded(`write-file ${WAF_SSL_DIR}/../ssl-evil.key`)).toBe(false);
    expect(wafStepGuarded(`rm -f ${WAF_MANAGED_FILE}`)).toBe(true); // rollback-only allow
    expect(wafStepGuarded(`rm -f /etc/nginx/nginx.conf`)).toBe(false);
    expect(wafStepGuarded(`cp ${WAF_MANAGED_FILE} /etc/shadow`)).toBe(false);
    expect(wafStepGuarded(`write-file ${WAF_RULES_DIR}/../../etc/cron.d/x`)).toBe(false);
    expect(wafStepGuarded("")).toBe(false);
    expect(wafStepGuarded("bash -c 'echo hi'")).toBe(false);
  });

  it("backup dirs must live in WAF_STATE_DIR with backup-<ts> names", () => {
    expect(isWafBackupDir(`${WAF_STATE_DIR}/backup-20261118T00-00-00-000Z`)).toBe(true);
    expect(isWafBackupDir(`${WAF_STATE_DIR}/evil`)).toBe(false);
    expect(isWafBackupDir(`${WAF_STATE_DIR}/../elsewhere/backup-x`)).toBe(false);
    expect(isWafBackupDir("/tmp/backup-1")).toBe(false);
  });
});

describe("hardWafRefusal", () => {
  it("refuses shell-breaking hostname/backend characters", () => {
    expect(hardWafRefusal(inputs({ vhosts: [vhost({ hostname: "app.corp.local; rm -rf /" })] }))).toContain("refused");
    expect(hardWafRefusal(inputs({ vhosts: [vhost({ backendHost: "10.0.0.1 $(id)" })] }))).toContain("refused");
  });
  it("refuses rateLimitRpm outside 10–10000 (validator bypass)", () => {
    expect(hardWafRefusal(inputs({ policies: [policy({ rateLimitRpm: 5 })] }))).toContain("rateLimitRpm");
  });
  it("passes a legitimate config", () => {
    expect(hardWafRefusal(inputs())).toBeNull();
  });
});

// ── plan: ordering + guard + empty behavior ────────────────────────────────

describe("buildWafApplyPlan", () => {
  it("builds a fully guarded plan: backup → write → validate → reload → verify", () => {
    const plan = buildWafApplyPlan(
      inputs({ vhosts: [vhost({ certId: 21 })], certs: [{ certId: 21, certPem: pem("C"), keyPem: pem("K") }] }),
      facts({ unitState: "active", managedFiles: [{ path: WAF_MANAGED_FILE, present: true, bytes: 10, hash: "x" }] }),
      "exec",
      "20261118T00-00-00-000Z",
    );
    expect(plan.guarded).toBe(true);
    expect(plan.refused).toBeNull();
    const names = plan.steps.map((s) => s.step);
    // backup of the existing main file comes first
    expect(names[0]).toBe("state dir");
    expect(names).toContain("backup utm-waf.conf");
    const idx = (n: string) => names.indexOf(n);
    expect(idx("backup utm-waf.conf")).toBeLessThan(idx("write utm-waf.conf"));
    // nginx -t AFTER staging, BEFORE reload
    const writeIdx = names.map((n, i) => (n.startsWith("write ") ? i : -1)).filter((i) => i >= 0);
    const validateIdx = idx("validate config");
    const reloadIdx = idx("reload nginx");
    expect(Math.max(...writeIdx)).toBeLessThan(validateIdx);
    expect(validateIdx).toBeLessThan(reloadIdx);
    expect(names).toContain("verify unit");
    expect(names).toContain("re-verify config");
    expect(names).toContain("probe listeners");
    expect(plan.steps.find((s) => s.cmd.startsWith("ss "))?.optional).toBe(true);
    // TLS material staged in the file plan
    expect(plan.files.some((f) => f.path.endsWith("utm-7.key"))).toBe(true);
    // hash mirrors the rendered files
    expect(plan.confHash).toBe(wafConfHash(plan.files.map((f) => ({ path: f.path, content: f.content }))));
    expect(plan.backupDir.startsWith(`${WAF_STATE_DIR}/backup-`)).toBe(true);
  });

  it("unit inactive → systemctl start (not reload); unit active → reload", () => {
    const start = buildWafApplyPlan(inputs(), facts({ unitState: "inactive" }), "exec", "t");
    expect(start.steps.find((s) => s.kind === "reload")?.cmd).toBe("systemctl start nginx");
    const reload = buildWafApplyPlan(inputs(), facts({ unitState: "active" }), "exec", "t");
    expect(reload.steps.find((s) => s.kind === "reload")?.cmd).toBe("systemctl reload nginx");
  });

  it("NO enabled vhost → empty conf, cleanup steps, NO start/reload/verify steps", () => {
    const plan = buildWafApplyPlan(
      inputs({ vhosts: [vhost({ enabled: false })] }),
      facts({
        unitState: "inactive",
        managedFiles: [
          { path: `${WAF_RULES_DIR}/7.conf`, present: true, bytes: 10, hash: "x" },
          { path: `${WAF_RULES_DIR}/7-setup.conf`, present: true, bytes: 10, hash: "x" },
        ],
      }),
      "exec",
      "t",
    );
    expect(plan.empty).toBe(true);
    const cmds = plan.steps.map((s) => s.cmd);
    expect(cmds).not.toContain("systemctl start nginx");
    expect(cmds).not.toContain("systemctl reload nginx");
    expect(cmds).not.toContain("systemctl is-active nginx");
    expect(cmds).toContain(`rm -f ${WAF_RULES_DIR}/7.conf`);
    expect(cmds).toContain(`rm -f ${WAF_RULES_DIR}/7-setup.conf`);
    expect(cmds).toContain(`rmdir ${WAF_RULES_DIR}`);
    // validate still runs (harmless, rollback safety)
    expect(cmds).toContain("nginx -t");
    expect(plan.steps.filter((s) => s.step.startsWith("write")).map((s) => s.cmd)).toEqual([`write-file ${WAF_MANAGED_FILE}`]);
    expect(plan.guarded).toBe(true);
  });

  it("stale on-disk modsec files get rm -f cleanup steps before validate", () => {
    const plan = buildWafApplyPlan(
      inputs(), // vhost 7 → files 7.conf + 7-setup.conf managed
      facts({
        unitState: "active",
        managedFiles: [
          { path: `${WAF_RULES_DIR}/99.conf`, present: true, bytes: 10, hash: "x" },
          { path: `${WAF_RULES_DIR}/7.conf`, present: true, bytes: 10, hash: "x" },
        ],
      }),
      "exec",
      "t",
    );
    const cmds = plan.steps.map((s) => s.cmd);
    expect(cmds).toContain(`rm -f ${WAF_RULES_DIR}/99.conf`);
    expect(cmds).not.toContain(`rm -f ${WAF_RULES_DIR}/7.conf`); // still managed
    const rmIdx = cmds.findIndex((c) => c.startsWith("rm -f "));
    expect(rmIdx).toBeLessThan(cmds.indexOf("nginx -t"));
  });

  it("carries renderer warnings (CRS 4.0 downgrade) without refusing", () => {
    const plan = buildWafApplyPlan(inputs({ policies: [policy({ crsVersion: "4.0" })] }), facts(), "plan", "t");
    expect(plan.warnings.some((w) => w.includes("CRS 4.0"))).toBe(true);
    expect(plan.mode).toBe("plan");
    expect(plan.guarded).toBe(true);
  });
});

// ── drift ───────────────────────────────────────────────────────────────────

describe("computeWafDrift", () => {
  const renderedHash = "a".repeat(16);

  it("in-sync: files deployed + hash matches state AND current render + unit active", () => {
    const d = computeWafDrift(
      { available: true, unitState: "active", confHash: renderedHash, stateHash: renderedHash },
      renderedHash,
      1,
    );
    expect(d.inSync).toBe(true);
    expect(d.managedByConsole).toBe(true);
    expect(d.reasons).toEqual([]);
  });

  it("not deployed / never applied → drift with honest reasons", () => {
    const d = computeWafDrift({ available: true, unitState: "active", confHash: null, stateHash: null }, renderedHash, 1);
    expect(d.inSync).toBe(false);
    expect(d.managedByConsole).toBe(false);
    expect(d.reasons.some((r) => r.includes("not deployed"))).toBe(true);
  });

  it("hand-edited files (conf ≠ last applied) → not managed by console", () => {
    const d = computeWafDrift({ available: true, unitState: "active", confHash: "b".repeat(16), stateHash: renderedHash }, renderedHash, 1);
    expect(d.managedByConsole).toBe(false);
    expect(d.reasons.some((r) => r.includes("outside the console"))).toBe(true);
  });

  it("console config changed since apply → drift (apply to OS)", () => {
    const d = computeWafDrift(
      { available: true, unitState: "active", confHash: renderedHash, stateHash: renderedHash },
      "c".repeat(16),
      1,
    );
    expect(d.inSync).toBe(false);
    expect(d.reasons.some((r) => r.includes("changed since last apply"))).toBe(true);
  });

  it("unit down with vhosts → drift; empty vhost set does NOT require an active unit", () => {
    const down = computeWafDrift({ available: true, unitState: "inactive", confHash: renderedHash, stateHash: renderedHash }, renderedHash, 2);
    expect(down.reasons.some((r) => r.includes("nginx service is inactive"))).toBe(true);
    const empty = computeWafDrift({ available: true, unitState: "inactive", confHash: renderedHash, stateHash: renderedHash }, renderedHash, 0);
    expect(empty.inSync).toBe(true);
  });

  it("nginx unavailable → drift with availability reason", () => {
    const d = computeWafDrift({ available: false, unitState: null, confHash: renderedHash, stateHash: renderedHash }, renderedHash, 1);
    expect(d.inSync).toBe(false);
    expect(d.reasons[0]).toContain("not available");
  });
});

// ── nginx -t interpretation ─────────────────────────────────────────────────

describe("interpretNginxTest", () => {
  it("passes on the real success output", () => {
    const v = interpretNginxTest(
      "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\nnginx: configuration file /etc/nginx/nginx.conf test is successful",
      true,
    );
    expect(v.ok).toBe(true);
    expect(v.hasErrors).toBe(false);
    expect(v.detail).toContain("passed");
  });

  it("fails on emerg errors", () => {
    const v = interpretNginxTest(
      "nginx: [emerg] unknown directive \"modsecurity_evil\" in /etc/nginx/conf.d/utm-waf.conf:12\nnginx: configuration file /etc/nginx/nginx.conf test failed",
      false,
    );
    expect(v.ok).toBe(false);
    expect(v.hasErrors).toBe(true);
    expect(v.detail).toContain("emerg");
  });

  it("exec failure with no output is a hard failure", () => {
    expect(interpretNginxTest("", false).ok).toBe(false);
  });
});

// ── hashing helpers ─────────────────────────────────────────────────────────

describe("hashing", () => {
  it("wafHash is stable and 16 hex chars", () => {
    expect(wafHash("abc")).toBe(wafHash("abc"));
    expect(wafHash("abc")).toMatch(/^[0-9a-f]{16}$/);
  });
  it("wafConfHash is order-insensitive (sorted by path) and concatenation-sensitive", () => {
    const a = wafConfHash([
      { path: "/b", content: "B" },
      { path: "/a", content: "A" },
    ]);
    const b = wafConfHash([
      { path: "/a", content: "A" },
      { path: "/b", content: "B" },
    ]);
    expect(a).toBe(b);
    expect(wafConfHash([{ path: "/a", content: "A" }])).not.toBe(wafConfHash([{ path: "/a", content: "AB" }]));
  });
});
