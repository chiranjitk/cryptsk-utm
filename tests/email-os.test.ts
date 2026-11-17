/**
 * Email OS layer tests — main.cf determinism (milter line, size-limit math,
 * relay domains, TLS modes), transport-map rendering (rules first, gateway
 * defaults, deliver/quarantine limitation), rspamd local.d renders (actions
 * thresholds math, phishing/malware conditionals, spf/dkim/dmarc, blocked
 * extension multimap+map), command whitelist, plan ordering (backup → stage →
 * install → postmap → validate → services → verify → state LAST), no-gateway
 * teardown, drift and the missing /email-security/test route wiring.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";
import {
  buildEmailApplyPlan,
  computeEmailDrift,
  EMAIL_MANAGED_PATHS,
  EMAIL_SS_PROBE,
  emailConfHash,
  emailHash,
  emailStepGuarded,
  hardEmailRefusal,
  parseSsPorts,
  POSTFIX_MAIN_CF,
  POSTFIX_TRANSPORT,
  renderEmailFiles,
  renderMainCf,
  renderRspamdActions,
  renderRspamdAttachConf,
  renderRspamdAttachMap,
  renderRspamdDmarc,
  renderTransportMap,
  RSPAMD_ATTACH_MAP,
  RSPAMD_LOCAL_D,
  safeTransportHost,
  transportKeyFor,
  type EmailGatewayOsShape,
  type EmailPolicyOsShape,
  type EmailRuleOsShape,
} from "@/lib/email-security/os";
import { emailTestSchema } from "@/lib/validators/email-security";

// ── shape factories ─────────────────────────────────────────────────────────

const policy = (over: Partial<EmailPolicyOsShape> = {}): EmailPolicyOsShape => ({
  spamThreshold: 6.0,
  blockPhishing: true,
  blockMalware: true,
  scanArchives: true,
  maxMessageSizeMb: 25,
  blockedExtensions: ["exe", "js", "vbs", "scr", "bat"],
  spfVerify: true,
  dkimVerify: true,
  dmarcPolicy: "quarantine",
  quarantineRetentionDays: 14,
  enabled: true,
  ...over,
});

const gateway = (over: Partial<EmailGatewayOsShape> = {}): EmailGatewayOsShape => ({
  id: 1,
  name: "corp-relay",
  mode: "relay",
  listenPort: 25,
  relayDomains: ["corp.local"],
  upstreamHost: "10.10.0.50",
  tlsMode: "starttls",
  enabled: true,
  ...over,
});

const rule = (over: Partial<EmailRuleOsShape> = {}): EmailRuleOsShape => ({
  id: 1,
  name: "partner-relay",
  matchDomain: "partner.com",
  action: "relay",
  targetHost: "192.0.2.77",
  priority: 10,
  enabled: true,
  ...over,
});

// ── main.cf determinism ─────────────────────────────────────────────────────

describe("renderMainCf", () => {
  it("renders the rspamd milter block (milter, non_smtpd mirror, fail-open accept)", () => {
    const { content } = renderMainCf(policy(), [gateway()]);
    expect(content).toContain("smtpd_milters = inet:127.0.0.1:11332");
    expect(content).toContain("non_smtpd_milters = $smtpd_milters");
    expect(content).toContain("milter_default_action = accept");
  });

  it("computes message_size_limit from maxMessageSizeMb (MB → bytes)", () => {
    expect(renderMainCf(policy({ maxMessageSizeMb: 25 }), [gateway()]).content).toContain("message_size_limit = 26214400");
    expect(renderMainCf(policy({ maxMessageSizeMb: 10 }), [gateway()]).content).toContain("message_size_limit = 10485760");
    expect(renderMainCf(policy({ maxMessageSizeMb: 1 }), [gateway()]).content).toContain("message_size_limit = 1048576");
  });

  it("renders the base identity + recipient restrictions", () => {
    const { content } = renderMainCf(policy(), [gateway()]);
    expect(content).toContain("myhostname = utm-gateway");
    expect(content).toContain("mydestination =");
    expect(content).toContain("inet_interfaces = all");
    expect(content).toContain("inet_protocols = ipv4");
    expect(content).toContain("smtpd_banner = $myhostname ESMTP");
    expect(content).toContain("mynetworks = 127.0.0.0/8");
    expect(content).toContain("transport_maps = hash:/etc/postfix/utm-transport");
    expect(content).toContain("smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination");
  });

  it("collects deduped sorted relay domains from ENABLED gateways only", () => {
    const gws = [
      gateway({ id: 1, relayDomains: ["corp.local", "mail.corp.local"] }),
      gateway({ id: 2, relayDomains: ["alpha.example", "corp.local"], enabled: false }),
      gateway({ id: 3, relayDomains: ["alpha.example", "beta.example"] }),
    ];
    const { content } = renderMainCf(policy(), gws);
    expect(content).toContain("relay_domains = alpha.example, beta.example, corp.local, mail.corp.local");
  });

  it("maps tlsMode: none→level none, starttls→may, wrapper→wrappermode+none", () => {
    const none = renderMainCf(policy(), [gateway({ tlsMode: "none" })]).content;
    expect(none).toContain("smtpd_tls_security_level = none");
    expect(none).not.toContain("wrappermode");
    const starttls = renderMainCf(policy(), [gateway({ tlsMode: "starttls" })]).content;
    expect(starttls).toContain("smtpd_tls_security_level = may");
    const wrapper = renderMainCf(policy(), [gateway({ tlsMode: "wrapper" })]).content;
    expect(wrapper).toContain("smtpd_tls_wrappermode = yes");
    expect(wrapper).toContain("smtpd_tls_security_level = none");
  });

  it("is deterministic (byte-identical renders) and warns on non-25 listenPort", () => {
    const a = renderMainCf(policy(), [gateway()]);
    const b = renderMainCf(policy(), [gateway()]);
    expect(a.content).toBe(b.content);
    const offPort = renderMainCf(policy(), [gateway({ listenPort: 2025 })]);
    expect(offPort.warnings.some((w) => w.includes("master.cf"))).toBe(true);
  });
});

// ── transport map ───────────────────────────────────────────────────────────

describe("renderTransportMap", () => {
  it("renders routing-rule relay entries as smtp:[host]:25 (priority order)", () => {
    const r = renderTransportMap([gateway()], [
      rule({ priority: 20, matchDomain: "zeta.example", targetHost: "192.0.2.20" }),
      rule({ id: 2, priority: 10, matchDomain: "alpha.example", targetHost: "192.0.2.10" }),
    ]);
    expect(r.content).toContain("alpha.example smtp:[192.0.2.10]:25");
    expect(r.content).toContain("zeta.example smtp:[192.0.2.20]:25");
    expect(r.content.indexOf("alpha.example")).toBeLessThan(r.content.indexOf("zeta.example"));
    expect(r.gatewayIds).toEqual([1]); // gateway domains landed after rules
  });

  it("renders reject entries as error:5.7.1 rejected by policy", () => {
    const r = renderTransportMap([], [rule({ action: "reject", targetHost: null, name: "block-zip" })]);
    expect(r.content).toContain("partner.com error:5.7.1 rejected by policy");
    expect(r.entries[0]?.kind).toBe("reject");
  });

  it("keeps deliver/quarantine as honest limitation comments (no transport line)", () => {
    const r = renderTransportMap([], [rule({ action: "quarantine", targetHost: null, name: "hold" })]);
    expect(r.content).toContain('rule "hold" (partner.com): action quarantine is NOT transport-mapped');
    expect(r.content).not.toMatch(/^partner\.com /m);
  });

  it("maps gateway relayDomains → smtp:[upstreamHost]:25 (relay-mode defaults)", () => {
    const r = renderTransportMap([gateway({ relayDomains: ["corp.local", "mail.corp.local"] })], []);
    expect(r.content).toContain("corp.local smtp:[10.10.0.50]:25");
    expect(r.content).toContain("mail.corp.local smtp:[10.10.0.50]:25");
    expect(r.gatewayIds).toEqual([1]);
  });

  it("strips @ from matchDomain keys and warns on duplicate domains (first wins)", () => {
    const r = renderTransportMap([gateway({ relayDomains: ["partner.com"] })], [rule({ matchDomain: "@partner.com" })]);
    expect(r.content.match(/^partner\.com smtp/gm)).toHaveLength(1);
    expect(r.content).toContain("partner.com smtp:[192.0.2.77]:25"); // rule wins
    expect(r.warnings.some((w) => w.includes("duplicate"))).toBe(true);
  });

  it("warns when a proxy gateway has relay domains but no upstreamHost", () => {
    const r = renderTransportMap([gateway({ mode: "proxy", upstreamHost: null, relayDomains: ["corp.local"] })], []);
    expect(r.warnings.some((w) => w.includes("no upstreamHost"))).toBe(true);
    expect(r.entries).toHaveLength(0);
  });
});

// ── rspamd local.d renders ──────────────────────────────────────────────────

describe("rspamd local.d renders", () => {
  it("actions.conf: add_header = spamThreshold, reject = spamThreshold + 4 (deterministic math)", () => {
    const six = renderRspamdActions(policy({ spamThreshold: 6 }));
    expect(six).toContain("add_header = 6;");
    expect(six).toContain("reject = 10;");
    const half = renderRspamdActions(policy({ spamThreshold: 6.5 }));
    expect(half).toContain("add_header = 6.5;");
    expect(half).toContain("reject = 10.5;");
    const zero = renderRspamdActions(policy({ spamThreshold: 0 }));
    expect(zero).toContain("add_header = 0;");
    expect(zero).toContain("reject = 4;");
  });

  it("phishing.conf: conditional action = reject", () => {
    expect(renderEmailFiles({ gateways: [gateway()], policy: policy(), rules: [] }).files.find((f) => f.path.endsWith("phishing.conf"))?.content).toContain("action = reject;");
    const off = renderEmailFiles({ gateways: [gateway()], policy: policy({ blockPhishing: false }), rules: [] }).files.find((f) => f.path.endsWith("phishing.conf"))?.content;
    expect(off).not.toContain("action = reject;");
    expect(off).toContain("blockPhishing=false");
  });

  it("antivirus.conf: clamd servers conditional on blockMalware (+ scanArchives note)", () => {
    const on = renderEmailFiles({ gateways: [gateway()], policy: policy(), rules: [] }).files.find((f) => f.path.endsWith("antivirus.conf"))?.content;
    expect(on).toContain("clamav {");
    expect(on).toContain('type = "clamav";');
    expect(on).toContain('servers = "127.0.0.1:3310";');
    expect(on).toContain('action = "reject";');
    const off = renderEmailFiles({ gateways: [gateway()], policy: policy({ blockMalware: false }), rules: [] }).files.find((f) => f.path.endsWith("antivirus.conf"))?.content;
    expect(off).not.toContain("clamav {");
    expect(off).toContain("blockMalware=false");
    const noArchives = renderEmailFiles({ gateways: [gateway()], policy: policy({ scanArchives: false }), rules: [] }).files.find((f) => f.path.endsWith("antivirus.conf"))?.content;
    expect(noArchives).toContain("scanArchives=false");
  });

  it("spf.conf / dkim.conf mirror the verify toggles", () => {
    const files = renderEmailFiles({ gateways: [gateway()], policy: policy({ spfVerify: false, dkimVerify: false }), rules: [] }).files;
    expect(files.find((f) => f.path.endsWith("spf.conf"))?.content).toContain("enabled = false;");
    expect(files.find((f) => f.path.endsWith("dkim.conf"))?.content).toContain("enabled = false;");
    const on = renderEmailFiles({ gateways: [gateway()], policy: policy(), rules: [] }).files;
    expect(on.find((f) => f.path.endsWith("spf.conf"))?.content).toContain("enabled = true;");
    expect(on.find((f) => f.path.endsWith("dkim.conf"))?.content).toContain("enabled = true;");
  });

  it("dmarc.conf: none→no_action, quarantine→add_header, reject→reject", () => {
    expect(renderRspamdDmarc(policy({ dmarcPolicy: "none" }))).toContain("action = no_action;");
    expect(renderRspamdDmarc(policy({ dmarcPolicy: "quarantine" }))).toContain("action = add_header;");
    expect(renderRspamdDmarc(policy({ dmarcPolicy: "reject" }))).toContain("action = reject;");
  });

  it("blocked extensions render the multimap + sorted map file", () => {
    const conf = renderRspamdAttachConf(policy({ blockedExtensions: ["exe", "js", "bat"] }));
    expect(conf).toContain("utm_attach {");
    expect(conf).toContain('type = "filename";');
    expect(conf).toContain('filter = "extension";');
    expect(conf).toContain(`map = "${RSPAMD_ATTACH_MAP}";`);
    expect(conf).toContain('action = "reject";');
    expect(conf).toContain('symbol = "UTM_BLOCKED_EXT";');
    const map = renderRspamdAttachMap(policy({ blockedExtensions: ["js", "exe", "bat"] }));
    const lines = map.split("\n").filter((l) => l && !l.startsWith("#"));
    expect(lines).toEqual(["bat", "exe", "js"]);
  });
});

// ── full real estate ────────────────────────────────────────────────────────

describe("renderEmailFiles", () => {
  const rendered = renderEmailFiles({ gateways: [gateway()], policy: policy(), rules: [rule()] });

  it("covers exactly the managed real estate (postfix pair + rspamd fragments + map)", () => {
    expect(rendered.files.map((f) => f.path).sort()).toEqual([...EMAIL_MANAGED_PATHS].sort());
    expect(rendered.files.filter((f) => f.kind === "postfix")).toHaveLength(2);
    expect(rendered.files.filter((f) => f.kind === "rspamd")).toHaveLength(8);
    expect(rendered.empty).toBe(false);
  });

  it("stage paths live under /var/lib/console/email/stage-*", () => {
    for (const f of rendered.files) {
      expect(f.stage).toMatch(/^\/var\/lib\/console\/email\/stage-[\w.-]+$/);
    }
  });

  it("confHash = sha256[:16] over the concatenated files; stable + per-file hashes present", () => {
    expect(rendered.confHash).toHaveLength(16);
    expect(rendered.confHash).toBe(emailConfHash(rendered.files.map((f) => ({ path: f.path, content: f.content }))));
    expect(Object.keys(rendered.fileHashes).sort()).toEqual([...EMAIL_MANAGED_PATHS].sort());
    expect(rendered.fileHashes[POSTFIX_MAIN_CF]).toBe(emailHash(rendered.files.find((f) => f.path === POSTFIX_MAIN_CF)!.content));
    // re-render → identical hash (determinism)
    expect(renderEmailFiles({ gateways: [gateway()], policy: policy(), rules: [rule()] }).confHash).toBe(rendered.confHash);
  });

  it("warns about the quarantine retention v1 scope", () => {
    expect(rendered.warnings.some((w) => w.includes("retention sweep is out of scope"))).toBe(true);
  });

  it("no enabled gateways → empty render (teardown), confHash null", () => {
    const empty = renderEmailFiles({ gateways: [gateway({ enabled: false })], policy: policy(), rules: [] });
    expect(empty.empty).toBe(true);
    expect(empty.files).toHaveLength(0);
    expect(empty.confHash).toBeNull();
    expect(empty.warnings.some((w) => w.includes("STOPPED"))).toBe(true);
  });

  it("renders transport entries into the transport file body", () => {
    const transport = rendered.files.find((f) => f.path === POSTFIX_TRANSPORT)!.content;
    expect(transport).toContain("partner.com smtp:[192.0.2.77]:25");
    expect(transport).toContain("corp.local smtp:[10.10.0.50]:25");
  });
});

// ── refusals + sanitizers ───────────────────────────────────────────────────

describe("hardEmailRefusal / sanitizers", () => {
  it("refuses hosts/domains with injection characters", () => {
    expect(hardEmailRefusal([gateway({ upstreamHost: "10.0.0.1; rm -rf /" })], [])).toContain("upstreamHost");
    expect(hardEmailRefusal([gateway({ relayDomains: ["corp local"] })], [])).toContain("relay domain");
    expect(hardEmailRefusal([], [rule({ targetHost: 'evil"[host]' })])).toContain("targetHost");
    expect(hardEmailRefusal([gateway()], [rule()])).toBeNull();
  });
  it("ignores disabled gateways/rules", () => {
    expect(hardEmailRefusal([gateway({ enabled: false, upstreamHost: "bad host" })], [])).toBeNull();
    expect(hardEmailRefusal([], [rule({ enabled: false, targetHost: "bad host" })])).toBeNull();
  });
  it("safeTransportHost / transportKeyFor strip @ and reject junk", () => {
    expect(safeTransportHost("10.10.0.50")).toBe("10.10.0.50");
    expect(safeTransportHost("bad host")).toBeNull();
    expect(transportKeyFor("@zip")).toBe("zip");
    expect(transportKeyFor("@partner.com")).toBe("partner.com");
  });
});

// ── command whitelist ───────────────────────────────────────────────────────

describe("emailStepGuarded", () => {
  it("allows exactly the email apply plan command forms", () => {
    expect(emailStepGuarded("mkdir -p /var/lib/console/email")).toBe(true);
    expect(emailStepGuarded("postmap /etc/postfix/utm-transport")).toBe(true);
    expect(emailStepGuarded("postfix check")).toBe(true);
    expect(emailStepGuarded("rspamadm configtest")).toBe(true);
    expect(emailStepGuarded(EMAIL_SS_PROBE)).toBe(true);
    expect(emailStepGuarded("systemctl enable --now rspamd")).toBe(true);
    expect(emailStepGuarded("systemctl restart rspamd")).toBe(true);
    expect(emailStepGuarded("systemctl start postfix")).toBe(true);
    expect(emailStepGuarded("systemctl reload postfix")).toBe(true);
    expect(emailStepGuarded("systemctl stop postfix")).toBe(true);
    expect(emailStepGuarded("systemctl stop rspamd")).toBe(true);
    expect(emailStepGuarded("systemctl is-active rspamd")).toBe(true);
    expect(emailStepGuarded("systemctl is-active postfix")).toBe(true);
    expect(emailStepGuarded("install -m 0644 /var/lib/console/email/stage-main.cf /etc/postfix/main.cf")).toBe(true);
    expect(emailStepGuarded("install -m 0644 /var/lib/console/email/stage-utm-transport /etc/postfix/utm-transport")).toBe(true);
    expect(emailStepGuarded(`install -m 0644 /var/lib/console/email/stage-actions.conf ${RSPAMD_LOCAL_D}/actions.conf`)).toBe(true);
    expect(emailStepGuarded(`cp ${POSTFIX_MAIN_CF} /var/lib/console/email/backup-2025-01-01T00-00-00-000Z${POSTFIX_MAIN_CF}`)).toBe(true);
    expect(emailStepGuarded(`cp /etc/rspamd/utm-attach.map /var/lib/console/email/backup-x/etc/rspamd/utm-attach.map`)).toBe(true);
    expect(emailStepGuarded("rm -f /var/lib/console/email/stage-main.cf /var/lib/console/email/stage-utm-transport")).toBe(true);
  });

  it("rejects anything else — master.cf, other units, chaining, reboots, traversal", () => {
    for (const evil of [
      "",
      "install -m 0644 /var/lib/console/email/stage-master.cf /etc/postfix/master.cf", // RED LINE
      "install -m 0644 /tmp/payload /etc/postfix/main.cf",
      "install -m 0644 /var/lib/console/email/stage-main.cf /etc/shadow",
      "cp /etc/shadow /var/lib/console/email/backup-x/etc/shadow",
      "cp /etc/postfix/main.cf /etc/postfix/main.cf.bak",
      "systemctl restart nginx",
      "systemctl restart rsyslog",
      "systemctl reboot",
      "reboot",
      "postmap /etc/postfix/other",
      "postfix flush",
      "rspamadm configtest -f /etc/shadow",
      "postfix check; rm -rf /",
      "systemctl stop postfix && reboot",
      "rm -f /var/lib/console/email/state.json",
      "rm -rf /etc/postfix",
      "rm -f /var/lib/console/email/backup-x/../../etc/shadow",
      "sh -c evil",
      "ss -ltn",
    ]) {
      expect(emailStepGuarded(evil)).toBe(false);
    }
  });
});

// ── apply plan ──────────────────────────────────────────────────────────────

describe("buildEmailApplyPlan", () => {
  const input = {
    gateways: [gateway()],
    policy: policy(),
    rules: [rule()],
    onDiskPaths: [POSTFIX_MAIN_CF, POSTFIX_TRANSPORT],
    postfixState: null,
    rspamdState: null,
    mode: "exec" as const,
    ts: "t",
  };

  it("orders: dir → backup → stage → install → cleanup → postmap → validate → service → verify → writefile LAST", () => {
    const plan = buildEmailApplyPlan(input);
    const kinds = plan.steps.map((s) => s.kind);
    expect(kinds[0]).toBe("dir");
    const idx = (k: string) => (kinds as string[]).indexOf(k);
    expect(idx("backup")).toBeGreaterThan(idx("dir"));
    expect(idx("stage")).toBeGreaterThan(idx("backup"));
    expect(idx("install")).toBeGreaterThan(idx("stage"));
    expect(idx("cleanup")).toBeGreaterThan(idx("install"));
    expect(idx("postmap")).toBeGreaterThan(idx("cleanup"));
    expect(idx("validate")).toBeGreaterThan(idx("postmap"));
    expect(idx("service")).toBeGreaterThan(idx("validate"));
    expect(idx("verify")).toBeGreaterThan(idx("service"));
    expect(kinds[kinds.length - 1]).toBe("writefile");
    // exact commands for the critical steps
    expect(plan.steps.find((s) => s.kind === "postmap")?.cmd).toBe("postmap /etc/postfix/utm-transport");
    const validates = plan.steps.filter((s) => s.kind === "validate").map((s) => s.cmd);
    expect(validates).toEqual(["rspamadm configtest", "postfix check"]);
    const services = plan.steps.filter((s) => s.kind === "service").map((s) => s.cmd);
    expect(services).toEqual(["systemctl enable --now rspamd", "systemctl start postfix"]); // both inactive
    expect(plan.steps.some((s) => s.cmd === EMAIL_SS_PROBE && s.kind === "probe")).toBe(true);
    expect(plan.confHash).toHaveLength(16);
  });

  it("service lifecycle follows unit state: active → restart/reload", () => {
    const plan = buildEmailApplyPlan({ ...input, postfixState: "active", rspamdState: "active" });
    const services = plan.steps.filter((s) => s.kind === "service").map((s) => s.cmd);
    expect(services).toEqual(["systemctl restart rspamd", "systemctl reload postfix"]);
  });

  it("backups only files present on disk (cp <path> <backupDir><path>)", () => {
    const plan = buildEmailApplyPlan(input);
    const backups = plan.steps.filter((s) => s.kind === "backup").map((s) => s.cmd);
    expect(backups).toHaveLength(2);
    expect(backups[0]).toBe(`cp ${POSTFIX_MAIN_CF} /var/lib/console/email/backup-t${POSTFIX_MAIN_CF}`);
    expect(backups[1]).toBe(`cp ${POSTFIX_TRANSPORT} /var/lib/console/email/backup-t${POSTFIX_TRANSPORT}`);
  });

  it("every non-fs step passes the whitelist (plan is executable as written)", () => {
    const plan = buildEmailApplyPlan(input);
    for (const s of plan.steps) {
      if (s.cmd !== "") expect(emailStepGuarded(s.cmd)).toBe(true);
    }
    expect(plan.guarded).toBe(true);
    expect(plan.refused).toBeNull();
  });

  it("installs pin stage → managed paths, never master.cf", () => {
    const plan = buildEmailApplyPlan(input);
    const installs = plan.steps.filter((s) => s.kind === "install").map((s) => s.cmd);
    expect(installs).toHaveLength(EMAIL_MANAGED_PATHS.length);
    for (const cmd of installs) {
      expect(cmd).toContain("install -m 0644 /var/lib/console/email/stage-");
      expect(cmd).not.toContain("master.cf");
    }
  });

  it("state content carries confHash + fileHashes + gatewayIds + appliedAt", () => {
    const plan = buildEmailApplyPlan(input);
    const state = JSON.parse(plan.stateContent) as { confHash: string; fileHashes: Record<string, string>; gatewayIds: number[]; appliedAt: string };
    expect(state.confHash).toBe(plan.confHash);
    expect(state.gatewayIds).toEqual([1]);
    expect(Object.keys(state.fileHashes)).toHaveLength(EMAIL_MANAGED_PATHS.length);
    expect(typeof state.appliedAt).toBe("string");
  });

  it("no gateway → teardown plan: stop postfix + rspamd, no files, no installs", () => {
    const plan = buildEmailApplyPlan({ ...input, gateways: [gateway({ enabled: false })] });
    const services = plan.steps.filter((s) => s.kind === "service").map((s) => s.cmd);
    expect(services).toEqual(["systemctl stop postfix", "systemctl stop rspamd"]);
    expect(plan.steps.some((s) => s.kind === "install")).toBe(false);
    expect(plan.steps.some((s) => s.kind === "stage")).toBe(false);
    expect(plan.empty).toBe(true);
    expect(plan.confHash).toBeNull();
    expect(plan.gatewayIds).toEqual([]);
    const state = JSON.parse(plan.stateContent) as { gatewayIds: number[]; stopped?: boolean };
    expect(state.gatewayIds).toEqual([]);
    expect(state.stopped).toBe(true);
  });

  it("refused input still builds a plan but carries the refusal (executor blocks)", () => {
    const plan = buildEmailApplyPlan({ ...input, gateways: [gateway({ upstreamHost: "bad host" })] });
    expect(plan.refused).toContain("upstreamHost");
    expect(plan.guarded).toBe(true);
  });
});

// ── drift ───────────────────────────────────────────────────────────────────

describe("computeEmailDrift", () => {
  const rendered = renderEmailFiles({ gateways: [gateway()], policy: policy(), rules: [] });
  const hash = rendered.confHash!;

  it("in-sync when on-disk hash == state hash == rendered hash and units active", () => {
    const d = computeEmailDrift({
      enabledGatewayCount: 1,
      renderedHash: hash,
      onDiskHash: hash,
      stateHash: hash,
      postfixActive: true,
      rspamdActive: true,
    });
    expect(d.inSync).toBe(true);
    expect(d.managedByConsole).toBe(true);
    expect(d.driftReasons).toEqual([]);
  });

  it("flags missing/foreign/changed files", () => {
    const missing = computeEmailDrift({ enabledGatewayCount: 1, renderedHash: hash, onDiskHash: null, stateHash: hash, postfixActive: true, rspamdActive: true });
    expect(missing.inSync).toBe(false);
    expect(missing.driftReasons[0]).toContain("not deployed");

    const foreign = computeEmailDrift({ enabledGatewayCount: 1, renderedHash: hash, onDiskHash: "deadbeefdeadbeef", stateHash: hash, postfixActive: true, rspamdActive: true });
    expect(foreign.driftReasons.some((r) => r.includes("outside the console"))).toBe(true);

    const changed = computeEmailDrift({ enabledGatewayCount: 1, renderedHash: "aaaa1111bbbb2222", onDiskHash: hash, stateHash: hash, postfixActive: true, rspamdActive: true });
    expect(changed.driftReasons.some((r) => r.includes("changed since last apply"))).toBe(true);
  });

  it("flags inactive units; ports never appear in drift reasons", () => {
    const d = computeEmailDrift({ enabledGatewayCount: 1, renderedHash: hash, onDiskHash: hash, stateHash: hash, postfixActive: false, rspamdActive: true });
    expect(d.inSync).toBe(false);
    expect(d.driftReasons.some((r) => r.includes("postfix"))).toBe(true);
    expect(d.driftReasons.some((r) => /:25|:11332/.test(r))).toBe(false);
  });

  it("no gateways: sync = units stopped; an active unit is drift", () => {
    const stopped = computeEmailDrift({ enabledGatewayCount: 0, renderedHash: null, onDiskHash: hash, stateHash: hash, postfixActive: false, rspamdActive: false });
    expect(stopped.inSync).toBe(true);
    const running = computeEmailDrift({ enabledGatewayCount: 0, renderedHash: null, onDiskHash: hash, stateHash: hash, postfixActive: true, rspamdActive: false });
    expect(running.inSync).toBe(false);
    expect(running.driftReasons[0]).toContain("no gateway is enabled");
  });
});

// ── ss probe parsing ────────────────────────────────────────────────────────

describe("parseSsPorts", () => {
  const SS = `State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port  Process
LISTEN 0      100     0.0.0.0:25          0.0.0.0:*          users:(("smtpd",pid=1,))
LISTEN 0      4096    127.0.0.1:11332     0.0.0.0:*          users:(("rspamd",pid=2,))
LISTEN 0      128     0.0.0.0:2025        0.0.0.0:*          users:(("other",pid=3,))`;

  it("detects exact port matches (:25 yes, :2025 does not fake :25)", () => {
    const r = parseSsPorts(SS, [25, 11332, 11334]);
    expect(r[25]).toBe(true);
    expect(r[11332]).toBe(true);
    expect(r[11334]).toBe(false);
  });
  it("empty output → nothing bound (no fabricated state)", () => {
    const r = parseSsPorts("", [25, 11332]);
    expect(r[25]).toBe(false);
    expect(r[11332]).toBe(false);
  });
});

// ── missing-route bug: /email-security/test wired ───────────────────────────

describe("POST /api/v1/email-security/test route wiring (GUI 404 bug)", () => {
  // The route pulls the prisma-backed handler chain, so the wiring is asserted
  // at source level (executing it would need a live DB + session).
  const src = readFileSync(path.resolve(process.cwd(), "src/app/api/v1/email-security/test/route.ts"), "utf8");

  it("the route file exists at the app router path the GUI posts to", () => {
    expect(src.length).toBeGreaterThan(0);
    expect(src).toContain("force-dynamic");
  });
  it("validates with the email test schema (from/to/subject/body/attachments/sizeKb)", () => {
    expect(src).toContain("emailTestSchema");
  });
  it("wires service.testMessage (persisting EmailLog rows)", () => {
    expect(src).toContain("testMessage");
  });
  it("audits email_security.policy.test in section email_security", () => {
    expect(src).toContain('"email_security.policy.test"');
    expect(src).toContain('section: "email_security"');
  });
  it("the schema accepts the exact GUI test payload", () => {
    const parsed = emailTestSchema.safeParse({
      from: "attacker@spamsource.example",
      to: "victim@corp.local",
      subject: "free money winner",
      body: "crypto crypto",
      attachments: ["invoice.exe"],
      sizeKb: 42,
    });
    expect(parsed.success).toBe(true);
  });
});
