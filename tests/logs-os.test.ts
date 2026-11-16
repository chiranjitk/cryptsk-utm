/**
 * Syslog OS layer tests — renderer determinism, severity mapping, protocol
 * mapping (tls → gtls), loopback/injection refusals, whitelist guard, plan
 * ordering, drift and ss parsing.
 */

import { describe, it, expect } from "vitest";
import {
  RSYSLOG_BEGIN_MARKER,
  RSYSLOG_END_MARKER,
  RSYSLOG_IDLE_ACTION,
  RSYSLOG_MANAGED_FILE,
  RSYSLOG_STAGE_FILE,
  SEVERITY_GATE,
  buildRsyslogApplyPlan,
  computeRsyslogDrift,
  hardRsyslogRefusal,
  isLoopbackHost,
  isUnsafeRsyslogHost,
  parseSsForTarget,
  renderRsyslogConf,
  renderTargetLine,
  rsyslogConfHash,
  rsyslogStepGuarded,
  type SyslogTargetShape,
} from "@/lib/logs/os";

const target = (over: Partial<SyslogTargetShape> = {}): SyslogTargetShape => ({
  id: 1,
  name: "siem",
  host: "192.0.2.10",
  port: 514,
  protocol: "udp",
  minSeverity: "info",
  enabled: true,
  ...over,
});

// ── severity mapping (documented in the file header AND code) ──────────────

describe("SEVERITY_GATE (RFC 5424 syslogseverity fold)", () => {
  it("maps console minSeverity onto the rsyslog scale", () => {
    expect(SEVERITY_GATE.critical).toBe(2); // crit
    expect(SEVERITY_GATE.high).toBe(3); // err
    expect(SEVERITY_GATE.medium).toBe(4); // warning
    expect(SEVERITY_GATE.low).toBe(5); // notice
    expect(SEVERITY_GATE.info).toBe(6); // info
  });
  it("renders the gate as `if $syslogseverity <= N then { … }`", () => {
    for (const sev of ["critical", "high", "medium", "low", "info"] as const) {
      const r = renderTargetLine(target({ minSeverity: sev }));
      expect(r.line).toContain(`if $syslogseverity <= ${SEVERITY_GATE[sev]} then {`);
      expect(r.severityNum).toBe(SEVERITY_GATE[sev]);
    }
  });
  it("keeps the file header comment in sync with the code table", () => {
    const { content } = renderRsyslogConf([target()]);
    expect(content).toContain("critical→2 (crit)   high→3 (err)     medium→4 (warning)");
    expect(content).toContain("low→5 (notice)      info→6 (info)");
  });
});

// ── renderer ───────────────────────────────────────────────────────────────

describe("renderRsyslogConf", () => {
  const full = [
    target({ id: 1, name: "siem-udp", host: "192.0.2.10", port: 514, protocol: "udp", minSeverity: "info" }),
    target({ id: 2, name: "siem-tls", host: "192.0.2.20", port: 6514, protocol: "tls", minSeverity: "high" }),
    target({ id: 3, name: "siem-off", host: "192.0.2.30", port: 514, protocol: "tcp", minSeverity: "critical", enabled: false }),
  ];

  it("is deterministic (byte-identical renders, hash-stable)", () => {
    const a = renderRsyslogConf(full);
    const b = renderRsyslogConf(full);
    expect(a.content).toBe(b.content);
    expect(rsyslogConfHash(a.content)).toBe(rsyslogConfHash(renderRsyslogConf(full).content));
    expect(rsyslogConfHash(a.content)).toHaveLength(16);
  });

  it("emits the marked console block with one action per ENABLED target", () => {
    const { content, targets } = renderRsyslogConf(full);
    expect(content).toContain(RSYSLOG_BEGIN_MARKER);
    expect(content).toContain(RSYSLOG_END_MARKER);
    expect(targets).toHaveLength(2); // disabled target skipped
    expect(targets.map((t) => t.id)).toEqual([1, 2]);
    const body = content.slice(content.indexOf(RSYSLOG_BEGIN_MARKER), content.indexOf(RSYSLOG_END_MARKER));
    expect(body).toContain('target="192.0.2.10"');
    expect(body).toContain('target="192.0.2.20"');
    expect(body).not.toContain("192.0.2.30");
    const actionLines = body.split("\n").filter((l) => l.includes("action(type=\"omfwd\"")).length;
    expect(actionLines).toBe(2);
  });

  it("renders every queue/retry param (buffered rows until reachable)", () => {
    const { content } = renderRsyslogConf([target({ id: 7 })]);
    expect(content).toContain('type="omfwd"');
    expect(content).toContain('template="RSYSLOG_TraditionalFileFormat"');
    expect(content).toContain('queue.type="LinkedList"');
    expect(content).toContain('queue.size="10000"');
    expect(content).toContain('queue.filename="utm_fwd_7"');
    expect(content).toContain('queue.maxDiskSpace="104857600"');
    expect(content).toContain('queue.saveOnShutdown="on"');
    expect(content).toContain('action.resumeRetryCount="-1"');
    expect(content).toContain('port="514"');
    expect(content).toContain('protocol="udp"');
  });

  it("maps tls → tcp + gtls StreamDriver and warns about the driver", () => {
    const { content, warnings } = renderRsyslogConf([target({ protocol: "tls" })]);
    expect(content).toContain('protocol="tcp"');
    expect(content).toContain('StreamDriverName="gtls"');
    expect(content).toContain('StreamDriverMode="1"');
    expect(content).not.toContain('protocol="tls"');
    expect(warnings.some((w) => w.includes("gnutls"))).toBe(true);
  });

  it("warns on disabled targets without failing", () => {
    const { warnings } = renderRsyslogConf([target({ enabled: false, name: "siem-off" })]);
    expect(warnings.some((w) => w.includes("siem-off") && w.includes("disabled"))).toBe(true);
  });

  it("renders the idle omfile action when no target is enabled (rsyslog 2103 guard)", () => {
    const { content, targets } = renderRsyslogConf([target({ enabled: false })]);
    expect(targets).toHaveLength(0);
    expect(content).toContain(RSYSLOG_IDLE_ACTION);
    expect(content).toContain(RSYSLOG_BEGIN_MARKER);
    expect(content).toContain(RSYSLOG_END_MARKER);
  });
});

// ── refusals (self-loop + config injection) ────────────────────────────────

describe("hardRsyslogRefusal / loopback + unsafe hosts", () => {
  it("detects loopback forms (127/8, localhost, ::1, brackets, v4-mapped)", () => {
    expect(isLoopbackHost("127.0.0.1")).toBe(true);
    expect(isLoopbackHost("127.9.9.9")).toBe(true);
    expect(isLoopbackHost("localhost")).toBe(true);
    expect(isLoopbackHost("LOCALHOST")).toBe(true);
    expect(isLoopbackHost("::1")).toBe(true);
    expect(isLoopbackHost("[::1]")).toBe(true);
    expect(isLoopbackHost("::ffff:127.0.0.1")).toBe(true);
    expect(isLoopbackHost("192.0.2.10")).toBe(false);
    expect(isLoopbackHost("syslog.corp.example")).toBe(false);
    expect(isLoopbackHost("2001:db8::1")).toBe(false);
  });
  it("hard-refuses enabled loopback targets with a self-loop explanation", () => {
    for (const host of ["127.0.0.1", "localhost", "::1"]) {
      const ref = hardRsyslogRefusal([target({ host })]);
      expect(ref).toContain(host);
      expect(ref).toContain("self-loop");
    }
    expect(hardRsyslogRefusal([target({ host: "192.0.2.10" })])).toBeNull();
  });
  it("ignores disabled targets (nothing is rendered for them)", () => {
    expect(hardRsyslogRefusal([target({ host: "127.0.0.1", enabled: false })])).toBeNull();
  });
  it("refuses hosts that could inject rsyslog syntax (quotes/whitespace/backslash)", () => {
    expect(isUnsafeRsyslogHost('evil" target="x')).toBe(true);
    expect(isUnsafeRsyslogHost("bad host")).toBe(true);
    expect(isUnsafeRsyslogHost("back\\slash")).toBe(true);
    expect(isUnsafeRsyslogHost("syslog.corp.example")).toBe(false);
    expect(hardRsyslogRefusal([target({ host: 'evil" target="x' })])).toContain("not valid for rsyslog omfwd");
  });
});

// ── command whitelist ──────────────────────────────────────────────────────

describe("rsyslogStepGuarded", () => {
  it("allows exactly the rsyslogd/install/cp/systemctl/ss/rm plan forms", () => {
    expect(rsyslogStepGuarded("rsyslogd -N1 -f /var/lib/console/rsyslog/stage-99-utm-console.conf")).toBe(true);
    expect(rsyslogStepGuarded("rsyslogd -N1 -f /etc/rsyslog.d/99-utm-console.conf")).toBe(true);
    expect(rsyslogStepGuarded("install -m 0644 /var/lib/console/rsyslog/stage-99-utm-console.conf /etc/rsyslog.d/99-utm-console.conf")).toBe(true);
    expect(rsyslogStepGuarded("cp /etc/rsyslog.d/99-utm-console.conf /var/lib/console/rsyslog/backup-2025-01-01T00-00-00-000Z/99-utm-console.conf")).toBe(true);
    expect(rsyslogStepGuarded("systemctl restart rsyslog")).toBe(true);
    expect(rsyslogStepGuarded("systemctl is-active rsyslog")).toBe(true);
    expect(rsyslogStepGuarded("ss -a -u -p")).toBe(true);
    expect(rsyslogStepGuarded("ss -a -t -p")).toBe(true);
    expect(rsyslogStepGuarded("rm -f /var/lib/console/rsyslog/stage-99-utm-console.conf")).toBe(true);
  });
  it("rejects anything else — chaining, other units, other binaries, empty", () => {
    for (const evil of [
      "",
      "rsyslogd -N5 -f /etc/shadow",
      "rsyslogd -N1 -f /etc/passwd; rm -rf /",
      "systemctl restart rsyslogd", // unit is `rsyslog`, NOT `rsyslogd`
      "systemctl restart cron",
      "systemctl stop rsyslog",
      "install -m 0644 /tmp/payload /etc/rsyslog.d/99-utm-console.conf",
      "rm -rf /etc/rsyslog.d",
      "rm -f /var/lib/console/rsyslog/state.json",
      "sh -c evil",
      "reboot",
      "ss -a -u -p && reboot",
      "cp /etc/shadow /var/lib/console/rsyslog/backup-x/shadow",
    ]) {
      expect(rsyslogStepGuarded(evil)).toBe(false);
    }
  });
});

// ── apply plan ─────────────────────────────────────────────────────────────

describe("buildRsyslogApplyPlan", () => {
  const targets = [
    target({ id: 1, protocol: "udp", minSeverity: "info" }),
    target({ id: 2, host: "192.0.2.20", port: 6514, protocol: "tls", minSeverity: "critical" }),
  ];

  it("orders: snapshot → stage → validate → install → cleanup → restart → verify → writefile", () => {
    const plan = buildRsyslogApplyPlan({ targets, managedFileExists: true, mode: "exec", ts: "t" });
    const kinds = plan.steps.map((s) => s.kind as string);
    expect(kinds[0]).toBe("snapshot");
    const idx = (k: string) => kinds.indexOf(k);
    expect(idx("stage")).toBeGreaterThan(idx("snapshot"));
    expect(idx("validate")).toBeGreaterThan(idx("stage"));
    expect(idx("install")).toBeGreaterThan(idx("validate"));
    expect(idx("restart")).toBeGreaterThan(idx("install"));
    expect(idx("verify")).toBeGreaterThan(idx("restart"));
    expect(kinds[kinds.length - 1]).toBe("writefile");
    // exact commands for the critical steps
    expect(plan.steps.find((s) => s.kind === "snapshot")?.cmd).toBe(
      `cp ${RSYSLOG_MANAGED_FILE} /var/lib/console/rsyslog/backup-t/99-utm-console.conf`,
    );
    expect(plan.steps.find((s) => s.kind === "stage")?.cmd).toBe("");
    expect(plan.steps.find((s) => s.kind === "validate")?.cmd).toBe(`rsyslogd -N1 -f ${RSYSLOG_STAGE_FILE}`);
    expect(plan.steps.find((s) => s.kind === "install")?.cmd).toBe(
      `install -m 0644 ${RSYSLOG_STAGE_FILE} ${RSYSLOG_MANAGED_FILE}`,
    );
    expect(plan.steps.find((s) => s.kind === "restart")?.cmd).toBe("systemctl restart rsyslog");
    const verifies = plan.steps.filter((s) => s.kind === "verify").map((s) => s.cmd);
    expect(verifies).toEqual(["systemctl is-active rsyslog", "", `rsyslogd -N1 -f ${RSYSLOG_MANAGED_FILE}`]);
    expect(plan.confHash).toHaveLength(16);
  });

  it("skips the snapshot step when no managed file exists (first apply)", () => {
    const plan = buildRsyslogApplyPlan({ targets, managedFileExists: false, mode: "exec", ts: "t" });
    expect(plan.steps.some((s) => s.kind === "snapshot")).toBe(false);
    expect(plan.steps.some((s) => s.kind === "writefile")).toBe(true);
  });

  it("state content carries confHash + appliedAt + enabled targetIds", () => {
    const plan = buildRsyslogApplyPlan({
      targets: [...targets, target({ id: 3, enabled: false })],
      managedFileExists: true,
      mode: "exec",
      ts: "t",
    });
    const state = JSON.parse(plan.stateContent) as { confHash: string; appliedAt: string; targetIds: number[] };
    expect(state.confHash).toBe(plan.confHash);
    expect(typeof state.appliedAt).toBe("string");
    expect(state.targetIds).toEqual([1, 2]); // disabled id 3 excluded
  });

  it("every step cmd passes the whitelist (plan is executable as written)", () => {
    const plan = buildRsyslogApplyPlan({ targets, managedFileExists: true, mode: "exec", ts: "t" });
    for (const s of plan.steps) {
      if (s.cmd !== "") expect(rsyslogStepGuarded(s.cmd)).toBe(true);
    }
  });

  it("drops refused targets from the render and warns (refusal surfaces separately)", () => {
    const plan = buildRsyslogApplyPlan({
      targets: [target({ id: 1, host: "127.0.0.1", name: "self" }), target({ id: 2, host: "192.0.2.10", name: "ok" })],
      managedFileExists: false,
      mode: "plan",
      ts: "t",
    });
    expect(plan.content).not.toContain("127.0.0.1");
    expect(plan.content).toContain("192.0.2.10");
    expect(plan.warnings.some((w) => w.includes("self") && w.includes("refused"))).toBe(true);
  });

  it("renders zero enabled targets with the idle omfile action (teardown apply)", () => {
    const plan = buildRsyslogApplyPlan({ targets: [target({ enabled: false })], managedFileExists: true, mode: "plan", ts: "t" });
    expect(plan.targets).toHaveLength(0);
    expect(plan.content).toContain(RSYSLOG_IDLE_ACTION);
    expect(plan.content).toContain(RSYSLOG_BEGIN_MARKER);
    expect(plan.content).toContain(RSYSLOG_END_MARKER);
    expect(plan.steps.some((s) => s.kind === "restart")).toBe(true);
  });
});

// ── drift + ss parsing ─────────────────────────────────────────────────────

describe("computeRsyslogDrift", () => {
  const rendered = renderRsyslogConf([target()]);

  it("in-sync only when live hash matches AND unit is active", () => {
    const ok = computeRsyslogDrift({
      renderedContent: rendered.content,
      liveFileHash: rsyslogConfHash(rendered.content),
      unitActive: true,
    });
    expect(ok.inSync).toBe(true);
    expect(ok.driftReasons).toEqual([]);
  });
  it("flags missing/changed file and inactive unit", () => {
    const missing = computeRsyslogDrift({ renderedContent: rendered.content, liveFileHash: null, unitActive: true });
    expect(missing.inSync).toBe(false);
    expect(missing.driftReasons[0]).toContain("managed file is missing");

    const changed = computeRsyslogDrift({ renderedContent: rendered.content, liveFileHash: "deadbeefdeadbeef", unitActive: true });
    expect(changed.driftReasons.some((r) => r.includes("deadbeefdeadbeef"))).toBe(true);

    const down = computeRsyslogDrift({
      renderedContent: rendered.content,
      liveFileHash: rsyslogConfHash(rendered.content),
      unitActive: false,
    });
    expect(down.inSync).toBe(false);
    expect(down.driftReasons[0]).toContain("not active");
  });
  it("unit state unknown (null) also breaks sync", () => {
    const d = computeRsyslogDrift({
      renderedContent: rendered.content,
      liveFileHash: rsyslogConfHash(rendered.content),
      unitActive: null,
    });
    expect(d.inSync).toBe(false);
    expect(d.driftReasons[0]).toContain("unknown");
  });
});

describe("parseSsForTarget", () => {
  const SS_TCP = `State  Recv-Q Send-Q Local Address:Port  Peer Address:Port  Process
ESTAB  0      128    192.168.1.5:42120   192.0.2.10:514     users:(("rsyslogd",pid=912,fd=4))
SYN-SENT 0  1  192.168.1.5:42122   192.0.2.20:6514    users:(("rsyslogd",pid=912,fd=5))`;
  const SS_UDP = `State  Recv-Q Send-Q Local Address:Port  Peer Address:Port  Process
ESTAB  0      0      192.168.1.5:42123   192.0.2.10:514     users:(("rsyslogd",pid=912,fd=6))`;

  it("tcp: connected only on ESTAB lines", () => {
    expect(parseSsForTarget(SS_TCP, "192.0.2.10", 514, "tcp")).toBe(true);
    expect(parseSsForTarget(SS_TCP, "192.0.2.20", 6514, "tcp")).toBe(false); // SYN-SENT
    expect(parseSsForTarget(SS_TCP, "203.0.113.9", 514, "tcp")).toBe(false);
  });
  it("udp: an omfwd socket at all counts as sending (informational)", () => {
    expect(parseSsForTarget(SS_UDP, "192.0.2.10", 514, "udp")).toBe(true);
    expect(parseSsForTarget(SS_UDP, "192.0.2.20", 6514, "udp")).toBe(false);
  });
  it("empty output cannot decide (null) — never fabricates a state", () => {
    expect(parseSsForTarget("", "192.0.2.10", 514, "tcp")).toBeNull();
    expect(parseSsForTarget("\n", "192.0.2.10", 514, "udp")).toBeNull();
  });
});

// ── per-target render identity ─────────────────────────────────────────────

describe("renderTargetLine identity", () => {
  it("renderHash is stable per target line and differs across targets", () => {
    const a = renderTargetLine(target({ id: 1 }));
    const b = renderTargetLine(target({ id: 2 }));
    expect(a.renderHash).toHaveLength(16);
    expect(a.renderHash).toBe(renderTargetLine(target({ id: 1 })).renderHash);
    expect(a.renderHash).not.toBe(b.renderHash);
  });
});
