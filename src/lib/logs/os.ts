/**
 * Syslog OS layer (M09 §4) — real rsyslogd forwarding with omfwd.
 *
 * Target: Debian 13, rsyslogd 8.25. Two names matter and are NOT the same:
 *   • systemd unit is `rsyslog`  → `systemctl restart rsyslog` / `is-active`;
 *   • validation binary `rsyslogd` → `rsyslogd -N1 -f <file>` (config check).
 *
 * Managed file: /etc/rsyslog.d/99-utm-console.conf. Everything OUTSIDE the
 * marked block is preserved (local admin snippets); everything INSIDE is
 * console-owned and overwritten on every apply:
 *
 *   # BEGIN UTM-managed (Cryptsk Console)
 *   if $syslogseverity <= N then { action(type="omfwd" …) }   ← one per target
 *   # END UTM-managed
 *
 * Severity mapping (RFC 5424 syslogseverity 0=emerg 1=alert 2=crit 3=err
 * 4=warning 5=notice 6=info 7=debug). Console minSeverity folds onto the
 * rsyslog scale — a target receives N and everything MORE severe than N
 * (debug=7 never matches any gate):
 *
 *   critical→2 (crit)   high→3 (err)     medium→4 (warning)
 *   low→5 (notice)      info→6 (info)
 *
 * (The comment is duplicated verbatim into the rendered file header — the
 * appliance admin must be able to read the mapping without the console.)
 *
 * Protocol mapping: udp → protocol="udp"; tcp → protocol="tcp"; tls →
 * protocol="tcp" + StreamDriverName="gtls" + StreamDriverMode="1" (gtls
 * requires the rsyslog gnutls driver package on the appliance — rendered
 * as-is, the driver presence is the admin's concern, surfaced as a warning).
 *
 * Every action gets reliable buffering (LinkedList queue + disk assist +
 * saveOnShutdown) so rows buffer until the collector is reachable again,
 * and action.resumeRetryCount="-1" retries forever.
 *
 * This module is PURE (no exec/db/fs) so the renderer, parsers, drift and
 * guard are fully unit-testable — fs/exec/db live in os-service.ts.
 */

import { createHash } from "crypto";

// ── constants ───────────────────────────────────────────────────────────────

export const RSYSLOG_STATE_DIR = "/var/lib/console/rsyslog";
export const RSYSLOG_STATE_FILE = `${RSYSLOG_STATE_DIR}/state.json`;
export const RSYSLOG_MANAGED_FILE = "/etc/rsyslog.d/99-utm-console.conf";
export const RSYSLOG_STAGE_FILE = `${RSYSLOG_STATE_DIR}/stage-99-utm-console.conf`;
/** systemd unit (NOT the rsyslogd binary name). */
export const RSYSLOG_UNIT = "rsyslog";
/** backup-<ts>/ directories hold the pre-apply managed file + dir listing */
export const RSYSLOG_BACKUP_DIR_RE = /^backup-[\w.-]+$/;

/** forward-marker header/footer of the console-owned block */
export const RSYSLOG_BEGIN_MARKER = "# BEGIN UTM-managed (Cryptsk Console)";
export const RSYSLOG_END_MARKER = "# END UTM-managed";

/**
 * Idle-state action (zero enabled targets): an omfile writing only emerg+
 * messages to a console-owned log file. Harmless (does not stop rule
 * evaluation, discards nothing from other outputs) and satisfies rsyslog's
 * "must have at least one active action" validation (error 2103).
 */
export const RSYSLOG_IDLE_ACTION =
  'if $syslogseverity <= 2 then { action(type="omfile" file="/var/lib/console/rsyslog/idle.log" template="RSYSLOG_TraditionalFileFormat") }';
const IDLE_ACTION_LINE = RSYSLOG_IDLE_ACTION;

// ── shapes (resolved by os-service, consumed here purely) ──────────────────

export type SyslogProtocol = "udp" | "tcp" | "tls";
export type SyslogMinSeverity = "info" | "low" | "medium" | "high" | "critical";

export interface SyslogTargetShape {
  id: number;
  name: string;
  host: string;
  port: number;
  protocol: SyslogProtocol;
  minSeverity: SyslogMinSeverity;
  enabled: boolean;
}

// ── severity mapping ────────────────────────────────────────────────────────

/**
 * Console minSeverity → syslogseverity gate value (`$syslogseverity <= N`).
 * Same table as the file-header comment above — keep both in sync.
 */
export const SEVERITY_GATE: Record<SyslogMinSeverity, number> = {
  critical: 2,
  high: 3,
  medium: 4,
  low: 5,
  info: 6,
};

// ── hard refusals (loopback self-loop + config injection) ──────────────────

/**
 * Loopback/self-loop detection: forwarding to ourselves would ping-pong every
 * log back into rsyslog (infinite loop). 127.0.0.0/8, localhost, ::1 (also in
 * bracket form and v4-mapped ::ffff:127.x) are refused.
 */
export function isLoopbackHost(host: string): boolean {
  let h = host.trim().toLowerCase();
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  if (h.includes("%")) h = h.split("%")[0]; // strip IPv6 zone id
  if (h.startsWith("::ffff:")) h = h.slice("::ffff:".length); // v4-mapped
  return h === "localhost" || h === "::1" || /^127(\.\d{1,3}){3}$/.test(h);
}

/** Hosts that would break the quoted rsyslog parameter syntax (injection). */
export function isUnsafeRsyslogHost(host: string): boolean {
  return /[\s"'\\]/.test(host);
}

/**
 * Hard refusals — a loopback target is a self-loop (rsyslog would feed its
 * own output back in); a syntactically unsafe host could inject config.
 * Returns null when nothing is refused.
 */
export function hardRsyslogRefusal(targets: SyslogTargetShape[]): string | null {
  for (const t of targets) {
    if (!t.enabled) continue;
    if (isLoopbackHost(t.host)) {
      return `target "${t.name}" (id ${t.id}) points at ${t.host} — forwarding to loopback would feed rsyslog its own output (self-loop) and is refused`;
    }
    if (isUnsafeRsyslogHost(t.host)) {
      return `target "${t.name}" (id ${t.id}) has a host not valid for rsyslog omfwd (quotes/whitespace/backslash) — refused`;
    }
  }
  return null;
}

// ── renderer ────────────────────────────────────────────────────────────────

export interface RenderedTarget {
  id: number;
  name: string;
  host: string;
  port: number;
  protocol: SyslogProtocol;
  minSeverity: SyslogMinSeverity;
  severityNum: number;
  /** the single `if $syslogseverity <= N then { action(…) }` line */
  line: string;
  /** sha256(line).slice(0,16) — per-target identity for status rows */
  renderHash: string;
}

export interface RenderedRsyslog {
  /** full managed-file content — deterministic, byte-stable for a given input */
  content: string;
  targets: RenderedTarget[];
  /** informational notes (tls driver, disabled targets, …) */
  warnings: string[];
}

const QUEUE_SIZE = "10000";
const QUEUE_MAX_DISK = "104857600";

/** One omfwd action per enabled target, behind a severity gate. Deterministic. */
export function renderTargetLine(t: SyslogTargetShape): RenderedTarget {
  const severityNum = SEVERITY_GATE[t.minSeverity] ?? SEVERITY_GATE.info;
  const proto = t.protocol === "tls" ? "tcp" : t.protocol;
  const tlsOpts = t.protocol === "tls" ? ' StreamDriverName="gtls" StreamDriverMode="1"' : "";
  const line =
    `if $syslogseverity <= ${severityNum} then { action(type="omfwd" target="${t.host}" port="${t.port}"` +
    ` protocol="${proto}" template="RSYSLOG_TraditionalFileFormat"` +
    ` queue.type="LinkedList" queue.size="${QUEUE_SIZE}" queue.filename="utm_fwd_${t.id}"` +
    ` queue.maxDiskSpace="${QUEUE_MAX_DISK}" queue.saveOnShutdown="on"` +
    ` action.resumeRetryCount="-1"${tlsOpts}) }`;
  return {
    id: t.id,
    name: t.name,
    host: t.host,
    port: t.port,
    protocol: t.protocol,
    minSeverity: t.minSeverity,
    severityNum,
    line,
    renderHash: createHash("sha256").update(line).digest("hex").slice(0, 16),
  };
}

const FILE_HEADER = [
  "# Managed by the Cryptsk Console — lines OUTSIDE the marked block are",
  "# preserved; lines INSIDE the block are overwritten on every console apply.",
  "#",
  "# severity mapping — RFC 5424 syslogseverity (0=emerg … 7=debug); console",
  "# minSeverity folds onto the rsyslog scale as a gate `if $syslogseverity <= N`:",
  "#   critical→2 (crit)   high→3 (err)     medium→4 (warning)",
  "#   low→5 (notice)      info→6 (info)",
  "#   (N and everything MORE severe forwards; debug=7 never matches)",
  "#",
  '# tls targets render as protocol="tcp" + StreamDriverName="gtls"',
  '# StreamDriverMode="1" — requires the rsyslog gnutls driver on this appliance.',
].join("\n");

/** Render the complete managed file. Same input → byte-identical output. */
export function renderRsyslogConf(targets: SyslogTargetShape[]): RenderedRsyslog {
  const warnings: string[] = [];
  const enabled = targets.filter((t) => t.enabled);
  for (const t of targets.filter((t) => !t.enabled)) {
    warnings.push(`target "${t.name}" is disabled — not rendered into the managed file`);
  }
  for (const t of enabled) {
    if (t.protocol === "tls") {
      warnings.push(`target "${t.name}" uses tls — StreamDriverName="gtls" requires the rsyslog gnutls driver on the appliance`);
    }
  }
  const targetsRendered = enabled.map(renderTargetLine);
  // rsyslog 8.25 refuses a config with zero outputs ("no active actions
  // configured", error 2103) — the idle fragment keeps a harmless omfile
  // action so validation passes and a fully-disabled state still applies.
  const bodyLines =
    targetsRendered.length > 0
      ? targetsRendered.map((r) => r.line)
      : [IDLE_ACTION_LINE];
  const content = [
    FILE_HEADER,
    RSYSLOG_BEGIN_MARKER,
    ...bodyLines,
    RSYSLOG_END_MARKER,
    "",
  ].join("\n");
  return { content, targets: targetsRendered, warnings };
}

/** sha256(content).slice(0,16) — the value stored in state.json + compared on status. */
export function rsyslogConfHash(content: string): string {
  return createHash("sha256").update(content).digest("hex").slice(0, 16);
}

// ── live state parsers (ss output, ground truth format from iproute2) ──────

/**
 * Parse `ss -a -t -p` / `ss -a -u -p` output for one target endpoint.
 *  • tcp: connected = a line mentions host:port with state ESTAB
 *    (SYN-SENT/-RECV, TIME-WAIT … are NOT connected).
 *  • udp: connected = an omfwd socket for host:port exists at all
 *    (ss prints UNCONN for unconnected UDP; omfwd connects its socket,
 *    which shows ESTAB — either way the socket proves the target is
 *    being sent to). Informational only — never flips inSync.
 * Returns null when the parse cannot decide (empty/unparseable output).
 */
export function parseSsForTarget(stdout: string, host: string, port: number, protocol: SyslogProtocol): boolean | null {
  const lines = stdout.split("\n").filter((l) => l.includes(`:${port}`) && l.includes(host));
  if (lines.length === 0) return stdout.trim().length === 0 ? null : false;
  if (protocol === "udp") return true; // socket exists → omfwd is sending
  return lines.some((l) => /\bESTAB\b/.test(l));
}

// ── drift ───────────────────────────────────────────────────────────────────

export interface RsyslogDrift {
  inSync: boolean;
  driftReasons: string[];
}

/**
 * File-hash + unit-state drift only (mirrors the qos convention): sockets are
 * transient and informational — they never flip inSync.
 */
export function computeRsyslogDrift(input: {
  renderedContent: string;
  liveFileHash: string | null;
  unitActive: boolean | null;
}): RsyslogDrift {
  const reasons: string[] = [];
  const expectedHash = rsyslogConfHash(input.renderedContent);
  if (input.liveFileHash == null) reasons.push("managed file is missing — expected /etc/rsyslog.d/99-utm-console.conf");
  else if (input.liveFileHash !== expectedHash) reasons.push(`live file hash ${input.liveFileHash} — expected ${expectedHash}`);
  if (input.unitActive !== true) reasons.push(`unit rsyslog is ${input.unitActive === false ? "not active" : "unknown"} — expected active`);
  return { inSync: reasons.length === 0, driftReasons: reasons };
}

// ── apply plan ──────────────────────────────────────────────────────────────

export type RsyslogPlanStepKind = "snapshot" | "stage" | "validate" | "install" | "exec" | "restart" | "verify" | "writefile";

export interface RsyslogPlanStep {
  step: string;
  cmd: string; // "" for stage/verify-hash/writefile (fs ops resolved at exec time)
  kind: RsyslogPlanStepKind;
}

export interface RsyslogApplyPlan {
  mode: "plan" | "exec";
  steps: RsyslogPlanStep[];
  /** sha256-16 of the rendered managed file (== state.json confHash) */
  confHash: string;
  backupDir: string;
  stateContent: string;
  targets: RenderedTarget[];
  /** rendered managed-file content (staged verbatim at exec time) */
  content: string;
  warnings: string[];
}

/**
 * Convergence plan (mirrors qos/ha ordering):
 *   snapshot → stage → validate → install → cleanup → restart →
 *   verify(unit, hash, config) → save state file.
 * The snapshot runs before ANY mutation; the state file is written only after
 * every verify passed (the executor enforces this).
 */
export function buildRsyslogApplyPlan(input: {
  targets: SyslogTargetShape[];
  managedFileExists: boolean;
  mode: "plan" | "exec";
  ts: string;
}): RsyslogApplyPlan {
  const { targets, managedFileExists, mode, ts } = input;
  const warnings: string[] = [];

  // refusal surfaces separately via hardRsyslogRefusal — skipped here so the
  // preview never normalizes a self-loop target (qos protected-iface convention)
  const acceptable = targets.filter((t) => !t.enabled || !(isLoopbackHost(t.host) || isUnsafeRsyslogHost(t.host)));
  for (const t of targets) {
    if (t.enabled && (isLoopbackHost(t.host) || isUnsafeRsyslogHost(t.host))) {
      warnings.push(`target "${t.name}" is refused and NOT part of this plan`);
    }
  }

  const rendered = renderRsyslogConf(acceptable);
  const backupDir = `${RSYSLOG_STATE_DIR}/backup-${ts}`;

  const steps: RsyslogPlanStep[] = [];
  if (managedFileExists) {
    steps.push({
      step: "snapshot managed file",
      cmd: `cp ${RSYSLOG_MANAGED_FILE} ${backupDir}/99-utm-console.conf`,
      kind: "snapshot",
    });
  }
  steps.push({ step: "stage rendered fragment", cmd: "", kind: "stage" });
  steps.push({ step: "validate staged config", cmd: `rsyslogd -N1 -f ${RSYSLOG_STAGE_FILE}`, kind: "validate" });
  steps.push({
    step: "install managed file",
    cmd: `install -m 0644 ${RSYSLOG_STAGE_FILE} ${RSYSLOG_MANAGED_FILE}`,
    kind: "install",
  });
  steps.push({ step: "cleanup stage file", cmd: `rm -f ${RSYSLOG_STAGE_FILE}`, kind: "exec" });
  steps.push({ step: "restart rsyslog", cmd: `systemctl restart ${RSYSLOG_UNIT}`, kind: "restart" });
  steps.push({ step: "verify unit active", cmd: `systemctl is-active ${RSYSLOG_UNIT}`, kind: "verify" });
  steps.push({ step: "verify managed file hash", cmd: "", kind: "verify" });
  steps.push({ step: "verify installed config", cmd: `rsyslogd -N1 -f ${RSYSLOG_MANAGED_FILE}`, kind: "verify" });
  steps.push({ step: "save state file", cmd: "", kind: "writefile" });

  const stateContent = JSON.stringify(
    {
      confHash: rsyslogConfHash(rendered.content),
      appliedAt: new Date().toISOString(),
      targetIds: rendered.targets.map((t) => t.id),
    },
    null,
    2,
  );

  return {
    mode,
    steps,
    confHash: rsyslogConfHash(rendered.content),
    backupDir,
    stateContent,
    targets: rendered.targets,
    content: rendered.content,
    warnings: [...rendered.warnings, ...warnings],
  };
}

// ── command whitelist ───────────────────────────────────────────────────────

/** Exact-prefix anchored forms — anything else (pipes, `;`, `&&`) fails. */
const RSYSLOG_STEP_RES: RegExp[] = [
  /^rsyslogd -N1 -f [\w./@-]+$/,
  /^install -m 0644 \/var\/lib\/console\/rsyslog\/[\w.-]+ \/etc\/rsyslog\.d\/[\w.-]+$/,
  /^cp \/etc\/rsyslog\.d\/[\w.-]+ \/var\/lib\/console\/rsyslog\/backup-[\w.-]+\/[\w.-]+$/,
  /^systemctl restart rsyslog$/,
  /^systemctl is-active rsyslog$/,
  /^ss -a -u -p$/,
  /^ss -a -t -p$/,
  /^rm -f \/var\/lib\/console\/rsyslog\/stage[\w.-]*$/,
];

export function rsyslogStepGuarded(cmd: string): boolean {
  return RSYSLOG_STEP_RES.some((re) => re.test(cmd));
}
