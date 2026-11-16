/**
 * IPS OS integration (GUI↔Suricata) — mirrors the firewall-os.ts architecture
 * for the Suricata engine:
 *
 *   DB policy (desired state)  ──generate──▶  /var/lib/suricata/rules/utm-managed.rules
 *                                             /etc/suricata/threshold.config (managed block)
 *                                             suricata.yaml rule-files + threshold-file
 *
 * Apply pipeline (gated by CONSOLE_OS_APPLY=1, fail-closed everywhere else):
 *   1. backup current files → /var/lib/console/ips/backup-<ts>/
 *   2. write managed files
 *   3. validate with `suricata -T` (engine test run)
 *   4. validation failure  → automatic rollback from the backup
 *   5. live reload via `suricatasc -c "ruleset-reload-nonterminal"` (no packet
 *      loss — reloads rules + threshold files on the running engine)
 *   6. record state.json (last apply, backup dir, validation, reload)
 *
 * Semantics honoured from M04/ADR-017:
 *   • default policy = first enabled policy by id asc
 *   • exceptions sid 0 = any-SID capture bypass → threshold.config
 *     `suppress gen_id 1, sig_id 0, track …` lines (sid 0 without a
 *     source/dest would suppress the entire ruleset — skipped with a warning)
 *   • thresholds → `threshold … track by_src/by_dst, count N, seconds S;`
 *   • custom rules are written verbatim into the managed rules file
 *
 * Pure functions (generateManagedRules, buildThresholdEntries,
 * replaceManagedBlock, yamlAppendRuleFile, yamlEnsureThresholdFile,
 * normalizeIpsAction, countRulesInText, computeIpsDrift) are unit-testable
 * without a filesystem or process environment.
 */

import fs from "fs/promises";
import path from "path";
import { db } from "@/lib/db";
import { runTool, hasTool, readServiceStates } from "@/lib/host/tools";
import { detectSuricataEve } from "@/lib/host/tools";
import type { ExceptionRow, ThresholdRow } from "./catalog";

// ── paths ───────────────────────────────────────────────────────────────────

export const IPS_DIR = process.env.CONSOLE_IPS_DIR || "/var/lib/console/ips";
export const SURICATA_RULES_DIR = process.env.CONSOLE_SURICATA_RULES_DIR || "/var/lib/suricata/rules";
export const SURICATA_ETC = process.env.CONSOLE_SURICATA_ETC || "/etc/suricata";
export const MANAGED_RULES_NAME = "utm-managed.rules";
export const MANAGED_RULES_FILE = path.join(SURICATA_RULES_DIR, MANAGED_RULES_NAME);
export const THRESHOLD_FILE = path.join(SURICATA_ETC, "threshold.config");
export const SURICATA_YAML = path.join(SURICATA_ETC, "suricata.yaml");

export const MARKER_BEGIN = "# === UTM CONSOLE MANAGED — BEGIN (generated, do not edit) ===";
export const MARKER_END = "# === UTM CONSOLE MANAGED — END ===";

// ── shapes ──────────────────────────────────────────────────────────────────

export interface IpsOsPolicyInput {
  id: number;
  name: string;
  mode: string;
  customRules: string[];
  exceptions: ExceptionRow[];
  thresholds: ThresholdRow[];
}

export interface IpsGenInput {
  policy: IpsOsPolicyInput | null;
}

export interface IpsOsFacts {
  available: boolean;
  service: string | null;
  version: string | null;
  runningMode: string | null;
  evePath: string | null;
  rulesFiles: Array<{ name: string; sids: number; alert: number; drop: number; pass: number; bytes: number }>;
  updaterInstalled: boolean;
  yamlHasManagedFile: boolean;
  yamlHasThresholdFile: boolean;
  thresholdManagedLines: number;
}

export interface IpsDrift {
  managedRulesInSync: boolean;
  thresholdInSync: boolean;
  yamlInSync: boolean;
  inSync: boolean;
}

export interface IpsApplyPlan {
  defaultPolicy: { id: number; name: string; mode: string } | null;
  enabledPolicyCount: number;
  managedRules: string;
  managedRuleCount: number;
  thresholdBlock: string;
  thresholdEntryCount: number;
  yamlNeedsManagedFile: boolean;
  yamlNeedsThresholdFile: boolean;
  drift: IpsDrift;
  warnings: string[];
  facts: IpsOsFacts;
}

export interface IpsApplyOutcome {
  applied: boolean;
  rolledBack: boolean;
  appliedAt: string | null;
  policyId: number | null;
  policyName: string | null;
  backupDir: string | null;
  validateOk: boolean;
  reloaded: boolean;
  warnings: string[];
  detail: string | null;
}

export interface IpsApplyState {
  lastApplyAt: string;
  policyId: number;
  policyName: string;
  backupDir: string;
  validateOk: boolean;
  reloaded: boolean;
}

export interface OsRuleUpdateResult {
  ranOnOs: boolean;
  reloaded: boolean;
  note: string;
  outputTail: string | null;
}

// ── pure helpers ────────────────────────────────────────────────────────────

/**
 * EVE alert.action → console IpsAction enum. IDS (passive) engines report
 * "allowed" (alert-only); inline engines report "blocked" for drop verdicts.
 * Unknown/legacy values map to "alert" (safe, detect-only default).
 */
export function normalizeIpsAction(action: string | null | undefined): "alert" | "drop" | "reject" | "bypass" | "suppressed" {
  switch (action) {
    case "alert":
    case "drop":
    case "reject":
    case "bypass":
    case "suppressed":
      return action;
    case "allowed":
      return "alert";
    case "blocked":
      return "drop";
    default:
      return "alert";
  }
}

/** Count rules (action lines) and SIDs inside a suricata rules text. */
export function countRulesInText(text: string): { sids: number; alert: number; drop: number; pass: number; reject: number } {
  const sids = new Set<string>();
  let alert = 0;
  let drop = 0;
  let pass = 0;
  let reject = 0;
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const m = /^(\w+)\s/.exec(t);
    if (!m) continue;
    const sidM = /\bsid:\s*(\d+)\s*;/.exec(t);
    if (sidM) sids.add(sidM[1]);
    switch (m[1]) {
      case "alert": alert++; break;
      case "drop": drop++; break;
      case "pass": pass++; break;
      case "reject": reject++; break;
      default: break;
    }
  }
  return { sids: sids.size, alert, drop, pass, reject };
}

/** Managed rules file content for the default policy (custom rules verbatim). */
export function generateManagedRules(input: IpsGenInput, generatedAt: string): string {
  const header = [
    `# ${MANAGED_RULES_NAME} — console-managed Suricata rules`,
    `# policy: ${input.policy ? `${input.policy.name} (id=${input.policy.id}, mode=${input.policy.mode})` : "(none enabled)"}`,
    `# generated: ${generatedAt}`,
    `# source: Cryptsk Console IPS policy "${input.policy?.name ?? "none"}" — custom rules verbatim`,
    "#",
  ];
  const rules = (input.policy?.customRules ?? []).map((r) => r.trim()).filter(Boolean);
  const body = rules.length > 0 ? rules : ["# (no custom rules in the active policy)"];
  return [...header, ...body, ""].join("\n");
}

/**
 * threshold.config entries from the policy. Returns the managed block body
 * plus warnings for defensive skips (any-SID bypass without scope).
 */
export function buildThresholdEntries(input: IpsGenInput): { lines: string[]; warnings: string[] } {
  const lines: string[] = [];
  const warnings: string[] = [];
  const policy = input.policy;

  for (const ex of policy?.exceptions ?? []) {
    const hasScope = Boolean(ex.source || ex.dest);
    if (ex.sid === 0 && !hasScope) {
      warnings.push(
        `exception sid=0 without source/dest would suppress the ENTIRE ruleset — skipped (scope any-SID bypass by a source/dest CIDR)`,
      );
      continue;
    }
    if (ex.sid === 0) {
      // any-SID capture bypass: scope decides the track direction
      if (ex.source) lines.push(`suppress gen_id 1, sig_id 0, track by_src, ip ${ex.source}`);
      if (ex.dest) lines.push(`suppress gen_id 1, sig_id 0, track by_dst, ip ${ex.dest}`);
    } else if (ex.source) {
      lines.push(`suppress gen_id 1, sig_id ${ex.sid}, track by_src, ip ${ex.source}`);
    } else if (ex.dest) {
      lines.push(`suppress gen_id 1, sig_id ${ex.sid}, track by_dst, ip ${ex.dest}`);
    } else {
      lines.push(`suppress gen_id 1, sig_id ${ex.sid}`);
    }
  }

  for (const th of policy?.thresholds ?? []) {
    lines.push(`threshold gen_id 1, sig_id ${th.sid}, track ${th.track}, count ${th.count}, seconds ${th.seconds}`);
  }

  return { lines, warnings };
}

export function generateThresholdBlock(input: IpsGenInput, generatedAt: string): string {
  const { lines } = buildThresholdEntries(input);
  // placeholder is a COMMENT so drift compare treats an empty policy as empty
  const body = lines.length > 0 ? lines : ["# (no thresholds / exceptions in the active policy)"];
  return [
    MARKER_BEGIN,
    `# policy: ${input.policy ? `${input.policy.name} (id=${input.policy.id})` : "(none enabled)"} · generated ${generatedAt}`,
    ...body,
    MARKER_END,
  ].join("\n");
}

/** True when the desired policy produces zero threshold entries (empty block). */
export function thresholdEntriesEmpty(input: IpsGenInput): boolean {
  return buildThresholdEntries(input).lines.length === 0;
}

/** Replace (or remove, when `block` is empty) the managed block in a config text. */
export function replaceManagedBlock(existing: string, block: string): string {
  const begin = existing.indexOf(MARKER_BEGIN);
  const end = existing.indexOf(MARKER_END);
  let cleaned = existing;
  if (begin !== -1 && end !== -1 && end > begin) {
    cleaned = existing.slice(0, begin) + existing.slice(end + MARKER_END.length);
  }
  // normalise the tail so the block lands on its own lines
  cleaned = cleaned.replace(/\s*$/, "\n");
  if (!block) return cleaned;
  return `${cleaned}\n${block}\n`;
}

/** Idempotently add `- <fileName>` to the `rule-files:` list of suricata.yaml. */
export function yamlAppendRuleFile(yaml: string, fileName: string): { content: string; changed: boolean } {
  if (new RegExp(`^\\s*-\\s*${fileName}\\s*$`, "m").test(yaml)) return { content: yaml, changed: false };
  const lines = yaml.split("\n");
  const idx = lines.findIndex((l) => /^rule-files:\s*$/.test(l.trim()) || /^rule-files:/.test(l));
  if (idx === -1) return { content: yaml, changed: false };
  // find the end of the list block (last consecutive "  - x" line after idx)
  let insertAt = idx + 1;
  while (insertAt < lines.length && /^\s+-\s+\S/.test(lines[insertAt])) insertAt++;
  lines.splice(insertAt, 0, `  - ${fileName}`);
  return { content: lines.join("\n"), changed: true };
}

/** Idempotently enable `threshold-file: <file>` at top level of suricata.yaml. */
export function yamlEnsureThresholdFile(yaml: string, file: string): { content: string; changed: boolean } {
  const active = /^threshold-file:[ \t]*\S+[ \t]*$/m;
  if (active.test(yaml)) {
    // already active — rewrite the path only when it differs
    const m = /^threshold-file:[ \t]*(\S+)[ \t]*$/m.exec(yaml)!;
    if (m[1] === file) return { content: yaml, changed: false };
    return { content: yaml.replace(/^threshold-file:[ \t]*\S+[ \t]*$/m, `threshold-file: ${file}`), changed: true };
  }
  // uncomment the commented sample (Debian default keeps it as "# threshold-file: …")
  const commented = new RegExp(`^#\\s*threshold-file:.*$`, "m");
  if (commented.test(yaml)) {
    return { content: yaml.replace(commented, `threshold-file: ${file}`), changed: true };
  }
  // append after classification-file / default-rule-path block as fallback
  const anchor = yaml.match(/^classification-file:.*$/m);
  if (anchor && anchor.index !== undefined) {
    const at = anchor.index + anchor[0].length;
    return { content: yaml.slice(0, at) + `\nthreshold-file: ${file}` + yaml.slice(at), changed: true };
  }
  return { content: `${yaml}\nthreshold-file: ${file}`, changed: true };
}

/** Pure drift compare of generated vs live artefacts. */
export function computeIpsDrift(
  genManaged: string,
  liveManaged: string | null,
  genThresholdBlock: string,
  liveThreshold: string | null,
  yamlNeedsManagedFile: boolean,
  yamlNeedsThresholdFile: boolean,
): IpsDrift {
  // managed file: compare rule lines only (headers carry a timestamp)
  const genRules = genManaged.split("\n").filter((l) => l.trim() && !l.trim().startsWith("#")).join("\n");
  const liveRules = (liveManaged ?? "").split("\n").filter((l) => l.trim() && !l.trim().startsWith("#")).join("\n");
  const managedRulesInSync = genRules === liveRules;
  // threshold: compare managed block content
  const genBlock = genThresholdBlock.split("\n").filter((l) => l.trim() && !l.trim().startsWith("#") && l !== MARKER_BEGIN && l !== MARKER_END).join("\n");
  let thresholdInSync = false;
  if (liveThreshold && liveThreshold.includes(MARKER_BEGIN)) {
    const liveBlock = liveThreshold
      .slice(liveThreshold.indexOf(MARKER_BEGIN), liveThreshold.indexOf(MARKER_END) + MARKER_END.length)
      .split("\n")
      .filter((l) => l.trim() && !l.trim().startsWith("#") && l !== MARKER_BEGIN && l !== MARKER_END)
      .join("\n");
    thresholdInSync = liveBlock === genBlock;
  } else {
    thresholdInSync = genBlock === "" && liveThreshold !== null;
  }
  const yamlInSync = !yamlNeedsManagedFile && !yamlNeedsThresholdFile;
  return { managedRulesInSync, thresholdInSync, yamlInSync, inSync: managedRulesInSync && thresholdInSync && yamlInSync };
}

// ── desired-state loader ────────────────────────────────────────────────────

/** Default policy = first enabled by id asc (ADR-017). */
export async function loadIpsGenInput(tenantId: number): Promise<{ input: IpsGenInput; enabledPolicyCount: number }> {
  const policies = await db.ipsPolicy.findMany({ where: { tenantId }, orderBy: { id: "asc" } });
  const enabled = policies.filter((p) => p.enabled);
  const parse = <T,>(raw: string, fb: T): T => {
    try {
      const v = JSON.parse(raw) as T;
      return v ?? fb;
    } catch {
      return fb;
    }
  };
  const first = enabled[0];
  const input: IpsGenInput = first
    ? {
        policy: {
          id: first.id,
          name: first.name,
          mode: first.mode,
          customRules: parse<string[]>(first.customRules, []),
          exceptions: parse<ExceptionRow[]>(first.exceptions, []),
          thresholds: parse<ThresholdRow[]>(first.thresholds, []),
        },
      }
    : { policy: null };
  return { input, enabledPolicyCount: enabled.length };
}

// ── OS reads ────────────────────────────────────────────────────────────────

async function readTextIfExists(file: string): Promise<string | null> {
  try {
    return await fs.readFile(file, "utf8");
  } catch {
    return null;
  }
}

export async function readIpsOsFacts(): Promise<IpsOsFacts> {
  const [serviceMap, versionRes, modeRes, updater, yamlText] = await Promise.all([
    readServiceStates(["suricata"]),
    runTool("suricata --build-info 2>/dev/null | head -1", 6000),
    runTool(`suricatasc -c "running-mode" 2>/dev/null`, 5000),
    hasTool("suricata-update"),
    readTextIfExists(SURICATA_YAML),
  ]);

  const rulesFiles: IpsOsFacts["rulesFiles"] = [];
  try {
    const entries = await fs.readdir(SURICATA_RULES_DIR);
    for (const name of entries.filter((n) => n.endsWith(".rules")).sort()) {
      const text = await readTextIfExists(path.join(SURICATA_RULES_DIR, name));
      if (text == null) continue;
      const c = countRulesInText(text);
      rulesFiles.push({ name, sids: c.sids, alert: c.alert, drop: c.drop, pass: c.pass, bytes: text.length });
    }
  } catch {
    // rules dir unreadable → empty list
  }

  const modeMsg = /"message"\s*:\s*"([^"]+)"/.exec(modeRes.stdout);
  const thresholdText = await readTextIfExists(THRESHOLD_FILE);
  let managedLines = 0;
  if (thresholdText) {
    const b = thresholdText.indexOf(MARKER_BEGIN);
    const e = thresholdText.indexOf(MARKER_END);
    if (b !== -1 && e > b) {
      managedLines = thresholdText
        .slice(b, e)
        .split("\n")
        .filter((l) => l.trim() && !l.trim().startsWith("#") && l !== MARKER_BEGIN).length;
    }
  }

  return {
    available: (serviceMap?.suricata ?? null) !== null,
    service: serviceMap?.suricata ?? null,
    version: versionRes.ok ? versionRes.stdout.trim() || null : null,
    runningMode: modeRes.ok && modeMsg ? modeMsg[1] : null,
    evePath: await detectSuricataEve(),
    rulesFiles,
    updaterInstalled: updater,
    yamlHasManagedFile: yamlText ? new RegExp(`^\\s*-\\s*${MANAGED_RULES_NAME}\\s*$`, "m").test(yamlText) : false,
    yamlHasThresholdFile: yamlText ? /^threshold-file:\s*\S+\s*$/m.test(yamlText) : false,
    thresholdManagedLines: managedLines,
  };
}

// ── plan ────────────────────────────────────────────────────────────────────

export async function buildIpsApplyPlan(tenantId: number): Promise<IpsApplyPlan> {
  const [{ input, enabledPolicyCount }, facts] = await Promise.all([loadIpsGenInput(tenantId), readIpsOsFacts()]);
  const generatedAt = new Date().toISOString();
  const managedRules = generateManagedRules(input, generatedAt);
  const thresholdBlock = generateThresholdBlock(input, generatedAt);
  const { warnings: thresholdWarnings } = buildThresholdEntries(input);

  const yamlText = await readTextIfExists(SURICATA_YAML);
  const yamlNeedsManagedFile = yamlText != null && !new RegExp(`^\\s*-\\s*${MANAGED_RULES_NAME}\\s*$`, "m").test(yamlText);
  const yamlNeedsThresholdFile = yamlText != null && !/^threshold-file:\s*\S+\s*$/m.test(yamlText);

  const [liveManaged, liveThreshold] = await Promise.all([readTextIfExists(MANAGED_RULES_FILE), readTextIfExists(THRESHOLD_FILE)]);
  const drift = computeIpsDrift(managedRules, liveManaged, thresholdBlock, liveThreshold, yamlNeedsManagedFile, yamlNeedsThresholdFile);

  const warnings: string[] = [...thresholdWarnings];
  if (enabledPolicyCount > 1) {
    warnings.push(
      `${enabledPolicyCount} enabled policies — the OS applies the default (first enabled by id): ${input.policy?.name ?? "—"}`,
    );
  }
  if (input.policy && input.policy.mode !== "passive" && facts.runningMode === "workers") {
    warnings.push(
      `policy mode "${input.policy.mode}" cannot be enforced inline — the appliance captures in passive AF_PACKET mode (workers); detection stays alert-only until inline capture (NFQ / af-packet pair) is wired`,
    );
  }
  if (!facts.updaterInstalled) {
    warnings.push("suricata-update not installed — ET rule refresh and category filtering of the vendor ruleset run console-side only");
  }
  if (!facts.yamlHasThresholdFile && yamlText != null) {
    warnings.push("suricata.yaml has no active threshold-file — suppress/threshold entries will be enabled by apply");
  }

  return {
    defaultPolicy: input.policy ? { id: input.policy.id, name: input.policy.name, mode: input.policy.mode } : null,
    enabledPolicyCount,
    managedRules,
    managedRuleCount: (input.policy?.customRules ?? []).filter((r) => r.trim()).length,
    thresholdBlock,
    thresholdEntryCount: buildThresholdEntries(input).lines.length,
    yamlNeedsManagedFile,
    yamlNeedsThresholdFile,
    drift,
    warnings,
    facts,
  };
}

// ── apply state ─────────────────────────────────────────────────────────────

export async function readIpsApplyState(): Promise<IpsApplyState | null> {
  try {
    const raw = await fs.readFile(path.join(IPS_DIR, "state.json"), "utf8");
    return JSON.parse(raw) as IpsApplyState;
  } catch {
    return null;
  }
}

async function writeIpsApplyState(state: IpsApplyState | null): Promise<void> {
  await fs.mkdir(IPS_DIR, { recursive: true });
  await fs.writeFile(path.join(IPS_DIR, "state.json"), JSON.stringify(state, null, 2), "utf8");
}

function newBackupDir(ts: string): string {
  return path.join(IPS_DIR, `backup-${ts}`);
}

async function backupFile(dir: string, file: string): Promise<boolean> {
  try {
    const text = await fs.readFile(file, "utf8");
    await fs.writeFile(path.join(dir, path.basename(file)), text, "utf8");
    return true;
  } catch {
    return false; // file may not exist yet — nothing to back up
  }
}

async function restoreFile(dir: string, file: string): Promise<boolean> {
  try {
    const text = await fs.readFile(path.join(dir, path.basename(file)), "utf8");
    await fs.writeFile(file, text, "utf8");
    return true;
  } catch {
    return false;
  }
}

/** Live reload of rules + threshold files (no packet loss, no service restart). */
async function reloadSuricata(): Promise<{ ok: boolean; detail: string }> {
  const viaRuleset = await runTool(`suricatasc -c "ruleset-reload-nonterminal" 2>&1`, 30_000);
  if (viaRuleset.ok && /OK/i.test(viaRuleset.stdout)) return { ok: true, detail: "ruleset-reload-nonterminal" };
  const viaReload = await runTool(`suricatasc -c "reload-rules" 2>&1`, 30_000);
  if (viaReload.ok && /OK/i.test(viaReload.stdout)) return { ok: true, detail: "reload-rules" };
  return { ok: false, detail: (viaRuleset.stderr || viaRuleset.stdout || viaReload.stderr || "reload failed").slice(0, 300) };
}

function tsSlug(): string {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

// ── apply / rollback ────────────────────────────────────────────────────────

export async function applyIpsOs(tenantId: number): Promise<IpsApplyOutcome> {
  const plan = await buildIpsApplyPlan(tenantId);
  const warnings = plan.warnings;

  if (process.env.CONSOLE_OS_APPLY !== "1") {
    return {
      applied: false,
      rolledBack: false,
      appliedAt: null,
      policyId: plan.defaultPolicy?.id ?? null,
      policyName: plan.defaultPolicy?.name ?? null,
      backupDir: null,
      validateOk: false,
      reloaded: false,
      warnings,
      detail: "OS apply gate is off (CONSOLE_OS_APPLY!=1) — plan-only preview",
    };
  }

  const ts = tsSlug();
  const backupDir = newBackupDir(ts);
  await fs.mkdir(backupDir, { recursive: true });
  await Promise.all([
    backupFile(backupDir, MANAGED_RULES_FILE),
    backupFile(backupDir, THRESHOLD_FILE),
    backupFile(backupDir, SURICATA_YAML),
  ]);

  const restoreAll = async (): Promise<void> => {
    await Promise.all([
      restoreFile(backupDir, MANAGED_RULES_FILE),
      restoreFile(backupDir, THRESHOLD_FILE),
      restoreFile(backupDir, SURICATA_YAML),
    ]);
  };

  // 1. write managed rules file
  await fs.mkdir(SURICATA_RULES_DIR, { recursive: true });
  await fs.writeFile(MANAGED_RULES_FILE, plan.managedRules, "utf8");

  // 2. rewrite threshold.config managed block
  const liveThreshold = await readTextIfExists(THRESHOLD_FILE);
  await fs.writeFile(THRESHOLD_FILE, replaceManagedBlock(liveThreshold ?? "", plan.thresholdBlock), "utf8");

  // 3. yaml surgery (rule-files + threshold-file), idempotent
  const yamlText = (await readTextIfExists(SURICATA_YAML)) ?? "";
  let yaml = yamlText;
  if (plan.yamlNeedsManagedFile) yaml = yamlAppendRuleFile(yaml, MANAGED_RULES_NAME).content;
  if (plan.yamlNeedsThresholdFile) yaml = yamlEnsureThresholdFile(yaml, THRESHOLD_FILE).content;
  if (yaml !== yamlText) await fs.writeFile(SURICATA_YAML, yaml, "utf8");

  // 4. validate with the engine test run — the exit code is the verdict
  //    (never text-matching: "0 rules failed" must not read as failure)
  const validate = await runTool(
    `out=$(mktemp); suricata -T -c ${JSON.stringify(SURICATA_YAML)} -v >"$out" 2>&1; rc=$?; tail -5 "$out"; rm -f "$out"; echo "SURICATA_T_EXIT:$rc"`,
    180_000,
  );
  const exitMatch = /SURICATA_T_EXIT:(\d+)/.exec(validate.stdout);
  const validateExit = exitMatch ? Number(exitMatch[1]) : validate.ok ? 0 : 1;
  if (validateExit !== 0) {
    await restoreAll();
    return {
      applied: false,
      rolledBack: true,
      appliedAt: null,
      policyId: plan.defaultPolicy?.id ?? null,
      policyName: plan.defaultPolicy?.name ?? null,
      backupDir,
      validateOk: false,
      reloaded: false,
      warnings,
      detail: `suricata -T validation failed (exit ${validateExit}) — files restored: ${(validate.stdout || validate.stderr || "no output").slice(0, 300)}`,
    };
  }

  // 5. live reload
  const reload = await reloadSuricata();
  if (!reload.ok) {
    await restoreAll();
    const afterRollback = await reloadSuricata();
    return {
      applied: false,
      rolledBack: true,
      appliedAt: null,
      policyId: plan.defaultPolicy?.id ?? null,
      policyName: plan.defaultPolicy?.name ?? null,
      backupDir,
      validateOk: true,
      reloaded: afterRollback.ok,
      warnings,
      detail: `reload failed (${reload.detail}) — previous files restored${afterRollback.ok ? " and reloaded" : " (reload pending)"}`,
    };
  }

  // 6. record state
  const state: IpsApplyState = {
    lastApplyAt: new Date().toISOString(),
    policyId: plan.defaultPolicy?.id ?? 0,
    policyName: plan.defaultPolicy?.name ?? "(none)",
    backupDir,
    validateOk: true,
    reloaded: true,
  };
  await writeIpsApplyState(state);
  await housekeepBackups();

  return {
    applied: true,
    rolledBack: false,
    appliedAt: state.lastApplyAt,
    policyId: plan.defaultPolicy?.id ?? null,
    policyName: plan.defaultPolicy?.name ?? null,
    backupDir,
    validateOk: true,
    reloaded: true,
    warnings,
    detail: `managed rules (${plan.managedRuleCount}) + ${plan.thresholdEntryCount} threshold entries applied to ${MANAGED_RULES_NAME} / threshold.config; engine reloaded via ${reload.detail}`,
  };
}

export async function rollbackIpsOs(): Promise<{ rolledBack: boolean; backupDir: string | null; reloaded: boolean; detail: string }> {
  const state = await readIpsApplyState();
  const dir = state?.backupDir ?? (await newestBackupDir());
  if (!dir) return { rolledBack: false, backupDir: null, reloaded: false, detail: "no backup available to roll back" };

  const results = await Promise.all([
    restoreFile(dir, MANAGED_RULES_FILE),
    restoreFile(dir, THRESHOLD_FILE),
    restoreFile(dir, SURICATA_YAML),
  ]);
  const restored = results.filter(Boolean).length;
  const reload = await reloadSuricata();
  return {
    rolledBack: restored > 0,
    backupDir: dir,
    reloaded: reload.ok,
    detail: `restored ${restored} file(s) from ${path.basename(dir)}${reload.ok ? `; reloaded (${reload.detail})` : `; reload failed (${reload.detail})`}`,
  };
}

async function newestBackupDir(): Promise<string | null> {
  try {
    const entries = await fs.readdir(IPS_DIR);
    const backups = entries.filter((e) => e.startsWith("backup-")).sort();
    return backups.length ? path.join(IPS_DIR, backups[backups.length - 1]) : null;
  } catch {
    return null;
  }
}

async function housekeepBackups(): Promise<void> {
  await runTool(`find ${JSON.stringify(IPS_DIR)} -maxdepth 1 -type d -name "backup-*" -mtime +7 -exec rm -rf {} + 2>/dev/null`, 5000);
}

// ── real rule update (suricata-update) ─────────────────────────────────────

/**
 * Run a real ET ruleset refresh on the appliance when suricata-update is
 * available and the OS apply gate is on; then live-reload the engine.
 * Everywhere else this is a no-op with an honest note (the schedule
 * bookkeeping in lib/ips/service.ts still applies).
 */
export async function runOsRuleUpdate(): Promise<OsRuleUpdateResult> {
  if (process.env.CONSOLE_OS_APPLY !== "1") {
    return { ranOnOs: false, reloaded: false, note: "OS apply gate off (CONSOLE_OS_APPLY!=1) — schedule kept, engine untouched", outputTail: null };
  }
  if (!(await hasTool("suricata-update"))) {
    return { ranOnOs: false, reloaded: false, note: "suricata-update not installed on this host — install it to enable live ET refresh", outputTail: null };
  }
  const res = await runTool(`suricata-update 2>&1 | tail -8`, 300_000);
  if (!res.ok) {
    return { ranOnOs: false, reloaded: false, note: `suricata-update failed: ${(res.stderr || res.error || "unknown").slice(0, 200)}`, outputTail: res.stdout.slice(-500) || null };
  }
  const reload = await reloadSuricata();
  return {
    ranOnOs: true,
    reloaded: reload.ok,
    note: reload.ok
      ? "suricata-update finished and the engine reloaded the refreshed ruleset"
      : `suricata-update finished but reload failed (${reload.detail})`,
    outputTail: res.stdout.slice(-500) || null,
  };
}
