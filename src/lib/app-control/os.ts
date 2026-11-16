/**
 * app-control/os — PURE app-control → nftables generator.
 *
 * Translates the GUI app-control model (policies, per-app nDPI rules) into an
 * nftables source file for the DEDICATED `inet utm_appctl` table. Pure module:
 * no db, no exec — fully unit-tested. Execution lives in os-service.ts, the
 * API surface in /api/v1/app-control/os.
 *
 * Design contract (copies firewall nft-gen semantics exactly):
 *
 *  • ISOLATION — the generator NEVER emits `flush ruleset`. Only
 *    `destroy table inet utm_appctl` is used (atomic delete-if-exists +
 *    recreate). Other tables (`inet console-firewall`, fail2ban, foreign
 *    rulesets) survive every apply untouched.
 *  • MANAGEMENT PLANE IS SACRED — the chain policy is ALWAYS accept and the
 *    chain only ever matches explicit app port classes. Unmatched traffic is
 *    NEVER dropped by this table (no catch-all verdict of any kind).
 *  • STRICT UNDER-MATCHING (firewall convention) — only port-identifiable
 *    apps reach the kernel. DPI-only apps (netflix, tiktok, instagram,
 *    facebook, spotify, youtube, github, gitlab, docker-registry — content
 *    and code hosting ride tcp/443 + QUIC shared with general HTTPS…) have
 *    no stable L4 signature: a port approximation would over-block collateral
 *    traffic, so the rule is EXCLUDED with a loud warning
 *    ("DPI-required — port approximation would over-block; rule skipped").
 *    Never silently pretend enforcement.
 *  • DIRECTION — upload → `tcp sport <ports>`, download → `tcp dport`,
 *    both → two statements (nft cannot OR sport/dport in one rule).
 *  • `limit` is counter-only at this layer (tc/HTB owns shaping) →
 *    `counter accept` + `:limit` comment suffix + warning (v1).
 *  • user-group scoping is an L7-engine concept: nftables cannot match
 *    users without session IPs, so a scoped rule still enforces its port
 *    class for ALL sources with an explicit warning (honest v1 semantics).
 *  • defaultAction=block does NOT install a default drop — that would need a
 *    full allowlist and break the appliance. It is surfaced as a terminal
 *    policy warning instead ("enforced only for port-identifiable apps (v1)").
 *    unknownAppAction=block is likewise comment+warning only.
 *  • Counters — every statement carries `counter` and a
 *    `appctl:<ruleId>:<name>` comment so the live dump is parseable back to
 *    DB rule ids (parseAppctlRuleCounters → hitCount sync).
 *  • First-match-wins — statements render in (policyId, ruleId) order; nft
 *    terminates on the first matching verdict, so an earlier allow shields a
 *    later drop for the same ports.
 */

import { APP_CATALOG } from "@/app/api/v1/app-control/catalog";

// ── constants ───────────────────────────────────────────────────────────────

export const APPCTL_TABLE_NAME = "utm_appctl";
export const APPCTL_TABLE = `inet ${APPCTL_TABLE_NAME}`;
export const APPCTL_CHAIN = "appctl_filter";
/** Runs BEFORE the console-firewall filter chain (priority filter = 0). */
export const APPCTL_PRIORITY = -10;

export const BACKUP_PROLOGUE = "#!/usr/sbin/nft -f\nflush ruleset\n";

// ── APP_PORT_MAP — the honest 26-app catalog → L4 tuples ────────────────────

export interface PortRange {
  lo: number;
  hi: number;
}

export interface AppPortEntry {
  proto: "tcp" | "udp";
  ports: PortRange[];
  /** collateral-risk note surfaced as a `port-shared` warning when rendered */
  note?: string;
}

/**
 * Port-identifiable catalog apps ONLY (strict under-match convention).
 * Everything in the 26-app catalog WITHOUT an entry here is DPI-required and
 * is excluded from kernel enforcement with a `dpi-required` warning —
 * including github/gitlab/docker-registry: their traffic rides tcp/443 which
 * is shared with general HTTPS, so a port class would over-block.
 *
 * Sources: IANA/well-known registrations, widely documented and stable.
 * Invented/elastic ranges (zoom 8801, epicgames, teams, slack…) are
 * deliberately NOT included — "if unsure → skip + warning".
 */
export const APP_PORT_MAP: Record<string, AppPortEntry[]> = {
  ssh: [{ proto: "tcp", ports: [{ lo: 22, hi: 22 }] }],
  rdp: [{ proto: "tcp", ports: [{ lo: 3389, hi: 3389 }] }],
  vnc: [{ proto: "tcp", ports: [{ lo: 5900, hi: 5902 }] }],
  teamviewer: [
    { proto: "tcp", ports: [{ lo: 5938, hi: 5938 }] },
    { proto: "udp", ports: [{ lo: 5938, hi: 5938 }] },
  ],
  bittorrent: [
    { proto: "tcp", ports: [{ lo: 6881, hi: 6889 }] },
    { proto: "udp", ports: [{ lo: 6881, hi: 6889 }] },
  ],
};

/** Catalog apps with no port mapping — DPI-required, never port-approximated. */
export const DPI_ONLY_APPS: string[] = APP_CATALOG.map((a) => a.name).filter((n) => !APP_PORT_MAP[n]);

/**
 * Guard for the strict under-match contract: the port map may never grow an
 * entry outside the reviewed, widely-documented set. A future catalog app
 * needs an explicit addition here AND a unit-test line.
 */
const PORT_IDENTIFIABLE_ALLOWLIST = new Set(["ssh", "rdp", "vnc", "teamviewer", "bittorrent"]);
export function isPortIdentifiableApp(appName: string): boolean {
  return PORT_IDENTIFIABLE_ALLOWLIST.has(appName.trim().toLowerCase());
}

/** "ports" (enforceable) or "dpi-only" (skipped with warning) for a label. */
export function appPortClass(appName: string): "ports" | "dpi-only" {
  return APP_PORT_MAP[appName.trim().toLowerCase()] ? "ports" : "dpi-only";
}

/** Human reason a label is DPI-only (report/UI table). */
export function dpiOnlyReason(appName: string): string {
  void appName;
  return "content rides tcp/443 + QUIC with no stable L4 signature — port approximation would over-block collateral traffic";
}

// ── input model ─────────────────────────────────────────────────────────────

export interface AppCtlRuleShape {
  id: number;
  appName: string;
  action: "allow" | "block" | "limit";
  bandwidthLimitMbps: number | null;
  direction: "both" | "upload" | "download";
  userGroupIds: number[];
  enabled: boolean;
}

export interface AppCtlPolicyShape {
  id: number;
  name: string;
  defaultAction: "allow" | "block";
  unknownAppAction: "allow" | "block" | "log";
  enabled: boolean;
  rules: AppCtlRuleShape[];
}

export interface AppctlGenWarning {
  scope: "rule" | "policy";
  policyId: number;
  ruleId: number | null;
  /** rule appName (scope rule) or policy name (scope policy) */
  name: string;
  code: string;
  message: string;
}

export interface AppctlCounts {
  /** enabled policies considered */
  policies: number;
  /** enabled rules considered */
  rules: number;
  /** nft statements rendered into the chain */
  statements: number;
  /** rules excluded from enforcement (DPI-only) */
  skipped: number;
}

export interface AppctlGenResult {
  /** complete nft source file (apply with `nft -f`) */
  file: string;
  counts: AppctlCounts;
  /** the rendered chain statements, in order (plan/preview visibility) */
  statements: string[];
  warnings: AppctlGenWarning[];
  /** DPI-only app labels that had rules skipped */
  skippedApps: string[];
}

// ── validation / fragment helpers ───────────────────────────────────────────

/** Same sanitize contract as firewall nft-gen (comment-safe subset). */
export function sanitizeComment(raw: string, maxLen = 40): string {
  const cleaned = raw.replace(/[^A-Za-z0-9._@:+-]/g, "-").replace(/^-+|-+$/g, "");
  return cleaned.slice(0, Math.max(1, maxLen));
}

/** Validated port ranges → nft fragment: `22` / `6881-6889` / `{ 22, 6881-6889 }`. */
function portSet(ranges: PortRange[]): string | null {
  const ok = ranges.filter((r) => Number.isInteger(r.lo) && Number.isInteger(r.hi) && r.lo >= 1 && r.hi <= 65535 && r.lo <= r.hi);
  if (ok.length !== ranges.length || ok.length === 0) return null;
  const items = ok.map((r) => (r.lo === r.hi ? `${r.lo}` : `${r.lo}-${r.hi}`));
  return items.length === 1 ? items[0] : `{ ${items.join(", ")} }`;
}

// ── generator ───────────────────────────────────────────────────────────────

const INDENT = "\t\t";
const CHAIN_INDENT = "\t";

/**
 * Generate the complete nft source file for `table inet utm_appctl`.
 * Idempotent: apply twice → identical kernel state (atomic destroy+recreate).
 * Deterministic: same input + generatedAt → byte-identical file.
 */
export function generateAppctlRuleset(input: { policies: AppCtlPolicyShape[]; generatedAt?: Date }): AppctlGenResult {
  const warnings: AppctlGenWarning[] = [];
  const statements: string[] = [];
  const skippedApps = new Set<string>();
  let policiesCount = 0;
  let rulesCount = 0;
  let skipped = 0;

  const ordered = [...input.policies].filter((p) => p.enabled).sort((a, b) => a.id - b.id);

  for (const policy of ordered) {
    policiesCount += 1;

    // policy-level honesty: these two knobs have NO port-layer equivalent —
    // surface them loudly, NEVER install a catch-all drop for them
    if (policy.unknownAppAction === "block") {
      warnings.push({
        scope: "policy",
        policyId: policy.id,
        ruleId: null,
        name: policy.name,
        code: "unknown-app-block-unenforceable",
        message:
          "unknownAppAction=block cannot be enforced at the port layer — unknown apps have no port class and no catch-all drop is emitted (it would break the appliance)",
      });
    }
    if (policy.defaultAction === "block") {
      warnings.push({
        scope: "policy",
        policyId: policy.id,
        ruleId: null,
        name: policy.name,
        code: "default-block-partial",
        message:
          "defaultAction=block enforced only for port-identifiable apps (v1) — unmatched traffic is never dropped by this table",
      });
    }

    for (const rule of [...policy.rules].filter((r) => r.enabled).sort((a, b) => a.id - b.id)) {
      rulesCount += 1;

      // WHITELIST GUARD + strict under-match: only the reviewed allowlist may
      // reach the kernel — no map entry, no kernel rule, loud warning
      const l4 = isPortIdentifiableApp(rule.appName) ? APP_PORT_MAP[rule.appName] : undefined;
      if (!l4) {
        skipped += 1;
        skippedApps.add(rule.appName);
        warnings.push({
          scope: "rule",
          policyId: policy.id,
          ruleId: rule.id,
          name: rule.appName,
          code: "dpi-required",
          message: `app '${rule.appName}': DPI-required — port approximation would over-block; rule skipped`,
        });
        continue;
      }

      // user-group scoping is L7-engine territory — ports apply to all sources
      if (rule.userGroupIds.length > 0) {
        warnings.push({
          scope: "rule",
          policyId: policy.id,
          ruleId: rule.id,
          name: rule.appName,
          code: "user-group-scope-l7",
          message: `app '${rule.appName}': user-group scoping applied at L7 engine — port class applies to all sources (v1)`,
        });
      }

      let verdict: string;
      let commentSuffix = "";
      if (rule.action === "block") {
        verdict = "drop";
      } else {
        verdict = "accept";
        if (rule.action === "limit") {
          commentSuffix = ":limit";
          warnings.push({
            scope: "rule",
            policyId: policy.id,
            ruleId: rule.id,
            name: rule.appName,
            code: "limit-tc-required",
            message: `app '${rule.appName}': limit action requires tc/HTB — counter-only at nft layer (v1)`,
          });
        }
      }

      const comment = `appctl:${rule.id}:${sanitizeComment(rule.appName, 32)}${commentSuffix}`;
      const dirs: Array<"sport" | "dport"> =
        rule.direction === "upload" ? ["sport"] : rule.direction === "download" ? ["dport"] : ["sport", "dport"];

      for (const entry of l4) {
        if (entry.note) {
          warnings.push({
            scope: "rule",
            policyId: policy.id,
            ruleId: rule.id,
            name: rule.appName,
            code: "port-shared",
            message: `app '${rule.appName}': ${entry.note}`,
          });
        }
        const set = portSet(entry.ports);
        if (!set) {
          skipped += 1;
          warnings.push({
            scope: "rule",
            policyId: policy.id,
            ruleId: rule.id,
            name: rule.appName,
            code: "port-invalid",
            message: `app '${rule.appName}': invalid port range in the port map — tuple skipped (generator bug, please report)`,
          });
          continue;
        }
        for (const dir of dirs) {
          // `meta l4proto X X <dir> …` — redundant but explicit inet-table idiom
          statements.push(`meta l4proto ${entry.proto} ${entry.proto} ${dir} ${set} counter ${verdict} comment ${JSON.stringify(comment)}`);
        }
      }
    }
  }

  const genAt = (input.generatedAt ?? new Date()).toISOString();
  const lines: string[] = [
    "#!/usr/sbin/nft -f",
    `# utm_appctl — managed by the UTM console (GUI: App Control → Apply to Host)`,
    `# generated: ${genAt}`,
    "#",
    "# Atomic replace of the console-managed table ONLY — never flushes the",
    "# entire ruleset: fail2ban tables, inet console-firewall and any foreign",
    "# rulesets survive every apply. Chain policy is permanently accept — this",
    "# table ONLY matches its own app port classes (strict under-match);",
    "# unmatched traffic is never dropped here.",
    "",
    `destroy table inet ${APPCTL_TABLE_NAME}`,
    "",
    `table inet ${APPCTL_TABLE_NAME} {`,
    `  chain ${APPCTL_CHAIN} {`,
    `${CHAIN_INDENT}type filter hook forward priority ${APPCTL_PRIORITY}; policy accept;`,
    ...statements.map((l) => `${INDENT}${l}`),
    `  }`,
    `}`,
    "",
  ];

  return {
    file: lines.join("\n"),
    counts: { policies: policiesCount, rules: rulesCount, statements: statements.length, skipped },
    statements,
    warnings,
    skippedApps: [...skippedApps].sort(),
  };
}

// ── drift / status parsers (pure) ───────────────────────────────────────────

/** Lines of the utm_appctl table block: comments/counters stripped, whitespace normalized. */
export function extractAppctlTableBlock(source: string): string[] {
  const lines: string[] = [];
  let inside = false;
  let depth = 0;
  for (const raw of source.split("\n")) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!inside) {
      if (new RegExp(`^table inet ${APPCTL_TABLE_NAME}\\s*\\{`).test(line)) {
        inside = true;
        depth = 1;
      }
      continue;
    }
    depth += (line.match(/\{/g) ?? []).length - (line.match(/\}/g) ?? []).length;
    if (depth <= 0) break;
    const norm = line
      .replace(/counter packets \d+ bytes \d+/g, "")
      // kernel dumps render generated `counter drop` as `counter packets 0 bytes 0 drop`
      // — collapse the bare counter token before a verdict on BOTH sides so the
      // normalized compare sees identical statements
      .replace(/\bcounter\s+(?=(?:drop|accept|reject|continue|return)\b)/g, "")
      .replace(/comment "[^"]*"/g, "")
      .replace(/\s+/g, " ")
      .trim();
    if (norm) lines.push(norm);
  }
  return lines;
}

/** Pure compare of generated vs live table bodies (unit-testable). */
export function appctlTableBlocksInSync(genFile: string, liveDump: string): boolean {
  const a = extractAppctlTableBlock(genFile);
  const b = extractAppctlTableBlock(liveDump);
  if (b.length === 0) return false;
  return a.length === b.length && a.every((l, i) => l === b[i]);
}

export interface AppctlCounter {
  ruleId: number;
  appName: string;
  packets: number;
  bytes: number;
}

/**
 * Parse `appctl:<ruleId>:<name>` comment counters from a live dump.
 * Multiple statements share one comment (sport+dport) — packets/bytes sum.
 */
export function parseAppctlRuleCounters(liveDump: string): AppctlCounter[] {
  const byId = new Map<number, AppctlCounter>();
  const counterRe = /counter packets (\d+) bytes (\d+)/g;
  const commentRe = /comment "appctl:(\d+):([^"]*)"/;
  for (const line of liveDump.split("\n")) {
    if (!/^\s+/.test(line)) continue;
    const cm = commentRe.exec(line);
    if (!cm) continue;
    const id = Number(cm[1]);
    counterRe.lastIndex = 0;
    let packets = 0;
    let bytes = 0;
    let m: RegExpExecArray | null;
    while ((m = counterRe.exec(line)) !== null) {
      packets += Number(m[1]);
      bytes += Number(m[2]);
    }
    const prev = byId.get(id);
    if (prev) {
      prev.packets += packets;
      prev.bytes += bytes;
    } else {
      byId.set(id, { ruleId: id, appName: cm[2], packets, bytes });
    }
  }
  return [...byId.values()].sort((a, b) => a.ruleId - b.ruleId);
}

// ── restore-point + exec whitelist guards ───────────────────────────────────

/**
 * Compose the full-ruleset backup file: `flush ruleset` prologue + live dump.
 * The prologue is MANDATORY — a restore file without it would merge instead
 * of restore and leave stale appctl rules in the kernel.
 */
export function composeBackupFile(liveRuleset: string): string {
  const body = liveRuleset.trim().length > 0 ? liveRuleset : "# empty ruleset at backup time";
  return `${BACKUP_PROLOGUE}\n${body}\n`;
}

/** A file is a faithful restore point ONLY when it carries the flush prologue. */
export function isRestoreFileContent(content: string): boolean {
  return content.startsWith(BACKUP_PROLOGUE);
}

/**
 * Command whitelist — the apply route aborts ANY step failing this guard.
 * Exact nft read/write forms, the detached rollback-timer arm, and the
 * persistence enable. Nothing else ever executes from this module.
 */
const NFT_CHECK_RE = /^nft -c -f "[^"]+"$/;
const NFT_APPLY_RE = /^nft -f "[^"]+"$/;
const NFT_ARM_RE = /^nohup \/bin\/sh "[^"]+" >\/dev\/null 2>&1 &$/;
const NFT_READ_RE = /^nft list (ruleset|table inet utm_appctl)( 2>\/dev\/null)?$/;
const NFT_VERSION_RE = /^nft --version$/;
const NFT_ENABLE_RE = /^systemctl enable nftables( >\/dev\/null 2>&1)?$/;

export function appctlStepGuarded(cmd: string): boolean {
  return (
    NFT_CHECK_RE.test(cmd) ||
    NFT_APPLY_RE.test(cmd) ||
    NFT_ARM_RE.test(cmd) ||
    NFT_READ_RE.test(cmd) ||
    NFT_VERSION_RE.test(cmd) ||
    NFT_ENABLE_RE.test(cmd)
  );
}

// ── apply plan (pure) ───────────────────────────────────────────────────────

export type AppctlPlanStepKind = "check" | "arm" | "apply" | "restore" | "persist";

export interface AppctlPlanStep {
  step: string;
  kind: AppctlPlanStepKind;
  /** exact exec command — every one passes appctlStepGuarded */
  cmd: string;
}

export interface AppctlRollbackScriptInput {
  ts: string;
  confirmSec: number;
  confirmFile: string;
  backupFile: string;
  scriptFile: string;
  stateFile: string;
}

/** Detached commit-confirm rollback timer (survives console restarts). */
export function buildAppctlRollbackScript(input: AppctlRollbackScriptInput): string {
  return [
    "#!/bin/sh",
    `# utm_appctl commit-confirm rollback armed ${input.ts}`,
    `sleep ${input.confirmSec}`,
    `if [ -f ${JSON.stringify(input.confirmFile)} ]; then exit 0; fi`,
    `/usr/sbin/nft -f ${JSON.stringify(input.backupFile)}`,
    `rm -f ${JSON.stringify(input.scriptFile)}`,
    `# clear the pending window if it still belongs to THIS apply (a newer`,
    `# apply supersedes it and owns the file — never touch that one)`,
    `if grep -qF ${JSON.stringify(`"ts": "${input.ts}"`)} ${JSON.stringify(input.stateFile)} 2>/dev/null; then rm -f ${JSON.stringify(input.stateFile)}; fi`,
  ].join("\n");
}

/**
 * Ordered exec plan for the apply pipeline. Paths are resolved by os-service;
 * every emitted cmd passes appctlStepGuarded (unit-test enforced).
 */
export function buildAppctlApplySteps(input: { file: string; backupFile: string; rollbackScript: string }): AppctlPlanStep[] {
  return [
    { step: "nft -c check", kind: "check", cmd: `nft -c -f ${JSON.stringify(input.file)}` },
    { step: "rollback timer", kind: "arm", cmd: `nohup /bin/sh ${JSON.stringify(input.rollbackScript)} >/dev/null 2>&1 &` },
    { step: "apply", kind: "apply", cmd: `nft -f ${JSON.stringify(input.file)}` },
    { step: "restore backup", kind: "restore", cmd: `nft -f ${JSON.stringify(input.backupFile)}` },
    { step: "systemctl enable nftables", kind: "persist", cmd: "systemctl enable nftables >/dev/null 2>&1" },
  ];
}
