/**
 * threat-intel/os — PURE threat-intel auto-block → nftables generator.
 *
 * Translates the GUI auto-block model (spec §2.11 "Auto-block malicious IPs
 * (feed → firewall)") into an nftables source file for the DEDICATED
 * `inet utm_ti_block` table. Pure module: no db, no exec — fully
 * unit-tested. Execution lives in os-service.ts, the API surface in
 * /api/v1/threat-intel/os.
 *
 * Design contract (mirrors app-control/os.ts + firewall nft-gen semantics):
 *
 *  • ISOLATION — the generator NEVER emits `flush ruleset`. Only
 *    `destroy table inet utm_ti_block` is used (atomic delete-if-exists +
 *    recreate). Other tables (`inet console-firewall`, `inet utm_appctl`,
 *    fail2ban, foreign rulesets) survive every apply untouched.
 *  • NO CATCH-ALL DROP — both chain policies are permanently accept. The
 *    table only ever drops packets whose source/destination address is an
 *    element of the `ti_block_v4` interval set. Unmatched traffic is never
 *    dropped here.
 *  • SET-BASED BLACKHOLE — one `set ti_block_v4 { type ipv4_addr; flags
 *    interval; auto-merge }` populated from enabled auto-block rules with
 *    action=block. Overlapping/adjacent CIDRs need no dedup (interval set +
 *    auto-merge coalesce them kernel-side); EXACT duplicate values are
 *    collapsed renderer-side with a warning (older nft rejects identical
 *    elements in one transaction).
 *  • TWO CHAINS, ONE SET — `prerouting` (hook priority -105, before dstnat)
 *    drops `ip saddr @ti_block_v4`, `postrouting` (priority -105) drops
 *    `ip daddr @ti_block_v4`. Both rules carry an anonymous counter for
 *    read-back (drop counters). A single shared set cannot scope per-rule
 *    direction, so direction=in|out rules get an explicit
 *    `direction-unscoped` warning (the element blocks BOTH directions —
 *    strict blackhole semantics, never silently widened).
 *  • L3-ONLY HONESTY — only matchType ip|cidr with a VALID host-bits-zero
 *    IPv4 address/CIDR reaches the kernel. domain/url/hash rules are L7
 *    (DNS/proxy layer) and are EXCLUDED with a loud warning; IPv6 values
 *    are warned (ipv6-not-rendered — this table is v4-only) and skipped;
 *    action=reject|quarantine_vlan has no prerouting/postrouting nft
 *    equivalent and stays config-only with a warning. Never silently
 *    pretend enforcement.
 *  • KERNEL-ENFORCEABLE ACTION — action=drop (the DB/validator enum is
 *    drop|reject|quarantine_vlan) is the blackhole verdict; the spec's
 *    "action=block" phrasing is accepted as an alias for the same verdict.
 *    Everything else stays config-only with a loud warning.
 *  • ATTRIBUTION — every element carries `counter` and a
 *    `ti:<ruleId>:<name>` comment so the live dump is parseable back to DB
 *    rule ids (parseTiElements → hitCount sync; per-element counters are
 *    kernel ≥5.6 stateful objects, Debian 13 ships ≥6.x).
 *  • DETERMINISM — same rules + generatedAt → byte-identical file. The
 *    confHash is computed over the comment-stripped canonical body, so it
 *    is STABLE across renders with different `# generated:` timestamps
 *    (state.json drift compare stays meaningful).
 *  • Elements are sorted by numeric start address — interval sets dump
 *    sorted kernel-side; the generated order matches.
 */

import { createHash } from "crypto";

// ── constants ───────────────────────────────────────────────────────────────

export const TI_TABLE_NAME = "utm_ti_block";
export const TI_TABLE = `inet ${TI_TABLE_NAME}`;
export const TI_SET_NAME = "ti_block_v4";
export const TI_PREROUTING_CHAIN = "prerouting";
export const TI_POSTROUTING_CHAIN = "postrouting";
/** Runs BEFORE dstnat (-100) and the console-firewall filter chain (0). */
export const TI_PRIORITY = -105;
/** Element comment prefix — `ti:<ruleId>:<name>` (parseable attribution). */
export const TI_COMMENT_PREFIX = "ti:";
/** Snapshot directory-name pattern inside the threat-intel state dir. */
export const TI_DIR_NAME_BACKUP_RE = /^backup-[\w.-]+$/;

/** Full-ruleset backup prologue — MANDATORY for a faithful restore point. */
export const BACKUP_PROLOGUE = "#!/usr/sbin/nft -f\nflush ruleset\n";

// ── input model (mirrors the Prisma AutoBlockRule rows) ─────────────────────

export interface TiBlockRuleShape {
  id: number;
  name: string;
  matchType: string; // ip | cidr | domain | url | hash
  matchValue: string;
  action: string; // drop | reject | quarantine_vlan
  direction: string; // in | out | both
  enabled: boolean;
}

export interface TiGenWarning {
  scope: "rule" | "table";
  ruleId: number | null;
  name: string;
  code: string;
  message: string;
}

export interface TiGenCounts {
  /** enabled auto-block rules considered */
  rules: number;
  /** rendered set elements (attributable rules) */
  elements: number;
  /** rules excluded from the set (l7, ipv6, invalid, non-block, duplicates) */
  skipped: number;
  /** chains rendered (prerouting + postrouting, always both) */
  chains: number;
}

export interface TiGenResult {
  /** complete nft source file (apply with `nft -f`) */
  file: string;
  /** sha256 hex over the comment-stripped canonical body (timestamp-stable) */
  confHash: string;
  counts: TiGenCounts;
  /** rendered element specs, kernel-sorted (numeric start address) */
  elements: string[];
  /** the rendered chain statements, in order (plan/preview visibility) */
  statements: string[];
  warnings: TiGenWarning[];
}

// ── validation / fragment helpers ───────────────────────────────────────────

/** Same sanitize contract as firewall nft-gen (comment-safe subset). */
export function sanitizeComment(raw: string, maxLen = 40): string {
  const cleaned = raw.replace(/[^A-Za-z0-9._@:+-]/g, "-").replace(/^-+|-+$/g, "");
  return cleaned.slice(0, Math.max(1, maxLen));
}

export type ParsedIpv4 =
  | { ok: true; /** canonical nft text (bare host or prefix-aligned CIDR) */ text: string; /** numeric start address for kernel-order sorting */ num: number }
  | { ok: false; reason: "ipv6" | "malformed" | "cidr-host-bits" };

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/(\d{1,2}))?$/;

/** Numeric value of a dotted-quad IPv4 address (for kernel-order sorting). */
function ipv4ToNum(a: number, b: number, c: number, d: number): number {
  return ((a << 24) >>> 0) + (b << 16) + (c << 8) + d;
}

/**
 * Strict IPv4 / CIDR element validation. Accepts bare hosts and
 * host-bits-zero CIDRs (kernel interval sets reject `1.2.3.1/24`); `/32`
 * normalizes to a bare host (kernel dump form). IPv6 (any `:`) is reported
 * as reason "ipv6" so the caller can warn-not-fail.
 */
export function parseIpv4Element(raw: string): ParsedIpv4 {
  const value = raw.trim();
  if (value.includes(":")) return { ok: false, reason: "ipv6" };
  const m = IPV4_RE.exec(value);
  if (!m) return { ok: false, reason: "malformed" };
  const octets = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  if (octets.some((o) => o > 255)) return { ok: false, reason: "malformed" };
  const prefix = m[6] !== undefined ? Number(m[6]) : null;
  if (prefix !== null && prefix > 32) return { ok: false, reason: "malformed" };
  const num = ipv4ToNum(octets[0], octets[1], octets[2], octets[3]);
  if (prefix === null || prefix === 32) {
    return { ok: true, text: octets.join("."), num };
  }
  // host bits must be zero for an interval-set CIDR element
  const hostBits = 32 - prefix;
  const hostMask = hostBits >= 32 ? 0xffffffff : ((1 << hostBits) - 1);
  if ((num & hostMask) !== 0) {
    return { ok: false, reason: "cidr-host-bits" };
  }
  return { ok: true, text: `${octets.join(".")}/${prefix}`, num };
}

// ── generator ───────────────────────────────────────────────────────────────

/**
 * Generate the complete nft source file for `table inet utm_ti_block`.
 * Idempotent: apply twice → identical kernel state (atomic destroy +
 * recreate). Deterministic: same input + generatedAt → byte-identical file,
 * identical confHash.
 */
export function generateTiBlockRuleset(input: { rules: TiBlockRuleShape[]; generatedAt?: Date }): TiGenResult {
  const warnings: TiGenWarning[] = [];
  const statements = [
    `ip saddr @${TI_SET_NAME} counter drop`,
    `ip daddr @${TI_SET_NAME} counter drop`,
  ];

  let rulesCount = 0;
  let skipped = 0;

  /** exact-duplicate guard: canonical text → owning rule id */
  const seen = new Map<string, number>();
  /** { num, text, spec } — sorted kernel-side by numeric start address */
  const rendered: Array<{ num: number; text: string; spec: string }> = [];

  for (const rule of [...input.rules].filter((r) => r.enabled).sort((a, b) => a.id - b.id)) {
    rulesCount += 1;

    // kernel-enforceable verdict: drop ("block" is the spec alias for it);
    // reject/quarantine_vlan have no prerouting/postrouting equivalent
    if (rule.action !== "drop" && rule.action !== "block") {
      skipped += 1;
      warnings.push({
        scope: "rule",
        ruleId: rule.id,
        name: rule.name,
        code: "action-not-kernel-enforceable",
        message: `rule '${rule.name}': action=${rule.action} has no prerouting/postrouting nftables equivalent (reject needs a route lookup verdict, quarantine_vlan is an L2 switch operation) — rule stays config-only`,
      });
      continue;
    }

    if (rule.matchType !== "ip" && rule.matchType !== "cidr") {
      skipped += 1;
      warnings.push({
        scope: "rule",
        ruleId: rule.id,
        name: rule.name,
        code: "l7-not-l3-enforceable",
        message: `rule '${rule.name}': matchType=${rule.matchType} is an L7 indicator (DNS/proxy layer) — nftables cannot match it, rule stays config-only`,
      });
      continue;
    }

    const parsed = parseIpv4Element(rule.matchValue);
    if (!parsed.ok) {
      skipped += 1;
      if (parsed.reason === "ipv6") {
        warnings.push({
          scope: "rule",
          ruleId: rule.id,
          name: rule.name,
          code: "ipv6-not-rendered",
          message: `rule '${rule.name}': ${rule.matchValue} is IPv6 — utm_ti_block renders v4 only (ipv6 blackhole is a future table); rule skipped from this fragment`,
        });
      } else if (parsed.reason === "cidr-host-bits") {
        warnings.push({
          scope: "rule",
          ruleId: rule.id,
          name: rule.name,
          code: "invalid-cidr",
          message: `rule '${rule.name}': ${rule.matchValue} has host bits set inside its prefix — nftables interval sets reject it, rule skipped`,
        });
      } else {
        warnings.push({
          scope: "rule",
          ruleId: rule.id,
          name: rule.name,
          code: "invalid-address",
          message: `rule '${rule.name}': '${rule.matchValue}' is not a valid IPv4 address or CIDR — rule skipped`,
        });
      }
      continue;
    }

    if (parsed.text === "0.0.0.0/0") {
      warnings.push({
        scope: "rule",
        ruleId: rule.id,
        name: rule.name,
        code: "default-route-element",
        message: `rule '${rule.name}': 0.0.0.0/0 in the blocklist drops ALL traffic in both directions — double-check the rule value`,
      });
    }

    const prior = seen.get(parsed.text);
    if (prior !== undefined) {
      skipped += 1;
      warnings.push({
        scope: "rule",
        ruleId: rule.id,
        name: rule.name,
        code: "duplicate-element",
        message: `rule '${rule.name}': ${parsed.text} is already in the blocklist via rule ${prior} — duplicate collapsed (interval set rejects identical elements)`,
      });
      continue;
    }
    seen.set(parsed.text, rule.id);

    // a single shared set cannot scope per-rule direction — the element
    // blocks BOTH directions (warning only for the non-default deviation)
    if (rule.direction === "in") {
      warnings.push({
        scope: "rule",
        ruleId: rule.id,
        name: rule.name,
        code: "direction-unscoped",
        message: `rule '${rule.name}': direction=in approximated — the shared ${TI_SET_NAME} set also drops egress toward this element (single-set blackhole)`,
      });
    } else if (rule.direction === "out") {
      warnings.push({
        scope: "rule",
        ruleId: rule.id,
        name: rule.name,
        code: "direction-unscoped",
        message: `rule '${rule.name}': direction=out approximated — the shared ${TI_SET_NAME} set also drops ingress from this element (single-set blackhole)`,
      });
    }

    const comment = `${TI_COMMENT_PREFIX}${rule.id}:${sanitizeComment(rule.name, 32)}`;
    rendered.push({ num: parsed.num, text: parsed.text, spec: `${parsed.text} counter comment ${JSON.stringify(comment)}` });
  }

  rendered.sort((a, b) => (a.num - b.num) || (a.text < b.text ? -1 : a.text > b.text ? 1 : 0));
  const elements = rendered.map((e) => e.spec);

  if (rulesCount === 0) {
    warnings.push({
      scope: "table",
      ruleId: null,
      name: TI_TABLE,
      code: "empty-blocklist",
      message:
        "no enabled auto-block rules were considered — the table applies empty, both chains match nothing and no traffic is affected",
    });
  }

  const genAt = (input.generatedAt ?? new Date()).toISOString();

  // set payload — continuation lines align under the first element; the last
  // entry closes the literal (kernel dumps may re-wrap, drift compare
  // collapses whitespace so the layout is cosmetic only)
  const elementLines: string[] = [];
  if (elements.length === 1) {
    elementLines.push(`    elements = { ${elements[0]} }`);
  } else if (elements.length > 1) {
    elementLines.push(`    elements = { ${elements[0]},`);
    for (let i = 1; i < elements.length; i += 1) {
      const tail = i === elements.length - 1 ? " }" : ",";
      elementLines.push(`                 ${elements[i]}${tail}`);
    }
  }

  const lines: string[] = [
    "#!/usr/sbin/nft -f",
    `# utm_ti_block — managed by the UTM console (GUI: Threat Intelligence → Auto-block → Apply to host)`,
    `# generated: ${genAt}`,
    "#",
    "# Atomic replace of the console-managed table ONLY — never flushes the",
    "# entire ruleset: inet console-firewall, inet utm_appctl, fail2ban and any",
    "# foreign rulesets survive every apply. Both chain policies are permanently",
    "# accept — this table ONLY blackholes packets whose source/destination",
    "# address is an element of the threat-intel blocklist (auto-block",
    "# action=block rules). Unmatched traffic is never affected here (no",
    "# catch-all verdict of any kind).",
    "",
    `destroy table inet ${TI_TABLE_NAME}`,
    "",
    `table inet ${TI_TABLE_NAME} {`,
    `  set ${TI_SET_NAME} {`,
    `    type ipv4_addr`,
    `    flags interval`,
    `    auto-merge`,
    ...elementLines,
    `  }`,
    ``,
    `  chain ${TI_PREROUTING_CHAIN} {`,
    `    type filter hook prerouting priority ${TI_PRIORITY}; policy accept;`,
    `    ${statements[0]}`,
    `  }`,
    ``,
    `  chain ${TI_POSTROUTING_CHAIN} {`,
    `    type filter hook postrouting priority ${TI_PRIORITY}; policy accept;`,
    `    ${statements[1]}`,
    `  }`,
    `}`,
    "",
  ];

  const file = lines.join("\n");
  return {
    file,
    confHash: tiConfHash(file),
    counts: { rules: rulesCount, elements: elements.length, skipped, chains: 2 },
    elements,
    statements,
    warnings,
  };
}

// ── confHash ────────────────────────────────────────────────────────────────

/**
 * sha256 hex over the canonical (comment-stripped) body. Comments carry the
 * `# generated:` timestamp — stripping them keeps the hash STABLE across
 * renders, so state.json drift compare stays meaningful.
 */
export function tiConfHash(file: string): string {
  const canonical = file
    .split("\n")
    .filter((l) => !l.trimStart().startsWith("#"))
    .join("\n")
    .trim();
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

// ── drift / status parsers (pure) ───────────────────────────────────────────

/**
 * Extract the `table inet utm_ti_block { … }` block from a dump/source,
 * comments + counters stripped, whitespace collapsed → canonical string.
 * Returns null when the table is absent. The ELEMENTS payload is replaced
 * by `elements = { }` — interval sets auto-merge/adjacent-coalesce
 * kernel-side, so element-level compare would report permanent false
 * drift; policy drift is the set/chain skeleton, data drift is per-rule
 * element presence (parseTiElements).
 */
export function extractTiTableBlock(source: string): string | null {
  const lines: string[] = [];
  let inside = false;
  let depth = 0;
  for (const raw of source.split("\n")) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!inside) {
      if (new RegExp(`^table inet ${TI_TABLE_NAME}\\s*\\{`).test(line)) {
        inside = true;
        depth = 1;
        lines.push(line); // the table header participates in the normalized block
      }
      continue;
    }
    depth += (line.match(/\{/g) ?? []).length - (line.match(/\}/g) ?? []).length;
    if (depth <= 0) break;
    const norm = line
      .replace(/comment "[^"]*"/g, "")
      .replace(/\bcounter( packets \d+ bytes \d+)?/g, "")
      .replace(/\s+/g, " ")
      .trim();
    if (norm) lines.push(norm);
  }
  if (!inside) return null;
  const collapsed = lines.join("\n").replace(/elements = \{[^}]*\}/g, "elements = { }");
  return collapsed.replace(/\s+/g, " ").trim();
}

/** Pure compare of generated vs live table skeleton (unit-testable). */
export function tiTableBlocksInSync(genFile: string, liveDump: string): boolean {
  const a = extractTiTableBlock(genFile);
  const b = extractTiTableBlock(liveDump);
  if (a === null || b === null) return false;
  return a === b;
}

export interface TiElement {
  address: string;
  ruleId: number | null;
  name: string | null;
  packets: number;
  bytes: number;
}

/**
 * Parse `ti:<ruleId>:<name>` element comments (+ per-element stateful
 * counters when the kernel attached them) from a live dump. Order is
 * PRESERVED (kernel dumps sets in numeric element order; the generated
 * fragment renders numeric-sorted) — never re-sorted by rule id.
 */
export function parseTiElements(liveDump: string): TiElement[] {
  const out: TiElement[] = [];
  const elementRe =
    /(\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?)\s+counter(?: packets (\d+) bytes (\d+))?\s+comment "ti:(\d+):([^"]*)"/g;
  let m: RegExpExecArray | null;
  while ((m = elementRe.exec(liveDump)) !== null) {
    out.push({
      address: m[1],
      ruleId: Number(m[4]),
      name: m[5],
      packets: Number(m[2] ?? 0),
      bytes: Number(m[3] ?? 0),
    });
  }
  return out;
}

export interface TiDropCounters {
  prerouting: { packets: number; bytes: number } | null;
  postrouting: { packets: number; bytes: number } | null;
}

/** Parse the two chain drop counters (ingress saddr / egress daddr). */
export function parseTiDropCounters(liveDump: string): TiDropCounters {
  const read = (kind: "saddr" | "daddr"): { packets: number; bytes: number } | null => {
    const re = new RegExp(`ip ${kind} @${TI_SET_NAME} counter(?: packets (\\d+) bytes (\\d+))?\\s+drop`);
    const m = re.exec(liveDump);
    if (!m) return null;
    return { packets: Number(m[1] ?? 0), bytes: Number(m[2] ?? 0) };
  };
  return { prerouting: read("saddr"), postrouting: read("daddr") };
}

// ── restore-point + exec whitelist guards ───────────────────────────────────

/**
 * Compose the full-ruleset backup file: `flush ruleset` prologue + live dump.
 * The prologue is MANDATORY — a restore file without it would merge instead
 * of restore and leave stale blocklist state in the kernel.
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
const NFT_READ_RE = /^nft list (ruleset|table inet utm_ti_block)( 2>\/dev\/null)?$/;
const NFT_VERSION_RE = /^nft --version$/;
const NFT_ENABLE_RE = /^systemctl enable nftables( >\/dev\/null 2>&1)?$/;

export function tiStepGuarded(cmd: string): boolean {
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

export type TiPlanStepKind = "check" | "arm" | "apply" | "restore" | "persist";

export interface TiPlanStep {
  step: string;
  kind: TiPlanStepKind;
  /** exact exec command — every one passes tiStepGuarded */
  cmd: string;
}

export interface TiRollbackScriptInput {
  ts: string;
  confirmSec: number;
  confirmFile: string;
  backupFile: string;
  scriptFile: string;
  stateFile: string;
}

/** Detached commit-confirm rollback timer (survives console restarts). */
export function buildTiRollbackScript(input: TiRollbackScriptInput): string {
  return [
    "#!/bin/sh",
    `# utm_ti_block commit-confirm rollback armed ${input.ts}`,
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
 * Ordered exec plan for the apply pipeline. Paths are resolved by
 * os-service; every emitted cmd passes tiStepGuarded (unit-test enforced).
 */
export function buildTiApplySteps(input: { file: string; backupFile: string; rollbackScript: string }): TiPlanStep[] {
  return [
    { step: "nft -c check", kind: "check", cmd: `nft -c -f ${JSON.stringify(input.file)}` },
    { step: "rollback timer", kind: "arm", cmd: `nohup /bin/sh ${JSON.stringify(input.rollbackScript)} >/dev/null 2>&1 &` },
    { step: "apply", kind: "apply", cmd: `nft -f ${JSON.stringify(input.file)}` },
    { step: "restore backup", kind: "restore", cmd: `nft -f ${JSON.stringify(input.backupFile)}` },
    { step: "systemctl enable nftables", kind: "persist", cmd: "systemctl enable nftables >/dev/null 2>&1" },
  ];
}
