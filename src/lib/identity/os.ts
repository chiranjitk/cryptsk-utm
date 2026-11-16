/**
 * RADIUS OS layer (IMPL-8) — real FreeRADIUS 3.2.7 NAS-client convergence for
 * the Debian 13 appliance.
 *
 * Two names matter and are NOT the same:
 *   • systemd unit is `freeradius`  → `systemctl restart freeradius` / `stop` /
 *     `is-active` (the unit ships disabled/inactive — an explicit `restart`
 *     WILL start it; enablement for boot is left untouched);
 *   • validation binary is `freeradius` → `freeradius -CX` (C = check config,
 *     X = debug; exit 0 = valid). NOTE: FreeRADIUS has no `-f <file>` — `-C`
 *     validates the WHOLE /etc/freeradius/3.0/ tree (radiusd.conf + our
 *     clients.conf), so validation can only run AFTER the managed file is
 *     installed. Any failure after install auto-restores the pre-apply file.
 *
 * Mapping (documented honestly): a console RadiusProfile models the appliance
 * as a RADIUS CLIENT to an external server (serverIp/authPort/sharedSecret/
 * timeoutSec/retries). For FreeRADIUS-SERVER integration the same row maps to
 * a NAS client — a device allowed to query OUR freeradius:
 *
 *   client <name-slug> {
 *       ipaddr = <serverIp>
 *       secret = <sharedSecret>
 *   }
 *
 *   • profile name → client slug: lowercased, runs of non [a-z0-9] folded to
 *     '-', trimmed; a slug collision is disambiguated with "-<id>".
 *   • timeoutSec/retries are client-side probe knobs (see service
 *     testRadiusProfile) — they are NOT rendered into clients.conf.
 *   • the M07 schema has NO enabled column: every row is a NAS client today.
 *     The renderer keeps an `enabled` flag so an additive schema change later
 *     needs no renderer change.
 *
 * Managed file: /etc/freeradius/3.0/clients.conf is a STOCK Debian file
 * (default client "localhost" + "localhost_ipv6"). Stock files are never
 * partially edited, and freeradius 3.0's radiusd.conf does NOT include a
 * conf.d fragment dir — so the console manages the file as a FULL FILE:
 *   apply    → backup stock → install our render (header + one client block
 *              per enabled profile; NO secrets invented, NO stock client
 *              silently kept) → freeradius -CX → restart → verify.
 *   rollback → re-install the newest backup-<ts>/clients.conf (the stock file
 *              when nothing but console applies has touched it).
 *
 * Empty state: NO enabled profiles → render the header-only file (no client
 * blocks, no invented localhost secret) and `systemctl stop freeradius`
 * (service left disabled — console-off).
 *
 * NEVER radtest: probing an external server is the client-side service test
 * (testRadiusProfile), never part of an OS apply. The whitelist below has no
 * radtest form by construction.
 *
 * This module is PURE (no exec/db/fs) — renderer, slug/sanitizer, drift, ss
 * parser and guard are unit-testable; fs/exec/db live in os-service.ts.
 */

import { createHash } from "crypto";

// ── constants ───────────────────────────────────────────────────────────────

export const RADIUS_STATE_DIR = "/var/lib/console/identity";
export const RADIUS_STATE_FILE = `${RADIUS_STATE_DIR}/state.json`;
export const RADIUS_STAGE_FILE = `${RADIUS_STATE_DIR}/stage-clients.conf`;
export const RADIUS_MANAGED_FILE = "/etc/freeradius/3.0/clients.conf";
/** FreeRADIUS config root — validated as a whole by `freeradius -CX`. */
export const RADIUS_CONF_DIR = "/etc/freeradius/3.0";
/** systemd unit (NOT the binary name — they coincide here, kept explicit). */
export const RADIUS_UNIT = "freeradius";
/** RADIUS auth port the appliance listens on for NAS clients. */
export const RADIUS_AUTH_PORT = 1812;
/** backup-<ts>/ directories hold the pre-apply managed file */
export const RADIUS_BACKUP_DIR_RE = /^backup-[\w.-]+$/;
/** Managed-file header marker — every console render starts with this line. */
export const RADIUS_HEADER_MARKER = "# Managed by the Cryptsk Console";

// ── shapes (resolved by os-service, consumed here purely) ──────────────────

export interface RadiusProfileShape {
  id: number;
  name: string;
  serverIp: string;
  authPort: number;
  /** clear secret — consumed ONLY by the renderer, never echoed to the API */
  sharedSecret: string;
  timeoutSec: number;
  retries: number;
  /** no enabled column in M07 — os-service sets true for every row */
  enabled: boolean;
}

export interface RenderedProfile {
  id: number;
  name: string;
  /** client block name — sanitized [a-z0-9-] slug */
  slug: string;
  serverIp: string;
  authPort: number;
  /** sha256-16 of the rendered client block — per-profile status identity */
  renderHash: string;
  /** secrets are NEVER carried here — only whether one was rendered */
  secretRendered: boolean;
}

export interface RenderedClients {
  /** full managed-file content — deterministic, byte-stable for a given input */
  content: string;
  profiles: RenderedProfile[];
  /** informational notes (disabled profiles, empty state, …) */
  warnings: string[];
}

// ── sanitizers + guards (config-injection refusals) ────────────────────────

/**
 * client block name: lowercase, runs of non [a-z0-9] → single '-', trimmed to
 * a max of 48 chars. Empty result falls back to "nas" (never bare).
 */
export function profileSlug(name: string): string {
  const slug = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48)
    .replace(/-+$/g, "");
  return slug || "nas";
}

/** Slugs must be unique per clients.conf — collisions are disambiguated by id. */
export function uniqueSlugs(profiles: RadiusProfileShape[]): Map<number, string> {
  const byBase = new Map<string, number>();
  const out = new Map<number, string>();
  for (const p of [...profiles].sort((a, b) => a.id - b.id)) {
    const base = profileSlug(p.name);
    const seen = byBase.get(base) ?? 0;
    byBase.set(base, seen + 1);
    out.set(p.id, seen === 0 ? base : `${base}-${p.id}`);
  }
  return out;
}

/**
 * FreeRADIUS token safety — the secret and the ipaddr are written as bare
 * `key = value` tokens inside a client block. Whitespace, quotes, backslashes
 * and the block/comment/variable metacharacters (# {} $ ` ;) would either
 * break parsing or inject config: refused, never escaped-and-hoped.
 */
export function isUnsafeRadiusToken(value: string): boolean {
  return /[\s"'\\#{}$`;\n\r]/.test(value);
}

/**
 * Hard refusals — an unsafe secret/ipaddr could inject clients.conf syntax.
 * Returns null when nothing is refused. (Loopback serverIp is LEGITIMATE for
 * a NAS client — the stock localhost client does exactly that — so it is not
 * refused.)
 */
export function hardRadiusRefusal(profiles: RadiusProfileShape[]): string | null {
  for (const p of profiles) {
    if (!p.enabled) continue;
    if (isUnsafeRadiusToken(p.sharedSecret)) {
      return `profile "${p.name}" (id ${p.id}) has a shared secret not valid for clients.conf (whitespace/quotes/backslash/metacharacters) — refused`;
    }
    if (isUnsafeRadiusToken(p.serverIp)) {
      return `profile "${p.name}" (id ${p.id}) has a serverIp not valid for clients.conf — refused`;
    }
  }
  return null;
}

// ── renderer ────────────────────────────────────────────────────────────────

const FILE_HEADER = [
  RADIUS_HEADER_MARKER + " — do not edit by hand; changes are overwritten on apply.",
  "#",
  "# This file REPLACES the stock Debian /etc/freeradius/3.0/clients.conf",
  "# (default clients \"localhost\" and \"localhost_ipv6\"). The stock file was",
  "# backed up by the console before the first apply — roll back via the",
  "# console (POST /api/v1/identity/os {\"action\":\"rollback\"}) to restore it.",
  "#",
  "# One client block per console RADIUS profile (RadiusProfile row = NAS",
  "# device allowed to query THIS server on udp/1812). Profile name is used",
  "# as the client slug (lowercase [a-z0-9-]). Secrets are the profile",
  "# sharedSecrets as stored in the console — none are invented here.",
  "#",
  "# Empty file = no NAS clients defined: the freeradius unit is STOPPED",
  "# (left disabled) until a profile is added in the console.",
];

/** One deterministic client block per enabled profile, sorted by id. */
export function renderClientBlock(p: RadiusProfileShape, slug: string): { block: string; rendered: RenderedProfile } {
  const lines = [
    `client ${slug} {`,
    `\tipaddr = ${p.serverIp}`,
    `\tsecret = ${p.sharedSecret}`,
    "}",
  ];
  const block = lines.join("\n");
  return {
    block,
    rendered: {
      id: p.id,
      name: p.name,
      slug,
      serverIp: p.serverIp,
      authPort: p.authPort,
      renderHash: createHash("sha256").update(block).digest("hex").slice(0, 16),
      secretRendered: true,
    },
  };
}

/** Render the complete managed file. Same input → byte-identical output. */
export function renderRadiusClientsConf(profiles: RadiusProfileShape[]): RenderedClients {
  const warnings: string[] = [];
  const enabled = profiles
    .filter((p) => p.enabled)
    .sort((a, b) => a.id - b.id);
  for (const p of profiles.filter((p) => !p.enabled)) {
    warnings.push(`profile "${p.name}" is disabled — not rendered into clients.conf`);
  }

  const slugs = uniqueSlugs(enabled);
  const blocks: string[] = [];
  const rendered: RenderedProfile[] = [];
  for (const p of enabled) {
    const { block, rendered: r } = renderClientBlock(p, slugs.get(p.id) ?? profileSlug(p.name));
    blocks.push(block);
    rendered.push(r);
  }

  const body = rendered.length === 0 ? ["# No console-managed NAS clients — freeradius is stopped (console-off)."] : blocks;
  const content = [...FILE_HEADER, "", ...body, ""].join("\n");
  if (rendered.length === 0) {
    warnings.push("no enabled RADIUS profiles — clients.conf renders empty and the freeradius unit is stopped on apply");
  }
  return { content, profiles: rendered, warnings };
}

/** sha256(content).slice(0,16) — the value stored in state.json + compared on status. */
export function radiusConfHash(content: string): string {
  return createHash("sha256").update(content).digest("hex").slice(0, 16);
}

// ── live state parser (ss output, ground truth format from iproute2) ───────

/**
 * Parse `ss -lun '( sport = :1812 )'` output — true when SOMETHING (freeradius
 * or other) holds a bound udp/1812 socket. Empty output = definitively not
 * bound (a listen probe has no ambiguity, unlike a per-target grep).
 */
export function parseSsForAuthPort(stdout: string): boolean {
  return stdout.split("\n").some((l) => /[:.]1812\b/.test(l));
}

// ── drift ──────────────────────────────────────────────────────────────────

export interface RadiusDrift {
  inSync: boolean;
  driftReasons: string[];
}

/**
 * File-hash + unit-state drift. Expectation depends on the desired state:
 *   ≥1 enabled profile → file matches render AND unit active;
 *   none               → file matches render AND unit NOT active.
 * Port-bound probe is informational (shared with other listeners) and never
 * flips inSync — it surfaces as status.portBound.
 */
export function computeRadiusDrift(input: {
  renderedContent: string;
  liveFileHash: string | null;
  unitActive: boolean | null;
  hasEnabledProfiles: boolean;
}): RadiusDrift {
  const reasons: string[] = [];
  const expectedHash = radiusConfHash(input.renderedContent);
  if (input.liveFileHash == null) reasons.push("managed file is missing — expected /etc/freeradius/3.0/clients.conf");
  else if (input.liveFileHash !== expectedHash) reasons.push(`live file hash ${input.liveFileHash} — expected ${expectedHash}`);

  if (input.hasEnabledProfiles) {
    if (input.unitActive !== true) {
      reasons.push(`unit freeradius is ${input.unitActive === false ? "not active" : "unknown"} — expected active with NAS clients defined`);
    }
  } else if (input.unitActive !== false) {
    reasons.push(`no NAS clients defined — unit freeradius should be stopped, but is ${input.unitActive === true ? "active" : "unknown"}`);
  }
  return { inSync: reasons.length === 0, driftReasons: reasons };
}

// ── apply plan ─────────────────────────────────────────────────────────────

export type RadiusPlanStepKind =
  | "snapshot"
  | "stage"
  | "install"
  | "validate"
  | "exec"
  | "restart"
  | "stop"
  | "verify"
  | "writefile";

export interface RadiusPlanStep {
  step: string;
  cmd: string; // "" for stage / hash-verify / writefile (fs ops resolved at exec time)
  kind: RadiusPlanStepKind;
}

export interface RadiusApplyPlan {
  mode: "plan" | "exec";
  /** true when no enabled profile exists → teardown (empty file + stop) */
  empty: boolean;
  steps: RadiusPlanStep[];
  /** sha256-16 of the rendered managed file (== state.json confHash) */
  confHash: string;
  backupDir: string;
  stateContent: string;
  profiles: RenderedProfile[];
  /** rendered clients.conf content (staged verbatim at exec time) */
  content: string;
  warnings: string[];
}

/**
 * Convergence plan (freeradius validation constraint: `-C` reads the whole
 * config dir, so validate runs on the INSTALLED file — snapshot-first +
 * auto-restore cover the failure window):
 *
 *   snapshot → stage → install → freeradius -CX → cleanup stage →
 *   restart | stop → verify(unit) → verify(port) → verify(freeradius -CX) →
 *   save state file (LAST).
 */
export function buildRadiusApplyPlan(input: {
  profiles: RadiusProfileShape[];
  managedFileExists: boolean;
  mode: "plan" | "exec";
  ts: string;
}): RadiusApplyPlan {
  const { profiles, managedFileExists, mode, ts } = input;
  const warnings: string[] = [];

  // refusal surfaces separately via hardRadiusRefusal — skipped here so the
  // preview never normalizes an injectable secret (qos protected-iface convention)
  const acceptable = profiles.filter((p) => !p.enabled || !(isUnsafeRadiusToken(p.sharedSecret) || isUnsafeRadiusToken(p.serverIp)));
  for (const p of profiles) {
    if (p.enabled && (isUnsafeRadiusToken(p.sharedSecret) || isUnsafeRadiusToken(p.serverIp))) {
      warnings.push(`profile "${p.name}" is refused and NOT part of this plan`);
    }
  }

  const rendered = renderRadiusClientsConf(acceptable);
  const empty = rendered.profiles.length === 0;
  const backupDir = `${RADIUS_STATE_DIR}/backup-${ts}`;

  const steps: RadiusPlanStep[] = [];
  if (managedFileExists) {
    steps.push({
      step: "snapshot managed file",
      cmd: `cp ${RADIUS_MANAGED_FILE} ${backupDir}/clients.conf`,
      kind: "snapshot",
    });
  }
  steps.push({ step: "stage rendered clients.conf", cmd: "", kind: "stage" });
  steps.push({
    step: "install managed file",
    cmd: `install -m 0640 -o root -g freerad ${RADIUS_STAGE_FILE} ${RADIUS_MANAGED_FILE}`,
    kind: "install",
  });
  steps.push({ step: "validate installed config", cmd: "freeradius -CX", kind: "validate" });
  steps.push({ step: "cleanup stage file", cmd: `rm -f ${RADIUS_STAGE_FILE}`, kind: "exec" });
  steps.push(
    empty
      ? { step: `stop ${RADIUS_UNIT} (console-off)`, cmd: `systemctl stop ${RADIUS_UNIT}`, kind: "stop" }
      : { step: `restart ${RADIUS_UNIT}`, cmd: `systemctl restart ${RADIUS_UNIT}`, kind: "restart" },
  );
  steps.push({ step: "verify unit state", cmd: `systemctl is-active ${RADIUS_UNIT}`, kind: "verify" });
  steps.push({ step: "verify auth port bound", cmd: `ss -lun '( sport = :${RADIUS_AUTH_PORT} )'`, kind: "verify" });
  steps.push({ step: "re-validate installed config", cmd: "freeradius -CX", kind: "verify" });
  steps.push({ step: "save state file", cmd: "", kind: "writefile" });

  const stateContent = JSON.stringify(
    {
      confHash: radiusConfHash(rendered.content),
      appliedAt: new Date().toISOString(),
      profileIds: rendered.profiles.map((p) => p.id),
      empty,
      note: empty ? "no NAS clients — freeradius stopped (console-off)" : undefined,
    },
    null,
    2,
  );

  return {
    mode,
    empty,
    steps,
    confHash: radiusConfHash(rendered.content),
    backupDir,
    stateContent,
    profiles: rendered.profiles,
    content: rendered.content,
    warnings: [...rendered.warnings, ...warnings],
  };
}

// ── command whitelist ──────────────────────────────────────────────────────

/** Exact-anchored forms — anything else (pipes, `;`, `&&`, radtest) fails. */
const RADIUS_STEP_RES: RegExp[] = [
  /^freeradius -CX$/,
  /^systemctl restart freeradius$/,
  /^systemctl stop freeradius$/,
  /^systemctl is-active freeradius$/,
  /^ss -lun '\( sport = :1812 \)'$/,
  /^cp \/etc\/freeradius\/3\.0\/clients\.conf \/var\/lib\/console\/identity\/backup-[\w.-]+\/clients\.conf$/,
  /^install -m 0640 -o root -g freerad \/var\/lib\/console\/identity\/[\w.-]+ \/etc\/freeradius\/3\.0\/clients\.conf$/,
  // rollback / auto-restore install from a console-owned backup dir
  // (nested path enumerated explicitly — no free-form slashes, no "..")
  /^install -m 0640 -o root -g freerad \/var\/lib\/console\/identity\/backup-[\w.-]+\/clients\.conf \/etc\/freeradius\/3\.0\/clients\.conf$/,
  /^rm -f \/var\/lib\/console\/identity\/stage[\w.-]*$/,
];

export function radiusStepGuarded(cmd: string): boolean {
  return RADIUS_STEP_RES.some((re) => re.test(cmd));
}
