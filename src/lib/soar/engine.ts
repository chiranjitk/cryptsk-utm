/**
 * SOAR playbook engine (Phase 4 §4.6) — PURE core, no db import (same style
 * as the DLP engine). Three responsibilities:
 *
 *   1. matchesTrigger(playbook, trigger) — decide whether a playbook fires for
 *      a trigger: triggerKind must equal the playbook's, then the filter JSON
 *      {severities[], sources[], kinds[]} narrows within that kind (an EMPTY
 *      array means match-all for that dimension; a non-empty array requires
 *      the payload to carry the dimension and be listed in it).
 *
 *   2. evaluateActions(actions) — validate an ordered action list against the
 *      allowed kinds block_ip | notify | create_incident | delay | webhook
 *      with the required params per kind. Deliberately hand-rolled (no zod):
 *      stored rows must be re-validated at RUN time even if the API-edge
 *      validator changes, and the engine must stay dependency-free.
 *
 *   3. dedupeBlocks(existing) — the pure half of the dedupe decision: an
 *      "open" run (running | success) with the same dedupeKey + triggerRef
 *      suppresses the fire; failed runs do NOT (they invite a retry). A
 *      `running` row older than STALE_RUN_MS is treated as DEAD (crashed
 *      process — it can never reach a terminal status again) so it neither
 *      blocks nor counts as the open run.
 */

// ── locked vocabularies (mirrors validators/soar.ts — module-local on purpose) ──

export type SoarTriggerKind = "incident_created" | "incident_severity" | "dlp_incident" | "dns_tunnel" | "ioc_hit";

export type SoarActionKind = "block_ip" | "notify" | "create_incident" | "delay" | "webhook";

export const SOAR_TRIGGER_KINDS: SoarTriggerKind[] = [
  "incident_created",
  "incident_severity",
  "dlp_incident",
  "dns_tunnel",
  "ioc_hit",
];

export const SOAR_ACTION_KINDS: SoarActionKind[] = ["block_ip", "notify", "create_incident", "delay", "webhook"];

export const SOAR_SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;

/** Run statuses that count as "open" for the dedupeKey + triggerRef check. */
export const DEDUPE_OPEN_STATUSES: readonly string[] = ["running", "success"];

/**
 * Stale-run horizon (audit fix F-d): a `running` row older than this is
 * DEAD — the executing process crashed before stamping a terminal status.
 * The service reaps such rows (→ failed) and the dedupe decision ignores
 * them (10 minutes ≫ any legitimate step duration; actions are in-process
 * awaits, not jobs).
 */
export const STALE_RUN_MS = 10 * 60 * 1000;

// ── shapes ──────────────────────────────────────────────────────────────────

export interface SoarTriggerFilter {
  severities?: string[];
  sources?: string[];
  kinds?: string[];
}

/** What upstream modules hand triggerIngest — dimension keys are optional. */
export interface SoarTriggerPayload {
  severity?: string;
  source?: string;
  kind?: string;
  /** open channel — srcIps for block_ip context, refs, anything */
  [key: string]: unknown;
}

export interface SoarTrigger {
  kind: SoarTriggerKind;
  /** "incident:INC-0007" style pointer, recorded on the run row */
  triggerRef: string;
  payload: SoarTriggerPayload;
}

export interface SoarAction {
  kind: SoarActionKind;
  params: Record<string, unknown>;
}

export type EvaluateResult = { ok: true; actions: SoarAction[] } | { ok: false; errors: string[] };

// ── helpers ─────────────────────────────────────────────────────────────────

/** Accept the stored JSON string or an already-parsed object; bad JSON → {}. */
export function parseFilter(raw: unknown): SoarTriggerFilter {
  let value: unknown = raw;
  if (typeof raw === "string") {
    try {
      value = JSON.parse(raw);
    } catch {
      return {};
    }
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const v = value as Record<string, unknown>;
  const list = (key: string): string[] => {
    const arr = v[key];
    return Array.isArray(arr) ? arr.filter((x): x is string => typeof x === "string") : [];
  };
  return { severities: list("severities"), sources: list("sources"), kinds: list("kinds") };
}

function includesIgnoreCase(list: string[], value: string | undefined): boolean {
  if (value === undefined) return false;
  const needle = value.toLowerCase();
  return list.some((item) => item.toLowerCase() === needle);
}

// ── 1. trigger matching ─────────────────────────────────────────────────────

/**
 * Decide if a playbook fires for a trigger. Kind must match exactly; every
 * non-empty filter dimension requires the payload to carry it and be listed
 * (empty arrays = match-all within the triggerKind).
 */
export function matchesTrigger(
  playbook: { triggerKind: string; triggerFilter: unknown },
  trigger: { kind: string; payload: SoarTriggerPayload },
): boolean {
  if (playbook.triggerKind !== trigger.kind) return false;
  const filter = parseFilter(playbook.triggerFilter);
  if (filter.severities?.length && !includesIgnoreCase(filter.severities, trigger.payload.severity)) return false;
  if (filter.sources?.length && !includesIgnoreCase(filter.sources, trigger.payload.source)) return false;
  if (filter.kinds?.length && !includesIgnoreCase(filter.kinds, trigger.payload.kind)) return false;
  return true;
}

// ── 2. action evaluation ────────────────────────────────────────────────────

const MAX_ACTIONS = 10;

function isIPv4(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value.trim());
  if (!m) return false;
  return m.slice(1).every((oct) => Number(oct) >= 0 && Number(oct) <= 255);
}

function octetsOf(ip: string): [number, number, number, number] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
  if (!m) return null;
  const nums = m.slice(1).map((oct) => Number(oct));
  if (nums.some((n) => n < 0 || n > 255)) return null;
  return [nums[0]!, nums[1]!, nums[2]!, nums[3]!];
}

/**
 * ALWAYS-refused block_ip targets (audit fix F-d — automation safety):
 * blocking any of these wedges the data plane instead of an attacker:
 *   0.0.0.0/8 (unspecified), 127/8 (loopback), 169.254/16 (link-local),
 *   224/4 (multicast), 240/4 (reserved, incl. 255.255.255.255 broadcast).
 * No override exists — these ranges are never a meaningful block target.
 * (RFC1918 refusal is a RUN-time, env-overridable policy — see the service.)
 */
export function isProtectedSpecialIp(ip: string): boolean {
  const o = octetsOf(ip);
  if (!o) return false;
  const [a, b] = [o[0], o[1]];
  if (a === 0) return true; // 0.0.0.0/8 — covers 0.0.0.0
  if (a === 127) return true; // 127.0.0.0/8
  if (a === 169 && b === 254) return true; // 169.254.0.0/16
  if (a >= 224 && a <= 239) return true; // 224.0.0.0/4 multicast
  if (a >= 240) return true; // 240.0.0.0/4 reserved — covers 255.255.255.255
  return false;
}

/**
 * RFC1918 private ranges (10/8, 172.16/12, 192.168/16). Legitimate RFC1918
 * gateways CANNOT be detected generically, so the auto-block refuses ALL of
 * them by default (a false positive here cuts internal users off);
 * CONSOLE_SOAR_ALLOW_PRIVATE=1 permits the block explicitly.
 */
export function isRfc1918Ip(ip: string): boolean {
  const o = octetsOf(ip);
  if (!o) return false;
  const [a, b] = [o[0], o[1]];
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  return false;
}

function isNonEmptyString(value: unknown, max: number): value is string {
  return typeof value === "string" && value.trim().length >= 1 && value.trim().length <= max;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Per-kind param validation — returns an error message or null when valid. */
function validateParams(kind: string, params: unknown): string | null {
  if (!isPlainObject(params)) return `params must be an object`;
  const p = params;

  switch (kind) {
    case "block_ip": {
      if (!isIPv4(p.ip)) return `ip must be a valid IPv4 address`;
      if (isProtectedSpecialIp(String(p.ip))) {
        return `ip is in a protected range (0/8, 127/8, 169.254/16, 224/4, 240/4) — auto-block refused`;
      }
      if (p.direction !== undefined && !["in", "out", "both"].includes(String(p.direction))) {
        return `direction must be in | out | both`;
      }
      return null;
    }
    case "notify": {
      if (!isNonEmptyString(p.title, 200)) return `title is required (1-200 chars)`;
      if (!isNonEmptyString(p.message, 2000)) return `message is required (1-2000 chars)`;
      return null;
    }
    case "create_incident": {
      if (!isNonEmptyString(p.title, 200)) return `title is required (1-200 chars)`;
      if (typeof p.severity !== "string" || !(SOAR_SEVERITIES as readonly string[]).includes(p.severity)) {
        return `severity must be one of ${SOAR_SEVERITIES.join(" | ")}`;
      }
      return null;
    }
    case "delay": {
      const seconds = p.seconds;
      if (typeof seconds !== "number" || !Number.isInteger(seconds) || seconds < 1 || seconds > 300) {
        return `seconds must be an integer between 1 and 300`;
      }
      return null;
    }
    case "webhook": {
      if (!isPlainObject(p.payload)) return `payload must be a JSON object`;
      return null;
    }
    default:
      return `unknown action kind`;
  }
}

/**
 * Validate the ordered action list. Returns the normalized actions on success
 * (params preserved as-is — the service interprets them) or the accumulated
 * error strings with `actions[i] <kind>` positions.
 */
export function evaluateActions(actions: unknown): EvaluateResult {
  if (!Array.isArray(actions)) return { ok: false, errors: ["actions must be an array"] };
  if (actions.length < 1) return { ok: false, errors: ["actions must contain at least one action"] };
  if (actions.length > MAX_ACTIONS) return { ok: false, errors: [`at most ${MAX_ACTIONS} actions per playbook`] };

  const errors: string[] = [];
  const valid: SoarAction[] = [];
  actions.forEach((raw, i) => {
    const at = `actions[${i}]`;
    if (!isPlainObject(raw)) {
      errors.push(`${at}: must be an object with kind + params`);
      return;
    }
    const kind = raw.kind;
    if (typeof kind !== "string" || !(SOAR_ACTION_KINDS as string[]).includes(kind)) {
      errors.push(`${at}: unknown kind "${String(kind)}" (allowed: ${SOAR_ACTION_KINDS.join(" | ")})`);
      return;
    }
    const err = validateParams(kind, raw.params);
    if (err) {
      errors.push(`${at} ${kind}: ${err}`);
      return;
    }
    valid.push({ kind: kind as SoarActionKind, params: raw.params as Record<string, unknown> });
  });

  if (errors.length) return { ok: false, errors };
  return { ok: true, actions: valid };
}

// ── 3. dedupe decision (pure half — the service supplies candidate runs) ────

/**
 * True when any candidate run blocks a new fire: a run with the same
 * dedupeKey + triggerRef that is still `running` or already `success`
 * (the trigger was already handled). Failed runs never block. A `running`
 * row older than STALE_RUN_MS (relative to `now`) is DEAD (crashed run) —
 * it neither blocks nor is reported as the open run.
 */
export function dedupeBlocks(
  existing: Array<{ status: string; startedAt?: Date | string }>,
  now: Date = new Date(),
): boolean {
  return existing.some((run) => {
    if (!DEDUPE_OPEN_STATUSES.includes(run.status)) return false;
    if (run.status === "running" && run.startedAt !== undefined) {
      const started = run.startedAt instanceof Date ? run.startedAt : new Date(run.startedAt);
      if (Number.isFinite(started.getTime()) && now.getTime() - started.getTime() > STALE_RUN_MS) {
        return false; // stale running row — dead, not open
      }
    }
    return true;
  });
}
