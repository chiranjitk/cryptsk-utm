/**
 * ZTNA policy engine (Phase 4 §4.4) — PURE core, no db import.
 *
 * Two functions, both total and side-effect-free so the service layer, the
 * /evaluate route and the continuous-validation loop share one decision path:
 *
 *   evaluatePosture(profileChecks, deviceResults)
 *     → {verdict: compliant|non_compliant|unknown, failedChecks[], unknownChecks[]}
 *     A required check with NO result (or an unrecognized result value) is
 *     UNKNOWN — fail-closed, never implicitly passing. A profile that
 *     requires nothing is vacuously compliant.
 *
 *   decideAccess({policies, subject, app, postureVerdict})
 *     → {decision: allow|deny, matchedPolicyId, reason}
 *     deny wins over allow; among equal actions the most specific subject
 *     wins (device > user > group, ties → lowest policy id). Disabled
 *     policies are ignored. A policy that ATTACHES a posture profile can
 *     only grant access on verdict=compliant (fail-closed for non_compliant
 *     AND unknown); deny policies always apply. No match at all → default
 *     deny (zero trust: nothing is allowed by default).
 *
 * Schedule strings ("Mon-Fri 09:00-17:00" style) are stored/displayed but
 * not time-evaluated here — the console has no trusted clock domain; they
 * ride along in the decision reason when set.
 */

// ── posture vocabulary (schema.prisma posture_profiles / device_posture_checks) ──

export type PostureVerdict = "compliant" | "non_compliant" | "unknown";
export type PostureCheckResult = "pass" | "fail" | "unknown";

/** The four basic checks (spec §4.4: OS patch age, AV, disk encrypt + firewall). */
export type CheckKey = "osPatch" | "av" | "diskEncrypt" | "firewall";

export const CHECK_KEYS: CheckKey[] = ["osPatch", "av", "diskEncrypt", "firewall"];

/** Requirement side — JSON stored on PostureProfile.checks. */
export interface PostureChecks {
  /** patch age ceiling in days; presence (> 0) makes the osPatch check required */
  osPatchMaxAgeDays?: number;
  avRequired?: boolean;
  diskEncryptRequired?: boolean;
  firewallRequired?: boolean;
}

/** Observation side — JSON stored on DevicePostureCheck.results ({check: result}). */
export type PostureResults = Partial<Record<CheckKey, PostureCheckResult>>;

export interface PostureEvaluation {
  verdict: PostureVerdict;
  failedChecks: CheckKey[];
  unknownChecks: CheckKey[];
}

/** Which checks a profile makes REQUIRED (osPatch needs a positive day ceiling). */
export function requiredCheckKeys(checks: PostureChecks): CheckKey[] {
  const required: CheckKey[] = [];
  if (
    typeof checks.osPatchMaxAgeDays === "number" &&
    Number.isFinite(checks.osPatchMaxAgeDays) &&
    checks.osPatchMaxAgeDays > 0
  ) {
    required.push("osPatch");
  }
  if (checks.avRequired === true) required.push("av");
  if (checks.diskEncryptRequired === true) required.push("diskEncrypt");
  if (checks.firewallRequired === true) required.push("firewall");
  return required;
}

export function evaluatePosture(checks: PostureChecks, results: PostureResults): PostureEvaluation {
  const failedChecks: CheckKey[] = [];
  const unknownChecks: CheckKey[] = [];
  for (const key of requiredCheckKeys(checks)) {
    const observed = results[key];
    if (observed === "pass") continue;
    if (observed === "fail") failedChecks.push(key);
    else unknownChecks.push(key); // missing result or unrecognized value → unknown
  }
  const verdict: PostureVerdict =
    failedChecks.length > 0 ? "non_compliant" : unknownChecks.length > 0 ? "unknown" : "compliant";
  return { verdict, failedChecks, unknownChecks };
}

// ── access decision ──────────────────────────────────────────────────────────

export type SubjectType = "user" | "group" | "device";
export type AccessAction = "allow" | "deny";

/** Shape the service maps ZtnaAccessPolicy rows into (subset used here). */
export interface AccessPolicyInput {
  id: number;
  appId: number;
  subjectType: SubjectType;
  subjectRef: string;
  action: AccessAction;
  postureProfileId: number | null;
  enabled: boolean;
}

export interface AccessSubjectInput {
  user?: string;
  groups?: string[];
  deviceId?: string;
}

export interface AccessAppInput {
  id: number;
}

export interface AccessDecision {
  decision: AccessAction;
  /** policy that produced the decision — null when nothing matched (default deny) */
  matchedPolicyId: number | null;
  reason: string;
}

/** Specificity order for equal actions: device > user > group. */
const SPECIFICITY: Record<SubjectType, number> = { device: 3, user: 2, group: 1 };

function moreSpecific(a: AccessPolicyInput, b: AccessPolicyInput): boolean {
  const sa = SPECIFICITY[a.subjectType] ?? 0;
  const sb = SPECIFICITY[b.subjectType] ?? 0;
  if (sa !== sb) return sa > sb;
  return a.id < b.id; // deterministic tie-break: earliest created policy
}

function subjectMatches(p: AccessPolicyInput, subject: AccessSubjectInput): boolean {
  switch (p.subjectType) {
    case "user":
      return Boolean(subject.user) && p.subjectRef === subject.user;
    case "group":
      return Array.isArray(subject.groups) && subject.groups.includes(p.subjectRef);
    case "device":
      return Boolean(subject.deviceId) && p.subjectRef === subject.deviceId;
    default:
      return false;
  }
}

export interface DecideAccessInput {
  policies: AccessPolicyInput[];
  subject: AccessSubjectInput;
  app: AccessAppInput;
  /** the device's CURRENT posture verdict (unknown when never checked) */
  postureVerdict: PostureVerdict;
}

export function decideAccess({ policies, subject, app, postureVerdict }: DecideAccessInput): AccessDecision {
  const postureOk = postureVerdict === "compliant";

  // enabled + app-scoped + subject-matching candidates
  const matched = policies.filter((p) => p.enabled && p.appId === app.id && subjectMatches(p, subject));

  // posture gate: an ALLOW policy that attaches a posture profile needs a
  // compliant device (fail-closed on non_compliant AND unknown). Deny
  // policies apply regardless of posture — posture never unlocks access.
  const postureBlocked = matched.filter(
    (p) => p.action === "allow" && p.postureProfileId !== null && !postureOk,
  );
  const applicable = matched.filter((p) => !postureBlocked.includes(p));

  const denies = applicable.filter((p) => p.action === "deny");
  if (denies.length > 0) {
    const hit = denies.reduce((best, p) => (moreSpecific(p, best) ? p : best), denies[0]);
    return {
      decision: "deny",
      matchedPolicyId: hit.id,
      reason:
        `Denied by ${hit.subjectType} policy '${hit.subjectRef}'` +
        (hit.postureProfileId !== null ? ` (posture verdict: ${postureVerdict})` : ""),
    };
  }

  const allows = applicable.filter((p) => p.action === "allow");
  if (allows.length > 0) {
    const hit = allows.reduce((best, p) => (moreSpecific(p, best) ? p : best), allows[0]);
    return {
      decision: "allow",
      matchedPolicyId: hit.id,
      reason: `Allowed by ${hit.subjectType} policy '${hit.subjectRef}'` + (hit.postureProfileId !== null ? ` (posture compliant)` : ""),
    };
  }

  // Everything that matched was posture-gated and the device is not
  // compliant — deny naming the most specific gated policy.
  if (postureBlocked.length > 0) {
    const hit = postureBlocked.reduce((best, p) => (moreSpecific(p, best) ? p : best), postureBlocked[0]);
    return {
      decision: "deny",
      matchedPolicyId: hit.id,
      reason: `Device posture is ${postureVerdict} — policy '${hit.subjectRef}' requires a compliant device posture`,
    };
  }

  return {
    decision: "deny",
    matchedPolicyId: null,
    reason: "No matching access policy — default deny",
  };
}
