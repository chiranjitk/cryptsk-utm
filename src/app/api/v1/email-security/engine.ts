/**
 * Email Security scan engine (M22, spec 2.8) — SIMULATED Rspamd+ClamAV
 * pipeline (the appliance runs the real stack): deterministic FNV-hash spam
 * score (0–12, 1dp) with keyword surcharges, phishing sender heuristics,
 * extension/malware blocking and SPF/DKIM/DMARC verdicts driven by the tenant
 * policy. Pure functions only — persistence lives in service.ts.
 */

import type { EmailVerdict } from "@/lib/validators/email-security";

export type AuthResult = "pass" | "fail" | "softfail" | "none";

/** Sender domains that always fail SPF/DKIM simulation (spec sample-bad list). */
export const BAD_SENDER_DOMAINS: ReadonlySet<string> = new Set([
  "spamsource.example",
  "throwaway.mx",
]);

/** Phishing sender markers — lookalike brands / credential-harvest patterns. */
const PHISHING_MARKERS: readonly string[] = ["paypa1", "amaz0n", "login-verify"];

/** Extensions the ClamAV simulation treats as malware carriers. */
const MALWARE_EXTENSIONS: ReadonlySet<string> = new Set(["exe", "scr", "vbs"]);

/** Spam keywords — +3 each (subject or body), capped at the 12.0 scale max. */
const SPAM_KEYWORDS: readonly string[] = ["free money", "winner", "crypto", "viagra"];

/** Scale max of the simulated Rspamd score. */
export const SPAM_SCORE_MAX = 12;

// ── deterministic primitives ────────────────────────────────────────────────

/** FNV-1a 32-bit — deterministic, dependency-free. */
export function fnv1a(input: string): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

/** Base 0.0–12.0 (1dp) from from+subject, +3 per keyword hit, capped at 12. */
export function computeSpamScore(from: string, subject: string, body: string): number {
  const base = (fnv1a(`${from}\u0000${subject}`) % 121) / 10;
  const haystack = `${subject}\n${body}`.toLowerCase();
  let score = base;
  for (const kw of SPAM_KEYWORDS) {
    if (haystack.includes(kw)) score += 3;
  }
  return Math.round(Math.min(score, SPAM_SCORE_MAX) * 10) / 10;
}

/** Lowercase domain part of an address (after the last "@"). */
export function domainOf(addr: string): string {
  const at = addr.lastIndexOf("@");
  return at === -1 ? addr.toLowerCase() : addr.slice(at + 1).toLowerCase();
}

/** Lowercase extension of an attachment filename, or null when none. */
export function extensionOf(filename: string): string | null {
  const base = filename.split(/[\\/]/).pop() ?? "";
  const dot = base.lastIndexOf(".");
  if (dot <= 0 || dot === base.length - 1) return null;
  const ext = base.slice(dot + 1).toLowerCase();
  return /^[a-z0-9]{1,10}$/.test(ext) ? ext : null;
}

// ── simulated auth results ──────────────────────────────────────────────────

function simulatedSpf(policy: ScanPolicy, fromDomain: string): AuthResult {
  if (!policy.spfVerify) return "none";
  return BAD_SENDER_DOMAINS.has(fromDomain) ? "fail" : "pass";
}

function simulatedDkim(policy: ScanPolicy, fromDomain: string): AuthResult {
  if (!policy.dkimVerify) return "none";
  return BAD_SENDER_DOMAINS.has(fromDomain) ? "fail" : "pass";
}

function simulatedDmarc(spf: AuthResult, dkim: AuthResult): AuthResult {
  return spf === "fail" || dkim === "fail" ? "fail" : "pass";
}

// ── full pipeline ───────────────────────────────────────────────────────────

export interface ScanInput {
  from: string;
  to: string;
  subject?: string;
  body?: string;
  attachments?: string[];
  sizeKb?: number;
}

export interface ScanVerdict {
  verdict: EmailVerdict;
  spamScore: number;
  reasons: string[];
  spfResult: AuthResult;
  dkimResult: AuthResult;
  dmarcResult: AuthResult;
  attachmentsScanned: number;
}

/**
 * Structural policy subset the pipeline consumes — service.ts passes the
 * parsed EmailPolicyDTO (blockedExtensions as string[], dmarcPolicy as the
 * union), NOT the raw Prisma row whose blockedExtensions is serialized JSON.
 */
export interface ScanPolicy {
  enabled: boolean;
  spamThreshold: number;
  blockPhishing: boolean;
  blockMalware: boolean;
  maxMessageSizeMb: number;
  blockedExtensions: string[];
  spfVerify: boolean;
  dkimVerify: boolean;
  dmarcPolicy: string;
}

/**
 * Run one message through the simulated pipeline against the tenant policy.
 * Reasons list every enforcement trigger that fired; verdict resolution is
 * malware/extension > phishing > size > dmarc_fail > spam_score (the spam and
 * dmarc outcomes map through dmarcPolicy: reject→rejected, quarantine→
 * quarantined, none→delivered). A disabled policy delivers everything but
 * still reports the computed scores/auth results.
 */
export function scanMessage(policy: ScanPolicy, input: ScanInput): ScanVerdict {
  const subject = input.subject ?? "";
  const body = input.body ?? "";
  const attachments = input.attachments ?? [];
  const fromLower = input.from.toLowerCase();
  const fromDomain = domainOf(input.from);

  const spamScore = computeSpamScore(fromLower, subject.toLowerCase(), body.toLowerCase());
  const spfResult = simulatedSpf(policy, fromDomain);
  const dkimResult = simulatedDkim(policy, fromDomain);
  const dmarcResult = simulatedDmarc(spfResult, dkimResult);

  const reasons: string[] = [];
  let verdict: EmailVerdict = "delivered";

  const reject = (reason: string) => {
    if (!reasons.includes(reason)) reasons.push(reason);
    verdict = "rejected";
  };
  const quarantine = (reason: string) => {
    if (!reasons.includes(reason)) reasons.push(reason);
    if (verdict !== "rejected") verdict = "quarantined";
  };

  if (policy.enabled) {
    // 1) ClamAV simulation — blocked extensions / malware attachments
    for (const filename of attachments) {
      const ext = extensionOf(filename);
      if (ext === null) continue;
      if (policy.blockMalware && MALWARE_EXTENSIONS.has(ext)) {
        reject("malware");
      } else if (policy.blockedExtensions.includes(ext)) {
        reject("blocked_extension");
      }
    }

    // 2) Phishing sender heuristics
    if (policy.blockPhishing && PHISHING_MARKERS.some((m) => fromLower.includes(m))) {
      reject("phishing");
    }

    // 3) Size cap
    if (input.sizeKb !== undefined && input.sizeKb > policy.maxMessageSizeMb * 1024) {
      reject("size");
    }

    const dmarcAction = policy.dmarcPolicy;

    // 4) DMARC failure → dmarcPolicy mapping
    if (dmarcResult === "fail") {
      if (dmarcAction === "reject") reject("dmarc_fail");
      else if (dmarcAction === "quarantine") quarantine("dmarc_fail");
    }

    // 5) Spam score over threshold → dmarcPolicy mapping
    if (spamScore > policy.spamThreshold) {
      if (!reasons.includes("spam_score")) reasons.push("spam_score");
      if (verdict === "delivered") {
        if (dmarcAction === "reject") verdict = "rejected";
        else if (dmarcAction === "quarantine") verdict = "quarantined";
      }
    }
  }

  return {
    verdict,
    spamScore,
    reasons,
    spfResult,
    dkimResult,
    dmarcResult,
    attachmentsScanned: attachments.length,
  };
}
