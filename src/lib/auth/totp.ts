/**
 * RFC 6238 TOTP verification (Phase 1 MFA gate — AUTH_AND_RBAC §6).
 * Base32 secret, SHA-1, 30 s step, ±1 window tolerance.
 *
 * Audit fixes: code comparison is timing-safe (constant-length 6-digit codes
 * compared via crypto.timingSafeEqual with a length guard), and a best-effort
 * replay guard tracks the last matched step per userId IN-PROCESS — steps
 * ≤ the last matched step are rejected. LIMITATION (documented, accepted):
 * the replay window lives in one Node process — a restart or multi-instance
 * deployment resets it; durable replay protection needs a per-user
 * lastTotpStep column (schema change — out of scope this pass).
 */

import { timingSafeEqual } from "crypto";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** userId → last matched time step (best-effort replay guard, see header). */
const lastMatchedStep = new Map<number, number>();
const REPLAY_MAP_MAX = 5_000;

function rememberStep(userId: number, step: number): void {
  if (lastMatchedStep.size >= REPLAY_MAP_MAX && !lastMatchedStep.has(userId)) {
    const oldest = [...lastMatchedStep.entries()].sort((a, b) => a[1] - b[1]).slice(0, lastMatchedStep.size - REPLAY_MAP_MAX + 1);
    for (const [k] of oldest) lastMatchedStep.delete(k);
  }
  lastMatchedStep.set(userId, step);
}

function base32Decode(input: string): Uint8Array {
  const clean = input.replace(/=+$/g, "").replace(/\s/g, "").toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

async function hotp(secret: Uint8Array, counter: number): Promise<string> {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setUint32(0, Math.floor(counter / 2 ** 32));
  view.setUint32(4, counter >>> 0);
  const key = await crypto.subtle.importKey("raw", secret as unknown as ArrayBuffer, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, buf));
  const offset = sig[sig.length - 1] & 0x0f;
  const code =
    ((sig[offset] & 0x7f) << 24) | ((sig[offset + 1] & 0xff) << 16) | ((sig[offset + 2] & 0xff) << 8) | (sig[offset + 3] & 0xff);
  return String(code % 1_000_000).padStart(6, "0");
}

export async function generateTotpSecret(): Promise<string> {
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/** Timing-safe equality over the (fixed-length) 6-digit code bytes. */
function codeEquals(expected: string, presented: string): boolean {
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(presented, "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/**
 * Verify a TOTP code. `userId` enables the best-effort replay guard (login
 * path); omitted (dummy-verify paths) the pure RFC check runs.
 */
export async function verifyTotp(secret: string, code: string, userId?: number): Promise<boolean> {
  const key = base32Decode(secret);
  const step = Math.floor(Date.now() / 30_000);
  const last = userId !== undefined ? lastMatchedStep.get(userId) : undefined;
  for (const w of [0, -1, 1]) {
    const candidate = step + w;
    if (last !== undefined && candidate <= last) continue; // replayed step → reject
    const expected = await hotp(key, candidate);
    if (codeEquals(expected, code)) {
      if (userId !== undefined) rememberStep(userId, candidate);
      return true;
    }
  }
  return false;
}
