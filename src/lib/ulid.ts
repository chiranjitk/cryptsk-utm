/**
 * ULID generator (ADR-016) — per-request correlation ids.
 * 48-bit timestamp + 80 bits of randomness, Crockford base32, 26 chars.
 */

const ENCODING = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function encodeTime(now: number, len: number): string {
  let mod: number;
  let str = "";
  for (let i = len - 1; i >= 0; i--) {
    mod = now % 32;
    str = ENCODING[mod] + str;
    now = (now - mod) / 32;
  }
  return str;
}

let lastTime = 0;
let lastRandom: number[] = [];

function randomChars(len: number): number[] {
  const out: number[] = [];
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  for (let i = 0; i < len; i++) out.push(bytes[i] % 32);
  return out;
}

/** Monotonic ULID: strictly increasing within the same millisecond. */
export function ulid(): string {
  const now = Date.now();
  if (now === lastTime) {
    // increment last random value for monotonicity
    for (let i = lastRandom.length - 1; i >= 0; i--) {
      if (lastRandom[i] < 31) {
        lastRandom[i] += 1;
        break;
      }
      lastRandom[i] = 0;
    }
  } else {
    lastTime = now;
    lastRandom = randomChars(16);
  }
  const time = encodeTime(now, 10);
  const rand = lastRandom.map((c) => ENCODING[c]).join("");
  return (time + rand).slice(0, 26);
}
