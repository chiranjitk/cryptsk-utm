/**
 * Guest vouchers — MockEngine in-memory store (SCHEMA.md §6 Pseudo-Resources;
 * M07 §5.4). Volatile across process restarts BY DESIGN (Phase 1) — the UI
 * labels the card "Volatile in sandbox". Codes `cks-XXXX-XXXX` (Crockford
 * base32), unique among live vouchers. Store lives on globalThis so HMR
 * doesn't wipe it mid-demo (same trick as the MockEngine singleton).
 */

export type VoucherState = "unused" | "used" | "expired";

export interface Voucher {
  id: number;
  code: string; // full code — server-side only, never returned after create
  state: VoucherState;
  createdAt: string;
  expiresAt: string;
  usedAt: string | null;
  bandwidthKbps: number | null;
}

/** Crockford base32 (no I, L, O, U) — human-transcribable voucher codes. */
const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function randomCode(rand: () => number): string {
  const pick = () => B32[Math.floor(rand() * B32.length)];
  const seg = () => Array.from({ length: 4 }, pick).join("");
  return `cks-${seg()}-${seg()}`;
}

interface Store {
  vouchers: Voucher[];
  nextId: number;
}

const g = globalThis as unknown as { __cryptskVoucherStore?: Store };
const store: Store = g.__cryptskVoucherStore ?? { vouchers: [], nextId: 1 };
g.__cryptskVoucherStore = store;

/** Deterministic PRNG for code generation (MOCK_SEED aligned with the engine). */
function voucherRand(): () => number {
  let a = (Number(process.env.MOCK_SEED ?? 1337) ^ Date.now()) >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 15)) >>> 0) / 4294967296;
  };
}

/** Age out unused vouchers whose TTL elapsed; returns the live list. */
function sweep(): Voucher[] {
  const now = Date.now();
  for (const v of store.vouchers) {
    if (v.state === "unused" && Date.parse(v.expiresAt) <= now) v.state = "expired";
  }
  return store.vouchers;
}

/** Batch-create N codes. The full codes are returned ONCE, here only. */
export function generateVouchers(count: number, ttlHours: number, bandwidthKbps?: number): Voucher[] {
  sweep();
  const rand = voucherRand();
  const live = new Set(store.vouchers.filter((v) => v.state === "unused").map((v) => v.code));
  const created: Voucher[] = [];
  for (let i = 0; i < count; i++) {
    let code = randomCode(rand);
    let guard = 0;
    while (live.has(code) && guard++ < 50) code = randomCode(rand);
    live.add(code);
    const nowIso = new Date().toISOString();
    const voucher: Voucher = {
      id: store.nextId++,
      code,
      state: "unused",
      createdAt: nowIso,
      expiresAt: new Date(Date.now() + ttlHours * 3_600_000).toISOString(),
      usedAt: null,
      bandwidthKbps: bandwidthKbps ?? null,
    };
    store.vouchers.push(voucher);
    created.push(voucher);
  }
  return created;
}

export function listVouchers(): Voucher[] {
  return [...sweep()].sort((a, b) => b.id - a.id);
}

export function revokeVoucher(id: number): boolean {
  const v = store.vouchers.find((x) => x.id === id);
  if (!v) return false;
  store.vouchers = store.vouchers.filter((x) => x.id !== id);
  return true;
}

/** Simulated portal login consumes the FIRST unused voucher; null if none. */
export function consumeVoucher(): Voucher | null {
  sweep();
  const v = store.vouchers.find((x) => x.state === "unused");
  if (!v) return null;
  v.state = "used";
  v.usedAt = new Date().toISOString();
  return v;
}

/** Masked form for every read AFTER creation — `…` + last 4 chars (M07 §4). */
export function maskVoucherCode(code: string): string {
  return `…${code.slice(-4)}`;
}

export type VoucherDTO = Omit<Voucher, "code"> & { codeMasked: string };

export function toVoucherDTO(v: Voucher): VoucherDTO {
  const { code, ...rest } = v;
  return { ...rest, codeMasked: maskVoucherCode(code) };
}

/** Live-voucher count for the engine's churn decision (cheap). */
export function unusedVoucherCount(): number {
  sweep();
  return store.vouchers.filter((v) => v.state === "unused").length;
}
