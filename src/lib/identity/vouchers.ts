/**
 * Guest vouchers (M07 §3/§5.4; spec §1.10) — Prisma-backed persistent store
 * (`captive_portal_vouchers`, schema §7). T1-d: the MockEngine in-memory
 * store was replaced — vouchers survive process restarts now.
 *
 * Codes: 16 chars from a crypto-random, unambiguous alphabet (A-Z minus I/O,
 * digits 2-9 — no 0/O/1/I), grouped `XXXX-XXXX-XXXX-XXXX`. The PLAIN code is
 * stored (it must be revealable/downloadable by admins) and unique per tenant
 * (@@unique([tenantId, code])); the one-time-reveal rule (M07 §4) stays a
 * route-layer concern — GET returns masked codes, POST is the only response
 * that ever carries the full codes.
 *
 * AT-REST NOTE (audit fix F-c #19 — schema.prisma is LOCKED, documented here
 * instead): voucher codes are stored PLAINTEXT BY DESIGN — admins must be
 * able to reveal/download the batch (M07 §4) and the portal redeem path must
 * look the code up by exact value. Disclosure is controlled in the response
 * layer: list/read DTOs carry codeMasked only (… + last 4), and the full
 * code leaves the server exactly once, in the POST /vouchers create batch.
 * This mirrors the portal-session token rule below (sha256 at rest, token
 * returned once) — tokens are one-time secrets; codes are re-presentable
 * credentials, hence the weaker (documented) at-rest guarantee.
 *
 * Redeem is TRANSACTIONAL (audit fix F-c #2): the voucher claim is a
 * conditional updateMany({where: {id, tenantId, state: "unused"}}) INSIDE a
 * db.$transaction that also creates the CaptivePortalSession — two racing
 * redemptions can never both win and the session row cannot exist without
 * the claimed voucher (no Promise.all split). A loser sees count === 0 and
 * returns null (route maps it to 409/400).
 */

import { createHash, randomBytes } from "crypto";
import { db } from "@/lib/db";

export type VoucherState = "unused" | "redeemed" | "expired" | "revoked";

export interface Voucher {
  id: number;
  code: string; // full code — server-side only, never returned after create
  state: VoucherState;
  createdAt: string;
  expiresAt: string;
  /** redemption timestamp (legacy field name — maps to the row's redeemedAt) */
  usedAt: string | null;
  /**
   * MockEngine-era per-voucher QoS cap. The persisted schema has no
   * per-voucher column — the ACTIVE portal profile's bandwidthKbps applies,
   * so this is always null and kept only for DTO-shape compatibility.
   */
  bandwidthKbps: number | null;
}

export type VoucherDTO = Omit<Voucher, "code"> & { codeMasked: string };

/** Guest-facing session grant — the token is shown/returned exactly once. */
export interface PortalSessionGrant {
  token: string;
  expiresAt: string;
  /** guest-facing session subset (mirrors /register's envelope — no hashed sessionId) */
  kind: string;
  clientIp: string;
  state: string;
  startedAt: string;
}

export interface RedeemResult {
  voucher: Voucher;
  session: PortalSessionGrant;
}

// ── code generation (crypto randomness — unbiased) ──────────────────────────

/** 32-symbol alphabet (no I, O, 0, 1) — a power of two, so byte-mapping is unbiased. */
const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const CODE_GROUP_LEN = 4;
const CODE_GROUPS = 4;

function randomVoucherCode(): string {
  const bytes = randomBytes(CODE_GROUP_LEN * CODE_GROUPS);
  const chars = Array.from(bytes, (b) => CODE_ALPHABET[b & (CODE_ALPHABET.length - 1)]);
  const groups: string[] = [];
  for (let g = 0; g < CODE_GROUPS; g++) {
    groups.push(chars.slice(g * CODE_GROUP_LEN, (g + 1) * CODE_GROUP_LEN).join(""));
  }
  return groups.join("-");
}

/** Opaque guest session token — plaintext lives only in the API response. */
export function newPortalSessionToken(): string {
  return randomBytes(32).toString("base64url");
}

/** At-rest form of a session token (captive_portal_sessions.session_id). */
export function hashSessionToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

// ── row mapping ──────────────────────────────────────────────────────────────

interface VoucherRow {
  id: number;
  code: string;
  state: string;
  createdAt: Date;
  expiresAt: Date;
  redeemedAt: Date | null;
}

function toVoucher(row: VoucherRow): Voucher {
  return {
    id: row.id,
    code: row.code,
    state: row.state as VoucherState,
    createdAt: row.createdAt.toISOString(),
    expiresAt: row.expiresAt.toISOString(),
    usedAt: row.redeemedAt ? row.redeemedAt.toISOString() : null,
    bandwidthKbps: null,
  };
}

/** Masked form for every read AFTER creation — `…` + last 4 chars (M07 §4). */
export function maskVoucherCode(code: string): string {
  return `…${code.slice(-4)}`;
}

export function toVoucherDTO(v: Voucher): VoucherDTO {
  const { code, ...rest } = v;
  return { ...rest, codeMasked: maskVoucherCode(code) };
}

// ── sweep (spec §7 retention) ────────────────────────────────────────────────

/**
 * Age out stale rows: unused vouchers past `expiresAt` → expired, active
 * portal sessions past `expiresAt` → expired. Cheap updateMany — safe to
 * call on every read.
 */
export async function expireSweep(tenantId = 1): Promise<{ vouchersExpired: number; sessionsExpired: number }> {
  const now = new Date();
  const vouchers = await db.captivePortalVoucher.updateMany({
    where: { tenantId, state: "unused", expiresAt: { lte: now } },
    data: { state: "expired" },
  });
  const sessions = await db.captivePortalSession.updateMany({
    where: { tenantId, state: "active", expiresAt: { lte: now } },
    data: { state: "expired" },
  });
  return { vouchersExpired: vouchers.count, sessionsExpired: sessions.count };
}

// ── CRUD ─────────────────────────────────────────────────────────────────────

/**
 * Batch-create N codes. The full codes are returned ONCE, here only.
 * `bandwidthKbps` is accepted for caller compatibility; the persisted schema
 * carries no per-voucher cap (the portal profile's cap applies).
 */
export async function generateVouchers(
  count: number,
  ttlHours: number,
  _bandwidthKbps?: number,
  tenantId = 1,
): Promise<Voucher[]> {
  const created: Voucher[] = [];
  const expiresAt = new Date(Date.now() + ttlHours * 3_600_000);
  for (let i = 0; i < count; i++) {
    // @@unique([tenantId, code]) — crypto codes make collisions vanishingly
    // rare, but retry a few times instead of failing the whole batch.
    for (let attempt = 0; attempt < 5; attempt++) {
      try {
        const row = await db.captivePortalVoucher.create({
          data: { tenantId, code: randomVoucherCode(), state: "unused", ttlHours, expiresAt },
        });
        created.push(toVoucher(row));
        break;
      } catch (err) {
        const code = (err as { code?: string }).code;
        if (code !== "P2002" || attempt === 4) throw err;
      }
    }
  }
  return created;
}

/** Live list, newest first — unused vouchers past their TTL age out on read. */
export async function listVouchers(tenantId = 1): Promise<Voucher[]> {
  await expireSweep(tenantId);
  const rows = await db.captivePortalVoucher.findMany({ where: { tenantId }, orderBy: { id: "desc" } });
  return rows.map(toVoucher);
}

/** Revoke an UNUSED voucher (redeemed/expired codes are terminal already). */
export async function revokeVoucher(id: number, tenantId = 1): Promise<boolean> {
  const row = await db.captivePortalVoucher.findFirst({ where: { tenantId, id } });
  if (!row || row.state !== "unused") return false;
  await db.captivePortalVoucher.update({ where: { id: row.id }, data: { state: "revoked" } });
  return true;
}

/** Live-voucher count for the engine's churn decision (cheap). */
export async function unusedVoucherCount(tenantId = 1): Promise<number> {
  await expireSweep(tenantId);
  return db.captivePortalVoucher.count({ where: { tenantId, state: "unused" } });
}

/**
 * Simulated portal login consumes the FIRST unused voucher (engine churn,
 * M07 §5.4); null if none. No session row — the engine has no client IP/MAC.
 */
export async function consumeVoucher(tenantId = 1): Promise<Voucher | null> {
  await expireSweep(tenantId);
  const row = await db.captivePortalVoucher.findFirst({ where: { tenantId, state: "unused" }, orderBy: { id: "asc" } });
  if (!row) return null;
  const updated = await db.captivePortalVoucher.update({
    where: { id: row.id },
    data: { state: "redeemed", redeemedAt: new Date() },
  });
  return toVoucher(updated);
}

/**
 * Guest redeems a voucher code at the portal (spec §1.10): the voucher flips
 * to `redeemed` and an ACTIVE CaptivePortalSession opens for (ip, mac), with
 * `expiresAt` = now + the active profile's sessionTimeoutMin. Returns null
 * when the code is unknown, expired, revoked or already redeemed.
 *
 * Audit fix F-c #2 — the claim + session creation run in ONE interactive
 * transaction: a conditional updateMany (state still "unused" AND not
 * expired) is the atomic claim; count === 0 → null WITHOUT opening a
 * session. A `portalId` may pin the profile (public /redeem body); when
 * given but unknown, redemption fails (no profile fallback for pinned ids).
 */
export async function redeem(
  rawCode: string,
  clientIp: string,
  clientMac?: string,
  tenantId = 1,
  portalId?: number,
): Promise<RedeemResult | null> {
  await expireSweep(tenantId);
  const code = rawCode.trim().toUpperCase();
  const row = await db.captivePortalVoucher.findFirst({ where: { tenantId, code } });
  if (!row || row.state !== "unused") return null;

  const profile = portalId
    ? await db.captivePortalProfile.findFirst({ where: { tenantId, id: portalId } })
    : await db.captivePortalProfile.findFirst({ where: { tenantId }, orderBy: { id: "asc" } });
  if (portalId !== undefined && !profile) return null; // pinned portal unknown → refuse
  const timeoutMin = profile?.sessionTimeoutMin ?? 240;
  const now = new Date();
  const token = newPortalSessionToken();
  const sessionExpiresAt = new Date(now.getTime() + timeoutMin * 60_000);

  const session = await db.$transaction(async (tx) => {
    // Atomic claim — the WHERE carries the state precondition, so a racing
    // redemption gets count 0 and never opens a session.
    const claimed = await tx.captivePortalVoucher.updateMany({
      where: { id: row.id, tenantId, state: "unused", expiresAt: { gt: now } },
      data: { state: "redeemed", redeemedBy: clientMac ?? null, redeemedIp: clientIp, redeemedAt: now },
    });
    if (claimed.count === 0) return null;
    return tx.captivePortalSession.create({
      data: {
        tenantId,
        portalId: profile?.id ?? 0,
        sessionId: hashSessionToken(token),
        kind: "voucher",
        clientMac: clientMac ?? null,
        clientIp,
        userName: null,
        state: "active",
        startedAt: now,
        expiresAt: sessionExpiresAt,
      },
    });
  });
  if (!session) return null;

  return {
    voucher: toVoucher({ ...row, state: "redeemed", redeemedAt: now }),
    session: {
      token,
      expiresAt: sessionExpiresAt.toISOString(),
      kind: session.kind,
      clientIp: session.clientIp,
      state: session.state,
      startedAt: session.startedAt.toISOString(),
    },
  };
}
