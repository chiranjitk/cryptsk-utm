/**
 * Portal persistence tests (T1-d — spec §1.10 + §7 tables):
 *   • vouchers are SQLite rows (no MockEngine global store) — codes survive
 *     restarts, redeem flips the voucher + opens a CaptivePortalSession,
 *   • redeem is TRANSACTIONAL (audit fix #2): double-redeem (sequential AND
 *     concurrent) yields exactly one winner and one session row,
 *   • expireSweep ages out unused vouchers and active sessions past expiry,
 *   • revoke is terminal (code refuses redemption afterwards),
 *   • guest self-registration honors the active portal profile (enabled
 *     check, mode-agnostic, sessionTimeoutMin → expiresAt) with a 3-session
 *     concurrent cap per client IP (audit fix #23) and control-char/bidi
 *     sanitization of the guest name,
 *   • the PUBLIC /register endpoint is rate limited per source IP (429
 *     envelope shape) and never leaks the hashed sessionId,
 *   • the PUBLIC /redeem endpoint (audit fix #12) mirrors the register
 *     subset, refuses reuse with a uniform 400 and rate limits per IP.
 *
 * Harness (mirrors the repo's service-test pattern — no DB test had existed,
 * so this file establishes it): the pushed dev schema (db/cryptsk.db) is
 * copied into a per-run temp sqlite file and DATABASE_URL points at the COPY,
 * so the dev DB is never written. The identity modules are imported AFTER the
 * env override — static imports would resolve the Prisma datasource too early.
 * CONSOLE_TRUST_PROXY=1 mirrors a proxied deployment so the tests' per-IP
 * x-forwarded-for headers are honored by the shared handler (audit fix #6).
 */

import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { NextRequest } from "next/server";

const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "portal-persistence-"));
const DB_PATH = path.join(TMP_DIR, "portal-test.db");
fs.copyFileSync(path.resolve(process.cwd(), "db/cryptsk.db"), DB_PATH);
process.env.DATABASE_URL = `file:${DB_PATH}`;
process.env.CONSOLE_TRUST_PROXY = "1"; // tests assert per-IP behavior via XFF

const { db } = await import("@/lib/db");
const vouchers = await import("@/lib/identity/vouchers");
const service = await import("@/lib/identity/service");
const registerRoute = await import("@/app/api/v1/captive-portal/register/route");
const redeemRoute = await import("@/app/api/v1/captive-portal/redeem/route");

type ProfileInput = Parameters<typeof service.putCaptivePortal>[1];

const profile = (over: Partial<ProfileInput> = {}): ProfileInput => ({
  name: "GUEST-PORTAL",
  enabled: true,
  mode: "credentials",
  interfaceName: "lan0",
  sessionTimeoutMin: 120,
  bandwidthKbps: null,
  redirectUrl: null,
  voucherTtlHours: 24,
  ...over,
});

beforeAll(async () => {
  // tenant 1 is seeded in the copied DB; make sure no stale portal profile leaks in
  await db.captivePortalProfile.deleteMany({});
});

beforeEach(async () => {
  await db.captivePortalSession.deleteMany({});
  await db.captivePortalVoucher.deleteMany({});
});

afterAll(async () => {
  await db.$disconnect();
  fs.rmSync(TMP_DIR, { recursive: true, force: true });
});

// ── voucher store: persistence + code shape ────────────────────────────────

describe("voucher store (Prisma-backed)", () => {
  it("generates 16-char codes from the unambiguous alphabet and persists them", async () => {
    const created = await vouchers.generateVouchers(3, 24);
    expect(created).toHaveLength(3);
    for (const v of created) {
      expect(v.code).toMatch(/^[A-HJ-NP-Z2-9]{4}(-[A-HJ-NP-Z2-9]{4}){3}$/);
      expect(v.state).toBe("unused");
      expect(v.usedAt).toBeNull();
    }
    const listed = await vouchers.listVouchers();
    expect(listed).toHaveLength(3);
    // persisted rows, newest first — and the in-memory MockEngine store is GONE
    expect(listed.map((v) => v.id)).toEqual([...created.map((v) => v.id)].reverse());
    expect((globalThis as unknown as { __cryptskVoucherStore?: unknown }).__cryptskVoucherStore).toBeUndefined();
  });

  it("keeps the VoucherDTO shape the portal view consumes (masked code, usedAt)", async () => {
    const [v] = await vouchers.generateVouchers(1, 24);
    const dto = vouchers.toVoucherDTO(v);
    expect(Object.keys(dto).sort()).toEqual(["bandwidthKbps", "codeMasked", "createdAt", "expiresAt", "id", "state", "usedAt"]);
    expect(dto.codeMasked).toBe(`…${v.code.slice(-4)}`);
    expect("code" in dto).toBe(false);
  });

  it("redeem marks the voucher redeemed and opens a CaptivePortalSession (hashed token at rest)", async () => {
    await service.putCaptivePortal(1, profile());
    const [v] = await vouchers.generateVouchers(1, 24);
    const res = await vouchers.redeem(v.code, "192.168.50.77", "aa:bb:cc:dd:ee:ff");
    expect(res).not.toBeNull();
    expect(res!.voucher.state).toBe("redeemed");
    expect(res!.voucher.usedAt).toBeTruthy();
    expect(res!.session.token.length).toBeGreaterThan(20);
    expect(res!.session.expiresAt > new Date().toISOString()).toBe(true);
    expect(res!.session.kind).toBe("voucher");
    expect(res!.session.clientIp).toBe("192.168.50.77");

    const row = await db.captivePortalSession.findFirst({ where: { tenantId: 1, kind: "voucher" } });
    expect(row).not.toBeNull();
    expect(row!.clientIp).toBe("192.168.50.77");
    expect(row!.clientMac).toBe("aa:bb:cc:dd:ee:ff");
    expect(row!.state).toBe("active");
    expect(row!.sessionId).not.toBe(res!.session.token); // sha256 at rest
    expect(row!.sessionId).toHaveLength(64);

    const rowAgain = await db.captivePortalVoucher.findUnique({ where: { tenantId_code: { tenantId: 1, code: v.code } } });
    expect(rowAgain!.state).toBe("redeemed");
    expect(rowAgain!.redeemedIp).toBe("192.168.50.77");
    expect(rowAgain!.redeemedBy).toBe("aa:bb:cc:dd:ee:ff");

    // a second (sequential) redemption of the same code is refused
    expect(await vouchers.redeem(v.code, "192.168.50.77")).toBeNull();
    // unknown code is refused
    expect(await vouchers.redeem("AAAA-BBBB-CCCC-DDDD", "192.168.50.77")).toBeNull();
  });

  it("double-redeem race (audit fix #2): exactly one of two concurrent claims wins", async () => {
    await service.putCaptivePortal(1, profile());
    const [v] = await vouchers.generateVouchers(1, 24);
    const results = await Promise.allSettled([
      vouchers.redeem(v.code, "192.168.50.90"),
      vouchers.redeem(v.code, "192.168.50.91"),
    ]);
    const winners = results.filter((r) => r.status === "fulfilled" && r.value !== null);
    expect(winners).toHaveLength(1);
    // exactly ONE session row exists — no orphaned session without a claim
    expect(await db.captivePortalSession.count({ where: { kind: "voucher" } })).toBe(1);
    const row = await db.captivePortalVoucher.findUnique({ where: { tenantId_code: { tenantId: 1, code: v.code } } });
    expect(row!.state).toBe("redeemed");
  });

  it("redeem inherits the portal profile sessionTimeoutMin", async () => {
    await service.putCaptivePortal(1, profile({ sessionTimeoutMin: 60 }));
    const [v] = await vouchers.generateVouchers(1, 24);
    const res = await vouchers.redeem(v.code, "192.168.50.78");
    expect(res).not.toBeNull();
    const row = await db.captivePortalSession.findFirst({ where: { kind: "voucher" } });
    const mins = (new Date(row!.expiresAt).getTime() - new Date(row!.startedAt).getTime()) / 60_000;
    expect(mins).toBeCloseTo(60, 1);
  });

  it("revoke is terminal — the code refuses redemption afterwards", async () => {
    const [v] = await vouchers.generateVouchers(1, 24);
    expect(await vouchers.revokeVoucher(v.id)).toBe(true);
    expect(await vouchers.revokeVoucher(v.id)).toBe(false); // already revoked
    const row = await db.captivePortalVoucher.findUnique({ where: { tenantId_code: { tenantId: 1, code: v.code } } });
    expect(row!.state).toBe("revoked");
    expect(await vouchers.redeem(v.code, "10.9.9.9")).toBeNull();
    // an unknown id revokes nothing
    expect(await vouchers.revokeVoucher(424_242)).toBe(false);
  });

  it("consumeVoucher (engine churn) redeems the first unused voucher", async () => {
    await vouchers.generateVouchers(2, 24);
    expect(await vouchers.unusedVoucherCount()).toBe(2);
    const c = await vouchers.consumeVoucher();
    expect(c).not.toBeNull();
    expect(c!.state).toBe("redeemed");
    expect(await vouchers.unusedVoucherCount()).toBe(1);
  });
});

// ── expiry sweep ────────────────────────────────────────────────────────────

describe("expireSweep", () => {
  it("ages out unused vouchers past their TTL (and refuses their redemption)", async () => {
    const [v] = await vouchers.generateVouchers(1, 24);
    await db.captivePortalVoucher.update({
      where: { id: v.id },
      data: { expiresAt: new Date(Date.now() - 60_000) }, // manual date — no fake timers needed
    });
    const listed = await vouchers.listVouchers(); // sweep on read
    expect(listed[0].state).toBe("expired");
    expect(await vouchers.redeem(v.code, "10.0.0.9")).toBeNull();
    const sweep = await vouchers.expireSweep();
    expect(sweep.vouchersExpired).toBe(0); // already swept by the read
  });

  it("ages out active portal sessions past their expiresAt", async () => {
    await service.putCaptivePortal(1, profile());
    const reg = await service.selfRegister(1, { name: "sweep-guest", agree: true, clientIp: "10.0.0.10" });
    await db.captivePortalSession.update({
      where: { id: reg.session.id },
      data: { expiresAt: new Date(Date.now() - 5_000) },
    });
    const sweep = await vouchers.expireSweep();
    expect(sweep.sessionsExpired).toBe(1);
    const row = await db.captivePortalSession.findUnique({ where: { id: reg.session.id } });
    expect(row!.state).toBe("expired");
  });
});

// ── guest self-registration ─────────────────────────────────────────────────

describe("selfRegister", () => {
  it("opens an active self-registration session lasting sessionTimeoutMin", async () => {
    await service.putCaptivePortal(1, profile({ sessionTimeoutMin: 90, mode: "clickthrough" }));
    const reg = await service.selfRegister(1, {
      name: "alice",
      phone: "+1 555 0100",
      agree: true,
      clientIp: "192.168.50.20",
      clientMac: "11:22:33:44:55:66",
    });
    expect(reg.token.length).toBeGreaterThan(20);
    expect(reg.session.kind).toBe("self-registration");
    expect(reg.session.userName).toBe("alice");
    expect(reg.session.clientIp).toBe("192.168.50.20");
    expect(reg.session.clientMac).toBe("11:22:33:44:55:66");
    expect(reg.session.state).toBe("active");
    const mins = (new Date(reg.session.expiresAt).getTime() - new Date(reg.session.startedAt).getTime()) / 60_000;
    expect(mins).toBeCloseTo(90, 1);

    const row = await db.captivePortalSession.findUnique({ where: { id: reg.session.id } });
    expect(row!.sessionId).not.toBe(reg.token);
    expect(row!.bytesIn).toBe(0);
    expect(row!.bytesOut).toBe(0);
  });

  it("refuses when the portal profile is disabled or missing", async () => {
    await service.putCaptivePortal(1, profile({ enabled: false }));
    await expect(
      service.selfRegister(1, { name: "bob", agree: true, clientIp: "192.168.50.21" }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });

    await db.captivePortalProfile.deleteMany({});
    await expect(
      service.selfRegister(1, { name: "carol", agree: true, clientIp: "192.168.50.22" }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    // nothing was written on refusal
    expect(await db.captivePortalSession.count()).toBe(0);
  });

  it("refuses without AUP acceptance and lists sessions with filters", async () => {
    await service.putCaptivePortal(1, profile());
    await expect(
      service.selfRegister(1, { name: "dave", agree: false, clientIp: "192.168.50.23" }),
    ).rejects.toMatchObject({ code: "VALIDATION_ERROR" });

    const [v] = await vouchers.generateVouchers(1, 24);
    await vouchers.redeem(v.code, "192.168.50.24", "0a:0b:0c:0d:0e:0f");
    await service.selfRegister(1, { name: "erin", agree: true, clientIp: "192.168.50.25" });

    const all = await service.listPortalSessions(1, { page: 1, limit: 50 });
    expect(all.data).toHaveLength(2);
    expect(all.meta.total).toBe(2);

    const selfOnly = await service.listPortalSessions(1, { page: 1, limit: 50, kind: "self-registration" });
    expect(selfOnly.data.every((s) => s.kind === "self-registration")).toBe(true);
    expect(selfOnly.data.map((s) => s.userName)).toContain("erin");

    const voucherOnly = await service.listPortalSessions(1, { page: 1, limit: 50, kind: "voucher" });
    expect(voucherOnly.data.every((s) => s.kind === "voucher")).toBe(true);

    const searched = await service.listPortalSessions(1, { page: 1, limit: 50, q: "erin" });
    expect(searched.data).toHaveLength(1);
    expect(searched.data[0].userName).toBe("erin");
  });

  it("terminatePortalSession flips active → terminated (idempotent, 404 unknown)", async () => {
    await service.putCaptivePortal(1, profile());
    const reg = await service.selfRegister(1, { name: "frank", agree: true, clientIp: "192.168.50.26" });
    const term = await service.terminatePortalSession(1, reg.session.id);
    expect(term.state).toBe("terminated");
    const again = await service.terminatePortalSession(1, reg.session.id);
    expect(again.state).toBe("terminated");
    await expect(service.terminatePortalSession(1, 987_654)).rejects.toMatchObject({ code: "NOT_FOUND" });
  });
});

// ── PUBLIC /register route: rate limit + response shape ─────────────────────

describe("POST /api/v1/captive-portal/register (public route)", () => {
  const POST = registerRoute.POST;

  const call = (ip: string, body: Record<string, unknown>) =>
    POST(
      new NextRequest("http://localhost/api/v1/captive-portal/register", {
        method: "POST",
        body: JSON.stringify(body),
        headers: { "content-type": "application/json", "x-forwarded-for": ip },
      }),
    );

  it("registers without an auth cookie, returns the token subset (no hashed sessionId), and rate limits per IP", async () => {
    await service.putCaptivePortal(1, profile());

    // calls 1..5 pass — each session is terminated right after its call so the
    // per-IP 3-concurrent cap (#23) never masks the 5/min throttle; call 6
    // trips the per-IP guest throttle
    let last: Response | undefined;
    for (let i = 0; i < 6; i++) {
      last = await call("203.0.113.44", { name: `guest-${i}`, agree: true });
      if (i < 5 && last.status === 200) {
        const row = await db.captivePortalSession.findFirst({ where: { userName: `guest-${i}` } });
        expect(row).not.toBeNull();
        await service.terminatePortalSession(1, row!.id);
      }
    }
    expect(last).toBeDefined();

    const limited = await last!.json();
    expect(last!.status).toBe(429);
    expect(limited.error.code).toBe("RATE_LIMITED");
    expect(limited.error.requestId).toBeTruthy();
    expect(last!.headers.get("retry-after")).toBeTruthy();

    // one of the successful responses — shape contract: token + expiry, no internals
    const okRes = await call("203.0.113.45", { name: "guest-ok", agree: true, clientMac: "0a:1b:2c:3d:4e:5f" });
    expect(okRes.status).toBe(200);
    const okBody = await okRes.json();
    expect(okBody.data.token).toBeTruthy();
    expect(okBody.data.kind).toBe("self-registration");
    expect(okBody.data.userName).toBe("guest-ok");
    expect(okBody.data.clientIp).toBe("203.0.113.45");
    expect(okBody.data.state).toBe("active");
    expect(okBody.data.expiresAt).toBeTruthy();
    expect(JSON.stringify(okBody.data)).not.toContain("sessionId");

    const row = await db.captivePortalSession.findFirst({ where: { userName: "guest-ok" } });
    expect(row).not.toBeNull();
    expect(row!.clientMac).toBe("0a:1b:2c:3d:4e:5f");
  });

  it("still validates the body (agree must be true) before opening a session", async () => {
    const res = await call("203.0.113.46", { name: "no-consent", agree: false });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error.code).toBe("VALIDATION_ERROR");
    expect(JSON.stringify(body.error.details)).toContain("agree");
    expect(await db.captivePortalSession.count({ where: { userName: "no-consent" } })).toBe(0);
  });

  it("strips C0/C1 control chars and bidi overrides from the guest name (audit fix #23)", async () => {
    await service.putCaptivePortal(1, profile());
    const res = await call("203.0.113.47", { name: "bad\u0007\u202Ename\uFEFF", agree: true });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data.userName).toBe("badname");
    // fully-control-char name is rejected (refines to empty)
    const empty = await call("203.0.113.48", { name: "\u0000\u202E\u0007", agree: true });
    expect(empty.status).toBe(400);
    expect(JSON.stringify((await empty.json()).error.details)).toContain("Name is required");
  });

  it("caps concurrent self-registration sessions per client IP at 3 (audit fix #23)", async () => {
    await service.putCaptivePortal(1, profile());
    for (let i = 0; i < 3; i++) {
      const res = await call("203.0.113.50", { name: `cap-guest-${i}`, agree: true });
      expect(res.status).toBe(200);
    }
    const fourth = await call("203.0.113.50", { name: "cap-guest-3", agree: true });
    expect(fourth.status).toBe(429);
    const body = await fourth.json();
    expect(body.error.code).toBe("RATE_LIMITED");
    expect(body.error.message).toContain("Too many active guest sessions");
    expect(await db.captivePortalSession.count({ where: { clientIp: "203.0.113.50", state: "active" } })).toBe(3);
  });
});

// ── PUBLIC /redeem route (audit fix #12): envelope + reuse + rate limit ──────

describe("POST /api/v1/captive-portal/redeem (public route)", () => {
  const POST = redeemRoute.POST;

  const call = (ip: string, body: Record<string, unknown>) =>
    POST(
      new NextRequest("http://localhost/api/v1/captive-portal/redeem", {
        method: "POST",
        body: JSON.stringify(body),
        headers: { "content-type": "application/json", "x-forwarded-for": ip },
      }),
    );

  it("redeems without auth, mirrors the register subset (no hashed sessionId), refuses reuse", async () => {
    await service.putCaptivePortal(1, profile());
    const [v] = await vouchers.generateVouchers(1, 24);

    // lowercase input — the code is normalized (trim + uppercase) in redeem
    const res = await call("198.51.100.10", { code: v.code.toLowerCase() });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data.token).toBeTruthy();
    expect(body.data.kind).toBe("voucher");
    expect(body.data.state).toBe("active");
    expect(body.data.clientIp).toBe("198.51.100.10");
    expect(body.data.expiresAt).toBeTruthy();
    expect(JSON.stringify(body.data)).not.toContain("sessionId");

    const row = await db.captivePortalSession.findFirst({ where: { kind: "voucher", clientIp: "198.51.100.10" } });
    expect(row).not.toBeNull();
    expect(row!.sessionId).toHaveLength(64); // sha256 at rest, token never stored

    // reuse → uniform 400 (no code-state oracle); unknown code → same shape
    const again = await call("198.51.100.10", { code: v.code });
    expect(again.status).toBe(400);
    expect((await again.json()).error.code).toBe("VALIDATION_ERROR");
    const unknown = await call("198.51.100.11", { code: "AAAA-BBBB-CCCC-DDDD" });
    expect(unknown.status).toBe(400);
  });

  it("rate limits redemption attempts per source IP (5/min)", async () => {
    let last: Response | undefined;
    for (let i = 0; i < 6; i++) {
      last = await call("198.51.100.12", { code: `ZZZZ-YYYY-XXXX-WWW${i}` }); // unknown codes
    }
    expect(last).toBeDefined();
    expect(last!.status).toBe(429);
    const body = await last!.json();
    expect(body.error.code).toBe("RATE_LIMITED");
    expect(last!.headers.get("retry-after")).toBeTruthy();
  });

  it("honors a pinned portalId and refuses an unknown one", async () => {
    await service.putCaptivePortal(1, profile());
    const portal = await db.captivePortalProfile.findFirst({ where: { tenantId: 1 } });
    expect(portal).not.toBeNull();
    const [v] = await vouchers.generateVouchers(1, 24);
    const res = await call("198.51.100.13", { code: v.code, portalId: portal!.id });
    expect(res.status).toBe(200);

    const [v2] = await vouchers.generateVouchers(1, 24);
    const bad = await call("198.51.100.14", { code: v2.code, portalId: 424_242 });
    expect(bad.status).toBe(400);
    // the pinned-portal refusal consumed nothing — code stays redeemable
    const retry = await call("198.51.100.15", { code: v2.code });
    expect(retry.status).toBe(200);
  });
});
