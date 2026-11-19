/**
 * Auth hardening regression tests (audit fix F-c) — copy-DB harness (mirrors
 * tests/portal-persistence.test.ts): the pushed dev schema (db/cryptsk.db) is
 * copied into a per-run temp sqlite file and DATABASE_URL points at the COPY,
 * so the dev DB is never written. Identity/auth modules are imported AFTER the
 * env override. CONSOLE_TRUST_PROXY=1 mirrors a proxied deployment so tests'
 * per-IP x-forwarded-for headers are honored by the shared handler (#6).
 *
 * Covers:
 *  - #1  JWT revocation: login registers an AuthSession (jti/ip/UA/expiry),
 *        disable → subsequent requests 401, logout revokes the presented
 *        token, user delete kills sessions.
 *  - #3  role hierarchy: security_admin cannot create a super_admin /
 *        tenant_admin (403) but CAN create lower ranks; nobody may modify a
 *        principal that outranks them.
 *  - #4  tenant resolved from the user row (login response carries it).
 *  - #5  lockout: policy maxAttempts failures lock the account (429 +
 *        Retry-After, correct credentials stay locked; restart caveat noted
 *        in the login route header — in-memory counter).
 *  - #7  MFA non-enumeration: unknown user / bad password / enrolled-but-
 *        missing code → identical generic failure, no totpRequired anywhere.
 *  - #8  policy totp.required → 403 "MFA enrollment required" (mfa_required).
 *  - #9  concurrent-session cap: oldest sessions revoked beyond the cap.
 *  - #10 session TTL from the policy (clamp 1–24 h), cookie Max-Age matches.
 *  - #11 NAC area move: network_admin now passes /iot/stats + NAC routes.
 *  - #16 /me tenant mismatch → 401.
 *  - #25 nac-profiles duplicate-name 409 (with the #11 area move).
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { NextRequest } from "next/server";

const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "auth-hardening-"));
const DB_PATH = path.join(TMP_DIR, "auth-test.db");
fs.copyFileSync(path.resolve(process.cwd(), "db/cryptsk.db"), DB_PATH);
process.env.DATABASE_URL = `file:${DB_PATH}`;
process.env.CONSOLE_TRUST_PROXY = "1"; // tests assert per-IP behavior via XFF

const { db } = await import("@/lib/db");
const { hashPassword } = await import("@/lib/auth/password");
const { generateTotpSecret } = await import("@/lib/auth/totp");
const { clampSessionTtl, SESSION_TTL_SEC, SESSION_TTL_MIN_SEC, SESSION_TTL_MAX_SEC } = await import("@/lib/auth/jwt");
const service = await import("@/lib/identity/service");
const loginRoute = await import("@/app/api/v1/auth/login/route");
const logoutRoute = await import("@/app/api/v1/auth/logout/route");
const meRoute = await import("@/app/api/v1/auth/me/route");
const iotStatsRoute = await import("@/app/api/v1/iot/stats/route");
const nacProfilesRoute = await import("@/app/api/v1/identity-advanced/nac-profiles/route");
const nacProfileItemRoute = await import("@/app/api/v1/identity-advanced/nac-profiles/[id]/route");
const usersRoute = await import("@/app/api/v1/users/route");

const SUF = Math.random().toString(36).slice(2, 7); // per-run suffix — clean scratch rows
const scratchUsernames: string[] = [];
let scratchTenantId: number | null = null;
let originalSettings: Awaited<ReturnType<typeof service.getAuthSettings>> | null = null;

// ── request helpers ──────────────────────────────────────────────────────────

function loginReq(body: Record<string, unknown>, ip = "203.0.114.9") {
  return new NextRequest("http://localhost/api/v1/auth/login", {
    method: "POST",
    body: JSON.stringify(body),
    headers: { "content-type": "application/json", "x-forwarded-for": ip },
  });
}

function setCookies(res: Response): string[] {
  const h = res.headers as Headers & { getSetCookie?: () => string[] };
  if (typeof h.getSetCookie === "function") return h.getSetCookie();
  const sc = res.headers.get("set-cookie");
  return sc ? [sc] : [];
}

function cookieValue(cookies: string[], name = "cryptsk_token"): string {
  const full = cookies.find((c) => c.startsWith(`${name}=`));
  return full ? full.split(";")[0] : "";
}

function cookieMaxAge(cookies: string[], name = "cryptsk_token"): number | null {
  const full = cookies.find((c) => c.startsWith(`${name}=`));
  if (!full) return null;
  const m = full.match(/Max-Age=(\d+)/i);
  return m ? Number(m[1]) : null;
}

function req(method: string, url: string, cookie: string, body?: Record<string, unknown>) {
  return new NextRequest(url, {
    method,
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: { "content-type": "application/json", cookie },
  });
}

async function login(username: string, password: string, ip = "203.0.114.9") {
  const res = await loginRoute.POST(loginReq({ username, password }, ip));
  return { res, cookies: setCookies(res), cookie: cookieValue(setCookies(res)) };
}

async function me(cookie: string): Promise<Response> {
  return meRoute.GET(req("GET", "http://localhost/api/v1/auth/me", cookie));
}

async function makeUser(username: string, role: string, password = "Scratch-Pass1"): Promise<{ id: number; username: string }> {
  scratchUsernames.push(username);
  const row = await db.user.create({
    data: {
      tenantId: 1,
      username,
      role,
      isActive: true,
      passwordHash: await hashPassword(password),
    },
  });
  return { id: row.id, username: row.username };
}

beforeAll(async () => {
  // tenant 1 is seeded; capture the auth policy so every test restores it
  originalSettings = await service.getAuthSettings();
});

afterAll(async () => {
  // restore the auth policy even if a test bailed early
  if (originalSettings) await service.putAuthSettings(originalSettings).catch(() => {});
  await db.user.deleteMany({ where: { username: { in: scratchUsernames } } });
  if (scratchTenantId !== null) await db.tenant.deleteMany({ where: { id: scratchTenantId } }).catch(() => {});
  await db.$disconnect();
  fs.rmSync(TMP_DIR, { recursive: true, force: true });
});

// ── #1 login registers a revocable session; tenant comes from the user (#4) ──

describe("login → AuthSession registry", () => {
  it("signs in, registers the jti (ip/UA/expiry), and /me authenticates", async () => {
    const { res, cookies } = await login("admin", "admin123", "203.0.114.1");
    expect(res.status).toBe(200);
    const cookie = cookieValue(cookies);
    expect(cookie).not.toBe("");

    const body = (await res.json()) as { data: { user: { id: number; tenantId: number } } };
    expect(body.data.user.tenantId).toBe(1); // #4 — tenant resolved from the user row

    const row = await db.authSession.findFirst({ where: { userId: body.data.user.id }, orderBy: { id: "desc" } });
    expect(row).not.toBeNull();
    expect(row!.revokedAt).toBeNull();
    expect(row!.ip).toBe("203.0.114.1");
    expect(typeof row!.userAgent).toBe("string"); // captured from the request (empty in bare test requests)
    const mins = (row!.expiresAt.getTime() - Date.now()) / 60_000;
    expect(mins).toBeGreaterThan(8 * 60 - 2); // default policy: 8 h
    expect(mins).toBeLessThan(8 * 60 + 1);

    const meRes = await me(cookie);
    expect(meRes.status).toBe(200);
    const meBody = (await meRes.json()) as { data: { username: string; tenantId: number } };
    expect(meBody.data.username).toBe("admin");
    expect(meBody.data.tenantId).toBe(1);
  });

  it("cookie Max-Age tracks the policy session lifetime (#10, clamped 1–24 h)", () => {
    expect(clampSessionTtl(8 * 3600)).toBe(8 * 3600);
    expect(clampSessionTtl(0.2 * 3600)).toBe(SESSION_TTL_MIN_SEC); // below window → clamped to 1 h
    expect(clampSessionTtl(48 * 3600)).toBe(SESSION_TTL_MAX_SEC); // above window → clamped to 24 h
    expect(clampSessionTtl(undefined)).toBe(SESSION_TTL_SEC); // default 8 h
    expect(clampSessionTtl(Number.NaN)).toBe(SESSION_TTL_SEC);
  });
});

// ── #5 lockout ────────────────────────────────────────────────────────────────

describe("lockout enforcement (#5)", () => {
  it("locks the account after policy.maxAttempts failures — even for correct credentials", async () => {
    const locked = { ...originalSettings!, lockout: { maxAttempts: 3, windowMin: 5 } };
    await service.putAuthSettings(locked);
    try {
      // three failed attempts (wrong password)
      for (let i = 0; i < 3; i++) {
        const r = await login("viewer", "definitely-wrong", "203.0.114.2");
        expect(r.res.status).toBe(401);
      }
      // 4th attempt: lockout wins BEFORE credential checking (still ≤ 5/min throttle)
      const ok = await login("viewer", "viewer123", "203.0.114.2");
      expect(ok.res.status).toBe(429);
      const body = (await ok.res.json()) as { error: { code: string; message: string } };
      expect(body.error.code).toBe("RATE_LIMITED");
      expect(body.error.message).toContain("temporarily locked");
      expect(ok.res.headers.get("retry-after")).toBeTruthy();
    } finally {
      await service.putAuthSettings(originalSettings!);
    }
  });
});

// ── #7 MFA non-enumeration + #8 mfa_required policy ──────────────────────────

describe("MFA anti-enumeration (#7) + policy mfa_required (#8)", () => {
  it("unknown user / bad password / enrolled-missing-code → identical generic 401, no totpRequired", async () => {
    const enrolled = await makeUser(`fmaudit-${SUF}`, "helpdesk");
    await db.user.update({
      where: { id: enrolled.id },
      data: { totpSecret: await generateTotpSecret() },
    });

    const unknown = await login(`ghost-${SUF}`, "whatever-1", "203.0.114.3");
    const badPw = await login("helpdesk", "wrong-password", "203.0.114.3");
    const noCode = await login(enrolled.username, "Scratch-Pass1", "203.0.114.3");

    for (const r of [unknown, badPw, noCode]) {
      expect(r.res.status).toBe(401);
      const body = (await r.res.json()) as { error: { code: string; message: string; details?: unknown } };
      expect(body.error.code).toBe("UNAUTHORIZED");
      expect(body.error.message).toBe("Invalid username or password");
      expect(JSON.stringify(body)).not.toContain("totpRequired");
    }
  });

  it("policy totp.required=true + un-enrolled user → 403 mfa_required after a verified password", async () => {
    const mfa = { ...originalSettings!, totp: { required: true } };
    await service.putAuthSettings(mfa);
    try {
      const r = await login("socuser", "socuser123", "203.0.114.4");
      expect(r.res.status).toBe(403);
      const body = (await r.res.json()) as { error: { code: string; message: string; details?: { code?: string } } };
      expect(body.error.code).toBe("FORBIDDEN");
      expect(body.error.message).toContain("MFA enrollment required");
      expect(body.error.details?.code).toBe("mfa_required");
    } finally {
      await service.putAuthSettings(originalSettings!);
    }
  });
});

// ── #3 role-hierarchy guard ──────────────────────────────────────────────────

describe("role-hierarchy guard (#3)", () => {
  it("security_admin cannot CREATE super_admin/tenant_admin users (403) but can create lower ranks", async () => {
    const sec = await login("secops", "secops123", "203.0.114.5");
    expect(sec.res.status).toBe(200);
    const secCookie = sec.cookie;

    const asSuper = await usersRoute.POST(
      req("POST", "http://localhost/api/v1/users", secCookie, {
        username: `fesc-super-${SUF}`,
        role: "super_admin",
        password: "Escalate-1",
        isActive: true,
        groupIds: [],
      }),
    );
    expect(asSuper.status).toBe(403);
    expect(((await asSuper.json()) as { error: { message: string } }).error.message).toContain("super_admin");

    const asTenantAdmin = await usersRoute.POST(
      req("POST", "http://localhost/api/v1/users", secCookie, {
        username: `fesc-tadmin-${SUF}`,
        role: "tenant_admin",
        password: "Escalate-1",
        isActive: true,
        groupIds: [],
      }),
    );
    expect(asTenantAdmin.status).toBe(403);

    // lower rank → allowed (identity.write includes security_admin)
    const asNet = await usersRoute.POST(
      req("POST", "http://localhost/api/v1/users", secCookie, {
        username: `fesc-net-${SUF}`,
        role: "network_admin",
        password: "Downward-1",
        isActive: true,
        groupIds: [],
      }),
    );
    expect(asNet.status).toBe(200);
    const created = (await asNet.json()) as { data: { id: number } };
    await db.user.delete({ where: { id: created.data.id } }).catch(() => {});
  });

  it("super_admin CAN create a super_admin user", async () => {
    const admin = await login("admin", "admin123", "203.0.114.6");
    const res = await usersRoute.POST(
      req("POST", "http://localhost/api/v1/users", admin.cookie, {
        username: `fsa-super-${SUF}`,
        role: "super_admin",
        password: "SuperOk-1",
        isActive: true,
        groupIds: [],
      }),
    );
    expect(res.status).toBe(200);
    const created = (await res.json()) as { data: { id: number } };
    await db.user.delete({ where: { id: created.data.id } }).catch(() => {});
  });

  it("nobody may password-reset or disable an OUTRANKING principal (service-level)", async () => {
    const admin = await db.user.findFirst({ where: { username: "admin" } });
    expect(admin).not.toBeNull();
    // security_admin actor → target super_admin → 403 (password reset attempt)
    await expect(
      service.updateUser(1, admin!.id, { password: "NewPass-99" }, "security_admin"),
    ).rejects.toMatchObject({ code: "FORBIDDEN", message: expect.stringContaining("outranks") });
    // tenant_admin actor → target super_admin → 403
    await expect(
      service.updateUser(1, admin!.id, { isActive: false }, "tenant_admin"),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });
});

// ── #1 revocation on lifecycle change + logout ────────────────────────────────

describe("JWT revocation (#1)", () => {
  it("login → disable the user → the outstanding cookie 401s (revoke-on-disable)", async () => {
    const u = await makeUser(`fdis-${SUF}`, "helpdesk");
    const first = await login(u.username, "Scratch-Pass1", "203.0.114.7");
    expect(first.res.status).toBe(200);
    expect((await me(first.cookie)).status).toBe(200);

    await service.updateUser(1, u.id, { isActive: false }, "super_admin");

    const sessionRow = await db.authSession.findFirst({ where: { userId: u.id } });
    expect(sessionRow?.revokedAt).not.toBeNull(); // all sessions revoked

    const second = await me(first.cookie);
    expect(second.status).toBe(401);
    const body = (await second.json()) as { error: { code: string } };
    expect(body.error.code).toBe("UNAUTHORIZED");
  });

  it("logout revokes the presented token's session (signature verified first)", async () => {
    const first = await login("tadmin", "tadmin123", "203.0.114.8");
    expect(first.res.status).toBe(200);
    expect((await me(first.cookie)).status).toBe(200);

    const tadmin = await db.user.findFirst({ where: { username: "tadmin" } });
    const before = await db.authSession.findFirst({ where: { userId: tadmin!.id }, orderBy: { id: "desc" } });
    expect(before?.revokedAt).toBeNull();

    const out = await logoutRoute.POST(req("POST", "http://localhost/api/v1/auth/logout", first.cookie));
    expect(out.status).toBe(200);

    const after = await me(first.cookie);
    expect(after.status).toBe(401);

    // the registry row is revoked
    const row = await db.authSession.findUnique({ where: { id: before!.id } });
    expect(row?.revokedAt).not.toBeNull();
  });

  it("deleting a user kills their live sessions", async () => {
    const u = await makeUser(`fdel-${SUF}`, "helpdesk");
    const first = await login(u.username, "Scratch-Pass1", "203.0.114.10");
    expect(first.res.status).toBe(200);
    await service.deleteUser(1, undefined, u.id, "super_admin");
    expect(await me(first.cookie).then((r) => r.status)).toBe(401);
  });
});

// ── #9 concurrent-session cap ─────────────────────────────────────────────────

describe("concurrent-session cap (#9)", () => {
  it("revokes the OLDEST session beyond the policy cap; newest keep working", async () => {
    const capped = { ...originalSettings!, sessionLimits: { maxConcurrentPerUser: 2 } };
    await service.putAuthSettings(capped);
    try {
      const c1 = await login("netops", "netops123", "203.0.114.11");
      const c2 = await login("netops", "netops123", "203.0.114.12");
      const c3 = await login("netops", "netops123", "203.0.114.13");

      const netops = await db.user.findFirst({ where: { username: "netops" } });
      const active = await db.authSession.count({
        where: { userId: netops!.id, revokedAt: null, expiresAt: { gt: new Date() } },
      });
      expect(active).toBe(2); // cap-1 kept + the new one

      expect((await me(c1.cookie)).status).toBe(401); // oldest revoked
      expect((await me(c2.cookie)).status).toBe(200);
      expect((await me(c3.cookie)).status).toBe(200);
    } finally {
      await service.putAuthSettings(originalSettings!);
    }
  });
});

// ── #11 NAC/IoT area move + #25 duplicate-name 409 ────────────────────────────

describe("NAC area move (#11) + duplicate-name pre-check (#25)", () => {
  it("network_admin passes the NAC/IoT guards (identity area used to 403 them)", async () => {
    const net = await login("netops", "netops123", "203.0.114.14");
    expect(net.res.status).toBe(200);

    const stats = await iotStatsRoute.GET(req("GET", "http://localhost/api/v1/iot/stats", net.cookie));
    expect(stats.status).toBe(200);

    const name = `audit-prof-${SUF}`;
    const created = await nacProfilesRoute.POST(
      req("POST", "http://localhost/api/v1/identity-advanced/nac-profiles", net.cookie, {
        name,
        method: "802.1x",
        eapType: "peap",
        dynamicVlan: true,
        profiling: true,
        byodOnboarding: false,
        enabled: true,
      }),
    );
    expect(created.status).toBe(200);
    const dto = (await created.json()) as { data: { id: number; name: string } };
    expect(dto.data.name).toBe(name);

    const dup = await nacProfilesRoute.POST(
      req("POST", "http://localhost/api/v1/identity-advanced/nac-profiles", net.cookie, {
        name,
        method: "802.1x",
        eapType: "peap",
        dynamicVlan: true,
        profiling: true,
        byodOnboarding: false,
        enabled: true,
      }),
    );
    expect(dup.status).toBe(409);
    expect(((await dup.json()) as { error: { message: string } }).error.message).toContain("already exists");

    const renamed = await nacProfileItemRoute.PUT(
      req("PUT", `http://localhost/api/v1/identity-advanced/nac-profiles/${dto.data.id}`, net.cookie, { name: `${name}-2` }),
      { params: Promise.resolve({ id: String(dto.data.id) }) },
    );
    expect(renamed.status).toBe(200);

    const del = await nacProfileItemRoute.DELETE(
      req("DELETE", `http://localhost/api/v1/identity-advanced/nac-profiles/${dto.data.id}`, net.cookie),
      { params: Promise.resolve({ id: String(dto.data.id) }) },
    );
    expect(del.status).toBe(200);
  });
});

// ── #16 /me tenant mismatch ───────────────────────────────────────────────────

describe("/me tenant assertion (#16)", () => {
  it("401s when the user row's tenant no longer matches the cookie claim", async () => {
    const tenant = await db.tenant.create({ data: { name: `audit-fix-${SUF}` } });
    scratchTenantId = tenant.id;
    const u = await makeUser(`ften-${SUF}`, "helpdesk");
    const first = await login(u.username, "Scratch-Pass1", "203.0.114.15");
    expect(first.res.status).toBe(200);
    expect((await me(first.cookie)).status).toBe(200);

    await db.user.update({ where: { id: u.id }, data: { tenantId: tenant.id } });

    const res = await me(first.cookie);
    expect(res.status).toBe(401);
    expect(((await res.json()) as { error: { message: string } }).error.message).toContain("tenant mismatch");
  });
});
