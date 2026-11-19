/**
 * Multi-Site Central Manager route tests (Phase 4 §4.1) — exercises the
 * /api/v1/sites/* handlers END-TO-END over a per-run copy of the pushed dev
 * schema (same harness as the portal persistence tests, which established
 * it; the incidents suite reuses it for service-level coverage):
 *   • site CRUD: register (unique per-tenant names), status/role/q list
 *     filters with pagination, patch (endpoint/version/status/limits),
 *     delete,
 *   • push: happy path records a `pushing` → `applied` SiteDeployment with
 *     pushedAt/appliedAt (simulated transport — remote push is out of scope);
 *     a site that has never connected fails with "site has never connected";
 *     template/firmware pushes validate their kind-specific refs,
 *   • template CRUD with the JSON-payload-object validation failure,
 *   • firmware catalog: sha256 must be exactly 64 hex chars, per-channel
 *     uniqueness,
 *   • stats endpoint (totals by status, per-role counts, deployments 7d),
 *   • deployment pagination + siteId/kind/status filters.
 *
 * Authenticated calls use a signed session cookie (tenant_admin) — the
 * route() wrapper enforces the "sites" RBAC area exactly as it does in
 * production. Modules are imported AFTER the DATABASE_URL override — static
 * imports would resolve the Prisma datasource too early.
 */

import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { NextRequest } from "next/server";

const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "sites-"));
const DB_PATH = path.join(TMP_DIR, "sites-test.db");
fs.copyFileSync(path.resolve(process.cwd(), "db/cryptsk.db"), DB_PATH);
process.env.DATABASE_URL = `file:${DB_PATH}`;

const { db } = await import("@/lib/db");
const { signSession, SESSION_COOKIE } = await import("@/lib/auth/jwt");
const sessionStore = await import("@/lib/auth/session-store");

const sitesRoute = await import("@/app/api/v1/sites/route");
const siteIdRoute = await import("@/app/api/v1/sites/[id]/route");
const pushRoute = await import("@/app/api/v1/sites/[id]/push/route");
const deploymentsRoute = await import("@/app/api/v1/sites/deployments/route");
const templatesRoute = await import("@/app/api/v1/sites/templates/route");
const templateIdRoute = await import("@/app/api/v1/sites/templates/[id]/route");
const firmwareRoute = await import("@/app/api/v1/sites/firmware/route");
const statsRoute = await import("@/app/api/v1/sites/stats/route");

// signSession now returns { token, jti, expiresAt } and the authenticate path
// requires the jti to be registered in the AuthSession registry (audit fix #1)
const SIGNED = await signSession({ sub: "1", username: "sites-admin", role: "tenant_admin", tenantId: 1 });
const TOKEN = SIGNED.token;
await sessionStore.createAuthSession({
  jti: SIGNED.jti,
  userId: 1,
  tenantId: 1,
  ip: "203.0.113.10",
  userAgent: "vitest",
  expiresAt: SIGNED.expiresAt,
});

type Res = { status: number; body: Record<string, unknown> };

function req(method: string, path: string, body?: unknown): NextRequest {
  return new NextRequest(`http://localhost/api/v1/sites${path}`, {
    method,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    headers: {
      "content-type": "application/json",
      cookie: `${SESSION_COOKIE}=${TOKEN}`,
      "x-forwarded-for": "203.0.113.10",
    },
  });
}

function json(res: Response): Promise<Record<string, unknown>> {
  return res.json() as Promise<Record<string, unknown>>;
}

async function callSites(method: "GET" | "POST", path: string, body?: unknown): Promise<Res> {
  const res = method === "POST" ? await sitesRoute.POST(req(method, path, body)) : await sitesRoute.GET(req(method, path));
  return { status: res.status, body: await json(res) };
}

function withParams(method: string, path: string, body?: unknown): NextRequest {
  return req(method, path, body);
}

async function callSiteId(method: "GET" | "PATCH" | "DELETE", id: number | string, body?: unknown): Promise<Res> {
  const r = withParams(method, `/${id}`, body);
  const res =
    method === "GET"
      ? await siteIdRoute.GET(r, { params: Promise.resolve({ id: String(id) }) })
      : method === "PATCH"
        ? await siteIdRoute.PATCH(r, { params: Promise.resolve({ id: String(id) }) })
        : await siteIdRoute.DELETE(r, { params: Promise.resolve({ id: String(id) }) });
  return { status: res.status, body: await json(res) };
}

async function callPush(id: number | string, body: Record<string, unknown>): Promise<Res> {
  const res = await pushRoute.POST(withParams("POST", `/${id}/push`, body), {
    params: Promise.resolve({ id: String(id) }),
  });
  return { status: res.status, body: await json(res) };
}

async function callDeployments(path: string): Promise<Res> {
  const res = await deploymentsRoute.GET(req("GET", path));
  return { status: res.status, body: await json(res) };
}

async function callTemplates(method: "GET" | "POST", body?: unknown): Promise<Res> {
  const res = method === "POST" ? await templatesRoute.POST(req(method, "", body)) : await templatesRoute.GET(req(method, ""));
  return { status: res.status, body: await json(res) };
}

async function callTemplateId(method: "GET" | "PATCH" | "DELETE", id: number | string, body?: unknown): Promise<Res> {
  const r = withParams(method, `/templates/${id}`, body);
  const res =
    method === "GET"
      ? await templateIdRoute.GET(r, { params: Promise.resolve({ id: String(id) }) })
      : method === "PATCH"
        ? await templateIdRoute.PATCH(r, { params: Promise.resolve({ id: String(id) }) })
        : await templateIdRoute.DELETE(r, { params: Promise.resolve({ id: String(id) }) });
  return { status: res.status, body: await json(res) };
}

async function callFirmware(method: "GET" | "POST", body?: unknown): Promise<Res> {
  const res = method === "POST" ? await firmwareRoute.POST(req(method, "", body)) : await firmwareRoute.GET(req(method, ""));
  return { status: res.status, body: await json(res) };
}

async function callStats(): Promise<Res> {
  const res = await statsRoute.GET(req("GET", "/stats"));
  return { status: res.status, body: await json(res) };
}

async function createSite(over: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
  const res = await callSites("POST", "", { name: `site-${Math.random().toString(36).slice(2, 8)}`, ...over });
  expect(res.status).toBe(200);
  return res.body.data as Record<string, unknown>;
}

async function pushOk(siteId: number, body: Record<string, unknown>): Promise<Record<string, unknown>> {
  const res = await callPush(siteId, body);
  expect(res.status).toBe(200);
  return res.body.data as Record<string, unknown>;
}

beforeAll(async () => {
  // the copied dev schema has no tenant rows — site rows FK to tenants
  await db.tenant.upsert({ where: { id: 1 }, update: {}, create: { id: 1, name: "sites-test" } });
});

beforeEach(async () => {
  await db.siteDeployment.deleteMany({});
  await db.managedSite.deleteMany({});
  await db.siteTemplate.deleteMany({});
  await db.firmwareCatalog.deleteMany({});
});

afterAll(async () => {
  await db.$disconnect();
  fs.rmSync(TMP_DIR, { recursive: true, force: true });
});

const SHA = "a".repeat(64);

// ── site CRUD ───────────────────────────────────────────────────────────────

describe("site CRUD (POST/GET/PATCH/DELETE /api/v1/sites)", () => {
  it("registers a site, enforces unique names, lists with filters and pagination", async () => {
    const hq = await createSite({ name: "hq", region: "eu-central", role: "hub", publicEndpoint: "hq.corp.example:8443" });
    expect(hq.status).toBe("never_seen");
    expect(hq.role).toBe("hub");
    expect(hq.resourceLimits).toEqual({});
    expect(hq.lastSeenAt).toBeNull();

    // per-tenant name uniqueness
    const dup = await callSites("POST", "", { name: "hq", role: "spoke" });
    expect(dup.status).toBe(409);
    expect((dup.body.error as { code: string }).code).toBe("CONFLICT");

    await createSite({ name: "branch-1", role: "spoke", status: "online" });
    await createSite({ name: "lab", region: "us-east" });

    const all = await callSites("GET", "?page=1&limit=2");
    expect(all.status).toBe(200);
    expect(all.body.meta).toMatchObject({ page: 1, limit: 2, total: 3, totalPages: 2 });

    const onlineOnly = await callSites("GET", "?status=online");
    expect((onlineOnly.body.data as Array<{ name: string }>).map((s) => s.name)).toEqual(["branch-1"]);

    const hubOnly = await callSites("GET", "?role=hub");
    expect((hubOnly.body.data as Array<{ name: string }>).map((s) => s.name)).toEqual(["hq"]);

    const qSearch = await callSites("GET", "?q=eu-central");
    expect((qSearch.body.data as Array<{ name: string }>).map((s) => s.name)).toEqual(["hq"]);

    const none = await callSites("GET", "?status=degraded");
    expect(none.body.data).toEqual([]);
    expect(none.body.meta).toMatchObject({ total: 0, totalPages: 1 });

    void hq;
  });

  it("patches endpoint/version/status/limits and deletes the site (404 afterwards)", async () => {
    const site = await createSite({ name: "edge-1" });
    const id = site.id as number;

    const bad = await callSiteId("PATCH", id, {});
    expect(bad.status).toBe(400);
    expect((bad.body.error as { code: string }).code).toBe("VALIDATION_ERROR");

    const badEndpoint = await callSiteId("PATCH", id, { publicEndpoint: "no-port-given" });
    expect(badEndpoint.status).toBe(400);

    const patched = await callSiteId("PATCH", id, {
      status: "online",
      version: "3.1.4",
      publicEndpoint: "edge.corp.example:8443",
      resourceLimits: { maxRules: 500, maxCpuPct: 80 },
    });
    expect(patched.status).toBe(200);
    expect(patched.body.data).toMatchObject({ status: "online", version: "3.1.4" });
    expect((patched.body.data as { resourceLimits: Record<string, unknown> }).resourceLimits).toEqual({
      maxRules: 500,
      maxCpuPct: 80,
    });

    const detail = await callSiteId("GET", id);
    expect(detail.status).toBe(200);
    expect((detail.body.data as { id: number }).id).toBe(id);

    const del = await callSiteId("DELETE", id);
    expect(del.status).toBe(200);
    expect(del.body.data).toEqual({ ok: true });

    const gone = await callSiteId("GET", id);
    expect(gone.status).toBe(404);
    expect((gone.body.error as { code: string }).code).toBe("NOT_FOUND");

    const invalidId = await callSiteId("GET", "not-a-number");
    expect(invalidId.status).toBe(400);
  });
});

// ── push ────────────────────────────────────────────────────────────────────

describe("POST /api/v1/sites/[id]/push (simulated transport)", () => {
  it("applies a policy push on a connected site (pushed → applied with timestamps)", async () => {
    const site = await createSite({ name: "edge-online", status: "online" });
    const dep = (await pushOk(site.id as number, {
      kind: "policy",
      payload: { allowCidrs: ["10.0.0.0/8"] },
    })) as Record<string, unknown> & { result: { applied: string[]; errors: string[] } };

    expect(dep.status).toBe("applied");
    expect(dep.kind).toBe("policy");
    expect(dep.siteId).toBe(site.id);
    expect(dep.pushedAt).toBeTruthy();
    expect(dep.appliedAt).toBeTruthy();
    expect(dep.result.applied).toEqual(["policy bundle"]);
    expect(dep.result.errors).toEqual([]);
    expect(dep.payload).toEqual({ allowCidrs: ["10.0.0.0/8"] });

    // the deployment row is persisted with the pushed payload
    const row = await db.siteDeployment.findFirstOrThrow({ where: { siteId: site.id as number } });
    expect(row.status).toBe("applied");
    expect(JSON.parse(row.payload)).toEqual({ allowCidrs: ["10.0.0.0/8"] });
  });

  it("fails the push for a site that has never connected", async () => {
    const site = await createSite({ name: "branch-never" });
    const dep = (await pushOk(site.id as number, { kind: "policy" })) as Record<string, unknown> & {
      result: { applied: string[]; errors: string[] };
    };
    expect(dep.status).toBe("failed");
    expect(dep.result.errors).toEqual(["site has never connected"]);
    expect(dep.result.applied).toEqual([]);
    expect(dep.pushedAt).toBeTruthy();
    expect(dep.appliedAt).toBeNull();
  });

  it("validates kind-specific refs (template bundle / catalog firmware) and unknown sites", async () => {
    const site = await createSite({ name: "edge-validate", status: "online" });

    const noTemplate = await callPush(site.id as number, { kind: "template" });
    expect(noTemplate.status).toBe(400);
    expect(JSON.stringify(noTemplate.body.error)).toContain("templateId");

    const noVersion = await callPush(site.id as number, { kind: "firmware" });
    expect(noVersion.status).toBe(400);
    expect(JSON.stringify(noVersion.body.error)).toContain("firmwareVersion");

    const unknownSite = await callPush(424_242, { kind: "policy" });
    expect(unknownSite.status).toBe(404);

    const unknownTemplate = await callPush(site.id as number, { kind: "template", templateId: 987_654 });
    expect(unknownTemplate.status).toBe(404);

    const unknownFirmware = await callPush(site.id as number, { kind: "firmware", firmwareVersion: "9.9.9" });
    expect(unknownFirmware.status).toBe(404);

    const badKind = await callPush(site.id as number, { kind: " zones" });
    expect(badKind.status).toBe(400);
  });

  it("pushes a template bundle (payload snapshot + templateId) and stamps the site version on firmware", async () => {
    const tpl = await callTemplates("POST", { name: "baseline", version: "2", payload: { firewallRules: ["deny-all"] } });
    expect(tpl.status).toBe(200);
    const tplId = (tpl.body.data as { id: number }).id;

    const site = await createSite({ name: "branch-template", status: "online" });
    const dep = (await pushOk(site.id as number, { kind: "template", templateId: tplId })) as Record<string, unknown> & {
      templateId: number | null;
      payload: Record<string, unknown>;
      result: { applied: string[] };
    };
    expect(dep.status).toBe("applied");
    expect(dep.templateId).toBe(tplId);
    expect(dep.payload.templateName).toBe("baseline");
    expect(dep.payload.templateVersion).toBe("2");
    expect(dep.payload.bundle).toEqual({ firewallRules: ["deny-all"] });
    expect(dep.result.applied[0]).toContain("baseline");

    await firmwareRoute.POST(req("POST", "", { version: "3.2.0", sha256: SHA, releaseNotes: "tls 1.3 hardening" }));
    const fwDep = (await pushOk(site.id as number, { kind: "firmware", firmwareVersion: "3.2.0" })) as Record<string, unknown> & {
      payload: Record<string, unknown>;
    };
    expect(fwDep.status).toBe("applied");
    expect(fwDep.payload.firmwareVersion).toBe("3.2.0");
    // successful firmware apply stamps the reported console version
    const after = await callSiteId("GET", site.id as number);
    expect((after.body.data as { version: string }).version).toBe("3.2.0");
  });
});

// ── templates ───────────────────────────────────────────────────────────────

describe("site template CRUD (/api/v1/sites/templates)", () => {
  it("creates, lists, patches and deletes templates; rejects non-object payloads", async () => {
    const created = await callTemplates("POST", {
      name: "branch-baseline",
      description: "standard branch config",
      version: "1",
      payload: { firewallRules: [{ action: "deny" }], dnsPolicies: [] },
    });
    expect(created.status).toBe(200);
    const tpl = created.body.data as { id: number; payload: Record<string, unknown>; version: string };
    expect(tpl.payload).toEqual({ firewallRules: [{ action: "deny" }], dnsPolicies: [] });
    expect(tpl.version).toBe("1");

    // payload must be a JSON OBJECT — a string (or any non-object) is a 400
    const stringPayload = await callTemplates("POST", { name: "bad-tpl", payload: "not-an-object" });
    expect(stringPayload.status).toBe(400);
    expect((stringPayload.body.error as { code: string }).code).toBe("VALIDATION_ERROR");
    expect(JSON.stringify(stringPayload.body.error)).toContain("payload");

    const dup = await callTemplates("POST", { name: "branch-baseline" });
    expect(dup.status).toBe(409);

    const patched = await callTemplateId("PATCH", tpl.id, { version: "2", payload: { natRules: [] } });
    expect(patched.status).toBe(200);
    expect((patched.body.data as { version: string; payload: Record<string, unknown> }).version).toBe("2");
    expect((patched.body.data as { payload: Record<string, unknown> }).payload).toEqual({ natRules: [] });

    const listed = await callTemplates("GET");
    expect((listed.body.data as Array<{ id: number }>).map((t) => t.id)).toContain(tpl.id);

    const detail = await callTemplateId("GET", tpl.id);
    expect(detail.status).toBe(200);

    const del = await callTemplateId("DELETE", tpl.id);
    expect(del.status).toBe(200);
    expect(del.body.data).toEqual({ ok: true });

    const gone = await callTemplateId("GET", tpl.id);
    expect(gone.status).toBe(404);
  });
});

// ── firmware catalog ────────────────────────────────────────────────────────

describe("firmware catalog (/api/v1/sites/firmware)", () => {
  it("rejects malformed sha256, accepts 64-hex digests and enforces per-channel uniqueness", async () => {
    const short = await callFirmware("POST", { version: "3.2.0", sha256: "deadbeef" });
    expect(short.status).toBe(400);
    expect(JSON.stringify(short.body.error)).toContain("sha256");

    const nonHex = await callFirmware("POST", { version: "3.2.0", sha256: "z".repeat(64) });
    expect(nonHex.status).toBe(400);

    const created = await callFirmware("POST", {
      version: "3.2.0",
      sha256: SHA,
      releaseNotes: "initial catalog entry",
    });
    expect(created.status).toBe(200);
    const fw = created.body.data as { id: number; sha256: string; channel: string; releasedAt: string | null };
    expect(fw.sha256).toBe(SHA);
    expect(fw.channel).toBe("stable");
    expect(fw.releasedAt).toBeTruthy();

    const sameChannel = await callFirmware("POST", { version: "3.2.0", sha256: SHA });
    expect(sameChannel.status).toBe(409);

    const otherChannel = await callFirmware("POST", { version: "3.2.0", channel: "beta", sha256: "b".repeat(64) });
    expect(otherChannel.status).toBe(200);

    const listed = await callFirmware("GET");
    expect(listed.status).toBe(200);
    expect((listed.body.data as Array<{ version: string; channel: string }>).map((r) => `${r.channel}@${r.version}`).sort()).toEqual([
      "beta@3.2.0",
      "stable@3.2.0",
    ]);
  });
});

// ── stats ───────────────────────────────────────────────────────────────────

describe("GET /api/v1/sites/stats", () => {
  it("aggregates totals by status, per-role counts and deployments in the last 7 days", async () => {
    const hub = await createSite({ name: "s-hub", role: "hub", status: "online" });
    await createSite({ name: "s-spoke", role: "spoke", status: "degraded" });
    const lonely = await createSite({ name: "s-lonely", role: "standalone" });

    await pushOk(hub.id as number, { kind: "policy" });
    await pushOk(lonely.id as number, { kind: "policy" });

    const stats = await callStats();
    expect(stats.status).toBe(200);
    const data = stats.body.data as {
      total: number;
      byStatus: Record<string, number>;
      byRole: Record<string, number>;
      deployments7d: number;
    };
    expect(data.total).toBe(3);
    expect(data.byStatus).toEqual({ online: 1, offline: 0, degraded: 1, never_seen: 1 });
    expect(data.byRole).toEqual({ hub: 1, spoke: 1, standalone: 1 });
    expect(data.deployments7d).toBe(2);
  });
});

// ── deployments ─────────────────────────────────────────────────────────────

describe("GET /api/v1/sites/deployments (pagination + filters)", () => {
  it("paginates the deployment history and filters by siteId/kind/status", async () => {
    const site = await createSite({ name: "edge-busy", status: "online" });
    for (let i = 0; i < 5; i++) {
      await pushOk(site.id as number, { kind: "policy" });
    }

    const page1 = await callDeployments("?page=1&limit=2");
    expect(page1.status).toBe(200);
    expect(page1.body.meta).toMatchObject({ page: 1, limit: 2, total: 5, totalPages: 3 });
    expect(page1.body.data).toHaveLength(2);

    const page3 = await callDeployments("?page=3&limit=2");
    expect((page3.body.data as unknown[]).length).toBe(1);

    const emptyPage = await callDeployments("?page=9&limit=2");
    expect(emptyPage.body.data).toEqual([]);
    expect(emptyPage.body.meta).toMatchObject({ total: 5, totalPages: 3 });

    const bySite = await callDeployments(`?siteId=${site.id}&limit=100`);
    expect(bySite.body.meta).toMatchObject({ total: 5 });

    const other = await createSite({ name: "edge-quiet", status: "online" });
    await pushOk(other.id as number, { kind: "policy" });
    const otherOnly = await callDeployments(`?siteId=${other.id}`);
    expect(otherOnly.body.meta).toMatchObject({ total: 1 });
    expect((otherOnly.body.data as Array<{ siteName: string }>)[0].siteName).toBe("edge-quiet");

    const never = await createSite({ name: "edge-never" });
    await pushOk(never.id as number, { kind: "policy" });
    const failedOnly = await callDeployments("?status=failed");
    expect(failedOnly.body.meta).toMatchObject({ total: 1 });
    const failedRow = (failedOnly.body.data as Array<{ result: { errors: string[] } }>)[0];
    expect(failedRow.result.errors).toEqual(["site has never connected"]);

    const kindOnly = await callDeployments("?kind=policy&limit=100");
    expect(kindOnly.body.meta).toMatchObject({ total: 7 });

    const none = await callDeployments("?kind=firmware");
    expect(none.body.meta).toMatchObject({ total: 0 });
  });
});

// ── stuck-push sweep (audit fix F-d) ────────────────────────────────────────

describe("stuck `pushing` sweep (audit fix F-d)", () => {
  it("sweeps deployments wedged in pushing >10min to failed on listSites", async () => {
    const site = await createSite({ name: "edge-wedge", status: "online" });
    // simulate a crashed transport: a deployment stuck in `pushing` since 11 min ago
    const wedged = await db.siteDeployment.create({
      data: {
        tenantId: 1,
        siteId: site.id as number,
        kind: "policy",
        status: "pushing",
        payload: "{}",
        result: "{}",
        pushedAt: new Date(Date.now() - 11 * 60_000),
      },
    });

    const res = await callSites("GET", "?limit=100");
    expect(res.status).toBe(200);

    const after = await db.siteDeployment.findUniqueOrThrow({ where: { id: wedged.id } });
    expect(after.status).toBe("failed");
    const result = JSON.parse(after.result) as { errors: string[] };
    expect(result.errors[0]).toContain("stuck in 'pushing'");

    // and a FRESH `pushing` row is left alone (the sweep is age-gated)
    const fresh = await db.siteDeployment.create({
      data: { tenantId: 1, siteId: site.id as number, kind: "policy", status: "pushing", payload: "{}", result: "{}", pushedAt: new Date() },
    });
    await callSites("GET", "?limit=100");
    const freshAfter = await db.siteDeployment.findUniqueOrThrow({ where: { id: fresh.id } });
    expect(freshAfter.status).toBe("pushing");
  });
});
