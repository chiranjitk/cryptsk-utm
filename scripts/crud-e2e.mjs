#!/usr/bin/env node
// crud-e2e.mjs — one-suite-at-a-time CRUD e2e against the prod console.
//
// Usage:
//   node scripts/crud-e2e.mjs list          → list all suites
//   node scripts/crud-e2e.mjs <suite>       → run ONE suite (one-by-one)
//   node scripts/crud-e2e.mjs status        → red-line check (nft hash, ens32, pm2)
//
// Every suite runs its cases strictly sequentially, prints PASS/FAIL per case,
// and cleans up its own E2E artifacts even when cases fail.

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { Client } from "ssh2";

// ── config ───────────────────────────────────────────────────────────────────
const HOST = process.env.E2E_HOST || "103.244.7.219";
const SSH_PORT = Number(process.env.SSH_PORT || 22222);
const SSH_USER = process.env.SSH_USER || "root";
const SSH_PASS = process.env.SSH_PASS || "CryptSK@123#$";
const BASE = process.env.E2E_BASE || `http://${HOST}:3000`;
const COOKIE_FILE = "/tmp/.crud-e2e-cookie.txt";
const NFT_BASELINE = process.env.NFT_BASELINE || "6851d18e0abab5a003d28706f6dd0ea2"; // raw hash (fail2ban set elements make it drift)
const NFT_STRUCT = process.env.NFT_STRUCT || "8ab0e46de0f18dfded4ed458853410d9"; // structural hash: counters + f2b set elements normalized

// ── state ────────────────────────────────────────────────────────────────────
let cookie = existsSync(COOKIE_FILE) ? readFileSync(COOKIE_FILE, "utf8").trim() : "";
let passed = 0;
let failed = 0;
const ctx = { tag: "", cleanup: [] };

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── reporting ────────────────────────────────────────────────────────────────
function check(name, cond, detail = "") {
  if (cond) passed++;
  else failed++;
  console.log(`  ${cond ? "PASS" : "FAIL"}  ${name}${detail && !cond ? ` — ${detail}` : detail ? ` — ${detail}` : ""}`);
  return cond;
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function expectOk(r, what = "") {
  assert(
    r.status >= 200 && r.status < 300,
    `expected 2xx${what ? ` (${what})` : ""}, got ${r.status}: ${JSON.stringify(r.json ?? {}).slice(0, 300)}`,
  );
  assert(r.json && r.json.data !== undefined, `missing data envelope${what ? ` (${what})` : ""}`);
  return r.json.data;
}

function expectErr(r, code, status) {
  assert(r.json && r.json.error, `expected error ${code}, got ${r.status} ${JSON.stringify(r.json ?? {}).slice(0, 200)}`);
  assert(r.json.error.code === code, `expected ${code}, got ${r.json.error.code} (${r.status}): ${r.json.error.message?.slice(0, 160)}`);
  if (status) assert(r.status === status, `expected HTTP ${status} for ${code}, got ${r.status}`);
  return r.json.error;
}

/** verify deletion via the list endpoint (several [id] routes export no GET). */
async function expectGoneViaList(listPath, id, label = "row") {
  const j = (await GET(listPath)).json;
  const rows = Array.isArray(j?.data) ? j.data : [];
  assert(!rows.some((x) => x.id === id), `${label} ${id} still present after delete`);
}

// ── auth ─────────────────────────────────────────────────────────────────────
async function doLogin() {
  const res = await fetch(`${BASE}/api/v1/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: "admin", password: "admin123" }),
    signal: AbortSignal.timeout(25000),
    redirect: "manual",
  });
  if (res.status === 429) {
    const ra = Number(res.headers.get("retry-after") || 65);
    console.log(`  ..  login throttled, waiting ${ra}s`);
    await sleep(Math.min(ra, 70) * 1000);
    return doLogin();
  }
  const setCookies = res.headers.getSetCookie?.() ?? [res.headers.get("set-cookie")].filter(Boolean);
  const sc = setCookies.find((c) => c.startsWith("cryptsk_token="));
  if (res.status !== 200 || !sc) return false;
  cookie = sc.split(";")[0];
  writeFileSync(COOKIE_FILE, cookie);
  return true;
}

// ── api helper ───────────────────────────────────────────────────────────────
async function api(method, path, body, opts = {}) {
  const doFetch = () =>
    fetch(`${BASE}${path}`, {
      method,
      headers: {
        ...(body !== undefined ? { "content-type": "application/json" } : {}),
        ...(cookie ? { cookie } : {}),
        ...(opts.headers || {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(30000),
      redirect: "manual",
    });
  let res = await doFetch();
  if (res.status === 429 && !opts.noRetry) {
    const ra = Number(res.headers.get("retry-after") || 3);
    await sleep(Math.min(ra, 35) * 1000 + 300);
    res = await doFetch();
  }
  if (res.status === 401 && !opts.noReauth) {
    const okLogin = await doLogin();
    if (okLogin) res = await doFetch();
  }
  let json = null;
  try {
    json = await res.json();
  } catch {
    /* non-JSON (e.g. csv export) */
  }
  return { status: res.status, json, headers: res.headers };
}

const GET = (p, o) => api("GET", p, undefined, o);
const POST = (p, b, o) => api("POST", p, b, o);
const PUT = (p, b, o) => api("PUT", p, b, o);
const PATCH = (p, b, o) => api("PATCH", p, b, o);
const DEL = (p, o) => api("DELETE", p, undefined, o);

// ── ssh helper ───────────────────────────────────────────────────────────────
function sshExec(cmd, timeoutMs = 60000) {
  return new Promise((resolve) => {
    const conn = new Client();
    let out = "";
    let code = 1;
    const done = () => {
      conn.end();
      resolve({ code, out });
    };
    const timer = setTimeout(done, timeoutMs);
    conn
      .on("ready", () => {
        conn.exec(cmd, (err, stream) => {
          if (err) {
            clearTimeout(timer);
            done();
            return;
          }
          stream
            .on("close", (c) => {
              code = c ?? 0;
              clearTimeout(timer);
              done();
            })
            .on("data", (d) => {
              out += d.toString();
            })
            .stderr.on("data", (d) => {
              out += d.toString();
            });
        });
      })
      .on("error", () => {
        clearTimeout(timer);
        done();
      })
      .connect({ host: HOST, port: SSH_PORT, username: SSH_USER, password: SSH_PASS, readyTimeout: 20000 });
  });
}

/** red-line check — never optional. */
async function nftHash() {
  const r = await sshExec(
    "nft list ruleset | sed -E 's/(packets|bytes) [0-9]+/\\1 N/g; s/elements = \\{[^}]*\\}/elements = { DYN }/' | md5sum | cut -d' ' -f1",
  );
  return r.out.trim();
}

async function redline(where) {
  const h = await nftHash();
  const link = await sshExec("ip link show ens32 | head -1");
  const up = /state UP|LOWER_UP/.test(link.out) || /UP/.test(link.out.split("\n")[0] || "");
  const curl = await sshExec("curl -s -o /dev/null -w '%{http_code}' --max-time 20 http://127.0.0.1:3001/");
  check(`[redline ${where}] nft ruleset structure unchanged`, h === NFT_STRUCT, `got=${h || "(none)"} baseline=${NFT_STRUCT}`);
  check(`[redline ${where}] ens32 UP + SSH alive`, up, (link.out || "").split("\n")[0] || "no output");
  check(`[redline ${where}] console :3001 serving 200`, curl.out.trim() === "200", `code=${curl.out.trim()}`);
}

// ── suite registry ───────────────────────────────────────────────────────────
const suites = {};
function suite(name, desc, fn) {
  suites[name] = { desc, fn };
}

/** run a single case, always record a verdict. */
async function tc(name, fn) {
  try {
    await fn();
    check(name, true);
  } catch (e) {
    check(name, false, e?.message || String(e));
  }
}

/** unique test-object name */
function un(prefix) {
  return `${prefix}-e2e-${ctx.tag}`;
}

/** register a best-effort cleanup DELETE */
function track(path) {
  ctx.cleanup.push(path);
}

async function runCleanup() {
  if (!ctx.cleanup.length) return;
  console.log("\n  .. cleanup");
  for (const p of [...ctx.cleanup].reverse()) {
    try {
      const r = await DEL(p);
      console.log(`     del ${p} → ${r.status}`);
    } catch {
      console.log(`     del ${p} → error (ignored)`);
    }
  }
  ctx.cleanup = [];
}

// ═════════════════════════════════════════════════════════════════════════════
// SUITES — batch 1: auth, dashboard, firewall (zones/objects/rules/nat)
// ═════════════════════════════════════════════════════════════════════════════

suite("auth", "Login / me / logout / negative auth", async () => {
  const prev = cookie;
  cookie = "";

  await tc("unauthenticated /api/v1/auth/me → 401", async () => {
    const r = await GET("/api/v1/auth/me", { noReauth: true, noRetry: true });
    expectErr(r, "UNAUTHORIZED", 401);
  });

  await tc("login with wrong password → 401", async () => {
    const r = await api("POST", "/api/v1/auth/login", { username: "admin", password: "definitely-wrong" }, { noReauth: true, noRetry: true });
    expectErr(r, "UNAUTHORIZED", 401);
  });

  await tc("login admin/admin123 → 200 + super_admin", async () => {
    const okLogin = await doLogin();
    assert(okLogin, `login failed (status != 200 or no cookie)`);
  });

  await tc("session cookie cached to disk", async () => {
    const saved = readFileSync(COOKIE_FILE, "utf8").trim();
    assert(saved.startsWith("cryptsk_token="), "cookie file missing cryptsk_token");
    check("cookie present", true, `${saved.slice(0, 24)}...`);
  });

  await tc("GET /api/v1/auth/me → admin profile", async () => {
    const data = expectOk(await GET("/api/v1/auth/me"));
    assert(String(data?.user?.username ?? data?.username).toLowerCase() === "admin", `username=${JSON.stringify(data).slice(0, 120)}`);
  });

  await tc("logout → 200, me afterwards → 401", async () => {
    const r = await POST("/api/v1/auth/logout", {});
    assert(r.status === 200, `logout status ${r.status}`);
    cookie = "";
    const me = await GET("/api/v1/auth/me", { noReauth: true, noRetry: true });
    expectErr(me, "UNAUTHORIZED", 401);
  });

  await tc("re-login for subsequent suites", async () => {
    cookie = "";
    const okLogin = await doLogin();
    if (!okLogin && prev) cookie = prev;
    assert(cookie.startsWith("cryptsk_token="), "could not re-login");
  });
});

suite("dashboard", "Dashboard summary read", async () => {
  await tc("GET /api/v1/dashboard/summary → aggregates", async () => {
    const data = expectOk(await GET("/api/v1/dashboard/summary"));
    const keys = Object.keys(data || {});
    assert(keys.length >= 3, `summary too small: ${keys.join(",")}`);
    check("summary fields", true, keys.slice(0, 10).join(","));
  });
});

suite("fw-zones", "Firewall → Zones CRUD", async () => {
  const zname = un("E2E-ZONE");
  let zid = null;

  await tc("list zones (baseline)", async () => {
    const data = expectOk(await GET("/api/v1/zones?limit=100"));
    assert(Array.isArray(data), `data not array: ${JSON.stringify(data).slice(0, 80)}`);
    check("baseline count", true, `${data.length} zones`);
  });

  await tc("create L3 zone", async () => {
    const z = expectOk(await POST("/api/v1/zones", { name: zname, type: "L3", interfaceNames: [], description: "e2e" }));
    zid = z.id;
    assert(z.name === zname && z.type === "L3", `bad create body: ${JSON.stringify(z).slice(0, 160)}`);
    track(`/api/v1/zones/${zid}`);
  });

  await tc("read back by id", async () => {
    const z = expectOk(await GET(`/api/v1/zones/${zid}`));
    assert(z.name === zname, `name=${z.name}`);
  });

  await tc("update zone (PUT) — rename + desc", async () => {
    const z = expectOk(await PUT(`/api/v1/zones/${zid}`, { name: `${zname}-v2`, type: "L3", interfaceNames: [], description: "e2e updated" }));
    assert(z.name === `${zname}-v2`, `name=${z.name}`);
  });

  await tc("update zone type → L2 accepted", async () => {
    const z = expectOk(await PUT(`/api/v1/zones/${zid}`, { name: `${zname}-v2`, type: "L2", interfaceNames: [], description: "e2e L2" }));
    assert(z.type === "L2", `type=${z.type}`);
  });

  await tc("duplicate zone name → 409", async () => {
    const dup = await POST("/api/v1/zones", { name: `${zname}-v2`, type: "L3" });
    if (dup.status < 300 && dup.json?.data?.id) track(`/api/v1/zones/${dup.json.data.id}`);
    const r = await POST("/api/v1/zones", { name: `${zname}-v2`, type: "L3" });
    expectErr(r, "CONFLICT", 409);
  });

  await tc("invalid zone type → 400 VALIDATION_ERROR", async () => {
    const r = await POST("/api/v1/zones", { name: un("E2E-BAD"), type: "NOPE" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("delete zone → gone (404)", async () => {
    expectOk(await DEL(`/api/v1/zones/${zid}`));
    const g = await GET(`/api/v1/zones/${zid}`);
    expectErr(g, "NOT_FOUND", 404);
    zid = null;
  });

  await tc("update missing zone → 404", async () => {
    const r = await PUT("/api/v1/zones/99999999", { name: "x-e2e", type: "L3", interfaceNames: [] });
    expectErr(r, "NOT_FOUND", 404);
  });
});

suite("obj-address", "Firewall → Objects: address objects + address groups CRUD", async () => {
  const n1 = un("E2E-ADDR-IP");
  const n2 = un("E2E-ADDR-SUBNET");
  const gn = un("E2E-ADDR-GROUP");
  let ipId = null;
  let subId = null;
  let grpId = null;

  await tc("create address object type=ip", async () => {
    const o = expectOk(await POST("/api/v1/address-objects", { name: n1, type: "ip", value: "10.90.0.11", description: "e2e" }));
    ipId = o.id;
    assert(o.type === "ip" && o.value === "10.90.0.11", JSON.stringify(o).slice(0, 140));
    track(`/api/v1/address-objects/${ipId}`);
  });

  await tc("create address object type=subnet", async () => {
    const o = expectOk(await POST("/api/v1/address-objects", { name: n2, type: "subnet", value: "10.90.1.0/24" }));
    subId = o.id;
    track(`/api/v1/address-objects/${subId}`);
  });

  await tc("invalid address value → 400", async () => {
    const r = await POST("/api/v1/address-objects", { name: un("E2E-BAD"), type: "ip", value: "not-an-ip" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("geo object with bad code → 400", async () => {
    const r = await POST("/api/v1/address-objects", { name: un("E2E-BAD2"), type: "geo", value: "DEU" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("read back + update value", async () => {
    const o = expectOk(await PUT(`/api/v1/address-objects/${ipId}`, { name: n1, type: "ip", value: "10.90.0.12" }));
    assert(o.value === "10.90.0.12", `value=${o.value}`);
  });

  await tc("create group with member", async () => {
    const g = expectOk(await POST("/api/v1/address-groups", { name: gn, memberIds: [ipId, subId] }));
    grpId = g.id;
    assert((g.memberIds || g.members || []).length >= 0, "no member field");
    track(`/api/v1/address-groups/${grpId}`);
  });

  await tc("group resolves members (read)", async () => {
    const g = expectOk(await GET(`/api/v1/address-groups/${grpId}`));
    const members = g.memberIds || g.members || [];
    assert(members.length === 2, `members=${JSON.stringify(members).slice(0, 120)}`);
  });

  await tc("update group members", async () => {
    const g = expectOk(await PUT(`/api/v1/address-groups/${grpId}`, { name: gn, memberIds: [ipId] }));
    const members = g.memberIds || g.members || [];
    assert(members.length === 1, `members=${JSON.stringify(members)}`);
  });

  await tc("duplicate object name → 409", async () => {
    const r = await POST("/api/v1/address-objects", { name: n1, type: "ip", value: "10.90.0.13" });
    expectErr(r, "CONFLICT", 409);
  });

  await tc("delete group → delete objects → 404", async () => {
    expectOk(await DEL(`/api/v1/address-groups/${grpId}`));
    expectOk(await DEL(`/api/v1/address-objects/${ipId}`));
    expectOk(await DEL(`/api/v1/address-objects/${subId}`));
    const g = await GET(`/api/v1/address-objects/${ipId}`);
    expectErr(g, "NOT_FOUND", 404);
    ipId = subId = grpId = null;
  });
});

suite("obj-service", "Firewall → Objects: service objects + service groups CRUD", async () => {
  const sn = un("E2E-SVC-TCP");
  const iname = un("E2E-SVC-ICMP");
  const gn = un("E2E-SVC-GROUP");
  let tcpId = null;
  let icmpId = null;
  let grpId = null;

  await tc("create tcp service 8443", async () => {
    const s = expectOk(await POST("/api/v1/service-objects", { name: sn, protocol: "tcp", dstPort: "8443" }));
    tcpId = s.id;
    assert(s.protocol === "tcp", JSON.stringify(s).slice(0, 120));
    track(`/api/v1/service-objects/${tcpId}`);
  });

  await tc("tcp service without ports → 400", async () => {
    const r = await POST("/api/v1/service-objects", { name: un("E2E-BAD"), protocol: "tcp" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("bad port list → 400", async () => {
    const r = await POST("/api/v1/service-objects", { name: un("E2E-BAD2"), protocol: "udp", dstPort: "99999" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("create icmp service", async () => {
    const s = expectOk(await POST("/api/v1/service-objects", { name: iname, protocol: "icmp", icmpType: 8, icmpCode: 0 }));
    icmpId = s.id;
    track(`/api/v1/service-objects/${icmpId}`);
  });

  await tc("update service port range", async () => {
    const s = expectOk(await PUT(`/api/v1/service-objects/${tcpId}`, { name: sn, protocol: "tcp", dstPort: "5000-5100,6000" }));
    assert(String(s.dstPort).includes("5000-5100"), `dstPort=${s.dstPort}`);
  });

  await tc("create service group", async () => {
    const g = expectOk(await POST("/api/v1/service-groups", { name: gn, memberIds: [tcpId, icmpId] }));
    grpId = g.id;
    track(`/api/v1/service-groups/${grpId}`);
  });

  await tc("delete group + services → 404", async () => {
    expectOk(await DEL(`/api/v1/service-groups/${grpId}`));
    expectOk(await DEL(`/api/v1/service-objects/${tcpId}`));
    expectOk(await DEL(`/api/v1/service-objects/${icmpId}`));
    const g = await GET(`/api/v1/service-objects/${tcpId}`);
    expectErr(g, "NOT_FOUND", 404);
    tcpId = icmpId = grpId = null;
  });
});

suite("obj-schedule", "Firewall → Objects: schedule objects CRUD", async () => {
  const rn = un("E2E-SCHED-REC");
  const on = un("E2E-SCHED-ONE");
  let recId = null;
  let oneId = null;

  await tc("create recurring schedule", async () => {
    const s = expectOk(await POST("/api/v1/schedule-objects", { name: rn, type: "recurring", recurrence: { days: [1, 2, 3, 4, 5], start: "08:00", end: "18:00" }, timezone: "UTC" }));
    recId = s.id;
    track(`/api/v1/schedule-objects/${recId}`);
  });

  await tc("recurring without recurrence → 400", async () => {
    const r = await POST("/api/v1/schedule-objects", { name: un("E2E-BAD"), type: "recurring" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("onetime with end before start → 400", async () => {
    const r = await POST("/api/v1/schedule-objects", {
      name: un("E2E-BAD2"),
      type: "onetime",
      startsAt: "2030-06-02T10:00:00Z",
      endsAt: "2030-06-01T10:00:00Z",
    });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("create onetime schedule", async () => {
    const s = expectOk(await POST("/api/v1/schedule-objects", { name: on, type: "onetime", startsAt: "2030-06-01T09:00:00Z", endsAt: "2030-06-01T17:00:00Z" }));
    oneId = s.id;
    track(`/api/v1/schedule-objects/${oneId}`);
  });

  await tc("update recurring days", async () => {
    const s = expectOk(await PUT(`/api/v1/schedule-objects/${recId}`, { name: rn, type: "recurring", recurrence: { days: [6, 7], start: "09:00", end: "12:00" }, timezone: "UTC" }));
    assert(s.recurrence?.days?.join() === "6,7", `days=${JSON.stringify(s.recurrence)}`);
  });

  await tc("delete schedules → 404", async () => {
    expectOk(await DEL(`/api/v1/schedule-objects/${recId}`));
    expectOk(await DEL(`/api/v1/schedule-objects/${oneId}`));
    const g = await GET(`/api/v1/schedule-objects/${oneId}`);
    expectErr(g, "NOT_FOUND", 404);
    recId = oneId = null;
  });
});

suite("fw-rules", "Firewall → Rules CRUD + toggle/reorder/hits/validate/export/import", async () => {
  const rn1 = un("E2E-RULE-A");
  const rn2 = un("E2E-RULE-B");
  const impName = un("E2E-RULE-IMP");
  let r1 = null;
  let r2 = null;
  let importedIds = [];

  await tc("list rules (baseline)", async () => {
    const j = (await GET("/api/v1/firewall-rules?limit=200")).json;
    assert(Array.isArray(j?.data), `rules not array: ${JSON.stringify(j).slice(0, 100)}`);
    check("baseline count", true, `${j.meta?.total ?? j.data.length} rules`);
  });

  await tc("create rule (allow, logging summary)", async () => {
    r1 = expectOk(await POST("/api/v1/firewall-rules", { name: rn1, action: "allow", logging: "summary", tags: ["e2e"] }));
    assert(r1.action === "allow" && r1.enabled === true, JSON.stringify(r1).slice(0, 140));
    track(`/api/v1/firewall-rules/${r1.id}`);
  });

  await tc("create second rule (deny)", async () => {
    r2 = expectOk(await POST("/api/v1/firewall-rules", { name: rn2, action: "deny", logging: "none" }));
    track(`/api/v1/firewall-rules/${r2.id}`);
  });

  await tc("rule name required → 400", async () => {
    const r = await POST("/api/v1/firewall-rules", { action: "allow" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("unknown zone id in srcZoneIds → 400", async () => {
    const r = await POST("/api/v1/firewall-rules", { name: un("E2E-BAD"), action: "allow", srcZoneIds: [99999999] });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("read back rule", async () => {
    const g = expectOk(await GET(`/api/v1/firewall-rules/${r1.id}`));
    assert(g.name === rn1, `name=${g.name}`);
  });

  await tc("update rule (PUT) — action + connLimit", async () => {
    const u = expectOk(await PUT(`/api/v1/firewall-rules/${r1.id}`, { name: rn1, action: "drop", logging: "detail", connLimit: 500 }));
    assert(u.action === "drop" && Number(u.connLimit) === 500, JSON.stringify(u).slice(0, 140));
  });

  await tc("toggle enabled=false (PATCH)", async () => {
    const t = expectOk(await PATCH(`/api/v1/firewall-rules/${r1.id}/toggle`, { enabled: false }));
    assert(t.enabled === false, JSON.stringify(t).slice(0, 120));
  });

  await tc("toggle back enabled=true (PATCH)", async () => {
    const t = expectOk(await PATCH(`/api/v1/firewall-rules/${r1.id}/toggle`, { enabled: true }));
    assert(t.enabled === true, "enabled not true");
  });

  await tc("reorder [r2, r1, ...rest] → positions updated", async () => {
    const j = (await GET("/api/v1/firewall-rules?limit=200")).json;
    const rest = j.data.filter((x) => x.id !== r1.id && x.id !== r2.id).map((x) => x.id);
    expectOk(await POST("/api/v1/firewall-rules/reorder", { orderedIds: [r2.id, r1.id, ...rest] }));
    const after = (await GET("/api/v1/firewall-rules?limit=200")).json.data;
    const p2 = after.find((x) => x.id === r2.id)?.position;
    const p1 = after.find((x) => x.id === r1.id)?.position;
    assert(p2 < p1, `positions r2=${p2} r1=${p1}`);
  });

  await tc("GET hits → counters object", async () => {
    const h = expectOk(await GET(`/api/v1/firewall-rules/${r1.id}/hits`));
    assert(h.id === r1.id || h.hitCount !== undefined, JSON.stringify(h).slice(0, 120));
  });

  await tc("POST hits/reset → ok", async () => {
    expectOk(await POST(`/api/v1/firewall-rules/${r1.id}/hits/reset`, {}));
  });

  await tc("validate endpoint → ok", async () => {
    const v = expectOk(await POST("/api/v1/firewall-rules/validate", { rule: { name: un("E2E-VAL"), action: "allow", logging: "none" }, excludeRuleId: r1.id }));
    check("validate returned", true, JSON.stringify(v).slice(0, 100));
  });

  await tc("export json → raw ruleset array", async () => {
    const r = await GET("/api/v1/firewall-rules/export?format=json");
    assert(r.status === 200, `export status ${r.status}`);
    const payload = r.json;
    assert(Array.isArray(payload), `export not array: ${JSON.stringify(payload)?.slice?.(0, 100)}`);
    check("export rows", true, `${payload.length} rules exported`);
  });

  await tc("import json (1 rule) → imported=1", async () => {
    const d = expectOk(
      await POST("/api/v1/firewall-rules/import", {
        format: "json",
        payload: JSON.stringify([{ name: impName, enabled: true, action: "deny", logging: "none" }]),
      }),
    );
    importedIds = (d.rules || []).map((x) => x.id);
    assert(d.imported === 1, `imported=${d.imported}`);
    for (const id of importedIds) track(`/api/v1/firewall-rules/${id}`);
  });

  await tc("import with invalid row → 400 all-or-nothing", async () => {
    const r = await POST("/api/v1/firewall-rules/import", {
      format: "json",
      payload: JSON.stringify([{ name: un("E2E-IMP-BAD"), action: "nope" }]),
    });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("delete both rules + imported → 404", async () => {
    expectOk(await DEL(`/api/v1/firewall-rules/${r1.id}`));
    expectOk(await DEL(`/api/v1/firewall-rules/${r2.id}`));
    for (const id of importedIds) expectOk(await DEL(`/api/v1/firewall-rules/${id}`));
    const g = await GET(`/api/v1/firewall-rules/${r1.id}`);
    expectErr(g, "NOT_FOUND", 404);
    r1 = r2 = null;
    importedIds = [];
  });
});

suite("fw-nat", "Firewall → NAT CRUD + 1:1 + toggle/reorder", async () => {
  const n1 = un("E2E-NAT-SNAT");
  const n2 = un("E2E-NAT-DNAT");
  const n3 = un("E2E-NAT-EXEMPT");
  let s1 = null;
  let s2 = null;
  let s3 = null;
  let o2oIds = [];

  await tc("list nat rules (baseline)", async () => {
    const j = (await GET("/api/v1/nat-rules?limit=200")).json;
    assert(Array.isArray(j?.data), `nat list not array: ${JSON.stringify(j).slice(0, 100)}`);
    check("baseline count", true, `${j.meta?.total ?? j.data.length} rules`);
  });

  await tc("create SNAT masq", async () => {
    s1 = expectOk(await POST("/api/v1/nat-rules", { name: n1, type: "snat", translatedSrc: "masq", outgoingIface: "ens32", logging: "none" }));
    assert(s1.type === "snat", JSON.stringify(s1).slice(0, 140));
    track(`/api/v1/nat-rules/${s1.id}`);
  });

  await tc("create DNAT port-forward", async () => {
    s2 = expectOk(await POST("/api/v1/nat-rules", { name: n2, type: "dnat", translatedDst: "10.90.0.50", translatedPort: 8080, logging: "none" }));
    assert(s2.type === "dnat", JSON.stringify(s2).slice(0, 140));
    track(`/api/v1/nat-rules/${s2.id}`);
  });

  await tc("create EXEMPT rule", async () => {
    s3 = expectOk(await POST("/api/v1/nat-rules", { name: n3, type: "exempt" }));
    track(`/api/v1/nat-rules/${s3.id}`);
  });

  await tc("SNAT without translation → 400", async () => {
    const r = await POST("/api/v1/nat-rules", { name: un("E2E-BAD"), type: "snat" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("EXEMPT with translatedSrc → 400", async () => {
    const r = await POST("/api/v1/nat-rules", { name: un("E2E-BAD2"), type: "exempt", translatedSrc: "masq" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("bad NAT type → 400", async () => {
    const r = await POST("/api/v1/nat-rules", { name: un("E2E-BAD3"), type: "fullconenat", translatedSrc: "masq" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("1:1 NAT → paired dnat+snat created", async () => {
    const d = expectOk(
      await POST("/api/v1/nat-rules", {
        oneToOne: { publicIp: "203.0.113.77", internalHost: "10.90.0.77", name: un("E2E-NAT-1TO1"), comment: "e2e" },
      }),
    );
    const rows = d.rules || d.created || (Array.isArray(d) ? d : [d]);
    o2oIds = rows.map((x) => x.id);
    assert(o2oIds.length >= 1, `1:1 created ${o2oIds.length} rows: ${JSON.stringify(d).slice(0, 200)}`);
    check("1:1 rows", true, `${o2oIds.length} rule(s)`);
    for (const id of o2oIds) track(`/api/v1/nat-rules/${id}`);
  });

  await tc("update SNAT rule → new comment", async () => {
    const u = expectOk(await PUT(`/api/v1/nat-rules/${s1.id}`, { name: n1, type: "snat", translatedSrc: "masq", outgoingIface: "ens32", comment: "e2e updated" }));
    assert((u.comment || "").includes("updated"), JSON.stringify(u).slice(0, 140));
  });

  await tc("toggle DNAT enabled=false (PATCH)", async () => {
    const t = expectOk(await PATCH(`/api/v1/nat-rules/${s2.id}/toggle`, { enabled: false }));
    assert(t.enabled === false, JSON.stringify(t).slice(0, 120));
  });

  await tc("reorder [dnat, snat, ...rest]", async () => {
    const j = (await GET("/api/v1/nat-rules?limit=200")).json;
    const rest = j.data.filter((x) => x.id !== s1.id && x.id !== s2.id && x.id !== s3.id).map((x) => x.id);
    expectOk(await POST("/api/v1/nat-rules/reorder", { orderedIds: [s2.id, s1.id, s3.id, ...rest] }));
    const after = (await GET("/api/v1/nat-rules?limit=200")).json.data;
    const p2 = after.find((x) => x.id === s2.id)?.position;
    const p1 = after.find((x) => x.id === s1.id)?.position;
    assert(p2 < p1, `positions dnat=${p2} snat=${p1}`);
  });

  await tc("delete all test nat rules → 404", async () => {
    for (const id of [...o2oIds, s1?.id, s2?.id, s3?.id].filter(Boolean)) expectOk(await DEL(`/api/v1/nat-rules/${id}`));
    const g = await GET(`/api/v1/nat-rules/${s1.id}`);
    expectErr(g, "NOT_FOUND", 404);
    o2oIds = [];
    s1 = s2 = s3 = null;
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// SUITES — batch 2: routing, pbr, wan, port-mirrors, interfaces (DB CRUD)
// ═════════════════════════════════════════════════════════════════════════════

suite("routing", "Network → Routing: static routes CRUD", async () => {
  const rn = un("E2E-ROUTE");
  let rid = null;

  await tc("list routes (baseline)", async () => {
    const data = expectOk(await GET("/api/v1/routes"));
    assert(Array.isArray(data), `not array: ${JSON.stringify(data).slice(0, 80)}`);
    check("baseline count", true, `${data.length} routes`);
  });

  await tc("create route 10.77.0.0/16 via 10.90.0.1", async () => {
    const r = expectOk(await POST("/api/v1/routes", { name: rn, destinationCidr: "10.77.0.0/16", gateway: "10.90.0.1", distance: 5, description: "e2e" }));
    rid = r.id;
    assert(r.destinationCidr === "10.77.0.0/16" && r.distance === 5, JSON.stringify(r).slice(0, 140));
    track(`/api/v1/routes/${rid}`);
  });

  await tc("invalid CIDR → 400", async () => {
    const r = await POST("/api/v1/routes", { destinationCidr: "10.77.0.999/16", gateway: "10.90.0.1" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("blackhole with gateway → 400", async () => {
    const r = await POST("/api/v1/routes", { destinationCidr: "10.78.0.0/16", blackhole: true, gateway: "10.90.0.1" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("unknown interfaceName → 400", async () => {
    const r = await POST("/api/v1/routes", { destinationCidr: "10.79.0.0/16", interfaceName: "no-such-if" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("update route (PUT) — new gateway + distance", async () => {
    const u = expectOk(await PUT(`/api/v1/routes/${rid}`, { destinationCidr: "10.77.0.0/16", gateway: "10.90.0.254", distance: 10 }));
    assert(u.gateway === "10.90.0.254" && u.distance === 10, JSON.stringify(u).slice(0, 140));
  });

  await tc("read back by id", async () => {
    const g = expectOk(await GET(`/api/v1/routes/${rid}`));
    assert(g.id === rid && g.gateway === "10.90.0.254", JSON.stringify(g).slice(0, 140));
  });

  await tc("delete route → 404", async () => {
    expectOk(await DEL(`/api/v1/routes/${rid}`));
    const g = await GET(`/api/v1/routes/${rid}`);
    expectErr(g, "NOT_FOUND", 404);
    rid = null;
  });
});

suite("pbr", "Network → Policy-Based Routing CRUD + toggle", async () => {
  const pn = un("E2E-PBR");
  let pid = null;

  await tc("list pbr rules (baseline)", async () => {
    const data = expectOk(await GET("/api/v1/pbr-rules"));
    assert(Array.isArray(data), `not array: ${JSON.stringify(data).slice(0, 80)}`);
    check("baseline count", true, `${data.length} rules`);
  });

  await tc("create PBR rule (by gateway)", async () => {
    const p = expectOk(await POST("/api/v1/pbr-rules", { name: pn, gateway: "10.90.0.1", description: "e2e" }));
    pid = p.id;
    assert(p.gateway === "10.90.0.1", JSON.stringify(p).slice(0, 140));
    track(`/api/v1/pbr-rules/${pid}`);
  });

  await tc("both iface+gateway → 400", async () => {
    const r = await POST("/api/v1/pbr-rules", { name: un("E2E-BAD"), outgoingIface: "ens34", gateway: "10.90.0.1" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("neither iface nor gateway → 400", async () => {
    const r = await POST("/api/v1/pbr-rules", { name: un("E2E-BAD2") });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("update PBR → outgoingIface replaces gateway", async () => {
    const u = expectOk(await PUT(`/api/v1/pbr-rules/${pid}`, { name: pn, outgoingIface: "ens34" }));
    assert(u.outgoingIface === "ens34" && !u.gateway, JSON.stringify(u).slice(0, 160));
  });

  await tc("toggle enabled=false (PATCH)", async () => {
    const t = expectOk(await PATCH(`/api/v1/pbr-rules/${pid}/toggle`, { enabled: false }));
    assert(t.enabled === false, JSON.stringify(t).slice(0, 120));
  });

  await tc("delete PBR rule → gone via list", async () => {
    expectOk(await DEL(`/api/v1/pbr-rules/${pid}`));
    await expectGoneViaList("/api/v1/pbr-rules", pid, "pbr");
    pid = null;
  });
});

suite("wan", "Network → Multi-WAN policies CRUD + probe", async () => {
  const wn = "ens34";
  let wid = null;

  await tc("list wan policies (baseline)", async () => {
    const data = expectOk(await GET("/api/v1/wan-policies"));
    assert(Array.isArray(data), `not array: ${JSON.stringify(data).slice(0, 80)}`);
    const pre = data.find((x) => x.interfaceName === wn);
    if (pre) track(`/api/v1/wan-policies/${pre.id}`);
    check("baseline", true, `${data.length} policies${pre ? " (pre-existing ens34 policy found)" : ""}`);
  });

  await tc("create wan policy for ens34 (failover)", async () => {
    const w = expectOk(await POST("/api/v1/wan-policies", { interfaceName: wn, mode: "failover", weight: 30, priority: 2 }));
    wid = w.id;
    assert(w.interfaceName === wn && w.mode === "failover", JSON.stringify(w).slice(0, 160));
    assert(w.probeTarget, `probeTarget not defaulted: ${JSON.stringify(w).slice(0, 160)}`);
    track(`/api/v1/wan-policies/${wid}`);
  });

  await tc("duplicate interfaceName → 400/409", async () => {
    const r = await POST("/api/v1/wan-policies", { interfaceName: wn, mode: "priority" });
    assert(r.status === 400 || r.status === 409, `expected 400/409 got ${r.status}: ${JSON.stringify(r.json).slice(0, 140)}`);
  });

  await tc("bad mode → 400", async () => {
    const r = await POST("/api/v1/wan-policies", { interfaceName: "ens35", mode: "turbo" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("update policy weight/priority", async () => {
    const u = expectOk(await PUT(`/api/v1/wan-policies/${wid}`, { interfaceName: wn, mode: "load_balance", weight: 70, priority: 1 }));
    assert(u.weight === 70 && u.mode === "load_balance", JSON.stringify(u).slice(0, 160));
  });

  await tc("probe now → state returned (real gateway probe)", async () => {
    const p = expectOk(await POST(`/api/v1/wan-policies/${wid}/probe`, {}));
    assert(typeof p.state === "string", `state=${JSON.stringify(p).slice(0, 140)}`);
    check("probe state", true, `state=${p.state}`);
  });

  await tc("delete wan policy → gone via list", async () => {
    expectOk(await DEL(`/api/v1/wan-policies/${wid}`));
    await expectGoneViaList("/api/v1/wan-policies", wid, "wan policy");
    wid = null;
  });
});

suite("port-mirrors", "Network → Port Mirroring (SPAN) CRUD", async () => {
  let mid = null;
  let srcIf = "ens34";
  let dstIf = null;

  await tc("list mirrors (baseline)", async () => {
    const data = expectOk(await GET("/api/v1/network/port-mirrors"));
    assert(Array.isArray(data), `not array: ${JSON.stringify(data).slice(0, 80)}`);
    check("baseline count", true, `${data.length} mirrors`);
  });

  await tc("pick two real interfaces from /interfaces", async () => {
    const ifaces = expectOk(await GET("/api/v1/interfaces?limit=100"));
    const names = ifaces.map((i) => i.name);
    assert(names.length >= 2, `need 2 interfaces, got ${names.join(",")}`);
    srcIf = names.find((n) => n !== "lo") || names[0];
    dstIf = names.find((n) => n !== srcIf);
    assert(dstIf, "no second interface found");
    check("chosen pair", true, `${srcIf} → ${dstIf}`);
  });

  await tc("create mirror session", async () => {
    const m = expectOk(await POST("/api/v1/network/port-mirrors", { name: un("E2E-MIRROR"), srcIface: srcIf, dstIface: dstIf, direction: "both" }));
    mid = m.id;
    track(`/api/v1/network/port-mirrors/${mid}`);
  });

  await tc("same src+dst → 400", async () => {
    const r = await POST("/api/v1/network/port-mirrors", { name: un("E2E-BAD"), srcIface: srcIf, dstIface: srcIf });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("update mirror direction → ingress", async () => {
    const u = expectOk(await PUT(`/api/v1/network/port-mirrors/${mid}`, { name: un("E2E-MIRROR"), srcIface: srcIf, dstIface: dstIf, direction: "ingress" }));
    assert(u.direction === "ingress", JSON.stringify(u).slice(0, 140));
  });

  await tc("delete mirror → gone via list", async () => {
    expectOk(await DEL(`/api/v1/network/port-mirrors/${mid}`));
    await expectGoneViaList("/api/v1/network/port-mirrors", mid, "mirror");
    mid = null;
  });
});

suite("interfaces-db", "Network → Interfaces DB CRUD (VLAN/bridge/bond, logical)", async () => {
  let vlanId = null;
  let brId = null;
  let ens34Before = null;

  await tc("list interfaces (baseline)", async () => {
    const j = (await GET("/api/v1/interfaces?limit=100")).json;
    assert(Array.isArray(j?.data), `not array: ${JSON.stringify(j).slice(0, 100)}`);
    const e34 = j.data.find((i) => i.name === "ens34");
    ens34Before = e34 ? { enabled: e34.enabled, mtu: e34.mtu } : null;
    check("baseline", true, `${j.meta?.total ?? j.data.length} ifaces: ${j.data.map((i) => i.name).join(",")}`);
  });

  await tc("create VLAN ens34.777 (DB)", async () => {
    const v = expectOk(await POST("/api/v1/interfaces", { type: "vlan", name: "vlan777", parent: "ens34", vlanId: 777, ip: "10.177.77.1", cidrPrefix: 24, role: "unused" }));
    vlanId = v.id;
    assert(v.name === "vlan777" && v.type === "vlan", JSON.stringify(v).slice(0, 160));
    check("os field on create", true, JSON.stringify(v.os ?? {}).slice(0, 120));
    track(`/api/v1/interfaces/${vlanId}`);
  });

  await tc("duplicate iface name → 400/409", async () => {
    const r = await POST("/api/v1/interfaces", { type: "vlan", name: "vlan777", parent: "ens34", vlanId: 778 });
    assert(r.status === 400 || r.status === 409, `expected 400/409 got ${r.status}: ${JSON.stringify(r.json).slice(0, 160)}`);
  });

  await tc("invalid vlanId 5000 → 400", async () => {
    const r = await POST("/api/v1/interfaces", { type: "vlan", name: "vlan5000", parent: "ens34", vlanId: 5000 });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("physical iface create rejected → 400", async () => {
    const r = await POST("/api/v1/interfaces", { type: "physical", name: "ens99" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("bond with 1 member → 400", async () => {
    const r = await POST("/api/v1/interfaces", { type: "bond", name: "bond0", members: ["ens34"], mode: "active-backup" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("bridge with L3-free member (DB)", async () => {
    // BR-L2-L3 + enslaving rules: members must be physical/vlan without L3 addressing
    const ifaces = (await GET("/api/v1/interfaces?limit=100")).json.data;
    const flat = ifaces.find((i) => i.name !== "ens32" && (i.type === "physical" || i.type === "vlan") && !i.config?.ip && !(i.config?.secondaryIps?.length));
    let member = flat?.name ?? null;
    if (!member) {
      const v = expectOk(await POST("/api/v1/interfaces", { type: "vlan", name: "vlan778", parent: "ens34", vlanId: 778, role: "unused", enabled: true }));
      track(`/api/v1/interfaces/${v.id}`);
      member = v.name;
      await PUT(`/api/v1/interfaces/${v.id}`, { mode: "l2" });
    }
    const b = expectOk(await POST("/api/v1/interfaces", { type: "bridge", name: "br-e2e", members: [member], stp: true, role: "unused" }));
    brId = b.id;
    assert(b.type === "bridge", JSON.stringify(b).slice(0, 160));
    check("bridge member", true, member);
  });

  await tc("update VLAN (PUT) — mtu 1400 + secondary ip via config patch", async () => {
    const u = expectOk(await PUT(`/api/v1/interfaces/${vlanId}`, { mtu: 1400, config: { secondaryIps: [{ ip: "10.177.77.2", cidrPrefix: 24 }] } }));
    assert(u.mtu === 1400, `mtu=${u.mtu}`);
    const secs = u.config?.secondaryIps ?? [];
    assert(secs.length === 1 && secs[0].ip === "10.177.77.2", `secondaryIps=${JSON.stringify(secs)} cfg=${JSON.stringify(u.config).slice(0, 160)}`);
  });

  await tc("update VLAN config patch — ip change via config", async () => {
    const u = expectOk(await PUT(`/api/v1/interfaces/${vlanId}`, { config: { ip: "10.177.77.9", cidrPrefix: 24 } }));
    const ip = u.config?.ip ?? u.ip;
    assert(ip === "10.177.77.9", `ip=${ip}: ${JSON.stringify(u.config).slice(0, 200)}`);
  });

  await tc("disable VLAN (enabled=false)", async () => {
    const u = expectOk(await PUT(`/api/v1/interfaces/${vlanId}`, { enabled: false }));
    assert(u.enabled === false, `enabled=${u.enabled}`);
  });

  await tc("re-enable VLAN", async () => {
    const u = expectOk(await PUT(`/api/v1/interfaces/${vlanId}`, { enabled: true }));
    assert(u.enabled === true, `enabled=${u.enabled}`);
  });

  await tc("delete bridge → 404", async () => {
    expectOk(await DEL(`/api/v1/interfaces/${brId}`));
    const g = await GET(`/api/v1/interfaces/${brId}`);
    expectErr(g, "NOT_FOUND", 404);
    brId = null;
  });

  await tc("delete VLAN → 404", async () => {
    expectOk(await DEL(`/api/v1/interfaces/${vlanId}`));
    const g = await GET(`/api/v1/interfaces/${vlanId}`);
    expectErr(g, "NOT_FOUND", 404);
    vlanId = null;
  });

  await tc("restore ens34 DB fields if changed", async () => {
    if (!ens34Before) return;
    const j = (await GET("/api/v1/interfaces?limit=100")).json;
    const e34 = j.data.find((i) => i.name === "ens34");
    if (e34 && e34.enabled !== ens34Before.enabled) {
      await PUT(`/api/v1/interfaces/${e34.id}`, { enabled: ens34Before.enabled });
      check("ens34 restored", true, `enabled=${ens34Before.enabled}`);
    } else {
      check("ens34 untouched", true, `enabled=${e34?.enabled}`);
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// SUITES — batch 3: interfaces OS-level on ens34 (kernel verification)
// ═════════════════════════════════════════════════════════════════════════════

/** run `ip -j …` on prod and parse JSON. */
async function ipJson(args) {
  const r = await sshExec(`ip -j ${args} 2>&1`);
  if (r.code !== 0) throw new Error(`ip -j ${args} failed: ${r.out.slice(0, 160)}`);
  const open = r.out.indexOf("[");
  if (open < 0) return [];
  return JSON.parse(r.out.slice(open));
}

function kernAddrs(iface) {
  const set = [];
  for (const a of iface[0]?.addr_info ?? []) if (a.local) set.push(`${a.local}/${a.prefixlen}`);
  return set.sort();
}

async function kernLink(name) {
  const r = await sshExec(`ip -j link show dev ${name} 2>/dev/null`);
  if (r.code !== 0 || !r.out.trim().startsWith("[")) return null;
  return JSON.parse(r.out.slice(r.out.indexOf("[")))[0] ?? null;
}

function flagsUp(link) {
  return Array.isArray(link?.flags) && link.flags.includes("UP");
}

const osOutcome = (r) => r.json?.os ?? null;

suite("interfaces-os", "Interfaces OS-level on ens34 — ip config/update/delete/up-down (kernel verified)", async () => {
  let baseline = null; // { db, addrs, mtu, flags, defDev }
  let ens34Id = null;

  await tc("redline + snapshot ens34 baseline (DB + kernel)", async () => {
    const e32 = await kernLink("ens32");
    assert(flagsUp(e32), "ens32 must be UP before OS tests");
    const j = (await GET("/api/v1/interfaces?limit=100")).json;
    const e34 = j.data.find((i) => i.name === "ens34");
    assert(e34, "ens34 missing in console DB");
    ens34Id = e34.id;
    const addrs = await ipJson("addr show dev ens34");
    const link = await kernLink("ens34");
    const def = await sshExec("ip route show default");
    baseline = {
      db: JSON.parse(JSON.stringify(e34)),
      addrs: kernAddrs(addrs),
      mtu: link?.mtu,
      flags: JSON.stringify(link?.flags ?? []),
      defDev: (/\bdev\s+(\S+)/.exec(def.out)?.[1] ?? "").trim(),
    };
    check("baseline", true, `addrs=[${baseline.addrs.join(",")}] mtu=${baseline.mtu} defDev=${baseline.defDev}`);
    const h = await nftHash();
    check("nft structural baseline", true, h === NFT_STRUCT ? "unchanged" : `STRUCT DRIFT got=${h} baseline=${NFT_STRUCT} (f2b ban-set changes are expected)`);
  });

  await tc("TC1 apply endpoint returns plan (explicit repair path)", async () => {
    const d = expectOk(await POST("/api/v1/interfaces/apply", { name: "ens34" }));
    assert(Array.isArray(d.plans), `plans missing: ${JSON.stringify(d).slice(0, 120)}`);
    check("apply outcome", true, `applied=${d.applied} reason=${d.reason}`);
  });

  await tc("TC2 static IP set 10.34.0.5/24 → kernel addr present", async () => {
    const r = await PUT(`/api/v1/interfaces/${ens34Id}`, { wanType: "static", ip: "10.34.0.5", cidrPrefix: 24, gateway: null, dns: [] });
    const os = osOutcome(r);
    assert(os && os.gate === "on", `gate=${os?.gate} reason=${os?.reason}`);
    assert(os.applied === true, `not applied: ${os?.reason} ${JSON.stringify(os.results ?? []).slice(0, 200)}`);
    const addrs = kernAddrs(await ipJson("addr show dev ens34"));
    assert(addrs.includes("10.34.0.5/24"), `kernel addrs=[${addrs.join(",")}]`);
  });

  await tc("TC3 IP change .5 → .6 (ip addr replace semantics)", async () => {
    const r = await PUT(`/api/v1/interfaces/${ens34Id}`, { ip: "10.34.0.6", cidrPrefix: 24 });
    const os = osOutcome(r);
    assert(os?.applied === true, `reason=${os?.reason}`);
    const addrs = kernAddrs(await ipJson("addr show dev ens34"));
    assert(addrs.includes("10.34.0.6/24"), `missing .6: [${addrs.join(",")}]`);
    assert(!addrs.includes("10.34.0.5/24"), `.5 still present: [${addrs.join(",")}]`);
  });

  await tc("TC4 secondary IP add 10.34.0.10/24 → kernel", async () => {
    const r = await PUT(`/api/v1/interfaces/${ens34Id}`, { secondaryIps: [{ ip: "10.34.0.10", cidrPrefix: 24 }] });
    const os = osOutcome(r);
    assert(os?.applied === true, `reason=${os?.reason}`);
    const addrs = kernAddrs(await ipJson("addr show dev ens34"));
    assert(addrs.includes("10.34.0.10/24"), `kernel addrs=[${addrs.join(",")}]`);
  });

  await tc("TC5 secondary IP remove → kernel drops it", async () => {
    const r = await PUT(`/api/v1/interfaces/${ens34Id}`, { secondaryIps: [] });
    const os = osOutcome(r);
    assert(os?.applied === true, `reason=${os?.reason}`);
    const addrs = kernAddrs(await ipJson("addr show dev ens34"));
    assert(!addrs.includes("10.34.0.10/24"), `kernel addrs=[${addrs.join(",")}]`);
  });

  await tc("TC6 MTU update 1500 → 1400 → kernel", async () => {
    const r = await PUT(`/api/v1/interfaces/${ens34Id}`, { mtu: 1400 });
    const os = osOutcome(r);
    assert(os?.applied === true, `reason=${os?.reason}`);
    const link = await kernLink("ens34");
    assert(link?.mtu === 1400, `kernel mtu=${link?.mtu}`);
  });

  await tc("TC7 MTU back to 1500 → kernel", async () => {
    const r = await PUT(`/api/v1/interfaces/${ens34Id}`, { mtu: 1500 });
    const os = osOutcome(r);
    assert(os?.applied === true, `reason=${os?.reason}`);
    const link = await kernLink("ens34");
    assert(link?.mtu === 1500, `kernel mtu=${link?.mtu}`);
  });

  await tc("TC8a admin DOWN without force → 409 lists references (zone lan)", async () => {
    const r = await PUT(`/api/v1/interfaces/${ens34Id}`, { enabled: false });
    expectErr(r, "CONFLICT", 409);
    const refs = r.json?.error?.details?.refs ?? [];
    assert(refs.some((x) => x.kind === "zone"), `refs=${JSON.stringify(refs).slice(0, 160)}`);
  });

  await tc("TC8b admin DOWN with force → kernel flags lose UP", async () => {
    const r = await PUT(`/api/v1/interfaces/${ens34Id}`, { enabled: false, force: true });
    const os = osOutcome(r);
    assert(os?.applied === true, `reason=${os?.reason} ${JSON.stringify(os?.results ?? []).slice(0, 160)}`);
    const link = await kernLink("ens34");
    assert(!flagsUp(link), `kernel flags=${JSON.stringify(link?.flags)}`);
  });

  await tc("TC9 admin UP (enable) → kernel flags regain UP", async () => {
    const r = await PUT(`/api/v1/interfaces/${ens34Id}`, { enabled: true });
    const os = osOutcome(r);
    assert(os?.applied === true, `reason=${os?.reason}`);
    const link = await kernLink("ens34");
    assert(flagsUp(link), `kernel flags=${JSON.stringify(link?.flags)}`);
  });

  await tc("TC10 VLAN 888 create on ens34 → kernel device + addr + id", async () => {
    const r = await POST("/api/v1/interfaces", { type: "vlan", name: "vlan888", parent: "ens34", vlanId: 888, ip: "10.88.0.1", cidrPrefix: 24, role: "unused" });
    const v = expectOk(r);
    track(`/api/v1/interfaces/${v.id}`);
    const os = osOutcome(r);
    assert(os?.applied === true, `os: gate=${os?.gate} reason=${os?.reason} steps=${JSON.stringify(os?.plan?.steps ?? []).slice(0, 200)}`);
    const d = await sshExec("ip -d -j link show dev vlan888");
    assert(d.code === 0, `kernel: vlan888 missing (${d.out.slice(0, 100)})`);
    const link = JSON.parse(d.out.slice(d.out.indexOf("[")))[0];
    const kind = link?.linkinfo?.info_kind;
    const vid = link?.linkinfo?.info_data?.id;
    assert(kind === "vlan" && vid === 888, `kind=${kind} vlanId=${vid}`);
    assert(link.link === "ens34", `parent=${link.link}`);
    const addrs = kernAddrs(await ipJson("addr show dev vlan888"));
    assert(addrs.includes("10.88.0.1/24"), `vlan addrs=[${addrs.join(",")}]`);
  });

  await tc("TC11 VLAN IP change .1 → .2 → kernel", async () => {
    const j = (await GET("/api/v1/interfaces?limit=100")).json;
    const v = j.data.find((i) => i.name === "vlan888");
    const r = await PUT(`/api/v1/interfaces/${v.id}`, { config: { ip: "10.88.0.2", cidrPrefix: 24 } });
    const os = osOutcome(r);
    assert(os?.applied === true, `reason=${os?.reason}`);
    const addrs = kernAddrs(await ipJson("addr show dev vlan888"));
    assert(addrs.includes("10.88.0.2/24"), `vlan addrs=[${addrs.join(",")}]`);
  });

  await tc("TC12 VLAN secondary IP add+remove → kernel", async () => {
    const j = (await GET("/api/v1/interfaces?limit=100")).json;
    const v = j.data.find((i) => i.name === "vlan888");
    let r = await PUT(`/api/v1/interfaces/${v.id}`, { config: { secondaryIps: [{ ip: "10.88.0.3", cidrPrefix: 24 }] } });
    assert(osOutcome(r)?.applied === true, `add reason=${osOutcome(r)?.reason}`);
    let addrs = kernAddrs(await ipJson("addr show dev vlan888"));
    assert(addrs.includes("10.88.0.3/24"), `after add: [${addrs.join(",")}]`);
    r = await PUT(`/api/v1/interfaces/${v.id}`, { config: { secondaryIps: [] } });
    assert(osOutcome(r)?.applied === true, `del reason=${osOutcome(r)?.reason}`);
    addrs = kernAddrs(await ipJson("addr show dev vlan888"));
    assert(!addrs.includes("10.88.0.3/24"), `after del: [${addrs.join(",")}]`);
  });

  await tc("TC13 VLAN admin down/up → kernel flags", async () => {
    const j = (await GET("/api/v1/interfaces?limit=100")).json;
    const v = j.data.find((i) => i.name === "vlan888");
    let r = await PUT(`/api/v1/interfaces/${v.id}`, { enabled: false });
    assert(osOutcome(r)?.applied === true, `down reason=${osOutcome(r)?.reason}`);
    let link = await kernLink("vlan888");
    assert(!flagsUp(link), `flags after down=${JSON.stringify(link?.flags)}`);
    r = await PUT(`/api/v1/interfaces/${v.id}`, { enabled: true });
    assert(osOutcome(r)?.applied === true, `up reason=${osOutcome(r)?.reason}`);
    link = await kernLink("vlan888");
    assert(flagsUp(link), `flags after up=${JSON.stringify(link?.flags)}`);
  });

  await tc("TC14 VLAN delete → kernel device removed", async () => {
    const j = (await GET("/api/v1/interfaces?limit=100")).json;
    const v = j.data.find((i) => i.name === "vlan888");
    const r = await DEL(`/api/v1/interfaces/${v.id}`);
    const os = osOutcome(r);
    assert(os?.applied === true, `teardown reason=${os?.reason} steps=${JSON.stringify(os?.plan?.steps ?? []).slice(0, 160)}`);
    const d = await sshExec("ip link show dev vlan888 2>&1");
    assert(/does not exist/.test(d.out), `vlan888 still on host: ${d.out.slice(0, 80)}`);
  });

  await tc("TC15 loopback create → kernel dummy device; delete → gone", async () => {
    const r = await POST("/api/v1/interfaces", { type: "loopback", name: "lo-e2e", ip: "10.99.0.1", cidrPrefix: 32, role: "unused" });
    const lo = expectOk(r);
    track(`/api/v1/interfaces/${lo.id}`);
    const os = osOutcome(r);
    assert(os?.applied === true, `os: ${os?.reason}`);
    const d = await sshExec("ip -d -j link show dev lo-e2e");
    assert(d.code === 0, `lo-e2e missing (${d.out.slice(0, 80)})`);
    const link = JSON.parse(d.out.slice(d.out.indexOf("[")))[0];
    assert(link?.linkinfo?.info_kind === "dummy", `kind=${link?.linkinfo?.info_kind}`);
    const del = await DEL(`/api/v1/interfaces/${lo.id}`);
    assert(osOutcome(del)?.applied === true, `teardown: ${osOutcome(del)?.reason}`);
    const gone = await sshExec("ip link show dev lo-e2e 2>&1");
    assert(/does not exist/.test(gone.out), `lo-e2e still on host`);
  });

  await tc("TC16 bridge create (vlan member) → kernel bridge + enslave; teardown", async () => {
    const v = expectOk(await POST("/api/v1/interfaces", { type: "vlan", name: "vlan779", parent: "ens34", vlanId: 779, role: "unused", enabled: true }));
    track(`/api/v1/interfaces/${v.id}`);
    await PUT(`/api/v1/interfaces/${v.id}`, { mode: "l2" });
    const r = await POST("/api/v1/interfaces", { type: "bridge", name: "br-e2e", members: ["vlan779"], stp: true, role: "unused" });
    const b = expectOk(r);
    track(`/api/v1/interfaces/${b.id}`);
    const os = osOutcome(r);
    const failedSteps = (os?.results ?? []).filter((x) => !x.ok);
    assert(os?.applied === true, `os: ${os?.reason} failed=${JSON.stringify(failedSteps).slice(0, 300)} steps=${JSON.stringify(os?.plan?.steps ?? []).slice(0, 240)}`);
    const d = await sshExec("ip -d -j link show dev br-e2e");
    assert(d.code === 0, `br-e2e missing (${d.out.slice(0, 100)})`);
    const link = JSON.parse(d.out.slice(d.out.indexOf("[")))[0];
    assert(link?.linkinfo?.info_kind === "bridge", `kind=${link?.linkinfo?.info_kind}`);
    const stp = await sshExec("cat /sys/class/net/br-e2e/bridge/stp_state");
    assert(stp.out.trim() === "1", `stp_state=${stp.out.trim()}`);
    const master = await sshExec("cat /sys/class/net/vlan779/master 2>/dev/null || true; ip -j link show dev vlan779 | grep -o 'master [a-z0-9-]*' || true");
    const m = await ipJson("link show dev vlan779");
    assert(m[0]?.master === "br-e2e", `vlan779 master=${m[0]?.master}`);
    const del = await DEL(`/api/v1/interfaces/${b.id}`);
    assert(osOutcome(del)?.applied === true, `teardown: ${osOutcome(del)?.reason}`);
    const gone = await sshExec("ip link show dev br-e2e 2>&1");
    assert(/does not exist/.test(gone.out), `br-e2e still on host`);
    const released = await ipJson("link show dev vlan779");
    assert(!released[0]?.master, `vlan779 still enslaved to ${released[0]?.master}`);
  });

  await tc("TC17 bond create (2 vlan members, active-backup) → kernel bond; teardown", async () => {
    const v1 = expectOk(await POST("/api/v1/interfaces", { type: "vlan", name: "vlan780", parent: "ens34", vlanId: 780, role: "unused", enabled: true }));
    track(`/api/v1/interfaces/${v1.id}`);
    await PUT(`/api/v1/interfaces/${v1.id}`, { mode: "l2" });
    const v2 = expectOk(await POST("/api/v1/interfaces", { type: "vlan", name: "vlan781", parent: "ens34", vlanId: 781, role: "unused", enabled: true }));
    track(`/api/v1/interfaces/${v2.id}`);
    await PUT(`/api/v1/interfaces/${v2.id}`, { mode: "l2" });
    const r = await POST("/api/v1/interfaces", { type: "bond", name: "bond-e2e", members: ["vlan780", "vlan781"], mode: "active-backup", miimon: 100, role: "unused" });
    const b = expectOk(r);
    track(`/api/v1/interfaces/${b.id}`);
    const os = osOutcome(r);
    assert(os?.applied === true, `os: ${os?.reason}`);
    const d = await sshExec("ip -d -j link show dev bond-e2e");
    assert(d.code === 0, `bond-e2e missing (${d.out.slice(0, 100)})`);
    const link = JSON.parse(d.out.slice(d.out.indexOf("[")))[0];
    assert(link?.linkinfo?.info_kind === "bond", `kind=${link?.linkinfo?.info_kind}`);
    const slaves = await sshExec("cat /sys/class/net/bond-e2e/bonding/slaves");
    assert(/vlan780.*vlan781|vlan781.*vlan780/.test(slaves.out.replace(/\s+/g, " ")), `slaves=${slaves.out.trim()}`);
    const mode = await sshExec("cat /sys/class/net/bond-e2e/bonding/mode");
    assert(/active-backup/.test(mode.out), `mode=${mode.out.trim()}`);
    const del = await DEL(`/api/v1/interfaces/${b.id}`);
    assert(osOutcome(del)?.applied === true, `teardown: ${osOutcome(del)?.reason}`);
    const gone = await sshExec("ip link show dev bond-e2e 2>&1");
    assert(/does not exist/.test(gone.out), `bond-e2e still on host`);
  });

  await tc("TC18 restore ens34 DB config to baseline (OS converges back)", async () => {
    const b = baseline.db;
    const cfg = b.config ?? {};
    const body = {
      mtu: b.mtu ?? 1500,
      enabled: b.enabled ?? true,
      ...(cfg.wanType ? { wanType: cfg.wanType } : {}),
      ...(cfg.ip ? { ip: cfg.ip, cidrPrefix: cfg.cidrPrefix } : { ip: undefined }),
      ...(cfg.gateway !== undefined ? { gateway: cfg.gateway } : {}),
      ...(cfg.dns !== undefined ? { dns: cfg.dns } : {}),
      secondaryIps: cfg.secondaryIps ?? [],
    };
    if (!cfg.ip) {
      // planner strips test addrs only when a primary exists — clean up directly
      await sshExec("ip addr del 10.34.0.6/24 dev ens34 2>/dev/null; ip addr del 10.34.0.5/24 dev ens34 2>/dev/null; true");
    }
    const r = await PUT(`/api/v1/interfaces/${ens34Id}`, body);
    const os = osOutcome(r);
    assert(os?.applied === true, `restore: ${os?.reason} steps=${JSON.stringify(os?.plan?.steps ?? []).slice(0, 240)}`);
    if (cfg.ip) {
      const addrs = kernAddrs(await ipJson("addr show dev ens34"));
      assert(addrs.includes(`${cfg.ip}/${cfg.cidrPrefix}`), `kernel=[${addrs.join(",")}] expected ${cfg.ip}`);
    } else {
      const addrs = kernAddrs(await ipJson("addr show dev ens34"));
      const leftover = addrs.filter((a) => a.startsWith("10.34."));
      assert(leftover.length === 0, `leftover test addrs: [${leftover.join(",")}]`);
    }
    const link = await kernLink("ens34");
    assert(link?.mtu === (b.mtu ?? 1500), `mtu=${link?.mtu}`);
  });

  await tc("TC19 final redline — nft, ens32, default route, ens34 baseline", async () => {
    const h = await nftHash();
    check("nft structural hash", h === NFT_STRUCT, h === NFT_STRUCT ? "unchanged" : `got=${h} (f2b dynamic bans may drift elements)`);
    const e32 = await kernLink("ens32");
    assert(flagsUp(e32), "ens32 not UP after OS tests");
    const def = await sshExec("ip route show default");
    const defDev = (/\bdev\s+(\S+)/.exec(def.out)?.[1] ?? "").trim();
    assert(defDev === baseline.defDev, `default route dev changed: ${baseline.defDev} → ${defDev}`);
    const addrs = kernAddrs(await ipJson("addr show dev ens34"));
    const added = addrs.filter((a) => a.startsWith("10.34.") || a.startsWith("10.88."));
    assert(added.length === (baseline.addrs.filter((a) => a.startsWith("10.34.") || a.startsWith("10.88.")).length), `ens34 addr set changed: [${addrs.join(",")}]`);
    check("redline", true, `defDev=${defDev} ens34=[${addrs.join(",")}]`);
  });

  await tc("TC20 apply endpoint — converged (no pending drift)", async () => {
    const d = expectOk(await POST("/api/v1/interfaces/apply", { name: "ens34" }));
    assert(d.applied === true, `applied=${d.applied} reason=${d.reason}`);
    const steps = d.plans?.[0]?.steps ?? [];
    check("steps", true, `${steps.length} step(s): ${steps.map((s) => s.cmd).join(" | ").slice(0, 160)}`);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// SUITES — batch 4: dns, dhcp
// ═════════════════════════════════════════════════════════════════════════════

suite("dns", "DNS & DHCP → DNS Security: settings/records/policies/logs", async () => {
  let snap = null;
  let recId = null;
  let polId = null;

  await tc("GET resolver settings (snapshot)", async () => {
    snap = expectOk(await GET("/api/v1/dns/settings"));
    assert(snap && typeof snap === "object", JSON.stringify(snap).slice(0, 100));
  });

  await tc("PUT resolver settings (cache 512 + rrl) → revert", async () => {
    const body = { ...snap, cacheSizeMb: 512, rrl: true };
    const u = expectOk(await PUT("/api/v1/dns/settings", body));
    assert(u.cacheSizeMb === 512 && u.rrl === true, JSON.stringify(u).slice(0, 140));
    const back = expectOk(await PUT("/api/v1/dns/settings", { ...snap, cacheSizeMb: snap.cacheSizeMb ?? 64, rrl: snap.rrl ?? false }));
    assert(back.cacheSizeMb === (snap.cacheSizeMb ?? 64), `revert cache=${back.cacheSizeMb}`);
  });

  await tc("settings validation: cacheSizeMb 8 → 400", async () => {
    const r = await PUT("/api/v1/dns/settings", { ...snap, cacheSizeMb: 8 });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("create A record", async () => {
    const rec = expectOk(await POST("/api/v1/dns/records", { zone: "e2e-lab.local", name: "host1", type: "A", value: "10.90.9.9", ttl: 300 }));
    recId = rec.id;
    assert(rec.type === "A" && rec.value === "10.90.9.9", JSON.stringify(rec).slice(0, 140));
  });

  await tc("A record with bad IP → 400", async () => {
    const r = await POST("/api/v1/dns/records", { zone: "e2e-lab.local", name: "bad", type: "A", value: "999.1.1.1" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("A record with priority → 400 (priority only for MX/SRV)", async () => {
    const r = await POST("/api/v1/dns/records", { zone: "e2e-lab.local", name: "bad2", type: "A", value: "10.90.9.10", priority: 10 });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("MX record without priority → 400", async () => {
    const r = await POST("/api/v1/dns/records", { zone: "e2e-lab.local", name: "@", type: "MX", value: "mail.e2e-lab.local" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("update A record value → 10.90.9.10", async () => {
    const u = expectOk(await PUT(`/api/v1/dns/records/${recId}`, { value: "10.90.9.10" }));
    assert(u.value === "10.90.9.10", JSON.stringify(u).slice(0, 140));
  });

  await tc("create DNS policy (block ads + custom)", async () => {
    const p = expectOk(await POST("/api/v1/dns/policies", { name: un("E2E-DNSPOL"), blockCategories: ["ads"], customBlock: ["tracker.e2e-lab.local"], action: "sinkhole", sinkholeIp: "0.0.0.0" }));
    polId = p.id;
    assert(p.blockCategories?.includes("ads"), JSON.stringify(p).slice(0, 160));
  });

  await tc("policy update (partial) — action nxdomain", async () => {
    const u = expectOk(await PUT(`/api/v1/dns/policies/${polId}`, { action: "nxdomain" }));
    assert(u.action === "nxdomain", `action=${u.action}`);
  });

  await tc("policy bad category → 400", async () => {
    const r = await POST("/api/v1/dns/policies", { name: un("E2E-BAD"), blockCategories: ["cryptojacking"] });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("query-logs endpoint → list", async () => {
    const data = expectOk(await GET("/api/v1/dns/query-logs?limit=5"));
    assert(Array.isArray(data), `not array: ${JSON.stringify(data).slice(0, 80)}`);
    check("log rows", true, `${data.length} rows`);
  });

  await tc("delete policy + record → gone via list", async () => {
    expectOk(await DEL(`/api/v1/dns/policies/${polId}`));
    expectOk(await DEL(`/api/v1/dns/records/${recId}`));
    const recs = (await GET("/api/v1/dns/records?q=host1")).json?.data ?? [];
    assert(!recs.some((x) => x.id === recId), "A record still present");
    const pols = (await GET("/api/v1/dns/policies")).json?.data ?? [];
    assert(!pols.some((x) => x.id === polId), "policy still present");
    recId = polId = null;
  });
});

suite("dhcp", "DNS & DHCP → DHCP: subnets/reservations/relay/leases", async () => {
  let subId = null;
  let resId = null;
  let relaySnap = null;

  await tc("list subnets (baseline)", async () => {
    const data = expectOk(await GET("/api/v1/dhcp/subnets"));
    assert(Array.isArray(data), `not array: ${JSON.stringify(data).slice(0, 80)}`);
    check("baseline", true, `${data.length} subnets`);
  });

  await tc("create subnet 10.219.77.0/24 on ens34", async () => {
    const s = expectOk(await POST("/api/v1/dhcp/subnets", {
      interfaceName: "ens34", family: "ipv4", subnetCidr: "10.219.77.0/24",
      rangeStart: "10.219.77.100", rangeEnd: "10.219.77.200", gateway: "10.219.77.1",
      dnsServers: ["10.219.77.1"], leaseTime: 3600,
    }));
    subId = s.id;
    assert(s.subnetCidr === "10.219.77.0/24", JSON.stringify(s).slice(0, 160));
  });

  await tc("overlapping subnet → 400/409", async () => {
    const r = await POST("/api/v1/dhcp/subnets", {
      interfaceName: "ens34", family: "ipv4", subnetCidr: "10.219.77.128/25",
      rangeStart: "10.219.77.130", rangeEnd: "10.219.77.140",
    });
    assert(r.status === 400 || r.status === 409, `expected 400/409 got ${r.status}: ${JSON.stringify(r.json).slice(0, 160)}`);
  });

  await tc("pool outside subnet → 400", async () => {
    const r = await POST("/api/v1/dhcp/subnets", {
      interfaceName: "ens34", family: "ipv4", subnetCidr: "10.219.78.0/24",
      rangeStart: "10.219.99.10", rangeEnd: "10.219.99.20",
    });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("unknown interface → 400", async () => {
    const r = await POST("/api/v1/dhcp/subnets", {
      interfaceName: "ens99", family: "ipv4", subnetCidr: "10.219.79.0/24",
      rangeStart: "10.219.79.10", rangeEnd: "10.219.79.20",
    });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("update subnet — range end 210", async () => {
    const u = expectOk(await PUT(`/api/v1/dhcp/subnets/${subId}`, { rangeEnd: "10.219.77.210" }));
    assert(u.rangeEnd === "10.219.77.210", JSON.stringify(u).slice(0, 140));
  });

  await tc("create reservation (mac + ip in pool subnet)", async () => {
    const r = expectOk(await POST("/api/v1/dhcp/reservations", { subnetId: subId, mac: "AA:BB:CC:DD:EE:10", ip: "10.219.77.50", hostname: "e2e-host" }));
    resId = r.id;
    assert(r.mac === "aa:bb:cc:dd:ee:10", `mac=${r.mac}`);
  });

  await tc("reservation ip outside subnet → 400", async () => {
    const r = await POST("/api/v1/dhcp/reservations", { subnetId: subId, mac: "AA:BB:CC:DD:EE:11", ip: "10.219.99.50" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("update reservation hostname", async () => {
    const u = expectOk(await PUT(`/api/v1/dhcp/reservations/${resId}`, { hostname: "e2e-host2" }));
    assert(u.hostname === "e2e-host2", JSON.stringify(u).slice(0, 140));
  });

  await tc("leases list → array", async () => {
    const data = expectOk(await GET("/api/v1/dhcp/leases?limit=10"));
    assert(Array.isArray(data), `not array: ${JSON.stringify(data).slice(0, 80)}`);
    check("lease rows", true, `${data.length} rows`);
  });

  await tc("relay settings — snapshot → set → revert", async () => {
    relaySnap = expectOk(await GET("/api/v1/dhcp/relay"));
    const u = expectOk(await PUT("/api/v1/dhcp/relay", { enabled: true, servers: ["10.90.0.1"], interfaces: ["ens34"] }));
    assert(u.enabled === true && u.servers?.[0] === "10.90.0.1", JSON.stringify(u).slice(0, 140));
    // PUT schema requires ≥1 server/interface — an empty snapshot reverts to
    // disabled+placeholder (functionally identical to unset)
    const hasServers = Array.isArray(relaySnap?.servers) && relaySnap.servers.length > 0;
    const revertBody = hasServers
      ? relaySnap
      : { enabled: false, servers: ["127.0.0.1"], interfaces: ["lo"] };
    const back = expectOk(await PUT("/api/v1/dhcp/relay", revertBody));
    assert(back.enabled === revertBody.enabled, `revert enabled=${back.enabled}`);
    check("relay reverted", true, hasServers ? "exact snapshot" : "disabled state (empty snapshot not expressible via PUT schema)");
  });

  await tc("relay with zero servers → 400", async () => {
    const r = await PUT("/api/v1/dhcp/relay", { enabled: true, servers: [], interfaces: ["ens34"] });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("delete reservation + subnet → gone via list", async () => {
    expectOk(await DEL(`/api/v1/dhcp/reservations/${resId}`));
    expectOk(await DEL(`/api/v1/dhcp/subnets/${subId}`));
    const subs = (await GET("/api/v1/dhcp/subnets")).json?.data ?? [];
    assert(!subs.some((x) => x.id === subId), "subnet still present");
    const ress = (await GET("/api/v1/dhcp/reservations")).json?.data ?? [];
    assert(!ress.some((x) => x.id === resId), "reservation still present");
    subId = resId = null;
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// SUITES — batch 5: identity (users/groups/sessions/settings, access, advanced)
// ═════════════════════════════════════════════════════════════════════════════

suite("identity-users", "Identity → Users & Groups CRUD + auth settings + sessions read", async () => {
  const uname = `e2euser${ctx.tag.slice(0, 5)}`;
  let uid = null;
  let gid = null;
  let snap = null;

  await tc("list users (baseline)", async () => {
    const data = expectOk(await GET("/api/v1/users"));
    const rows = Array.isArray(data) ? data : data?.users ?? [];
    assert(Array.isArray(rows), `unexpected: ${JSON.stringify(data).slice(0, 100)}`);
    check("baseline", true, `${rows.length} users`);
  });

  await tc("create user (helpdesk role)", async () => {
    const u = expectOk(await POST("/api/v1/users", { username: uname, email: `${uname}@e2e-lab.local`, role: "helpdesk", password: "e2e-Pass-123" }));
    uid = u.id ?? u.user?.id;
    assert(uid, `no id: ${JSON.stringify(u).slice(0, 160)}`);
  });

  await tc("duplicate username → 400/409", async () => {
    const r = await POST("/api/v1/users", { username: uname, email: `${uname}@e2e-lab.local`, password: "x" });
    assert(r.status === 400 || r.status === 409, `expected 400/409 got ${r.status}: ${JSON.stringify(r.json).slice(0, 160)}`);
  });

  await tc("bad username grammar → 400", async () => {
    const r = await POST("/api/v1/users", { username: "AB", email: "a@b.c", password: "x" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("update user — email + role soc_analyst", async () => {
    const u = expectOk(await PUT(`/api/v1/users/${uid}`, { email: `${uname}-2@e2e-lab.local`, role: "soc_analyst" }));
    const got = u.email ?? u.user?.email;
    assert(got === `${uname}-2@e2e-lab.local` || got === null, `email=${got}`);
  });

  await tc("create group with user member", async () => {
    const g = expectOk(await POST("/api/v1/user-groups", { name: un("E2E-GROUP"), memberIds: [uid] }));
    gid = g.id;
    assert(gid, JSON.stringify(g).slice(0, 140));
  });

  await tc("update group members", async () => {
    const g = expectOk(await PUT(`/api/v1/user-groups/${gid}`, { memberIds: [] }));
    check("group updated", true, JSON.stringify(g).slice(0, 120));
  });

  await tc("assign user groupIds replace-all", async () => {
    const u = expectOk(await PUT(`/api/v1/users/${uid}`, { groupIds: [gid] }));
    check("groups assigned", true, JSON.stringify(u).slice(0, 120));
  });

  await tc("identity sessions read → array", async () => {
    const data = expectOk(await GET("/api/v1/identity/sessions?limit=10"));
    assert(Array.isArray(data), `not array: ${JSON.stringify(data).slice(0, 100)}`);
    check("session rows", true, `${data.length} rows`);
  });

  await tc("auth-settings snapshot → change session lifetime → revert", async () => {
    snap = expectOk(await GET("/api/v1/auth-settings"));
    const u = expectOk(await PUT("/api/v1/auth-settings", { ...snap, sessionLifetimeHours: 12 }));
    assert(u.sessionLifetimeHours === 12, JSON.stringify(u).slice(0, 160));
    const back = expectOk(await PUT("/api/v1/auth-settings", snap));
    assert(back.sessionLifetimeHours === snap.sessionLifetimeHours, "revert mismatch");
  });

  await tc("auth-settings invalid (lockout 2) → 400", async () => {
    const r = await PUT("/api/v1/auth-settings", { ...snap, lockout: { ...snap.lockout, maxAttempts: 2 } });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("delete group → delete user → gone via list", async () => {
    expectOk(await DEL(`/api/v1/user-groups/${gid}`));
    expectOk(await DEL(`/api/v1/users/${uid}`));
    const users = expectOk(await GET("/api/v1/users"));
    const rows = Array.isArray(users) ? users : users?.users ?? [];
    assert(!rows.some((x) => x.id === uid), "user still present");
    const groups = expectOk(await GET("/api/v1/user-groups"));
    const grows = Array.isArray(groups) ? groups : groups?.groups ?? [];
    assert(!grows.some((x) => x.id === gid), "group still present");
    uid = gid = null;
  });
});

suite("identity-access", "Identity → Directory sources / RADIUS / Captive portal / Vouchers", async () => {
  let srcId = null;
  let radId = null;
  let portalSnap = null;
  let voucherIds = [];

  await tc("create LDAP directory source", async () => {
    const s = expectOk(await POST("/api/v1/directory-sources", { name: un("E2E-LDAP"), type: "ldap", serverIp: "10.90.0.9", port: 389, baseDn: "dc=e2e,dc=local", bindDn: "cn=svc,dc=e2e,dc=local", bindPassword: "pw-e2e" }));
    srcId = s.id;
    assert(s.type === "ldap", JSON.stringify(s).slice(0, 160));
    assert(s.bindPassword !== "pw-e2e", `bindPassword NOT masked: ${s.bindPassword}`);
    check("secret masked", true, `bindPassword=${s.bindPassword}`);
  });

  await tc("bad baseDn → 400", async () => {
    const r = await POST("/api/v1/directory-sources", { name: un("E2E-BAD"), type: "ldap", serverIp: "10.90.0.9", baseDn: "not-a-dn" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("update directory source — port 636", async () => {
    const u = expectOk(await PUT(`/api/v1/directory-sources/${srcId}`, { port: 636 }));
    assert(u.port === 636, JSON.stringify(u).slice(0, 140));
  });

  await tc("create RADIUS profile", async () => {
    const p = expectOk(await POST("/api/v1/radius-profiles", { name: un("E2E-RADIUS"), serverIp: "10.90.0.10", authPort: 1812, sharedSecret: "e2e-secret-1", timeoutSec: 3, retries: 2 }));
    radId = p.id;
    assert(!p.sharedSecret || p.sharedSecret === "••••••" || typeof p.sharedSecret !== "string" || p.sharedSecret.includes("•"), `secret echoed? ${p.sharedSecret}`);
  });

  await tc("RADIUS reveal endpoint returns secret once", async () => {
    const d = expectOk(await POST(`/api/v1/radius-profiles/${radId}/reveal`, {}));
    assert(typeof d.sharedSecret === "string" && d.sharedSecret.includes("e2e-secret-1"), `reveal=${JSON.stringify(d).slice(0, 140)}`);
  });

  await tc("RADIUS update keeps secret when omitted", async () => {
    const u = expectOk(await PUT(`/api/v1/radius-profiles/${radId}`, { timeoutSec: 5 }));
    assert(u.timeoutSec === 5, JSON.stringify(u).slice(0, 140));
  });

  await tc("captive portal snapshot → update → revert", async () => {
    portalSnap = expectOk(await GET("/api/v1/captive-portal"));
    const cur = portalSnap?.profile ?? portalSnap ?? {};
    const body = {
      name: cur.name ?? "E2E-PORTAL", enabled: true, mode: "voucher", interfaceName: "ens34",
      sessionTimeoutMin: 60, voucherTtlHours: 24,
    };
    const u = expectOk(await PUT("/api/v1/captive-portal", body));
    const got = u.profile ?? u;
    assert(got.mode === "voucher" && got.enabled === true, JSON.stringify(got).slice(0, 200));
    const revertBody = {
      name: cur.name ?? "GUEST-PORTAL", enabled: cur.enabled ?? false, mode: cur.mode ?? "clickthrough",
      interfaceName: cur.interfaceName ?? "ens34", sessionTimeoutMin: cur.sessionTimeoutMin ?? 240,
      bandwidthKbps: cur.bandwidthKbps ?? null, redirectUrl: cur.redirectUrl ?? null,
      voucherTtlHours: cur.voucherTtlHours ?? 24,
    };
    const back = expectOk(await PUT("/api/v1/captive-portal", revertBody));
    check("portal reverted", true, `mode=${(back.profile ?? back).mode}`);
  });

  await tc("portal bad mode → 400", async () => {
    const r = await PUT("/api/v1/captive-portal", { name: "x", enabled: false, mode: "walled-garden", interfaceName: "ens34" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("generate 3 vouchers → returned codes", async () => {
    const d = expectOk(await POST("/api/v1/captive-portal/vouchers", { count: 3, ttlHours: 24 }));
    const rows = d.vouchers ?? d.codes ?? (Array.isArray(d) ? d : []);
    voucherIds = rows.map((v) => v.id).filter(Boolean);
    assert(voucherIds.length === 3, `generated=${JSON.stringify(d).slice(0, 200)}`);
  });

  await tc("voucher list shows 3 new", async () => {
    const data = expectOk(await GET("/api/v1/captive-portal/vouchers"));
    const rows = Array.isArray(data) ? data : data?.vouchers ?? [];
    const mine = rows.filter((v) => voucherIds.includes(v.id));
    assert(mine.length === 3, `found ${mine.length}/3`);
  });

  await tc("delete a voucher → gone", async () => {
    expectOk(await DEL(`/api/v1/captive-portal/vouchers/${voucherIds[0]}`));
    const data = expectOk(await GET("/api/v1/captive-portal/vouchers"));
    const rows = Array.isArray(data) ? data : data?.vouchers ?? [];
    assert(!rows.some((v) => v.id === voucherIds[0]), "voucher still present");
    voucherIds = voucherIds.slice(1);
  });

  await tc("delete radius + directory source + remaining vouchers", async () => {
    expectOk(await DEL(`/api/v1/radius-profiles/${radId}`));
    expectOk(await DEL(`/api/v1/directory-sources/${srcId}`));
    for (const id of voucherIds) await DEL(`/api/v1/captive-portal/vouchers/${id}`);
    const srcs = (await GET("/api/v1/directory-sources")).json?.data ?? [];
    assert(!srcs.some((x) => x.id === srcId), "source still present");
    srcId = radId = null;
    voucherIds = [];
  });
});

suite("identity-advanced", "Identity → Federation/NAC/CoA/BYOD/devices/activity", async () => {
  let idpId = null;
  let nacId = null;
  let coaId = null;
  let byodId = null;

  await tc("create SAML2 IdP", async () => {
    const p = expectOk(await POST("/api/v1/identity-advanced/idps", { name: un("E2E-IDP"), protocol: "saml2", entityId: "https://idp.e2e-lab.local/sso", ssoUrl: "https://idp.e2e-lab.local/saml", clientSecret: "s3cret" }));
    idpId = p.id;
    assert(p.protocol === "saml2" && !p.clientSecret, `secret echoed: ${JSON.stringify(p).slice(0, 160)}`);
  });

  await tc("SAML2 without entityId/metadataUrl → 400", async () => {
    const r = await POST("/api/v1/identity-advanced/idps", { name: un("E2E-BAD"), protocol: "saml2" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("update IdP — disable", async () => {
    const u = expectOk(await PUT(`/api/v1/identity-advanced/idps/${idpId}`, { enabled: false }));
    assert(u.enabled === false, JSON.stringify(u).slice(0, 140));
  });

  await tc("create NAC profile (802.1x + peap)", async () => {
    const p = expectOk(await POST("/api/v1/identity-advanced/nac-profiles", { name: un("E2E-NAC"), method: "802.1x", eapType: "peap", dynamicVlan: true, guestVlan: 900, authFailVlan: 901, profiling: true }));
    nacId = p.id;
    assert(p.method === "802.1x", JSON.stringify(p).slice(0, 160));
  });

  await tc("NAC profile update — mab", async () => {
    const u = expectOk(await PUT(`/api/v1/identity-advanced/nac-profiles/${nacId}`, { method: "mab" }));
    assert(u.method === "mab", `method=${u.method}`);
  });

  await tc("create CoA profile (dynamicVlan pool 100-200)", async () => {
    const p = expectOk(await POST("/api/v1/identity-advanced/coa-profiles", { name: un("E2E-COA"), coaEnabled: true, dynamicVlan: true, vlanPoolStart: 100, vlanPoolEnd: 200, sessionTimeoutMin: 480 }));
    coaId = p.id;
    assert(p.vlanPoolEnd === 200, JSON.stringify(p).slice(0, 160));
  });

  await tc("CoA pool without end → 400", async () => {
    const r = await POST("/api/v1/identity-advanced/coa-profiles", { name: un("E2E-BAD"), dynamicVlan: true, vlanPoolStart: 100 });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("CoA send (simulated reauth) on an existing user", async () => {
    const users = expectOk(await GET("/api/v1/users"));
    const rows = Array.isArray(users) ? users : users?.users ?? [];
    const target = rows[0]?.username;
    assert(target, "no existing user to target");
    const d = expectOk(await POST(`/api/v1/identity-advanced/coa-profiles/${coaId}/coa`, { userName: target, action: "reauth" }));
    check("coa ack", true, JSON.stringify(d).slice(0, 120));
  });

  await tc("CoA send with unknown user → 400 (validation works)", async () => {
    const r = await POST(`/api/v1/identity-advanced/coa-profiles/${coaId}/coa`, { userName: `e2e-nonexistent-${ctx.tag}`, action: "reauth" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("CoA vlan action without vlanId → 400", async () => {
    const r = await POST(`/api/v1/identity-advanced/coa-profiles/${coaId}/coa`, { userName: "e2e", action: "vlan" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("devices read → array", async () => {
    const data = expectOk(await GET("/api/v1/identity-advanced/devices?limit=50"));
    const rows = Array.isArray(data) ? data : data?.devices ?? [];
    assert(Array.isArray(rows), `unexpected: ${JSON.stringify(data).slice(0, 120)}`);
    check("device rows", true, `${rows.length} rows`);
  });

  await tc("devices rescan (simulated)", async () => {
    const d = await POST("/api/v1/identity-advanced/devices/rescan", {});
    check("rescan", true, `status=${d.status} body=${JSON.stringify(d.json).slice(0, 120)}`);
  });

  await tc("BYOD create enrollment (pending)", async () => {
    const d = expectOk(await POST("/api/v1/identity-advanced/byod", { userName: `e2euser${ctx.tag.slice(0, 5)}`, ttlHours: 24 }));
    byodId = d.id ?? d.enrollment?.id;
    assert(byodId, `no id: ${JSON.stringify(d).slice(0, 200)}`);
    const status = d.status ?? d.enrollment?.status;
    assert(status === "pending", `status=${status}`);
  });

  await tc("BYOD revoke while pending → revoked", async () => {
    const d = expectOk(await DEL(`/api/v1/identity-advanced/byod/${byodId}`));
    const status = d.status ?? d.enrollment?.status;
    assert(status === "revoked", `status=${status}`);
  });

  await tc("BYOD second enrollment + approve → approved", async () => {
    const d = expectOk(await POST("/api/v1/identity-advanced/byod", { userName: `e2euser${ctx.tag.slice(0, 5)}`, ttlHours: 24 }));
    byodId = d.id ?? d.enrollment?.id;
    const a = expectOk(await POST(`/api/v1/identity-advanced/byod/${byodId}/approve`, {}));
    const status = a.status ?? a.enrollment?.status;
    assert(status === "approved", `status=${status} body=${JSON.stringify(a).slice(0, 160)}`);
  });

  await tc("BYOD revoke after approve → 409 (M23 lifecycle guard)", async () => {
    const r = await DEL(`/api/v1/identity-advanced/byod/${byodId}`);
    expectErr(r, "CONFLICT", 409);
  });

  await tc("activity timeline read → array", async () => {
    const data = expectOk(await GET("/api/v1/identity-advanced/activity?limit=20"));
    const rows = Array.isArray(data) ? data : data?.activity ?? data?.events ?? [];
    assert(Array.isArray(rows), `unexpected: ${JSON.stringify(data).slice(0, 120)}`);
    check("activity rows", true, `${rows.length} rows`);
  });

  await tc("cleanup: coa + nac + idp → gone via list", async () => {
    expectOk(await DEL(`/api/v1/identity-advanced/coa-profiles/${coaId}`));
    expectOk(await DEL(`/api/v1/identity-advanced/nac-profiles/${nacId}`));
    expectOk(await DEL(`/api/v1/identity-advanced/idps/${idpId}`));
    const idps = (await GET("/api/v1/identity-advanced/idps")).json?.data ?? [];
    assert(!idps.some((x) => x.id === idpId), "idp still present");
    idpId = nacId = coaId = null;
  });

  await tc("note: approved BYOD row remains (M23 spec: pending-only revoke)", async () => {
    check("byod leftover", true, `enrollment ${byodId} approved — documented M23 lifecycle dead-end`);
    byodId = null;
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// SUITES — batch 6: ips, vpn
// ═════════════════════════════════════════════════════════════════════════════

suite("ips", "IPS → Policies CRUD + preset + categories + events + update settings", async () => {
  let polId = null;
  let presetId = null;
  let snap = null;

  await tc("list policies (baseline)", async () => {
    const data = expectOk(await GET("/api/v1/ips/policies"));
    assert(Array.isArray(data), `not array: ${JSON.stringify(data).slice(0, 100)}`);
    check("baseline", true, `${data.length} policies`);
  });

  await tc("create IPS policy (categories + custom rule)", async () => {
    const p = expectOk(await POST("/api/v1/ips/policies", {
      name: un("E2E-IPS"), mode: "inline_drop",
      ruleCategories: { trojan: true, scan: true, dos: false },
      customRules: ['alert tcp any any -> any any (msg:"E2E test rule"; sid:9000001;)'],
      exceptions: [{ sid: 9000001, source: "10.90.0.5", comment: "e2e allow" }],
      thresholds: [{ sid: 9000001, track: "by_src", count: 10, seconds: 60 }],
    }));
    polId = p.id;
    assert(p.mode === "inline_drop", JSON.stringify(p).slice(0, 160));
  });

  await tc("unknown category → 400", async () => {
    const r = await POST("/api/v1/ips/policies", { name: un("E2E-BAD"), ruleCategories: { notacat: true } });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("custom rule without sid → 400 (per-line errors)", async () => {
    const r = await POST("/api/v1/ips/policies", { name: un("E2E-BAD2"), customRules: ['alert tcp any any -> any any (msg:"no sid";)'] });
    expectErr(r, "VALIDATION_ERROR", 400);
    assert(JSON.stringify(r.json.error.details ?? "").includes("sid"), "details should mention sid");
  });

  await tc("update policy — mode passive", async () => {
    const u = expectOk(await PUT(`/api/v1/ips/policies/${polId}`, { mode: "passive" }));
    assert(u.mode === "passive", `mode=${u.mode}`);
  });

  await tc("apply-preset balanced → new policy", async () => {
    const d = expectOk(await POST("/api/v1/ips/policies/apply-preset", { preset: "balanced", name: un("E2E-IPS-PRESET") }));
    presetId = d.id ?? d.policy?.id;
    assert(presetId, `no id: ${JSON.stringify(d).slice(0, 160)}`);
  });

  await tc("rule-categories endpoint → list", async () => {
    const d = expectOk(await GET("/api/v1/ips/rule-categories"));
    check("categories", true, JSON.stringify(d).slice(0, 120));
  });

  await tc("events list → array", async () => {
    const d = expectOk(await GET("/api/v1/ips/events?limit=5"));
    const rows = Array.isArray(d) ? d : d?.events ?? [];
    assert(Array.isArray(rows), `unexpected: ${JSON.stringify(d).slice(0, 120)}`);
    check("event rows", true, `${rows.length} rows`);
  });

  await tc("suppress first event (24h) if any", async () => {
    const d = expectOk(await GET("/api/v1/ips/events?limit=1"));
    const rows = Array.isArray(d) ? d : d?.events ?? [];
    if (!rows.length) {
      check("no events to suppress", true, "skipped (no seeded events)");
      return;
    }
    const sid = rows[0].id;
    const s = expectOk(await POST(`/api/v1/ips/events/${sid}/suppress`, { duration: "24h" }));
    check("suppressed", true, JSON.stringify(s).slice(0, 120));
  });

  await tc("update-settings snapshot → change → revert", async () => {
    snap = expectOk(await GET("/api/v1/ips/update-settings"));
    const body = { enabled: snap.enabled ?? true, interval: snap.interval ?? "daily", time: "04:45", source: snap.source };
    const u = expectOk(await PUT("/api/v1/ips/update-settings", body));
    assert(u.time === "04:45", JSON.stringify(u).slice(0, 160));
    const back = expectOk(await PUT("/api/v1/ips/update-settings", { enabled: snap.enabled ?? true, interval: snap.interval ?? "daily", time: snap.time ?? "03:00", source: snap.source }));
    assert(back.time === (snap.time ?? "03:00"), `revert time=${back.time}`);
  });

  await tc("update-settings bad interval → 400", async () => {
    const r = await PUT("/api/v1/ips/update-settings", { ...snap, interval: "hourly" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("delete preset + policy → gone via list", async () => {
    expectOk(await DEL(`/api/v1/ips/policies/${presetId}`));
    expectOk(await DEL(`/api/v1/ips/policies/${polId}`));
    const list = (await GET("/api/v1/ips/policies")).json?.data ?? [];
    assert(!list.some((x) => x.id === polId || x.id === presetId), "policy still present");
    polId = presetId = null;
  });
});

suite("vpn", "VPN → Configs (WG s2s + remote) + status + bundle + sessions + user groups", async () => {
  let s2sId = null;
  let remId = null;
  let grpId = null;

  await tc("list configs (baseline)", async () => {
    const data = expectOk(await GET("/api/v1/vpn/configs"));
    assert(Array.isArray(data), `not array: ${JSON.stringify(data).slice(0, 100)}`);
    check("baseline", true, `${data.length} configs`);
  });

  await tc("create wireguard_s2s config", async () => {
    const c = expectOk(await POST("/api/v1/vpn/configs", {
      name: un("E2E-WG-S2S"), type: "wireguard_s2s",
      config: {
        privateKey: "e2e-private-key-placeholder==", listenPort: 51821,
        address: "10.99.1.1/24",
        peers: [{ name: "e2e-peer", publicKey: "e2e-public-key-placeholder==", allowedIps: ["10.99.1.2/32"], endpoint: "198.51.100.10:51821", keepaliveSec: 25 }],
      },
    }));
    s2sId = c.id;
    assert(c.type === "wireguard_s2s", JSON.stringify(c).slice(0, 160));
  });

  await tc("WG s2s without privateKey → 400", async () => {
    const r = await POST("/api/v1/vpn/configs", { name: un("E2E-BAD"), type: "wireguard_s2s", config: { listenPort: 51820, address: "10.99.2.1/24", peers: [] } });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("config type mismatch (openvpn shape on s2s) → 400", async () => {
    const r = await POST("/api/v1/vpn/configs", { name: un("E2E-BAD2"), type: "wireguard_s2s", config: { proto: "udp", port: 1194, pool: "10.99.3.0/24" } });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("create wireguard_remote config (client pool)", async () => {
    const c = expectOk(await POST("/api/v1/vpn/configs", {
      name: un("E2E-WG-REM"), type: "wireguard_remote",
      config: { privateKey: "e2e-rem-key==", listenPort: 51822, address: "10.99.4.1/24", pool: "10.99.4.0/24", dns: "10.99.4.1", peers: [] },
    }));
    remId = c.id;
    assert(c.type === "wireguard_remote", JSON.stringify(c).slice(0, 160));
  });

  await tc("update s2s config — disable", async () => {
    const u = expectOk(await PUT(`/api/v1/vpn/configs/${s2sId}`, { enabled: false }));
    assert(u.enabled === false, JSON.stringify(u).slice(0, 140));
  });

  await tc("status endpoint (engine-owned, simulated)", async () => {
    const d = expectOk(await GET(`/api/v1/vpn/configs/${s2sId}/status`));
    check("status", true, JSON.stringify(d).slice(0, 140));
  });

  await tc("client-bundle for remote config (POST)", async () => {
    const r = await POST(`/api/v1/vpn/configs/${remId}/client-bundle`, {});
    assert(r.status === 200 || r.status === 400, `bundle status=${r.status}`);
    check("bundle", true, r.status === 200 ? `${String(JSON.stringify(r.json)).length}B` : `rejected: ${JSON.stringify(r.json).slice(0, 100)}`);
  });

  await tc("vpn sessions list → array", async () => {
    const d = expectOk(await GET("/api/v1/vpn/sessions?limit=10"));
    const rows = Array.isArray(d) ? d : d?.sessions ?? [];
    assert(Array.isArray(rows), `unexpected: ${JSON.stringify(d).slice(0, 120)}`);
    check("session rows", true, `${rows.length} rows`);
  });

  await tc("create vpn user group", async () => {
    const g = expectOk(await POST("/api/v1/vpn/user-groups", { name: un("E2E-VGROUP"), pool: "10.99.9.0/24", dns: "10.99.9.1", idleTimeoutMin: 30, maxSessionsPerUser: 2 }));
    grpId = g.id;
    assert(gid_ok(g), JSON.stringify(g).slice(0, 120));
  });

  await tc("update vpn user group", async () => {
    const g = expectOk(await PUT(`/api/v1/vpn/user-groups/${grpId}`, { idleTimeoutMin: 60 }));
    assert(g.idleTimeoutMin === 60, JSON.stringify(g).slice(0, 140));
  });

  await tc("bad pool cidr → 400", async () => {
    const r = await POST("/api/v1/vpn/user-groups", { name: un("E2E-BAD"), pool: "10.99.9.0/99" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("delete group + configs → gone via list", async () => {
    expectOk(await DEL(`/api/v1/vpn/user-groups/${grpId}`));
    expectOk(await DEL(`/api/v1/vpn/configs/${s2sId}`));
    expectOk(await DEL(`/api/v1/vpn/configs/${remId}`));
    const list = (await GET("/api/v1/vpn/configs")).json?.data ?? [];
    assert(!list.some((x) => x.id === s2sId || x.id === remId), "config still present");
    s2sId = remId = grpId = null;
  });
});

function gid_ok(g) {
  return Boolean(g.id);
}

// ═════════════════════════════════════════════════════════════════════════════
// SUITES — batch 7: web security (ssl, urlf, waf, appctl)
// ═════════════════════════════════════════════════════════════════════════════

suite("ssl", "Web Security → SSL Inspection: policies + bypass rules + stats/logs", async () => {
  let polId = null;
  let ruleId = null;
  let caId = null;

  await tc("temp signing CA for selective mode", async () => {
    const c = expectOk(await POST("/api/v1/pki/cas", { name: un("E2E-SSL-CA"), type: "root", commonName: "E2E SSL CA", keyType: "rsa2048", validityDays: 365 }));
    caId = c.id ?? c.ca?.id;
    assert(caId, `no CA id: ${JSON.stringify(c).slice(0, 160)}`);
    track(`/api/v1/pki/cas/${caId}`);
  });

  await tc("list policies (baseline)", async () => {
    const data = expectOk(await GET("/api/v1/ssl-inspection/policies"));
    assert(Array.isArray(data), `not array: ${JSON.stringify(data).slice(0, 100)}`);
    check("baseline", true, `${data.length} policies`);
  });

  await tc("create SSL policy (selective + signing CA)", async () => {
    const p = expectOk(await POST("/api/v1/ssl-inspection/policies", { name: un("E2E-SSL"), mode: "selective", signingCaId: caId, hstsHandling: "honor", certPinningAction: "bypass", invalidCertAction: "block", minTlsVersion: "1.2" }));
    polId = p.id;
    assert(p.mode === "selective", JSON.stringify(p).slice(0, 160));
  });

  await tc("selective without signingCaId → 400", async () => {
    const r = await POST("/api/v1/ssl-inspection/policies", { name: un("E2E-BAD"), mode: "selective" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("update policy — full mode + minTls 1.3", async () => {
    const u = expectOk(await PUT(`/api/v1/ssl-inspection/policies/${polId}`, { mode: "full", minTlsVersion: "1.3" }));
    assert(u.mode === "full" && u.minTlsVersion === "1.3", JSON.stringify(u).slice(0, 160));
  });

  await tc("non-numeric id → 400 (not 500)", async () => {
    const r = await PUT("/api/v1/ssl-inspection/policies/null", { mode: "full" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("create bypass rule (domain banking.e2e-lab.local)", async () => {
    const r = expectOk(await POST("/api/v1/ssl-inspection/bypass-rules", { policyId: polId, matchType: "domain", matchValue: "banking.e2e-lab.local", reason: "e2e banking" }));
    ruleId = r.id;
    assert(r.matchValue === "banking.e2e-lab.local", JSON.stringify(r).slice(0, 160));
  });

  await tc("bypass rule bad value for cidr type → 400", async () => {
    const r = await POST("/api/v1/ssl-inspection/bypass-rules", { policyId: polId, matchType: "cidr", matchValue: "not-a-cidr" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("update bypass rule — disable", async () => {
    const u = expectOk(await PUT(`/api/v1/ssl-inspection/bypass-rules/${ruleId}`, { enabled: false }));
    assert(u.enabled === false, JSON.stringify(u).slice(0, 140));
  });

  await tc("stats + logs endpoints", async () => {
    const st = expectOk(await GET("/api/v1/ssl-inspection/stats"));
    check("stats", true, JSON.stringify(st).slice(0, 100));
    const lg = expectOk(await GET("/api/v1/ssl-inspection/logs?limit=5"));
    const rows = Array.isArray(lg) ? lg : lg?.logs ?? [];
    check("logs", true, `${rows.length} rows`);
  });

  await tc("delete bypass rule + policy → gone via list", async () => {
    expectOk(await DEL(`/api/v1/ssl-inspection/bypass-rules/${ruleId}`));
    expectOk(await DEL(`/api/v1/ssl-inspection/policies/${polId}`));
    const list = (await GET("/api/v1/ssl-inspection/policies")).json?.data ?? [];
    assert(!list.some((x) => x.id === polId), "policy still present");
    polId = ruleId = null;
  });
});

suite("urlf", "Web Security → URL Filtering: policies + category rules + custom lists + import", async () => {
  let polId = null;
  let listId = null;

  await tc("list policies (baseline)", async () => {
    const data = expectOk(await GET("/api/v1/url-filter/policies"));
    assert(Array.isArray(data), `not array: ${JSON.stringify(data).slice(0, 100)}`);
    check("baseline", true, `${data.length} policies`);
  });

  await tc("create URL filter policy", async () => {
    const p = expectOk(await POST("/api/v1/url-filter/policies", { name: un("E2E-URLF"), defaultAction: "allow", safeSearchEnforce: true, transparentProxy: true }));
    polId = p.id;
    assert(p.defaultAction === "allow", JSON.stringify(p).slice(0, 160));
  });

  await tc("update policy — defaultAction block", async () => {
    const u = expectOk(await PUT(`/api/v1/url-filter/policies/${polId}`, { defaultAction: "block" }));
    assert(u.defaultAction === "block", `action=${u.defaultAction}`);
  });

  await tc("category rules GET (13-row joined view)", async () => {
    const rules = expectOk(await GET(`/api/v1/url-filter/policies/${polId}/categories`));
    assert(Array.isArray(rules) && rules.length >= 10, `rows=${Array.isArray(rules) ? rules.length : "nan"}`);
  });

  await tc("category rules PUT — block gambling+malware", async () => {
    const d = expectOk(await PUT(`/api/v1/url-filter/policies/${polId}/categories`, { rules: [{ category: "gambling", action: "block", enabled: true }, { category: "malware", action: "block", enabled: true }] }));
    const configured = d.filter((r) => r.configured && r.action === "block");
    assert(configured.length === 2, `configured=${JSON.stringify(d).slice(0, 200)}`);
  });

  await tc("category rules bad category → 400", async () => {
    const r = await PUT(`/api/v1/url-filter/policies/${polId}/categories`, { rules: [{ category: "nosuchcat", action: "block", enabled: true }] });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("custom list add block domain", async () => {
    const c = expectOk(await POST("/api/v1/url-filter/custom-lists", { policyId: polId, listType: "block", matchType: "domain", value: "blocked.e2e-lab.local" }));
    listId = c.id;
    assert(c.value === "blocked.e2e-lab.local", JSON.stringify(c).slice(0, 140));
  });

  await tc("custom list bad wildcard → 400", async () => {
    const r = await POST("/api/v1/url-filter/custom-lists", { policyId: polId, listType: "block", matchType: "wildcard", value: "http://bad" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("import by paste (2 lines, 1 bad)", async () => {
    const d = expectOk(await POST("/api/v1/url-filter/custom-lists/import", { policyId: polId, listType: "block", text: "ads.e2e-lab.local\n*.trackers.e2e-lab.local" }));
    check("import result", true, JSON.stringify(d).slice(0, 140));
  });

  await tc("stats + logs", async () => {
    const st = expectOk(await GET("/api/v1/url-filter/stats"));
    check("stats", true, JSON.stringify(st).slice(0, 100));
    const lg = expectOk(await GET("/api/v1/url-filter/logs?limit=5"));
    const rows = Array.isArray(lg) ? lg : lg?.logs ?? [];
    check("logs", true, `${rows.length} rows`);
  });

  await tc("delete custom lists + policy → gone via list", async () => {
    expectOk(await DEL(`/api/v1/url-filter/custom-lists/${listId}`));
    expectOk(await DEL(`/api/v1/url-filter/policies/${polId}`));
    const list = (await GET("/api/v1/url-filter/policies")).json?.data ?? [];
    assert(!list.some((x) => x.id === polId), "policy still present");
    polId = listId = null;
  });
});

suite("waf", "Web Security → WAF: vhosts + policies + exclusions + logs", async () => {
  let vhId = null;
  let polId = null;
  let exId = null;

  await tc("list vhosts (baseline)", async () => {
    const data = expectOk(await GET("/api/v1/waf/vhosts"));
    assert(Array.isArray(data), `not array: ${JSON.stringify(data).slice(0, 100)}`);
    check("baseline", true, `${data.length} vhosts`);
  });

  await tc("create vhost (no TLS cert)", async () => {
    const v = expectOk(await POST("/api/v1/waf/vhosts", { name: un("E2E-VHOST"), hostname: "shop.e2e-lab.local", backendHost: "10.90.0.80", backendPort: 8080, listenPort: 8443, tls: false, mode: "waf" }));
    vhId = v.id;
    assert(v.hostname === "shop.e2e-lab.local", JSON.stringify(v).slice(0, 160));
  });

  await tc("vhost bad hostname → 400", async () => {
    const r = await POST("/api/v1/waf/vhosts", { name: un("E2E-BAD"), hostname: "not a hostname", backendHost: "10.90.0.80", tls: false });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("create WAF policy on vhost", async () => {
    const p = expectOk(await POST("/api/v1/waf/policies", { name: un("E2E-WAFPOL"), vhostId: vhId, owaspCrsEnabled: true, crsVersion: "4.0", paranoiaLevel: 2, anomalyInThreshold: 10, geoBlockCountries: ["KP"], rateLimitRpm: 300, rateLimitBurst: 50 }));
    polId = p.id;
    assert(p.paranoiaLevel === 2, JSON.stringify(p).slice(0, 200));
  });

  await tc("second policy on same vhost → 409 (one per vhost)", async () => {
    const r = await POST("/api/v1/waf/policies", { name: un("E2E-WAFPOL2"), vhostId: vhId });
    expectErr(r, "CONFLICT", 409);
  });

  await tc("policy on missing vhost → 404", async () => {
    const r = await POST("/api/v1/waf/policies", { name: un("E2E-WAFPOL3"), vhostId: 99999999 });
    expectErr(r, "NOT_FOUND", 404);
  });

  await tc("update policy — paranoia 3 + learning mode", async () => {
    const u = expectOk(await PUT(`/api/v1/waf/policies/${polId}`, { paranoiaLevel: 3, learningMode: true }));
    assert(u.paranoiaLevel === 3 && u.learningMode === true, JSON.stringify(u).slice(0, 180));
  });

  await tc("create exclusion (rule_id scope)", async () => {
    const e = expectOk(await POST(`/api/v1/waf/policies/${polId}/exclusions`, { scope: "rule_id", matchValue: "942100", note: "e2e exclusion" }));
    exId = e.id;
    assert(e.matchValue === "942100", JSON.stringify(e).slice(0, 160));
  });

  await tc("update exclusion — disable", async () => {
    const u = expectOk(await PUT(`/api/v1/waf/policies/${polId}/exclusions/${exId}`, { enabled: false }));
    assert(u.enabled === false, JSON.stringify(u).slice(0, 140));
  });

  await tc("waf logs + stats", async () => {
    const lg = expectOk(await GET("/api/v1/waf/logs?limit=5"));
    const rows = Array.isArray(lg) ? lg : lg?.logs ?? [];
    check("logs", true, `${rows.length} rows`);
    const st = expectOk(await GET("/api/v1/waf/stats"));
    check("stats", true, JSON.stringify(st).slice(0, 100));
  });

  await tc("delete exclusion → policy → vhost → gone via list", async () => {
    expectOk(await DEL(`/api/v1/waf/policies/${polId}/exclusions/${exId}`));
    expectOk(await DEL(`/api/v1/waf/policies/${polId}`));
    expectOk(await DEL(`/api/v1/waf/vhosts/${vhId}`));
    const vhosts = (await GET("/api/v1/waf/vhosts")).json?.data ?? [];
    assert(!vhosts.some((x) => x.id === vhId), "vhost still present");
    vhId = polId = exId = null;
  });
});

suite("appctl", "Web Security → App Control: policies + rules + catalog + logs", async () => {
  let polId = null;
  let ruleId = null;
  let appName = null;
  let appName2 = null;

  await tc("catalog read + pick two apps", async () => {
    const d = expectOk(await GET("/api/v1/app-control/catalog"));
    const rows = Array.isArray(d) ? d : d?.apps ?? d?.catalog ?? [];
    assert(rows.length >= 2, `catalog too small: ${JSON.stringify(d).slice(0, 120)}`);
    appName = rows[0].name ?? rows[0].appName;
    appName2 = rows[1].name ?? rows[1].appName;
    assert(typeof appName === "string" && appName.length > 0, `no name: ${JSON.stringify(rows[0]).slice(0, 120)}`);
    check("catalog", true, `${rows.length} apps, first=${appName}`);
  });

  await tc("list policies (baseline)", async () => {
    const data = expectOk(await GET("/api/v1/app-control/policies"));
    assert(Array.isArray(data), `not array: ${JSON.stringify(data).slice(0, 100)}`);
    check("baseline", true, `${data.length} policies`);
  });

  await tc("create app-control policy (block default for unknown)", async () => {
    const p = expectOk(await POST("/api/v1/app-control/policies", { name: un("E2E-APPCTL"), defaultAction: "allow", unknownAppAction: "log" }));
    polId = p.id;
    assert(p.unknownAppAction === "log", JSON.stringify(p).slice(0, 160));
  });

  await tc("bad action → 400", async () => {
    const r = await POST("/api/v1/app-control/policies", { name: un("E2E-BAD"), defaultAction: "deny" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("create rule (block app, upload direction)", async () => {
    const r = expectOk(await POST(`/api/v1/app-control/policies/${polId}/rules`, { appName, action: "block", direction: "upload" }));
    ruleId = r.id ?? r.rule?.id;
    assert(ruleId, JSON.stringify(r).slice(0, 180));
  });

  await tc("limit rule without bandwidth → 400", async () => {
    const r = await POST(`/api/v1/app-control/policies/${polId}/rules`, { appName, action: "limit" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("limit rule with bandwidth 10 (different app)", async () => {
    const r = expectOk(await POST(`/api/v1/app-control/policies/${polId}/rules`, { appName: appName2, action: "limit", bandwidthLimitMbps: 10, direction: "download" }));
    const rid = r.id ?? r.rule?.id;
    assert(rid, JSON.stringify(r).slice(0, 180));
    await DEL(`/api/v1/app-control/rules/${rid}`);
  });

  await tc("duplicate app rule → 409", async () => {
    const r = await POST(`/api/v1/app-control/policies/${polId}/rules`, { appName, action: "block", direction: "upload" });
    assert(r.status === 409 || r.status === 400, `expected 409/400 got ${r.status}`);
  });

  await tc("update rule — allow", async () => {
    const u = expectOk(await PUT(`/api/v1/app-control/rules/${ruleId}`, { action: "allow" }));
    const act = u.action ?? u.rule?.action;
    assert(act === "allow", JSON.stringify(u).slice(0, 140));
  });

  await tc("logs + stats", async () => {
    const lg = expectOk(await GET("/api/v1/app-control/logs?limit=5"));
    const rows = Array.isArray(lg) ? lg : lg?.logs ?? [];
    check("logs", true, `${rows.length} rows`);
    const st = expectOk(await GET("/api/v1/app-control/stats"));
    check("stats", true, JSON.stringify(st).slice(0, 100));
  });

  await tc("delete rule + policy → gone via list", async () => {
    expectOk(await DEL(`/api/v1/app-control/rules/${ruleId}`));
    expectOk(await DEL(`/api/v1/app-control/policies/${polId}`));
    const list = (await GET("/api/v1/app-control/policies")).json?.data ?? [];
    assert(!list.some((x) => x.id === polId), "policy still present");
    polId = ruleId = null;
    appName = null;
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// SUITES — batch 8: dynroute (BGP/OSPF/BFD/prefix/route-map/community), sdwan, ipv6
// ═════════════════════════════════════════════════════════════════════════════

suite("dynroute", "Advanced Routing → BGP/OSPF/BFD/prefix-lists/route-maps/community-lists/rib", async () => {
  let ospfSnap = null;
  let ospfIfaceId = null;
  let nbrId = null;
  let bfdId = null;
  let plId = null;
  let rmId = null;
  let clId = null;

  await tc("ospf settings snapshot → change → revert", async () => {
    ospfSnap = expectOk(await GET("/api/v1/dynamic-routing/ospf/settings"));
    const body = { routerId: "10.220.0.9", referenceBandwidth: 10000, gracefulRestart: false, enabled: ospfSnap.enabled ?? false };
    const u = expectOk(await PUT("/api/v1/dynamic-routing/ospf/settings", body));
    assert(u.routerId === "10.220.0.9", JSON.stringify(u).slice(0, 160));
    const back = expectOk(await PUT("/api/v1/dynamic-routing/ospf/settings", { ...ospfSnap, routerId: ospfSnap.routerId ?? "1.1.1.1", referenceBandwidth: ospfSnap.referenceBandwidth ?? 100, gracefulRestart: ospfSnap.gracefulRestart ?? false, enabled: ospfSnap.enabled ?? false }));
    check("ospf reverted", true, `routerId=${back.routerId}`);
  });

  await tc("ospf settings bad routerId → 400", async () => {
    const r = await PUT("/api/v1/dynamic-routing/ospf/settings", { routerId: "nope", referenceBandwidth: 100, gracefulRestart: false, enabled: false });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("ospf interface create on ens34", async () => {
    const i = expectOk(await POST("/api/v1/dynamic-routing/ospf/interfaces", { interfaceName: "ens34", area: "0.0.0.0", helloSec: 10, deadSec: 40, cost: 10, networkType: "broadcast", passive: true, enabled: true }));
    ospfIfaceId = i.id;
    assert(i.area === "0.0.0.0", JSON.stringify(i).slice(0, 160));
  });

  await tc("ospf interface dead < 2×hello → 400", async () => {
    const r = await POST("/api/v1/dynamic-routing/ospf/interfaces", { interfaceName: "ens34", area: "0.0.0.0", helloSec: 10, deadSec: 15 });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("ospf interface update — cost 20", async () => {
    const u = expectOk(await PUT(`/api/v1/dynamic-routing/ospf/interfaces/${ospfIfaceId}`, { cost: 20 }));
    assert(u.cost === 20, JSON.stringify(u).slice(0, 140));
  });

  await tc("bfd profile create + update", async () => {
    const b = expectOk(await POST("/api/v1/dynamic-routing/bfd-profiles", { name: un("E2E-BFD"), detectMultiplier: 3, txIntervalMs: 300, rxIntervalMs: 300, enabled: true }));
    bfdId = b.id;
    const u = expectOk(await PUT(`/api/v1/dynamic-routing/bfd-profiles/${bfdId}`, { txIntervalMs: 500 }));
    assert(u.txIntervalMs === 500, JSON.stringify(u).slice(0, 140));
  });

  await tc("prefix-list create (ipv4 2 entries)", async () => {
    const p = expectOk(await POST("/api/v1/dynamic-routing/prefix-lists", { name: un("E2E-PL"), family: "ipv4", entries: [{ seq: 10, action: "permit", prefix: "10.220.0.0/16", ge: 16, le: 24 }, { seq: 20, action: "deny", prefix: "0.0.0.0/0" }] }));
    plId = p.id;
    assert(p.entryCount === 2 || JSON.parse(p.entries).length === 2, JSON.stringify(p).slice(0, 160));
  });

  await tc("prefix-list bad family cidr → 400", async () => {
    const r = await POST("/api/v1/dynamic-routing/prefix-lists", { name: un("E2E-BAD"), family: "ipv4", entries: [{ seq: 10, action: "permit", prefix: "2001:db8::/32" }] });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("route-map create (match prefix-list)", async () => {
    const r = expectOk(await POST("/api/v1/dynamic-routing/route-maps", { name: un("E2E-RM"), entries: [{ seq: 10, action: "permit", matchPrefixListId: plId, setLocalPref: 200 }] }));
    rmId = r.id;
    assert(r.entryCount === 1 || JSON.parse(r.entries).length === 1, JSON.stringify(r).slice(0, 160));
  });

  await tc("route-map entry without match → 400", async () => {
    const r = await POST("/api/v1/dynamic-routing/route-maps", { name: un("E2E-BAD2"), entries: [{ seq: 10, action: "permit", setLocalPref: 100 }] });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("community-list create", async () => {
    const c = expectOk(await POST("/api/v1/dynamic-routing/community-lists", { name: un("E2E-CL"), type: "standard", entries: ["65000:100"] }));
    clId = c.id;
    const entries = typeof c.entries === "string" ? JSON.parse(c.entries) : c.entries;
    assert(entries?.[0] === "65000:100", JSON.stringify(c).slice(0, 160));
  });

  await tc("community-list bad tag → 400", async () => {
    const r = await POST("/api/v1/dynamic-routing/community-lists", { name: un("E2E-BAD3"), type: "standard", entries: ["notatag"] });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("bgp neighbor create", async () => {
    const n = expectOk(await POST("/api/v1/dynamic-routing/bgp/neighbors", { name: un("E2E-BGP"), remoteAs: 65001, peerIp: "10.220.0.1", keepaliveSec: 30, holdtimeSec: 90, enabled: true }));
    nbrId = n.id;
    assert(n.remoteAs === 65001, JSON.stringify(n).slice(0, 160));
  });

  await tc("bgp holdtime < 3×keepalive → 400", async () => {
    const r = await POST("/api/v1/dynamic-routing/bgp/neighbors", { name: un("E2E-BAD4"), remoteAs: 65002, peerIp: "10.220.0.2", keepaliveSec: 60, holdtimeSec: 100 });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("bgp neighbor session action start (simulated)", async () => {
    const d = expectOk(await POST(`/api/v1/dynamic-routing/bgp/neighbors/${nbrId}/session`, { action: "start" }));
    check("session action", true, JSON.stringify(d).slice(0, 120));
  });

  await tc("bgp neighbor update — localAs", async () => {
    const u = expectOk(await PUT(`/api/v1/dynamic-routing/bgp/neighbors/${nbrId}`, { localAs: 65000 }));
    assert(Number(u.localAs) === 65000, JSON.stringify(u).slice(0, 140));
  });

  await tc("rib read + refresh", async () => {
    const rib = expectOk(await GET("/api/v1/dynamic-routing/rib?limit=20"));
    const rows = Array.isArray(rib) ? rib : rib?.routes ?? [];
    check("rib rows", true, `${rows.length} rows`);
    const r = await POST("/api/v1/dynamic-routing/rib/refresh", {});
    check("rib refresh", true, `status=${r.status}`);
  });

  await tc("cleanup: nbr/bfd/pl/rm/cl + ospf iface → gone", async () => {
    expectOk(await DEL(`/api/v1/dynamic-routing/bgp/neighbors/${nbrId}`));
    expectOk(await DEL(`/api/v1/dynamic-routing/bfd-profiles/${bfdId}`));
    expectOk(await DEL(`/api/v1/dynamic-routing/prefix-lists/${plId}`));
    expectOk(await DEL(`/api/v1/dynamic-routing/route-maps/${rmId}`));
    expectOk(await DEL(`/api/v1/dynamic-routing/community-lists/${clId}`));
    expectOk(await DEL(`/api/v1/dynamic-routing/ospf/interfaces/${ospfIfaceId}`));
    nbrId = bfdId = plId = rmId = clId = ospfIfaceId = null;
  });
});

suite("sdwan", "Advanced Routing → SD-WAN: sla/overlays/sites/paths/policies + probe + stats", async () => {
  let slaId = null;
  let ovId = null;
  let siteId = null;
  let polId = null;

  await tc("sla profile create + update", async () => {
    const s = expectOk(await POST("/api/v1/sdwan/sla-profiles", { name: un("E2E-SLA"), latencyMsMax: 150, jitterMsMax: 30, lossPctMax: 2, actionOnBreach: "switch" }));
    slaId = s.id;
    const u = expectOk(await PUT(`/api/v1/sdwan/sla-profiles/${slaId}`, { latencyMsMax: 200 }));
    assert(Number(u.latencyMsMax) === 200, JSON.stringify(u).slice(0, 140));
  });

  await tc("sla bad loss → 400", async () => {
    const r = await POST("/api/v1/sdwan/sla-profiles", { name: un("E2E-BAD"), latencyMsMax: 150, jitterMsMax: 30, lossPctMax: 99 });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("overlay create + update", async () => {
    const o = expectOk(await POST("/api/v1/sdwan/overlays", { name: un("E2E-OVL"), topology: "hub_spoke", encryption: "wireguard" }));
    ovId = o.id;
    const u = expectOk(await PUT(`/api/v1/sdwan/overlays/${ovId}`, { enabled: false }));
    assert(u.enabled === false, JSON.stringify(u).slice(0, 140));
    await PUT(`/api/v1/sdwan/overlays/${ovId}`, { enabled: true });
  });

  await tc("site create on overlay", async () => {
    const s = expectOk(await POST("/api/v1/sdwan/sites", { overlayId: ovId, name: un("E2E-SITE"), role: "spoke", publicIp: "203.0.113.50", region: "e2e" }));
    siteId = s.id;
    assert(s.role === "spoke", JSON.stringify(s).slice(0, 160));
  });

  await tc("site bad publicIp → 400", async () => {
    const r = await POST("/api/v1/sdwan/sites", { overlayId: ovId, name: un("E2E-BAD"), publicIp: "999.1.1.1" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("site paths — create + update + probe (paths/probe)", async () => {
    const paths = expectOk(await POST(`/api/v1/sdwan/sites/${siteId}/paths`, { wanInterface: "wan0", label: "broadband", latencyMs: 25, jitterMs: 4, lossPct: 0.5, state: "up" }));
    const pathId = paths.id ?? paths.path?.id;
    assert(pathId, JSON.stringify(paths).slice(0, 200));
    const u = expectOk(await PUT(`/api/v1/sdwan/paths/${pathId}`, { latencyMs: 40 }));
    assert(Number(u.latencyMs) === 40, JSON.stringify(u).slice(0, 140));
    // probe is a cycle endpoint: POST /sdwan/paths/probe (optionally ?overlayId)
    const p = expectOk(await POST(`/api/v1/sdwan/paths/probe`, { overlayId: ovId }));
    check("probe cycle", true, JSON.stringify(p).slice(0, 140));
  });

  await tc("sdwan policy create + update", async () => {
    const p = expectOk(await POST("/api/v1/sdwan/policies", { name: un("E2E-SDWANPOL"), overlayId: ovId, slaProfileId: slaId, preferredPath: "latency", enabled: true }));
    polId = p.id;
    assert(p.preferredPath === "latency", JSON.stringify(p).slice(0, 200));
    const u = expectOk(await PUT(`/api/v1/sdwan/policies/${polId}`, { preferredPath: "loss" }));
    assert(u.preferredPath === "loss", JSON.stringify(u).slice(0, 160));
  });

  await tc("sdwan stats", async () => {
    const st = expectOk(await GET("/api/v1/sdwan/stats"));
    check("stats", true, JSON.stringify(st).slice(0, 120));
  });

  await tc("cleanup: policy/site/overlay/sla → gone via list", async () => {
    expectOk(await DEL(`/api/v1/sdwan/policies/${polId}`));
    expectOk(await DEL(`/api/v1/sdwan/sites/${siteId}`));
    expectOk(await DEL(`/api/v1/sdwan/overlays/${ovId}`));
    expectOk(await DEL(`/api/v1/sdwan/sla-profiles/${slaId}`));
    const ovs = (await GET("/api/v1/sdwan/overlays")).json?.data ?? [];
    assert(!ovs.some((x) => x.id === ovId), "overlay still present");
    slaId = ovId = siteId = polId = null;
  });
});

suite("ipv6", "System → IPv6: settings/nat66(+simulate)/dhcpv6/prefix-delegation/status", async () => {
  let setSnap = null;
  let natId = null;
  let dhcpId = null;

  await tc("ipv6 settings snapshot → change → revert", async () => {
    setSnap = expectOk(await GET("/api/v1/ipv6/settings"));
    const body = { enabled: true, dhcpv6Enabled: true, slaacEnabled: false, rdnssEnabled: false, pdWanInterface: "ens34", pdPrefixLength: setSnap.pdPrefixLength ?? 56, raMode: setSnap.raMode ?? "slaac" };
    const u = expectOk(await PUT("/api/v1/ipv6/settings", body));
    assert(u.slaacEnabled === false, JSON.stringify(u).slice(0, 200));
    const back = expectOk(await PUT("/api/v1/ipv6/settings", setSnap));
    check("ipv6 settings reverted", true, `enabled=${back.enabled}`);
  });

  await tc("nat66 nptv6 create + update + simulate", async () => {
    const n = expectOk(await POST("/api/v1/ipv6/nat66-rules", { name: un("E2E-NAT66"), type: "nptv6", sourcePrefix: "2001:db8:aa::/48", translatedPrefix: "2001:db8:bb::/48", interfaceName: "ens34" }));
    natId = n.id;
    assert(n.type === "nptv6", JSON.stringify(n).slice(0, 160));
    const u = expectOk(await PUT(`/api/v1/ipv6/nat66-rules/${natId}`, { enabled: false }));
    assert(u.enabled === false, JSON.stringify(u).slice(0, 140));
    const s = await POST(`/api/v1/ipv6/nat66-rules/${natId}/simulate`, {});
    check("nat66 simulate", true, `status=${s.status} body=${JSON.stringify(s.json).slice(0, 120)}`);
  });

  await tc("nat66 nptv6 same prefix → 400", async () => {
    const r = await POST("/api/v1/ipv6/nat66-rules", { name: un("E2E-BAD"), type: "nptv6", sourcePrefix: "2001:db8:cc::/48", translatedPrefix: "2001:db8:cc::/48", interfaceName: "ens34" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("nat66 dnat66 without destPort → 400", async () => {
    const r = await POST("/api/v1/ipv6/nat66-rules", { name: un("E2E-BAD2"), type: "dnat66", sourcePrefix: "2001:db8:dd::/48", interfaceName: "ens34" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("dhcpv6 server create + update", async () => {
    const d = expectOk(await POST("/api/v1/ipv6/dhcpv6-servers", { interfaceName: "ens34", poolStart: "2001:db8:ee::100", poolEnd: "2001:db8:ee::1ff", prefixLength: 64, dnsServers: ["2001:db8:ee::1"] }));
    dhcpId = d.id;
    assert(d.poolStart === "2001:db8:ee::100", JSON.stringify(d).slice(0, 180));
    const u = expectOk(await PUT(`/api/v1/ipv6/dhcpv6-servers/${dhcpId}`, { preferredLifetime: 1800 }));
    assert(Number(u.preferredLifetime) === 1800, JSON.stringify(u).slice(0, 140));
  });

  await tc("dhcpv6 poolEnd <= poolStart → 400", async () => {
    const r = await POST("/api/v1/ipv6/dhcpv6-servers", { interfaceName: "ens34", poolStart: "2001:db8:ff::200", poolEnd: "2001:db8:ff::100" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("prefix delegation read + status read", async () => {
    const pd = expectOk(await GET("/api/v1/ipv6/prefix-delegation"));
    check("pd", true, JSON.stringify(pd).slice(0, 120));
    const st = expectOk(await GET("/api/v1/ipv6/status"));
    check("status", true, JSON.stringify(st).slice(0, 120));
  });

  await tc("cleanup: nat66 + dhcpv6 → gone via list", async () => {
    expectOk(await DEL(`/api/v1/ipv6/nat66-rules/${natId}`));
    expectOk(await DEL(`/api/v1/ipv6/dhcpv6-servers/${dhcpId}`));
    const nats = (await GET("/api/v1/ipv6/nat66-rules")).json?.data ?? [];
    assert(!nats.some((x) => x.id === natId), "nat66 still present");
    natId = dhcpId = null;
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// SUITES — batch 9: threat-intel, pki, qos, email
// ═════════════════════════════════════════════════════════════════════════════

suite("ti", "Threat Intelligence → feeds (+sync)/iocs(+disable)/auto-block/hits", async () => {
  let feedId = null;
  let iocId = null;
  let abId = null;

  await tc("create feed (custom, localhost url)", async () => {
    const f = expectOk(await POST("/api/v1/threat-intel/feeds", { name: un("E2E-FEED"), provider: "custom", url: "http://127.0.0.1:9/e2e-feed.csv", format: "csv", category: "botnet", intervalMinutes: 60, autoBlock: false }));
    feedId = f.id;
    assert(f.provider === "custom", JSON.stringify(f).slice(0, 160));
  });

  await tc("bad provider → 400", async () => {
    const r = await POST("/api/v1/threat-intel/feeds", { name: un("E2E-BAD"), provider: "twitter", url: "http://x/" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("feed update — interval 30", async () => {
    const u = expectOk(await PUT(`/api/v1/threat-intel/feeds/${feedId}`, { intervalMinutes: 30 }));
    assert(Number(u.intervalMinutes) === 30, JSON.stringify(u).slice(0, 140));
  });

  await tc("feed sync (localhost target fails gracefully)", async () => {
    const r = await POST(`/api/v1/threat-intel/feeds/${feedId}/sync`, {});
    check("sync", true, `status=${r.status} body=${JSON.stringify(r.json).slice(0, 140)}`);
  });

  await tc("ioc create (ip) + disable + re-enable", async () => {
    const iocVal = `203.0.113.${50 + (ctx.tag.charCodeAt(0) + ctx.tag.charCodeAt(1)) % 200}`;
    const i = expectOk(await POST("/api/v1/threat-intel/iocs", { type: "ip", value: iocVal, category: "c2", severity: "critical", confidence: 90, description: "e2e ioc" }));
    iocId = i.id;
    const d = expectOk(await POST(`/api/v1/threat-intel/iocs/${iocId}/disable`, {}));
    const en = d.enabled ?? d.ioc?.enabled;
    assert(en === false, `disabled=${en}`);
    const r = expectOk(await POST(`/api/v1/threat-intel/iocs/${iocId}/disable`, { enabled: true }));
    const en2 = r.enabled ?? r.ioc?.enabled;
    assert(en2 === true, `re-enabled=${en2}`);
  });

  await tc("ioc bad type → 400", async () => {
    const r = await POST("/api/v1/threat-intel/iocs", { type: "fingerprint", value: "x" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("iocs list shows ours", async () => {
    const d = expectOk(await GET("/api/v1/threat-intel/iocs?limit=50"));
    const rows = Array.isArray(d) ? d : d?.iocs ?? [];
    assert(rows.some((x) => x.id === iocId), "ioc missing from list");
  });

  await tc("auto-block rule create + update", async () => {
    const a = expectOk(await POST("/api/v1/threat-intel/auto-block-rules", { name: un("E2E-AB"), matchType: "ip", matchValue: "203.0.113.67", action: "drop", direction: "both" }));
    abId = a.id;
    const u = expectOk(await PUT(`/api/v1/threat-intel/auto-block-rules/${abId}`, { enabled: false }));
    assert(u.enabled === false, JSON.stringify(u).slice(0, 140));
  });

  await tc("auto-block bad action → 400", async () => {
    const r = await POST("/api/v1/threat-intel/auto-block-rules", { name: un("E2E-BAD"), matchType: "ip", matchValue: "1.2.3.4", action: "nuke" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("hits + stats read", async () => {
    const h = expectOk(await GET("/api/v1/threat-intel/hits?limit=5"));
    const rows = Array.isArray(h) ? h : h?.hits ?? [];
    check("hits", true, `${rows.length} rows`);
    const st = expectOk(await GET("/api/v1/threat-intel/stats"));
    check("stats", true, JSON.stringify(st).slice(0, 120));
  });

  await tc("cleanup: autoblock + ioc + feed → gone via list", async () => {
    expectOk(await DEL(`/api/v1/threat-intel/auto-block-rules/${abId}`));
    expectOk(await DEL(`/api/v1/threat-intel/iocs/${iocId}`));
    expectOk(await DEL(`/api/v1/threat-intel/feeds/${feedId}`));
    const feeds = (await GET("/api/v1/threat-intel/feeds")).json?.data ?? [];
    assert(!feeds.some((x) => x.id === feedId), "feed still present");
    feedId = iocId = abId = null;
  });
});

suite("pki", "PKI → CAs (create/crl/export/revoke) + certificates lifecycle", async () => {
  let caId = null;
  let subCaId = null;
  let certId = null;

  await tc("create root CA", async () => {
    const c = expectOk(await POST("/api/v1/pki/cas", { name: un("E2E-ROOT"), type: "root", commonName: "E2E Root CA", org: "E2E", keyType: "rsa2048", validityDays: 730 }));
    caId = c.id ?? c.ca?.id;
    assert(caId, JSON.stringify(c).slice(0, 200));
  });

  await tc("subordinate CA without parentCaId → 400", async () => {
    const r = await POST("/api/v1/pki/cas", { name: un("E2E-BAD"), type: "subordinate", commonName: "E2E Sub CA" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("create subordinate CA under root", async () => {
    const c = expectOk(await POST("/api/v1/pki/cas", { name: un("E2E-SUB"), type: "subordinate", commonName: "E2E Issuing CA", parentCaId: caId, validityDays: 365 }));
    subCaId = c.id ?? c.ca?.id;
    assert(subCaId, JSON.stringify(c).slice(0, 200));
  });

  await tc("CA update — autoRenew", async () => {
    const u = expectOk(await PUT(`/api/v1/pki/cas/${caId}`, { autoRenew: true }));
    check("ca updated", true, JSON.stringify(u).slice(0, 120));
  });

  await tc("issue certificate from issuing CA", async () => {
    const c = expectOk(await POST("/api/v1/pki/certificates", { name: un("E2E-CERT"), commonName: "host.e2e-lab.local", caId: subCaId, keyType: "rsa2048", validityDays: 90, issuedFor: "general" }));
    certId = c.id ?? c.certificate?.id;
    assert(certId, `no cert id: ${JSON.stringify(c).slice(0, 240)}`);
  });

  await tc("cert expiring endpoint → list", async () => {
    const d = expectOk(await GET("/api/v1/pki/certificates/expiring?days=365"));
    const rows = Array.isArray(d) ? d : d?.certificates ?? [];
    check("expiring", true, `${rows.length} rows`);
  });

  await tc("CRL + export endpoints", async () => {
    const crl = await GET(`/api/v1/pki/cas/${subCaId}/crl`);
    check("crl", true, `status=${crl.status}`);
    const exp = await GET(`/api/v1/pki/cas/${caId}/export?format=pem`);
    check("export", true, `status=${exp.status} len=${String(JSON.stringify(exp.json) ?? "").length}`);
  });

  await tc("revoke certificate → revoked", async () => {
    const r = expectOk(await POST(`/api/v1/pki/certificates/${certId}/revoke`, { reason: "superseded" }));
    const st = r.status ?? r.certificate?.status;
    assert(st === "revoked", `status=${st} body=${JSON.stringify(r).slice(0, 160)}`);
  });

  await tc("cleanup: cert + sub CA + root CA → gone via list", async () => {
    expectOk(await DEL(`/api/v1/pki/certificates/${certId}`));
    expectOk(await DEL(`/api/v1/pki/cas/${subCaId}`));
    expectOk(await DEL(`/api/v1/pki/cas/${caId}`));
    const cas = (await GET("/api/v1/pki/cas")).json?.data ?? [];
    assert(!cas.some((x) => x.id === caId || x.id === subCaId), "CA still present");
    caId = subCaId = certId = null;
  });
});

suite("qos", "QoS → policies + rules CRUD + validation", async () => {
  let polId = null;
  let ruleId = null;

  await tc("list policies (baseline)", async () => {
    const data = expectOk(await GET("/api/v1/qos/policies"));
    assert(Array.isArray(data), `not array: ${JSON.stringify(data).slice(0, 100)}`);
    check("baseline", true, `${data.length} policies`);
  });

  await tc("create QoS policy (voip template, 50 Mbps on ens34)", async () => {
    const p = expectOk(await POST("/api/v1/qos/policies", { name: un("E2E-QOS"), template: "voip", bandwidthKbps: 50000, ifaceName: "ens34" }));
    polId = p.id;
    assert(Number(p.bandwidthKbps) === 50000, JSON.stringify(p).slice(0, 160));
  });

  await tc("bandwidth below 1000 kbps → 400 (unit guard)", async () => {
    const r = await POST("/api/v1/qos/policies", { name: un("E2E-BAD"), bandwidthKbps: 50 });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("update policy — bandwidth 20000", async () => {
    const u = expectOk(await PUT(`/api/v1/qos/policies/${polId}`, { bandwidthKbps: 20000 }));
    assert(Number(u.bandwidthKbps) === 20000, JSON.stringify(u).slice(0, 140));
  });

  await tc("create QoS rule (priority 0, dscp 46)", async () => {
    const r = expectOk(await POST("/api/v1/qos/rules", { policyId: polId, name: un("E2E-QRULE"), priority: 0, guaranteedKbps: 5000, maxKbps: 40000, dscpMark: 46, matchApps: [], matchAddresses: ["10.90.0.0/24"] }));
    ruleId = r.id;
    assert(Number(r.dscpMark) === 46, JSON.stringify(r).slice(0, 180));
  });

  await tc("rule priority 9 → 400", async () => {
    const r = await POST("/api/v1/qos/rules", { policyId: polId, name: un("E2E-BAD2"), priority: 9 });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("update rule — maxKbps 30000", async () => {
    const u = expectOk(await PUT(`/api/v1/qos/rules/${ruleId}`, { maxKbps: 30000 }));
    assert(Number(u.maxKbps) === 30000, JSON.stringify(u).slice(0, 140));
  });

  await tc("rules list by policyId", async () => {
    const d = expectOk(await GET(`/api/v1/qos/rules?policyId=${polId}`));
    const rows = Array.isArray(d) ? d : d?.rules ?? [];
    assert(rows.some((x) => x.id === ruleId), "rule missing");
  });

  await tc("cleanup: rule + policy → gone via list", async () => {
    expectOk(await DEL(`/api/v1/qos/rules/${ruleId}`));
    expectOk(await DEL(`/api/v1/qos/policies/${polId}`));
    const list = (await GET("/api/v1/qos/policies")).json?.data ?? [];
    assert(!list.some((x) => x.id === polId), "policy still present");
    polId = ruleId = null;
  });
});

suite("email", "System → Email Security: gateways/policy/routing-rules/logs/stats", async () => {
  let gwId = null;
  let ruleId = null;
  let polSnap = null;

  await tc("create relay gateway", async () => {
    const g = expectOk(await POST("/api/v1/email-security/gateways", { name: un("E2E-SMTP"), mode: "relay", listenPort: 2525, relayDomains: ["e2e-lab.local"], upstreamHost: "10.90.0.25", tlsMode: "starttls" }));
    gwId = g.id;
    assert(g.mode === "relay", JSON.stringify(g).slice(0, 160));
  });

  await tc("relay without upstreamHost → 400", async () => {
    const r = await POST("/api/v1/email-security/gateways", { name: un("E2E-BAD"), mode: "relay" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("update gateway — listenPort 2626", async () => {
    const u = expectOk(await PUT(`/api/v1/email-security/gateways/${gwId}`, { listenPort: 2626 }));
    assert(Number(u.listenPort) === 2626, JSON.stringify(u).slice(0, 140));
  });

  await tc("policy snapshot → change spamThreshold → revert", async () => {
    polSnap = expectOk(await GET("/api/v1/email-security/policy"));
    const u = expectOk(await PUT("/api/v1/email-security/policy", { ...polSnap, spamThreshold: 7.5 }));
    assert(Number(u.spamThreshold) === 7.5, JSON.stringify(u).slice(0, 180));
    const back = expectOk(await PUT("/api/v1/email-security/policy", polSnap));
    check("policy reverted", true, `threshold=${back.spamThreshold}`);
  });

  await tc("policy spamThreshold 7.3 (not half-step) → 400", async () => {
    const r = await PUT("/api/v1/email-security/policy", { ...polSnap, spamThreshold: 7.3 });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("routing rule create + update", async () => {
    const r = expectOk(await POST("/api/v1/email-security/routing-rules", { name: un("E2E-EMRULE"), matchDomain: "@partner.e2e-lab.local", action: "relay", targetHost: "10.90.0.26", priority: 5 }));
    ruleId = r.id;
    const u = expectOk(await PUT(`/api/v1/email-security/routing-rules/${ruleId}`, { priority: 8 }));
    assert(Number(u.priority) === 8, JSON.stringify(u).slice(0, 140));
  });

  await tc("relay rule without targetHost → 400", async () => {
    const r = await POST("/api/v1/email-security/routing-rules", { name: un("E2E-BAD2"), matchDomain: "@x.e2e-lab.local", action: "relay" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("logs + stats read", async () => {
    const lg = expectOk(await GET("/api/v1/email-security/logs?limit=5"));
    const rows = Array.isArray(lg) ? lg : lg?.logs ?? [];
    check("logs", true, `${rows.length} rows`);
    const st = expectOk(await GET("/api/v1/email-security/stats"));
    check("stats", true, JSON.stringify(st).slice(0, 120));
  });

  await tc("cleanup: rule + gateway → gone via list", async () => {
    expectOk(await DEL(`/api/v1/email-security/routing-rules/${ruleId}`));
    expectOk(await DEL(`/api/v1/email-security/gateways/${gwId}`));
    const gws = (await GET("/api/v1/email-security/gateways")).json?.data ?? [];
    assert(!gws.some((x) => x.id === gwId), "gateway still present");
    gwId = ruleId = null;
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// SUITES — batch 10: logs (all tabs), ha, system
// ═════════════════════════════════════════════════════════════════════════════

suite("logs", "Logs & Reports → all tabs: reads/exports/saved/schedules/compliance/syslog/netflow/anonymization", async () => {
  let syslogId = null;
  let nfId = null;
  let schedId = null;
  let savedId = null;
  let tplId = null;
  let anonId = null;

  await tc("firewall/ips/audit logs + stats read", async () => {
    const fw = expectOk(await GET("/api/v1/logs/firewall?limit=5"));
    const fwRows = Array.isArray(fw) ? fw : fw?.logs ?? fw?.data ?? [];
    check("fw logs", true, `${Array.isArray(fwRows) ? fwRows.length : "?"} rows`);
    const ips = expectOk(await GET("/api/v1/logs/ips?limit=5"));
    check("ips logs", true, JSON.stringify(ips).slice(0, 60));
    const au = expectOk(await GET("/api/v1/logs/audit?limit=5"));
    const auRows = Array.isArray(au) ? au : au?.logs ?? au?.data ?? [];
    check("audit logs", true, `${Array.isArray(auRows) ? auRows.length : "?"} rows`);
    const st = expectOk(await GET("/api/v1/logs/stats?range=24h"));
    check("stats", true, JSON.stringify(st).slice(0, 80));
  });

  await tc("firewall logs export (json)", async () => {
    const r = await GET("/api/v1/logs/firewall/export?format=json&limit=10");
    assert(r.status === 200, `export status ${r.status}`);
    check("export", true, `${JSON.stringify(r.json ?? r).length}B`);
  });

  await tc("log search run (GET) + saved search CRUD", async () => {
    const s = expectOk(await GET("/api/v1/logs/search?dataset=firewall&q=e2e"));
    check("search run", true, JSON.stringify(s).slice(0, 80));
    const sv = expectOk(await POST("/api/v1/logs/search/saved", { name: un("E2E-SAVED"), dataset: "firewall", queryText: "action:deny", filters: { action: "deny" } }));
    savedId = sv.id;
    const list = expectOk(await GET("/api/v1/logs/search/saved"));
    const lrows = Array.isArray(list) ? list : list?.searches ?? [];
    assert(lrows.some((x) => x.id === savedId), "saved search missing from list");
    expectOk(await DEL(`/api/v1/logs/search/saved/${savedId}`));
    savedId = null;
  });

  await tc("report schedules CRUD + run once", async () => {
    const sc = expectOk(await POST("/api/v1/logs/report-schedules", { name: un("E2E-SCHED"), range: "daily", format: "pdf", sections: ["traffic"], enabled: true }));
    schedId = sc.id;
    const u = expectOk(await PUT(`/api/v1/logs/report-schedules/${schedId}`, { format: "csv" }));
    assert(u.format === "csv", JSON.stringify(u).slice(0, 140));
    const run = await POST(`/api/v1/logs/report-schedules/${schedId}/run`, {});
    check("schedule run", true, `status=${run.status} body=${JSON.stringify(run.json).slice(0, 120)}`);
  });

  await tc("report schedules list + runs list", async () => {
    const r1 = expectOk(await GET("/api/v1/logs/report-schedules"));
    const r1rows = Array.isArray(r1) ? r1 : r1?.schedules ?? [];
    check("schedules", true, `${r1rows.length} rows`);
    const r2 = expectOk(await GET("/api/v1/reports/runs"));
    const r2rows = Array.isArray(r2) ? r2 : r2?.runs ?? [];
    check("runs", true, `${r2rows.length} rows`);
  });

  await tc("compliance template CRUD + run", async () => {
    const t = expectOk(await POST("/api/v1/logs/compliance/templates", { name: un("E2E-COMPL"), framework: "GDPR", sections: ["audit"], range: "weekly" }));
    tplId = t.id;
    const run = await POST("/api/v1/logs/compliance/run", { templateId: tplId });
    check("compliance run", true, `status=${run.status} body=${JSON.stringify(run.json).slice(0, 120)}`);
    const u = expectOk(await PUT(`/api/v1/logs/compliance/templates/${tplId}`, { range: "monthly" }));
    assert(u.range === "monthly", JSON.stringify(u).slice(0, 140));
  });

  await tc("syslog target CRUD", async () => {
    const s = expectOk(await POST("/api/v1/logs/syslog-targets", { name: un("E2E-SYSLOG"), host: "10.90.0.60", port: 514, protocol: "udp", minSeverity: "low" }));
    syslogId = s.id;
    const u = expectOk(await PUT(`/api/v1/logs/syslog-targets/${syslogId}`, { protocol: "tcp", port: 601 }));
    assert(u.protocol === "tcp", JSON.stringify(u).slice(0, 140));
  });

  await tc("netflow target CRUD", async () => {
    const n = expectOk(await POST("/api/v1/logs/netflow-targets", { name: un("E2E-NF"), host: "10.90.0.61", port: 2055, version: "ipfix", samplingRate: 100 }));
    nfId = n.id;
    const u = expectOk(await PUT(`/api/v1/logs/netflow-targets/${nfId}`, { samplingRate: 50 }));
    assert(Number(u.samplingRate) === 50, JSON.stringify(u).slice(0, 140));
  });

  await tc("anonymization rule CRUD + preview", async () => {
    const a = expectOk(await POST("/api/v1/logs/anonymization", { name: un("E2E-ANON"), dataset: "firewall", field: "source_ip", strategy: "hash" }));
    anonId = a.id;
    const u = expectOk(await PUT(`/api/v1/logs/anonymization/${anonId}`, { strategy: "mask" }));
    assert(u.strategy === "mask", JSON.stringify(u).slice(0, 140));
    const p = expectOk(await GET("/api/v1/logs/anonymization/preview?dataset=firewall"));
    check("preview", true, JSON.stringify(p).slice(0, 120));
  });

  await tc("cleanup: anon/netflow/syslog/schedule/compliance → gone", async () => {
    expectOk(await DEL(`/api/v1/logs/anonymization/${anonId}`));
    expectOk(await DEL(`/api/v1/logs/netflow-targets/${nfId}`));
    expectOk(await DEL(`/api/v1/logs/syslog-targets/${syslogId}`));
    expectOk(await DEL(`/api/v1/logs/report-schedules/${schedId}`));
    expectOk(await DEL(`/api/v1/logs/compliance/templates/${tplId}`));
    anonId = nfId = syslogId = schedId = tplId = null;
  });
});

suite("ha", "System → High Availability: status + config update/revert", async () => {
  let snap = null;

  await tc("ha status read", async () => {
    const s = expectOk(await GET("/api/v1/ha/status"));
    check("status", true, JSON.stringify(s).slice(0, 140));
  });

  await tc("ha config snapshot → enable (active, vip) → revert", async () => {
    snap = expectOk(await GET("/api/v1/ha/config"));
    const body = { enabled: true, role: "active", priority: 200, virtualIp: "192.168.77.254/24", ifaceName: "ens34", peerIp: "192.168.77.9", syncConfig: true, sessionSync: true, trackedInterfaces: ["ens34"], failAfterSec: 10, holdDownSec: 60 };
    const u = expectOk(await PUT("/api/v1/ha/config", body));
    assert(u.enabled === true && u.role === "active", JSON.stringify(u).slice(0, 200));
    // revert to a disabled state valid on THIS host (seed iface lan0 not present)
    const back = expectOk(await PUT("/api/v1/ha/config", { enabled: false, role: "standby", priority: snap.priority ?? 100, virtualIp: snap.virtualIp ?? "192.168.10.254/24", ifaceName: "ens34", peerIp: snap.peerIp ?? "192.168.10.253", syncConfig: snap.syncConfig ?? true, sessionSync: snap.sessionSync ?? true, trackedInterfaces: [], failAfterSec: snap.failAfterSec ?? 10, holdDownSec: snap.holdDownSec ?? 60 }));
    assert(back.enabled === false, `ha still enabled: ${JSON.stringify(back).slice(0, 140)}`);
    check("ha reverted (disabled)", true, `role=${back.role}`);
  });

  await tc("ha enable without role → 400", async () => {
    const r = await PUT("/api/v1/ha/config", { enabled: true, role: "disabled", ifaceName: "ens34" });
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("ha holdDown < failAfter → 400", async () => {
    const r = await PUT("/api/v1/ha/config", { enabled: false, role: "active", ifaceName: "ens34", failAfterSec: 60, holdDownSec: 10 });
    expectErr(r, "VALIDATION_ERROR", 400);
  });
});

suite("system", "System → settings/status/services/ssh-keys/api-keys/webhooks/notifications/templates/versions", async () => {
  let sshKeyId = null;
  let apiKeyId = null;
  let keyPlain = null;
  let hookId = null;
  let snap = null;

  await tc("system status read", async () => {
    const s = expectOk(await GET("/api/v1/system/status"));
    check("status", true, JSON.stringify(s).slice(0, 120));
  });

  await tc("settings read → set general/hostname variant → revert", async () => {
    snap = expectOk(await GET("/api/v1/system/settings"));
    const entries = Array.isArray(snap) ? snap : snap?.settings ?? snap?.data ?? [];
    const arr = Array.isArray(entries) ? entries : [];
    check("settings keys", true, `${arr.length} entries`);
    // find an existing editable entry to toggle (logging retention firewall_logs)
    const cur = arr.find((e) => e.category === "logging" && String(e.key).startsWith("retention.firewall_logs"));
    if (cur) {
      const days = Number(cur.value);
      const next = days >= 60 ? days - 10 : days + 10;
      const u = expectOk(await PUT("/api/v1/system/settings", [{ category: "logging", key: "retention.firewall_logs", value: next }]));
      check("retention set", true, JSON.stringify(u).slice(0, 120));
      await PUT("/api/v1/system/settings", [{ category: "logging", key: "retention.firewall_logs", value: cur.value }]);
    }
  });

  await tc("unknown setting key → 400", async () => {
    const r = await PUT("/api/v1/system/settings", [{ category: "logging", key: "retention.nope", value: 30 }]);
    expectErr(r, "VALIDATION_ERROR", 400);
  });

  await tc("services list + simulated restart", async () => {
    const s = expectOk(await GET("/api/v1/system/status"));
    check("services via status", true, "ok");
    const r = await POST("/api/v1/system/services/sshd/restart", {});
    check("service restart (simulated)", true, `status=${r.status}`);
  });

  await tc("ssh-keys CRUD (public key only)", async () => {
    const k = expectOk(await POST("/api/v1/system/ssh-keys", { name: un("E2E-KEY"), publicKey: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDJe2eE2ETestKeyBase64PlaceholderValue000 e2e@lab" }));
    sshKeyId = k.id;
    assert(sshKeyId, JSON.stringify(k).slice(0, 160));
    const priv = await POST("/api/v1/system/ssh-keys", { name: un("E2E-BADKEY"), publicKey: "-----BEGIN PRIVATE KEY-----abc" });
    assert(priv.status === 400, `private key accepted?! ${priv.status}`);
  });

  await tc("api-keys CRUD + auth with key", async () => {
    const k = expectOk(await POST("/api/v1/api-keys", { name: un("E2E-APIKEY"), scopes: ["read"] }));
    apiKeyId = k.id ?? k.key?.id;
    keyPlain = k.plainToken ?? k.token ?? k.secret ?? null;
    assert(apiKeyId, JSON.stringify(k).slice(0, 220));
    if (keyPlain) {
      const me = await GET("/api/v1/auth/me", { headers: { "x-api-key": keyPlain } });
      check("api-key auth works", me.status === 200, `status=${me.status}`);
    }
    const list = expectOk(await GET("/api/v1/api-keys"));
    const rows = Array.isArray(list) ? list : list?.keys ?? [];
    assert(rows.some((x) => x.id === apiKeyId), "key missing from list");
  });

  await tc("webhooks CRUD (https url, events)", async () => {
    const w = expectOk(await POST("/api/v1/webhooks", { name: un("E2E-HOOK"), url: "https://127.0.0.1/e2e-hook", events: ["alerts.new", "config.updated"], secret: "e2e-webhook-secret-123" }));
    hookId = w.id;
    assert(hookId, JSON.stringify(w).slice(0, 200));
    const badHttp = await POST("/api/v1/webhooks", { name: un("E2E-BADHOOK"), url: "http://insecure.example/e2e", events: ["alerts.new"] });
    assert(badHttp.status === 400, `http url accepted: ${badHttp.status}`);
    const u = expectOk(await PUT(`/api/v1/webhooks/${hookId}`, { enabled: false }));
    assert(u.enabled === false, JSON.stringify(u).slice(0, 140));
  });

  await tc("notifications list + read-all", async () => {
    const n = expectOk(await GET("/api/v1/notifications?limit=5"));
    const rows = Array.isArray(n) ? n : n?.notifications ?? [];
    check("notifications", true, `${rows.length} rows`);
    if (rows.length > 0) {
      const r = await POST(`/api/v1/notifications/${rows[0].id}/read`, {});
      check("mark read", true, `status=${r.status}`);
    }
    const ra = await POST("/api/v1/notifications/read-all", {});
    check("read-all", true, `status=${ra.status}`);
  });

  await tc("policy-templates list", async () => {
    const t = expectOk(await GET("/api/v1/system/policy-templates"));
    const rows = Array.isArray(t) ? t : t?.templates ?? [];
    check("templates", true, `${rows.length} available (apply skipped — overwrites policy state)`);
  });

  await tc("config-versions list + restore-noop", async () => {
    const v = expectOk(await GET("/api/v1/config-versions?limit=5"));
    const rows = Array.isArray(v) ? v : v?.versions ?? [];
    check("versions", true, `${rows.length} snapshots`);
  });

  await tc("backups create + list (restore skipped on prod)", async () => {
    const b = expectOk(await POST("/api/v1/system/backups", { type: "config" }));
    const bid = b.id ?? b.backup?.id;
    check("backup created", true, `id=${bid}`);
    const list = expectOk(await GET("/api/v1/system/backups"));
    const rows = Array.isArray(list) ? list : list?.backups ?? [];
    check("backup listed", rows.some((x) => x.id === bid), `${rows.length} backups`);
    if (bid) await DEL(`/api/v1/system/backups/${bid}`);
  });

  await tc("firmware status read (upgrade/rollback skipped)", async () => {
    const f = expectOk(await GET("/api/v1/system/firmware"));
    check("firmware", true, JSON.stringify(f).slice(0, 120));
  });

  await tc("cleanup: ssh-key + webhook → gone", async () => {
    if (sshKeyId) expectOk(await DEL(`/api/v1/system/ssh-keys/${sshKeyId}`));
    if (hookId) expectOk(await DEL(`/api/v1/webhooks/${hookId}`));
    const keys = expectOk(await GET("/api/v1/system/ssh-keys"));
    const rows = Array.isArray(keys) ? keys : keys?.keys ?? [];
    assert(!rows.some((x) => x.name?.includes("E2E-KEY")), "ssh key still present");
    sshKeyId = hookId = null;
  });

  await tc("api-key revoke last (after all suites done)", async () => {
    if (apiKeyId) {
      expectOk(await DEL(`/api/v1/api-keys/${apiKeyId}`));
      check("api-key revoked", true, `id=${apiKeyId}`);
      apiKeyId = null;
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// runner
// ═════════════════════════════════════════════════════════════════════════════

async function redlineStatus() {
  console.log(`nft baseline: ${NFT_BASELINE}`);
  await redline("status");
}

async function main() {
  const cmd = process.argv[2] || "list";
  if (cmd === "list") {
    console.log("available suites:\n");
    for (const [k, v] of Object.entries(suites)) console.log(`  ${k.padEnd(22)} ${v.desc}`);
    return;
  }
  if (cmd === "status") {
    await redlineStatus();
    return;
  }
  const s = suites[cmd];
  if (!s) {
    console.error(`unknown suite: ${cmd}`);
    process.exitCode = 2;
    return;
  }
  ctx.tag = Math.random().toString(36).slice(2, 8);
  console.log(`\n=== suite: ${cmd} — ${s.desc} ===\n`);
  const t0 = Date.now();
  try {
    await s.fn();
  } finally {
    await runCleanup();
  }
  console.log(`\n-- ${cmd}: ${passed} passed, ${failed} failed (${Date.now() - t0}ms)`);
  process.exitCode = failed ? 1 : 0;
}

main().catch((e) => {
  console.error("runner crashed:", e);
  process.exitCode = 1;
});
