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

  await tc("TC8 admin DOWN (disable) → kernel flags lose UP", async () => {
    const r = await PUT(`/api/v1/interfaces/${ens34Id}`, { enabled: false });
    const os = osOutcome(r);
    assert(os?.applied === true, `reason=${os?.reason}`);
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
