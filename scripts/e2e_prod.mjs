#!/usr/bin/env node
// e2e_prod.mjs — end-to-end test suite for the Cryptsk Console production deployment.
// Exercises: web serving, auth (cookie security + RBAC), API reads, a reversible
// API write (API key create/revoke), realtime gateway, Go agent, SQLite DB state,
// and system health. All checks are passive or fully reversible.
//
// Usage: node scripts/e2e_prod.mjs
// Env:   E2E_HOST (default 103.244.7.219) SSH_PORT/SSH_USER/SSH_PASS overrides

import { Client } from "ssh2";

const HOST = process.env.E2E_HOST || "103.244.7.219";
const SSH_PORT = Number(process.env.SSH_PORT || 22222);
const SSH_USER = process.env.SSH_USER || "root";
const SSH_PASS = process.env.SSH_PASS || "CryptSK@123#$";
const BASE = `http://${HOST}:3000`;
const GW = `http://${HOST}:81`;
const DB = "/opt/cryptsk/console/db/cryptsk.db";

const results = [];
let cookie = "";

function check(group, name, pass, detail = "") {
  results.push({ group, name, pass, detail });
  console.log(`${pass ? "  ✅ PASS" : "  ❌ FAIL"}  [${group}] ${name}${detail ? ` — ${detail}` : ""}`);
}

async function pub(path, opts = {}) {
  const res = await fetch(`${BASE}${path}`, {
    ...opts,
    headers: { ...(opts.headers || {}), ...(cookie ? { cookie } : {}) },
    signal: AbortSignal.timeout(20000),
    redirect: "manual",
  });
  return res;
}

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
          if (err) { clearTimeout(timer); done(); return; }
          stream.on("close", (c) => { code = c ?? 0; clearTimeout(timer); done(); })
            .on("data", (d) => { out += d.toString(); })
            .stderr.on("data", (d) => { out += d.toString(); });
        });
      })
      .on("error", () => { clearTimeout(timer); done(); })
      .connect({ host: HOST, port: SSH_PORT, username: SSH_USER, password: SSH_PASS, readyTimeout: 20000 });
  });
}

// ── 1. WEB ──────────────────────────────────────────────────────────────────
async function testWeb() {
  const g = "web";
  const res = await pub("/");
  const html = await res.text();
  check(g, "GET / → 200", res.status === 200, `status=${res.status}`);
  check(g, "page renders Cryptsk shell", /cryptsk/i.test(html), `${html.length} bytes`);
}

// ── 2. REALTIME (socket.io via Caddy gateway) ───────────────────────────────
async function testRealtime() {
  const g = "realtime";
  // the :81 gateway routes by XTransformPort query param — without it, requests
  // fall through to the Next app (:3000) and 404/308
  const res = await fetch(`${GW}/socket.io/?EIO=4&transport=polling&XTransformPort=3003`, { signal: AbortSignal.timeout(15000) });
  const body = await res.text();
  check(g, "gateway :81 socket.io handshake", res.status === 200 && body.trimStart().startsWith("0{"), `status=${res.status}`);
  check(g, "handshake returns sid", /"sid":"[^"]+"/.test(body), body.slice(0, 60));
  const local = await sshExec(`curl -s -o /dev/null -w '%{http_code}' 'http://127.0.0.1:81/socket.io/?EIO=4&transport=polling&XTransformPort=3003'`);
  check(g, "loopback gateway handshake (server-local)", local.out.trim() === "200", `code=${local.out.trim()}`);
}

// ── 3. AUTH ─────────────────────────────────────────────────────────────────
async function testAuth() {
  const g = "auth";
  // negative: no credentials
  const anon = await pub("/api/v1/auth/me");
  check(g, "unauthenticated /me → 401", anon.status === 401, `status=${anon.status}`);

  // negative: wrong password (1 failed attempt — well under the 5/min throttle)
  const bad = await pub("/api/v1/auth/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: "admin", password: "definitely-wrong" }),
  });
  check(g, "wrong password → 401", bad.status === 401, `status=${bad.status}`);

  // positive login (retry once if the shared 5/min per-user throttle trips)
  async function doLogin() {
    return pub("/api/v1/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: "admin", password: "admin123" }),
    });
  }
  let res = await doLogin();
  if (res.status === 429) {
    await new Promise((r) => setTimeout(r, 65000));
    res = await doLogin();
  }
  const body = await res.json().catch(() => ({}));
  check(g, "login admin → 200", res.status === 200, `status=${res.status}`);
  check(g, "role = super_admin", body?.data?.user?.role === "super_admin", body?.data?.user?.role ?? "missing");

  const setCookies = res.headers.getSetCookie?.() ?? [res.headers.get("set-cookie")].filter(Boolean);
  const sc = setCookies.find((c) => c.startsWith("cryptsk_token="));
  check(g, "session cookie present", Boolean(sc), `${setCookies.length} set-cookie headers`);
  check(g, "cookie is httpOnly", Boolean(sc && /httponly/i.test(sc)));
  check(g, "cookie is SameSite=Lax", Boolean(sc && /samesite=lax/i.test(sc)));
  check(g, "cookie NOT Secure over plain HTTP (browser-reachable)", Boolean(sc && !/secure/i.test(sc)), sc?.split(";").join(" "));
  if (sc) {
    cookie = sc.split(";")[0];
    const me = await pub("/api/v1/auth/me");
    const meBody = await me.json().catch(() => ({}));
    check(g, "authenticated /me → 200", me.status === 200, `status=${me.status}`);
    check(g, "/me returns session user", meBody?.data?.username === "admin", meBody?.data?.username ?? "missing");
    check(g, "/me carries permissions matrix", Array.isArray(meBody?.data?.permissions?.read) && meBody.data.permissions.read.length > 0);
  }
}

// ── 4. API READS (RBAC-protected) ───────────────────────────────────────────
async function testReads() {
  const g = "api-reads";
  const endpoints = [
    "/api/v1/dashboard/summary",
    "/api/v1/interfaces",
    "/api/v1/firewall-rules",
    "/api/v1/zones",
    "/api/v1/wan-policies",
    "/api/v1/logs/audit",
  ];
  for (const ep of endpoints) {
    const res = await pub(ep);
    const body = await res.json().catch(() => null);
    const shaped = body && typeof body === "object" && "data" in body;
    check(g, `GET ${ep}`, res.status === 200 && shaped, `status=${res.status}${shaped ? "" : " (no data envelope)"}`);
  }
  // dashboard carries real host telemetry
  const dash = await (await pub("/api/v1/dashboard/summary")).json().catch(() => null);
  const blob = JSON.stringify(dash?.data ?? {});
  check(g, "dashboard summary includes host metrics", /cpu|ram|mem/i.test(blob), `${blob.length} bytes`);
}

// ── 5. API WRITE (reversible: API key create → use → revoke) ────────────────
async function testWrite() {
  const g = "api-write";
  // raw fetch WITHOUT the session cookie — pub() injects the global cookie
  const anonWrite = await fetch(`${BASE}/api/v1/firewall-rules`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({}),
    signal: AbortSignal.timeout(20000),
  });
  check(g, "unauthenticated write → 401", anonWrite.status === 401, `status=${anonWrite.status}`);

  const created = await pub("/api/v1/api-keys", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: "e2e-probe", scopes: ["read"] }),
  });
  const cBody = await created.json().catch(() => ({}));
  check(g, "create API key → 200", created.status === 200, `status=${created.status} ${JSON.stringify(cBody?.error ?? "").slice(0, 80)}`);
  const key = cBody?.data?.key;
  const keyId = cBody?.data?.id;
  // ck_ + 8-char prefix + "_" + 32-char base64url secret (may contain - and _)
  check(g, "one-time key reveal (ck_… shape)", typeof key === "string" && /^ck_[A-Za-z0-9]{8}_[A-Za-z0-9_-]{32}$/.test(key), key ? `len=${key.length} prefix=${key.slice(0, 11)}` : "missing");

  if (key) {
    // the new key must actually authenticate machine calls (Bearer flow)
    const mach = await fetch(`${BASE}/api/v1/dashboard/summary`, {
      headers: { authorization: `Bearer ${key}` },
      signal: AbortSignal.timeout(20000),
    });
    check(g, "API key Bearer auth works on reads", mach.status === 200, `status=${mach.status}`);
  }

  if (keyId) {
    const del = await pub(`/api/v1/api-keys/${keyId}`, { method: "DELETE" });
    check(g, "revoke API key (cleanup)", del.status === 200 || del.status === 204, `status=${del.status}`);
  }
}

// ── 6. AGENT ────────────────────────────────────────────────────────────────
async function testAgent() {
  const g = "agent";
  const h = await sshExec(`curl -s --max-time 10 http://127.0.0.1:8080/healthz`);
  check(g, "agent :8080/healthz ok:true", /"ok"\s*:\s*true/.test(h.out), h.out.trim().slice(0, 60));
}

// ── 7. DATABASE ─────────────────────────────────────────────────────────────
async function testDb() {
  const g = "db";
  const users = await sshExec(`sqlite3 ${DB} "select count(*) from users;"`);
  check(g, "users seeded", Number(users.out.trim()) >= 2, `count=${users.out.trim()}`);
  const audit = await sshExec(`sqlite3 ${DB} "select count(*) from audit_log;"`);
  check(g, "audit_log populated", Number(audit.out.trim()) > 0, `count=${audit.out.trim()}`);
  const lastLogin = await sshExec(`sqlite3 -json ${DB} "select username,result from audit_log where action='auth.login' order by created_at desc limit 1;"`);
  let row = {};
  try { const parsed = JSON.parse(lastLogin.out.trim().split("\n").filter(Boolean).pop() || "[]"); row = Array.isArray(parsed) ? (parsed[0] ?? {}) : parsed; } catch {}
  check(g, "latest auth.login audited as success", row.result === "success", JSON.stringify(row));
}

// ── 8. SYSTEM ───────────────────────────────────────────────────────────────
async function testSystem() {
  const g = "system";
  const pm2 = await sshExec(`pm2 jlist | node -e 'const d=JSON.parse(require("fs").readFileSync(0));console.log(d.filter(p=>p.pm2_env.status==="online").length+"/"+d.length)'`);
  check(g, "pm2 processes online (3/3)", pm2.out.trim() === "3/3", pm2.out.trim());
  const loop = await sshExec(`curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3000/`);
  check(g, "loopback app :3000 → 200", loop.out.trim() === "200", `code=${loop.out.trim()}`);
  const tools = await sshExec(`for t in nft wg swanctl dnsmasq iperf3 jq sqlite3; do command -v $t >/dev/null || echo missing:$t; done; true`);
  check(g, "apt toolchain present (nft/wg/swanctl/dnsmasq/iperf3/jq/sqlite3)", !/missing:/.test(tools.out), tools.out.trim() || "all found");
  const disk = await sshExec(`df --output=avail -BG / | tail -1 | tr -dc '0-9'`);
  check(g, "disk available > 1GB", Number(disk.out.trim()) > 1, `${disk.out.trim()}G free`);
  const mem = await sshExec(`free -m | awk '/Mem:/{print $7}'`);
  check(g, "memory available > 500MB", Number(mem.out.trim()) > 500, `${mem.out.trim()}MB free`);
}

// ── runner ──────────────────────────────────────────────────────────────────
console.log(`\nE2E — Cryptsk Console production (${HOST}) — ${new Date().toISOString()}\n`);
const suites = [
  ["WEB", testWeb], ["REALTIME", testRealtime], ["AUTH", testAuth],
  ["API-READS", testReads], ["API-WRITE", testWrite], ["AGENT", testAgent],
  ["DB", testDb], ["SYSTEM", testSystem],
];
for (const [, fn] of suites) {
  try { await fn(); } catch (e) { results.push({ group: fn.name, name: "suite crashed", pass: false, detail: e.message }); console.log(`  ❌ FAIL  suite error — ${e.message}`); }
}
const passed = results.filter((r) => r.pass).length;
console.log(`\n═══════ E2E RESULT: ${passed}/${results.length} passed ${passed === results.length ? "— ALL GREEN ✅" : "— FAILURES ABOVE ❌"} ═══════\n`);
process.exit(passed === results.length ? 0 : 1);
