# DEPLOYMENT — Cryptsk Console on Debian 13 ("Trixie") Appliance

> Target: production appliance (spec §3 — Debian 13, Go data-plane agent on :8080).
> The console ships in **simulation mode** out of the box and flips to
> **appliance mode** with one env var (`ADAPTER_MODE=agent`) once the Go agent
> implements the `SystemAdapter` contract (see `deploy/AGENT_ADAPTER_CHECKLIST.md`).
> Everything below is the complete, tested-shaped path from this repository to a
> running production box.

---

## 1. Prerequisites (Debian 13)

```bash
sudo apt update
sudo apt install -y ca-certificates curl git postgresql-16 caddy
# Node.js 22 LTS (Next.js 16 runtime) — via nodesource:
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs
# bun (runtime for the realtime mini-service):
curl -fsSL https://bun.sh/install | bash
```

Release upgrade path note: the appliance image pins Debian 13; keep
`postgresql-16` on the same major for the lifetime of the box (ADR-005).

## 2. Layout

```
/opt/cryptsk/console/          ← this repo at the release tag
/opt/cryptsk/console/db/       ← SQLite artifacts (SANDBOX ONLY — production uses PostgreSQL)
/opt/cryptsk/console/.env      ← real secrets (600, root:cryptsk)
/var/lib/cryptsk/              ← writable state (backups, report artifacts)
```

## 3. Database — SQLite → PostgreSQL (ADR-005 portability)

The schema is written portable (no SQLite-only types; JSON stored as strings by
design, ADR-005). Switch:

```bash
# 1. create role + db
sudo -u postgres psql <<'SQL'
CREATE ROLE cryptsk WITH LOGIN PASSWORD '<strong-secret>';
CREATE DATABASE cryptsk OWNER cryptsk;
SQL

# 2. point the datasource at it
#    prisma/schema.prisma → provider = "postgresql", url = env("DATABASE_URL")
#    (the committed schema keeps the sqlite default for sandbox portability —
#     on the appliance we generate from the same models via the deploy flag)
DATABASE_URL="postgresql://cryptsk:<secret>@127.0.0.1:5432/cryptsk" \
  npx prisma db push --skip-generate

# 3. seed the RBAC baseline (admin user, roles, groups — NOT the sandbox traffic data)
DATABASE_URL="postgresql://..." npx prisma db push && bun prisma/seed.ts --minimal
```

> **Deterministic rule:** the sandbox `db/cryptsk.db` (tracked in git for
> sandbox-reset recovery) is NEVER shipped to a production box. Production
> starts from schema + minimal seed only.

## 4. Environment (`.env`, mode 600)

```ini
# ── database ────────────────────────────────────────────────────────────────
DATABASE_URL="postgresql://cryptsk:<secret>@127.0.0.1:5432/cryptsk"

# ── auth (CHANGE BOTH; generate: openssl rand -hex 32) ─────────────────────
JWT_SECRET="<64-hex>"
SESSION_COOKIE_NAME="cryptsk_session"
NODE_ENV=production

# ── adapter mode ────────────────────────────────────────────────────────────
# simulated = console-internal MockEngine (sandbox)
# agent     = real appliance data-plane via the Go agent on :8080
ADAPTER_MODE=agent
AGENT_BASE_URL="http://127.0.0.1:8080"
AGENT_SHARED_SECRET="<64-hex>"   # console ↔ agent mTLS-alternative (spec §7)

# ── realtime ────────────────────────────────────────────────────────────────
REALTIME_PORT=3003
```

## 5. Build & install

```bash
cd /opt/cryptsk/console
bun install --frozen-lockfile
bunx prisma generate
# Next standalone build (server.js bundles the console):
bun run build
# artifact: .next/standalone/server.js (+ .next/static must be copied in)
cp -r .next/static .next/standalone/.next/
cp -r public .next/standalone/ 2>/dev/null || true
```

## 6. systemd units

Install the two shipped units (see `deploy/`):

```bash
sudo cp deploy/cryptsk-console.service  /etc/systemd/system/
sudo cp deploy/cryptsk-realtime.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cryptsk-realtime.service cryptsk-console.service
systemctl status cryptsk-console --no-pager
```

Ports: console `127.0.0.1:3000`, realtime `127.0.0.1:3003` — both loopback-only;
public traffic terminates at Caddy (below).

## 7. Edge TLS — Caddy

`deploy/Caddyfile.example` fronts the console + proxies the realtime socket
(`XTransformPort` gateway pattern used in the sandbox is REPLACED on the
appliance by the explicit `/realtime` path shown there).

```bash
sudo cp deploy/Caddyfile.example /etc/caddy/Caddyfile
sudo systemctl reload caddy   # issues ACME certs automatically for console.corp.example
```

## 8. Appliance Mode — AgentAdapter wiring

The console is written once against `SystemAdapter` (`src/lib/adapters/types.ts`,
ADR-004). To flip a production box from simulation to the real data plane:

1. Implement the Go agent (port 8080) endpoints listed in
   `deploy/AGENT_ADAPTER_CHECKLIST.md` (per-module mapping: nftables, Suricata
   NFQUEUE, WireGuard, Unbound, Kea, FRR, Squid, Coraza, Postfix/Rspamd, Step-CA).
2. `src/lib/adapters/agent.ts` — ship the HTTP adapter speaking
   `AGENT_BASE_URL` + `X-Agent-Auth: <AGENT_SHARED_SECRET>`; the checklist file
   enumerates every method with its appliance-side backing service.
3. Set `ADAPTER_MODE=agent` and restart. Health check:
   `curl -s localhost:3000/api/v1/dashboard/summary -H "Cookie: <session>" | jq .data.source`
   → `"agent"`.

Until the agent lands, the console runs fine with `ADAPTER_MODE=simulated` on
the appliance for staging/training — this is supported, documented behavior.

## 9. Security hardening checklist (spec §7 alignment)

- [ ] `.env` mode 600, owned root:cryptsk; secrets rotated from seed values
- [ ] `JWT_SECRET` unique per appliance; session cookies `Secure; HttpOnly; SameSite=Lax`
- [ ] Caddy: only 443 public; 3000/3003/8080 loopback
- [ ] PostgreSQL: `cryptsk` role scoped to the single DB; SCRAM-SHA-256
- [ ] RBAC: change default `admin/admin123` on first login (wizard forces it, `#/setup`)
- [ ] API keys: scope per consumer, `api_service` role only
- [ ] Webhook secrets: rotate quarterly; verify `X-Cryptsk-Signature` on receivers
- [ ] Backups: `POST /api/v1/system/backups` nightly (cron → API key), copy off-box
- [ ] Audit log retention: syslog target to the SIEM (M09 forwarding surfaces)
- [ ] Unattended-upgrades on; appliance reboot tested (HA pair = two boxes)

## 10. Upgrades

```bash
cd /opt/cryptsk/console
git fetch --tags && git checkout <release-tag>
bun install --frozen-lockfile && bunx prisma generate && bun run build
sudo systemctl restart cryptsk-console cryptsk-realtime
# schema migrations (additive-only policy per ADR-014 era):
DATABASE_URL=... npx prisma db push
```

Rollback = previous tag + previous `.next/standalone` (keep one release back).
Config history (`config_versions`) + audit trail survive upgrades.

## 11. Verify deployment (smoke test)

```bash
# console up
curl -fsS http://127.0.0.1:3000/api/v1/health || curl -fsS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3000/
# realtime up
curl -fsS http://127.0.0.1:3003/healthz
# login works + RBAC matrix loads
curl -fsS -c /tmp/c.txt -X POST https://console.corp.example/api/v1/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"<new-password>"}'
# adapter mode report
curl -fsS -b /tmp/c.txt https://console.corp.example/api/v1/dashboard/summary | jq '.data.mode // .data'
```

---

**Ship state at this tag:** Phase 1 (M0–M11) + Phase 2 (M12–M23) console
complete — 46 hash views, ~90 tables, 12 RBAC capability areas, real-PKI
tooling, real webhook egress, CEF/LEEF export, compliance reporting — all
contracts locked in `docs/` and ready for the Debian 13 appliance build.
