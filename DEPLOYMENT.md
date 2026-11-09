# DEPLOYMENT — Cryptsk Console on Debian 13 ("Trixie") Appliance

> Target: production appliance (spec §3 — Debian 13).
> **ADR-021 (2026-11-09): the console ships with the REAL data plane**
> (`ADAPTER_MODE=host`) — every metric, interface, session, service state and
> log comes from the actual host (`/proc`, sysfs, `systemctl`, Suricata,
> nftables, WireGuard, Kea, unbound). **No mock/simulated data ships.**
> The optional Go-agent HTTP transport (`ADAPTER_MODE=agent`) remains the
> future path for remote sensor boxes (`deploy/AGENT_ADAPTER_CHECKLIST.md`).
> The legacy demo plane (`ADAPTER_MODE=simulated`) exists only for offline demos.

---

## 0. One-shot install (fresh Debian 13 — RECOMMENDED)

```bash
# as root, on a fresh Debian 13 box:
git clone https://github.com/chiranjitk/cryptsk-utm.git /tmp/inst && cd /tmp/inst
sudo bash deploy/install-debian13.sh

# optional appliance stack (flags add apt packages the collector auto-detects):
sudo bash deploy/install-debian13.sh --with-ips --with-dns --with-dhcp
#   --with-ips  → suricata (IPS events from eve.json)
#   --with-dns  → unbound (real DNS query log)
#   --with-dhcp → kea-dhcp4-server (real DHCP leases)
# sudo bash deploy/install-debian13.sh --db postgres   # PostgreSQL 16 per ADR-005
```

The script: installs apt deps (nftables, wireguard-tools, …) + Node 22 + bun +
pm2 → clones the repo to `/opt/cryptsk/console` → writes `.env` with generated
secrets → fresh SQLite DB + **production seed** (zero demo rows) → production
build → **starts both services under pm2** → boot-persistence hook → smoke
check → prints the URL + credentials.

What you get at the end:

```
pm2 services : cryptsk-utm (Next.js :3000) + realtime-service (:3003)
URL          : http://<server-ip>:3000/        (Caddy TLS optional, §7)
Login        : admin / admin123  ← CHANGE ON FIRST LOGIN
Data plane   : host (real telemetry) — the setup wizard builds LAN/WAN config
```

Later updates: `sudo bash deploy/update.sh` (pull → rebuild → pm2 reload).

---

## 1. Manual prerequisites (only when NOT using the install script)

```bash
sudo apt update
sudo apt install -y ca-certificates curl git build-essential nftables wireguard-tools
# Node.js 22 LTS (Next.js 16 runtime) — via nodesource:
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs
# bun (runtime for the realtime mini-service):
curl -fsSL https://bun.sh/install | bash
# pm2 (process manager for both services — the appliance runtime):
sudo npm install -g pm2
```

## 2. Layout

```
/opt/cryptsk/console/          ← this repo
/opt/cryptsk/console/db/       ← SQLite DB (default; PostgreSQL optional §3)
/opt/cryptsk/console/.env      ← real secrets (600, root-owned)
/opt/cryptsk/console/logs/     ← pm2 out/err logs
```

## 3. Database — SQLite (default) or PostgreSQL (ADR-005)

Default is SQLite — zero-config, works from the first boot. PostgreSQL switch:

```bash
sudo apt install -y postgresql
sudo -u postgres psql -c "CREATE ROLE cryptsk WITH LOGIN PASSWORD '<secret>'"
sudo -u postgres psql -c "CREATE DATABASE cryptsk OWNER cryptsk"
# point the datasource at it and switch the provider
sed -i 's/provider = "sqlite"/provider = "postgresql"/' prisma/schema.prisma
DATABASE_URL="postgresql://cryptsk:<secret>@127.0.0.1:5432/cryptsk" npx prisma db push
```

The schema is written portable (JSON stored as strings by design, ADR-005).

> **Deterministic rule (ADR-021):** the production database starts from schema
> + `prisma/seed.ts --production` ONLY. The tracked sandbox `db/cryptsk.db` is
> never shipped (the install script deletes it before `db push`). Existing
> demo databases are cleaned with `bun run purge:mock`.

### Production seed — what it contains (and what it MUST NOT)

`bun prisma/seed.ts --production` seeds **only**: the tenant, the 8 RBAC users
(change the default passwords!), user groups, default system settings
(`system/setup.completed = false` → the first-time wizard runs), and config
version v1. It contains **NO** demo objects/rules/interfaces and **NO** mock
operational rows (no fake logs/events/leases/sessions/notifications).

## 4. Environment (`.env`, mode 600)

```ini
NODE_ENV=production
ADAPTER_MODE=host                # REAL data plane (ADR-021)
DATABASE_URL="file:/opt/cryptsk/console/db/cryptsk.db"
AUTH_SECRET="<64-hex>"           # generate: openssl rand -hex 32
JWT_SECRET="<64-hex>"            # documented alias of AUTH_SECRET
INTERNAL_TOKEN="<24-hex>"        # console ↔ realtime-service internal poll
# Optional future remote-agent transport (AGENT_ADAPTER_CHECKLIST):
# AGENT_BASE_URL="http://127.0.0.1:8080"
# AGENT_SHARED_SECRET="<64-hex>"
```

## 5. Build & install (manual path)

```bash
cd /opt/cryptsk/console
bun install --frozen-lockfile
bunx prisma generate
bunx prisma db push --accept-data-loss
bun prisma/seed.ts --production
bun run build        # next build standalone (+ static copied in)
```

## 6. pm2 — the process manager (appliance runtime)

Start both services from the shipped production ecosystem (paths resolve
relative to the repo root automatically):

```bash
cd /opt/cryptsk/console
pm2 start ecosystem.prod.config.cjs
pm2 save                                   # persist the process list
pm2 startup systemd -u root --hp /root     # boot persistence (systemd hook)
pm2 save                                   # re-save after startup install
pm2 status
```

| pm2 app            | runs                        | port |
|--------------------|-----------------------------|------|
| `cryptsk-utm`      | `next start` (production)   | 3000 |
| `realtime-service` | `bun run start` (socket.io) | 3003 |

Ops cheatsheet: `pm2 status` · `pm2 logs cryptsk-utm` · `pm2 restart cryptsk-utm`
· `pm2 reload ecosystem.prod.config.cjs` · logs also on disk under `logs/`.

Sandbox note: `ecosystem.config.cjs` (dev variant, `next dev`) is for the
development sandbox only — production MUST use `ecosystem.prod.config.cjs`.

## 7. Edge TLS — Caddy (optional but recommended)

`deploy/Caddyfile.example` fronts the console + proxies the realtime socket
(the sandbox `XTransformPort` gateway pattern is replaced by an explicit
`/realtime` path). 3000/3003 stay loopback or LAN-only behind it.

```bash
sudo apt install -y caddy
sudo cp deploy/Caddyfile.example /etc/caddy/Caddyfile
sudo systemctl reload caddy   # issues ACME certs automatically
```

## 8. What is REAL on the appliance (ADR-021 source map)

| Console surface | Real source (Debian 13) | Degrades to (absent) |
|---|---|---|
| CPU / memory / uptime / load | `/proc/stat`, `/proc/meminfo` every 2 s | zeros (never fabricated) |
| Disk usage | `statfs` on the console dir | zeros |
| Temperature | `/sys/class/thermal/*` | 0 °C (no sensor — honest) |
| Interfaces + throughput | `/proc/net/dev` deltas, sysfs, auto-discovered into the DB | — |
| WAN probe states | real gateway TCP probe (`/proc/net/route` → connect :53) | `down` with reason |
| Sessions (dashboard) | `/proc/net/tcp{,6}` + UDP endpoints, nf_conntrack count when present | real TCP count |
| Service health | `systemctl is-active` batch | honest `stopped` (no systemd) |
| IPS events | Suricata `eve.json` tail (persisted to `ips_events`) | empty |
| Firewall logs | nftables kernel logs via `journalctl -k` | empty |
| VPN sessions | `wg show all dump` (WireGuard peers, real rx/tx) | empty |
| DHCP leases | Kea `kea-leases4.csv` | empty |
| DNS query log | unbound query log tail | empty |
| Audit trail | the console's own API middleware | — |

Everything the collector cannot observe is shown as an honest empty/zero —
**no simulated fill-in anywhere**. Threshold alerts (CPU/mem/disk/temp) fire on
the REAL vitals with the same edge-triggered notification pipeline.

## 9. Optional future — AgentAdapter (remote sensors)

The console remains written once against `SystemAdapter` (ADR-004). For remote
sensor boxes where the collector must run on another host, implement the Go
agent (port 8080) per `deploy/AGENT_ADAPTER_CHECKLIST.md`, ship
`src/lib/adapters/agent.ts` (HTTP + `X-Agent-Auth`), set `ADAPTER_MODE=agent`.
Until then `host` mode is the production data plane.

## 10. Security hardening checklist (spec §7 alignment)

- [ ] `.env` mode 600, root-owned; secrets rotated from install-script values
- [ ] `AUTH_SECRET` unique per appliance; session cookies `Secure; HttpOnly; SameSite=Lax`
- [ ] Caddy: only 443 public; 3000/3003 loopback/LAN
- [ ] PostgreSQL (if used): `cryptsk` role scoped to the single DB; SCRAM-SHA-256
- [ ] RBAC: change default `admin/admin123` on first login
- [ ] API keys: scope per consumer, `api_service` role only
- [ ] Webhook secrets: rotate quarterly; verify `X-Cryptsk-Signature` on receivers
- [ ] Backups: `POST /api/v1/system/backups` nightly (cron → API key), copy off-box
- [ ] Audit log retention: syslog target to the SIEM (M09 forwarding surfaces)
- [ ] Unattended-upgrades on; appliance reboot tested (pm2 resurrects services)

## 11. Upgrades

```bash
sudo bash deploy/update.sh        # pull → bun install → prisma push → build → pm2 reload
# or manually: git fetch && git checkout <tag> && bun install --frozen-lockfile \
#   && bunx prisma generate && bunx prisma db push && bun run build && pm2 reload ecosystem.prod.config.cjs
```

Rollback = previous tag + rebuild (keep one release back).
Config history (`config_versions`) + audit trail survive upgrades.

## 12. Verify deployment (smoke test)

```bash
curl -fsS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3000/          # 200
curl -fsS http://127.0.0.1:3003/healthz                                    # realtime up
curl -fsS -c /tmp/c.txt -X POST http://127.0.0.1:3000/api/v1/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"<new-password>"}'
# REAL telemetry sanity — iface names + live rates must match the host:
curl -fsS -b /tmp/c.txt http://127.0.0.1:3000/api/v1/dashboard/summary | jq '.data.throughput.ifaces'
curl -fsS -b /tmp/c.txt http://127.0.0.1:3000/api/v1/system/status | jq '.data.hostname, .data.dataPlane'
# → hostname = the appliance's real hostname; dataPlane = "host (real telemetry)"
```

---

**Ship state at this tag:** Phase 1 (M0–M11) + Phase 2 (M12–M23) console
complete + **ADR-021 real data plane (M24)** — 46 hash views, ~90 tables, 12
RBAC capability areas, real-PKI tooling, real webhook egress, CEF/LEEF export,
compliance reporting — running under pm2 with zero simulated data, ready for
Debian 13 via `deploy/install-debian13.sh`.
