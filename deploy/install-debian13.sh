#!/usr/bin/env bash
# =============================================================================
# Cryptsk UTM / NGFW Console — Debian 13 (trixie) fresh-install deploy script
# ADR-021: real data plane (ADAPTER_MODE=host) — NO mock/simulated data.
#
# What it does on a FRESH Debian 13 box:
#   1. apt installs core deps (git, curl, build-essential, nftables, wireguard-tools)
#      + optional appliance stack via flags (--with-ips / --with-dns / --with-dhcp)
#   2. installs Node.js 22 + bun + pm2 (global)
#   3. clones the repo to /opt/cryptsk/console (or pulls if already present)
#   4. writes .env with real secrets (AUTH_SECRET / INTERNAL_TOKEN generated)
#   5. fresh SQLite DB: prisma db push + PRODUCTION seed (zero demo/mock rows)
#      (--db postgres switches the provider per ADR-005 instead)
#   6. production build (next build standalone)
#   7. starts everything under pm2 (cryptsk-utm + realtime-service), saves the
#      process list and installs the boot-persistence hook (pm2 startup)
#   8. smoke-checks http://localhost:3000 and prints the URL + credentials
#
# Usage (as root, on Debian 13):
#   bash deploy/install-debian13.sh                    # core (nftables + wireguard)
#   bash deploy/install-debian13.sh --with-ips --with-dns --with-dhcp
#   bash deploy/install-debian13.sh --db postgres      # PostgreSQL instead of SQLite
#
# Overrides: CRYPTSK_DIR=/opt/cryptsk/console  CRYPTSK_REPO=<git url>  NEXT_PORT=3000
# =============================================================================
set -euo pipefail

# ── config ────────────────────────────────────────────────────────────────────
CRYPTSK_DIR="${CRYPTSK_DIR:-/opt/cryptsk/console}"
CRYPTSK_REPO="${CRYPTSK_REPO:-https://github.com/chiranjitk/cryptsk-utm.git}"
NEXT_PORT="${NEXT_PORT:-3000}"
NODE_MAJOR=22
WITH_IPS=false WITH_DNS=false WITH_DHCP=false DB_ENGINE="sqlite"

for arg in "$@"; do
  case "$arg" in
    --with-ips)  WITH_IPS=true ;;
    --with-dns)  WITH_DNS=true ;;
    --with-dhcp) WITH_DHCP=true ;;
    --db) DB_ENGINE_SET=true ;;
    --db=postgresql|--db=postgres) DB_ENGINE="postgresql" ;;
    --db=sqlite) DB_ENGINE="sqlite" ;;
    *) echo "unknown arg: $arg" ;;
  esac
done
[ "${DB_ENGINE_SET:-false}" = true ] && DB_ENGINE="postgresql" # legacy --db flag

log()  { printf '\n\033[1;36m[deploy]\033[0m %s\n' "$*"; }
fail() { printf '\n\033[1;31m[deploy:FAIL]\033[0m %s\n' "$*" >&2; exit 1; }

# ── preflight ─────────────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || fail "run as root (sudo bash deploy/install-debian13.sh)"
command -v apt-get >/dev/null || fail "apt-get not found — this script targets Debian 12/13"

. /etc/os-release
log "Detected ${PRETTY_NAME:-unknown} — continuing (Debian 12/13 expected)"

export DEBIAN_FRONTEND=noninteractive

# ── 1. apt dependencies ───────────────────────────────────────────────────────
log "Installing apt packages…"
apt-get update -y
apt-get install -y curl git ca-certificates gnupg build-essential nftables wireguard-tools sqlite3
$WITH_IPS  && apt-get install -y suricata || true
$WITH_DNS  && apt-get install -y unbound || true
$WITH_DHCP && apt-get install -y kea-dhcp4-server || true

# ── 2. runtimes: Node.js, bun, pm2 ───────────────────────────────────────────
if ! command -v node >/dev/null || [ "$(node -v | cut -dv -f2 | cut -d. -f1)" -lt "$NODE_MAJOR" ] 2>/dev/null; then
  log "Installing Node.js ${NODE_MAJOR}.x (NodeSource)…"
  (curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash - && apt-get install -y nodejs) \
    || { log "NodeSource unavailable — falling back to distro nodejs"; apt-get install -y nodejs npm; }
fi

if ! command -v bun >/dev/null; then
  log "Installing bun…"
  curl -fsSL https://bun.sh/install | bash
fi
export PATH="$PATH:/root/.bun/bin:/usr/local/bin"
command -v bun >/dev/null || fail "bun not on PATH after install"

if ! command -v pm2 >/dev/null; then
  log "Installing pm2 (global)…"
  npm install -g pm2
fi

# ── 3. source code ────────────────────────────────────────────────────────────
if [ -d "$CRYPTSK_DIR/.git" ]; then
  log "Repo exists at $CRYPTSK_DIR — pulling latest…"
  git -C "$CRYPTSK_DIR" fetch --all
  git -C "$CRYPTSK_DIR" reset --hard origin/HEAD 2>/dev/null || git -C "$CRYPTSK_DIR" reset --hard origin/main
else
  log "Cloning $CRYPTSK_REPO → $CRYPTSK_DIR…"
  mkdir -p "$(dirname "$CRYPTSK_DIR")"
  rm -rf "$CRYPTSK_DIR.tmp"
  git clone --depth 1 "$CRYPTSK_REPO" "$CRYPTSK_DIR.tmp"
  mv "$CRYPTSK_DIR.tmp" "$CRYPTSK_DIR"
fi
cd "$CRYPTSK_DIR"

# ── 4. .env (real secrets; never print them) ─────────────────────────────────
log "Writing .env…"
AUTH_SECRET="$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | sha256sum | cut -d' ' -f1)"
INTERNAL_TOKEN="$(openssl rand -hex 24 2>/dev/null || head -c 24 /dev/urandom | sha256sum | cut -d' ' -f1)"
if [ "$DB_ENGINE" = "postgresql" ]; then
  DATABASE_URL="postgresql://cryptsk:${AUTH_SECRET:0:16}@127.0.0.1:5432/cryptsk"
else
  DATABASE_URL="file:${CRYPTSK_DIR}/db/cryptsk.db"
fi
cat > .env <<ENV
NODE_ENV=production
ADAPTER_MODE=host
DATABASE_URL=${DATABASE_URL}
AUTH_SECRET=${AUTH_SECRET}
JWT_SECRET=${AUTH_SECRET}
INTERNAL_TOKEN=${INTERNAL_TOKEN}
ENV
chmod 600 .env
mkdir -p logs db

# ── 5. dependencies + database ────────────────────────────────────────────────
log "Installing JS dependencies (bun install)…"
bun install --frozen-lockfile || bun install

if [ "$DB_ENGINE" = "postgresql" ]; then
  log "Setting up PostgreSQL (ADR-005 switch)…"
  apt-get install -y postgresql
  systemctl enable --now postgresql
  sudo -u postgres psql -tc "SELECT 1" >/dev/null 2>&1 || fail "PostgreSQL did not start"
  sudo -u postgres psql -c "CREATE USER cryptsk WITH PASSWORD '${AUTH_SECRET:0:16}'" 2>/dev/null || true
  sudo -u postgres psql -c "CREATE DATABASE cryptsk OWNER cryptsk" 2>/dev/null || true
  sed -i 's/provider = "sqlite"/provider = "postgresql"/' prisma/schema.prisma
else
  log "Fresh SQLite database (removing any tracked demo DB first — no mock data ships)…"
  rm -f db/cryptsk.db db/cryptsk.db-journal
fi

log "Prisma: generate + push schema…"
bunx prisma generate
bunx prisma db push --accept-data-loss

log "Seeding PRODUCTION baseline (identity/RBAC + defaults only — zero mock rows)…"
bun prisma/seed.ts --production

# ── 6. production build ───────────────────────────────────────────────────────
log "Building production bundle (next build — takes a few minutes)…"
bun run build

# ── 7. pm2: start + persist + boot hook ──────────────────────────────────────
log "Starting services under pm2 (cryptsk-utm :${NEXT_PORT} + realtime-service :3003)…"
NEXT_PORT="$NEXT_PORT" pm2 start ecosystem.prod.config.cjs || pm2 reload ecosystem.prod.config.cjs
pm2 save

# boot persistence — pm2 resurrects the process list on every reboot
if ! systemctl list-unit-files | grep -q pm2-*.service 2>/dev/null; then
  log "Installing pm2 boot hook (systemd)…"
  pm2 startup systemd -u root --hp /root >/dev/null 2>&1 || true
  pm2 save
fi

# ── 8. smoke check ────────────────────────────────────────────────────────────
log "Waiting for the console to answer…"
CODE="000"
for _ in $(seq 1 30); do
  CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://localhost:${NEXT_PORT}/" || echo 000)"
  [ "$CODE" = "200" ] && break
  sleep 2
done
if [ "$CODE" != "200" ]; then
  pm2 logs --nostream --lines 40 || true
  fail "console did not return HTTP 200 (got $CODE) — check logs above"
fi

IP_DISCOVERED="$(hostname -I 2>/dev/null | awk '{print $1}')"
cat <<DONE

=============================================================================
  ✅ Cryptsk UTM Console is UP — data plane: host (REAL telemetry, ADR-021)
=============================================================================

  pm2 services : cryptsk-utm (Next.js :${NEXT_PORT}) + realtime-service (:3003)
  URL          : http://${IP_DISCOVERED:-<server-ip>}:${NEXT_PORT}/
  Local check  : http://localhost:${NEXT_PORT}/

  Login (CHANGE THESE NOW — Settings → Auth):
    admin   / admin123     (super_admin)
    tadmin  / tadmin123    (tenant_admin)   … 8 accounts total, pattern <user>123

  What is REAL now (no simulated data):
    • CPU/memory/disk/temperature — read from the appliance every 2 s
    • Network interfaces + throughput — /proc/net/dev (auto-discovered)
    • WAN probe states — real gateway TCP probes
    • TCP/UDP session counts — /proc/net/tcp
    • systemd service health — systemctl (suricata, unbound, kea, keepalived…)
    • IPS events — Suricata eve.json (when suricata is installed and running)
    • Firewall logs — nftables kernel logs (when rules log with prefixes)
    • VPN sessions — `wg show` (WireGuard peers with live handshakes)
    • DHCP leases — Kea lease file (when kea-dhcp4-server is installed)
    • DNS query log — unbound query log (when unbound logs queries)

  First run: the setup wizard builds your LAN/WAN config from factory defaults.

  Ops cheatsheet:
    pm2 status                        # both services
    pm2 logs cryptsk-utm              # console logs (logs/ dir too)
    pm2 restart cryptsk-utm           # restart console
    bash deploy/update.sh             # pull + rebuild + reload (later updates)

  Optional: install Caddy for TLS in front of :${NEXT_PORT} (see DEPLOYMENT.md §7).
=============================================================================
DONE
