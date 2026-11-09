#!/usr/bin/env bash
# =============================================================================
# Cryptsk UTM Console — update script (Debian 13 appliance, pm2-managed).
# Pulls the latest main, reinstalls deps, pushes schema, rebuilds and reloads
# pm2 with zero-downtime reload semantics. Run as root.
# =============================================================================
set -euo pipefail

CRYPTSK_DIR="${CRYPTSK_DIR:-/opt/cryptsk/console}"

log() { printf '\n\033[1;36m[update]\033[0m %s\n' "$*"; }
fail() { printf '\n\033[1;31m[update:FAIL]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "run as root"
[ -d "$CRYPTSK_DIR/.git" ] || fail "no repo at $CRYPTSK_DIR — run deploy/install-debian13.sh first"

cd "$CRYPTSK_DIR"
export PATH="$PATH:/root/.bun/bin:/usr/local/bin"
command -v bun >/dev/null || fail "bun not on PATH"
command -v pm2 >/dev/null || fail "pm2 not on PATH"

log "Pulling latest main…"
git fetch --all
BEFORE="$(git rev-parse --short HEAD)"
git reset --hard origin/main
AFTER="$(git rev-parse --short HEAD)"
log "HEAD: ${BEFORE} → ${AFTER}"

log "Installing deps…"
bun install --frozen-lockfile || bun install

log "Prisma: generate + push…"
bunx prisma generate
bunx prisma db push --accept-data-loss

log "Building…"
bun run build

log "Reloading pm2 services…"
pm2 start ecosystem.prod.config.cjs --update-env || pm2 reload ecosystem.prod.config.cjs || pm2 restart all
pm2 save

log "Waiting for the console…"
for _ in $(seq 1 30); do
  CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://localhost:3000/ || echo 000)"
  [ "$CODE" = "200" ] && { log "OK — HTTP 200"; pm2 status; exit 0; }
  sleep 2
done
pm2 logs --nostream --lines 40 || true
fail "console did not return HTTP 200 after update"
