#!/bin/bash
# sandbox-recovery.sh — restore the Cryptsk console after a sandbox reboot.
#
# The sandbox reset (machine reboot) causes three recurring problems:
#   1. .env is replaced by the platform stub (DATABASE_URL=db/custom.db, no AUTH_SECRET)
#   2. pm2 (npm -g) is wiped, and the platform watchdog starts `bun run dev`
#      directly — uncapped heap (next dev balloons on a 4GB box) and no dev.log
#   3. db/cryptsk.db survives as an empty-schema file (untracked in git) — all
#      rows lost, users table empty → login 401
#
# This script is IDEMPOTENT — safe to run any time:
#   bash scripts/sandbox-recovery.sh
#
# After it finishes, the app is served under pm2 per ecosystem.config.cjs
# (memory-capped 1400M, logs in dev.log, realtime-service on 3003).

set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

log() { echo "[recovery $(date '+%H:%M:%S')] $*"; }

# ── 1. .env: restore full sandbox env if the platform stub is present ─────────
if ! grep -q "AUTH_SECRET" .env 2>/dev/null; then
  log "restoring .env (stub detected)"
  AUTH=$(openssl rand -hex 32)
  AGENT=$(openssl rand -hex 32)
  INTERNAL=$(openssl rand -hex 12)
  cat > .env <<EOF
# Cryptsk Console — sandbox runtime env (restored by sandbox-recovery.sh)

# database
DATABASE_URL="file:/home/z/my-project/db/cryptsk.db"

# auth
AUTH_SECRET="$AUTH"
JWT_SECRET="$AUTH"
NODE_ENV=development

# data plane / adapter mode (ADR-004 + ADR-021)
ADAPTER_MODE=host
AGENT_BASE_URL="http://127.0.0.1:8080"
AGENT_SHARED_SECRET="$AGENT"

# realtime mini-service (socket.io, ADR-008)
INTERNAL_TOKEN="$INTERNAL"
EOF
  chmod 600 .env
else
  log ".env OK"
fi

# ── 2. dependencies (node_modules may be pruned) ───────────────────────────────
if [ ! -d node_modules/next ]; then
  log "installing dependencies"
  bun install
else
  log "node_modules OK"
fi

# ── 3. database: ensure schema + seed if the users table is empty ─────────────
mkdir -p db
if ! bun -e "
import { PrismaClient } from '@prisma/client';
const p = new PrismaClient();
const n = await p.user.count();
await p.\$disconnect();
process.exit(n > 0 ? 0 : 1);
" >/dev/null 2>&1; then
  log "database empty/missing — pushing schema and seeding"
  bun run db:generate >/dev/null 2>&1 || true
  bun run db:push
  bun run seed
else
  log "database OK (users present)"
fi

# ── 4. pm2: (re)install if wiped, take over from the watchdog dev server ──────

# Fast path: pm2 apps already online AND app already serving → nothing to do.
PM2_UTM_PID=$(pm2 pid cryptsk-utm 2>/dev/null || true)
if [ -n "$PM2_UTM_PID" ] && ps -p "$PM2_UTM_PID" >/dev/null 2>&1; then
  CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 http://localhost:3000/ 2>/dev/null || echo 000)
  if [ "$CODE" = "200" ]; then
    log "pm2 cryptsk-utm already running and healthy (HTTP 200) — nothing to do"
    exit 0
  fi
fi

if ! command -v pm2 >/dev/null 2>&1; then
  log "installing pm2"
  npm install -g pm2
fi

# Kill any watchdog-started uncapped dev server holding :3000/:3003.
# Runs BEFORE pm2 apps exist, so EVERY listener on those ports is a stray.
# Kill the whole PROCESS GROUP (bun run dev → next dev → next-server die together,
# otherwise the parent respawns/rebinds and pm2 crash-loops on EADDRINUSE).
for pid in $(ss -tlnp 2>/dev/null | grep -E ':(3000|3003)\b' | grep -oP 'pid=\K[0-9]+' | sort -u); do
  PGID=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')
  if [ -n "$PGID" ] && [ "$PGID" != "1" ]; then
    log "stopping stray process tree on port (pid $pid, pgid $PGID)"
    kill -- -"$PGID" 2>/dev/null || kill "$pid" 2>/dev/null || true
  else
    log "stopping stray process on port (pid $pid)"
    kill "$pid" 2>/dev/null || true
  fi
done
sleep 3

# stop stale pm2 entries so the restart counter resets and ports are re-bound cleanly
pm2 delete cryptsk-utm 2>/dev/null || true
pm2 delete realtime-service 2>/dev/null || true

# start under pm2
pm2 start ecosystem.config.cjs
pm2 save

# ── 5. wait for first compile and report ──────────────────────────────────────
log "waiting for the app to come up on :3000"
for i in $(seq 1 60); do
  sleep 5
  CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 http://localhost:3000/ 2>/dev/null || echo 000)
  if [ "$CODE" = "200" ]; then
    log "app is UP (HTTP 200)"
    curl -s -o /dev/null -w "login probe → HTTP %{http_code}\n" \
      -X POST http://localhost:3000/api/v1/auth/login \
      -H "Content-Type: application/json" \
      -d '{"username":"admin","password":"admin123"}' || true
    exit 0
  fi
done
log "WARNING: app did not return 200 within 300s — check dev.log"
exit 1
