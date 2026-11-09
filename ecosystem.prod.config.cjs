/**
 * pm2 PRODUCTION ecosystem — Cryptsk UTM console on Debian 13 (ADR-021).
 *
 * Paths are derived from this file's location, so the same config works in
 * the sandbox (/home/z/my-project) and on the appliance (/opt/cryptsk/console).
 *
 * Fresh Debian install:  sudo deploy/install-debian13.sh   (starts everything)
 * Manual start:          pm2 start ecosystem.prod.config.cjs && pm2 save
 * Boot persistence:      pm2 startup systemd -u $USER && pm2 save
 *
 * NOTE: `pm2 start ecosystem.config.cjs` (dev variant) is for the sandbox
 * only — production MUST use this file (next standalone build, not dev).
 *
 * Three apps:
 *   1. cryptsk-utm        Next.js console (:3000) — real data plane (ADR-021)
 *   2. realtime-service   socket.io mini-service (:3003)
 *   3. cryptsk-agent      Go sensor agent (:8080, ADR-004) — started ONLY
 *                         when agent/cryptsk-agent is built (deploy script
 *                         builds it). Serves remote consoles / Phase-4
 *                         manager; console transport = ADAPTER_MODE=agent.
 */

const fs = require("fs");
const path = require("path");

const ROOT = __dirname;
const NEXT_PORT = process.env.NEXT_PORT || "3000";

// pull the secrets the agent needs from .env (never log them)
function readDotEnv(p) {
  const out = {};
  try {
    for (const line of fs.readFileSync(p, "utf8").split("\n")) {
      const t = line.trim();
      if (!t || t.startsWith("#")) continue;
      const i = t.indexOf("=");
      if (i > 0) out[t.slice(0, i).trim()] = t.slice(i + 1).trim().replace(/^['"]|['"]$/g, "");
    }
  } catch {}
  return out;
}
const dotEnv = readDotEnv(path.join(ROOT, ".env"));

const apps = [
  {
    name: "cryptsk-utm",
    cwd: ROOT,
    script: "node_modules/next/dist/bin/next",
    args: "start -p " + NEXT_PORT,
    exec_mode: "fork",
    instances: 1,
    autorestart: true,
    max_memory_restart: "1500M",
    restart_delay: 3000,
    env: {
      NODE_ENV: "production",
      PORT: NEXT_PORT,
      NODE_OPTIONS: "--max-old-space-size=1500",
    },
    out_file: ROOT + "/logs/console-out.log",
    error_file: ROOT + "/logs/console-err.log",
    merge_logs: true,
    time: true,
  },
  {
    name: "realtime-service",
    cwd: ROOT + "/mini-services/realtime-service",
    script: "bun",
    args: "run start",
    autorestart: true,
    restart_delay: 3000,
    max_memory_restart: "400M",
    env: {
      NODE_ENV: "production",
    },
    out_file: ROOT + "/logs/realtime-out.log",
    error_file: ROOT + "/logs/realtime-err.log",
    merge_logs: true,
    time: true,
  },
];

// sensor agent — only when the Go binary has been built (deploy/install-debian13.sh)
const agentBin = path.join(ROOT, "agent", "cryptsk-agent");
if (fs.existsSync(agentBin)) {
  apps.push({
    name: "cryptsk-agent",
    cwd: ROOT,
    script: agentBin,
    interpreter: "none",
    autorestart: true,
    restart_delay: 3000,
    max_memory_restart: "150M",
    env: {
      AGENT_LISTEN: ":8080",
      AGENT_SHARED_SECRET: dotEnv.AGENT_SHARED_SECRET || "",
      SURICATA_EVE_PATH: dotEnv.SURICATA_EVE_PATH || "/var/log/suricata/eve.json",
      UNBOUND_LOG_PATH: dotEnv.UNBOUND_LOG_PATH || "/var/log/unbound/unbound.log",
    },
    out_file: ROOT + "/logs/agent-out.log",
    error_file: ROOT + "/logs/agent-err.log",
    merge_logs: true,
    time: true,
  });
}

module.exports = { apps };
