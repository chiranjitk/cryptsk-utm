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
 */

const ROOT = __dirname;
const NEXT_PORT = process.env.NEXT_PORT || "3000";

module.exports = {
  apps: [
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
  ],
};
