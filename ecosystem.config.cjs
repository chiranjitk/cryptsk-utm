/**
 * pm2 ecosystem — Cryptsk UTM console (Debian 13 target, sandbox dev).
 * Start/reload:  pm2 start ecosystem.config.cjs
 * Persist list:  pm2 save   →   pm2 resurrect  (after daemon restart)
 * Logs:          pm2 logs cryptsk-utm
 */
module.exports = {
  apps: [
    {
      name: "cryptsk-utm",
      cwd: "/home/z/my-project",
      script: "node_modules/next/dist/bin/next",
      args: "dev -p 3000",
      exec_mode: "fork",
      instances: 1,
      autorestart: true,
      max_memory_restart: "1400M",
      restart_delay: 3000,
      env: {
        NODE_ENV: "development",
        NODE_OPTIONS: "--max-old-space-size=1400",
      },
      out_file: "/home/z/my-project/dev.log",
      error_file: "/home/z/my-project/dev.log",
      merge_logs: true,
      time: true,
    },
    {
      name: "realtime-service",
      cwd: "/home/z/my-project/mini-services/realtime-service",
      script: "bun",
      args: "run dev",
      autorestart: true,
      restart_delay: 3000,
      out_file: "/home/z/my-project/.zscripts/mini-service-realtime-service.log",
      error_file: "/home/z/my-project/.zscripts/mini-service-realtime-service.log",
      merge_logs: true,
      time: true,
    },
  ],
};
