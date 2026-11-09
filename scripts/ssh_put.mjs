#!/usr/bin/env node
// ssh_put.mjs — upload a local file to the production server over SFTP using the Node `ssh2` client.
// Usage:   node scripts/ssh_put.mjs <local-file> <remote-path>
// Example: node scripts/ssh_put.mjs ./deploy.tar.gz /opt/deploy.tar.gz
// Env overrides: SSH_HOST SSH_PORT SSH_USER SSH_PASS SSH_TIMEOUT_MS

import { statSync } from "node:fs";
import { basename } from "node:path";
import { Client } from "ssh2";

const HOST = process.env.SSH_HOST || "103.244.7.219";
const PORT = Number(process.env.SSH_PORT || 22222);
const USER = process.env.SSH_USER || "root";
const PASS = process.env.SSH_PASS || "CryptSK@123#$";
const TIMEOUT_MS = Number(process.env.SSH_TIMEOUT_MS || 300000);

const [localPath, remotePath] = process.argv.slice(2);
if (!localPath || !remotePath) {
  console.error("usage: node scripts/ssh_put.mjs <local-file> <remote-path>");
  process.exit(2);
}

let size = 0;
try {
  size = statSync(localPath).size;
} catch {
  console.error(`[ssh_put] local file not found: ${localPath}`);
  process.exit(2);
}

let closed = false;
const finish = (code, msg) => {
  if (closed) return;
  closed = true;
  clearTimeout(timer);
  if (msg) console.error(msg);
  process.exit(code);
};

const timer = setTimeout(
  () => finish(124, `[ssh_put] timed out after ${TIMEOUT_MS}ms`),
  TIMEOUT_MS
);

const conn = new Client();

conn
  .on("ready", () => {
    conn.sftp((err, sftp) => {
      if (err) {
        conn.end();
        finish(1, `[ssh_put] sftp error: ${err.message}`);
        return;
      }
      const dest =
        remotePath.endsWith("/") ? remotePath + basename(localPath) : remotePath;
      let lastPct = -1;
      sftp.fastPut(localPath, dest, {
        step: (transferred) => {
          const pct = Math.floor((transferred / size) * 100);
          if (pct !== lastPct && pct % 10 === 0) {
            lastPct = pct;
            process.stdout.write(`[ssh_put] ${pct}%\r`);
            if (pct === 100) process.stdout.write("\n");
          }
        },
      }, (err2) => {
        sftp.end();
        conn.end();
        if (err2) finish(1, `[ssh_put] upload failed: ${err2.message}`);
        else finish(0, `[ssh_put] uploaded ${localPath} -> ${HOST}:${dest} (${size} bytes)`);
      });
    });
  })
  .on("error", (err) => finish(1, `[ssh_put] ssh error: ${err.message}`))
  .connect({
    host: HOST,
    port: PORT,
    username: USER,
    password: PASS,
    readyTimeout: 20000,
    keepaliveInterval: 10000,
  });
