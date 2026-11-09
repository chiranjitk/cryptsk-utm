#!/usr/bin/env node
// ssh_run.mjs — run a command on the production server over SSH using the Node `ssh2` client.
// Usage:   node scripts/ssh_run.mjs "<command>"
// Example: node scripts/ssh_run.mjs "pm2 ls && curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3000/"
// Env overrides: SSH_HOST SSH_PORT SSH_USER SSH_PASS SSH_TIMEOUT_MS

import { Client } from "ssh2";

const HOST = process.env.SSH_HOST || "103.244.7.219";
const PORT = Number(process.env.SSH_PORT || 22222);
const USER = process.env.SSH_USER || "root";
const PASS = process.env.SSH_PASS || "CryptSK@123#$";
const TIMEOUT_MS = Number(process.env.SSH_TIMEOUT_MS || 120000);

const cmd = process.argv.slice(2).join(" ").trim();
if (!cmd) {
  console.error("usage: node scripts/ssh_run.mjs \"<command>\"");
  process.exit(2);
}

let closed = false;
const timer = setTimeout(() => {
  if (!closed) {
    closed = true;
    console.error(`\n[ssh_run] timed out after ${TIMEOUT_MS}ms`);
    process.exit(124);
  }
}, TIMEOUT_MS);

const finish = (code) => {
  if (closed) return;
  closed = true;
  clearTimeout(timer);
  process.exit(code);
};

const conn = new Client();

conn
  .on("ready", () => {
    conn.exec(cmd, (err, stream) => {
      if (err) {
        console.error(`[ssh_run] exec error: ${err.message}`);
        conn.end();
        finish(1);
        return;
      }
      stream
        .on("close", (code) => {
          conn.end();
          finish(code ?? 0);
        })
        .on("data", (data) => process.stdout.write(data.toString()))
        .stderr.on("data", (data) => process.stderr.write(data.toString()));
    });
  })
  .on("error", (err) => {
    console.error(`[ssh_run] ssh error: ${err.message}`);
    finish(1);
  })
  .on("end", () => finish(0))
  .connect({
    host: HOST,
    port: PORT,
    username: USER,
    password: PASS,
    readyTimeout: 20000,
    keepaliveInterval: 10000,
  });
