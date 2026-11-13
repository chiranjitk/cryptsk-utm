#!/usr/bin/env node
// ssh_put.mjs — SFTP-upload a local file to the production server (ssh2).
// Usage: node scripts/ssh_put.mjs <localPath> <remotePath>

import { Client } from "ssh2";
import { readFileSync, statSync } from "fs";
import { basename } from "path";

const HOST = process.env.SSH_HOST || "103.244.7.219";
const PORT = Number(process.env.SSH_PORT || 22222);
const USER = process.env.SSH_USER || "root";
const PASS = process.env.SSH_PASS || "CryptSK@123#$";
const TIMEOUT_MS = Number(process.env.SSH_TIMEOUT_MS || 300000);

const [localPath, remotePath] = process.argv.slice(2);
if (!localPath || !remotePath) {
  console.error("usage: node scripts/ssh_put.mjs <localPath> <remotePath>");
  process.exit(2);
}

const size = statSync(localPath).size;
let closed = false;
const timer = setTimeout(() => {
  if (!closed) {
    closed = true;
    console.error(`[ssh_put] timed out after ${TIMEOUT_MS}ms`);
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
    conn.sftp((err, sftp) => {
      if (err) {
        console.error(`[ssh_put] sftp error: ${err.message}`);
        conn.end();
        finish(1);
        return;
      }
      const ws = sftp.createWriteStream(remotePath, { mode: 0o600 });
      let sent = 0;
      ws.on("error", (e) => {
        console.error(`[ssh_put] write error: ${e.message}`);
        conn.end();
        finish(1);
      });
      // chunked write with backpressure
      const data = readFileSync(localPath);
      let offset = 0;
      const CHUNK = 256 * 1024;
      const writeNext = () => {
        while (offset < data.length) {
          const chunk = data.subarray(offset, Math.min(offset + CHUNK, data.length));
          offset += chunk.length;
          sent = offset;
          if (!ws.write(chunk)) {
            ws.once("drain", writeNext);
            return;
          }
        }
        ws.end();
      };
      ws.on("close", () => {
        console.log(`[ssh_put] uploaded ${basename(localPath)} (${size} bytes) -> ${remotePath}`);
        conn.end();
        finish(0);
      });
      writeNext();
    });
  })
  .on("error", (e) => {
    console.error(`[ssh_put] connection error: ${e.message}`);
    finish(1);
  })
  .connect({ host: HOST, port: PORT, username: USER, password: PASS, readyTimeout: TIMEOUT_MS });
