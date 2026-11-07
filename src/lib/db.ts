/**
 * Prisma client singleton (ADR-004 build contract).
 *
 * DATABASE_URL resolution — explicit because Next standalone builds do NOT
 * reliably forward process.env into the traced client's internal env lookup
 * (symptom: SQLite "Error code 14: Unable to open the database file" even with
 * a correct absolute DATABASE_URL exported; the same URL passed via the
 * constructor `datasourceUrl` works):
 *
 *   1. process.env.DATABASE_URL — trusted for `postgresql://…` and for `file:`
 *      URLs whose target actually exists (guards against stale session envs
 *      pointing at scaffold-era phantom files like db/custom.db);
 *   2. `<cwd>/.env` — parsed for DATABASE_URL (repo dev + standalone layouts);
 *   3. undefined — Prisma falls back to schema.prisma env resolution (dev).
 */
import fs from "node:fs";
import path from "node:path";
import { PrismaClient } from "@prisma/client";

function fileExistsForUrl(url: string): boolean {
  if (!url.startsWith("file:")) return true; // non-file URLs (postgres…) pass through
  const p = url.slice("file:".length);
  const abs = p.startsWith("/") ? p : path.resolve(process.cwd(), p);
  return fs.existsSync(abs);
}

function envFileDatabaseUrl(): string | undefined {
  for (const candidate of [path.resolve(process.cwd(), ".env"), path.resolve(process.cwd(), "../.env")]) {
    try {
      const text = fs.readFileSync(candidate, "utf8");
      const line = text.split("\n").find((l) => /^\s*DATABASE_URL\s*=/.test(l));
      if (!line) continue;
      const value = line.slice(line.indexOf("=") + 1).trim().replace(/^["']|["']$/g, "");
      if (value) return value;
    } catch {
      // no .env at this level — try next candidate
    }
  }
  return undefined;
}

function resolveDatabaseUrl(): string | undefined {
  const fromEnv = process.env.DATABASE_URL;
  if (fromEnv && fileExistsForUrl(fromEnv)) return fromEnv;
  const fromDotenv = envFileDatabaseUrl();
  if (fromDotenv && fileExistsForUrl(fromDotenv)) return fromDotenv;
  return undefined;
}

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined
}

export const db =
  globalForPrisma.prisma ??
  new PrismaClient({
    log: ['query'],
    ...(resolveDatabaseUrl() ? { datasourceUrl: resolveDatabaseUrl() } : {}),
  })

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = db
