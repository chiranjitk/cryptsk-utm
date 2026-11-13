/**
 * Phase 2 seed orchestrator (M12–M23).
 *
 * Each milestone ships its own seed module under `prisma/seed-phase2/<milestone>.ts`
 * exporting a default `async function seed(prisma: PrismaClient): Promise<string>` that
 * returns a one-line human summary (rendered in the completion JSON below).
 *
 * Orchestrator imports modules DYNAMICALLY and tolerates missing files, so it can be
 * re-run at any point of the Phase 2 rollout. All module seeds must be idempotent
 * (upsert by the module's unique keys, `tenantId = 1`).
 *
 * Usage: bun prisma/seed-phase2.ts
 */

import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

type SeedFn = (client: PrismaClient) => Promise<string>;

const MODULES: Array<{ id: string; path: string }> = [
  { id: "M12", path: "./seed-phase2/m12" },
  { id: "M13", path: "./seed-phase2/m13" },
  { id: "M14", path: "./seed-phase2/m14" },
  { id: "M15", path: "./seed-phase2/m15" },
  { id: "M16", path: "./seed-phase2/m16" },
  { id: "M17", path: "./seed-phase2/m17" },
  { id: "M18", path: "./seed-phase2/m18" },
  { id: "M19", path: "./seed-phase2/m19" },
  { id: "M20", path: "./seed-phase2/m20" },
  { id: "M21", path: "./seed-phase2/m21" },
  { id: "M22", path: "./seed-phase2/m22" },
  { id: "M23", path: "./seed-phase2/m23" },
];

async function main() {
  const results: Record<string, string> = {};
  for (const mod of MODULES) {
    try {
      const imported = (await import(mod.path)) as { default: SeedFn };
      results[mod.id] = await imported.default(prisma);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (/Cannot find module|MODULE_NOT_FOUND|ERR_MODULE_NOT_FOUND/.test(msg)) {
        results[mod.id] = "skipped (module not built yet)";
        continue;
      }
      throw err;
    }
  }
  console.log(JSON.stringify({ phase2Seed: results }, null, 2));
}

main()
  .then(() => prisma.$disconnect())
  .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    process.exit(1);
  });
