/**
 * Next.js instrumentation hook — boots the MockEngine tick loop with the
 * server process so metrics/logs flow before the first API hit.
 */

export async function register() {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  try {
    const { getMockEngine } = await import("@/lib/engine/mock-engine");
    await getMockEngine().start();
  } catch (err) {
    console.error("[instrumentation] mock engine boot deferred:", err instanceof Error ? err.message : err);
  }
}
