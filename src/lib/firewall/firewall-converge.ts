/**
 * firewall-converge — debounced real-time OS convergence for firewall changes.
 *
 * Every firewall/NAT/zone/object mutation schedules a full policy re-apply
 * (coalesced). Auto mode self-confirms when the post-apply WAN health check
 * passes and auto-restores the backup when it regresses — a bad rule can
 * never leave the host in a broken state for more than one probe cycle.
 *
 * In sandbox/dev (CONSOLE_OS_APPLY unset) this is a silent no-op — the
 * console honestly stays DB-only there.
 */

import { applyFirewallNft } from "./firewall-os";

const DEBOUNCE_MS = 1500;
let timer: ReturnType<typeof setTimeout> | null = null;
let lastTenantId = 1;
let converging = false;

export function scheduleFirewallConverge(tenantId = 1, delayMs = DEBOUNCE_MS): void {
  if (process.env.CONSOLE_OS_APPLY !== "1") return;
  lastTenantId = tenantId;
  if (timer) clearTimeout(timer);
  timer = setTimeout(() => {
    timer = null;
    void runConverge();
  }, delayMs);
  timer.unref?.();
}

async function runConverge(): Promise<void> {
  if (converging) {
    scheduleFirewallConverge(lastTenantId, DEBOUNCE_MS); // re-arm — a change landed mid-apply
    return;
  }
  converging = true;
  try {
    const outcome = await applyFirewallNft(lastTenantId, { mode: "auto" });
    if (outcome.rolledBack) {
      console.error(`[fw-converge] apply rolled back automatically: ${outcome.rollbackReason}`);
    } else if (!outcome.applied && outcome.gate === "on") {
      console.warn(`[fw-converge] apply did not complete: ${outcome.results.filter((r) => !r.ok).map((r) => `${r.step}: ${r.detail ?? "?"}`).join("; ")}`);
    }
  } catch (err) {
    console.error("[fw-converge] convergence error:", err instanceof Error ? err.message : err);
  } finally {
    converging = false;
  }
}

/** Test hook — clears the pending timer. */
export function cancelScheduledConverge(): void {
  if (timer) clearTimeout(timer);
  timer = null;
}
