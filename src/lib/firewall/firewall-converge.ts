/**
 * firewall-converge — debounced real-time OS convergence for firewall changes.
 *
 * Every firewall/NAT/zone/object mutation schedules a full policy re-apply
 * (coalesced PER TENANT — each tenant owns its own pending timer and debounce
 * window; bursts of changes across tenants never collapse into one global
 * apply of the "last" tenant). Auto mode self-confirms when the post-apply WAN
 * health check passes and auto-restores the backup when it regresses — a bad
 * rule can never leave the host in a broken state for more than one probe
 * cycle.
 *
 * In sandbox/dev (CONSOLE_OS_APPLY unset) this is a silent no-op — the
 * console honestly stays DB-only there.
 */

import { applyFirewallNft } from "./firewall-os";

const DEBOUNCE_MS = 1500;
/** per-tenant pending timers — one debounce window per tenant */
const pendingTimers = new Map<number, ReturnType<typeof setTimeout>>();
/** tenants with an apply currently in flight (re-arm per tenant on overlap) */
const convergingTenants = new Set<number>();

export function scheduleFirewallConverge(tenantId: number, delayMs = DEBOUNCE_MS): void {
  if (process.env.CONSOLE_OS_APPLY !== "1") return;
  const existing = pendingTimers.get(tenantId);
  if (existing) clearTimeout(existing);
  const timer = setTimeout(() => {
    pendingTimers.delete(tenantId);
    void runConverge(tenantId);
  }, delayMs);
  timer.unref?.();
  pendingTimers.set(tenantId, timer);
}

async function runConverge(tenantId: number): Promise<void> {
  if (convergingTenants.has(tenantId)) {
    scheduleFirewallConverge(tenantId, DEBOUNCE_MS); // re-arm — a change landed mid-apply
    return;
  }
  convergingTenants.add(tenantId);
  try {
    const outcome = await applyFirewallNft(tenantId, { mode: "auto" });
    if (outcome.rolledBack) {
      console.error(`[fw-converge] tenant ${tenantId}: apply rolled back automatically: ${outcome.rollbackReason}`);
    } else if (!outcome.applied && outcome.gate === "on") {
      console.warn(`[fw-converge] tenant ${tenantId}: apply did not complete: ${outcome.results.filter((r) => !r.ok).map((r) => `${r.step}: ${r.detail ?? "?"}`).join("; ")}`);
    }
  } catch (err) {
    console.error(`[fw-converge] tenant ${tenantId}: convergence error:`, err instanceof Error ? err.message : err);
  } finally {
    convergingTenants.delete(tenantId);
  }
}

/** Test hook — clears ALL pending tenant timers. */
export function cancelScheduledConverge(): void {
  for (const timer of pendingTimers.values()) clearTimeout(timer);
  pendingTimers.clear();
}
