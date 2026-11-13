/**
 * /api/v1/firewall-rules/os — the GUI↔nftables integration endpoint.
 *
 * GET   — live OS status: facts (nft version, ip_forward, interfaces, table
 *         presence, fail2ban coexistence), the generated plan (counts,
 *         warnings, forward policy, full file), drift (applied/in-sync),
 *         kernel rule counters, pending commit-confirm window, gate state.
 *
 * POST  — { action }:
 *           "apply"    — plan → `nft -c` check → backup → arm rollback
 *                        timer → `nft -f` → WAN-health probe (auto-restore on
 *                        regression) → persistence. mode "auto" self-confirms
 *                        after health; "manual" leaves the commit-confirm
 *                        window open for the operator.
 *           "confirm"  — confirms the pending apply (cancels the rollback)
 *           "rollback" — restores the newest backup immediately
 *           "sync-hits"— pushes kernel counters into DB hitCount (real hits)
 *           "enable-forwarding" — sysctl net.ipv4.ip_forward=1 + persist
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { z } from "zod";
import {
  buildFirewallPlan,
  readApplyState,
  readConsoleTableDump,
  applyFirewallNft,
  confirmFirewallApply,
  rollbackFirewall,
  syncHitsFromKernel,
  parseRuleCounters,
  readOsFacts,
} from "@/lib/firewall/firewall-os";
import { runTool } from "@/lib/host/tools";

export const dynamic = "force-dynamic";

const bodySchema = z.object({
  action: z.enum(["apply", "confirm", "rollback", "sync-hits", "enable-forwarding"]),
  mode: z.enum(["manual", "auto"]).optional(),
  confirmSec: z.number().int().min(15).max(600).optional(),
  ts: z.string().max(64).optional(),
  enableForwarding: z.boolean().optional(),
});

export const GET = route({ area: "firewall" }, async ({ auth }) => {
  const plan = await buildFirewallPlan(auth.tenantId);
  const [liveDump, pending] = await Promise.all([readConsoleTableDump(), readApplyState()]);
  const counters = liveDump ? parseRuleCounters(liveDump) : [];
  return {
    data: {
      gate: process.env.CONSOLE_OS_APPLY === "1" ? "on" : "off",
      facts: plan.facts,
      drift: plan.drift,
      counts: plan.gen.counts,
      forwardPolicy: plan.gen.forwardPolicy,
      warnings: plan.gen.warnings,
      file: plan.file,
      ipForwardRequired: plan.ipForwardRequired,
      counters,
      pendingConfirm: pending,
      tableDump: liveDump,
    },
  };
});

export const POST = route({ area: "firewall", bodySchema, section: "firewall" }, async ({ auth, body }) => {
  switch (body.action) {
    case "apply": {
      const outcome = await applyFirewallNft(auth.tenantId, {
        mode: body.mode ?? "manual",
        confirmSec: body.confirmSec,
        enableForwarding: body.enableForwarding,
      });
      return {
        data: outcome,
        audit: {
          action: outcome.rolledBack ? "firewall.os-apply-rollback" : "firewall.os-apply",
          objectType: "firewall_policy",
          objectName: `mode=${body.mode ?? "manual"}`,
          result: outcome.applied && !outcome.rolledBack ? "success" : "rolled-back",
        },
      };
    }
    case "confirm": {
      if (!body.ts) throw ApiError.validation("confirm requires ts of the pending apply");
      const r = await confirmFirewallApply(body.ts);
      if (!r.confirmed) throw ApiError.notFound("no pending apply window for this ts (already confirmed or expired)");
      return {
        data: r,
        audit: { action: "firewall.os-confirm", objectType: "firewall_policy", objectId: body.ts },
      };
    }
    case "rollback": {
      const r = await rollbackFirewall(body.ts);
      return {
        data: r,
        audit: {
          action: "firewall.os-rollback",
          objectType: "firewall_policy",
          objectName: r.file ?? undefined,
          result: r.rolledBack ? "success" : "failed",
        },
      };
    }
    case "sync-hits": {
      const r = await syncHitsFromKernel(auth.tenantId);
      return { data: r, audit: { action: "firewall.os-sync-hits", objectType: "firewall_policy" } };
    }
    case "enable-forwarding": {
      const res = await runTool("sysctl -w net.ipv4.ip_forward=1", 5000);
      if (!res.ok) throw ApiError.internal(`sysctl failed: ${res.stderr || res.error || "unknown"}`);
      let persisted = false;
      try {
        const { default: fs } = await import("fs/promises");
        await fs.writeFile("/etc/sysctl.d/90-console-forwarding.conf", "# console-managed: required for firewall forwarding/NAT\nnet.ipv4.ip_forward=1\n", "utf8");
        persisted = true;
      } catch {
        persisted = false;
      }
      const facts = await readOsFacts();
      return {
        data: { ipForward: facts.ipForward, persisted },
        audit: { action: "firewall.os-enable-forwarding", objectType: "firewall_policy" },
      };
    }
  }
});
