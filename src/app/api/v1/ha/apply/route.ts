/**
 * POST /api/v1/ha/apply — converge /etc/keepalived/keepalived.conf onto the
 * console HA config (validate-first, backup, auto-restore on failure).
 *
 * Gate model (identical to interfaces/firewall):
 *   • CONSOLE_OS_APPLY=1  → execute the plan on the appliance;
 *   • otherwise           → plan preview only (no exec, no OS change).
 *
 * Red lines enforced here:
 *   • HA disabled → refuse (never touch an operator-managed conf);
 *   • protected WAN uplinks (ens32) are hard-refused by hardRefusal();
 *   • `keepalived -t` must pass on the STAGE file before the live conf moves;
 *   • failed restart/verify → the timestamped backup is restored and
 *     keepalived restarted again (auto-rollback).
 */

import osMod from "os";
import { writeFile, rm } from "fs/promises";
import { route } from "@/lib/api/handler";
import { runTool } from "@/lib/host/tools";
import { getDataPlaneMode } from "@/lib/engine";
import { getHaConfig, toKeepalivedInput, buildHaFacts } from "@/lib/ha/service";
import {
  buildHaApplyPlan,
  hardRefusal,
  haStepGuarded,
  isHaBackupPath,
  interpretKeepalivedTest,
  KEEPALIVED_STAGE,
  KEEPALIVED_CONF,
} from "@/lib/ha/os";
import { db } from "@/lib/db";

export const dynamic = "force-dynamic";

type StepResult = { step: string; ok: boolean; detail?: string };

export const POST = route({ area: "ha", section: "ha" }, async ({ auth }) => {
  const config = await getHaConfig(auth.tenantId);
  const gateOn = process.env.CONSOLE_OS_APPLY === "1" && getDataPlaneMode() === "host";

  // build plan from the DB row + real host facts (unicast needs the local IP)
  const facts = await buildHaFacts(auth.tenantId);
  const cfgInput = toKeepalivedInput(config);
  const refusal = hardRefusal(cfgInput);
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const plan = buildHaApplyPlan(
    cfgInput,
    { routerId: osMod.hostname().toUpperCase().slice(0, 24) || "UTM-CONSOLE", localIfaceIp: facts.localIfaceIp },
    gateOn ? "exec" : "plan",
    ts,
  );

  if (refusal) {
    return {
      data: { applied: false, refused: refusal, plan: { steps: plan.steps, confText: plan.confText }, results: [] },
      audit: { action: "ha.os-apply.refused", objectType: "ha_config", objectName: "ha" },
    };
  }
  if (!config.enabled || config.role === "disabled") {
    return {
      data: {
        applied: false,
        refused: "HA is disabled in the console — apply would only be safe after enabling HA with a virtual IP; the OS conf was left untouched",
        plan: { steps: plan.steps, confText: plan.confText },
        results: [],
      },
      audit: { action: gateOn ? "ha.os-apply.exec" : "ha.os-apply.plan", objectType: "ha_config", objectName: "ha" },
    };
  }

  const results: StepResult[] = [];
  if (!gateOn) {
    return {
      data: {
        applied: false,
        refused: "CONSOLE_OS_APPLY is off — plan preview only (rendered conf attached)",
        plan: { steps: plan.steps, confText: plan.confText },
        results,
      },
      audit: { action: "ha.os-apply.plan", objectType: "ha_config", objectName: "ha" },
    };
  }

  let failed = false;
  let failDetail = "";
  for (const s of plan.steps) {
    if (s.step === "write stage") {
      // file write (not exec) — content comes from the deterministic renderer
      await writeFile(KEEPALIVED_STAGE, plan.confText, "utf8");
      results.push({ step: s.step, ok: true, detail: `${plan.confText.length} bytes staged` });
      continue;
    }
    if (!haStepGuarded(s.cmd)) {
      failed = true;
      failDetail = `step '${s.step}' failed the command whitelist — execution aborted`;
      results.push({ step: s.step, ok: false, detail: failDetail });
      break;
    }
    const r = await runTool(s.cmd, 20000);
    // keepalived -t exits non-zero for warnings too — errors only are fatal
    const isTestStep = s.step.startsWith("validate");
    const verdict = isTestStep ? interpretKeepalivedTest(`${r.stderr}${r.stdout}`, r.ok) : null;
    if (verdict) {
      if (!verdict.ok) {
        failed = true;
        failDetail = `step '${s.step}' failed: ${verdict.detail}`;
        results.push({ step: s.step, ok: false, detail: verdict.detail });
        break;
      }
      results.push({ step: s.step, ok: true, detail: verdict.detail || undefined });
      continue;
    }
    if (!r.ok) {
      failed = true;
      failDetail = `step '${s.step}' failed: ${(r.stderr || r.error || "").trim().slice(0, 300) || "exec error"}`;
      results.push({ step: s.step, ok: false, detail: failDetail });
      break;
    }
    const detail = r.stdout.trim().slice(0, 400);
    results.push({ step: s.step, ok: true, detail: detail || undefined });
  }

  // ── auto-rollback: restore the backup + restart again (only if live conf moved) ──
  let rolledBack = false;
  const installOk = results.find((r) => r.step === "install conf")?.ok === true;
  if (failed && installOk && isHaBackupPath(plan.backupFile)) {
    const restore = await runTool(`install -m 0644 ${plan.backupFile} ${KEEPALIVED_CONF}`, 10000);
    const restart = await runTool("systemctl restart keepalived", 20000);
    rolledBack = restore.ok && restart.ok;
    results.push({
      step: "auto-rollback",
      ok: rolledBack,
      detail: rolledBack ? "previous keepalived.conf restored and keepalived restarted" : `restore failed: ${restore.stderr || restart.error}`,
    });
  }

  if (!failed) {
    await rm(KEEPALIVED_STAGE, { force: true }).catch(() => {});
    const row = await db.haConfig.findFirst({ where: { tenantId: auth.tenantId } });
    if (row) {
      await db.haConfig.update({
        where: { id: row.id },
        data: { osConfHash: plan.confHash, osAppliedAt: new Date() },
      });
    }
  }

  return {
    data: {
      applied: !failed,
      reason: failed ? failDetail : `keepalived.conf converged (hash ${plan.confHash})`,
      rolledBack,
      confHash: plan.confHash,
      backupFile: plan.backupFile,
      plan: { steps: plan.steps, confText: plan.confText },
      results,
    },
    audit: {
      action: failed ? "ha.os-apply.failed" : "ha.os-apply.exec",
      objectType: "ha_config",
      objectId: config.id,
      objectName: "ha",
      after: { confHash: plan.confHash, backup: plan.backupFile, results },
    },
  };
});
