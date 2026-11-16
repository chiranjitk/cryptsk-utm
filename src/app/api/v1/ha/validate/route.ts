/**
 * POST /api/v1/ha/validate — render the console HA config into keepalived.conf
 * and run `keepalived -t` on a TEMP file. Nothing on the appliance is
 * modified: no /etc write, no service restart. Sandbox (no keepalived
 * binary) returns honest { available:false } instead of a fake pass.
 */

import osMod from "os";
import { writeFile, rm } from "fs/promises";
import { route } from "@/lib/api/handler";
import { runTool, hasTool } from "@/lib/host/tools";
import { getDataPlaneMode } from "@/lib/engine";
import { getHaConfig, toKeepalivedInput, buildHaFacts } from "@/lib/ha/service";
import { renderKeepalivedConf, haConfHash, haStepGuarded, HA_VALIDATE_TMP } from "@/lib/ha/os";

export const dynamic = "force-dynamic";

export const POST = route({ area: "ha", section: "ha" }, async ({ auth }) => {
  const config = await getHaConfig(auth.tenantId);
  const hostMode = getDataPlaneMode() === "host";
  const facts = await buildHaFacts(auth.tenantId);
  const confText = renderKeepalivedConf(toKeepalivedInput(config), {
    routerId: osMod.hostname().toUpperCase().slice(0, 24) || "UTM-CONSOLE",
    localIfaceIp: facts.localIfaceIp,
  });

  if (!hostMode || !(await hasTool("keepalived"))) {
    return {
      data: {
        available: false,
        ok: null,
        confText,
        confHash: haConfHash(confText),
        detail: "keepalived binary not available on this host — validation unavailable (config rendered for preview)",
      },
    };
  }

  await writeFile(HA_VALIDATE_TMP, confText, "utf8");
  const cmd = `keepalived -t -f ${HA_VALIDATE_TMP}`;
  if (!haStepGuarded(cmd)) {
    await rm(HA_VALIDATE_TMP, { force: true }).catch(() => {});
    return {
      data: { available: true, ok: false, confText, confHash: haConfHash(confText), detail: "validation command failed the whitelist" },
    };
  }
  const r = await runTool(cmd, 15000);
  await rm(HA_VALIDATE_TMP, { force: true }).catch(() => {});
  const output = `${r.stderr}${r.stdout}`.trim();
  return {
    data: {
      available: true,
      ok: r.ok,
      confText,
      confHash: haConfHash(confText),
      detail: r.ok ? output || "keepalived -t passed (rc=0)" : output || "keepalived -t failed",
    },
  };
});
