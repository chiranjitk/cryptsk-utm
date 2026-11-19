/**
 * POST /api/v1/ha/validate — render the console HA config into keepalived.conf
 * and run `keepalived -t` on a TEMP file. Nothing on the appliance is
 * modified: no /etc write, no service restart. Sandbox (no keepalived
 * binary) returns honest { available:false } instead of a fake pass.
 *
 * The validate conf carries the VRRP auth_pass in plaintext — it is staged
 * under the console HA state dir (${HA_STATE_DIR}/validate-<ts>.conf, 0600)
 * and deleted in a finally block, never /tmp.
 */

import osMod from "os";
import { mkdir, writeFile, rm, chmod } from "fs/promises";
import { route } from "@/lib/api/handler";
import { runTool, hasTool } from "@/lib/host/tools";
import { getDataPlaneMode } from "@/lib/engine";
import { getHaConfigRow, toKeepalivedInput, buildHaFacts } from "@/lib/ha/service";
import {
  renderKeepalivedConf,
  redactHaConfSecrets,
  haConfHash,
  haStepGuarded,
  interpretKeepalivedTest,
  haValidateConfPath,
  HA_VALIDATE_DIR,
} from "@/lib/ha/os";

export const dynamic = "force-dynamic";

export const POST = route({ area: "ha", section: "ha" }, async ({ auth }) => {
  const row = await getHaConfigRow(auth.tenantId);
  const hostMode = getDataPlaneMode() === "host";
  const facts = await buildHaFacts(auth.tenantId);
  const fullConf = renderKeepalivedConf(toKeepalivedInput(row), {
    routerId: osMod.hostname().toUpperCase().slice(0, 24) || "UTM-CONSOLE",
    localIfaceIp: facts.localIfaceIp,
  });
  // audit fix M11 — the RESPONSE carries the redacted copy; the staged file
  // (written below) keeps the real auth_pass so `keepalived -t` validates
  // the true config. confHash is computed over the REDACTED text so callers
  // can compare it against the apply endpoint's hash of the same shape.
  const confText = redactHaConfSecrets(fullConf);

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

  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const validateFile = haValidateConfPath(ts);
  let r: Awaited<ReturnType<typeof runTool>> | null = null;
  try {
    await mkdir(HA_VALIDATE_DIR, { recursive: true });
    await writeFile(validateFile, fullConf, "utf8");
    // the staged conf embeds auth_pass — keep it owner-only
    await chmod(validateFile, 0o600).catch(() => {});
    const cmd = `keepalived -t -f ${validateFile}`;
    if (!haStepGuarded(cmd)) {
      return {
        data: { available: true, ok: false, confText, confHash: haConfHash(confText), detail: "validation command failed the whitelist" },
      };
    }
    r = await runTool(cmd, 15000);
  } finally {
    await rm(validateFile, { force: true }).catch(() => {});
  }

  const verdict = interpretKeepalivedTest(`${r!.stderr}${r!.stdout}`, r!.ok);
  return {
    data: {
      available: true,
      ok: verdict.ok,
      confText,
      confHash: haConfHash(confText),
      detail: verdict.detail,
    },
  };
});
