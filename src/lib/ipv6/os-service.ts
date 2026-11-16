/**
 * IPv6 OS service (IMPL-6) — the db/exec glue for lib/ipv6/os.ts (pure):
 *
 *   collectIpv6Inputs     DB → pure input slices (settings + DHCPv6 + NAT66)
 *   readIpv6OsFacts       REAL host reads (binaries, units, conf files, nft
 *                         dump, sysctl forwarding, UDP :547 probe)
 *   buildIpv6Plan         facts + inputs → guarded plan (exec | plan mode)
 *   execIpv6ApplyPlan     snapshot → stage → guarded steps → verify →
 *                         state.json LAST; failure restores backups + service
 *                         pre-states
 *   getIpv6OsStatus       GUI↔OS honesty view (availability, drift, previews)
 *   applyIpv6Os           full converge pass (never throws)
 *
 * Gate: CONSOLE_OS_APPLY=1 AND data-plane host mode — off → plan preview only.
 */

import fs from "fs/promises";
import path from "path";
import { db } from "@/lib/db";
import { parseJson } from "@/lib/json";
import { hasTool, runTool, readServiceStates, readNftRuleset } from "@/lib/host/tools";
import { getDataPlaneMode } from "@/lib/engine";
import {
  buildIpv6ApplyPlan,
  computeIpv6Drift,
  fnv1aHash,
  ipv6StepGuarded,
  liveKea6ManagedIds,
  nat66BlocksInSync,
  parseKea6Conf,
  renderKea6Conf,
  renderNat66Nft,
  renderRadvdConf,
  KEA6_CONF_FILE,
  KEA6_SERVICE,
  IPV6_STATE_DIR,
  NAT66_ETC_DIR,
  NAT66_ETC_FILE,
  NAT66_INCLUDE_LINE,
  NFT_ETC_CONF,
  FORWARDING_SYSCTL_FILE,
  RADVD_CONF_FILE,
  RADVD_SERVICE,
  type Dhcpv6ServerInput,
  type Ipv6DriftEntry,
  type Ipv6OsFile,
  type Ipv6OsFacts,
  type Ipv6OsInput,
  type Ipv6OsPlan,
  type Nat66RuleInput,
} from "./os";

// ── state file ──────────────────────────────────────────────────────────────

export interface Ipv6StateFile {
  /** kea-dhcp6.conf rendered hash of the last successful apply */
  confHash?: string;
  radvdHash?: string;
  nat66Hash?: string;
  sysctlForwarding?: boolean;
  appliedAt?: string;
  lastApply?: { at: string; backupDir: string | null; applied: boolean; reason: string };
  steps?: number;
  results?: Array<{ step: string; cmd: string; ok: boolean; detail?: string }>;
}

async function readIpv6State(): Promise<Ipv6StateFile> {
  try {
    return parseJson<Ipv6StateFile>(await fs.readFile(path.join(IPV6_STATE_DIR, "state.json"), "utf8"), {});
  } catch {
    return {};
  }
}

async function persistState(patch: Ipv6StateFile): Promise<void> {
  // ALWAYS the last write of an apply (task contract) — after files, steps,
  // rollback and persistence attempts.
  try {
    await fs.mkdir(IPV6_STATE_DIR, { recursive: true });
    const file = path.join(IPV6_STATE_DIR, "state.json");
    const cur = await readIpv6State();
    await fs.writeFile(file, JSON.stringify({ ...cur, ...patch }, null, 2), "utf8");
  } catch {
    /* best-effort */
  }
}

// ── DB collectors ───────────────────────────────────────────────────────────

export async function collectIpv6Inputs(tenantId: number): Promise<Ipv6OsInput> {
  const [settingsRow, serverRows, natRows] = await Promise.all([
    db.ipv6Settings.findFirst({ where: { tenantId } }),
    db.dhcpv6Server.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
    db.nat66Rule.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
  ]);

  const settings = {
    enabled: settingsRow?.enabled ?? true,
    dhcpv6Enabled: settingsRow?.dhcpv6Enabled ?? true,
    slaacEnabled: settingsRow?.slaacEnabled ?? true,
    rdnssEnabled: settingsRow?.rdnssEnabled ?? true,
    pdWanInterface: settingsRow?.pdWanInterface ?? "wan0",
    pdPrefixLength: settingsRow?.pdPrefixLength ?? 56,
    raMode: (settingsRow?.raMode ?? "slaac_dhcpv6") as Ipv6OsInput["settings"]["raMode"],
  };

  const servers: Dhcpv6ServerInput[] = serverRows.map((s) => ({
    id: s.id,
    interfaceName: s.interfaceName,
    poolStart: s.poolStart,
    poolEnd: s.poolEnd,
    prefixLength: s.prefixLength,
    preferredLifetimeSec: s.preferredLifetime,
    validLifetimeSec: s.validLifetime,
    dnsServers: parseJson<string[]>(s.dnsServers, []),
    domainSearch: s.domainSearch,
    enabled: s.enabled,
  }));

  const nat66: Nat66RuleInput[] = natRows.map((r) => ({
    id: r.id,
    name: r.name,
    type: r.type as Nat66RuleInput["type"],
    sourcePrefix: r.sourcePrefix,
    translatedPrefix: r.translatedPrefix,
    destPort: r.destPort,
    interfaceName: r.interfaceName,
    enabled: r.enabled,
  }));

  return { settings, servers, nat66 };
}

// ── OS facts (real reads — honest in the sandbox: all unavailable) ──────────

function isRunning(state: string | undefined | null): boolean {
  return state === "running" || state === "active";
}

function parseVersion(out: string): string | null {
  const m = /(\d+\.\d+(?:\.\d+)?)/.exec(out);
  return m ? m[1] : null;
}

async function readText(file: string): Promise<{ present: boolean; text: string | null }> {
  try {
    const text = await fs.readFile(file, "utf8");
    return { present: true, text };
  } catch {
    return { present: false, text: null };
  }
}

export async function readIpv6OsFacts(): Promise<Ipv6OsFacts> {
  const [keaBin, radvdBin, nftBin, svcStates, ssOut] = await Promise.all([
    hasTool("kea-dhcp6"),
    hasTool("radvd"),
    hasTool("nft"),
    readServiceStates([KEA6_SERVICE, RADVD_SERVICE]),
    runTool("ss -lun 2>/dev/null", 5000),
  ]);

  const [keaVer, radvdVer, sysctlRes, keaConf, radvdConf, nat66Etc, nftDump] = await Promise.all([
    keaBin ? runTool("kea-dhcp6 -v 2>/dev/null", 6000) : Promise.resolve({ ok: false, stdout: "", stderr: "", error: undefined }),
    radvdBin ? runTool("radvd --version 2>&1", 6000) : Promise.resolve({ ok: false, stdout: "", stderr: "", error: undefined }),
    runTool("sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null", 3000),
    readText(KEA6_CONF_FILE),
    readText(RADVD_CONF_FILE),
    readText(NAT66_ETC_FILE),
    nftBin ? readNftRuleset() : Promise.resolve({ available: false, ruleset: "", permissionDenied: false }),
  ]);

  // kea-dhcp6 binds via raw sockets by default — :547 may never appear in ss.
  // Informational only (same honesty note as dhcp4 port67Bound).
  const udp547Bound = ssOut.ok ? /:547\s/.test(ssOut.stdout) || (/kea/.test(ssOut.stdout) && /:547\s/.test(ssOut.stdout)) : null;

  return {
    keaAvailable: keaBin,
    radvdAvailable: radvdBin,
    nftAvailable: nftBin,
    keaVersion: keaVer.ok ? parseVersion(keaVer.stdout) : null,
    radvdVersion: radvdVer.ok ? parseVersion(radvdVer.stdout) : null,
    keaRunning: isRunning(svcStates?.[KEA6_SERVICE]),
    radvdRunning: isRunning(svcStates?.[RADVD_SERVICE]),
    keaConfPresent: keaConf.present,
    keaConfText: keaConf.text,
    radvdConfPresent: radvdConf.present,
    radvdConfText: radvdConf.text,
    nat66EtcPresent: nat66Etc.present,
    liveRuleset: nftDump.available && nftDump.ruleset.trim() ? nftDump.ruleset : null,
    rulesetAvailable: nftDump.available,
    sysctlForwarding: sysctlRes.ok ? sysctlRes.stdout.trim() === "1" : null,
    udp547Bound,
  };
}

// ── gate ────────────────────────────────────────────────────────────────────

export function isIpv6GateOn(): boolean {
  return process.env.CONSOLE_OS_APPLY === "1" && getDataPlaneMode() === "host";
}

// ── plan (service wrapper) ──────────────────────────────────────────────────

export async function buildIpv6Plan(tenantId: number, mode: "exec" | "plan", ts: string): Promise<Ipv6OsPlan> {
  const [input, facts] = await Promise.all([collectIpv6Inputs(tenantId), readIpv6OsFacts()]);
  return buildIpv6ApplyPlan(input, facts, mode, ts);
}

// ── executor ────────────────────────────────────────────────────────────────

export interface Ipv6ApplyResultStep {
  step: string;
  cmd: string;
  ok: boolean;
  detail?: string;
}

/** Stage path per file kind (staging happens via fs; installs run guarded). */
function stagePathFor(plan: Ipv6OsPlan, kind: Ipv6OsFile["kind"]): string {
  switch (kind) {
    case "kea6":
      return plan.keaStageFile;
    case "radvd":
      return plan.radvdStageFile;
    case "nat66":
      return plan.nat66File;
  }
}

/** fs snapshot of every plan file that currently exists (restore source). */
async function backupPlanFiles(plan: Ipv6OsPlan): Promise<string | null> {
  try {
    let backedUp = 0;
    for (const f of plan.files) {
      try {
        const cur = await fs.readFile(f.path, "utf8");
        await fs.mkdir(path.dirname(path.join(plan.backupDir, f.path)), { recursive: true });
        await fs.writeFile(path.join(plan.backupDir, f.path), cur, "utf8");
        backedUp += 1;
      } catch {
        /* file not on disk yet */
      }
    }
    // faithful kernel snapshot with a flush prologue (firewall pattern) —
    // restores f2b/console-firewall tables too if a rollback ever needs it
    if (plan.nat66Changed) {
      const dump = await runTool("nft list ruleset", 6000);
      if (dump.ok) {
        await fs.mkdir(plan.backupDir, { recursive: true });
        const body = dump.stdout.trim().length > 0 ? dump.stdout : "# empty ruleset at backup time";
        await fs.writeFile(path.join(plan.backupDir, "ruleset.nft"), `#!/usr/sbin/nft -f\nflush ruleset\n\n${body}\n`, "utf8");
      }
    }
    await fs.mkdir(IPV6_STATE_DIR, { recursive: true });
    if (backedUp === 0) await fs.mkdir(plan.backupDir, { recursive: true });
    return plan.backupDir;
  } catch {
    return null;
  }
}

async function restoreBackupDir(dir: string | null, files: Ipv6OsFile[]): Promise<void> {
  if (!dir) return;
  for (const f of files) {
    try {
      const prev = await fs.readFile(path.join(dir, f.path), "utf8");
      await fs.mkdir(path.dirname(f.path), { recursive: true });
      await fs.writeFile(f.path, prev, "utf8");
    } catch {
      await fs.unlink(f.path).catch(() => {});
    }
  }
}

/** nat66 persistence: /etc/console-nft/nat66.nft + include line (best-effort). */
async function persistNat66(content: string, results: Ipv6ApplyResultStep[]): Promise<void> {
  try {
    await fs.mkdir(NAT66_ETC_DIR, { recursive: true });
    await fs.writeFile(NAT66_ETC_FILE, content, "utf8");
    results.push({ step: `write ${NAT66_ETC_FILE}`, cmd: "fs-write", ok: true });
    const conf = await fs.readFile(NFT_ETC_CONF, "utf8").catch(() => null);
    if (conf !== null && !conf.includes(NAT66_INCLUDE_LINE)) {
      await fs.writeFile(`${NFT_ETC_CONF}.console-backup`, conf, "utf8").catch(() => {});
      await fs.writeFile(NFT_ETC_CONF, `${conf.replace(/\s*$/, "")}\n\n# console-managed IPv6 NAT66 (GUI: Network → IPv6 → Apply to OS)\n${NAT66_INCLUDE_LINE}\n`, "utf8");
      results.push({ step: `include added to ${NFT_ETC_CONF}`, cmd: "fs-write", ok: true });
    } else if (conf === null) {
      results.push({ step: `${NFT_ETC_CONF} absent — nat66 persistence skipped`, cmd: "fs-write", ok: false, detail: `no ${NFT_ETC_CONF} on this host` });
    }
  } catch (err) {
    results.push({ step: "nat66 persistence", cmd: "fs-write", ok: false, detail: err instanceof Error ? err.message : "unknown" });
  }
}

/** forwarding persistence (best-effort, firewall ip_forward pattern). */
async function persistForwarding(results: Ipv6ApplyResultStep[]): Promise<void> {
  try {
    await fs.writeFile(FORWARDING_SYSCTL_FILE, "# console-managed: required for IPv6 RA/DHCPv6 serving + NAT66\nnet.ipv6.conf.all.forwarding=1\n", "utf8");
    results.push({ step: `write ${FORWARDING_SYSCTL_FILE}`, cmd: "fs-write", ok: true });
  } catch (err) {
    results.push({ step: "forwarding persistence", cmd: "fs-write", ok: false, detail: err instanceof Error ? err.message : "unknown" });
  }
}

/** Restore services to their pre-apply states (rollback contract). */
async function restoreServiceStates(plan: Ipv6OsPlan, results: Ipv6ApplyResultStep[]): Promise<void> {
  if (plan.keaChanged) {
    const cmd = plan.preState.keaRunning ? `systemctl restart ${KEA6_SERVICE}` : `systemctl stop ${KEA6_SERVICE}`;
    const r = await runTool(cmd, 15000);
    results.push({ step: `restore ${KEA6_SERVICE} pre-apply state`, cmd, ok: r.ok, detail: r.ok ? undefined : r.stderr || r.error });
  }
  if (plan.radvdChanged) {
    const cmd = plan.preState.radvdRunning ? `systemctl restart ${RADVD_SERVICE}` : `systemctl stop ${RADVD_SERVICE}`;
    const r = await runTool(cmd, 15000);
    results.push({ step: `restore ${RADVD_SERVICE} pre-apply state`, cmd, ok: r.ok, detail: r.ok ? undefined : r.stderr || r.error });
  }
}

export interface Ipv6ApplyOutcome {
  gate: "on" | "off";
  applied: boolean;
  refused?: string;
  reason: string;
  rolledBack: boolean;
  backupDir?: string;
  confHash?: string;
  radvdHash?: string;
  nat66Hash?: string;
  plan: {
    steps: Array<{ step: string; cmd: string; kind: string; optional?: boolean }>;
    files: Array<{ path: string; kind: string; bytes: number }>;
    keaSubnets: Ipv6OsPlan["keaSubnets"];
    radvdIfaces: Ipv6OsPlan["radvdIfaces"];
    nat66Statements: Ipv6OsPlan["nat66Statements"];
    skipped: Ipv6OsPlan["skipped"];
    warnings: string[];
    refused: string | null;
  };
  results: Ipv6ApplyResultStep[];
}

export async function execIpv6ApplyPlan(plan: Ipv6OsPlan): Promise<Ipv6ApplyOutcome> {
  const outcomeBase = {
    plan: {
      steps: plan.steps.map((s) => ({ step: s.step, cmd: s.cmd, kind: s.kind, optional: s.optional })),
      files: plan.files.map((f) => ({ path: f.path, kind: f.kind, bytes: Buffer.byteLength(f.content) })),
      keaSubnets: plan.keaSubnets,
      radvdIfaces: plan.radvdIfaces,
      nat66Statements: plan.nat66Statements,
      skipped: plan.skipped,
      warnings: plan.warnings,
      refused: plan.refused,
    },
  };

  if (!isIpv6GateOn()) {
    return {
      gate: "off",
      applied: false,
      reason: "OS enforcement disabled (CONSOLE_OS_APPLY off or non-host data plane) — plan is a preview only; rendered files attached",
      rolledBack: false,
      ...outcomeBase,
      results: [],
    };
  }
  if (plan.refused) {
    return { gate: "on", applied: false, refused: plan.refused, reason: plan.refused, rolledBack: false, ...outcomeBase, results: [] };
  }
  if (plan.empty) {
    return {
      gate: "on",
      applied: false,
      reason: "in sync — rendered confs, kernel table and services already match the GUI (zero-churn, nothing touched)",
      rolledBack: false,
      ...outcomeBase,
      results: [],
    };
  }

  // tool availability — honest refusals (never pretend to apply)
  if (plan.keaChanged && !(await hasTool("kea-dhcp6"))) {
    return { gate: "on", applied: false, reason: "'kea-dhcp6' binary not found on the host — cannot validate or restart kea-dhcp6-server", rolledBack: false, ...outcomeBase, results: [] };
  }
  if (plan.radvdChanged && plan.radvdServiceWanted === "active" && !(await hasTool("radvd"))) {
    return { gate: "on", applied: false, reason: "'radvd' binary not found on the host — cannot validate or restart radvd", rolledBack: false, ...outcomeBase, results: [] };
  }
  if (plan.nat66Changed && !(await hasTool("nft"))) {
    return { gate: "on", applied: false, reason: "'nft' binary not found on the host — cannot validate or apply utm_nat66", rolledBack: false, ...outcomeBase, results: [] };
  }
  // guard re-check (defense in depth — the plan is re-verified at exec time)
  const unguarded = plan.steps.find((s) => s.kind !== "write" && !ipv6StepGuarded(s.cmd));
  if (unguarded) {
    return {
      gate: "on",
      applied: false,
      reason: `refused: step failed the IPv6 guard — "${unguarded.cmd}" (kea-dhcp6 -t, radvd -c, nft -c/-f, managed units, state dir only)`,
      rolledBack: false,
      ...outcomeBase,
      results: [],
    };
  }

  const results: Ipv6ApplyResultStep[] = [];
  const backupDir = await backupPlanFiles(plan);

  // stage every managed file via fs (no shell writes) — validates run on the
  // STAGED files before the live confs are touched
  let staged = false;
  try {
    for (const f of plan.files) {
      const stage = stagePathFor(plan, f.kind);
      await fs.mkdir(path.dirname(stage), { recursive: true });
      await fs.writeFile(stage, f.content, "utf8");
      // the install steps copy staged → live; make sure the live parent dirs
      // exist (no shell mkdir needed — fs here, install only installs)
      await fs.mkdir(path.dirname(f.path), { recursive: true });
      // kea runs as user `_kea` on Debian — the INSTALLED conf must be
      // world-readable (0640 made the daemon fail; same fix as kea-dhcp4).
      await fs.chmod(stage, 0o644);
      results.push({ step: `stage ${path.basename(stage)}`, cmd: `fs-write ${stage}`, ok: true, detail: `${Buffer.byteLength(f.content)} bytes` });
    }
    staged = true;
  } catch (err) {
    const detail = err instanceof Error ? err.message : "write failed";
    if (backupDir) await restoreBackupDir(backupDir, plan.files);
    return {
      gate: "on",
      applied: false,
      reason: `file staging failed: ${detail} — backups restored`,
      rolledBack: true,
      ...(backupDir ? { backupDir } : {}),
      ...outcomeBase,
      results,
    };
  }

  // run the guarded steps
  let nat66Applied = false;
  let failed = false;
  let failDetail = "";
  for (const step of plan.steps) {
    if (step.kind === "write") continue; // staged via fs above
    const r = await runTool(step.cmd, step.kind === "validate" ? 20000 : step.kind === "restart" ? 20000 : 12000);

    // a "stop"-driven is-active probe EXPECTS "inactive" (rc≠0, stdout says it)
    if (step.optional && step.kind === "probe" && !r.ok && /^inactive\s*$/m.test(r.stdout)) {
      results.push({ step: step.step, cmd: step.cmd, ok: true, detail: "inactive (expected)" });
      continue;
    }
    // informational listener probes never fail the apply
    if (step.kind === "probe" && (step.cmd === "ss -ltn" || step.cmd === "ss -lun")) {
      results.push({ step: step.step, cmd: step.cmd, ok: true, detail: r.stdout.trim().slice(0, 200) || "(no listeners)" });
      continue;
    }

    if (!r.ok && !step.optional) {
      failed = true;
      failDetail = `step '${step.step}' failed: ${(r.stderr || r.error || "").trim().slice(0, 300) || "exec error"}`;
      results.push({ step: step.step, cmd: step.cmd, ok: false, detail: failDetail });
      break;
    }
    if (step.kind === "install" && step.cmd.startsWith("nft -f")) nat66Applied = true;
    const detail = r.stdout.trim().slice(0, 200);
    results.push({ step: step.step, cmd: step.cmd, ok: true, ...(detail ? { detail } : {}) });
  }

  // ── auto-rollback: restore all backups + service pre-states ──
  let rolledBack = false;
  if (failed) {
    if (nat66Applied && backupDir) {
      const rbFile = path.join(backupDir, "ruleset.nft");
      const rb = await runTool(`nft -f ${rbFile}`, 15000).catch(() => ({ ok: false, stdout: "", stderr: "backup dump missing" }));
      results.push({ step: "restore kernel ruleset", cmd: `nft -f ${rbFile}`, ok: rb.ok, detail: rb.ok ? "pre-apply ruleset restored" : rb.stderr || "restore failed" });
      nat66Applied = false;
    }
    if (backupDir) await restoreBackupDir(backupDir, plan.files);
    await restoreServiceStates(plan, results);
    rolledBack = true;
    results.push({ step: "auto-rollback", cmd: "restore", ok: true, detail: "pre-apply confs + service states restored" });
  }

  // ── persistence (best-effort — failures are warnings, runtime state stands) ──
  if (staged && !failed) {
    if (plan.nat66Changed) {
      const natFile = plan.files.find((f) => f.kind === "nat66");
      if (natFile) await persistNat66(natFile.content, results);
    }
    if (plan.sysctlNeeded) await persistForwarding(results);
    // settle before the state hash snapshot (systemd restart returns at START)
    await new Promise((resolve) => setTimeout(resolve, 1500));
  }

  const applied = staged && !failed;
  const reason = !staged
    ? "staging failed — rolled back"
    : failed
      ? failDetail
      : plan.empty
        ? "in sync — nothing to apply"
        : `IPv6 stack converged (kea6 ${plan.keaChanged ? "updated" : "unchanged"}, radvd ${plan.radvdChanged ? "updated" : "unchanged"}, nat66 ${plan.nat66Changed ? "updated" : "unchanged"}, forwarding ${plan.sysctlNeeded ? "on" : "n/a"})`;

  // state.json LAST — success carries the applied hashes; failure carries the
  // honest lastApply record only (never a confHash we did not install)
  await persistState(
    applied
      ? {
          confHash: plan.confHash,
          radvdHash: plan.radvdHash,
          nat66Hash: plan.nat66Hash,
          sysctlForwarding: plan.sysctlNeeded ? true : undefined,
          appliedAt: new Date().toISOString(),
          lastApply: { at: new Date().toISOString(), backupDir, applied, reason },
          steps: results.length,
          results,
        }
      : {
          lastApply: { at: new Date().toISOString(), backupDir, applied: false, reason },
          steps: results.length,
          results,
        },
  );

  return {
    gate: "on",
    applied,
    reason,
    rolledBack,
    ...(backupDir ? { backupDir } : {}),
    ...(applied ? { confHash: plan.confHash, radvdHash: plan.radvdHash, nat66Hash: plan.nat66Hash } : {}),
    ...outcomeBase,
    results,
  };
}

/** Full converge pass (inputs → facts → plan → exec). Never throws. */
export async function applyIpv6Os(tenantId: number): Promise<Ipv6ApplyOutcome> {
  try {
    const gateOn = isIpv6GateOn();
    const ts = new Date().toISOString().replace(/[:.]/g, "-");
    const plan = await buildIpv6Plan(tenantId, gateOn ? "exec" : "plan", ts);
    return await execIpv6ApplyPlan(plan);
  } catch (err) {
    return {
      gate: isIpv6GateOn() ? "on" : "off",
      applied: false,
      reason: `convergence error: ${err instanceof Error ? err.message : "unknown"}`,
      rolledBack: false,
      plan: { steps: [], files: [], keaSubnets: [], radvdIfaces: [], nat66Statements: [], skipped: [], warnings: [], refused: null },
      results: [],
    };
  }
}

// ── status assembly (GET /ipv6/os-status) ───────────────────────────────────

export interface Ipv6OsStatus {
  gate: "on" | "off";
  available: boolean;
  keaAvailable: boolean;
  radvdAvailable: boolean;
  nftAvailable: boolean;
  dataPlaneMode: string;
  kea: {
    running: boolean;
    confPresent: boolean;
    confHash: string | null;
    version: string | null;
    renderedHash: string;
    inSync: boolean | null;
    managedSubnetIds: number[];
  };
  radvd: {
    running: boolean;
    confPresent: boolean;
    confHash: string | null;
    version: string | null;
    renderedHash: string;
    inSync: boolean | null;
    ifaces: Array<{ iface: string; prefix: string; mode: string }>;
  };
  nat66: {
    tablePresent: boolean;
    inSync: boolean | null;
    statements: number;
    etcPresent: boolean;
  };
  sysctlForwarding: boolean | null;
  sysctlExpected: boolean;
  udp547Bound: boolean | null;
  lastApply: Ipv6StateFile | null;
  drift: Ipv6DriftEntry[];
  summary: { total: number; inSync: number; driftCount: number; unsupported: number };
  preview: { keaConf: string; radvdConf: string; nat66Nft: string };
  warnings: string[];
}

export async function getIpv6OsStatus(tenantId: number): Promise<Ipv6OsStatus> {
  const [input, facts, state] = await Promise.all([collectIpv6Inputs(tenantId), readIpv6OsFacts(), readIpv6State()]);
  const kea = renderKea6Conf(input);
  const radvd = renderRadvdConf(input);
  const nat66 = renderNat66Nft(input.nat66);

  const drift = computeIpv6Drift(input, facts, {
    kea: { text: kea.text, subnets: kea.subnets, enabledServers: kea.enabledServers },
    radvd: { text: radvd.text, ifaces: radvd.ifaces },
    nat66: { text: nat66.text, statements: nat66.statements },
  });

  const keaLiveHash = facts.keaConfText ? fnv1aHash(facts.keaConfText) : null;
  const radvdLiveHash = facts.radvdConfText ? fnv1aHash(facts.radvdConfText) : null;
  const tablePresent = facts.liveRuleset !== null && /table inet utm_nat66\b/.test(facts.liveRuleset);

  const warnings = [...radvd.warnings, ...nat66.warnings];
  if (input.settings.enabled && input.settings.dhcpv6Enabled && input.servers.some((s) => s.enabled) && !facts.keaAvailable) {
    warnings.push("kea-dhcp6 binary not found on this host — DHCPv6 serving cannot be enforced here");
  }
  if (input.settings.enabled && input.settings.raMode !== "disabled" && input.servers.some((s) => s.enabled) && !facts.radvdAvailable) {
    warnings.push("radvd binary not found on this host — router advertisements cannot be enforced here");
  }

  return {
    gate: isIpv6GateOn() ? "on" : "off",
    available: facts.keaAvailable,
    keaAvailable: facts.keaAvailable,
    radvdAvailable: facts.radvdAvailable,
    nftAvailable: facts.nftAvailable,
    dataPlaneMode: getDataPlaneMode(),
    kea: {
      running: facts.keaRunning,
      confPresent: facts.keaConfPresent,
      confHash: keaLiveHash,
      version: facts.keaVersion,
      renderedHash: fnv1aHash(kea.text),
      inSync: facts.keaConfPresent ? keaLiveHash === fnv1aHash(kea.text) : false,
      managedSubnetIds: facts.keaConfText
        ? (() => {
            try {
              return liveKea6ManagedIds(parseKea6Conf(facts.keaConfText));
            } catch {
              return [];
            }
          })()
        : [],
    },
    radvd: {
      running: facts.radvdRunning,
      confPresent: facts.radvdConfPresent,
      confHash: radvdLiveHash,
      version: facts.radvdVersion,
      renderedHash: fnv1aHash(radvd.text),
      inSync: facts.radvdConfPresent ? radvdLiveHash === fnv1aHash(radvd.text) : false,
      ifaces: radvd.ifaces,
    },
    nat66: {
      tablePresent,
      inSync: facts.liveRuleset !== null ? nat66BlocksInSyncSafe(nat66.text, facts.liveRuleset) : false,
      statements: nat66.statements.length,
      etcPresent: facts.nat66EtcPresent,
    },
    sysctlForwarding: facts.sysctlForwarding,
    sysctlExpected: input.settings.enabled && (input.settings.dhcpv6Enabled || input.settings.raMode !== "disabled"),
    udp547Bound: facts.udp547Bound,
    lastApply: state.lastApply ? state : null,
    drift,
    summary: {
      total: drift.length,
      inSync: drift.filter((d) => d.osState === "in-sync" || d.osState === "disabled").length,
      driftCount: drift.filter((d) => d.osState === "drift" || d.osState === "missing").length,
      unsupported: drift.filter((d) => d.osState === "unsupported").length,
    },
    preview: { keaConf: kea.text, radvdConf: radvd.text, nat66Nft: nat66.text },
    warnings,
  };
}

function nat66BlocksInSyncSafe(genFile: string, liveDump: string): boolean {
  try {
    return nat66BlocksInSync(genFile, liveDump);
  } catch {
    return false;
  }
}
