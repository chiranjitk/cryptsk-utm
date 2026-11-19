/**
 * firewall-os — real nftables convergence for the GUI firewall.
 *
 * THE missing leg (2026-11-15): GUI rules previously terminated at the DB;
 * this module plans (nft-gen), verifies (`nft -c`), applies (`nft -f`) and
 * ROLLS BACK (commit-confirm) the dedicated `inet console-firewall` table.
 *
 * Safety architecture:
 *   • gate          CONSOLE_OS_APPLY=1 required (off → plan preview only)
 *   • pre-check     `nft -c -f` syntax/commit check BEFORE any mutation
 *   • backup        the live console-firewall table dumped to
 *                   <dir>/backup-<ts>.nft as a TABLE-SCOPED restore point
 *                   (audit fix M3 — declares the table if missing, flushes
 *                   ONLY it, merges the pre-apply dump back; other modules'
 *                   tables and fail2ban are never touched by a rollback)
 *   • commit-confirm a detached rollback timer (nohup sh) restores the
 *                   backup after CONSOLE_NFT_CONFIRM_SEC unless the confirm
 *                   flag file appears. The apply route additionally probes
 *                   WAN health (probeWanHealth) and restores immediately on
 *                   a measured regression — management-plane outages cannot
 *                   survive either mechanism.
 *   • isolation     only `inet console-firewall` is touched (atomic destroy +
 *                   recreate; no `flush ruleset` in generated files)
 *   • tenancy       SINGLE-TABLE SINGLE-TENANT APPLIANCE CONTRACT: there is
 *                   exactly one `console-firewall` table enforcing ONE
 *                   tenant's policy at a time (no per-tenant tables). The
 *                   ApplyState in state.json stamps the owning tenantId and
 *                   confirm/rollback refuse callers from a different tenant.
 *   • hit counters  kernel rule counters reset when the table is recreated on
 *                   every apply — syncHitsFromKernel accumulates DELTAS
 *                   against per-rule watermarks (state.json lastHitSync) and
 *                   the pre-apply counters are banked before the recreate, so
 *                   hit history survives every apply.
 *   • persistence   /etc/console-nft/ruleset.nft + an `include` line appended
 *                   to /etc/nftables.conf (+ best-effort `systemctl enable
 *                   nftables`) so policy survives reboots. Every persistence
 *                   write is backed up first and failures are warnings — the
 *                   runtime apply is never reverted because of them.
 *   • red lines     ens32/WAN interface configuration is never touched; the
 *                   input chain baseline (loopback/established/ICMP/SSH
 *                   22+22222/DHCP/VRRP/conntrackd) is unconditional.
 */

import fs from "fs/promises";
import path from "path";
import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { hasTool, runTool, applyNftFile, readNftRuleset } from "@/lib/host/tools";
import { composeTableScopedBackup } from "@/lib/host/nft-restore";
import { probeWanHealth, pbrHealthRegressed, type PbrWanHealth } from "@/lib/network/pbr-os";
import { loadExpansionContext, safeStrArr } from "./rule-loader";
import { isFqdnStale } from "./fqdn-resolver";
import { getGeoResolver } from "@/lib/geoip/service";
import { parseIds } from "./refs";
import {
  generateNftRuleset,
  NFT_TABLE_NAME,
  type NftGenInput,
  type NftGenNatRule,
  type NftGenResult,
  type NftGenRule,
  type NftGenWarning,
  type NftGenCounts,
} from "./nft-gen";

export const NFT_TABLE = `inet ${NFT_TABLE_NAME}`;
export const NFT_DIR = process.env.CONSOLE_NFT_DIR || "/var/lib/console/nft";
export const NFT_ETC_DIR = "/etc/console-nft";
export const NFT_ETC_CONF = "/etc/nftables.conf";
export const NFT_INCLUDE_LINE = `include "${NFT_ETC_DIR}/ruleset.nft"`;
const CONFIRM_SEC = Math.max(15, Number(process.env.CONSOLE_NFT_CONFIRM_SEC || 60));

// ── DB → generator input ────────────────────────────────────────────────────

export async function loadFirewallGenInput(tenantId: number): Promise<NftGenInput> {
  const [ruleRows, natRows, zoneRows, ctx] = await Promise.all([
    db.firewallRule.findMany({ where: { tenantId }, orderBy: { position: "asc" } }),
    db.natRule.findMany({ where: { tenantId }, orderBy: { position: "asc" } }),
    db.zone.findMany({ where: { tenantId } }),
    loadExpansionContext(tenantId),
  ]);

  const parsePool = (raw: string): string[] => {
    try {
      const v = JSON.parse(raw);
      return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
    } catch {
      return [];
    }
  };

  /**
   * SECURITY GUARD (defense-in-depth behind the API-level empty-group block):
   * a rule whose referenced ids ALL fail to expand (empty group, dangling
   * member) would compile clause-less — a match-any nft statement, i.e. an
   * accidental allow-all. Such rules are excluded from the kernel input.
   */
  const brokenRefRules = new Set<number>();
  const brokenRefNats = new Set<number>();
  const broken = (rowIds: number[], expanded: unknown[]): boolean =>
    rowIds.length > 0 && expanded.length === 0;

  const rules: NftGenRule[] = [];
  for (const r of ruleRows) {
    const srcIds = parseIds(r.srcAddrIds);
    const dstIds = parseIds(r.dstAddrIds);
    const svcIds = parseIds(r.serviceIds);
    const srcAddrs = ctx.expandAddr(srcIds);
    const dstAddrs = ctx.expandAddr(dstIds);
    const services = ctx.expandSvc(svcIds);
    if (broken(srcIds, srcAddrs) || broken(dstIds, dstAddrs) || broken(svcIds, services)) {
      brokenRefRules.add(r.id);
      continue; // excluded — never widen to match-any
    }
    rules.push({
      id: r.id,
      name: r.name,
      position: r.position,
      enabled: r.enabled,
      srcZoneIds: parseIds(r.srcZoneIds),
      dstZoneIds: parseIds(r.dstZoneIds),
      srcAddrs,
      dstAddrs,
      services,
      srcMacs: safeStrArr(r.srcMacs),
      applicationIds: safeStrArr(r.applicationIds),
      userNames: ctx.userNames(parseIds(r.userIds)),
      schedule: ctx.toSchedule(r.scheduleId),
      action: r.action,
      logging: r.logging,
      rateLimit: r.rateLimit,
    });
  }

  const natRules: NftGenNatRule[] = [];
  for (const n of natRows) {
    const srcIds = parseIds(n.srcAddrIds);
    const dstIds = parseIds(n.dstAddrIds);
    const svcIds = parseIds(n.serviceIds);
    const srcAddrs = ctx.expandAddr(srcIds);
    const dstAddrs = ctx.expandAddr(dstIds);
    const services = ctx.expandSvc(svcIds);
    // NAT treats empty matcher arrays as MATCH-ALL sides — a broken ref here
    // widens the NAT itself (worse than a filter rule). Exclude + warn.
    if (broken(srcIds, srcAddrs) || broken(dstIds, dstAddrs) || broken(svcIds, services)) {
      brokenRefNats.add(n.id);
      continue;
    }
    natRules.push({
      id: n.id,
      name: n.name,
      position: n.position,
      enabled: n.enabled,
      type: n.type,
      srcAddrs,
      dstAddrs,
      services,
      outgoingIface: n.outgoingIface,
      translatedSrc: n.translatedSrc,
      translatedSrcPool: parsePool(n.translatedSrcPool),
      translatedDst: n.translatedDst,
      translatedPort: n.translatedPort,
      translatedPortRange: n.translatedPortRange,
      logging: n.logging,
    });
  }
  const zones = zoneRows.map((z) => ({
    id: z.id,
    name: z.name,
    interfaces: safeStrArr(z.interfaceNames),
  }));

  return { rules, natRules, zones, _brokenRefRules: [...brokenRefRules], _brokenRefNats: [...brokenRefNats] } as NftGenInput & {
    _brokenRefRules: number[];
    _brokenRefNats: number[];
  };
}

// ── OS facts ────────────────────────────────────────────────────────────────

export interface OsIface {
  name: string;
  up: boolean;
  addresses: string[];
}

export interface FirewallOsFacts {
  nftAvailable: boolean;
  nftVersion: string | null;
  ipForward: boolean | null;
  interfaces: OsIface[];
  consoleTablePresent: boolean;
  f2bTablePresent: boolean;
}

function parseIpJsonAddr(out: string): OsIface[] {
  try {
    const parsed = JSON.parse(out) as Array<{ ifname?: string; operstate?: string; flags?: string[]; addr_info?: Array<{ family?: string; local?: string }> }>;
    return parsed
      .filter((i) => i.ifname)
      .map((i) => ({
        name: i.ifname!,
        up: i.operstate === "UNKNOWN" ? true : i.operstate === "UP" || (i.flags ?? []).includes("UP"),
        addresses: (i.addr_info ?? [])
          .filter((a) => a.family === "inet" && a.local)
          .map((a) => a.local!),
      }));
  } catch {
    return [];
  }
}

export async function readOsFacts(liveRuleset?: string): Promise<FirewallOsFacts> {
  const nftOk = await hasTool("nft");
  const [versionRes, fwdRes, ipRes] = await Promise.all([
    nftOk ? runTool("nft --version", 3000) : Promise.resolve({ ok: false, stdout: "", stderr: "", error: "no nft" }),
    runTool("sysctl -n net.ipv4.ip_forward 2>/dev/null", 3000),
    runTool("ip -j addr show 2>/dev/null", 5000),
  ]);
  const dump = liveRuleset ?? (await readNftRuleset()).ruleset;
  return {
    nftAvailable: nftOk,
    nftVersion: versionRes.ok ? versionRes.stdout.trim() || null : null,
    ipForward: fwdRes.ok ? fwdRes.stdout.trim() === "1" : null,
    interfaces: ipRes.ok ? parseIpJsonAddr(ipRes.stdout) : [],
    consoleTablePresent: new RegExp(`table inet ${NFT_TABLE_NAME}\\b`).test(dump),
    f2bTablePresent: /table inet f2b-table\b/.test(dump),
  };
}

// ── plan ────────────────────────────────────────────────────────────────────

export interface FirewallPlan {
  gen: NftGenResult;
  facts: FirewallOsFacts;
  drift: {
    /** console table exists in the live kernel */
    applied: boolean;
    /** live table matches the generated policy (normalized compare) */
    inSync: boolean;
  };
  /** generated file — surfaced for the preview dialog */
  file: string;
  ipForwardRequired: boolean;
}

function extractTableBlock(source: string): string[] {
  // lines of the console-firewall table block, comments stripped, whitespace normalized
  const lines: string[] = [];
  let inside = false;
  let depth = 0;
  for (const raw of source.split("\n")) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!inside) {
      if (new RegExp(`^table inet ${NFT_TABLE_NAME}\\s*\\{`).test(line)) {
        inside = true;
        depth = 1;
      }
      continue;
    }
    depth += (line.match(/\{/g) ?? []).length - (line.match(/\}/g) ?? []).length;
    if (depth <= 0) break;
    const norm = line
      .replace(/counter packets \d+ bytes \d+/g, "")
      .replace(/comment "[^"]*"/g, "")
      .replace(/\s+/g, " ")
      .trim();
    if (norm) lines.push(norm);
  }
  return lines;
}

/** Pure compare of generated vs live table bodies (unit-testable). */
export function tableBlocksInSync(genFile: string, liveDump: string): boolean {
  const a = extractTableBlock(genFile);
  const b = extractTableBlock(liveDump);
  if (b.length === 0) return false;
  return a.length === b.length && a.every((l, i) => l === b[i]);
}

export async function buildFirewallPlan(tenantId: number): Promise<FirewallPlan> {
  const [loaded, liveDump, fqdnRows, geoResolver] = await Promise.all([
    loadFirewallGenInput(tenantId),
    readNftRuleset().then((r) => r.ruleset),
    // spec §1.4 — fqdn objects feed the generator's named-set expansion from
    // their stored resolver snapshot (refresh via /objects/fqdn/refresh)
    db.addressObject.findMany({
      where: { tenantId, type: "fqdn" },
      select: { id: true, name: true, value: true, resolvedIps: true, resolvedAt: true },
      orderBy: { name: "asc" },
    }),
    // spec §1.4 — injected GeoIP callback (null when no source is loaded →
    // the generator keeps geo rules config-only with a loud warning)
    getGeoResolver(tenantId),
  ]);
  const { _brokenRefRules = [], _brokenRefNats = [], ...input } = loaded as NftGenInput & {
    _brokenRefRules?: number[];
    _brokenRefNats?: number[];
  };
  const facts = await readOsFacts(liveDump);
  const gen = generateNftRuleset({
    ...input,
    osInterfaces: facts.interfaces.map((i) => i.name),
    fqdnObjects: fqdnRows.map((r) => ({
      hostname: r.value,
      ips: safeStrArr(r.resolvedIps),
      stale: isFqdnStale(r.resolvedAt),
    })),
    ...(geoResolver ? { geoResolver } : {}),
  });
  // surface the excluded broken-ref rules as loud warnings (honesty at apply time)
  for (const id of _brokenRefRules) {
    (gen.warnings as NftGenWarning[]).push({
      scope: "rule",
      id,
      name: `rule #${id}`,
      code: "broken-ref-excluded",
      message: `rule #${id} references object/group ids that resolve to NOTHING — excluded from enforcement (would otherwise match ALL traffic)`,
    });
  }
  for (const id of _brokenRefNats) {
    (gen.warnings as NftGenWarning[]).push({
      scope: "nat",
      id,
      name: `nat #${id}`,
      code: "broken-ref-excluded",
      message: `NAT rule #${id} references object/group ids that resolve to NOTHING — excluded from enforcement (would otherwise NAT ALL traffic)`,
    });
  }
  const applied = facts.consoleTablePresent;
  const inSync = applied ? tableBlocksInSync(gen.file, liveDump) : false;
  const ipForwardRequired = gen.counts.forward > 0 || gen.counts.postrouting > 0 || gen.counts.prerouting > 0;
  if (ipForwardRequired && facts.ipForward === false) {
    (gen.warnings as NftGenWarning[]).push({
      scope: "policy",
      id: null,
      name: "kernel",
      code: "ip-forward-off",
      message: "net.ipv4.ip_forward=0 — forwarded/NAT traffic will not flow until forwarding is enabled (apply dialog offers a one-click enable)",
    });
  }
  return { gen, facts, drift: { applied, inSync }, file: gen.file, ipForwardRequired };
}

// ── commit-confirm apply ────────────────────────────────────────────────────

export interface ApplyResults {
  step: string;
  ok: boolean;
  detail?: string;
}

export interface FirewallApplyOutcome {
  gate: "on" | "off";
  applied: boolean;
  rolledBack: boolean;
  rollbackReason: string | null;
  confirmSec: number;
  confirmDeadlineAt: string | null;
  ts: string;
  warnings: NftGenWarning[];
  counts: NftGenCounts | null;
  forwardPolicy: "accept" | "drop";
  health: {
    baseline: PbrWanHealth | null;
    after: PbrWanHealth | null;
    postRollback: PbrWanHealth | null;
  };
  results: ApplyResults[];
  persistence: ApplyResults[];
}

interface ApplyState {
  ts: string;
  armedAt: string;
  deadlineAt: string;
  mode: "manual" | "auto";
  backupFile: string;
  confirmFile: string;
  /** owning tenant (single-table appliance contract) — stamped at plan time */
  tenantId: number;
}

/**
 * state.json on-disk shape: the commit-confirm window fields (when armed) plus
 * the hit-counter watermarks (`lastHitSync`) which must survive every window
 * open/confirm/rollback/clear.
 */
interface NftStateFile extends Partial<ApplyState> {
  lastHitSync?: Record<string, number>;
}

const STATE_FILE = path.join(NFT_DIR, "state.json");

/** Read state.json: the armed apply window (if any) + hit-counter watermarks. */
async function readRawState(): Promise<{ apply: ApplyState | null; lastHitSync: Record<string, number> }> {
  try {
    const s = JSON.parse(await fs.readFile(STATE_FILE, "utf8")) as NftStateFile;
    const lastHitSync = s.lastHitSync && typeof s.lastHitSync === "object" ? { ...s.lastHitSync } : {};
    const apply: ApplyState | null =
      typeof s.ts === "string" && typeof s.confirmFile === "string"
        ? {
            ts: s.ts,
            armedAt: s.armedAt ?? s.ts,
            deadlineAt: s.deadlineAt ?? s.ts,
            mode: s.mode ?? "manual",
            backupFile: s.backupFile ?? "",
            confirmFile: s.confirmFile,
            // legacy pre-tenancy states carry no stamp (0 = unverifiable → allowed)
            tenantId: typeof s.tenantId === "number" ? s.tenantId : 0,
          }
        : null;
    return { apply, lastHitSync };
  } catch {
    return { apply: null, lastHitSync: {} };
  }
}

async function writeState(state: ApplyState | null): Promise<void> {
  await fs.mkdir(NFT_DIR, { recursive: true });
  // watermarks survive every window open/confirm/rollback/clear
  const { lastHitSync } = await readRawState();
  const payload: NftStateFile = state ? { ...state, lastHitSync } : { lastHitSync };
  await fs.writeFile(STATE_FILE, JSON.stringify(payload, null, 2), "utf8");
}

/** Persist hit-counter watermarks without disturbing the apply window. */
async function writeHitSyncMap(map: Record<string, number>): Promise<void> {
  await fs.mkdir(NFT_DIR, { recursive: true });
  const { apply } = await readRawState();
  const payload: NftStateFile = apply ? { ...apply, lastHitSync: map } : { lastHitSync: map };
  await fs.writeFile(STATE_FILE, JSON.stringify(payload, null, 2), "utf8");
}

/** Remove superseded/stale artefacts: armed scripts >60min, generated rulesets
 *  and confirm flags >24h, backups >7d (restore points). */
async function housekeepArtefacts(): Promise<void> {
  await runTool(
    `find ${JSON.stringify(NFT_DIR)} -name "rollback-*.sh" -mmin +60 -delete 2>/dev/null; ` +
      `find ${JSON.stringify(NFT_DIR)} \( -name "ruleset-*.nft" -o -name "confirm-*" \) -mmin +1440 -delete 2>/dev/null; ` +
      `find ${JSON.stringify(NFT_DIR)} -name "backup-*.nft" -mtime +7 -delete 2>/dev/null`,
    5000,
  );
}

function rollbackScriptPath(ts: string): string {
  return path.join(NFT_DIR, `rollback-${ts}.sh`);
}

export async function readApplyState(): Promise<ApplyState | null> {
  const { apply } = await readRawState();
  if (!apply) return null;
  const confirmed = await fs
    .access(apply.confirmFile)
    .then(() => true)
    .catch(() => false);
  if (confirmed) return null; // commit confirmed → no pending window
  return apply;
}

/**
 * Single-table appliance contract: a pending apply window belongs to ONE
 * tenant — confirm/rollback from another tenant are refused. Legacy states
 * written before the stamp carry tenantId 0 (unverifiable → allowed, so a
 * deploy never bricks an in-flight window).
 */
function assertApplyTenant(callerTenantId: number, stateTenantId: number): void {
  if (stateTenantId !== 0 && stateTenantId !== callerTenantId) {
    throw ApiError.forbidden(
      `pending firewall apply belongs to tenant ${stateTenantId} — confirm/rollback must come from the applying tenant`,
    );
  }
}

function assertOwnPath(p: string, prefix: RegExp): string {
  const resolved = path.resolve(p);
  if (!resolved.startsWith(path.resolve(NFT_DIR)) || resolved.includes("..")) {
    throw new Error(`refusing path outside the console nft directory: ${p}`);
  }
  if (!prefix.test(path.basename(resolved))) {
    throw new Error(`refusing unexpected file name: ${p}`);
  }
  return resolved;
}

/** Engine data-plane mode — the sibling gate from threat-intel/os-service.ts. */
async function dataPlaneMode(): Promise<string> {
  const { getDataPlaneMode } = await import("@/lib/engine");
  return getDataPlaneMode();
}

export interface ApplyOptions {
  mode?: "manual" | "auto";
  enableForwarding?: boolean;
  confirmSec?: number;
}

/**
 * Full apply pipeline. Never throws — every failure surfaces as an honest
 * outcome so the API layer can report it.
 */
export async function applyFirewallNft(tenantId: number, opts: ApplyOptions = {}): Promise<FirewallApplyOutcome> {
  const mode = opts.mode ?? "manual";
  const confirmSec = Math.max(15, Number(opts.confirmSec ?? CONFIRM_SEC));
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const results: ApplyResults[] = [];
  const persistence: ApplyResults[] = [];
  const gateOn = process.env.CONSOLE_OS_APPLY === "1";

  const plan = await buildFirewallPlan(tenantId);
  const outcome: FirewallApplyOutcome = {
    gate: gateOn ? "on" : "off",
    applied: false,
    rolledBack: false,
    rollbackReason: null,
    confirmSec,
    confirmDeadlineAt: null,
    ts,
    warnings: plan.gen.warnings,
    counts: plan.gen.counts,
    forwardPolicy: plan.gen.forwardPolicy,
    health: { baseline: null, after: null, postRollback: null },
    results,
    persistence,
  };

  if (!gateOn) {
    results.push({ step: "gate", ok: false, detail: "OS convergence disabled by platform policy — plan is a preview only" });
    return outcome;
  }
  if ((await dataPlaneMode()) !== "host") {
    results.push({ step: "mode", ok: false, detail: "data plane is not in host mode — OS enforcement is preview-only" });
    return outcome;
  }
  if (!(await hasTool("nft"))) {
    results.push({ step: "tool", ok: false, detail: "nft binary not found on host" });
    return outcome;
  }

  // 1. syntax/commit pre-check — never touch the kernel on a broken plan
  const file = path.join(NFT_DIR, `ruleset-${ts}.nft`);
  await fs.mkdir(NFT_DIR, { recursive: true });
  void housekeepArtefacts().catch(() => {}); // audit fix L27 — never an unobserved rejection
  await fs.writeFile(file, plan.file, "utf8");
  const check = await runTool(`nft -c -f ${JSON.stringify(file)}`, 10000);
  results.push({ step: "nft -c check", ok: check.ok, detail: check.ok ? undefined : check.stderr || check.error });
  if (!check.ok) {
    await writeState(null);
    return outcome;
  }

  // 2. backup — TABLE-SCOPED restore point (audit fix M3): only the
  // console-firewall table is snapshotted and restored; a rollback never
  // replays `flush ruleset`, so utm_ti_block / utm_appctl / fail2ban tables
  // created after this backup survive intact.
  const live = await readNftRuleset();
  if (!live.available) {
    results.push({ step: "backup", ok: false, detail: "cannot read the live ruleset — refusing to apply without a restore point" });
    return outcome;
  }
  const backupFile = path.join(NFT_DIR, `backup-${ts}.nft`);
  const backupContent = composeTableScopedBackup(live.ruleset, NFT_TABLE_NAME);
  await fs.writeFile(backupFile, backupContent, "utf8");
  results.push({ step: "backup", ok: true, detail: backupFile });

  // 3. arm the detached rollback timer (survives console restarts)
  const confirmFile = path.join(NFT_DIR, `confirm-${ts}`);
  const rollbackScript = rollbackScriptPath(ts);
  await fs.writeFile(
    rollbackScript,
    [
      "#!/bin/sh",
      `# console-firewall commit-confirm rollback armed ${ts}`,
      `sleep ${confirmSec}`,
      `if [ -f ${JSON.stringify(confirmFile)} ]; then exit 0; fi`,
      `/usr/sbin/nft -f ${JSON.stringify(backupFile)}`,
      `rm -f ${JSON.stringify(rollbackScript)}`,
      `# clear the pending window if it still belongs to THIS apply (a newer`,
      `# apply supersedes it and owns the file — never touch that one)`,
      `if grep -qF ${JSON.stringify(`"ts": "${ts}"`)} ${JSON.stringify(path.join(NFT_DIR, "state.json"))} 2>/dev/null; then rm -f ${JSON.stringify(path.join(NFT_DIR, "state.json"))}; fi`,
    ].join("\n"),
    "utf8",
  );
  const arm = await runTool(`nohup /bin/sh ${JSON.stringify(rollbackScript)} >/dev/null 2>&1 &`, 4000);
  results.push({ step: "rollback timer", ok: arm.ok, detail: arm.ok ? `auto-restore in ${confirmSec}s unless confirmed` : arm.stderr || arm.error });

  const deadlineAt = new Date(Date.now() + confirmSec * 1000).toISOString();
  // a new apply SUPERSEDES any still-pending window: confirm the previous
  // timer so it cannot fire mid-flight and revert the newer policy
  const prior = await readApplyState();
  if (prior) await fs.writeFile(prior.confirmFile, "superseded", "utf8").catch(() => {});
  await writeState({ ts, armedAt: new Date().toISOString(), deadlineAt, mode, backupFile, confirmFile, tenantId });
  outcome.confirmDeadlineAt = deadlineAt;

  // 4. WAN health baseline (the 2026-11-14 outage class guard)
  const baseline = await probeWanHealth();
  outcome.health.baseline = baseline;

  // 4b. bank the PRE-apply hit counters — the destroy+recreate below resets
  //     kernel counters to zero; pending increments are folded into the DB and
  //     watermarked first so hit history survives the recreate
  try {
    const banked = await bankHitCountersBeforeApply(live.ruleset, tenantId);
    results.push({ step: "hit-counter bank", ok: true, detail: banked > 0 ? `${banked} rule counter(s) banked before the table recreate` : undefined });
  } catch (err) {
    results.push({
      step: "hit-counter bank",
      ok: false,
      detail: err instanceof Error ? err.message : "bank failed (kernel counters reset at recreate — deltas re-sync from the watermark)",
    });
  }

  // 5. apply — atomic destroy+recreate of the console table only
  const applyRes = await applyNftFile(file);
  results.push({ step: "apply", ok: applyRes.ok, detail: applyRes.ok ? undefined : applyRes.stderr || applyRes.error });
  if (!applyRes.ok) {
    // failed mid-file? `nft -f` is transactional, but restore defensively
    await runTool(`nft -f ${JSON.stringify(backupFile)}`, 10000);
    outcome.rolledBack = true;
    outcome.rollbackReason = "apply failed — backup restored";
    await writeState(null);
    return outcome;
  }
  outcome.applied = true;

  // 6. post-apply health — immediate auto-restore on measured regression
  const after = await probeWanHealth();
  outcome.health.after = after;
  if (pbrHealthRegressed(baseline, after)) {
    const restore = await runTool(`nft -f ${JSON.stringify(backupFile)}`, 10000);
    const post = await probeWanHealth();
    outcome.rolledBack = true;
    outcome.rollbackReason = `WAN health regressed after apply (gateway ${after.gatewayOk === false ? "unreachable" : "?"} / public probe ${after.internetOk === false ? "unreachable" : "?"}) — backup restored automatically`;
    outcome.health.postRollback = post;
    results.push({ step: "auto-rollback", ok: restore.ok, detail: restore.ok ? "backup restored" : restore.stderr });
    await writeState(null);
    return outcome;
  }

  // 7. persistence (best-effort — failures are warnings, runtime state stands)
  try {
    await fs.mkdir(NFT_ETC_DIR, { recursive: true });
    await fs.writeFile(path.join(NFT_ETC_DIR, "ruleset.nft"), plan.file, "utf8");
    persistence.push({ step: "write /etc/console-nft/ruleset.nft", ok: true });
    const conf = await fs.readFile(NFT_ETC_CONF, "utf8").catch(() => null);
    if (conf !== null && !conf.includes(NFT_INCLUDE_LINE)) {
      await fs.writeFile(`${NFT_ETC_CONF}.console-backup-${ts}`, conf, "utf8");
      await fs.writeFile(NFT_ETC_CONF, `${conf.replace(/\s*$/, "")}\n\n# console-managed firewall policy (GUI: Firewall → Apply to Host)\n${NFT_INCLUDE_LINE}\n`, "utf8");
      persistence.push({ step: `include added to ${NFT_ETC_CONF} (backup saved)`, ok: true });
    } else if (conf === null) {
      persistence.push({ step: `${NFT_ETC_CONF} absent — persistence skipped`, ok: false });
    } else {
      persistence.push({ step: `${NFT_ETC_CONF} include already present`, ok: true });
    }
    const en = await runTool("systemctl enable nftables >/dev/null 2>&1", 10000);
    persistence.push({ step: "systemctl enable nftables", ok: en.ok, detail: en.ok ? undefined : en.stderr || en.error });
  } catch (err) {
    persistence.push({ step: "persistence", ok: false, detail: err instanceof Error ? err.message : "unknown" });
  }

  // 8. optional IPv4 forwarding enable (required for NAT/forward policy)
  if (opts.enableForwarding && plan.facts.ipForward === false) {
    const fwd = await runTool("sysctl -w net.ipv4.ip_forward=1", 5000);
    let persist = { ok: false };
    if (fwd.ok) {
      try {
        await fs.writeFile("/etc/sysctl.d/90-console-forwarding.conf", "# console-managed: required for firewall forwarding/NAT\nnet.ipv4.ip_forward=1\n", "utf8");
        persist = { ok: true };
      } catch {
        persist = { ok: false };
      }
    }
    persistence.push({ step: "ip_forward enable", ok: fwd.ok && persist.ok, detail: fwd.ok ? (persist.ok ? "runtime + /etc/sysctl.d/90-console-forwarding.conf" : "runtime set, persistence failed") : fwd.stderr || fwd.error });
  }

  // 9. auto mode self-confirms on healthy apply; manual mode leaves the
  //    commit-confirm window open for the operator
  if (mode === "auto") {
    await fs.writeFile(confirmFile, new Date().toISOString(), "utf8").catch(() => {});
    await writeState(null);
    await fs.rm(rollbackScript, { force: true }).catch(() => {});
    outcome.confirmDeadlineAt = null;
    persistence.push({ step: "auto-confirm", ok: true, detail: "auto-converge mode — commit confirmed immediately (health verified)" });
  }
  return outcome;
}

// ── confirm / rollback / counters ───────────────────────────────────────────

export async function confirmFirewallApply(tenantId: number, ts: string): Promise<{ confirmed: boolean; ts: string }> {
  const state = await readApplyState();
  const target = state?.ts === ts ? state : null;
  if (!target) return { confirmed: false, ts };
  assertApplyTenant(tenantId, target.tenantId);
  await fs.writeFile(target.confirmFile, new Date().toISOString(), "utf8");
  await writeState(null);
  await fs.rm(rollbackScriptPath(ts), { force: true }).catch(() => {});
  return { confirmed: true, ts };
}

export async function rollbackFirewall(tenantId: number, ts?: string): Promise<{ rolledBack: boolean; file: string | null; health: PbrWanHealth | null; detail: string }> {
  const state = await readApplyState();
  if (state) assertApplyTenant(tenantId, state.tenantId);
  let backupFile: string | null = state?.backupFile ?? null;
  if (!backupFile && ts) {
    backupFile = assertOwnPath(path.join(NFT_DIR, `backup-${ts}.nft`), /^backup-[\w.-]+\.nft$/);
  }
  if (!backupFile) {
    // fall back to the newest backup file on disk
    const files = (await fs.readdir(NFT_DIR).catch(() => [] as string[]))
      .filter((f) => /^backup-[\w.-]+\.nft$/.test(f))
      .sort();
    backupFile = files.length > 0 ? path.join(NFT_DIR, files[files.length - 1]) : null;
  }
  if (!backupFile) return { rolledBack: false, file: null, health: null, detail: "no backup available" };
  const res = await runTool(`nft -f ${JSON.stringify(backupFile)}`, 10000);
  if (state) {
    await fs.writeFile(state.confirmFile, "rollback", "utf8").catch(() => {});
    await writeState(null);
    await fs.rm(rollbackScriptPath(state.ts), { force: true }).catch(() => {});
  }
  const health = await probeWanHealth();
  return {
    rolledBack: res.ok,
    file: backupFile,
    health,
    detail: res.ok ? "backup restored" : res.stderr || res.error || "restore failed",
  };
}

export interface RuleCounter {
  ruleId: number;
  name: string;
  packets: number;
  bytes: number;
  /** which DB table the comment belongs to (fw: / nat: prefix families) */
  ruleKind: "firewall" | "nat";
}

/** Parse `fw:<id>:<name>` / `nat:<id>:<name>` comment counters from a live table dump. */
export function parseRuleCounters(liveDump: string): RuleCounter[] {
  const byId = new Map<string, RuleCounter>();
  const counterRe = /counter packets (\d+) bytes (\d+)/g;
  const commentRe = /comment "(fw|nat):(\d+):([^"]*)"/;
  for (const line of liveDump.split("\n")) {
    if (!/^\s+/.test(line)) continue;
    const cm = commentRe.exec(line);
    if (!cm) continue;
    const kind = cm[1] === "nat" ? "nat" : "firewall";
    const id = Number(cm[2]);
    counterRe.lastIndex = 0;
    let m: RegExpExecArray | null;
    let packets = 0;
    let bytes = 0;
    while ((m = counterRe.exec(line)) !== null) {
      packets += Number(m[1]);
      bytes += Number(m[2]);
    }
    const key = `${kind}:${id}`;
    const prev = byId.get(key);
    if (prev) {
      prev.packets += packets;
      prev.bytes += bytes;
    } else {
      byId.set(key, { ruleId: id, name: cm[3], packets, bytes, ruleKind: kind });
    }
  }
  return [...byId.values()].sort((a, b) => a.ruleId - b.ruleId);
}

// ── hit counters (delta accumulation — kernel counters reset on apply) ──────

interface HitWrite {
  kind: "firewall" | "nat";
  id: number;
  hitCount: number;
}

/**
 * Delta semantics: `newHitCount = existing.hitCount + (packets − watermark)`
 * while the kernel counter is monotonic. When the watermark is AHEAD of the
 * kernel (the apply's destroy/recreate — or a manual `nft flush` — reset the
 * counter), the whole current kernel value is new: `delta = packets`. Plain
 * `max(0, packets − watermark)` would silently drop every post-apply
 * increment until the kernel re-passed the old watermark.
 */
function hitDelta(packets: number, watermark: number): number {
  return packets >= watermark ? packets - watermark : packets;
}

/**
 * Batch-load the rule rows referenced by the parsed counters (ONE findMany per
 * table, tenant-scoped — replaces the per-counter findFirst N+1) and compute
 * the delta writes against the watermark map (mutated in place).
 */
async function computeHitWrites(
  counters: RuleCounter[],
  tenantId: number,
  map: Record<string, number>,
): Promise<HitWrite[]> {
  const fwIds = counters.filter((c) => c.ruleKind === "firewall").map((c) => c.ruleId);
  const natIds = counters.filter((c) => c.ruleKind === "nat").map((c) => c.ruleId);
  const [fwRows, natRows] = await Promise.all([
    fwIds.length
      ? db.firewallRule.findMany({ where: { id: { in: fwIds }, tenantId }, select: { id: true, hitCount: true } })
      : Promise.resolve([] as Array<{ id: number; hitCount: number }>),
    natIds.length
      ? db.natRule.findMany({ where: { id: { in: natIds }, tenantId }, select: { id: true, hitCount: true } })
      : Promise.resolve([] as Array<{ id: number; hitCount: number }>),
  ]);
  const rows = new Map<string, { id: number; hitCount: number; kind: "firewall" | "nat" }>();
  for (const r of fwRows) rows.set(`firewall:${r.id}`, { id: r.id, hitCount: r.hitCount, kind: "firewall" });
  for (const r of natRows) rows.set(`nat:${r.id}`, { id: r.id, hitCount: r.hitCount, kind: "nat" });

  const writes: HitWrite[] = [];
  for (const c of counters) {
    const key = `${c.ruleKind}:${c.ruleId}`;
    const row = rows.get(key);
    if (!row) continue; // counter for a deleted rule / another tenant's policy — untouched
    const last = map[key] ?? 0;
    const delta = hitDelta(c.packets, last);
    map[key] = c.packets; // watermark tracks the kernel's actual value
    if (delta > 0) {
      writes.push({ kind: c.ruleKind, id: c.ruleId, hitCount: row.hitCount + delta });
    }
  }
  return writes;
}

/** Batched DB write for the delta writes (one transaction, per-row updates). */
async function persistHitWrites(writes: HitWrite[]): Promise<void> {
  if (writes.length === 0) return;
  const now = new Date();
  await db.$transaction(async (tx) => {
    for (const w of writes) {
      if (w.kind === "nat") {
        await tx.natRule.update({ where: { id: w.id }, data: { hitCount: w.hitCount, lastHitAt: now } });
      } else {
        await tx.firewallRule.update({ where: { id: w.id }, data: { hitCount: w.hitCount, lastHitAt: now } });
      }
    }
  });
}

/**
 * Bank the PRE-apply kernel counters right before the console table is
 * destroyed/recreated: increments since the last sync are folded into the DB
 * hitCount and the watermark stores the final pre-apply value, so the
 * post-apply sync (kernel reset to 0) detects the reset and nothing is lost.
 */
async function bankHitCountersBeforeApply(liveDump: string, tenantId: number): Promise<number> {
  const counters = parseRuleCounters(liveDump);
  if (counters.length === 0) return 0;
  const { lastHitSync } = await readRawState();
  const map = { ...lastHitSync };
  const writes = await computeHitWrites(counters, tenantId, map);
  await persistHitWrites(writes);
  await writeHitSyncMap(map);
  return writes.length;
}

/**
 * Push kernel counters into the DB hit fields (real hits) — DELTA accumulation
 * against the per-rule watermarks in state.json `lastHitSync`
 * (`"fw:<id>"|"nat:<id>" → packets`), so an apply's counter reset never
 * clobbers the accumulated history.
 */
export async function syncHitsFromKernel(tenantId: number): Promise<{ updated: number; natUpdated: number }> {
  const dump = (await readNftRuleset()).ruleset;
  if (!new RegExp(`table inet ${NFT_TABLE_NAME}\\b`).test(dump)) return { updated: 0, natUpdated: 0 };
  const counters = parseRuleCounters(dump);
  const { lastHitSync } = await readRawState();
  const map = { ...lastHitSync };
  const writes = await computeHitWrites(counters, tenantId, map);
  await persistHitWrites(writes);
  await writeHitSyncMap(map);
  const updated = writes.filter((w) => w.kind === "firewall").length;
  const natUpdated = writes.filter((w) => w.kind === "nat").length;
  return { updated, natUpdated };
}

/** Live dump of only the console table (for status UI). */
export async function readConsoleTableDump(): Promise<string | null> {
  const res = await runTool(`nft list table inet ${NFT_TABLE_NAME} 2>/dev/null`, 6000);
  return res.ok && res.stdout.trim() ? res.stdout : null;
}
