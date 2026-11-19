/**
 * QoS OS service — resolves console policies into tc-expressible shapes
 * (address objects → CIDRs, identity sessions → /32s, app labels → L4 map)
 * and executes/reads kernel state for the status + apply routes.
 * Pure mapping lives in os.ts; everything touching db/exec is here.
 *
 * Server-only (fs/exec/db imports).
 */

import { readFile, writeFile, mkdir } from "fs/promises";
import { db } from "@/lib/db";
import { canonicalAppLabel } from "@/lib/firewall/app-catalog";
import { loadQosRuntime } from "./runtime";
import {
  addressObjectCidrs,
  buildQosApplyPlan,
  computeQosDrift,
  hardQosRefusal,
  parseTcClassShow,
  parseTcFilterShow,
  parseTcQdiscShow,
  QOS_STATE_DIR,
  QOS_STATE_FILE,
  renderQosIface,
  renderRestoreQdisc,
  qosStepGuarded,
  type QosApplyPlan,
  type QosPolicyShape,
  type TcQdiscJson,
} from "./os";

export interface QosStateFile {
  hash: string;
  appliedAt: string;
  managedIfaces: string[];
  policies: { iface: string; policyId: number | null }[];
}

export async function readQosState(): Promise<QosStateFile | null> {
  try {
    const raw = await readFile(QOS_STATE_FILE, "utf8");
    const parsed = JSON.parse(raw) as QosStateFile;
    if (!parsed || !Array.isArray(parsed.managedIfaces)) return null;
    return parsed;
  } catch {
    return null;
  }
}

export async function writeQosState(content: string): Promise<void> {
  await mkdir(QOS_STATE_DIR, { recursive: true });
  await writeFile(QOS_STATE_FILE, content, "utf8");
}

/**
 * Load enabled+attached policies with OS-expressible matcher resolution:
 *  • matchAddresses (object ids) → ip/subnet/wildcard values → CIDRs;
 *    range/fqdn/geo become notes
 *  • matchUsers (user ids) → ACTIVE identity sessions → distinct /32s
 *  • matchApps → canonicalized; non-catalog labels dropped defensively
 */
export async function buildQosShapes(tenantId: number): Promise<{
  shapes: QosPolicyShape[];
  notes: string[];
}> {
  const runtime = await loadQosRuntime(tenantId);
  const notes: string[] = [];
  const shapes: QosPolicyShape[] = [];

  const attached = runtime.policies.filter((p) => p.ifaceName);

  const addrIds = new Set<number>();
  const userNames = new Set<string>();
  for (const p of attached) {
    for (const r of p.rules) {
      for (const a of r.matchAddresses) {
        const n = Number(a);
        if (Number.isInteger(n) && n > 0) addrIds.add(n);
      }
      for (const u of r.matchUsers) userNames.add(u);
    }
  }
  const [addrRows, sessionRows] = await Promise.all([
    addrIds.size > 0
      ? db.addressObject.findMany({ where: { tenantId, id: { in: [...addrIds] } }, select: { id: true, name: true, type: true, value: true } })
      : Promise.resolve([] as Array<{ id: number; name: string; type: string; value: string }>),
    userNames.size > 0
      ? db.identitySession.findMany({
          where: { tenantId, userName: { in: [...userNames] }, state: "active" },
          select: { userName: true, sourceIp: true },
        })
      : Promise.resolve([] as Array<{ userName: string; sourceIp: string }>),
  ]);

  const addrById = new Map(addrRows.map((a) => [a.id, a]));
  const userCidrs = new Map<string, string[]>();
  for (const s of sessionRows) {
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(s.sourceIp)) continue; // IPv4 only for tc u32
    const list = userCidrs.get(s.userName) ?? [];
    if (!list.includes(`${s.sourceIp}/32`)) list.push(`${s.sourceIp}/32`);
    userCidrs.set(s.userName, list);
  }

  for (const p of attached) {
    const rules = p.rules.map((r) => {
      const matchCidrs: string[] = [];
      for (const a of r.matchAddresses) {
        const id = Number(a);
        const obj = addrById.get(id);
        if (!obj) {
          notes.push(`rule "${r.name}": address object ${a} not found — skipped by tc`);
          continue;
        }
        const res = addressObjectCidrs(obj);
        matchCidrs.push(...res.cidrs);
        if (res.note) notes.push(`rule "${r.name}": ${res.note}`);
      }
      for (const u of r.matchUsers) {
        const list = userCidrs.get(u) ?? [];
        if (list.length === 0) notes.push(`rule "${r.name}": user "${u}" has no active identity sessions — no tc filters emitted`);
        matchCidrs.push(...list);
      }
      const apps: string[] = [];
      for (const raw of r.matchApps) {
        const canonical = canonicalAppLabel(raw);
        if (!canonical) {
          notes.push(`rule "${r.name}": unknown app label "${raw}" — skipped by tc`);
          continue;
        }
        if (!apps.includes(canonical)) apps.push(canonical);
      }
      return {
        id: r.id,
        name: r.name,
        priority: r.priority,
        guaranteedKbps: r.guaranteedKbps,
        maxKbps: r.maxKbps,
        dscpMark: r.dscpMark,
        matchApps: apps,
        matchCidrs,
      };
    });
    shapes.push({
      id: p.id,
      name: p.name,
      bandwidthKbps: p.bandwidthKbps,
      ifaceName: p.ifaceName as string,
      rules,
    });
  }

  return { shapes, notes };
}

// ── status ──────────────────────────────────────────────────────────────────

export interface QosPolicyOsStatus {
  id: number;
  name: string;
  ifaceName: string;
  classesExpected: number;
  filtersExpected: number;
  unclassifiableApps: string[];
  inSync: boolean | null;
  driftReasons: string[];
  live: {
    qdiscKind: string | null;
    defaultClassid: string | null;
    classes: number;
    filters: number;
  } | null;
}

export async function readQosKernelStatus(tenantId: number): Promise<{
  available: boolean;
  dataPlaneMode: string;
  note: string;
  state: QosStateFile | null;
  policies: QosPolicyOsStatus[];
  warnings: string[];
}> {
  const [{ getDataPlaneMode }, { hasTool, runTool }] = await Promise.all([
    import("@/lib/engine"),
    import("@/lib/host/tools"),
  ]);
  const mode = getDataPlaneMode();
  const tcOk = await hasTool("tc");
  const available = tcOk && mode === "host";
  const state = await readQosState();
  const { shapes, notes } = await buildQosShapes(tenantId);

  const policies: QosPolicyOsStatus[] = [];
  const warnings = [...notes];

  for (const shape of shapes) {
    const rendered = renderQosIface(shape, shape.ifaceName);
    const filterCount = Object.values(rendered.filtersByFlowid).reduce((s, n) => s + n, 0);
    const entry: QosPolicyOsStatus = {
      id: shape.id,
      name: shape.name,
      ifaceName: shape.ifaceName,
      classesExpected: rendered.classes.length,
      filtersExpected: filterCount,
      unclassifiableApps: rendered.unclassifiableApps,
      inSync: null,
      driftReasons: [],
      live: null,
    };
    if (available) {
      const [qd, cl, fl] = await Promise.all([
        runTool(`tc -j qdisc show dev ${shape.ifaceName}`, 5000),
        runTool(`tc -j class show dev ${shape.ifaceName}`, 5000),
        runTool(`tc -j filter show dev ${shape.ifaceName} parent 1:`, 5000),
      ]);
      if (qd.ok && cl.ok && fl.ok) {
        const qdisc = parseTcQdiscShow(qd.stdout);
        const classes = parseTcClassShow(cl.stdout);
        const filters = parseTcFilterShow(fl.stdout);
        const drift = computeQosDrift(rendered, qdisc, classes, filters);
        entry.live = {
          qdiscKind: qdisc?.kind ?? null,
          defaultClassid: qdisc?.defaultClassid ?? null,
          classes: classes.length,
          filters: filters.length,
        };
        entry.inSync = drift.inSync;
        entry.driftReasons = drift.driftReasons;
      } else {
        entry.driftReasons = [`kernel reads failed: ${(qd.error || cl.error || fl.error || "").slice(0, 120)}`];
        entry.inSync = false;
      }
    }
    policies.push(entry);
  }

  return {
    available,
    dataPlaneMode: mode,
    note: available
      ? "tc present — shaping applies to the kernel on Apply"
      : "tc unavailable or data plane in simulated mode — OS enforcement is preview-only",
    state,
    policies,
    warnings,
  };
}

// ── apply executor (mirrors the HA route pattern) ───────────────────────────

export interface QosStepResult {
  step: string;
  ok: boolean;
  detail?: string;
}

export interface QosApplyOutcome {
  applied: boolean;
  refused?: string;
  reason?: string;
  rolledBack: boolean;
  confHash?: string;
  backupFile?: string;
  plan: { steps: { step: string; cmd: string; kind: string }[]; expected: Record<string, unknown> };
  results: QosStepResult[];
}

/**
 * Execute the convergence plan on the appliance (executors SELF-GATE — F-e #19:
 * the CONSOLE_OS_APPLY check lives here so every caller inherits the gate;
 * routes additionally pass their own flag, defense in depth). Snapshot-first
 * per iface; failed install/verify after a mutation triggers auto-rollback:
 * touched ifaces are reset (`qdisc del`) and their pre-apply root qdisc
 * re-attached from the captured snapshot. The state file is the LAST plan
 * step — only written when every verify passed.
 */
export async function applyQosToOs(tenantId: number, exec: boolean): Promise<QosApplyOutcome> {
  const [{ getDataPlaneMode }, { runTool }] = await Promise.all([
    import("@/lib/engine"),
    import("@/lib/host/tools"),
  ]);

  // F-e #19: executor-side env gate — coherent with the route-side flag.
  const execGated = exec && process.env.CONSOLE_OS_APPLY === "1";
  const { shapes } = await buildQosShapes(tenantId);
  const refusal = hardQosRefusal(shapes);
  const state = await readQosState();
  const mode: QosApplyPlan["mode"] = execGated && getDataPlaneMode() === "host" ? "exec" : "plan";
  const ts = new Date().toISOString().replace(/[:.]/g, "-");

  const plan: QosApplyPlan = buildQosApplyPlan({
    policies: shapes,
    managedIfaces: state?.managedIfaces ?? [],
    mode,
    ts,
  });
  const preview = () => ({ steps: plan.steps, expected: plan.expected });

  if (refusal) {
    return { applied: false, refused: refusal, rolledBack: false, plan: preview(), results: [] };
  }
  if (!execGated || mode !== "exec") {
    return {
      applied: false,
      refused: !execGated
        ? "CONSOLE_OS_APPLY is off — plan preview only (tc command sequence attached)"
        : "data plane is not in host mode — OS enforcement is preview-only",
      rolledBack: false,
      plan: preview(),
      results: [],
    };
  }

  const results: QosStepResult[] = [];
  let failed = false;
  let failDetail = "";
  /** per-iface pre-apply root qdisc (restore source) */
  const snapshots = new Map<string, TcQdiscJson>();
  const touchedIfaces = new Set<string>();
  const verifyBufs: Record<string, { qdisc: string; classes: string; filters: string }> = {};

  for (const s of plan.steps) {
    if (s.kind === "snapshot") {
      const iface = s.iface ?? "";
      // snapshot reads go through the same whitelist as every other exec step
      if (!qosStepGuarded(s.cmd)) {
        failed = true;
        failDetail = `step '${s.step}' failed the tc command whitelist — execution aborted`;
        results.push({ step: s.step, ok: false, detail: failDetail });
        break;
      }
      const r = await runTool(s.cmd, 10000);
      if (!r.ok) {
        failed = true;
        failDetail = `snapshot ${iface} failed: ${(r.stderr || r.error || "").slice(0, 200)}`;
        results.push({ step: s.step, ok: false, detail: failDetail });
        break;
      }
      let rootRaw: TcQdiscJson | null = null;
      try {
        rootRaw = (JSON.parse(r.stdout || "[]") as TcQdiscJson[]).find((q) => q.root === true) ?? null;
      } catch {
        // corrupt tc -j output — treat as a failed step (auto-rollback can
        // still reset the iface; it just has no pre-apply root to re-attach)
        failed = true;
        failDetail = `snapshot ${iface} parse failed: tc -j output is not valid JSON (${r.stdout.length} bytes)`;
        results.push({ step: s.step, ok: false, detail: "snapshot parse failed" });
        break;
      }
      const arr = parseTcQdiscShow(r.stdout);
      snapshots.set(iface, rootRaw ?? {});
      results.push({ step: s.step, ok: true, detail: `${arr ? "parsed" : "raw"} (${r.stdout.length} bytes)` });
      continue;
    }

    if (s.kind === "writefile") {
      await writeQosState(plan.stateContent);
      results.push({ step: s.step, ok: true, detail: QOS_STATE_FILE });
      continue;
    }

    if (s.kind === "restore") {
      const iface = s.iface ?? "";
      const snap = snapshots.get(iface);
      const cmd = (snap && renderRestoreQdisc(iface, snap)) || `tc qdisc add dev ${iface} root fq_codel`;
      if (!cmd) {
        results.push({ step: s.step, ok: true, detail: "no previous root qdisc to restore" });
        continue;
      }
      if (!qosStepGuarded(cmd)) {
        failed = true;
        failDetail = `step '${s.step}' failed the tc command whitelist — execution aborted`;
        results.push({ step: s.step, ok: false, detail: failDetail });
        break;
      }
      const r = await runTool(cmd, 10000);
      results.push({ step: s.step, ok: r.ok, detail: r.ok ? cmd : (r.stderr || r.error || "").slice(0, 200) });
      if (!r.ok) {
        failed = true;
        failDetail = `restore failed for ${iface}: ${(r.stderr || r.error || "").slice(0, 200)}`;
        break;
      }
      continue;
    }

    if (s.kind === "reset") {
      // best-effort: the root may be empty (fresh apply) — a real failure
      // (missing iface etc.) surfaces at the subsequent install `add`
      if (!qosStepGuarded(s.cmd)) {
        failed = true;
        failDetail = `step '${s.step}' failed the tc command whitelist — execution aborted`;
        results.push({ step: s.step, ok: false, detail: failDetail });
        break;
      }
      const r = await runTool(s.cmd, 10000);
      touchedIfaces.add(s.iface ?? "");
      results.push({ step: s.step, ok: true, detail: r.ok ? "root cleared" : "root already empty" });
      continue;
    }

    if (!qosStepGuarded(s.cmd)) {
      failed = true;
      failDetail = `step '${s.step}' failed the tc command whitelist — execution aborted`;
      results.push({ step: s.step, ok: false, detail: failDetail });
      break;
    }
    const r = await runTool(s.cmd, 15000);
    if (!r.ok) {
      failed = true;
      failDetail = `step '${s.step}' failed: ${(r.stderr || r.error || "").trim().slice(0, 300) || "exec error"}`;
      results.push({ step: s.step, ok: false, detail: failDetail });
      break;
    }

    if (s.kind === "verify") {
      const iface = s.iface ?? "";
      verifyBufs[iface] ??= { qdisc: "", classes: "", filters: "" };
      if (s.cmd.includes("qdisc show")) verifyBufs[iface].qdisc = r.stdout;
      else if (s.cmd.includes("class show")) verifyBufs[iface].classes = r.stdout;
      else verifyBufs[iface].filters = r.stdout;

      const buf = verifyBufs[iface];
      if (buf.qdisc && buf.classes && buf.filters) {
        const rendered = plan.expected[iface];
        const drift = computeQosDrift(rendered, parseTcQdiscShow(buf.qdisc), parseTcClassShow(buf.classes), parseTcFilterShow(buf.filters));
        if (!drift.inSync) {
          failed = true;
          failDetail = `verify ${iface} failed: ${drift.driftReasons.slice(0, 3).join("; ")}`;
          results.push({ step: s.step, ok: false, detail: failDetail });
          break;
        }
        results.push({
          step: s.step,
          ok: true,
          detail: `${rendered.classes.length} classes, ${Object.values(rendered.filtersByFlowid).reduce((a, b) => a + b, 0)} filters verified`,
        });
      }
      continue;
    }

    // plain exec (modprobe / install / teardown)
    if (s.cmd.startsWith("tc qdisc del") || s.cmd.startsWith("tc qdisc add dev") && s.cmd.includes(" root handle")) touchedIfaces.add(s.iface ?? "");
    results.push({ step: s.step, ok: true, detail: r.stdout.trim().slice(0, 200) || undefined });
  }

  // ── auto-rollback: reset touched ifaces to their pre-apply root qdiscs ──
  let rolledBack = false;
  if (failed && touchedIfaces.size > 0) {
    let allOk = true;
    for (const iface of [...touchedIfaces].filter(Boolean)) {
      const delCmd = `tc qdisc del dev ${iface} root`;
      const snap = snapshots.get(iface);
      const restoreCmd = (snap && renderRestoreQdisc(iface, snap)) || `tc qdisc add dev ${iface} root fq_codel`;
      const del = qosStepGuarded(delCmd) ? await runTool(delCmd, 10000) : { ok: false, stdout: "", stderr: "whitelist" };
      const restore = restoreCmd && qosStepGuarded(restoreCmd)
        ? await runTool(restoreCmd, 10000)
        : { ok: false, stdout: "", stderr: "whitelist" };
      if (!del.ok || !restore.ok) allOk = false;
    }
    rolledBack = allOk;
    results.push({
      step: "auto-rollback",
      ok: rolledBack,
      detail: rolledBack
        ? "touched ifaces reset to their pre-apply root qdiscs from the per-iface snapshots"
        : "rollback partially failed — inspect kernel qdisc state manually",
    });
  }

  // backup files are forensic records of pre-apply state — always kept

  return {
    applied: !failed,
    reason: failed ? failDetail : `kernel shaper converged (hash ${plan.confHash})`,
    rolledBack,
    confHash: plan.confHash,
    backupFile: plan.backupFile,
    plan: preview(),
    results,
  };
}
