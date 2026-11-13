"use client";

/**
 * FirewallOsSync — the GUI↔nftables integration surface.
 *
 *   • sync badge — In sync / Drift / Not applied / Preview-only, with the
 *     OS facts on hover (nft version, ip_forward, table presence, fail2ban
 *     coexistence) and enforceability warnings
 *   • Apply to Host dialog — plan preview (chain counts, forward policy,
 *     warnings, generated file) → commit-confirm apply backed by the OS
 *     backup/rollback engine
 *   • pending commit-confirm banner — countdown with Confirm / Rollback now
 *
 * Shared by the Rules view and the NAT view toolbars (same kernel policy).
 */

import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { ScrollArea } from "@/components/ui/scroll-area";
import * as Icons from "lucide-react";
import { cn } from "@/lib/utils";
import { fwFetch } from "./fw-api";
import { toastErr, toastOk } from "./fw-ui";

// ── types (mirror firewall-os.ts) ───────────────────────────────────────────

interface NftWarning {
  scope: "rule" | "nat" | "zone" | "policy";
  id: number | null;
  name: string;
  code: string;
  message: string;
}

interface OsStatus {
  gate: "on" | "off";
  facts: {
    nftAvailable: boolean;
    nftVersion: string | null;
    ipForward: boolean | null;
    interfaces: Array<{ name: string; up: boolean; addresses: string[] }>;
    consoleTablePresent: boolean;
    f2bTablePresent: boolean;
  };
  drift: { applied: boolean; inSync: boolean };
  counts: { forward: number; input: number; prerouting: number; postrouting: number; skipped: number };
  forwardPolicy: "accept" | "drop";
  warnings: NftWarning[];
  file: string;
  ipForwardRequired: boolean;
  counters: Array<{ ruleId: number; name: string; packets: number; bytes: number }>;
  pendingConfirm: { ts: string; deadlineAt: string; mode: string; backupFile: string } | null;
  tableDump: string | null;
}

interface OsApplyOutcome {
  gate: "on" | "off";
  applied: boolean;
  rolledBack: boolean;
  rollbackReason: string | null;
  confirmSec: number;
  confirmDeadlineAt: string | null;
  warnings: NftWarning[];
  health: { baseline: unknown; after: unknown; postRollback: unknown };
  results: Array<{ step: string; ok: boolean; detail?: string }>;
  persistence: Array<{ step: string; ok: boolean; detail?: string }>;
}

const OS_KEY = ["firewall", "os-status"];

function osPost<T>(body: Record<string, unknown>): Promise<T> {
  return fwFetch<T>("/api/v1/firewall-rules/os", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

// ── badge ───────────────────────────────────────────────────────────────────

function badgeFor(s: OsStatus | undefined): { label: string; cls: string } {
  if (!s) return { label: "OS status…", cls: "border-zinc-300 text-zinc-500 dark:border-zinc-700" };
  if (!s.facts.nftAvailable) return { label: "nft unavailable", cls: "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400" };
  if (s.gate === "off") return { label: "Preview only", cls: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300" };
  if (s.pendingConfirm) return { label: "Unconfirmed apply", cls: "border-amber-500/50 bg-amber-500/10 text-amber-600 dark:text-amber-400" };
  if (!s.drift.applied) return { label: "Not applied to OS", cls: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300" };
  if (s.drift.inSync) return { label: "In sync with OS", cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400" };
  return { label: "Drift", cls: "border-amber-500/50 bg-amber-500/10 text-amber-600 dark:text-amber-400" };
}

// ── main component ──────────────────────────────────────────────────────────

export function FirewallOsSync() {
  const queryClient = useQueryClient();
  const [applyOpen, setApplyOpen] = useState(false);
  const [now, setNow] = useState(Date.now());

  const status = useQuery<OsStatus>({
    queryKey: OS_KEY,
    queryFn: () => fwFetch<OsStatus>("/api/v1/firewall-rules/os"),
    refetchInterval: 30000,
  });

  const data = status.data;
  const badge = badgeFor(data);
  const hardWarnings = useMemo(() => (data?.warnings ?? []).filter((w) => w.code !== "rate-limit-ignored"), [data]);

  // 1s tick while a commit-confirm window is open (countdown)
  useEffect(() => {
    if (!data?.pendingConfirm) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [data?.pendingConfirm]);

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: OS_KEY });

  const applyMut = useMutation({
    mutationFn: (enableForwarding: boolean) =>
      osPost<OsApplyOutcome>({ action: "apply", mode: "manual", enableForwarding }),
    onSuccess: (res) => {
      if (res.rolledBack) toastErr(new Error(res.rollbackReason ?? "rolled back"), "Apply rolled back");
      else if (res.gate === "off") toastOk("Plan generated", "OS apply is disabled on this installation — preview only");
      else toastOk("Firewall policy applied to host", res.confirmDeadlineAt ? `Confirm within ${res.confirmSec}s to keep it` : undefined);
      invalidate();
    },
    onError: (err) => toastErr(err, "Apply failed"),
  });

  const confirmMut = useMutation({
    mutationFn: (ts: string) => osPost<{ confirmed: boolean }>({ action: "confirm", ts }),
    onSuccess: () => {
      toastOk("Commit confirmed", "Rollback timer cancelled — policy is live");
      invalidate();
    },
    onError: (err) => toastErr(err, "Confirm failed"),
  });

  const rollbackMut = useMutation({
    mutationFn: () => osPost<{ rolledBack: boolean; detail: string }>({ action: "rollback" }),
    onSuccess: (r) => {
      if (r.rolledBack) toastOk("Rolled back", "Previous policy restored from backup");
      else toastErr(new Error(r.detail), "Rollback failed");
      invalidate();
    },
    onError: (err) => toastErr(err, "Rollback failed"),
  });

  const pending = data?.pendingConfirm;
  const remainSec = pending ? Math.max(0, Math.round((new Date(pending.deadlineAt).getTime() - now) / 1000)) : 0;

  return (
    <div className="flex flex-wrap items-center gap-2">
      {/* commit-confirm banner */}
      {pending && (
        <Alert className="w-full border-amber-500/50 bg-amber-500/5">
          <Icons.TriangleAlert className="h-4 w-4 text-amber-500" />
          <AlertTitle className="text-amber-600 dark:text-amber-400">
            Firewall policy is live but unconfirmed — auto-rollback in {remainSec}s
          </AlertTitle>
          <AlertDescription className="flex flex-wrap items-center gap-2 text-xs">
            <span>
              If the host is unreachable for you, the previous policy will be restored automatically from backup.
            </span>
            <Button size="sm" className="h-7 bg-emerald-600 text-white hover:bg-emerald-700" onClick={() => confirmMut.mutate(pending.ts)} disabled={confirmMut.isPending}>
              <Icons.Check className="mr-1 h-3.5 w-3.5" /> Confirm commit
            </Button>
            <Button size="sm" variant="outline" className="h-7 border-rose-500/50 text-rose-600 hover:bg-rose-500/10 dark:text-rose-400" onClick={() => rollbackMut.mutate()} disabled={rollbackMut.isPending}>
              <Icons.RotateCcw className="mr-1 h-3.5 w-3.5" /> Rollback now
            </Button>
          </AlertDescription>
        </Alert>
      )}

      {/* sync badge with facts popover */}
      <div className="flex items-center gap-2">
        <Badge variant="outline" className={cn("gap-1.5", badge.cls)}>
          <Icons.HardDrive className="h-3 w-3" />
          {badge.label}
        </Badge>
        <span className="hidden text-xs text-zinc-400 lg:inline">
          {data?.counts.forward ?? 0} fwd / {data?.counts.input ?? 0} in / {data?.counts.postrouting ?? 0}+{data?.counts.prerouting ?? 0} nat
          {hardWarnings.length > 0 && <span className="text-amber-500"> · {hardWarnings.length} warning{hardWarnings.length === 1 ? "" : "s"}</span>}
        </span>
      </div>

      <Button size="sm" variant="outline" onClick={() => setApplyOpen(true)} title="Apply firewall policy to the host (nftables)">
        <Icons.UploadCloud className="mr-1 h-4 w-4" /> Apply to host
      </Button>

      <FirewallApplyDialog
        open={applyOpen}
        onOpenChange={(o) => {
          setApplyOpen(o);
          if (o) invalidate();
        }}
        status={data}
        applying={applyMut.isPending}
        outcome={applyMut.data ?? null}
        error={applyMut.error instanceof Error ? applyMut.error.message : null}
        enableForwarding={applyMut.variables ?? false}
        onApply={(ef) => applyMut.mutate(ef)}
      />
    </div>
  );
}

// ── apply dialog ────────────────────────────────────────────────────────────

function FirewallApplyDialog(props: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  status: OsStatus | undefined;
  applying: boolean;
  outcome: OsApplyOutcome | null;
  error: string | null;
  enableForwarding: boolean;
  onApply: (enableForwarding: boolean) => void;
}) {
  const [ef, setEf] = useState(false);
  const s = props.status;
  const warn = s?.warnings ?? [];
  const rulesWarned = warn.filter((w) => w.scope === "rule" || w.scope === "nat" || w.scope === "zone");

  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Icons.HardDriveDownload className="h-5 w-5" /> Apply firewall policy to host
          </DialogTitle>
          <DialogDescription>
            Generates the nftables <code className="rounded bg-zinc-100 px-1 dark:bg-zinc-800">inet console-firewall</code> table,
            verifies it with <code className="rounded bg-zinc-100 px-1 dark:bg-zinc-800">nft -c</code>, snapshots a backup, applies
            atomically, then verifies WAN health. An automatic rollback timer restores the previous policy unless you confirm.
          </DialogDescription>
        </DialogHeader>

        {props.outcome ? (
          <ApplyOutcomeView outcome={props.outcome} error={props.error} />
        ) : (
          <div className="space-y-3">
            {/* plan facts */}
            <div className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
              <PlanStat label="Forward rules" value={String(s?.counts.forward ?? 0)} />
              <PlanStat label="Input rules" value={String(s?.counts.input ?? 0)} />
              <PlanStat label="NAT (out/in)" value={`${s?.counts.postrouting ?? 0}/${s?.counts.prerouting ?? 0}`} />
              <PlanStat label="Forward policy" value={(s?.forwardPolicy ?? "accept").toUpperCase()} warn={s?.forwardPolicy === "drop"} />
            </div>

            {/* safety facts */}
            <div className="flex flex-wrap gap-1.5 text-[11px]">
              <FactChip ok={!!s?.facts.nftAvailable} label={`nft ${s?.facts.nftVersion?.split(" ")[1] ?? ""}`} />
              <FactChip ok={s?.facts.consoleTablePresent ?? false} label={s?.facts.consoleTablePresent ? "console table present" : "table not yet applied"} />
              <FactChip ok={true} label={s?.facts.f2bTablePresent ? "fail2ban table preserved" : "no fail2ban table"} />
              <FactChip ok={s?.facts.ipForward !== false} label={`ip_forward ${s?.facts.ipForward == null ? "?" : s.facts.ipForward ? "on" : "off"}`} />
              {s?.gate === "off" && <FactChip ok={false} label="OS apply disabled — preview only" />}
            </div>

            {/* ip forwarding offer */}
            {s?.ipForwardRequired && s?.facts.ipForward === false && s.gate === "on" && (
              <label className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/5 p-3 text-xs">
                <Checkbox checked={ef} onCheckedChange={(v) => setEf(v === true)} className="mt-0.5" />
                <span>
                  <span className="font-medium">Enable IPv4 forwarding</span> — required for forwarded traffic and NAT to flow
                  (sets net.ipv4.ip_forward=1 at runtime and persists it to /etc/sysctl.d/90-console-forwarding.conf).
                </span>
              </label>
            )}

            {/* warnings */}
            {rulesWarned.length > 0 && (
              <div className="rounded-md border border-amber-500/40">
                <div className="border-b border-amber-500/30 bg-amber-500/5 px-3 py-1.5 text-xs font-medium text-amber-600 dark:text-amber-400">
                  {rulesWarned.length} enforceability warning{rulesWarned.length === 1 ? "" : "s"} — these rules stay config-only (never silently widened):
                </div>
                <ScrollArea className="max-h-40">
                  <ul className="space-y-1 p-3 text-xs">
                    {rulesWarned.map((w, i) => (
                      <li key={i} className="text-zinc-600 dark:text-zinc-300">
                        <span className="font-medium">{w.scope === "rule" ? `rule '${w.name}'` : w.scope === "nat" ? `NAT '${w.name}'` : `zone '${w.name}'`}:</span>{" "}
                        {w.message}
                      </li>
                    ))}
                  </ul>
                </ScrollArea>
              </div>
            )}
          </div>
        )}

        <DialogFooter>
          <Button variant="ghost" onClick={() => props.onOpenChange(false)}>
            {props.outcome ? "Close" : "Cancel"}
          </Button>
          {!props.outcome && (
            <Button onClick={() => props.onApply(ef)} disabled={props.applying || s?.gate === "off" || !s?.facts.nftAvailable} className="bg-zinc-700 text-white hover:bg-zinc-800">
              {props.applying ? "Applying…" : "Apply now"}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ApplyOutcomeView(props: { outcome: OsApplyOutcome | null; error: string | null }) {
  const o = props.outcome;
  if (props.error && !o) {
    return (
      <Alert variant="destructive">
        <Icons.CircleX className="h-4 w-4" />
        <AlertTitle>Apply failed</AlertTitle>
        <AlertDescription className="text-xs">{props.error}</AlertDescription>
      </Alert>
    );
  }
  if (!o) return null;
  if (o.gate === "off") {
    return (
      <Alert>
        <Icons.Info className="h-4 w-4" />
        <AlertTitle>Preview only</AlertTitle>
        <AlertDescription className="text-xs">
          OS convergence is disabled by platform policy on this installation (CONSOLE_OS_APPLY). The generated plan was verified
          but the kernel was not touched.
        </AlertDescription>
      </Alert>
    );
  }
  if (o.rolledBack) {
    return (
      <Alert variant="destructive">
        <Icons.RotateCcw className="h-4 w-4" />
        <AlertTitle>Applied, then rolled back automatically</AlertTitle>
        <AlertDescription className="text-xs">
          {o.rollbackReason}
          <ul className="mt-2 space-y-0.5">
            {o.results.filter((r) => !r.ok).map((r, i) => (
              <li key={i}>· {r.step}: {r.detail}</li>
            ))}
          </ul>
        </AlertDescription>
      </Alert>
    );
  }
  return (
    <Alert className="border-emerald-500/40 bg-emerald-500/5">
      <Icons.ShieldCheck className="h-4 w-4 text-emerald-500" />
      <AlertTitle className="text-emerald-600 dark:text-emerald-400">Firewall policy is live on the host</AlertTitle>
      <AlertDescription className="space-y-1 text-xs">
        <p>
          Commit-confirm window: {o.confirmDeadlineAt ? `${o.confirmSec}s — confirm in the banner to keep the policy` : "self-confirmed"}.
          WAN health verified after apply.
        </p>
        {o.persistence.length > 0 && (
          <ul className="text-zinc-500 dark:text-zinc-400">
            {o.persistence.map((p, i) => (
              <li key={i}>
                {p.ok ? "✓" : "⚠"} {p.step}
                {p.detail ? ` — ${p.detail}` : ""}
              </li>
            ))}
          </ul>
        )}
      </AlertDescription>
    </Alert>
  );
}

function PlanStat(props: { label: string; value: string; warn?: boolean }) {
  return (
    <div className="rounded-md border border-zinc-200 p-2 dark:border-zinc-800">
      <p className="text-[10px] uppercase tracking-wide text-zinc-400">{props.label}</p>
      <p className={cn("text-sm font-semibold", props.warn && "text-amber-500")}>{props.value}</p>
    </div>
  );
}

function FactChip(props: { ok: boolean; label: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full border px-2 py-0.5",
        props.ok
          ? "border-zinc-200 text-zinc-500 dark:border-zinc-700 dark:text-zinc-300"
          : "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
      )}
    >
      {props.ok ? <Icons.Check className="h-3 w-3" /> : <Icons.TriangleAlert className="h-3 w-3" />}
      {props.label}
    </span>
  );
}

export type { OsStatus };
