"use client";

/**
 * SdwanOsPanel — the SD-WAN GUI↔WireGuard OS integration surface (spec 2.5).
 *
 *   • sync badge — In sync / Drift / Not applied / Preview-only, with the OS
 *     facts on hover (wg version, data-plane mode, per-file state, running
 *     utm-sdwan-* interfaces) and the plan warnings (probe-simulated,
 *     traffic-affecting, generated-on-apply keys…)
 *   • Apply to Host dialog — redacted plan preview (per-overlay wg-quick
 *     files, hashes, warnings, generated conf) → confirm step-guard apply
 *     (first call returns {confirmed:false, ts}, the dialog re-issues with an
 *     explicit confirmSec window) backed by snapshot-first + auto-restore and
 *     a commit-confirm rollback timer
 *   • Bring up / Bring down dialogs — traffic-affecting, double-confirmed
 *     (bringUp=true AND confirmSec; never automatic)
 *   • pending commit-confirm banner — countdown with Confirm / Rollback now
 *
 * Mount: bottom of sdwan-view (write-capable roles only via isAdmin —
 * read-only status badge otherwise).
 */

import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
import { Switch } from "@/components/ui/switch";
import * as Icons from "lucide-react";
import { cn } from "@/lib/utils";
import {
  sdwanApi,
  type SdwanOsApplyOutcome,
  type SdwanOsStatus,
  type SdwanOsUpDownOutcome,
} from "./sdwan-api";
import { toastErr, toastOk } from "../firewall/fw-ui";

const OS_KEY = ["sdwan", "os-status"];
const CONFIRM_SEC = 60;

function badgeFor(s: SdwanOsStatus | undefined): { label: string; cls: string } {
  if (!s) return { label: "OS status…", cls: "border-zinc-300 text-zinc-500 dark:border-zinc-700" };
  if (!s.available) return { label: "wg unavailable", cls: "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400" };
  if (s.gate === "off") return { label: "Preview only", cls: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300" };
  if (s.pendingConfirm) return { label: "Unconfirmed apply", cls: "border-amber-500/50 bg-amber-500/10 text-amber-600 dark:text-amber-400" };
  if (s.drift.appliedFiles === 0) return { label: "Not applied to OS", cls: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300" };
  if (s.drift.inSyncFiles === s.drift.appliedFiles) return { label: "In sync with OS", cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400" };
  return { label: "Drift", cls: "border-amber-500/50 bg-amber-500/10 text-amber-600 dark:text-amber-400" };
}

// ── main panel ──────────────────────────────────────────────────────────────

export function SdwanOsPanel({ isAdmin }: { isAdmin: boolean }) {
  const queryClient = useQueryClient();
  const [applyOpen, setApplyOpen] = useState(false);
  const [upOpen, setUpOpen] = useState(false);
  const [now, setNow] = useState(Date.now());

  const status = useQuery<SdwanOsStatus>({
    queryKey: OS_KEY,
    queryFn: () => sdwanApi.getOsStatus(),
    refetchInterval: 30000,
  });

  const data = status.data;
  const badge = badgeFor(data);
  const planWarnings = useMemo(() => (data?.plan.warnings ?? []).filter((w) => w.scope === "plan"), [data]);
  const fileWarnings = useMemo(() => (data?.plan.warnings ?? []).filter((w) => w.scope !== "plan"), [data]);

  // 1s tick while a commit-confirm window is open (countdown)
  useEffect(() => {
    if (!data?.pendingConfirm) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [data?.pendingConfirm]);

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: OS_KEY });

  const applyMut = useMutation({
    mutationFn: async () => {
      // confirm step-guard: first call returns {confirmed:false, ts} —
      // re-issue with an explicit confirmSec window to execute
      const guard = await sdwanApi.applyOs({ action: "apply" });
      if ("confirmed" in guard && guard.confirmed === false) {
        return sdwanApi.applyOs({ action: "apply", confirmSec: CONFIRM_SEC }) as Promise<SdwanOsApplyOutcome>;
      }
      return guard as SdwanOsApplyOutcome;
    },
    onSuccess: (res) => {
      if (res.rolledBack) toastErr(new Error(res.rollbackReason ?? "rolled back"), "Apply rolled back");
      else if (res.gate === "off") toastOk("Plan generated", "OS apply is disabled on this installation — preview only");
      else toastOk("Overlay configs written", res.confirmDeadlineAt ? `Confirm within ${res.confirmSec}s to keep them` : undefined);
      invalidate();
    },
    onError: (err) => toastErr(err, "Apply failed"),
  });

  const confirmMut = useMutation({
    mutationFn: (ts: string) => sdwanApi.confirmOsApply(ts),
    onSuccess: () => {
      toastOk("Commit confirmed", "Rollback timer cancelled — overlay configs stay");
      invalidate();
    },
    onError: (err) => toastErr(err, "Confirm failed"),
  });

  const rollbackMut = useMutation({
    mutationFn: () => sdwanApi.rollbackOs(),
    onSuccess: (r) => {
      if (r.rolledBack) toastOk("Rolled back", "Previous configs restored from the pre-apply snapshot");
      else toastErr(new Error(r.detail), "Rollback failed");
      invalidate();
    },
    onError: (err) => toastErr(err, "Rollback failed"),
  });

  const upMut = useMutation({
    // single confirmed call: bringUp=true AND confirmSec satisfy both guards
    // (a client calling up without confirmSec receives {confirmed:false, ts})
    mutationFn: () => sdwanApi.upOs(CONFIRM_SEC),
    onSuccess: (res) => {
      if (res.broughtUp && res.broughtUp > 0) toastOk("Tunnels up", `${res.broughtUp}/${res.requested} managed interfaces brought up`);
      else toastErr(new Error(res.results.find((r) => !r.ok)?.detail ?? "no interface came up"), "Bring up failed");
      invalidate();
    },
    onError: (err) => toastErr(err, "Bring up failed"),
  });

  const downMut = useMutation({
    mutationFn: () => sdwanApi.downOs(CONFIRM_SEC),
    onSuccess: (res) => {
      if (res.broughtDown && res.broughtDown > 0) toastOk("Tunnels down", `${res.broughtDown}/${res.requested} managed interfaces brought down`);
      else toastOk("Nothing to bring down", res.results[0]?.detail ?? "no running managed interfaces");
      invalidate();
    },
    onError: (err) => toastErr(err, "Bring down failed"),
  });

  const pending = data?.pendingConfirm;
  const remainSec = pending ? Math.max(0, Math.round((new Date(pending.deadlineAt).getTime() - now) / 1000)) : 0;
  const runningCount = data?.runningIfaces.length ?? 0;

  return (
    <Card className="border-dashed">
      <CardHeader className="flex flex-col gap-2 space-y-0 pb-3 sm:flex-row sm:flex-wrap sm:items-center sm:justify-between">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.HardDrive className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
          OS integration — WireGuard overlays
          <Badge variant="outline" className={cn("gap-1.5 font-normal", badge.cls)}>
            {badge.label}
          </Badge>
          <span className="hidden text-xs font-normal text-zinc-400 lg:inline">
            {data?.plan.counts.rendered ?? 0} config file{(data?.plan.counts.rendered ?? 0) === 1 ? "" : "s"} ·{" "}
            {data?.plan.counts.peers ?? 0} peers · {runningCount} running
            {fileWarnings.length > 0 && (
              <span className="text-amber-500">
                {" "}
                · {fileWarnings.length} warning{fileWarnings.length === 1 ? "" : "s"}
              </span>
            )}
          </span>
        </CardTitle>
        {isAdmin && (
          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              className="h-8 text-xs"
              disabled={runningCount === 0}
              onClick={() => setUpOpen(true)}
              title="Bring up the managed utm-sdwan-* interfaces (affects tunnel traffic)"
            >
              <Icons.Play className="mr-1 h-3.5 w-3.5" /> Bring up
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="h-8 border-rose-500/50 text-rose-600 hover:bg-rose-500/10 dark:text-rose-400"
              disabled={runningCount === 0}
              onClick={() => downMut.mutate()}
              title="Bring down the running utm-sdwan-* interfaces (affects tunnel traffic)"
            >
              <Icons.Square className="mr-1 h-3.5 w-3.5" /> Bring down
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="h-8 text-xs"
              onClick={() => setApplyOpen(true)}
              title="Write the wg-quick overlay configs to /etc/wireguard (files only — no tunnels are brought up)"
            >
              <Icons.UploadCloud className="mr-1 h-3.5 w-3.5" /> Apply to host
            </Button>
          </div>
        )}
      </CardHeader>
      <CardContent className="space-y-3 p-4 pt-0">
        {/* commit-confirm banner */}
        {pending && isAdmin && (
          <Alert className="border-amber-500/50 bg-amber-500/5">
            <Icons.TriangleAlert className="h-4 w-4 text-amber-500" />
            <AlertTitle className="text-amber-600 dark:text-amber-400">
              Overlay configs are written but unconfirmed — auto-restore in {remainSec}s
            </AlertTitle>
            <AlertDescription className="flex flex-wrap items-center gap-2 text-xs">
              <span>The pre-apply snapshot is restored automatically (config files only — running tunnels are not torn down).</span>
              <Button size="sm" className="h-7 bg-emerald-600 text-white hover:bg-emerald-700" onClick={() => confirmMut.mutate(pending.ts)} disabled={confirmMut.isPending}>
                <Icons.Check className="mr-1 h-3.5 w-3.5" /> Confirm commit
              </Button>
              <Button size="sm" variant="outline" className="h-7 border-rose-500/50 text-rose-600 hover:bg-rose-500/10 dark:text-rose-400" onClick={() => rollbackMut.mutate()} disabled={rollbackMut.isPending}>
                <Icons.RotateCcw className="mr-1 h-3.5 w-3.5" /> Rollback now
              </Button>
            </AlertDescription>
          </Alert>
        )}

        {status.isError ? (
          <p className="text-xs text-rose-600 dark:text-rose-400">OS status unavailable — {(status.error as Error).message}</p>
        ) : !data ? (
          <p className="text-xs text-zinc-400">Reading kernel state…</p>
        ) : (
          <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
            <FactChip ok={data.available} label={`wg ${data.wgVersion?.split(" ")[1] ?? ""}`} />
            <FactChip ok={data.drift.appliedFiles > 0} label={data.drift.appliedFiles > 0 ? `${data.drift.appliedFiles} config file(s) installed` : "no config files installed"} />
            <FactChip ok={data.drift.inSyncFiles === data.drift.appliedFiles} label={data.drift.inSyncFiles === data.drift.appliedFiles && data.drift.appliedFiles > 0 ? "hashes match plan" : data.drift.reasons[0] || "drift"} />
            <FactChip ok={data.gate === "on"} label={data.gate === "on" ? `OS apply armed (${data.mode})` : "OS apply disabled — preview only"} />
            <FactChip ok={data.keySource !== "absent"} label={data.keySource === "absent" ? "no private key source — files carry [GENERATED-ON-APPLY]" : `private key source: ${data.keySource}`} />
            {data.plan.counts.skipped > 0 && <FactChip ok={false} label={`${data.plan.counts.skipped} overlay(s) skipped`} />}
          </div>
        )}

        {/* plan warnings — always visible (mission-mandated honesty) */}
        {(planWarnings.length > 0 || fileWarnings.length > 0) && (
          <div className="rounded-md border border-amber-500/40">
            <div className="border-b border-amber-500/30 bg-amber-500/5 px-3 py-1.5 text-xs font-medium text-amber-600 dark:text-amber-400">
              {planWarnings.length + fileWarnings.length} plan warning{planWarnings.length + fileWarnings.length === 1 ? "" : "s"} — rendered configs stay honest (never silently widened):
            </div>
            <ScrollArea className="max-h-36">
              <ul className="space-y-1 p-3 text-xs">
                {planWarnings.map((w, i) => (
                  <li key={`p${i}`} className="text-zinc-600 dark:text-zinc-300">
                    <span className="font-medium">plan:</span> {w.message}
                  </li>
                ))}
                {fileWarnings.map((w, i) => (
                  <li key={`f${i}`} className="text-zinc-600 dark:text-zinc-300">
                    <span className="font-medium">{w.scope === "site" ? `site '${w.name}'` : `overlay '${w.name}'`}:</span> {w.message}
                  </li>
                ))}
              </ul>
            </ScrollArea>
          </div>
        )}

        <SdwanApplyDialog
          open={applyOpen}
          onOpenChange={(o) => {
            setApplyOpen(o);
            if (o) invalidate();
          }}
          status={data}
          applying={applyMut.isPending}
          outcome={applyMut.data ?? null}
          error={applyMut.error instanceof Error ? applyMut.error.message : null}
          onApply={() => applyMut.mutate()}
        />

        <SdwanUpDialog
          open={upOpen}
          onOpenChange={setUpOpen}
          status={data}
          bringingUp={upMut.isPending}
          outcome={upMut.data ?? null}
          error={upMut.error instanceof Error ? upMut.error.message : null}
          onUp={() => upMut.mutate()}
        />
      </CardContent>
    </Card>
  );
}

// ── apply dialog (plan preview → confirm step-guard apply) ──────────────────

function SdwanApplyDialog(props: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  status: SdwanOsStatus | undefined;
  applying: boolean;
  outcome: SdwanOsApplyOutcome | null;
  error: string | null;
  onApply: () => void;
}) {
  const s = props.status;
  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent className="max-h-[85vh] max-w-2xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Icons.HardDriveDownload className="h-5 w-5" /> Apply SD-WAN overlays to host
          </DialogTitle>
          <DialogDescription>
            Writes one wg-quick config per enabled WireGuard overlay to{" "}
            <code className="rounded bg-zinc-100 px-1 dark:bg-zinc-800">/etc/wireguard/utm-sdwan-&lt;overlay&gt;.conf</code>,
            validates each with <code className="rounded bg-zinc-100 px-1 dark:bg-zinc-800">wg-quick strip</code> (a pure
            parser — it never brings interfaces up) and snapshots the previous files for automatic restore. Private keys
            never appear in the plan; they materialize server-side at apply time.
          </DialogDescription>
        </DialogHeader>

        {props.outcome ? (
          <ApplyOutcomeView outcome={props.outcome} error={props.error} />
        ) : (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
              <PlanStat label="Overlays" value={String(s?.plan.counts.overlays ?? 0)} />
              <PlanStat label="Config files" value={String(s?.plan.counts.rendered ?? 0)} />
              <PlanStat label="Peers" value={String(s?.plan.counts.peers ?? 0)} />
              <PlanStat label="Skipped" value={String(s?.plan.counts.skipped ?? 0)} warn={(s?.plan.counts.skipped ?? 0) > 0} />
            </div>

            <div className="flex flex-wrap gap-1.5 text-[11px]">
              <FactChip ok={!!s?.available} label={`wg ${s?.wgVersion?.split(" ")[1] ?? ""}`} />
              <FactChip ok={s?.gate === "on"} label={s?.gate === "on" ? `OS apply armed (${s?.mode ?? "?"})` : "OS apply disabled — preview only"} />
              <FactChip ok={(s?.drift.appliedFiles ?? 0) === 0} label={(s?.drift.appliedFiles ?? 0) === 0 ? "no files installed yet" : "existing files will be snapshotted"} />
            </div>

            {(s?.plan.files ?? []).length > 0 && (
              <div className="rounded-md border border-zinc-200 p-2 text-xs dark:border-zinc-800">
                <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-zinc-400">Planned files</p>
                <ul className="space-y-1">
                  {(s?.plan.files ?? []).map((f) => (
                    <li key={f.iface} className="flex flex-wrap items-center gap-2">
                      <code className="rounded bg-zinc-100 px-1 font-mono text-[11px] dark:bg-zinc-800">{f.iface}</code>
                      <span className="text-zinc-400">
                        {f.peers.length} peer(s) · port {f.listenPort} · {f.confHash.slice(0, 12)}…
                      </span>
                      {f.warnings.length > 0 && <Icons.TriangleAlert className="h-3 w-3 text-amber-500" />}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {s?.plan.files[0]?.conf && (
              <details className="rounded-md border border-zinc-200 p-2 text-xs dark:border-zinc-800">
                <summary className="cursor-pointer font-medium text-zinc-500 dark:text-zinc-400">Generated wg-quick file (preview, keys redacted)</summary>
                <pre className="mt-2 max-h-64 overflow-auto whitespace-pre font-mono text-[11px] leading-relaxed text-zinc-600 dark:text-zinc-300">{s.plan.files[0].conf}</pre>
              </details>
            )}

            {props.applying && (
              <div role="status" aria-live="polite" className="flex flex-wrap items-center gap-2 rounded-lg border border-zinc-200 px-3 py-2 text-xs dark:border-zinc-800">
                <Icons.LoaderCircle className="h-3.5 w-3.5 animate-spin text-zinc-500" />
                <span className="font-medium">Applying</span>
                <span className="text-zinc-400">snapshot → write → wg-quick strip validation → rollback timer…</span>
              </div>
            )}
          </div>
        )}

        <DialogFooter>
          <Button variant="ghost" onClick={() => props.onOpenChange(false)}>
            {props.outcome ? "Close" : "Cancel"}
          </Button>
          {!props.outcome && (
            <Button onClick={props.onApply} disabled={props.applying || s?.gate === "off" || !s?.available} className="bg-zinc-700 text-white hover:bg-zinc-800">
              {props.applying ? "Applying…" : "Apply now"}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── bring-up dialog (double confirmation — traffic affecting) ───────────────

function SdwanUpDialog(props: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  status: SdwanOsStatus | undefined;
  bringingUp: boolean;
  outcome: SdwanOsUpDownOutcome | null;
  error: string | null;
  onUp: () => void;
}) {
  const [bringUp, setBringUp] = useState(false);
  const s = props.status;
  const canUp = s?.gate === "on" && s?.available === true && bringUp === true && (s?.drift.appliedFiles ?? 0) > 0;
  return (
    <Dialog
      open={props.open}
      onOpenChange={(o) => {
        props.onOpenChange(o);
        if (!o) setBringUp(false);
      }}
    >
      <DialogContent className="max-h-[85vh] max-w-xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Icons.Play className="h-5 w-5" /> Bring up SD-WAN tunnels
          </DialogTitle>
          <DialogDescription>
            Runs <code className="rounded bg-zinc-100 px-1 dark:bg-zinc-800">wg-quick up utm-sdwan-&lt;overlay&gt;</code>{" "}
            for enabled overlays whose config files were applied. This affects live tunnel traffic — it never happens
            automatically and requires the explicit bring-up confirmation below. A successful up also confirms the
            pending apply window.
          </DialogDescription>
        </DialogHeader>

        {props.outcome ? (
          props.error && !props.outcome ? (
            <Alert variant="destructive">
              <Icons.CircleX className="h-4 w-4" />
              <AlertTitle>Bring up failed</AlertTitle>
              <AlertDescription className="text-xs">{props.error}</AlertDescription>
            </Alert>
          ) : (
            <div className="rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
              <p className="text-[10px] font-semibold uppercase tracking-wide text-zinc-400">Bring-up steps</p>
              <ul className="mt-1.5 space-y-1">
                {props.outcome.results.map((r, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs">
                    {r.ok ? <Icons.CircleCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-500" /> : <Icons.CircleX className="mt-0.5 h-3.5 w-3.5 shrink-0 text-rose-500" />}
                    <span className="min-w-0">
                      <span className="font-medium">{r.step}</span>
                      {r.detail ? <span className="block break-words font-mono text-[11px] text-zinc-500">{r.detail}</span> : null}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )
        ) : (
          <div className="space-y-3">
            <div className="flex flex-wrap gap-1.5 text-[11px]">
              <FactChip ok={s?.gate === "on"} label={s?.gate === "on" ? `OS apply armed (${s?.mode ?? "?"})` : "OS apply disabled — preview only"} />
              <FactChip ok={(s?.drift.appliedFiles ?? 0) > 0} label={(s?.drift.appliedFiles ?? 0) > 0 ? `${s?.drift.appliedFiles} config file(s) installed` : "apply first — no config files installed"} />
              <FactChip ok={s?.keySource !== "absent"} label={s?.keySource === "absent" ? "no private key source — up will fail" : `private key source: ${s?.keySource ?? "?"}`} />
            </div>
            {(s?.plan.files ?? []).filter((f) => f.warnings.some((w) => w.code === "iface-name-too-long" || w.code === "generated-on-apply")).length > 0 && (
              <Alert className="border-amber-500/50 bg-amber-500/5">
                <Icons.TriangleAlert className="h-4 w-4 text-amber-500" />
                <AlertTitle className="text-amber-600 dark:text-amber-400">Some overlays cannot come up yet</AlertTitle>
                <AlertDescription className="text-xs">
                  Interfaces longer than 15 characters (IFNAMSIZ) or peers without a recorded public key will make
                  wg-quick refuse the tunnel — check the plan warnings before bringing up.
                </AlertDescription>
              </Alert>
            )}
            <div className="flex items-center justify-between gap-3 rounded-md border border-zinc-200 p-3 dark:border-zinc-800">
              <div className="text-xs">
                <p className="font-medium">Confirm bring-up</p>
                <p className="text-zinc-500 dark:text-zinc-400">Tunnel traffic will switch to the overlay interfaces.</p>
              </div>
              <Switch checked={bringUp} onCheckedChange={setBringUp} aria-label="Confirm bringing tunnels up" />
            </div>
            {props.bringingUp && (
              <div role="status" aria-live="polite" className="flex flex-wrap items-center gap-2 rounded-lg border border-zinc-200 px-3 py-2 text-xs dark:border-zinc-800">
                <Icons.LoaderCircle className="h-3.5 w-3.5 animate-spin text-zinc-500" />
                <span className="font-medium">Bringing up</span>
                <span className="text-zinc-400">wg-quick up per managed interface…</span>
              </div>
            )}
          </div>
        )}

        <DialogFooter>
          <Button variant="ghost" onClick={() => props.onOpenChange(false)}>
            {props.outcome ? "Close" : "Cancel"}
          </Button>
          {!props.outcome && (
            <Button onClick={props.onUp} disabled={props.bringingUp || !canUp} className="bg-zinc-700 text-white hover:bg-zinc-800">
              {props.bringingUp ? "Bringing up…" : "Bring up now"}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ApplyOutcomeView(props: { outcome: SdwanOsApplyOutcome | null; error: string | null }) {
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
          OS convergence is disabled by platform policy on this installation (CONSOLE_OS_APPLY). The plan was generated
          but no files were written.
        </AlertDescription>
      </Alert>
    );
  }
  if (o.rolledBack) {
    return (
      <Alert variant="destructive">
        <Icons.RotateCcw className="h-4 w-4" />
        <AlertTitle>Applied, then rolled back automatically</AlertTitle>
        <AlertDescription className="text-xs">{o.rollbackReason}</AlertDescription>
      </Alert>
    );
  }
  return (
    <>
      <Alert className="border-emerald-500/40 bg-emerald-500/5">
        <Icons.ShieldCheck className="h-4 w-4 text-emerald-500" />
        <AlertTitle className="text-emerald-600 dark:text-emerald-400">Overlay configs are on the host</AlertTitle>
        <AlertDescription className="text-xs">
          Commit-confirm window: {o.confirmDeadlineAt ? `${o.confirmSec}s — confirm in the panel banner to keep the files` : "closed"}.{" "}
          Config files were written and validated with wg-quick strip — no tunnel was brought up.
        </AlertDescription>
      </Alert>
      <div className="rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
        <p className="text-[10px] font-semibold uppercase tracking-wide text-zinc-400">Apply steps</p>
        <ul className="mt-1.5 space-y-1">
          {o.results.map((r, i) => (
            <li key={i} className="flex items-start gap-2 text-xs">
              {r.ok ? <Icons.CircleCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-500" /> : <Icons.CircleX className="mt-0.5 h-3.5 w-3.5 shrink-0 text-rose-500" />}
              <span className="min-w-0">
                <span className="font-medium">{r.step}</span>
                {r.detail ? <span className="block break-words font-mono text-[11px] text-zinc-500">{r.detail}</span> : null}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </>
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
