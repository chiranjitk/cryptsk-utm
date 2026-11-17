"use client";

/**
 * AppControlOsApply — the App Control GUI↔nftables integration surface.
 *
 *   • sync badge — In sync / Drift / Not applied / Preview-only, with the OS
 *     facts on hover (nft version, data-plane mode, table presence) and the
 *     enforceability warnings (DPI-required skips, shared-443 port classes…)
 *   • Apply to Host dialog — plan preview (statement counts, warnings, skipped
 *     apps, generated file) → commit-confirm apply backed by the OS
 *     backup/rollback engine on the dedicated `inet utm_appctl` table
 *   • pending commit-confirm banner — countdown with Confirm / Rollback now
 *
 * Mount: under the rules table in app-control-view (write-capable roles only —
 * super_admin / tenant_admin / security_admin; read-only badge otherwise).
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
import * as Icons from "lucide-react";
import { cn } from "@/lib/utils";
import {
  appControlApi,
  type AppctlApplyOutcome,
  type AppctlOsStatus,
  type AppctlWarning,
} from "./app-control-api";
import { toastErr, toastOk } from "../firewall/fw-ui";

/** Roles allowed to mutate (mirror of the RBAC matrix app_control write column). */
const OS_WRITE_ROLES = new Set(["super_admin", "tenant_admin", "security_admin"]);

const OS_KEY = ["app-control", "os-status"];
const ME_KEY = ["auth", "me"];

function badgeFor(s: AppctlOsStatus | undefined): { label: string; cls: string } {
  if (!s) return { label: "OS status…", cls: "border-zinc-300 text-zinc-500 dark:border-zinc-700" };
  if (!s.available) return { label: "nft unavailable", cls: "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400" };
  if (s.gate === "off") return { label: "Preview only", cls: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300" };
  if (s.pendingConfirm) return { label: "Unconfirmed apply", cls: "border-amber-500/50 bg-amber-500/10 text-amber-600 dark:text-amber-400" };
  if (!s.drift.applied) return { label: "Not applied to OS", cls: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300" };
  if (s.drift.inSync) return { label: "In sync with OS", cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400" };
  return { label: "Drift", cls: "border-amber-500/50 bg-amber-500/10 text-amber-600 dark:text-amber-400" };
}

// ── main component ──────────────────────────────────────────────────────────

export function AppControlOsApply() {
  const queryClient = useQueryClient();
  const [applyOpen, setApplyOpen] = useState(false);
  const [now, setNow] = useState(Date.now());

  const status = useQuery<AppctlOsStatus>({
    queryKey: OS_KEY,
    queryFn: () => appControlApi.getOsStatus(),
    refetchInterval: 30000,
  });

  // write-capable roles only — the panel mirrors the RBAC matrix
  const me = useQuery({
    queryKey: ME_KEY,
    queryFn: async () => {
      const res = await fetch("/api/v1/auth/me", { credentials: "same-origin" });
      return (await res.json()) as { data?: { role?: string } };
    },
    staleTime: 60_000,
  });
  const canApply = OS_WRITE_ROLES.has(me.data?.data?.role ?? "");

  const data = status.data;
  const badge = badgeFor(data);
  const hardWarnings = useMemo(
    () => (data?.warnings ?? []).filter((w) => w.code !== "limit-tc-required" && w.code !== "port-shared"),
    [data],
  );

  // 1s tick while a commit-confirm window is open (countdown)
  useEffect(() => {
    if (!data?.pendingConfirm) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [data?.pendingConfirm]);

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: OS_KEY });

  const applyMut = useMutation({
    mutationFn: () => appControlApi.applyToOs({ action: "apply", mode: "manual" }),
    onSuccess: (res) => {
      if (res.rolledBack) toastErr(new Error(res.rollbackReason ?? "rolled back"), "Apply rolled back");
      else if (res.gate === "off") toastOk("Plan generated", "OS apply is disabled on this installation — preview only");
      else toastOk("App-control policy applied to host", res.confirmDeadlineAt ? `Confirm within ${res.confirmSec}s to keep it` : undefined);
      invalidate();
    },
    onError: (err) => toastErr(err, "Apply failed"),
  });

  const confirmMut = useMutation({
    mutationFn: (ts: string) => appControlApi.confirmApply(ts),
    onSuccess: () => {
      toastOk("Commit confirmed", "Rollback timer cancelled — policy is live");
      invalidate();
    },
    onError: (err) => toastErr(err, "Confirm failed"),
  });

  const rollbackMut = useMutation({
    mutationFn: () => appControlApi.rollback(),
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
    <Card className="border-dashed">
      <CardHeader className="flex flex-col gap-2 space-y-0 pb-3 sm:flex-row sm:flex-wrap sm:items-center sm:justify-between">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.HardDrive className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
          OS enforcement
          <Badge variant="outline" className={cn("gap-1.5 font-normal", badge.cls)}>
            {badge.label}
          </Badge>
          <span className="hidden text-xs font-normal text-zinc-400 lg:inline">
            table <code className="rounded bg-zinc-100 px-1 dark:bg-zinc-800">inet utm_appctl</code> ·{" "}
            {data?.counts.statements ?? 0} statements
            {hardWarnings.length > 0 && (
              <span className="text-amber-500">
                {" "}
                · {hardWarnings.length} warning{hardWarnings.length === 1 ? "" : "s"}
              </span>
            )}
          </span>
        </CardTitle>
        {canApply && (
          <Button size="sm" variant="outline" className="h-8 text-xs" onClick={() => setApplyOpen(true)} title="Apply app-control port classes to the host (nftables)">
            <Icons.UploadCloud className="mr-1 h-3.5 w-3.5" /> Apply to host
          </Button>
        )}
      </CardHeader>
      <CardContent className="space-y-3 p-4 pt-0">
        {/* commit-confirm banner */}
        {pending && canApply && (
          <Alert className="border-amber-500/50 bg-amber-500/5">
            <Icons.TriangleAlert className="h-4 w-4 text-amber-500" />
            <AlertTitle className="text-amber-600 dark:text-amber-400">
              App-control policy is live but unconfirmed — auto-rollback in {remainSec}s
            </AlertTitle>
            <AlertDescription className="flex flex-wrap items-center gap-2 text-xs">
              <span>If the host misbehaves, the previous ruleset will be restored automatically from backup.</span>
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
            <FactChip ok={data.available} label={`nft ${data.nftVersion?.split(" ")[1] ?? ""}`} />
            <FactChip ok={data.tablePresent} label={data.tablePresent ? "utm_appctl table present" : "table not yet applied"} />
            <FactChip ok={data.drift.inSync} label={data.drift.inSync ? "normalized compare: match" : data.drift.reasons[0] || "drift"} />
            <FactChip ok={data.gate === "on"} label={data.gate === "on" ? `OS apply armed (${data.mode})` : "OS apply disabled — preview only"} />
            {data.counts.skipped > 0 && <FactChip ok={false} label={`${data.counts.skipped} DPI-only rule${data.counts.skipped === 1 ? "" : "s"} skipped`} />}
          </div>
        )}

        {hardWarnings.length > 0 && (
          <div className="rounded-md border border-amber-500/40">
            <div className="border-b border-amber-500/30 bg-amber-500/5 px-3 py-1.5 text-xs font-medium text-amber-600 dark:text-amber-400">
              {hardWarnings.length} enforceability warning{hardWarnings.length === 1 ? "" : "s"} — skipped rules stay config-only (never silently widened):
            </div>
            <ScrollArea className="max-h-32">
              <ul className="space-y-1 p-3 text-xs">
                {hardWarnings.map((w, i) => (
                  <li key={i} className="text-zinc-600 dark:text-zinc-300">
                    <span className="font-medium">{w.scope === "rule" ? `rule '${w.name}'` : `policy '${w.name}'`}:</span> {w.message}
                  </li>
                ))}
              </ul>
            </ScrollArea>
          </div>
        )}

        <AppctlApplyDialog
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
      </CardContent>
    </Card>
  );
}

// ── apply dialog ────────────────────────────────────────────────────────────

function AppctlApplyDialog(props: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  status: AppctlOsStatus | undefined;
  applying: boolean;
  outcome: AppctlApplyOutcome | null;
  error: string | null;
  onApply: () => void;
}) {
  const s = props.status;
  const warnings = s?.warnings ?? [];
  const ruleWarnings = warnings.filter((w) => w.scope === "rule");

  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent className="max-h-[85vh] max-w-2xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Icons.HardDriveDownload className="h-5 w-5" /> Apply app-control policy to host
          </DialogTitle>
          <DialogDescription>
            Generates the nftables <code className="rounded bg-zinc-100 px-1 dark:bg-zinc-800">inet utm_appctl</code> table,
            verifies it with <code className="rounded bg-zinc-100 px-1 dark:bg-zinc-800">nft -c</code>, snapshots a full-ruleset
            backup, applies atomically, then verifies WAN health. An automatic rollback timer restores the previous ruleset
            unless you confirm. Only the utm_appctl table is touched — console-firewall and fail2ban survive every apply.
          </DialogDescription>
        </DialogHeader>

        {props.outcome ? (
          <ApplyOutcomeView outcome={props.outcome} error={props.error} />
        ) : (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
              <PlanStat label="Policies" value={String(s?.counts.policies ?? 0)} />
              <PlanStat label="Rules" value={String(s?.counts.rules ?? 0)} />
              <PlanStat label="nft statements" value={String(s?.counts.statements ?? 0)} />
              <PlanStat label="DPI-only skipped" value={String(s?.counts.skipped ?? 0)} warn={(s?.counts.skipped ?? 0) > 0} />
            </div>

            <div className="flex flex-wrap gap-1.5 text-[11px]">
              <FactChip ok={!!s?.available} label={`nft ${s?.nftVersion?.split(" ")[1] ?? ""}`} />
              <FactChip ok={s?.tablePresent ?? false} label={s?.tablePresent ? "table present" : "table not yet applied"} />
              <FactChip ok={s?.gate === "on"} label={s?.gate === "on" ? `OS apply armed (${s?.mode ?? "?"})` : "OS apply disabled — preview only"} />
              {s?.counters.length ? <FactChip ok={true} label={`${s.counters.length} live rule counter${s.counters.length === 1 ? "" : "s"}`} /> : null}
            </div>

            {ruleWarnings.length > 0 && (
              <div className="rounded-md border border-amber-500/40">
                <div className="border-b border-amber-500/30 bg-amber-500/5 px-3 py-1.5 text-xs font-medium text-amber-600 dark:text-amber-400">
                  {ruleWarnings.length} enforceability warning{ruleWarnings.length === 1 ? "" : "s"}:
                </div>
                <ScrollArea className="max-h-40">
                  <ul className="space-y-1 p-3 text-xs">
                    {ruleWarnings.map((w: AppctlWarning, i) => (
                      <li key={i} className="text-zinc-600 dark:text-zinc-300">
                        <span className="font-medium">rule &apos;{w.name}&apos;:</span> {w.message}
                      </li>
                    ))}
                  </ul>
                </ScrollArea>
              </div>
            )}

            {s?.file && (
              <details className="rounded-md border border-zinc-200 p-2 text-xs dark:border-zinc-800">
                <summary className="cursor-pointer font-medium text-zinc-500 dark:text-zinc-400">Generated nft file (preview)</summary>
                <pre className="mt-2 max-h-64 overflow-auto whitespace-pre font-mono text-[11px] leading-relaxed text-zinc-600 dark:text-zinc-300">{s.file}</pre>
              </details>
            )}

            {props.applying && (
              <div role="status" aria-live="polite" className="flex flex-wrap items-center gap-2 rounded-lg border border-zinc-200 px-3 py-2 text-xs dark:border-zinc-800">
                <Icons.LoaderCircle className="h-3.5 w-3.5 animate-spin text-zinc-500" />
                <span className="font-medium">Applying</span>
                <span className="text-zinc-400">validate → backup → converge → kernel status…</span>
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

function ApplyOutcomeView(props: { outcome: AppctlApplyOutcome | null; error: string | null }) {
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
          OS convergence is disabled by platform policy on this installation (CONSOLE_OS_APPLY). The generated plan was
          validated but the kernel was not touched.
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
        <AlertTitle className="text-emerald-600 dark:text-emerald-400">App-control policy is live on the host</AlertTitle>
        <AlertDescription className="text-xs">
          Commit-confirm window: {o.confirmDeadlineAt ? `${o.confirmSec}s — confirm in the panel banner to keep the policy` : "self-confirmed"}.
          WAN health verified after apply.
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
          {o.persistence.map((r, i) => (
            <li key={`p${i}`} className="flex items-start gap-2 text-xs">
              {r.ok ? <Icons.CircleCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-500" /> : <Icons.TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-500" />}
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
