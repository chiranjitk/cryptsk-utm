"use client";

/**
 * M19 OS-apply panel (FRR appliance) — live integration card for the dynamic
 * routing module: availability/service state, conf-hash drift vs the last
 * applied apply, daemon-set mismatch, rendered frr.conf preview, `vtysh -C -f`
 * validation and the gated Apply (CONSOLE_OS_APPLY=1 + host mode executes;
 * otherwise plan preview only). Commands run through the anchored whitelist —
 * no vtysh configure/write path exists.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ConfirmDialog, QueryError, toastErr, toastOk } from "@/components/views/firewall/fw-ui";
import { useState } from "react";
import { drApi, type DrApplyOutcomeDTO, type DrValidateResultDTO } from "./dynamic-routing-api";

const OS_KEY = ["dynamic-routing", "os"] as const;

function DaemonChips({
  daemonSet,
  liveDaemonSet,
}: {
  daemonSet: Record<string, boolean>;
  liveDaemonSet: Record<string, boolean> | null;
}) {
  const keys = ["zebra", "bgpd", "ospfd", "bfdd"];
  return (
    <div className="flex flex-wrap gap-1.5">
      {keys.map((k) => {
        const want = daemonSet[k] === true;
        const live = liveDaemonSet ? liveDaemonSet[k] === true : null;
        const mismatch = live !== null && live !== want;
        return (
          <Badge
            key={k}
            variant="outline"
            className={
              mismatch
                ? "border-amber-500/40 bg-amber-500/10 font-mono text-amber-600 dark:text-amber-400"
                : want
                  ? "border-emerald-500/40 bg-emerald-500/10 font-mono text-emerald-600 dark:text-emerald-400"
                  : "border-zinc-500/30 bg-zinc-500/10 font-mono text-zinc-500"
            }
          >
            {k}={want ? "yes" : "no"}
            {live !== null && live !== want ? ` (live ${live ? "yes" : "no"})` : ""}
          </Badge>
        );
      })}
    </div>
  );
}

function ApplyResults({ outcome }: { outcome: DrApplyOutcomeDTO }) {
  return (
    <div className="space-y-2 rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
      <p className="text-sm font-medium">
        {outcome.applied ? "Apply completed" : outcome.refused ? "Plan preview" : "Apply failed"}
        {outcome.skipped ? " (zero-churn — nothing touched)" : ""}
      </p>
      {outcome.reason ? <p className="text-xs text-zinc-500">{outcome.reason}</p> : null}
      {outcome.refused ? <p className="text-xs text-amber-600 dark:text-amber-400">{outcome.refused}</p> : null}
      <ul className="space-y-1">
        {outcome.results.map((r, i) => (
          <li key={`${r.step}-${i}`} className="flex items-start gap-2 text-xs">
            {r.ok ? (
              <Icons.CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-600 dark:text-emerald-400" />
            ) : (
              <Icons.XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-rose-600 dark:text-rose-400" />
            )}
            <span className="font-medium">{r.step}</span>
            {r.detail ? <span className="min-w-0 flex-1 truncate text-zinc-500">{r.detail}</span> : null}
          </li>
        ))}
      </ul>
      {outcome.rolledBack ? (
        <p className="text-xs text-amber-600 dark:text-amber-400">auto-rollback restored the previous frr.conf + daemons and restarted frr</p>
      ) : null}
    </div>
  );
}

export function OsApplyPanel() {
  const qc = useQueryClient();
  const [validateResult, setValidateResult] = useState<DrValidateResultDTO | null>(null);
  const [applyResult, setApplyResult] = useState<DrApplyOutcomeDTO | null>(null);
  const [confirmApply, setConfirmApply] = useState(false);
  const [showConf, setShowConf] = useState(false);

  const statusQ = useQuery({ queryKey: OS_KEY, queryFn: drApi.getOsStatus });

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ["dynamic-routing"] });
  };

  const validateMut = useMutation({
    mutationFn: drApi.validateOs,
    onSuccess: (r) => {
      setValidateResult(r);
      toastOk(
        r.ok ? "Validation passed" : r.ok === false ? "Validation failed" : "Validation unavailable",
        r.detail,
      );
    },
    onError: (err) => toastErr(err, "Validation failed"),
  });

  const applyMut = useMutation({
    mutationFn: drApi.applyOs,
    onSuccess: (r) => {
      setApplyResult(r);
      invalidate();
      toastOk(
        r.applied ? (r.skipped ? "Already in sync" : "FRR conf applied") : "Apply not executed",
        r.applied ? r.reason : r.refused ?? r.reason,
      );
    },
    onError: (err) => toastErr(err, "Apply failed"),
  });

  const s = statusQ.data;
  const gateOn = s?.gateOn === true;

  return (
    <Card>
      <CardHeader className="pb-4">
        <CardTitle className="flex items-center gap-2 text-base">
          <Icons.Server className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
          FRR appliance (OS layer)
        </CardTitle>
        <CardDescription>
          Renders BGP/OSPF/policy/BFD config into /etc/frr/frr.conf + /etc/frr/daemons — validate-first apply with
          backup and auto-rollback. Static routes stay kernel-managed by the routes module.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {statusQ.isLoading ? (
          <p className="text-sm text-zinc-500">Reading OS status…</p>
        ) : statusQ.isError ? (
          <QueryError error={statusQ.error} onRetry={() => void statusQ.refetch()} />
        ) : s ? (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <Badge
                variant="outline"
                className={
                  s.available
                    ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                    : "border-zinc-500/30 bg-zinc-500/10 text-zinc-500"
                }
              >
                {s.available ? `frr available · ${s.serviceState ?? "unknown"}` : "frr not available"}
              </Badge>
              <Badge variant="outline" className="border-zinc-500/30 bg-zinc-500/10 font-mono text-zinc-500">
                data plane: {s.dataPlaneMode}
              </Badge>
              <Badge
                variant="outline"
                className={
                  gateOn
                    ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                    : "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400"
                }
              >
                CONSOLE_OS_APPLY={gateOn ? "1 (exec)" : "off (plan preview)"}
              </Badge>
              {s.inSync !== null ? (
                <Badge
                  variant="outline"
                  className={
                    s.inSync
                      ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                      : "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400"
                  }
                >
                  {s.inSync ? "in sync" : "drifted"}
                </Badge>
              ) : null}
              {s.managedByConsole ? (
                <Badge variant="outline" className="border-zinc-500/30 bg-zinc-500/10 font-mono text-zinc-500">
                  managed · hash {s.expectedConfHash}
                </Badge>
              ) : null}
            </div>

            {s.driftReasons.length > 0 ? (
              <ul className="space-y-1 rounded-lg border border-rose-500/30 bg-rose-500/5 p-3">
                {s.driftReasons.map((r) => (
                  <li key={r} className="flex items-start gap-2 text-xs text-rose-600 dark:text-rose-400">
                    <Icons.AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                    {r}
                  </li>
                ))}
              </ul>
            ) : null}

            <div className="space-y-2">
              <DaemonChips daemonSet={s.daemonSet} liveDaemonSet={s.liveDaemonSet} />
              <p className="text-xs text-zinc-500">
                live frr.conf hash: <span className="font-mono">{s.liveConfHash ?? "missing"}</span> · expected:{" "}
                <span className="font-mono">{s.expectedConfHash}</span>
                {s.state ? (
                  <>
                    {" "}
                    · state.json applied at <span className="font-mono">{s.state.appliedAt}</span>
                  </>
                ) : null}
              </p>
              <p className="text-xs text-zinc-500">{s.note}</p>
            </div>

            {s.warnings.length > 0 ? (
              <ul className="space-y-1">
                {s.warnings.map((w) => (
                  <li key={w} className="text-xs text-amber-600 dark:text-amber-400">
                    {w}
                  </li>
                ))}
              </ul>
            ) : null}

            <div className="flex flex-wrap items-center gap-2">
              <Button
                variant="outline"
                className="gap-1.5"
                disabled={validateMut.isPending}
                onClick={() => validateMut.mutate()}
              >
                <Icons.ShieldCheck className={validateMut.isPending ? "h-4 w-4 animate-pulse" : "h-4 w-4"} />
                Validate (vtysh -C)
              </Button>
              <Button
                className="gap-1.5 bg-zinc-700 text-white hover:bg-zinc-800"
                disabled={applyMut.isPending}
                onClick={() => setConfirmApply(true)}
              >
                <Icons.UploadCloud className="h-4 w-4" />
                {gateOn ? "Apply to appliance" : "Preview apply plan"}
              </Button>
              <Button variant="ghost" className="gap-1.5" onClick={() => setShowConf((v) => !v)}>
                <Icons.FileCode className="h-4 w-4" />
                {showConf ? "Hide frr.conf" : "Show frr.conf"}
              </Button>
            </div>

            {validateResult ? (
              <div className="space-y-1 rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
                <p className="text-sm font-medium">
                  {validateResult.ok === true ? "vtysh -C parse passed" : validateResult.ok === false ? "vtysh -C parse FAILED" : "validation unavailable"}
                  <span className="ml-2 font-mono text-xs text-zinc-500">hash {validateResult.confHash}</span>
                </p>
                <p className="text-xs text-zinc-500">{validateResult.detail}</p>
              </div>
            ) : null}

            {applyResult ? <ApplyResults outcome={applyResult} /> : null}

            {showConf ? (
              <pre className="max-h-96 overflow-auto rounded-lg border border-zinc-200 bg-zinc-50 p-3 font-mono text-[11px] leading-relaxed text-zinc-700 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300">
                {s.confPreview}
              </pre>
            ) : null}

            <p className="text-xs text-zinc-400">{s.simulatedSessionNote}</p>
          </>
        ) : null}
      </CardContent>

      <ConfirmDialog
        open={confirmApply}
        onOpenChange={(open) => {
          if (!open) setConfirmApply(false);
        }}
        title={gateOn ? "Converge FRR on the appliance?" : "Preview apply plan?"}
        description={
          gateOn
            ? "Backs up /etc/frr/frr.conf + /etc/frr/daemons, validates the staged conf with vtysh -C, installs and reloads (restart on daemon-set change). Failures auto-restore the backup."
            : "CONSOLE_OS_APPLY is off — the rendered conf and the exact command sequence are returned without touching the appliance."
        }
        loading={applyMut.isPending}
        onConfirm={() => {
          setConfirmApply(false);
          applyMut.mutate();
        }}
      />
    </Card>
  );
}
