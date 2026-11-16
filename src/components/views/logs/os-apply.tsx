"use client";

/**
 * Syslog OS forwarding panel (M09 §4) — mirrors the QoS OsApplyPanel pattern:
 * live rsyslog state per syslog target (expected render hash vs managed-file
 * hash + unit state, socket reachability as an informational dot), drift
 * reasons, plan preview when the CONSOLE_OS_APPLY gate is off, and an
 * admin-gated "Apply to OS" action. Execution is snapshot-first with
 * auto-restore on the server; here we only surface the outcome.
 */

import * as Icons from "lucide-react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { toastErr, toastOk } from "../firewall/fw-ui";
import { cn } from "@/lib/utils";
import { logsApi, type LogsApplyResultDTO, type LogsOsStatusDTO, type LogsOsTargetStatus } from "./logs-api";

function SyncBadge({ target }: { target: LogsOsTargetStatus }) {
  if (!target.enabled) {
    return (
      <Badge variant="outline" className="border-zinc-300 text-zinc-500 dark:border-zinc-700">
        disabled
      </Badge>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 font-mono text-[10px] text-zinc-400" title="sha256-16 of the rendered action line">
      {target.renderHash ?? "—"}
    </span>
  );
}

function TargetOsRow({ target }: { target: LogsOsTargetStatus }) {
  return (
    <div className="rounded-lg border border-zinc-200 px-3 py-2.5 dark:border-zinc-800">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-zinc-700 dark:text-zinc-200">{target.name}</span>
          <span className="font-mono text-xs text-zinc-500">
            {target.host}:{target.port}
          </span>
          <Badge variant="outline" className="border-zinc-500/30 bg-zinc-500/10 text-[11px] uppercase text-zinc-600 dark:text-zinc-300">
            {target.protocol}
          </Badge>
          <span className="text-xs capitalize text-zinc-500">≥ {target.minSeverity}</span>
          {target.enabled ? (
            <span
              className={cn(
                "inline-block h-1.5 w-1.5 rounded-full",
                target.socketConnected === true
                  ? "bg-emerald-500"
                  : target.socketConnected === false
                    ? "bg-amber-500"
                    : "bg-zinc-400",
              )}
              title={
                target.socketConnected === true
                  ? "omfwd socket to the collector is up (informational)"
                  : target.socketConnected === false
                    ? "no omfwd socket yet — rows are buffering (informational)"
                    : "socket state unknown"
              }
            />
          ) : null}
        </div>
        <SyncBadge target={target} />
      </div>
    </div>
  );
}

function ApplyResult({ result }: { result: LogsApplyResultDTO }) {
  return (
    <div className="space-y-1.5">
      {result.results.map((r, i) => (
        <div key={i} className="flex items-start justify-between gap-2 text-xs">
          <span className="flex items-center gap-1.5 text-zinc-600 dark:text-zinc-300">
            {r.ok ? (
              <Icons.CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-emerald-500" aria-hidden />
            ) : (
              <Icons.XCircle className="h-3.5 w-3.5 shrink-0 text-rose-500" aria-hidden />
            )}
            {r.step}
          </span>
          <span className={cn("max-w-[60%] truncate font-mono text-[10px]", r.ok ? "text-zinc-400" : "text-rose-500")} title={r.detail}>
            {r.detail ?? ""}
          </span>
        </div>
      ))}
      {result.rolledBack ? (
        <p className="mt-1 flex items-center gap-1.5 text-xs text-amber-600 dark:text-amber-400">
          <Icons.Undo2 className="h-3.5 w-3.5" aria-hidden />
          Auto-restore: the pre-apply managed file was re-installed and rsyslog restarted.
        </p>
      ) : null}
      {result.backupDir && !result.applied ? (
        <p className="font-mono text-[10px] text-zinc-400">backup: {result.backupDir}</p>
      ) : null}
    </div>
  );
}

export function LogsOsPanel({ isAdmin }: { isAdmin: boolean }) {
  const queryClient = useQueryClient();
  const status = useQuery<LogsOsStatusDTO>({
    queryKey: ["logs", "os-status"],
    queryFn: logsApi.getOsStatus,
    staleTime: 10_000,
  });

  const apply = useMutation({
    mutationFn: () => logsApi.applyToOs(),
    onSuccess: (d: LogsApplyResultDTO) => {
      if (d.refused) {
        toastErr(new Error(d.refused), "Apply refused");
      } else if (d.applied) {
        toastOk(d.skipped ? "Already in sync" : "Syslog forwarding applied", d.reason ?? "rsyslog converged");
      } else {
        toastErr(new Error(d.reason ?? "apply failed"), d.rolledBack ? "Restored" : "Apply failed");
      }
      void queryClient.invalidateQueries({ queryKey: ["logs"] });
    },
    onError: (err) => toastErr(err, "Apply failed"),
  });

  const os = status.data;
  const hasTargets = (os?.targets.length ?? 0) > 0;

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between space-y-0">
        <div className="space-y-1">
          <CardTitle className="flex items-center gap-2 text-base">
            <Icons.ServerCog className="h-4.5 w-4.5 text-zinc-500 dark:text-zinc-400" />
            OS forwarding (rsyslog)
          </CardTitle>
          <CardDescription>
            {os?.note ?? "Loading rsyslog forwarding state…"}
            {os?.state ? ` · hash ${os.state.confHash.slice(0, 8)} · applied ${os.state.appliedAt.replace("T", " ").slice(0, 16)}` : ""}
            {os?.unitState ? ` · unit ${os.unitState}` : ""}
          </CardDescription>
        </div>
        <div className="flex items-center gap-2">
          {os ? (
            <Badge
              variant="outline"
              className={cn(
                os.available
                  ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                  : "border-zinc-300 text-zinc-500 dark:border-zinc-700",
              )}
            >
              {os.available ? "rsyslog ready" : `preview only (${os.dataPlaneMode})`}
            </Badge>
          ) : null}
          {os && os.available ? (
            <Badge
              variant="outline"
              className={cn(
                os.inSync
                  ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                  : "border-rose-500/30 bg-rose-500/10 text-rose-600 dark:text-rose-400",
              )}
            >
              <span
                className={cn(
                  "mr-1 inline-block h-1.5 w-1.5 rounded-full",
                  os.inSync ? "bg-emerald-500" : "bg-rose-500",
                )}
                aria-hidden
              />
              {os.inSync ? "in sync" : "drift"}
            </Badge>
          ) : null}
          <Button
            size="sm"
            variant="outline"
            className="bg-zinc-700 text-white hover:bg-zinc-800"
            onClick={() => apply.mutate()}
            disabled={apply.isPending || status.isLoading || !isAdmin}
          >
            {apply.isPending ? (
              <Icons.Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
            ) : (
              <Icons.ServerCog className="mr-1.5 h-3.5 w-3.5" />
            )}
            Apply to OS
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {!isAdmin ? (
          <p className="flex items-center gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-400">
            <Icons.Lock className="h-3.5 w-3.5 shrink-0" aria-hidden />
            Read-only — applying to the OS requires the forwarding write role.
          </p>
        ) : null}

        {status.isError ? (
          <p className="flex items-center gap-2 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-600 dark:text-rose-400">
            <Icons.AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden />
            OS status unavailable — {(status.error as Error)?.message ?? "unknown error"}
          </p>
        ) : null}

        {os && !hasTargets ? (
          <p className="rounded-lg border border-dashed border-zinc-300 px-3 py-2 text-xs text-zinc-500 dark:border-zinc-700">
            No syslog targets — add one above; Apply writes /etc/rsyslog.d/99-utm-console.conf (one omfwd action per enabled target).
          </p>
        ) : null}

        {os?.targets.map((t) => <TargetOsRow key={t.id} target={t} />)}

        {os && os.driftReasons.length > 0 ? (
          <ul className="space-y-0.5" role="list">
            {os.driftReasons.slice(0, 4).map((r, i) => (
              <li key={i} className="flex items-start gap-1.5 text-xs text-rose-600 dark:text-rose-400">
                <Icons.AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" aria-hidden />
                {r}
              </li>
            ))}
          </ul>
        ) : null}

        {os && os.warnings.length > 0 ? (
          <Collapsible>
            <CollapsibleTrigger className="flex items-center gap-1.5 text-xs text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300">
              <Icons.ChevronRight className="h-3.5 w-3.5 transition-transform [[data-state=open]>&]:rotate-90" aria-hidden />
              {os.warnings.length} renderer note{os.warnings.length === 1 ? "" : "s"} (tls driver, disabled targets)
            </CollapsibleTrigger>
            <CollapsibleContent>
              <ul className="mt-1.5 max-h-40 space-y-1 overflow-y-auto rounded-lg border border-zinc-200 bg-zinc-50 p-2 dark:border-zinc-800 dark:bg-zinc-900" role="list">
                {os.warnings.map((w, i) => (
                  <li key={i} className="font-mono text-[10px] leading-relaxed text-zinc-500 dark:text-zinc-400">
                    {w}
                  </li>
                ))}
              </ul>
            </CollapsibleContent>
          </Collapsible>
        ) : null}

        {apply.data && apply.data.results.length > 0 ? (
          <div className="rounded-lg border border-zinc-200 px-3 py-2.5 dark:border-zinc-800">
            <p className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-zinc-700 dark:text-zinc-200">
              {apply.data.applied ? (
                <Icons.CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" aria-hidden />
              ) : apply.data.refused ? (
                <Icons.Ban className="h-3.5 w-3.5 text-amber-500" aria-hidden />
              ) : (
                <Icons.XCircle className="h-3.5 w-3.5 text-rose-500" aria-hidden />
              )}
              {apply.data.applied ? (apply.data.reason ?? "applied") : apply.data.refused ?? apply.data.reason ?? "plan result"}
              {apply.data.confHash ? <span className="font-mono text-[10px] text-zinc-400">hash {apply.data.confHash}</span> : null}
            </p>
            <ApplyResult result={apply.data} />
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
