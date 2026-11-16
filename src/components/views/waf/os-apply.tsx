"use client";

/**
 * WAF OS enforcement panel (M17 §2.4) — clone of the QoS OS panel adapted to
 * the nginx + ModSecurity 3 appliance: live unit state, managed-file hashes,
 * drift (in-sync / drift / not installed), per-vhost render preview (policy
 * CRS knobs, rate limit, exclusions, renderer warnings), plan preview when
 * the CONSOLE_OS_APPLY gate is off, and an admin-gated Apply / Rollback.
 */

import * as Icons from "lucide-react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { toastErr, toastOk } from "../firewall/fw-ui";
import { cn } from "@/lib/utils";
import {
  wafApi,
  type WafApplyResultDTO,
  type WafOsStatusDTO,
  type WafOsVhostStatusDTO,
} from "./waf-api";

function SyncBadge({ inSync, managedByConsole }: { inSync: boolean; managedByConsole: boolean }) {
  if (!managedByConsole) {
    return (
      <Badge variant="outline" className="border-zinc-300 text-zinc-500 dark:border-zinc-700">
        not installed
      </Badge>
    );
  }
  if (inSync) {
    return (
      <Badge className="border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
        <span className="mr-1 inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" aria-hidden />
        in sync
      </Badge>
    );
  }
  return (
    <Badge className="border-rose-500/30 bg-rose-500/10 text-rose-600 dark:text-rose-400">
      <span className="mr-1 inline-block h-1.5 w-1.5 rounded-full bg-rose-500" aria-hidden />
      drift
    </Badge>
  );
}

function VhostOsRow({ vhost }: { vhost: WafOsVhostStatusDTO }) {
  return (
    <div className="rounded-lg border border-zinc-200 px-3 py-2.5 dark:border-zinc-800">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="font-mono text-sm font-medium text-zinc-700 dark:text-zinc-200">{vhost.hostname}</span>
          <Badge variant="outline" className="font-mono text-[10px] uppercase text-zinc-500">
            {vhost.mode.replace("_", " ")}
          </Badge>
          <span className="font-mono text-[10px] text-zinc-400" title="per-vhost render hash">
            {vhost.renderHash}
          </span>
        </div>
        {vhost.policy ? (
          <span className="font-mono text-xs text-zinc-500">
            CRS {vhost.policy.crs ? `v${vhost.policy.crsVersion}` : "off"} · PL{vhost.policy.paranoiaLevel} · in {vhost.policy.thresholds.in}/out{" "}
            {vhost.policy.thresholds.out}
            {vhost.policy.learning ? " · learning" : ""}
            {vhost.policy.rateLimit ? ` · ${vhost.policy.rateLimit.rpm} rpm (burst ${vhost.policy.rateLimit.burst})` : ""}
          </span>
        ) : (
          <span className="text-xs text-zinc-400">no policy — plain proxy</span>
        )}
      </div>
      {vhost.exclusions.length > 0 ? (
        <p className="mt-1 font-mono text-[10px] text-zinc-500">
          {vhost.exclusions.length} exclusion(s):{" "}
          {vhost.exclusions
            .slice(0, 3)
            .map((x) => `${x.scope}:${x.matchValue}`)
            .join(", ")}
          {vhost.exclusions.length > 3 ? " …" : ""}
        </p>
      ) : null}
      {vhost.warnings.length > 0 ? (
        <ul className="mt-1.5 space-y-0.5" role="list">
          {vhost.warnings.slice(0, 3).map((w, i) => (
            <li key={i} className="flex items-start gap-1.5 text-xs text-amber-600 dark:text-amber-400">
              <Icons.AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" aria-hidden />
              {w}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

function ApplyResult({ result }: { result: WafApplyResultDTO }) {
  const results = result.results ?? [];
  if (results.length === 0) {
    return (
      <div className="space-y-1.5">
        <p className="text-xs text-zinc-500">
          Plan preview — {result.plan.steps.length} step(s), {result.plan.files.length} managed file(s). Apply runs
          only with CONSOLE_OS_APPLY=1 on the host data plane.
        </p>
        {result.plan.steps.map((s, i) => (
          <div key={i} className="flex items-start justify-between gap-2 text-xs">
            <span className="flex items-center gap-1.5 text-zinc-600 dark:text-zinc-300">
              <Icons.Circle className="h-3 w-3 shrink-0 text-zinc-300 dark:text-zinc-600" aria-hidden />
              {s.step}
            </span>
            <span className="max-w-[60%] truncate font-mono text-[10px] text-zinc-400" title={s.cmd}>
              {s.cmd}
            </span>
          </div>
        ))}
      </div>
    );
  }
  return (
    <div className="space-y-1.5">
      {results.map((r, i) => (
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
          Auto-rollback: previous managed files restored and revalidated.
        </p>
      ) : null}
      {result.backupDir && !result.applied ? (
        <p className="font-mono text-[10px] text-zinc-400">backup: {result.backupDir}</p>
      ) : null}
    </div>
  );
}

export function WafOsPanel({ isAdmin }: { isAdmin: boolean }) {
  const queryClient = useQueryClient();
  const status = useQuery<WafOsStatusDTO>({
    queryKey: ["waf", "os-status"],
    queryFn: wafApi.getOsStatus,
    staleTime: 10_000,
  });

  const apply = useMutation({
    mutationFn: () => wafApi.applyToOs(),
    onSuccess: (d: WafApplyResultDTO) => {
      if (d.refused) {
        toastErr(new Error(d.refused), "Apply refused");
      } else if (d.applied) {
        toastOk("WAF applied to OS", d.reason ?? "nginx converged");
      } else {
        toastErr(new Error(d.reason ?? "apply failed"), d.rolledBack ? "Rolled back" : "Apply failed");
      }
      void queryClient.invalidateQueries({ queryKey: ["waf"] });
    },
    onError: (err) => toastErr(err, "Apply failed"),
  });

  const rollback = useMutation({
    mutationFn: () => wafApi.rollbackOs(),
    onSuccess: (d) => {
      if (d.rolledBack) toastOk("Rollback complete", d.detail);
      else toastErr(new Error(d.detail), "Rollback failed");
      void queryClient.invalidateQueries({ queryKey: ["waf"] });
    },
    onError: (err) => toastErr(err, "Rollback failed"),
  });

  const os = status.data;
  const hasVhosts = (os?.vhosts.length ?? 0) > 0;
  const busy = apply.isPending || rollback.isPending;

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between space-y-0">
        <div className="space-y-1">
          <CardTitle className="flex items-center gap-2 text-base">
            <Icons.ServerCog className="h-4.5 w-4.5 text-zinc-500 dark:text-zinc-400" />
            OS enforcement (nginx + ModSecurity)
          </CardTitle>
          <CardDescription>
            {os
              ? `nginx unit ${os.unitState ?? "unknown"} · CRS ${os.crs.version}${os.crs.dir ? "" : " (bundle missing)"} · ${os.managedFiles.filter((f) => f.present).length} managed file(s)`
              : "Loading nginx state…"}
            {os?.lastApply?.appliedAt
              ? ` · applied ${os.lastApply.appliedAt.replace("T", " ").slice(0, 16)}${os.lastApply.confHash ? ` · hash ${os.lastApply.confHash}` : ""}`
              : ""}
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
              {os.available ? "nginx ready" : `preview only (${os.dataPlaneMode})`}
            </Badge>
          ) : null}
          <Button
            size="sm"
            variant="outline"
            className="bg-zinc-700 text-white hover:bg-zinc-800"
            onClick={() => apply.mutate()}
            disabled={busy || status.isLoading || !isAdmin}
          >
            {apply.isPending ? (
              <Icons.Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
            ) : (
              <Icons.ServerCog className="mr-1.5 h-3.5 w-3.5" />
            )}
            Apply to OS
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => rollback.mutate()}
            disabled={busy || !isAdmin}
            aria-label="Rollback to newest backup"
          >
            {rollback.isPending ? <Icons.Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <Icons.Undo2 className="mr-1.5 h-3.5 w-3.5" />}
            Rollback
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {!isAdmin ? (
          <p className="flex items-center gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-400">
            <Icons.Lock className="h-3.5 w-3.5 shrink-0" aria-hidden />
            Read-only — applying to the OS requires an admin role.
          </p>
        ) : null}

        {status.isError ? (
          <p className="flex items-center gap-2 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-600 dark:text-rose-400">
            <Icons.AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden />
            OS status unavailable — {(status.error as Error)?.message ?? "unknown error"}
          </p>
        ) : null}

        {os ? (
          <div className="flex flex-wrap items-center gap-2">
            <SyncBadge inSync={os.inSync} managedByConsole={os.managedByConsole} />
            {os.portsBound != null ? (
              <Badge variant="outline" className="border-zinc-300 bg-zinc-100 font-mono text-[10px] text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800">
                {os.portsBound ? "listener bound (:80/:443)" : "no :80/:443 listener"}
              </Badge>
            ) : null}
            {os.gate === "off" ? (
              <Badge variant="outline" className="border-amber-500/40 bg-amber-500/10 text-[10px] text-amber-600 dark:text-amber-400">
                plan preview (CONSOLE_OS_APPLY off)
              </Badge>
            ) : null}
          </div>
        ) : null}

        {os && os.driftReasons.length > 0 ? (
          <ul className="space-y-0.5" role="list">
            {os.driftReasons.map((r, i) => (
              <li key={i} className="flex items-start gap-1.5 text-xs text-rose-600 dark:text-rose-400">
                <Icons.AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" aria-hidden />
                {r}
              </li>
            ))}
          </ul>
        ) : null}

        {os && !hasVhosts ? (
          <p className="rounded-lg border border-dashed border-zinc-300 px-3 py-2 text-xs text-zinc-500 dark:border-zinc-700">
            No enabled vhost — apply writes an empty managed conf and leaves the nginx unit untouched.
          </p>
        ) : null}

        {os?.vhosts.map((v) => <VhostOsRow key={v.id} vhost={v} />)}

        {os && os.warnings.length > 0 ? (
          <Collapsible>
            <CollapsibleTrigger className="flex items-center gap-1.5 text-xs text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300">
              <Icons.ChevronRight className="h-3.5 w-3.5 transition-transform [[data-state=open]>&]:rotate-90" aria-hidden />
              {os.warnings.length} renderer note{os.warnings.length === 1 ? "" : "s"} (CRS downgrades, skipped exclusions, TLS warnings)
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

        {apply.data ? (
          <div className="rounded-lg border border-zinc-200 px-3 py-2.5 dark:border-zinc-800">
            <p className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-zinc-700 dark:text-zinc-200">
              {apply.data.applied ? (
                <Icons.CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" aria-hidden />
              ) : apply.data.refused || apply.data.gate === "off" ? (
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
