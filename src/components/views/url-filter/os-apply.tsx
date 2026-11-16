"use client";

/**
 * URL-Filter OS enforcement panel (Squid) — mirrors the QoS OsPanel / HA
 * OsApplyPanel pattern: live appliance status per policy (rendered conf hash,
 * category rules, custom list counts, per-policy honest warnings), global
 * drift reasons for /etc/squid/squid.conf (full-file management), plan preview
 * when the CONSOLE_OS_APPLY gate is off, and admin-gated Apply / Rollback
 * actions. Execution (stage → squid -k parse → install → reload → verify,
 * auto-restore) happens snapshot-first on the server; here we only surface
 * the outcome.
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
  urlFilterApi,
  type UrlApplyResultDTO,
  type UrlOsPolicyStatus,
  type UrlOsStatusDTO,
} from "./url-filter-api";

function SyncBadge({ inSync }: { inSync: boolean | null }) {
  if (inSync === null) {
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

function PolicyOsRow({ policy }: { policy: UrlOsPolicyStatus }) {
  const counts = policy.customListCounts;
  return (
    <div className="rounded-lg border border-zinc-200 px-3 py-2.5 dark:border-zinc-800">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <span className="truncate text-sm font-medium text-zinc-700 dark:text-zinc-200">{policy.name}</span>
          <span className="font-mono text-xs text-zinc-500">#{policy.id}</span>
          {!policy.enabled ? (
            <Badge variant="outline" className="border-zinc-300 text-[10px] uppercase text-zinc-400 dark:border-zinc-700">
              disabled
            </Badge>
          ) : null}
        </div>
        <div className="flex items-center gap-3 font-mono text-xs text-zinc-500">
          <span title="rendered policy section hash">
            hash {policy.renderHash ? policy.renderHash.slice(0, 8) : "—"}
          </span>
          <span>
            {policy.categoryRules.filter((r) => r.enabled).length} cat rules · {counts.block}B/{counts.allow}A lists
          </span>
        </div>
      </div>
      {policy.warnings.length > 0 ? (
        <ul className="mt-1.5 space-y-0.5" role="list">
          {policy.warnings.slice(0, 4).map((w, i) => (
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

function ApplyResult({ result }: { result: UrlApplyResultDTO }) {
  const failed = result.results.some((r) => !r.ok);
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
          Auto-rollback: the pre-apply squid.conf was restored and squid restarted.
        </p>
      ) : null}
      {result.backupDir && failed ? (
        <p className="font-mono text-[10px] text-zinc-400">backup: {result.backupDir}</p>
      ) : null}
    </div>
  );
}

export function UrlOsPanel({ isAdmin }: { isAdmin: boolean }) {
  const queryClient = useQueryClient();
  const status = useQuery<UrlOsStatusDTO>({
    queryKey: ["url-filter", "os-status"],
    queryFn: urlFilterApi.getOsStatus,
    staleTime: 10_000,
  });

  const apply = useMutation({
    mutationFn: (action: "apply" | "rollback") => urlFilterApi.applyToOs(action),
    onSuccess: (d: UrlApplyResultDTO) => {
      if (d.refused) {
        toastErr(new Error(d.refused), d.action === "rollback" ? "Rollback refused" : "Apply refused");
      } else if (d.applied) {
        toastOk(d.action === "rollback" ? "squid.conf restored" : "Squid applied", d.reason ?? "converged");
      } else {
        toastErr(new Error(d.reason ?? "apply failed"), d.action === "rollback" ? "Rollback failed" : "Apply failed");
      }
      void queryClient.invalidateQueries({ queryKey: ["url-filter"] });
    },
    onError: (err) => toastErr(err, "Apply failed"),
  });

  const os = status.data;
  const hasPolicies = (os?.policies.length ?? 0) > 0;

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between space-y-0">
        <div className="space-y-1">
          <CardTitle className="flex items-center gap-2 text-base">
            <Icons.ServerCog className="h-4.5 w-4.5 text-zinc-500 dark:text-zinc-400" />
            OS enforcement (Squid :3128)
          </CardTitle>
          <CardDescription>
            {os?.note ?? "Loading squid state…"}
            {os?.state ? ` · hash ${os.state.confHash.slice(0, 8)} · applied ${os.state.appliedAt.replace("T", " ").slice(0, 16)}` : ""}
            {os?.managedFile ? ` · ${os.managedFile}` : ""}
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
              {os.available ? (os.port3128Bound ? "squid ready · :3128 bound" : "squid ready · :3128 down") : `preview only (${os.dataPlaneMode})`}
            </Badge>
          ) : null}
          {os?.inSync === false ? <SyncBadge inSync={false} /> : null}
          {os?.inSync === true ? <SyncBadge inSync={true} /> : null}
          {os?.state?.backupDir ? (
            <Button
              size="sm"
              variant="outline"
              disabled={apply.isPending || status.isLoading || !isAdmin}
              onClick={() => apply.mutate("rollback")}
            >
              {apply.isPending && apply.variables === "rollback" ? (
                <Icons.Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
              ) : (
                <Icons.Undo2 className="mr-1.5 h-3.5 w-3.5" />
              )}
              Rollback
            </Button>
          ) : null}
          <Button
            size="sm"
            variant="outline"
            className="bg-zinc-700 text-white hover:bg-zinc-800"
            onClick={() => apply.mutate("apply")}
            disabled={apply.isPending || status.isLoading || !isAdmin}
          >
            {apply.isPending && apply.variables !== "rollback" ? (
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
            Read-only — applying to the OS requires an admin role.
          </p>
        ) : null}

        {status.isError ? (
          <p className="flex items-center gap-2 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-600 dark:text-rose-400">
            <Icons.AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden />
            OS status unavailable — {(status.error as Error)?.message ?? "unknown error"}
          </p>
        ) : null}

        {os && os.driftReasons.length > 0 ? (
          <ul className="space-y-0.5" role="list">
            {os.driftReasons.slice(0, 4).map((r, i) => (
              <li key={i} className="flex items-start gap-1.5 text-xs text-rose-600 dark:text-rose-400">
                <Icons.Globe className="mt-0.5 h-3 w-3 shrink-0" aria-hidden />
                {r}
              </li>
            ))}
          </ul>
        ) : null}

        {os && !hasPolicies ? (
          <p className="rounded-lg border border-dashed border-zinc-300 px-3 py-2 text-xs text-zinc-500 dark:border-zinc-700">
            No URL filter policies — the rendered squid.conf is the stock catch-all (`http_access deny all` before the
            conf.d include, which is why this module manages the full file).
          </p>
        ) : null}

        {os?.policies.map((p) => <PolicyOsRow key={p.id} policy={p} />)}

        {os && os.warnings.length > 0 ? (
          <Collapsible>
            <CollapsibleTrigger className="flex items-center gap-1.5 text-xs text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300">
              <Icons.ChevronRight className="h-3.5 w-3.5 transition-transform [[data-state=open]>&]:rotate-90" aria-hidden />
              {os.warnings.length} renderer note{os.warnings.length === 1 ? "" : "s"} (aggregated feeds, warn-as-deny, ssl-bump, tproxy)
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
