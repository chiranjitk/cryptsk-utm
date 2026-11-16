"use client";

/**
 * RADIUS OS panel (IMPL-8) — mirrors the logs os-apply panel pattern:
 * live FreeRADIUS state per RADIUS profile (expected render slug/hash vs
 * managed-file hash + unit state, udp/1812 bound probe as an informational
 * dot), drift reasons, plan preview when the CONSOLE_OS_APPLY gate is off,
 * and admin-gated "Apply to OS" / "Roll back" actions. Execution is
 * snapshot-first with auto-restore on the server; here we only surface the
 * outcome. One RadiusProfile row = one NAS client block in
 * /etc/freeradius/3.0/clients.conf; with NO profiles the unit is stopped
 * (console-off).
 */

import * as Icons from "lucide-react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { toastErr, toastOk } from "../firewall/fw-ui";
import { cn } from "@/lib/utils";
import { radiusOsApi, type RadiusApplyResultDTO, type RadiusOsProfileStatus, type RadiusOsStatusDTO } from "./identity-api";

function SyncBadge({ profile }: { profile: RadiusOsProfileStatus }) {
  if (!profile.enabled) {
    return (
      <Badge variant="outline" className="border-zinc-300 text-zinc-500 dark:border-zinc-700">
        disabled
      </Badge>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 font-mono text-[10px] text-zinc-400" title="sha256-16 of the rendered client block">
      {profile.renderHash ?? "—"}
    </span>
  );
}

function ProfileOsRow({ profile }: { profile: RadiusOsProfileStatus }) {
  return (
    <div className="rounded-lg border border-zinc-200 px-3 py-2.5 dark:border-zinc-800">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-zinc-700 dark:text-zinc-200">{profile.name}</span>
          <span className="font-mono text-xs text-zinc-500">
            {profile.serverIp}:{profile.authPort}
          </span>
          <Badge variant="outline" className="border-zinc-500/30 bg-zinc-500/10 text-[11px] uppercase text-zinc-600 dark:text-zinc-300">
            nas
          </Badge>
          <span className="text-xs text-zinc-500">timeout {profile.timeoutSec}s · retries {profile.retries}</span>
        </div>
        <SyncBadge profile={profile} />
      </div>
      {profile.slug ? <p className="mt-1 font-mono text-[10px] text-zinc-400">client {profile.slug}</p> : null}
    </div>
  );
}

function ApplyResult({ result }: { result: RadiusApplyResultDTO }) {
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
          Auto-restore: the pre-apply clients.conf was re-installed and freeradius restarted.
        </p>
      ) : null}
      {result.backupDir && !result.applied ? (
        <p className="font-mono text-[10px] text-zinc-400">backup: {result.backupDir}</p>
      ) : null}
    </div>
  );
}

export function IdentityOsPanel({ isAdmin }: { isAdmin: boolean }) {
  const queryClient = useQueryClient();
  const status = useQuery<RadiusOsStatusDTO>({
    queryKey: ["radius", "os-status"],
    queryFn: radiusOsApi.getOsStatus,
    staleTime: 10_000,
  });

  const act = useMutation({
    mutationFn: (action: "apply" | "rollback") => radiusOsApi.applyToOs(action),
    onSuccess: (d: RadiusApplyResultDTO, action) => {
      if (d.refused) {
        toastErr(new Error(d.refused), action === "apply" ? "Apply refused" : "Rollback refused");
      } else if (d.applied || d.rolledBack) {
        toastOk(d.skipped ? "Already in sync" : action === "apply" ? "FreeRADIUS applied" : "Rolled back", d.reason ?? "freeradius converged");
      } else {
        toastErr(new Error(d.reason ?? "action failed"), d.rolledBack ? "Restored" : action === "apply" ? "Apply failed" : "Rollback failed");
      }
      void queryClient.invalidateQueries({ queryKey: ["radius"] });
    },
    onError: (err) => toastErr(err, "OS action failed"),
  });

  const os = status.data;
  const hasProfiles = (os?.profiles.length ?? 0) > 0;
  const busy = act.isPending || status.isLoading || !isAdmin;

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between space-y-0">
        <div className="space-y-1">
          <CardTitle className="flex items-center gap-2 text-base">
            <Icons.ServerCog className="h-4.5 w-4.5 text-zinc-500 dark:text-zinc-400" />
            OS integration (FreeRADIUS)
          </CardTitle>
          <CardDescription>
            {os?.note ?? "Loading FreeRADIUS state…"}
            {os?.state ? ` · hash ${os.state.confHash.slice(0, 8)} · applied ${os.state.appliedAt.replace("T", " ").slice(0, 16)}` : ""}
            {os?.unitState ? ` · unit ${os.unitState}` : ""}
          </CardDescription>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {os ? (
            <Badge
              variant="outline"
              className={cn(
                os.available
                  ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                  : "border-zinc-300 text-zinc-500 dark:border-zinc-700",
              )}
            >
              {os.available ? "freeradius ready" : `preview only (${os.dataPlaneMode})`}
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
                className={cn("mr-1 inline-block h-1.5 w-1.5 rounded-full", os.inSync ? "bg-emerald-500" : "bg-rose-500")}
                aria-hidden
              />
              {os.inSync ? "in sync" : "drift"}
            </Badge>
          ) : null}
          <Badge variant="outline" className={cn("border-zinc-300 text-zinc-500 dark:border-zinc-700")} title="udp/1812 listener probe (informational)">
            1812 {os?.portBound === true ? "bound" : os?.portBound === false ? "unbound" : "?"}
          </Badge>
          <Button
            size="sm"
            variant="outline"
            className="bg-zinc-700 text-white hover:bg-zinc-800"
            onClick={() => act.mutate("apply")}
            disabled={busy}
          >
            {act.isPending && act.variables === "apply" ? (
              <Icons.Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
            ) : (
              <Icons.ServerCog className="mr-1.5 h-3.5 w-3.5" />
            )}
            Apply to OS
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => act.mutate("rollback")}
            disabled={busy}
            title="Restore the newest console backup of clients.conf (the stock Debian file)"
          >
            {act.isPending && act.variables === "rollback" ? (
              <Icons.Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
            ) : (
              <Icons.Undo2 className="mr-1.5 h-3.5 w-3.5" />
            )}
            Roll back
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {!isAdmin ? (
          <p className="flex items-center gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-400">
            <Icons.Lock className="h-3.5 w-3.5 shrink-0" aria-hidden />
            Read-only — applying to the OS requires the identity write role.
          </p>
        ) : null}

        {status.isError ? (
          <p className="flex items-center gap-2 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-600 dark:text-rose-400">
            <Icons.AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden />
            OS status unavailable — {(status.error as Error)?.message ?? "unknown error"}
          </p>
        ) : null}

        {os && !hasProfiles ? (
          <p className="rounded-lg border border-dashed border-zinc-300 px-3 py-2 text-xs text-zinc-500 dark:border-zinc-700">
            No RADIUS profiles — Apply writes an empty clients.conf and STOPS freeradius (console-off); add a profile above to define NAS clients.
          </p>
        ) : null}

        {os?.profiles.map((p) => <ProfileOsRow key={p.id} profile={p} />)}

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
              {os.warnings.length} renderer note{os.warnings.length === 1 ? "" : "s"} (disabled profiles, empty state)
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

        {act.data && (act.data.results.length > 0 || act.data.refused) ? (
          <div className="rounded-lg border border-zinc-200 px-3 py-2.5 dark:border-zinc-800">
            <p className="mb-1.5 flex flex-wrap items-center gap-1.5 text-xs font-medium text-zinc-700 dark:text-zinc-200">
              {act.data.applied || act.data.rolledBack ? (
                <Icons.CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" aria-hidden />
              ) : act.data.refused ? (
                <Icons.Ban className="h-3.5 w-3.5 text-amber-500" aria-hidden />
              ) : (
                <Icons.XCircle className="h-3.5 w-3.5 text-rose-500" aria-hidden />
              )}
              {act.data.applied || act.data.rolledBack ? (act.data.reason ?? "done") : act.data.refused ?? act.data.reason ?? "result"}
              {act.data.confHash ? <span className="font-mono text-[10px] text-zinc-400">hash {act.data.confHash}</span> : null}
            </p>
            {act.data.results.length > 0 ? <ApplyResult result={act.data} /> : null}
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
