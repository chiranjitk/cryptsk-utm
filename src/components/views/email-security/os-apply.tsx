"use client";

/**
 * Email Security OS panel (M22) — mirrors the LogsOsPanel pattern: live
 * postfix/rspamd unit state per gateway (expected render hash, transport-map
 * contribution), policy summary chips, listener ports + clamd reachability as
 * informational dots, drift reasons, plan preview when the CONSOLE_OS_APPLY
 * gate is off, and an admin-gated "Apply to OS" action (with rollback to the
 * newest console backup). Execution is snapshot-first with auto-restore on the
 * server; here we only surface the outcome.
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
  emailSecurityApi,
  type EmailOsApplyResultDTO,
  type EmailOsGatewayStatus,
  type EmailOsStatusDTO,
} from "./email-security-api";

function StateDot({ value, title }: { value: boolean | null; title: string }) {
  return (
    <span
      className={cn(
        "inline-block h-1.5 w-1.5 rounded-full",
        value === true ? "bg-emerald-500" : value === false ? "bg-amber-500" : "bg-zinc-400",
      )}
      title={title}
    />
  );
}

function GatewayOsRow({ gw }: { gw: EmailOsGatewayStatus }) {
  return (
    <div className="rounded-lg border border-zinc-200 px-3 py-2.5 dark:border-zinc-800">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium text-zinc-700 dark:text-zinc-200">{gw.name}</span>
          <Badge
            variant="outline"
            className={cn(
              "text-[11px] uppercase",
              gw.mode === "relay"
                ? "border-sky-500/40 bg-sky-500/10 text-sky-600 dark:text-sky-400"
                : "border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300",
            )}
          >
            {gw.mode}
          </Badge>
          <span className="font-mono text-xs text-zinc-500">:{gw.listenPort}</span>
          {gw.upstreamHost ? <span className="font-mono text-xs text-zinc-500">→ {gw.upstreamHost}</span> : null}
          <Badge variant="outline" className="border-zinc-500/30 bg-zinc-500/10 text-[11px] uppercase text-zinc-600 dark:text-zinc-300">
            tls {gw.tlsMode}
          </Badge>
          {!gw.enabled ? (
            <Badge variant="outline" className="border-zinc-300 text-zinc-500 dark:border-zinc-700">
              disabled
            </Badge>
          ) : null}
          {gw.relayDomains.length > 0 ? (
            <span className="max-w-[24rem] truncate font-mono text-[10px] text-zinc-400" title={gw.relayDomains.join(", ")}>
              {gw.relayDomains.join(", ")}
            </span>
          ) : null}
        </div>
        <span className="inline-flex items-center gap-1 font-mono text-[10px] text-zinc-400" title="sha256-16 of the gateway's rendered identity">
          {gw.renderHash}
        </span>
      </div>
      {gw.enabled && gw.transportLines.length > 0 ? (
        <p className="mt-1 max-w-full truncate font-mono text-[10px] text-zinc-400" title={gw.transportLines.join("\n")}>
          transport: {gw.transportLines[0]}
          {gw.transportLines.length > 1 ? ` (+${gw.transportLines.length - 1} more)` : ""}
        </p>
      ) : null}
    </div>
  );
}

function ApplyResult({ result }: { result: EmailOsApplyResultDTO }) {
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
          Auto-restore: the pre-apply files were re-installed and rspamd + postfix restarted.
        </p>
      ) : null}
      {result.backupDir && !result.applied ? (
        <p className="font-mono text-[10px] text-zinc-400">backup: {result.backupDir}</p>
      ) : null}
    </div>
  );
}

export function EmailOsPanel({ isAdmin }: { isAdmin: boolean }) {
  const queryClient = useQueryClient();
  const status = useQuery<EmailOsStatusDTO>({
    queryKey: ["email-security", "os-status"],
    queryFn: emailSecurityApi.getOsStatus,
    staleTime: 10_000,
  });

  const apply = useMutation({
    mutationFn: () => emailSecurityApi.applyToOs("apply"),
    onSuccess: (d) => {
      const r = d as EmailOsApplyResultDTO;
      if ("restored" in r) {
        // rollback payload (not expected on this mutation, but typed safely)
        toastErr(new Error((r as { reason?: string }).reason ?? "unexpected payload"), "Apply failed");
      } else if (r.refused) {
        toastErr(new Error(r.refused), "Apply refused");
      } else if (r.applied) {
        toastOk(r.skipped ? "Already in sync" : "Email OS applied", r.reason ?? "postfix + rspamd converged");
      } else {
        toastErr(new Error(r.reason ?? "apply failed"), r.rolledBack ? "Restored" : "Apply failed");
      }
      void queryClient.invalidateQueries({ queryKey: ["email-security"] });
    },
    onError: (err) => toastErr(err, "Apply failed"),
  });

  const rollback = useMutation({
    mutationFn: () => emailSecurityApi.applyToOs("rollback"),
    onSuccess: (d) => {
      const r = d as { rolledBack: boolean; detail: string };
      if (r.rolledBack) toastOk("Rolled back", r.detail);
      else toastErr(new Error(r.detail), "Rollback failed");
      void queryClient.invalidateQueries({ queryKey: ["email-security"] });
    },
    onError: (err) => toastErr(err, "Rollback failed"),
  });

  const os = status.data;
  const enabledGateways = os?.gateways.filter((g) => g.enabled) ?? [];
  const policy = os?.policy;

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between space-y-0">
        <div className="space-y-1">
          <CardTitle className="flex items-center gap-2 text-base">
            <Icons.ServerCog className="h-4.5 w-4.5 text-zinc-500 dark:text-zinc-400" />
            OS enforcement (Postfix + Rspamd)
          </CardTitle>
          <CardDescription>
            {os?.note ?? "Loading Postfix/Rspamd enforcement state…"}
            {os?.state?.appliedAt ? ` · applied ${os.state.appliedAt.replace("T", " ").slice(0, 16)}` : ""}
            {os?.postfixState ? ` · postfix ${os.postfixState}` : ""}
            {os?.rspamdState ? ` · rspamd ${os.rspamdState}` : ""}
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
              {os.available ? "stack ready" : `preview only (${os.dataPlaneMode})`}
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
              <span className={cn("mr-1 inline-block h-1.5 w-1.5 rounded-full", os.inSync ? "bg-emerald-500" : "bg-rose-500")} aria-hidden />
              {os.inSync ? "in sync" : "drift"}
            </Badge>
          ) : null}
          {os?.state?.appliedAt ? (
            <Button
              size="sm"
              variant="ghost"
              className="h-8 text-xs"
              onClick={() => rollback.mutate()}
              disabled={rollback.isPending || !isAdmin}
              title="Restore the newest /var/lib/console/email/backup-<ts>/"
            >
              {rollback.isPending ? <Icons.Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" /> : <Icons.Undo2 className="mr-1 h-3.5 w-3.5" />}
              Rollback
            </Button>
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
            Read-only — applying to the OS requires the email-security write role.
          </p>
        ) : null}

        {status.isError ? (
          <p className="flex items-center gap-2 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-600 dark:text-rose-400">
            <Icons.AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden />
            OS status unavailable — {(status.error as Error)?.message ?? "unknown error"}
          </p>
        ) : null}

        {os && policy ? (
          <div className="flex flex-wrap items-center gap-1.5 rounded-lg border border-zinc-200 px-3 py-2 text-xs text-zinc-600 dark:border-zinc-800 dark:text-zinc-300">
            <span className="font-medium">Policy:</span>
            <Badge variant="outline" className="text-[11px]">
              spam ≥ {policy.spamThreshold} / reject ≥ {policy.spamThreshold + 4}
            </Badge>
            <Badge variant="outline" className="text-[11px]">
              DMARC {policy.dmarcPolicy}
            </Badge>
            <Badge variant="outline" className={cn("text-[11px]", policy.blockPhishing ? "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400" : "")}>
              phishing {policy.blockPhishing ? "reject" : "off"}
            </Badge>
            <Badge variant="outline" className={cn("text-[11px]", policy.blockMalware ? "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400" : "")}>
              malware {policy.blockMalware ? "clamd" : "off"}
            </Badge>
            <Badge variant="outline" className="text-[11px]">
              ≤ {policy.maxMessageSizeMb} MB
            </Badge>
            <span className="inline-flex items-center gap-1" title="clamd reachability (informational — freshclam may still be downloading on a fresh appliance)">
              clamd <StateDot value={os.clamdReachable} title="clamdscan --ping 1 reachability" />
            </span>
            <span className="inline-flex items-center gap-1" title="smtp :25 listener (informational)">
              :25 <StateDot value={os.portsBound.p25} title="postfix smtp listener :25" />
            </span>
            <span className="inline-flex items-center gap-1" title="rspamd milter :11332 (informational)">
              :11332 <StateDot value={os.portsBound.p11332} title="rspamd milter listener :11332" />
            </span>
            <span className="inline-flex items-center gap-1" title="rspamd webui :11334 (informational)">
              :11334 <StateDot value={os.portsBound.p11334} title="rspamd web UI :11334" />
            </span>
          </div>
        ) : null}

        {os && os.gateways.length === 0 ? (
          <p className="rounded-lg border border-dashed border-zinc-300 px-3 py-2 text-xs text-zinc-500 dark:border-zinc-700">
            No email gateways — Apply stops postfix + rspamd (teardown). Add one in the Gateways tab; Apply writes /etc/postfix/main.cf, /etc/postfix/utm-transport and /etc/rspamd/local.d/*.conf.
          </p>
        ) : null}

        {(os?.gateways ?? []).map((g) => (
          <GatewayOsRow key={g.id} gw={g} />
        ))}
        {os && os.gateways.length > 0 && enabledGateways.length === 0 ? (
          <p className="text-xs text-amber-600 dark:text-amber-400">All gateways disabled — Apply stops postfix + rspamd (teardown).</p>
        ) : null}

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
              {os.warnings.length} renderer note{os.warnings.length === 1 ? "" : "s"} (master.cf scope, retention, clamd)
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

        {apply.data && (apply.data as EmailOsApplyResultDTO).results?.length > 0 ? (
          <div className="rounded-lg border border-zinc-200 px-3 py-2.5 dark:border-zinc-800">
            {(() => {
              const r = apply.data as EmailOsApplyResultDTO;
              return (
                <>
                  <p className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-zinc-700 dark:text-zinc-200">
                    {r.applied ? (
                      <Icons.CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" aria-hidden />
                    ) : r.refused ? (
                      <Icons.Ban className="h-3.5 w-3.5 text-amber-500" aria-hidden />
                    ) : (
                      <Icons.XCircle className="h-3.5 w-3.5 text-rose-500" aria-hidden />
                    )}
                    {r.applied ? (r.reason ?? "applied") : r.refused ?? r.reason ?? "plan result"}
                    {r.confHash ? <span className="font-mono text-[10px] text-zinc-400">hash {r.confHash}</span> : null}
                  </p>
                  <ApplyResult result={r} />
                </>
              );
            })()}
          </div>
        ) : null}

        {rollback.data && (rollback.data as { detail: string }).detail ? (
          <p className="rounded-lg border border-zinc-200 px-3 py-2 font-mono text-[10px] text-zinc-500 dark:border-zinc-800">
            rollback: {(rollback.data as { detail: string }).detail}
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}
