"use client";

/**
 * SSL Inspection OS enforcement panel (M15 §2.1) — clone of the WAF OS panel
 * adapted to the squid ssl-bump fragment: live unit state, ssl-crtd capability
 * badge, managed-fragment hash + drift, effective policy + PKI signing-CA
 * summary, plan preview when the CONSOLE_OS_APPLY gate is off, and an
 * admin-gated Apply / Rollback.
 *
 * HONEST DEGRADATION (spec §6): when `sslCrtdSupported === false` a permanent
 * amber banner explains that the host squid cannot run MITM — apply refuses
 * with install/compile guidance until squid is rebuilt with ssl-crtd or the
 * policy is kept in cert-pinning-bypass-only (mode none).
 */

import * as Icons from "lucide-react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { toastErr, toastOk } from "../firewall/fw-ui";
import { cn } from "@/lib/utils";
import { sslInspectionApi, type SslOsApplyResultDTO, type SslOsStatusDTO } from "./ssl-inspection-api";

function SyncBadge({ inSync, fragmentPresent }: { inSync: boolean | null; fragmentPresent: boolean }) {
  if (!fragmentPresent || inSync === null) {
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

function CapabilityBadge({ supported, method }: { supported: boolean; method: string | null }) {
  if (supported) {
    return (
      <Badge
        variant="outline"
        className="border-emerald-500/30 bg-emerald-500/10 font-mono text-[10px] text-emerald-600 dark:text-emerald-400"
      >
        ssl-crtd ok{method ? ` (${method})` : ""}
      </Badge>
    );
  }
  return (
    <Badge
      variant="outline"
      className="border-amber-500/40 bg-amber-500/10 font-mono text-[10px] text-amber-600 dark:text-amber-400"
    >
      ssl-crtd missing
    </Badge>
  );
}

function ApplyResult({ result }: { result: SslOsApplyResultDTO }) {
  const results = result.results ?? [];
  if (results.length === 0) {
    return (
      <div className="space-y-1.5">
        <p className="text-xs text-zinc-500">
          Plan preview — {result.plan.steps.length} step(s), fragment staged to /etc/squid/conf.d/utm-ssl.conf. Apply runs
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
          Auto-rollback: previous fragment restored and revalidated with squid -k parse.
        </p>
      ) : null}
      {result.backupDir && !result.applied ? (
        <p className="font-mono text-[10px] text-zinc-400">backup: {result.backupDir}</p>
      ) : null}
    </div>
  );
}

export function SslOsPanel({ isAdmin }: { isAdmin: boolean }) {
  const queryClient = useQueryClient();
  const status = useQuery<SslOsStatusDTO>({
    queryKey: ["ssl-inspection", "os-status"],
    queryFn: sslInspectionApi.getOsStatus,
    staleTime: 10_000,
  });

  const apply = useMutation({
    mutationFn: () => sslInspectionApi.applyToOs(),
    onSuccess: (d: SslOsApplyResultDTO) => {
      if (d.refused) {
        toastErr(new Error(d.refused), "Apply refused");
      } else if (d.applied) {
        toastOk("SSL inspection applied to OS", d.reason ?? "fragment converged");
      } else {
        toastErr(new Error(d.reason ?? "apply failed"), d.rolledBack ? "Rolled back" : "Apply failed");
      }
      void queryClient.invalidateQueries({ queryKey: ["ssl-inspection"] });
    },
    onError: (err) => toastErr(err, "Apply failed"),
  });

  const rollback = useMutation({
    mutationFn: () => sslInspectionApi.rollbackOs(),
    onSuccess: (d) => {
      if (d.rolledBack) toastOk("Rollback complete", d.detail);
      else toastErr(new Error(d.detail), d.gate === "off" ? "Rollback preview only" : "Rollback failed");
      void queryClient.invalidateQueries({ queryKey: ["ssl-inspection"] });
    },
    onError: (err) => toastErr(err, "Rollback failed"),
  });

  const os = status.data;
  const busy = apply.isPending || rollback.isPending;
  const capabilityBlocked = os?.sslCrtdSupported === false && (os?.plan.empty === false || Boolean(os?.policy));

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between space-y-0">
        <div className="space-y-1">
          <CardTitle className="flex items-center gap-2 text-base">
            <Icons.ServerCog className="h-4.5 w-4.5 text-zinc-500 dark:text-zinc-400" />
            OS enforcement (squid ssl-bump)
          </CardTitle>
          <CardDescription>
            {os
              ? `squid unit ${os.unitState ?? "unknown"}${os.version ? ` · v${os.version}` : ""} · ${os.managedFile}`
              : "Loading squid state…"}
            {os?.state?.appliedAt
              ? ` · applied ${os.state.appliedAt.replace("T", " ").slice(0, 16)}${os.state.confHash ? ` · hash ${os.state.confHash}` : ""}`
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
              {os.available ? "squid ready" : `preview only (${os.dataPlaneMode})`}
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

        {/* capability banner — permanent while the host squid lacks ssl-crtd */}
        {os && os.sslCrtdSupported === false ? (
          <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2.5" role="alert">
            <p className="flex items-center gap-1.5 text-xs font-medium text-amber-700 dark:text-amber-400">
              <Icons.ShieldOff className="h-3.5 w-3.5 shrink-0" aria-hidden />
              Host squid lacks ssl-crtd — MITM inspection cannot run here.
            </p>
            <p className="mt-1 text-xs leading-relaxed text-amber-700/90 dark:text-amber-400/90">
              The squid build has no --enable-ssl-crtd flag and no ssl_crtd / security_file_certgen helper, so dynamic
              certificate generation is impossible. Install or compile squid with ssl-crtd support to enable inspection,
              or keep the policy in cert-pinning-bypass-only mode (mode none). Apply is refused until then — no
              partial enforcement is simulated.
            </p>
          </div>
        ) : null}

        {os ? (
          <div className="flex flex-wrap items-center gap-2">
            <SyncBadge inSync={os.inSync} fragmentPresent={os.fragmentPresent} />
            <CapabilityBadge supported={os.sslCrtdSupported} method={os.sslCrtdMethod} />
            {os.port3129Bound != null ? (
              <Badge
                variant="outline"
                className="border-zinc-300 bg-zinc-100 font-mono text-[10px] text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800"
              >
                {os.port3129Bound ? "bump listener bound (:3129)" : "no :3129 listener"}
              </Badge>
            ) : null}
            {os.gate === "off" ? (
              <Badge variant="outline" className="border-amber-500/40 bg-amber-500/10 text-[10px] text-amber-600 dark:text-amber-400">
                plan preview (CONSOLE_OS_APPLY off)
              </Badge>
            ) : null}
            {os.fragmentPresent && !os.fragmentByConsole ? (
              <Badge variant="outline" className="border-rose-500/40 bg-rose-500/10 text-[10px] text-rose-600 dark:text-rose-400">
                fragment not console-managed
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

        {os?.policy ? (
          <div className="rounded-lg border border-zinc-200 px-3 py-2.5 dark:border-zinc-800">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm font-medium text-zinc-700 dark:text-zinc-200">{os.policy.name}</span>
                <Badge variant="outline" className="font-mono text-[10px] uppercase text-zinc-500">
                  {os.policy.mode}
                </Badge>
                <span className="font-mono text-[10px] text-zinc-400" title="plan render hash">
                  {os.plan.confHash}
                </span>
              </div>
              <span className="font-mono text-xs text-zinc-500">
                {os.policy.bypassRuleCount} bypass rule(s)
                {os.ca ? ` · CA ${os.ca.name} (${os.ca.status}${os.ca.hasKey ? "" : ", no key"})` : " · no signing CA"}
              </span>
            </div>
            {os.plan.empty ? (
              <p className="mt-1.5 text-xs text-zinc-500">
                No enabled selective/full policy — apply writes an empty fragment and leaves the squid unit untouched.
              </p>
            ) : null}
            {os.plan.skipped.length > 0 ? (
              <p className="mt-1 font-mono text-[10px] text-zinc-500">
                {os.plan.skipped.length} skipped entr{os.plan.skipped.length === 1 ? "y" : "ies"}:{" "}
                {os.plan.skipped
                  .slice(0, 2)
                  .map((s) => s.name)
                  .join(", ")}
                {os.plan.skipped.length > 2 ? " …" : ""}
              </p>
            ) : null}
          </div>
        ) : (
          os && (
            <p className="rounded-lg border border-dashed border-zinc-300 px-3 py-2 text-xs text-zinc-500 dark:border-zinc-700">
              No enabled SSL inspection policy — MITM stays off; apply renders an empty fragment.
            </p>
          )
        )}

        {os && os.warnings.length > 0 ? (
          <Collapsible>
            <CollapsibleTrigger className="flex items-center gap-1.5 text-xs text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300">
              <Icons.ChevronRight className="h-3.5 w-3.5 transition-transform [[data-state=open]>&]:rotate-90" aria-hidden />
              {os.warnings.length} renderer note{os.warnings.length === 1 ? "" : "s"} (conf.d include order, pinning/HSTS
              limits, generated-CA requirement)
            </CollapsibleTrigger>
            <CollapsibleContent>
              <ul
                className="mt-1.5 max-h-40 space-y-1 overflow-y-auto rounded-lg border border-zinc-200 bg-zinc-50 p-2 dark:border-zinc-800 dark:bg-zinc-900"
                role="list"
              >
                {os.warnings.map((w, i) => (
                  <li key={i} className="font-mono text-[10px] leading-relaxed text-zinc-500 dark:text-zinc-400">
                    {w}
                  </li>
                ))}
              </ul>
            </CollapsibleContent>
          </Collapsible>
        ) : null}

        {capabilityBlocked && os?.plan.refused ? (
          <p className="flex items-start gap-1.5 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 font-mono text-[10px] leading-relaxed text-amber-700 dark:text-amber-400">
            <Icons.Ban className="mt-0.5 h-3 w-3 shrink-0" aria-hidden />
            {os.plan.refused}
          </p>
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
