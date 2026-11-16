"use client";

/**
 * IPS OS Sync card — the GUI↔Suricata integration surface on the Policies
 * tab (mirrors FirewallOsSync). Shows real engine facts, the generated plan,
 * drift, and the backup → validate (`suricata -T`) → reload apply pipeline
 * with automatic rollback. Zero commit-confirm window: a rule reload never
 * touches traffic flow on the passive capture.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useState } from "react";
import { ipsApi, fmtDateTime, type IpsOsApplyOutcome } from "./ips-api";
import { toastErr, toastOk } from "../firewall/fw-ui";

const OS_KEY = ["ips", "os"] as const;

function ServiceBadge({ state }: { state: string | null }) {
  if (state === "active") {
    return (
      <Badge className="gap-1 border-transparent bg-emerald-600 text-white">
        <Icons.CircleCheck className="h-3 w-3" /> service active
      </Badge>
    );
  }
  if (state === null) {
    return (
      <Badge variant="outline" className="border-zinc-300 bg-zinc-100 text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-400">
        engine not detected
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="gap-1 border-rose-500/50 bg-rose-500/10 text-rose-600 dark:text-rose-400">
      <Icons.CircleX className="h-3 w-3" /> service {state}
    </Badge>
  );
}

export function IpsOsSync() {
  const queryClient = useQueryClient();
  const [showFiles, setShowFiles] = useState(false);

  const osQuery = useQuery({ queryKey: OS_KEY, queryFn: ipsApi.getOs, refetchInterval: 30_000 });

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: OS_KEY });
    void queryClient.invalidateQueries({ queryKey: ["ips"] });
  };

  const applyMut = useMutation({
    mutationFn: () => ipsApi.osApply(),
    onSuccess: (res: IpsOsApplyOutcome) => {
      if (res.rolledBack) {
        toastErr(new Error(res.detail ?? "validation failed"), "Apply rolled back");
      } else if (res.applied) {
        toastOk("IPS policy applied to host", res.detail ?? undefined);
      } else {
        toastErr(new Error(res.detail ?? "apply refused"), "Apply not executed");
      }
      invalidate();
    },
    onError: (err) => toastErr(err, "OS apply failed"),
  });

  const rollbackMut = useMutation({
    mutationFn: () => ipsApi.osRollback(),
    onSuccess: (res) => {
      if (res.rolledBack) toastOk("Rollback complete", res.detail);
      else toastErr(new Error(res.detail), "Rollback failed");
      invalidate();
    },
    onError: (err) => toastErr(err, "Rollback failed"),
  });

  const updateMut = useMutation({
    mutationFn: () => ipsApi.osUpdateRules(),
    onSuccess: (res) => {
      if (res.ranOnOs) toastOk("ET ruleset refreshed", res.note);
      else toastErr(new Error(res.note), "Rule refresh not run");
      invalidate();
    },
    onError: (err) => toastErr(err, "Rule refresh failed"),
  });

  if (osQuery.isLoading) {
    return (
      <Card>
        <CardContent className="flex items-center gap-2 pt-6 text-sm text-zinc-500">
          <Icons.Loader2 className="h-4 w-4 animate-spin" /> Reading Suricata engine state…
        </CardContent>
      </Card>
    );
  }
  if (osQuery.isError || !osQuery.data) {
    return (
      <Card>
        <CardContent className="flex items-center justify-between gap-2 pt-6 text-sm text-zinc-500">
          <span>Suricata engine state unavailable.</span>
          <Button size="sm" variant="outline" onClick={() => void osQuery.refetch()}>
            <Icons.RefreshCw className="h-3.5 w-3.5" /> Retry
          </Button>
        </CardContent>
      </Card>
    );
  }

  const { facts, plan, drift, lastApply, gate } = osQuery.data;
  const managedFile = facts.rulesFiles.find((f) => f.name === "utm-managed.rules");

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Icons.ShieldCheck className="h-5 w-5 text-zinc-700 dark:text-zinc-300" />
            <CardTitle className="text-base">OS Sync — Suricata</CardTitle>
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            <ServiceBadge state={facts.service} />
            {facts.version ? (
              <Badge variant="outline" className="border-zinc-300 bg-zinc-50 font-mono text-[11px] text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300">
                {facts.version.replace("This is ", "")}
              </Badge>
            ) : null}
            {facts.runningMode ? (
              <Badge variant="outline" className="border-zinc-300 bg-zinc-50 text-[11px] text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300">
                mode: {facts.runningMode}
              </Badge>
            ) : null}
            <Badge
              variant="outline"
              className={
                gate === "on"
                  ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                  : "border-amber-500/50 bg-amber-500/10 text-amber-600 dark:text-amber-400"
              }
            >
              OS apply gate {gate}
            </Badge>
            {drift.inSync ? (
              <Badge variant="outline" className="border-emerald-500/50 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                <Icons.Check className="h-3 w-3" /> in sync
              </Badge>
            ) : (
              <Badge variant="outline" className="border-amber-500/50 bg-amber-500/10 text-amber-600 dark:text-amber-400">
                <Icons.AlertTriangle className="h-3 w-3" /> drift detected
              </Badge>
            )}
          </div>
        </div>
        <CardDescription>
          The default (first enabled) policy is generated into{" "}
          <span className="font-mono text-xs">utm-managed.rules</span> +{" "}
          <span className="font-mono text-xs">threshold.config</span>, validated with{" "}
          <span className="font-mono text-xs">suricata -T</span>, then live-reloaded — automatic rollback on any failure.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* plan summary */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <div className="rounded-lg border border-zinc-200 bg-zinc-50 p-3 dark:border-zinc-800 dark:bg-zinc-900/60">
            <p className="text-[11px] font-medium uppercase tracking-wide text-zinc-500">Default policy</p>
            <p className="mt-0.5 truncate text-sm font-semibold text-zinc-800 dark:text-zinc-200" title={plan.defaultPolicy?.name ?? "none"}>
              {plan.defaultPolicy ? plan.defaultPolicy.name : "none enabled"}
            </p>
            {plan.defaultPolicy ? <p className="text-[11px] text-zinc-500">mode {plan.defaultPolicy.mode}</p> : null}
            {plan.enabledPolicyCount > 1 ? <p className="text-[11px] text-amber-600 dark:text-amber-400">{plan.enabledPolicyCount} enabled — first wins</p> : null}
          </div>
          <div className="rounded-lg border border-zinc-200 bg-zinc-50 p-3 dark:border-zinc-800 dark:bg-zinc-900/60">
            <p className="text-[11px] font-medium uppercase tracking-wide text-zinc-500">Managed rules</p>
            <p className="mt-0.5 text-sm font-semibold text-zinc-800 dark:text-zinc-200">{plan.managedRuleCount} custom</p>
            <p className="text-[11px] text-zinc-500">
              {managedFile ? `on disk: ${managedFile.sids} sids` : facts.yamlHasManagedFile ? "registered, not on disk" : "not registered"}
            </p>
          </div>
          <div className="rounded-lg border border-zinc-200 bg-zinc-50 p-3 dark:border-zinc-800 dark:bg-zinc-900/60">
            <p className="text-[11px] font-medium uppercase tracking-wide text-zinc-500">Threshold entries</p>
            <p className="mt-0.5 text-sm font-semibold text-zinc-800 dark:text-zinc-200">{plan.thresholdEntryCount}</p>
            <p className="text-[11px] text-zinc-500">
              {facts.thresholdManagedLines > 0 ? `${facts.thresholdManagedLines} live in threshold.config` : facts.yamlHasThresholdFile ? "no managed block" : "threshold-file inactive"}
            </p>
          </div>
          <div className="rounded-lg border border-zinc-200 bg-zinc-50 p-3 dark:border-zinc-800 dark:bg-zinc-900/60">
            <p className="text-[11px] font-medium uppercase tracking-wide text-zinc-500">ET updater</p>
            <p className="mt-0.5 text-sm font-semibold text-zinc-800 dark:text-zinc-200">{facts.updaterInstalled ? "suricata-update" : "not installed"}</p>
            <p className="text-[11px] text-zinc-500">{lastApply ? `last apply ${fmtDateTime(lastApply.lastApplyAt)}` : "never applied"}</p>
          </div>
        </div>

        {/* warnings */}
        {plan.warnings.length > 0 ? (
          <ul className="space-y-1 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-xs text-amber-700 dark:border-amber-500/40 dark:text-amber-400">
            {plan.warnings.map((w, i) => (
              <li key={i} className="flex gap-1.5">
                <Icons.AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />
                <span>{w}</span>
              </li>
            ))}
          </ul>
        ) : null}

        {/* rule files */}
        <Collapsible open={showFiles} onOpenChange={setShowFiles}>
          <div className="flex items-center justify-between">
            <CollapsibleTrigger asChild>
              <Button variant="ghost" size="sm" className="h-7 gap-1 px-2 text-xs text-zinc-500">
                <Icons.ChevronDown className={showFiles ? "rotate-180 transition-transform" : "transition-transform"} />
                {showFiles ? "Hide engine rule files" : `Engine rule files (${facts.rulesFiles.length})`}
              </Button>
            </CollapsibleTrigger>
          </div>
          <CollapsibleContent className="pt-1">
            <div className="max-h-64 overflow-y-auto rounded-lg border border-zinc-200 dark:border-zinc-800">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="text-xs">File</TableHead>
                    <TableHead className="text-right text-xs">SIDs</TableHead>
                    <TableHead className="text-right text-xs">alert</TableHead>
                    <TableHead className="text-right text-xs">drop</TableHead>
                    <TableHead className="text-right text-xs">pass</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {facts.rulesFiles.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center text-xs text-zinc-500">
                        no rules files readable under /var/lib/suricata/rules
                      </TableCell>
                    </TableRow>
                  ) : (
                    facts.rulesFiles.map((f) => (
                      <TableRow key={f.name}>
                        <TableCell className="font-mono text-xs">{f.name}</TableCell>
                        <TableCell className="text-right text-xs">{f.sids}</TableCell>
                        <TableCell className="text-right text-xs text-amber-600 dark:text-amber-400">{f.alert}</TableCell>
                        <TableCell className="text-right text-xs text-rose-600 dark:text-rose-400">{f.drop}</TableCell>
                        <TableCell className="text-right text-xs">{f.pass}</TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>
            {plan.managedRules || plan.thresholdBlock ? (
              <Collapsible className="mt-2">
                <CollapsibleTrigger asChild>
                  <Button variant="ghost" size="sm" className="h-7 gap-1 px-2 text-xs text-zinc-500">
                    <Icons.FileCode className="h-3.5 w-3.5" /> Preview generated files
                  </Button>
                </CollapsibleTrigger>
                <CollapsibleContent className="pt-1">
                  <pre className="max-h-48 overflow-auto rounded-lg border border-zinc-200 bg-zinc-950 p-3 font-mono text-[11px] leading-relaxed text-emerald-300 dark:border-zinc-800">
                    {`# utm-managed.rules\n${plan.managedRules}\n\n# threshold.config (managed block)\n${plan.thresholdBlock}`}
                  </pre>
                </CollapsibleContent>
              </Collapsible>
            ) : null}
          </CollapsibleContent>
        </Collapsible>

        {/* actions */}
        <div className="flex flex-wrap items-center gap-2">
          <Button
            onClick={() => applyMut.mutate()}
            disabled={applyMut.isPending || gate === "off" || drift.inSync}
            className="gap-1.5"
          >
            {applyMut.isPending ? <Icons.Loader2 className="h-4 w-4 animate-spin" /> : <Icons.Upload className="h-4 w-4" />}
            Apply to host
          </Button>
          <Button
            onClick={() => rollbackMut.mutate()}
            disabled={rollbackMut.isPending || !lastApply}
            variant="outline"
            className="gap-1.5 border-rose-500/50 text-rose-600 hover:bg-rose-500/10 dark:text-rose-400"
          >
            {rollbackMut.isPending ? <Icons.Loader2 className="h-4 w-4 animate-spin" /> : <Icons.Undo2 className="h-4 w-4" />}
            Rollback
          </Button>
          <Button
            onClick={() => updateMut.mutate()}
            disabled={updateMut.isPending || gate === "off" || !facts.updaterInstalled}
            variant="outline"
            className="gap-1.5"
            title={facts.updaterInstalled ? "Run suricata-update + live reload" : "suricata-update is not installed on this host"}
          >
            {updateMut.isPending ? <Icons.Loader2 className="h-4 w-4 animate-spin" /> : <Icons.DownloadCloud className="h-4 w-4" />}
            Update ET rules
          </Button>
          <span className="text-xs text-zinc-500">
            {drift.inSync
              ? "Generated policy matches the live engine."
              : `Drift: ${!drift.managedRulesInSync ? "managed rules " : ""}${!drift.thresholdInSync ? "thresholds " : ""}${!drift.yamlInSync ? "suricata.yaml" : ""}`}
          </span>
        </div>

        {lastApply ? (
          <p className="text-xs text-zinc-500">
            Last apply {fmtDateTime(lastApply.lastApplyAt)} — policy{" "}
            <span className="font-medium text-zinc-700 dark:text-zinc-300">{lastApply.policyName}</span>
            {lastApply.validateOk ? ", validated" : ""} {lastApply.reloaded ? ", engine reloaded" : ""}
            {" · "}backup <span className="font-mono">{lastApply.backupDir.split("/").pop()}</span>
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}
