"use client";

/**
 * IPv6 OS apply panel (IMPL-6) — mirrors the logs/os-apply.tsx pattern:
 * live kea-dhcp6 / radvd / utm_nat66 state per section (rendered hash vs
 * on-host conf hash, unit states, sysctl forwarding, nat66 kernel table),
 * per-entity drift rows, plan preview when the CONSOLE_OS_APPLY gate is off,
 * and an admin-gated "Apply to OS" action. Execution is snapshot-first with
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
import { usePermissions } from "../system/system-ui";
import { ipv6Api, type Ipv6ApplyResultDTO, type Ipv6OsStatusDTO } from "./ipv6-api";

function SectionDot({ ok }: { ok: boolean | null }) {
  return (
    <span
      className={cn(
        "inline-block h-1.5 w-1.5 shrink-0 rounded-full",
        ok === true ? "bg-emerald-500" : ok === false ? "bg-amber-500" : "bg-zinc-400",
      )}
      aria-hidden
    />
  );
}

function ToolBadge({ label, available, version }: { label: string; available: boolean; version?: string | null }) {
  return (
    <Badge
      variant="outline"
      className={cn(
        "text-[10px]",
        available
          ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
          : "border-zinc-300 text-zinc-500 dark:border-zinc-700",
      )}
      title={available ? `${label} binary present${version ? ` ${version}` : ""}` : `${label} not installed on this host`}
    >
      {label}
      {available && version ? ` ${version}` : ""}
    </Badge>
  );
}

function DriftBadge({ state }: { state: string }) {
  const cls =
    state === "in-sync"
      ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
      : state === "unsupported"
        ? "border-zinc-300 text-zinc-500 dark:border-zinc-700"
        : state === "disabled"
          ? "border-zinc-300 text-zinc-500 dark:border-zinc-700"
          : "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400";
  return (
    <Badge variant="outline" className={cn("text-[10px] uppercase", cls)}>
      {state}
    </Badge>
  );
}

function ApplyResult({ result }: { result: Ipv6ApplyResultDTO }) {
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
          Auto-restore: pre-apply confs, kernel ruleset and service states were restored.
        </p>
      ) : null}
      {result.backupDir && !result.applied ? (
        <p className="font-mono text-[10px] text-zinc-400">backup: {result.backupDir}</p>
      ) : null}
    </div>
  );
}

export function Ipv6OsPanel({ isAdmin }: { isAdmin: boolean }) {
  const queryClient = useQueryClient();
  const status = useQuery<Ipv6OsStatusDTO>({
    queryKey: ["ipv6", "os-status"],
    queryFn: ipv6Api.getOsStatus,
    staleTime: 10_000,
  });

  const apply = useMutation({
    mutationFn: () => ipv6Api.applyToOs(),
    onSuccess: (d: Ipv6ApplyResultDTO) => {
      if (d.refused) {
        toastErr(new Error(d.refused), "Apply refused");
      } else if (d.applied) {
        toastOk("IPv6 stack applied", d.reason ?? "kea-dhcp6 + radvd + nat66 converged");
      } else {
        toastErr(new Error(d.reason ?? "apply failed"), d.rolledBack ? "Restored" : d.gate === "off" ? "Plan preview" : "Apply failed");
      }
      void queryClient.invalidateQueries({ queryKey: ["ipv6"] });
    },
    onError: (err) => toastErr(err, "Apply failed"),
  });

  const os = status.data;
  const inSync = os ? os.summary.driftCount === 0 : null;
  const driftRows = (os?.drift ?? []).filter((d) => d.osState !== "in-sync");

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between space-y-0">
        <div className="space-y-1">
          <CardTitle className="flex items-center gap-2 text-base">
            <Icons.ServerCog className="h-4.5 w-4.5 text-zinc-500 dark:text-zinc-400" />
            OS integration (kea-dhcp6 · radvd · nft66)
          </CardTitle>
          <CardDescription>
            {os
              ? `kea ${os.kea.confPresent ? `hash ${os.kea.confHash?.slice(0, 8) ?? "—"}` : "conf absent"} · radvd ${os.radvd.confPresent ? `hash ${os.radvd.confHash?.slice(0, 8) ?? "—"}` : "conf absent"} · utm_nat66 ${os.nat66.tablePresent ? `${os.nat66.statements} stmt(s)` : "absent"}`
              : "Loading IPv6 OS state…"}
            {os?.lastApply?.appliedAt ? ` · applied ${os.lastApply.appliedAt.replace("T", " ").slice(0, 16)}` : ""}
          </CardDescription>
        </div>
        <div className="flex flex-wrap items-center justify-end gap-2">
          {os ? (
            <>
              <ToolBadge label="kea-dhcp6" available={os.keaAvailable} version={os.kea.version} />
              <ToolBadge label="radvd" available={os.radvdAvailable} version={os.radvd.version} />
              <ToolBadge label="nft" available={os.nftAvailable} />
              <Badge
                variant="outline"
                className={cn(
                  "text-[10px] uppercase",
                  os.gate === "on"
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                    : "border-zinc-300 text-zinc-500 dark:border-zinc-700",
                )}
                title={os.gate === "on" ? "CONSOLE_OS_APPLY=1 + host data plane — applies for real" : "apply returns a plan preview only"}
              >
                {os.gate === "on" ? "gate on" : "preview only"}
              </Badge>
              <Badge
                variant="outline"
                className={cn(
                  inSync === null
                    ? "border-zinc-300 text-zinc-500 dark:border-zinc-700"
                    : inSync
                      ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                      : "border-rose-500/30 bg-rose-500/10 text-rose-600 dark:text-rose-400",
                )}
              >
                <span className={cn("mr-1 inline-block h-1.5 w-1.5 rounded-full", inSync ? "bg-emerald-500" : "bg-rose-500")} aria-hidden />
                {inSync ? "in sync" : "drift"}
              </Badge>
            </>
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
            Read-only — applying to the OS requires the IPv6 write role.
          </p>
        ) : null}

        {status.isError ? (
          <p className="flex items-center gap-2 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-600 dark:text-rose-400">
            <Icons.AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden />
            OS status unavailable — {(status.error as Error)?.message ?? "unknown error"}
          </p>
        ) : null}

        {os ? (
          <div className="grid gap-2 sm:grid-cols-2">
            <div className="flex items-center gap-2 rounded-lg border border-zinc-200 px-3 py-2 text-xs dark:border-zinc-800">
              <SectionDot ok={os.kea.inSync} />
              <span className="font-medium text-zinc-700 dark:text-zinc-200">kea-dhcp6-server</span>
              <span className="text-zinc-500">{os.kea.running ? "active" : "inactive"}</span>
              <span className="ml-auto font-mono text-[10px] text-zinc-400" title={os.kea.confHash ?? ""}>
                {os.kea.inSync ? "render matches host" : os.kea.confPresent ? "conf drift" : "not deployed"}
              </span>
            </div>
            <div className="flex items-center gap-2 rounded-lg border border-zinc-200 px-3 py-2 text-xs dark:border-zinc-800">
              <SectionDot ok={os.radvd.inSync} />
              <span className="font-medium text-zinc-700 dark:text-zinc-200">radvd</span>
              <span className="text-zinc-500">{os.radvd.running ? "active" : "inactive"}</span>
              <span className="ml-auto font-mono text-[10px] text-zinc-400" title={os.radvd.confHash ?? ""}>
                {os.radvd.inSync ? "render matches host" : os.radvd.confPresent ? "conf drift" : "not deployed"}
              </span>
            </div>
            <div className="flex items-center gap-2 rounded-lg border border-zinc-200 px-3 py-2 text-xs dark:border-zinc-800">
              <SectionDot ok={os.nat66.inSync} />
              <span className="font-medium text-zinc-700 dark:text-zinc-200">nft table inet utm_nat66</span>
              <span className="text-zinc-500">{os.nat66.statements} stmt(s)</span>
              <span className="ml-auto font-mono text-[10px] text-zinc-400">{os.nat66.tablePresent ? "kernel" : "not loaded"}</span>
            </div>
            <div className="flex items-center gap-2 rounded-lg border border-zinc-200 px-3 py-2 text-xs dark:border-zinc-800">
              <SectionDot ok={os.sysctlExpected ? os.sysctlForwarding : true} />
              <span className="font-medium text-zinc-700 dark:text-zinc-200">net.ipv6.conf.all.forwarding</span>
              <span className="text-zinc-500">{os.sysctlForwarding === null ? "unknown" : os.sysctlForwarding ? "1" : "0"}</span>
              <span className="ml-auto font-mono text-[10px] text-zinc-400">{os.sysctlExpected ? "wanted" : "not forced"}</span>
            </div>
          </div>
        ) : null}

        {os && driftRows.length > 0 ? (
          <Collapsible defaultOpen>
            <CollapsibleTrigger className="flex items-center gap-1.5 text-xs text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300">
              <Icons.ChevronRight className="h-3.5 w-3.5 transition-transform [[data-state=open]>&]:rotate-90" aria-hidden />
              {driftRows.length} drift row{driftRows.length === 1 ? "" : "s"}
            </CollapsibleTrigger>
            <CollapsibleContent>
              <ul className="mt-1.5 max-h-44 space-y-1 overflow-y-auto rounded-lg border border-zinc-200 bg-zinc-50 p-2 dark:border-zinc-800 dark:bg-zinc-900" role="list">
                {driftRows.slice(0, 12).map((d, i) => (
                  <li key={i} className="flex items-center gap-2 text-xs">
                    <DriftBadge state={d.osState} />
                    <span className="text-zinc-600 dark:text-zinc-300">{d.name}</span>
                    <span className="truncate font-mono text-[10px] text-zinc-400" title={d.detail ?? ""}>
                      {d.detail ?? ""}
                    </span>
                  </li>
                ))}
              </ul>
            </CollapsibleContent>
          </Collapsible>
        ) : null}

        {os && os.warnings.length > 0 ? (
          <Collapsible>
            <CollapsibleTrigger className="flex items-center gap-1.5 text-xs text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300">
              <Icons.ChevronRight className="h-3.5 w-3.5 transition-transform [[data-state=open]>&]:rotate-90" aria-hidden />
              {os.warnings.length} renderer note{os.warnings.length === 1 ? "" : "s"} (multi-server ifaces, prefix lengths)
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
              {apply.data.confHash ? <span className="font-mono text-[10px] text-zinc-400">kea hash {apply.data.confHash}</span> : null}
            </p>
            <ApplyResult result={apply.data} />
          </div>
        ) : null}

        {os && os.gate === "off" ? (
          <Collapsible>
            <CollapsibleTrigger className="flex items-center gap-1.5 text-xs text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300">
              <Icons.ChevronRight className="h-3.5 w-3.5 transition-transform [[data-state=open]>&]:rotate-90" aria-hidden />
              Plan preview ({os.preview.keaConf.split("\n").length}·{os.preview.radvdConf.split("\n").length}·{os.preview.nat66Nft.split("\n").length} lines · gate off — POST /api/v1/ipv6/apply returns steps only)
            </CollapsibleTrigger>
            <CollapsibleContent>
              <pre className="mt-1.5 max-h-56 overflow-auto rounded-lg border border-zinc-200 bg-zinc-50 p-2 font-mono text-[10px] leading-relaxed text-zinc-600 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300">
                {`# /etc/kea/kea-dhcp6.conf\n${os.preview.keaConf}\n# /etc/radvd.conf\n${os.preview.radvdConf}\n# nat66\n${os.preview.nat66Nft}`}
              </pre>
            </CollapsibleContent>
          </Collapsible>
        ) : null}
      </CardContent>
    </Card>
  );
}
