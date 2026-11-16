"use client";

/**
 * VPN ↔ OS sync toolbar (mirrors FirewallOsSync / IpsOsSync):
 *   • honest sync badge — in-sync / drift / OS-off, computed from REAL host
 *     facts (charon VICI, wg ifaces, openvpn units)
 *   • Apply-to-OS dialog with plan preview (managed conns/ifaces, skipped
 *     tunnels, reasons) and per-step execution results with auto-rollback
 *     surfacing
 *   • gate = CONSOLE_VPN_OS (independent of CONSOLE_OS_APPLY like Multi-WAN)
 */

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import { toastErr, toastOk } from "../firewall/fw-ui";
import { vpnApi, type VpnOsApplyOutcome, type VpnOsStatus } from "./vpn-api";

const OS_KEY = ["vpn", "os-status"] as const;

function badgeFor(data: VpnOsStatus | undefined): { cls: string; label: string } {
  if (!data) return { cls: "border-zinc-300 bg-zinc-50 text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300", label: "OS sync …" };
  if (!data.available) return { cls: "border-zinc-300 bg-zinc-50 text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300", label: "OS plane unavailable" };
  if (data.summary.total === 0) return { cls: "border-zinc-300 bg-zinc-50 text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300", label: "OS sync — no tunnels" };
  if (data.gate === "off") return { cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400", label: "OS apply off (preview)" };
  if (data.summary.driftCount > 0) return { cls: "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400", label: `OS drift — ${data.summary.driftCount}` };
  return { cls: "border-transparent bg-emerald-600 text-white", label: "OS in sync" };
}

export function VpnOsSync() {
  const queryClient = useQueryClient();
  const [applyOpen, setApplyOpen] = useState(false);

  const status = useQuery({
    queryKey: OS_KEY,
    queryFn: () => vpnApi.osStatus(),
    refetchInterval: 30000,
  });

  const data = status.data;
  const badge = badgeFor(data);

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: OS_KEY });

  const applyMut = useMutation({
    mutationFn: () => vpnApi.applyOs(),
    onSuccess: (res) => {
      if (!res.applied && res.gate === "off") toastOk("Plan generated", "VPN OS enforcement is disabled — preview only");
      else if (!res.applied) toastErr(new Error(res.reason), "Apply failed");
      else toastOk("Tunnels applied to host", res.reason);
      invalidate();
    },
    onError: (err) => toastErr(err, "Apply failed"),
  });

  return (
    <div className="flex flex-wrap items-center gap-2">
      <div className="flex items-center gap-2">
        <Badge variant="outline" className={cn("gap-1.5", badge.cls)}>
          <Icons.Server className="h-3 w-3" />
          {badge.label}
        </Badge>
        <span className="hidden text-xs text-zinc-400 lg:inline">
          {data?.charonRunning ? "charon up" : "charon down"}
          {data?.ikePortsBound ? " · IKE :500/:4500" : ""}
          {data?.wgIfaces.length ? ` · ${data.wgIfaces.length} wg iface${data.wgIfaces.length === 1 ? "" : "s"}` : ""}
          {data?.openvpnServices.filter((s) => s.active).length
            ? ` · ${data.openvpnServices.filter((s) => s.active).length} ovpn svc`
            : ""}
        </span>
      </div>

      <Button size="sm" variant="outline" onClick={() => setApplyOpen(true)} title="Apply tunnel configs to the host (swanctl / wg-quick / openvpn)">
        <Icons.UploadCloud className="mr-1 h-4 w-4" /> Apply to OS
      </Button>

      <VpnApplyDialog
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
    </div>
  );
}

// ── apply dialog ────────────────────────────────────────────────────────────

function VpnApplyDialog(props: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  status: VpnOsStatus | undefined;
  applying: boolean;
  outcome: VpnOsApplyOutcome | null;
  error: string | null;
  onApply: () => void;
}) {
  const plan = props.outcome?.plan;
  const steps = plan?.steps ?? [];
  const results = props.outcome?.results;
  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Apply tunnels to OS</DialogTitle>
          <DialogDescription>
            Renders managed configs for strongswan (swanctl), WireGuard (wg-quick) and OpenVPN (server units), validates them
            live and rolls back automatically on failure. Managed namespace <code className="font-mono text-[11px]">utm-*</code> only —
            existing OS VPN configuration is never touched.
          </DialogDescription>
        </DialogHeader>

        <ScrollArea className="max-h-72 rounded-md border p-3">
          {props.status?.gate === "off" && (
            <p className="mb-2 rounded bg-amber-500/10 px-2 py-1.5 text-xs text-amber-600 dark:text-amber-400">
              CONSOLE_VPN_OS is off on this installation — the plan below is a PREVIEW only, nothing is executed.
            </p>
          )}
          {plan ? (
            <div className="space-y-2 text-xs">
              <p className="font-medium text-zinc-600 dark:text-zinc-300">
                {steps.length} step{steps.length === 1 ? "" : "s"}
                {plan.managedConns.length > 0 && ` · conns: ${plan.managedConns.join(", ")}`}
                {plan.managedIfaces.length > 0 && ` · ifaces/units: ${plan.managedIfaces.join(", ")}`}
              </p>
              {steps.map((s, i) => (
                <div key={`${s.cmd}-${i}`} className="flex items-start gap-2">
                  {results ? (
                    <span
                      className={cn(
                        "mt-0.5 flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-full text-[9px] font-bold text-white",
                        results.find((r) => r.cmd === s.cmd)?.ok ? "bg-emerald-600" : "bg-rose-600",
                      )}
                    >
                      {results.find((r) => r.cmd === s.cmd)?.ok ? "✓" : "×"}
                    </span>
                  ) : (
                    <Icons.ChevronRight className="mt-0.5 h-3.5 w-3.5 shrink-0 text-zinc-400" />
                  )}
                  <div className="min-w-0">
                    <p className="font-medium">{s.summary}</p>
                    <p className="truncate font-mono text-[10px] text-zinc-400" title={s.cmd}>
                      {s.cmd}
                    </p>
                    {results
                      ?.filter((r) => r.cmd === s.cmd && !r.ok && r.stderr)
                      .map((r, j) => (
                        <p key={j} className="whitespace-pre-wrap text-[10px] text-rose-500">
                          {r.stderr}
                        </p>
                      ))}
                  </div>
                </div>
              ))}
              {plan.skipped.map((s) => (
                <div key={s.name} className="flex items-start gap-2">
                  <Icons.SeparatorHorizontal className="mt-0.5 h-3.5 w-3.5 shrink-0 text-zinc-400" />
                  <div>
                    <p className="font-medium">
                      {s.name} <span className="font-normal text-zinc-400">— skipped</span>
                    </p>
                    <p className="text-[10px] text-zinc-500">{s.reason}</p>
                  </div>
                </div>
              ))}
              {plan.reasons.map((r) => (
                <p key={r} className="rounded bg-zinc-500/10 px-2 py-1 text-[11px] text-zinc-500 dark:text-zinc-400">
                  {r}
                </p>
              ))}
            </div>
          ) : props.status ? (
            <div className="space-y-1.5 text-xs text-zinc-500">
              <p>
                charon: {props.status.charonRunning ? "running" : "down"} · IKE ports {props.status.ikePortsBound ? "bound" : "not bound"} ·
                swanctl tool {props.status.tools.swanctl ? "yes" : "no"} · wg {props.status.tools.wgQuick ? "yes" : "no"} · openvpn{" "}
                {props.status.tools.openvpn ? "yes" : "no"}
              </p>
              <p>
                tunnels: {props.status.summary.total} total · {props.status.summary.inSync} in sync · {props.status.summary.driftCount}{" "}
                drift/missing
              </p>
              <p className="text-zinc-400">Press Apply to generate and execute the convergence plan.</p>
            </div>
          ) : (
            <p className="text-xs text-zinc-400">Loading host facts …</p>
          )}
        </ScrollArea>

        {props.error && <p className="mt-2 text-xs text-rose-500">{props.error}</p>}

        <DialogFooter>
          <Button variant="outline" onClick={() => props.onOpenChange(false)}>
            Close
          </Button>
          <Button onClick={props.onApply} disabled={props.applying}>
            {props.applying ? <Icons.LoaderCircle className="mr-1 h-4 w-4 animate-spin" /> : <Icons.UploadCloud className="mr-1 h-4 w-4" />}
            Apply
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
