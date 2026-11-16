"use client";

/**
 * DNS & DHCP ↔ OS sync toolbar (mirrors VpnOsSync):
 *   • honest sync badge — in-sync / drift / OS-off, computed from REAL host
 *     facts (unbound-checkconf, unbound-control, kea-dhcp4 -t, :53/:67 ports)
 *   • Apply-to-OS dialog with combined plan preview (managed zones/records/
 *     subnets, skipped items, reasons) and per-step execution results with
 *     auto-rollback surfacing
 *   • gates = CONSOLE_DNS_OS (unbound) + CONSOLE_DHCP_OS (kea), independent
 *     of CONSOLE_OS_APPLY like Multi-WAN / VPN
 * Used on BOTH the DNS Security and DHCP views.
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
import { dnsDhcpOsApi, type DnsDhcpOsApplyOutcome, type DnsDhcpOsStatus } from "./dns-dhcp-api";

const OS_KEY = ["dns-dhcp", "os-status"] as const;

function badgeFor(data: DnsDhcpOsStatus | undefined): { cls: string; label: string } {
  if (!data) return { cls: "border-zinc-300 bg-zinc-50 text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300", label: "OS sync …" };
  if (!data.dns.available && !data.dhcp.available) return { cls: "border-zinc-300 bg-zinc-50 text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300", label: "OS plane unavailable" };
  if (data.summary.total === 0) return { cls: "border-zinc-300 bg-zinc-50 text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300", label: "OS sync — nothing managed" };
  const dnsOff = data.dns.gate === "off";
  const dhcpOff = data.dhcp.gate === "off";
  if (dnsOff && dhcpOff) return { cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400", label: "OS apply off (preview)" };
  if (data.summary.driftCount > 0) return { cls: "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400", label: `OS drift — ${data.summary.driftCount}` };
  return { cls: "border-transparent bg-emerald-600 text-white", label: "OS in sync" };
}

function PlanSection(props: { title: string; outcome: DnsDhcpOsApplyOutcome["dns"] }) {
  const plan = props.outcome.plan;
  const steps = plan?.steps ?? [];
  const results = props.outcome.results;
  return (
    <div className="space-y-1.5">
      <p className="flex items-center gap-1.5 font-semibold text-zinc-700 dark:text-zinc-200">
        <Icons.Cpu className="h-3.5 w-3.5" /> {props.title}
        {props.outcome.gate === "off" && (
          <span className="rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-600 dark:text-amber-400">gate off — preview</span>
        )}
      </p>
      {plan ? (
        <>
          <p className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
            {steps.length} step{steps.length === 1 ? "" : "s"}
            {plan.managedSubnets?.length ? ` · subnets: ${plan.managedSubnets.map((s) => s.cidr).join(", ")}` : ""}
            {plan.managedZones?.length ? ` · zones: ${plan.managedZones.length}` : ""}
            {plan.managedRecords?.length ? ` · records: ${plan.managedRecords.length}` : ""}
            {plan.preservedSubnets?.length ? ` · preserved (foreign): ${plan.preservedSubnets.join(", ")}` : ""}
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
                <p className="font-medium">
                  {s.summary}
                  {s.optional ? <span className="ml-1 text-[10px] font-normal text-zinc-400">(probe)</span> : null}
                </p>
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
        </>
      ) : (
        <p className="text-[11px] text-zinc-400">Plan not generated yet.</p>
      )}
    </div>
  );
}

export function DnsDhcpOsSync() {
  const queryClient = useQueryClient();
  const [applyOpen, setApplyOpen] = useState(false);

  const status = useQuery({
    queryKey: OS_KEY,
    queryFn: () => dnsDhcpOsApi.osStatus(),
    refetchInterval: 30000,
  });

  const data = status.data;
  const badge = badgeFor(data);

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: OS_KEY });

  const applyMut = useMutation({
    mutationFn: () => dnsDhcpOsApi.applyOs(),
    onSuccess: (res) => {
      if (res.gate === "off") toastOk("Plan generated", "DNS/DHCP OS enforcement is disabled — preview only");
      else if (!res.applied) toastErr(new Error(res.reason), "Apply failed");
      else toastOk("DNS & DHCP applied to host", res.reason);
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
          {data?.dns.available
            ? `unbound ${data.dns.version ?? "?"}${data.dns.running ? " up" : " down"}${data.dns.ports53Bound ? " :53" : ""}${data.dns.logQueriesEnabled ? " · qlog on" : ""}`
            : "unbound n/a"}
          {data?.dhcp.available
            ? ` · kea ${data.dhcp.version ?? "?"}${data.dhcp.running ? " up" : " down"}${data.dhcp.port67Bound ? " :67" : ""}${data.dhcp.leaseCount ? ` · ${data.dhcp.leaseCount} lease${data.dhcp.leaseCount === 1 ? "" : "s"}` : ""}`
            : data?.dhcp?.tools.keaDhcp4
              ? " · kea not running"
              : ""}
        </span>
      </div>

      <Button
        size="sm"
        variant="outline"
        onClick={() => setApplyOpen(true)}
        title="Apply resolver policies/records + DHCP subnets to the host (unbound-control reload / kea-dhcp4 -t)"
      >
        <Icons.UploadCloud className="mr-1 h-4 w-4" /> Apply to OS
      </Button>

      <DnsDhcpApplyDialog
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

function DnsDhcpApplyDialog(props: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  status: DnsDhcpOsStatus | undefined;
  applying: boolean;
  outcome: DnsDhcpOsApplyOutcome | null;
  error: string | null;
  onApply: () => void;
}) {
  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Apply DNS &amp; DHCP to OS</DialogTitle>
          <DialogDescription>
            Renders the managed unbound fragment (listeners, ACLs, caching, RRL, forward zones, policies, records) and merges
            the Kea DHCPv4 config (managed subnets id ≥ 1000, reservations, foreign subnets preserved verbatim), validates live
            (<code className="font-mono text-[11px]">unbound-checkconf</code>, <code className="font-mono text-[11px]">kea-dhcp4 -t</code>) and
            rolls back automatically on failure. unbound reloads with zero downtime; kea restarts only when its config changed.
          </DialogDescription>
        </DialogHeader>

        <ScrollArea className="max-h-80 rounded-md border p-3">
          {props.outcome ? (
            <div className="space-y-3 text-xs">
              <p
                className={cn(
                  "rounded px-2 py-1.5 font-medium",
                  props.outcome.applied
                    ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                    : "bg-amber-500/10 text-amber-600 dark:text-amber-400",
                )}
              >
                {props.outcome.reason}
              </p>
              <PlanSection title="DNS — unbound" outcome={props.outcome.dns} />
              <div className="border-t pt-3">
                <PlanSection title="DHCP — Kea DHCPv4" outcome={props.outcome.dhcp} />
              </div>
            </div>
          ) : props.status ? (
            <div className="space-y-1.5 text-xs text-zinc-500">
              <p>
                unbound: {props.status.dns.running ? "running" : "down"} · :53 {props.status.dns.ports53Bound ? "bound" : "not bound"} ·
                checkconf {props.status.dns.checkconfOk == null ? "n/a" : props.status.dns.checkconfOk ? "ok" : "FAILED"} · control{" "}
                {props.status.dns.controlOk ? "yes" : "no"} · managed conf {props.status.dns.managedFilePresent ? "deployed" : "absent"}
              </p>
              <p>
                kea: {props.status.dhcp.running ? "running" : "down"} · :67 {props.status.dhcp.port67Bound ? "bound" : "not bound"} ·
                conf {props.status.dhcp.configValid == null ? "unverified" : props.status.dhcp.configValid ? "valid" : "INVALID"} ·
                leases {props.status.dhcp.leaseCount}
                {props.status.dhcp.leaseReadError ? " (lease read failed)" : ""}
              </p>
              <p>
                managed items: {props.status.summary.total} tracked · {props.status.summary.inSync} in sync ·{" "}
                {props.status.summary.driftCount} drift/missing · {props.status.summary.unsupported} unsupported
              </p>
              {props.status.dhcp.mergeError && (
                <p className="text-rose-500">kea merge refused: {props.status.dhcp.mergeError}</p>
              )}
              <p className="text-zinc-400">Press Apply to generate and execute the convergence plans.</p>
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
