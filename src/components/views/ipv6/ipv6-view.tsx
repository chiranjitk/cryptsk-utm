"use client";

/**
 * #/network/ipv6 — IPv6 Dual-Stack (M21, spec 2.7). Single-view layout: a
 * status strip (dual-stack pill / delegated prefix chip / RA-mode badge /
 * v6 firewall + NAT66 + DHCPv6 counts, 10s TanStack polling — no socket
 * events for this module), the simulated IA_PD prefix-delegation
 * lease panel next to the dual-stack settings card (toggles + PD WAN select +
 * PD prefix-length pills + RA mode), then the NAT66 rules table (per-type
 * translation cell, deterministic "simulate traffic" hit bumps) and the
 * DHCPv6 servers table. Theme: blue-600 for active/primary, amber for
 * masquerade, zinc for DNAT/disabled.
 */

import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";
import { IPV6_CIDR_RE, IPV6_RE, ipv6ToBigInt } from "@/lib/validators/ipv6";
import {
  DHCPV6_PREFIX_LENGTHS,
  Ipv6ApiError,
  FALLBACK_INTERFACES,
  NAT66_TYPES,
  PD_PREFIX_LENGTHS,
  RA_MODES,
  fieldErrorsOf,
  fmtLifetime,
  fmtRelative,
  ipv6Api,
  raModeLabel,
  type Dhcpv6PrefixLength,
  type Dhcpv6ServerDTO,
  type Ipv6SettingsDTO,
  type Ipv6StatusDTO,
  type Nat66RuleDTO,
  type Nat66Type,
  type PdPrefixLength,
  type PrefixDelegationDTO,
  type RaMode,
} from "./ipv6-api";
import { ConfirmDialog, EmptyBlock, FieldLabel, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";

function invalidateAll(queryClient: ReturnType<typeof useQueryClient>) {
  void queryClient.invalidateQueries({ queryKey: ["ipv6"] });
}

/** First zod fieldError of a failed save, else the error message itself. */
function firstErrorOf(err: unknown): string {
  const fe = fieldErrorsOf(err);
  for (const messages of Object.values(fe)) {
    const first = messages[0];
    if (first) return first;
  }
  return err instanceof Error ? err.message : "Save failed";
}

/** Errors surfaced to the user — 401 is left to the shell (re-login flow). */
function toastLoadErr(err: unknown, fallback: string) {
  if (err instanceof Ipv6ApiError && err.code === "UNAUTHORIZED") return;
  toastErr(err, fallback);
}

/**
 * Toast once when a query transitions into the error state (10s status polling
 * keeps retrying — repeated failures must not spam toasts).
 */
function useLoadErrorToast(query: { isError: boolean; error: unknown }, label: string) {
  const wasError = useRef(false);
  const { isError, error } = query;
  useEffect(() => {
    if (isError && !wasError.current) toastLoadErr(error, `${label} failed to load`);
    wasError.current = isError;
  }, [isError, error, label]);
}

// ── badge recipes (UI_DESIGN_SYSTEM: nptv6=blue, masquerade=amber, dnat=zinc) ──

const NAT66_BADGE: Record<Nat66Type, string> = {
  nptv6: "border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400",
  masquerade66: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  dnat66: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
};

function Nat66TypeBadge({ type }: { type: Nat66Type }) {
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium", NAT66_BADGE[type])}>
      <Icons.ArrowLeftRight className="h-3 w-3" />
      {type}
    </Badge>
  );
}

function FlagPill({ label, on }: { label: string; on: boolean }) {
  return (
    <Badge
      variant="outline"
      className={cn(
        "text-[10px]",
        on
          ? "border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400"
          : "border-zinc-300 text-zinc-400 dark:border-zinc-700",
      )}
    >
      {label}
    </Badge>
  );
}

// ── stat cards (sdwan StatCard pattern) ──────────────────────────────────────

function StatCard(props: { label: string; value: React.ReactNode; icon: React.ReactNode; sub?: React.ReactNode }) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs font-medium text-zinc-500">{props.label}</span>
          <span className="text-blue-600 dark:text-blue-400">{props.icon}</span>
        </div>
        <div className="mt-1">{props.value}</div>
        {props.sub ? <div className="mt-1">{props.sub}</div> : null}
      </CardContent>
    </Card>
  );
}

// ── status strip ─────────────────────────────────────────────────────────────

function StatusStrip() {
  const statusQuery = useQuery({
    queryKey: ["ipv6", "status"],
    queryFn: ipv6Api.getStatus,
    refetchInterval: 10_000, // live strip — no socket events for this module
  });
  const status: Ipv6StatusDTO | undefined = statusQuery.data;
  useLoadErrorToast(statusQuery, "Dual-stack status");

  return (
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <StatCard
        label="Dual-stack"
        value={
          status ? (
            <Badge
              variant="outline"
              className={cn(
                "gap-1 font-medium",
                status.enabled
                  ? "border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400"
                  : "border-zinc-300 bg-zinc-100 text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800",
              )}
            >
              <Icons.Globe className="h-3 w-3" />
              {status.enabled ? "enabled" : "disabled"}
            </Badge>
          ) : (
            <Skeleton className="h-6 w-20" />
          )
        }
        icon={<Icons.Globe className="h-4 w-4" />}
        sub={
          status ? (
            <div className="flex flex-wrap gap-1">
              <FlagPill label="dhcpv6" on={status.dhcpv6Enabled} />
              <FlagPill label="slaac" on={status.slaacEnabled} />
            </div>
          ) : null
        }
      />
      <StatCard
        label="Delegated prefix"
        value={
          status ? (
            <span
              className="block truncate font-mono text-lg font-semibold text-blue-600 dark:text-blue-400"
              title={status.delegatedPrefix}
            >
              {status.delegatedPrefix}
            </span>
          ) : (
            <Skeleton className="h-6 w-40" />
          )
        }
        icon={<Icons.Network className="h-4 w-4" />}
        sub={<p className="text-[11px] text-zinc-400">IA_PD on the selected WAN uplink</p>}
      />
      <StatCard
        label="Router advertisements"
        value={
          status ? (
            <Badge variant="outline" className="border-blue-500/40 bg-blue-500/10 font-medium text-blue-600 dark:text-blue-400">
              <Icons.Rss className="h-3 w-3" />
              {raModeLabel(status.raMode)}
            </Badge>
          ) : (
            <Skeleton className="h-6 w-28" />
          )
        }
        icon={<Icons.Rss className="h-4 w-4" />}
        sub={<p className="text-[11px] text-zinc-400">RA announcements per RFC 4861</p>}
      />
      <StatCard
        label="v6 firewall rules"
        value={
          status ? (
            <span className="text-2xl font-semibold tabular-nums">{status.v6FirewallRules}</span>
          ) : (
            <Skeleton className="h-8 w-12" />
          )
        }
        icon={<Icons.ShieldCheck className="h-4 w-4" />}
        sub={
          status ? (
            <div className="flex flex-wrap items-center gap-1">
              <button
                type="button"
                onClick={() => {
                  window.location.hash = "#/firewall/rules";
                }}
                className="inline-flex items-center gap-1 rounded-full border border-blue-500/40 bg-blue-500/10 px-2.5 py-1 text-[11px] font-medium text-blue-600 transition-colors hover:bg-blue-500/20 dark:text-blue-400"
              >
                <Icons.ShieldCheck className="h-3 w-3" />
                Open v6 rules
              </button>
              <Badge variant="outline" className="border-zinc-300 text-[10px] text-zinc-500 dark:border-zinc-700">
                nat66 {status.nat66.enabled}/{status.nat66.total}
              </Badge>
              <Badge variant="outline" className="border-zinc-300 text-[10px] text-zinc-500 dark:border-zinc-700">
                dhcpv6 {status.dhcpv6.enabledServers}/{status.dhcpv6.servers}
              </Badge>
            </div>
          ) : null
        }
      />
    </div>
  );
}

// ── prefix delegation (simulated IA_PD lease) ────────────────────────────────

function LeaseRow(props: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-2 border-b border-zinc-100 py-2 last:border-b-0 dark:border-zinc-800">
      <span className="text-xs font-medium text-zinc-500">{props.label}</span>
      {props.children}
    </div>
  );
}

function PrefixDelegationCard() {
  const leaseQuery = useQuery({ queryKey: ["ipv6", "pd"], queryFn: ipv6Api.getPrefixDelegation });
  const lease: PrefixDelegationDTO | undefined = leaseQuery.data;
  useLoadErrorToast(leaseQuery, "Prefix delegation lease");

  const renew = async () => {
    await leaseQuery.refetch();
    toastOk("Lease renewed", "The simulated IA_PD lease was re-computed");
  };

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.ArrowDownToLine className="h-4 w-4 text-blue-600 dark:text-blue-400" />
          Prefix delegation (IA_PD)
        </CardTitle>
        <Button
          size="sm"
          variant="outline"
          className="h-8"
          disabled={leaseQuery.isFetching}
          onClick={() => void renew()}
        >
          {leaseQuery.isFetching ? (
            <Icons.Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
          ) : (
            <Icons.RefreshCw className="mr-1 h-3.5 w-3.5" />
          )}
          Renew
        </Button>
      </CardHeader>
      <CardContent className="p-4 pt-0">
        {leaseQuery.isError ? (
          <QueryError error={leaseQuery.error} onRetry={() => void leaseQuery.refetch()} />
        ) : !lease ? (
          <div className="space-y-3">
            <Skeleton className="h-9 w-56" />
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-4 w-3/4" />
          </div>
        ) : (
          <div className="space-y-3">
            <p className="truncate rounded-lg border border-blue-500/30 bg-blue-500/5 px-4 py-3 font-mono text-2xl font-semibold text-blue-600 dark:text-blue-400" title={lease.prefix}>
              {lease.prefix}
            </p>
            <div>
              <LeaseRow label="IAID">
                <span className="font-mono text-xs">{lease.iaId}</span>
              </LeaseRow>
              <LeaseRow label="Valid lifetime">
                <span className="text-xs font-medium tabular-nums">{fmtLifetime(lease.validLifetime)}</span>
              </LeaseRow>
              <LeaseRow label="Preferred lifetime">
                <span className="text-xs font-medium tabular-nums">{fmtLifetime(lease.preferredLifetime)}</span>
              </LeaseRow>
              <LeaseRow label="Last renew">
                <span className="text-xs tabular-nums text-zinc-500">{fmtRelative(lease.lastRenew)}</span>
              </LeaseRow>
            </div>
            <div className="flex items-start gap-2 rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
              <Icons.Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-zinc-400" />
              <p className="text-[11px] leading-relaxed text-zinc-500">
                Simulated IA_PD — the appliance delegates the real prefix via DHCPv6-PD on the
                selected WAN interface; values here are deterministic demo data.
              </p>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ── dual-stack settings card ─────────────────────────────────────────────────

interface SettingsDraft {
  enabled: boolean;
  dhcpv6Enabled: boolean;
  slaacEnabled: boolean;
  rdnssEnabled: boolean;
  pdWanInterface: string;
  pdPrefixLength: PdPrefixLength;
  raMode: RaMode;
}

function draftFrom(s: Ipv6SettingsDTO): SettingsDraft {
  return {
    enabled: s.enabled,
    dhcpv6Enabled: s.dhcpv6Enabled,
    slaacEnabled: s.slaacEnabled,
    rdnssEnabled: s.rdnssEnabled,
    pdWanInterface: s.pdWanInterface,
    pdPrefixLength: s.pdPrefixLength as PdPrefixLength,
    raMode: s.raMode,
  };
}

function ToggleRow(props: {
  label: string;
  description: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
      <div>
        <p className="text-xs font-medium text-zinc-700 dark:text-zinc-300">{props.label}</p>
        <p className="text-[11px] text-zinc-400">{props.description}</p>
      </div>
      <Switch checked={props.checked} onCheckedChange={props.onChange} aria-label={props.label} />
    </div>
  );
}

function SettingsCard(props: { ifaces: string[] }) {
  const queryClient = useQueryClient();
  const settingsQuery = useQuery({ queryKey: ["ipv6", "settings"], queryFn: ipv6Api.getSettings });
  const settings = settingsQuery.data;
  useLoadErrorToast(settingsQuery, "Dual-stack settings");
  const [draft, setDraft] = useState<SettingsDraft | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const current: SettingsDraft | null = settings ? (draft ?? draftFrom(settings)) : null;

  const save = useMutation({
    mutationFn: (body: SettingsDraft) => ipv6Api.updateSettings({ ...body }),
    onSuccess: () => {
      toastOk("Settings saved", "IPv6 dual-stack configuration updated");
      setDraft(null);
      setErr(null);
      invalidateAll(queryClient);
    },
    onError: (e) => {
      setErr(firstErrorOf(e));
      toastLoadErr(e, "Saving settings failed");
    },
  });

  const patch = (p: Partial<SettingsDraft>) => {
    if (!current) return;
    setDraft({ ...current, ...p });
  };

  const ifaceOptions = Array.from(
    new Set([...props.ifaces, ...(current ? [current.pdWanInterface] : [])]),
  );

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.Settings2 className="h-4 w-4 text-blue-600 dark:text-blue-400" />
          Dual-stack settings
        </CardTitle>
        {draft ? (
          <Badge variant="outline" className="border-amber-500/40 bg-amber-500/10 text-[10px] text-amber-600 dark:text-amber-400">
            unsaved
          </Badge>
        ) : null}
      </CardHeader>
      <CardContent className="p-4 pt-0">
        {settingsQuery.isError ? (
          <QueryError error={settingsQuery.error} onRetry={() => void settingsQuery.refetch()} />
        ) : !current ? (
          <div className="space-y-3">
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-9 w-full" />
          </div>
        ) : (
          <div className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <ToggleRow
                label="IPv6 enabled"
                description="Master switch for the dual-stack data plane"
                checked={current.enabled}
                onChange={(v) => patch({ enabled: v })}
              />
              <ToggleRow
                label="DHCPv6"
                description="Stateful address assignment alongside SLAAC"
                checked={current.dhcpv6Enabled}
                onChange={(v) => patch({ dhcpv6Enabled: v })}
              />
              <ToggleRow
                label="SLAAC"
                description="Stateless address autoconfiguration per RFC 4862"
                checked={current.slaacEnabled}
                onChange={(v) => patch({ slaacEnabled: v })}
              />
              <ToggleRow
                label="RDNSS"
                description="Recursive DNS server option in RAs (RFC 8106)"
                checked={current.rdnssEnabled}
                onChange={(v) => patch({ rdnssEnabled: v })}
              />
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <FieldLabel hint="delegation uplink">PD WAN interface</FieldLabel>
                <Select
                  value={current.pdWanInterface}
                  onValueChange={(v) => patch({ pdWanInterface: v })}
                >
                  <SelectTrigger className="w-full">
                    <SelectValue placeholder="Select interface" />
                  </SelectTrigger>
                  <SelectContent>
                    {ifaceOptions.map((name) => (
                      <SelectItem key={name} value={name}>
                        {name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <FieldLabel hint="RFC 6603">Delegated prefix length</FieldLabel>
                <div className="flex flex-wrap gap-1.5">
                  {PD_PREFIX_LENGTHS.map((len) => {
                    const active = current.pdPrefixLength === len;
                    return (
                      <button
                        key={len}
                        type="button"
                        aria-pressed={active}
                        onClick={() => patch({ pdPrefixLength: len })}
                        className={cn(
                          "min-h-9 rounded-full border px-3 text-xs transition-colors",
                          active
                            ? "border-blue-500/40 bg-blue-500/10 font-semibold text-blue-600 dark:text-blue-400"
                            : "border-zinc-200 text-zinc-500 hover:bg-zinc-100 dark:border-zinc-800 dark:text-zinc-400 dark:hover:bg-zinc-800",
                        )}
                      >
                        /{len}
                      </button>
                    );
                  })}
                </div>
              </div>
            </div>

            <div>
              <FieldLabel hint="flags in router advertisements">RA mode</FieldLabel>
              <Select value={current.raMode} onValueChange={(v) => patch({ raMode: v as RaMode })}>
                <SelectTrigger className="w-full">
                  <SelectValue placeholder="Select RA mode" />
                </SelectTrigger>
                <SelectContent>
                  {RA_MODES.map((m) => (
                    <SelectItem key={m} value={m}>
                      {raModeLabel(m)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {err ? <p className="text-xs text-rose-600">{err}</p> : null}

            <div className="flex items-center justify-end gap-2">
              {draft ? (
                <Button variant="ghost" size="sm" onClick={() => setDraft(null)}>
                  Discard
                </Button>
              ) : null}
              <Button
                size="sm"
                className="min-h-9 bg-blue-600 px-5 text-white hover:bg-blue-700"
                disabled={!draft || save.isPending}
                onClick={() => draft && save.mutate(draft)}
              >
                {save.isPending ? "Saving…" : "Save settings"}
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ── NAT66 translation cell ───────────────────────────────────────────────────

function TranslationCell({ rule }: { rule: Nat66RuleDTO }) {
  if (rule.type === "nptv6") {
    return (
      <span className="flex flex-wrap items-center gap-1.5 font-mono text-xs" title={`${rule.sourcePrefix ?? ""} → ${rule.translatedPrefix ?? ""}`}>
        <span className="max-w-36 truncate">{rule.sourcePrefix}</span>
        <Icons.ArrowRight className="h-3 w-3 shrink-0 text-zinc-400" />
        <span className="max-w-36 truncate text-blue-600 dark:text-blue-400">{rule.translatedPrefix}</span>
      </span>
    );
  }
  if (rule.type === "dnat66") {
    return (
      <span className="flex items-center gap-1.5 font-mono text-xs">
        <span className="text-zinc-400">dnat</span>
        <Icons.ArrowRight className="h-3 w-3 shrink-0 text-zinc-400" />
        <span className="text-blue-600 dark:text-blue-400">:{rule.destPort}</span>
      </span>
    );
  }
  return (
    <span className="flex items-center gap-1.5 font-mono text-xs">
      <span className="text-zinc-400">all sources</span>
      <Icons.ArrowRight className="h-3 w-3 shrink-0 text-zinc-400" />
      <span className="text-blue-600 dark:text-blue-400">iface address</span>
    </span>
  );
}

// ── NAT66 editor (create + edit, per-type field visibility) ──────────────────

function Nat66Editor(props: { rule: Nat66RuleDTO | null; ifaces: string[]; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = props.rule !== null;
  const [name, setName] = useState(props.rule?.name ?? "");
  const [type, setType] = useState<Nat66Type>(props.rule?.type ?? "nptv6");
  const [sourcePrefix, setSourcePrefix] = useState(props.rule?.sourcePrefix ?? "");
  const [translatedPrefix, setTranslatedPrefix] = useState(props.rule?.translatedPrefix ?? "");
  const [destPort, setDestPort] = useState(props.rule?.destPort !== null && props.rule?.destPort !== undefined ? String(props.rule.destPort) : "");
  const [interfaceName, setInterfaceName] = useState(
    props.rule?.interfaceName ?? props.ifaces[0] ?? "wan0",
  );
  const [enabled, setEnabled] = useState(props.rule?.enabled ?? true);
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => {
      const id = props.rule?.id;
      if (isEdit && id !== undefined) return ipv6Api.updateNat66(id, body);
      return ipv6Api.createNat66(body);
    },
    onSuccess: (rule) => {
      toastOk(isEdit ? "NAT66 rule updated" : "NAT66 rule created", rule.name);
      invalidateAll(queryClient);
      props.onClose();
    },
    onError: (e) => setErr(firstErrorOf(e)),
  });

  const submit = () => {
    if (!name.trim()) {
      setErr("Name is required");
      return;
    }
    if (type === "nptv6") {
      if (!IPV6_CIDR_RE.test(sourcePrefix.trim())) {
        setErr("Source prefix must be an IPv6 CIDR like 2001:db8:1::/48");
        return;
      }
      if (!IPV6_CIDR_RE.test(translatedPrefix.trim())) {
        setErr("Translated prefix must be an IPv6 CIDR like 2001:db8:2::/48");
        return;
      }
      if (sourcePrefix.trim().toLowerCase() === translatedPrefix.trim().toLowerCase()) {
        setErr("Translated prefix must differ from the source prefix");
        return;
      }
    }
    if (type === "dnat66") {
      const port = Number(destPort);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        setErr("Destination port must be an integer between 1 and 65535");
        return;
      }
    }
    setErr(null);
    save.mutate({
      name: name.trim(),
      type,
      sourcePrefix: type === "nptv6" ? sourcePrefix.trim() : null,
      translatedPrefix: type === "nptv6" ? translatedPrefix.trim() : null,
      destPort: type === "dnat66" ? Number(destPort) : null,
      interfaceName,
      enabled,
    });
  };

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-base">{isEdit ? "Edit NAT66 rule" : "New NAT66 rule"}</DialogTitle>
          <DialogDescription>
            NPTv6 rewrites prefixes, masquerade66 source-NATs to the interface address, DNAT66
            forwards a WAN port.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div>
            <FieldLabel>Name</FieldLabel>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="corp-nptv6" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel>Type</FieldLabel>
              <Select value={type} onValueChange={(v) => setType(v as Nat66Type)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {NAT66_TYPES.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel>Interface</FieldLabel>
              <Select value={interfaceName} onValueChange={setInterfaceName}>
                <SelectTrigger>
                  <SelectValue placeholder="Select interface" />
                </SelectTrigger>
                <SelectContent>
                  {props.ifaces.map((i) => (
                    <SelectItem key={i} value={i}>
                      {i}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          {type === "nptv6" ? (
            <div className="grid gap-4 sm:grid-cols-[1fr_auto_1fr] sm:items-end">
              <div>
                <FieldLabel hint="IPv6 CIDR">Source prefix</FieldLabel>
                <Input
                  className="font-mono text-xs"
                  value={sourcePrefix}
                  onChange={(e) => setSourcePrefix(e.target.value)}
                  placeholder="2001:db8:1::/48"
                />
              </div>
              <Icons.ArrowRight className="mx-auto h-4 w-4 text-zinc-400 sm:mb-2.5" />
              <div>
                <FieldLabel hint="must differ">Translated prefix</FieldLabel>
                <Input
                  className="font-mono text-xs"
                  value={translatedPrefix}
                  onChange={(e) => setTranslatedPrefix(e.target.value)}
                  placeholder="2001:db8:2::/48"
                />
              </div>
            </div>
          ) : null}

          {type === "dnat66" ? (
            <div>
              <FieldLabel hint="1–65535">Destination port</FieldLabel>
              <Input
                className="font-mono text-xs"
                inputMode="numeric"
                value={destPort}
                onChange={(e) => setDestPort(e.target.value)}
                placeholder="25"
              />
            </div>
          ) : null}

          {type === "masquerade66" ? (
            <p className="rounded-lg border border-zinc-200 p-3 text-[11px] text-zinc-500 dark:border-zinc-800">
              All IPv6 traffic leaving <span className="font-mono">{interfaceName}</span> is
              masqueraded to the interface address — no extra fields.
            </p>
          ) : null}

          <div className="flex items-center justify-between gap-4 rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
            <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Rule enabled</span>
            <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="Rule enabled" />
          </div>

          {err ? <p className="text-xs text-rose-600">{err}</p> : null}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button
            className="bg-blue-600 text-white hover:bg-blue-700"
            disabled={save.isPending || !name.trim()}
            onClick={submit}
          >
            {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create rule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── NAT66 table ──────────────────────────────────────────────────────────────

function Nat66Card(props: {
  rules: Nat66RuleDTO[];
  isLoading: boolean;
  isError: boolean;
  error: unknown;
  onRetry: () => void;
  onAdd: () => void;
  onEdit: (rule: Nat66RuleDTO) => void;
  onDelete: (rule: Nat66RuleDTO) => void;
}) {
  const queryClient = useQueryClient();
  useLoadErrorToast(props, "NAT66 rules");
  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => ipv6Api.updateNat66(id, { enabled }),
    onSuccess: () => invalidateAll(queryClient),
    onError: (e) => toastLoadErr(e, "Toggle failed"),
  });
  const simulate = useMutation({
    mutationFn: ({ id, name, before }: { id: number; name: string; before: number }) =>
      ipv6Api.simulateNat66(id).then((row) => ({ row, name, before })),
    onSuccess: ({ row, name, before }) => {
      toastOk("Traffic simulated", `${name}: ${before} → ${row.hitCount} hits`);
      invalidateAll(queryClient);
    },
    onError: (e) => toastLoadErr(e, "Simulate failed"),
  });

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.ArrowLeftRight className="h-4 w-4 text-blue-600 dark:text-blue-400" />
          NAT66 rules
        </CardTitle>
        <Button size="sm" className="h-8 bg-blue-600 text-white hover:bg-blue-700" onClick={props.onAdd}>
          <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add rule
        </Button>
      </CardHeader>
      <CardContent className="p-0">
        {props.isError ? (
          <div className="p-4">
            <QueryError error={props.error} onRetry={props.onRetry} />
          </div>
        ) : props.isLoading ? (
          <TableSkeleton rows={3} cols={7} />
        ) : props.rules.length === 0 ? (
          <EmptyBlock
            icon={<Icons.ArrowLeftRight className="h-6 w-6" />}
            title="No NAT66 rules yet"
            description="Create a rule to translate IPv6 prefixes, masquerade outbound traffic or forward a WAN port."
            action={
              <Button size="sm" className="bg-blue-600 text-white hover:bg-blue-700" onClick={props.onAdd}>
                <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add rule
              </Button>
            }
          />
        ) : (
          <div className="max-h-96 overflow-y-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead className="w-32">Type</TableHead>
                  <TableHead>Translation</TableHead>
                  <TableHead className="w-20">Iface</TableHead>
                  <TableHead className="w-16 text-right">Hits</TableHead>
                  <TableHead className="w-16">On</TableHead>
                  <TableHead className="w-24 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {props.rules.map((rule) => (
                  <TableRow key={rule.id} className={rule.enabled ? undefined : "opacity-70"}>
                    <TableCell>
                      <span className="text-sm font-medium">{rule.name}</span>
                    </TableCell>
                    <TableCell>
                      <Nat66TypeBadge type={rule.type} />
                    </TableCell>
                    <TableCell>
                      <TranslationCell rule={rule} />
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-xs">{rule.interfaceName}</span>
                    </TableCell>
                    <TableCell className="text-right">
                      <span className="text-sm tabular-nums">{rule.hitCount.toLocaleString()}</span>
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={rule.enabled}
                        disabled={toggle.isPending && toggle.variables?.id === rule.id}
                        onCheckedChange={(enabled) => toggle.mutate({ id: rule.id, enabled })}
                        aria-label={`Toggle ${rule.name}`}
                      />
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-zinc-400 hover:text-blue-600"
                          aria-label={`Simulate traffic for ${rule.name}`}
                          title="Simulate traffic (+1–5 hits)"
                          disabled={simulate.isPending && simulate.variables?.id === rule.id}
                          onClick={() => simulate.mutate({ id: rule.id, name: rule.name, before: rule.hitCount })}
                        >
                          <Icons.Zap className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-zinc-400 hover:text-blue-600"
                          aria-label={`Edit ${rule.name}`}
                          onClick={() => props.onEdit(rule)}
                        >
                          <Icons.Pencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-zinc-400 hover:text-rose-600"
                          aria-label={`Delete ${rule.name}`}
                          onClick={() => props.onDelete(rule)}
                        >
                          <Icons.Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ── DHCPv6 editor (create + edit) ────────────────────────────────────────────

function Dhcpv6Editor(props: { server: Dhcpv6ServerDTO | null; ifaces: string[]; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = props.server !== null;
  const [interfaceName, setInterfaceName] = useState(
    props.server?.interfaceName ?? props.ifaces.find((i) => i.startsWith("lan")) ?? props.ifaces[0] ?? "lan0",
  );
  const [poolStart, setPoolStart] = useState(props.server?.poolStart ?? "2001:db8:10::100");
  const [poolEnd, setPoolEnd] = useState(props.server?.poolEnd ?? "2001:db8:10::1ff");
  const [prefixLength, setPrefixLength] = useState<Dhcpv6PrefixLength>(
    (props.server?.prefixLength as Dhcpv6PrefixLength | undefined) ?? 64,
  );
  const [preferred, setPreferred] = useState(props.server ? String(props.server.preferredLifetime) : "3600");
  const [valid, setValid] = useState(props.server ? String(props.server.validLifetime) : "7200");
  const [dnsText, setDnsText] = useState(props.server?.dnsServers.join(", ") ?? "2001:db8:1::1");
  const [domainSearch, setDomainSearch] = useState(props.server?.domainSearch ?? "");
  const [enabled, setEnabled] = useState(props.server?.enabled ?? true);
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => {
      const id = props.server?.id;
      if (isEdit && id !== undefined) return ipv6Api.updateDhcpv6(id, body);
      return ipv6Api.createDhcpv6(body);
    },
    onSuccess: (server) => {
      toastOk(isEdit ? "DHCPv6 server updated" : "DHCPv6 server created", `on ${server.interfaceName}`);
      invalidateAll(queryClient);
      props.onClose();
    },
    onError: (e) => setErr(firstErrorOf(e)),
  });

  const submit = () => {
    const start = poolStart.trim();
    const end = poolEnd.trim();
    if (!IPV6_RE.test(start)) {
      setErr("Pool start must be an IPv6 address like 2001:db8:10::100");
      return;
    }
    if (!IPV6_RE.test(end)) {
      setErr("Pool end must be an IPv6 address like 2001:db8:10::1ff");
      return;
    }
    const startBig = ipv6ToBigInt(start);
    const endBig = ipv6ToBigInt(end);
    if (startBig === null || endBig === null || endBig <= startBig) {
      setErr("Pool end must be greater than pool start");
      return;
    }
    const pref = Number(preferred);
    const val = Number(valid);
    if (!Number.isInteger(pref) || pref < 60) {
      setErr("Preferred lifetime must be an integer of at least 60 seconds");
      return;
    }
    if (!Number.isInteger(val) || val < pref) {
      setErr("Valid lifetime must be an integer ≥ preferred lifetime");
      return;
    }
    const dnsServers = dnsText
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    if (dnsServers.length === 0 || dnsServers.some((s) => !IPV6_RE.test(s))) {
      setErr("DNS servers must be a comma-separated list of IPv6 addresses");
      return;
    }
    setErr(null);
    save.mutate({
      interfaceName,
      poolStart: start,
      poolEnd: end,
      prefixLength,
      preferredLifetime: pref,
      validLifetime: val,
      dnsServers,
      domainSearch: domainSearch.trim() ? domainSearch.trim() : null,
      enabled,
    });
  };

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-base">{isEdit ? "Edit DHCPv6 server" : "New DHCPv6 server"}</DialogTitle>
          <DialogDescription>
            One stateful server per interface — the interface name is unique per tenant.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel hint="unique">Interface</FieldLabel>
              <Select value={interfaceName} onValueChange={setInterfaceName}>
                <SelectTrigger>
                  <SelectValue placeholder="Select interface" />
                </SelectTrigger>
                <SelectContent>
                  {props.ifaces.map((i) => (
                    <SelectItem key={i} value={i}>
                      {i}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel hint="pool prefix size">Prefix length</FieldLabel>
              <div className="flex gap-1.5">
                {DHCPV6_PREFIX_LENGTHS.map((len) => {
                  const active = prefixLength === len;
                  return (
                    <button
                      key={len}
                      type="button"
                      aria-pressed={active}
                      onClick={() => setPrefixLength(len)}
                      className={cn(
                        "min-h-9 flex-1 rounded-full border px-3 text-xs transition-colors",
                        active
                          ? "border-blue-500/40 bg-blue-500/10 font-semibold text-blue-600 dark:text-blue-400"
                          : "border-zinc-200 text-zinc-500 hover:bg-zinc-100 dark:border-zinc-800 dark:text-zinc-400 dark:hover:bg-zinc-800",
                      )}
                    >
                      /{len}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-[1fr_auto_1fr] sm:items-end">
            <div>
              <FieldLabel hint="IPv6 address">Pool start</FieldLabel>
              <Input
                className="font-mono text-xs"
                value={poolStart}
                onChange={(e) => setPoolStart(e.target.value)}
                placeholder="2001:db8:10::100"
              />
            </div>
            <Icons.ArrowRight className="mx-auto h-4 w-4 text-zinc-400 sm:mb-2.5" />
            <div>
              <FieldLabel hint="> start">Pool end</FieldLabel>
              <Input
                className="font-mono text-xs"
                value={poolEnd}
                onChange={(e) => setPoolEnd(e.target.value)}
                placeholder="2001:db8:10::1ff"
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel hint="seconds">Preferred lifetime</FieldLabel>
              <Input
                className="font-mono text-xs"
                inputMode="numeric"
                value={preferred}
                onChange={(e) => setPreferred(e.target.value)}
                placeholder="3600"
              />
            </div>
            <div>
              <FieldLabel hint="≥ preferred">Valid lifetime</FieldLabel>
              <Input
                className="font-mono text-xs"
                inputMode="numeric"
                value={valid}
                onChange={(e) => setValid(e.target.value)}
                placeholder="7200"
              />
            </div>
          </div>

          <div>
            <FieldLabel hint="comma-separated IPv6">DNS servers</FieldLabel>
            <Input
              className="font-mono text-xs"
              value={dnsText}
              onChange={(e) => setDnsText(e.target.value)}
              placeholder="2001:db8:10::1, 2001:db8:10::2"
            />
          </div>

          <div>
            <FieldLabel hint="optional">Domain search</FieldLabel>
            <Input
              value={domainSearch}
              onChange={(e) => setDomainSearch(e.target.value)}
              placeholder="corp.example.net"
            />
          </div>

          <div className="flex items-center justify-between gap-4 rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
            <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Server enabled</span>
            <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="Server enabled" />
          </div>

          {err ? <p className="text-xs text-rose-600">{err}</p> : null}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button className="bg-blue-600 text-white hover:bg-blue-700" disabled={save.isPending} onClick={submit}>
            {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create server"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── DHCPv6 table ─────────────────────────────────────────────────────────────

function DnsChips({ servers }: { servers: string[] }) {
  if (servers.length === 0) return <span className="text-[11px] text-zinc-400">none</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {servers.slice(0, 2).map((s) => (
        <Badge
          key={s}
          variant="outline"
          className="max-w-36 border-zinc-300 font-mono text-[10px] text-zinc-600 dark:border-zinc-700 dark:text-zinc-300"
        >
          <span className="truncate">{s}</span>
        </Badge>
      ))}
      {servers.length > 2 ? (
        <Badge variant="outline" className="border-zinc-300 text-[10px] text-zinc-400 dark:border-zinc-700">
          +{servers.length - 2}
        </Badge>
      ) : null}
    </span>
  );
}

function Dhcpv6Card(props: {
  servers: Dhcpv6ServerDTO[];
  isLoading: boolean;
  isError: boolean;
  error: unknown;
  onRetry: () => void;
  onAdd: () => void;
  onEdit: (server: Dhcpv6ServerDTO) => void;
  onDelete: (server: Dhcpv6ServerDTO) => void;
}) {
  const queryClient = useQueryClient();
  useLoadErrorToast(props, "DHCPv6 servers");
  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => ipv6Api.updateDhcpv6(id, { enabled }),
    onSuccess: () => invalidateAll(queryClient),
    onError: (e) => toastLoadErr(e, "Toggle failed"),
  });

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.Server className="h-4 w-4 text-blue-600 dark:text-blue-400" />
          DHCPv6 servers
        </CardTitle>
        <Button size="sm" className="h-8 bg-blue-600 text-white hover:bg-blue-700" onClick={props.onAdd}>
          <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add server
        </Button>
      </CardHeader>
      <CardContent className="p-0">
        {props.isError ? (
          <div className="p-4">
            <QueryError error={props.error} onRetry={props.onRetry} />
          </div>
        ) : props.isLoading ? (
          <TableSkeleton rows={2} cols={7} />
        ) : props.servers.length === 0 ? (
          <EmptyBlock
            icon={<Icons.Server className="h-6 w-6" />}
            title="No DHCPv6 servers yet"
            description="Create a server to hand out stateful IPv6 addresses on an interface."
            action={
              <Button size="sm" className="bg-blue-600 text-white hover:bg-blue-700" onClick={props.onAdd}>
                <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add server
              </Button>
            }
          />
        ) : (
          <div className="max-h-96 overflow-y-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-20">Iface</TableHead>
                  <TableHead>Pool</TableHead>
                  <TableHead className="w-16">Prefix</TableHead>
                  <TableHead className="w-28">Lifetimes</TableHead>
                  <TableHead>DNS</TableHead>
                  <TableHead className="w-16">On</TableHead>
                  <TableHead className="w-16 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {props.servers.map((server) => (
                  <TableRow key={server.id} className={server.enabled ? undefined : "opacity-70"}>
                    <TableCell>
                      <span className="font-mono text-xs font-medium">{server.interfaceName}</span>
                    </TableCell>
                    <TableCell>
                      <span
                        className="block max-w-56 truncate font-mono text-xs"
                        title={`${server.poolStart} → ${server.poolEnd}`}
                      >
                        {server.poolStart} <Icons.ArrowRight className="inline h-3 w-3 text-zinc-400" /> {server.poolEnd}
                      </span>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="border-zinc-300 text-[10px] text-zinc-600 dark:border-zinc-700 dark:text-zinc-300">
                        /{server.prefixLength}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs tabular-nums text-zinc-500">
                        {fmtLifetime(server.preferredLifetime)} / {fmtLifetime(server.validLifetime)}
                      </span>
                    </TableCell>
                    <TableCell>
                      <DnsChips servers={server.dnsServers} />
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={server.enabled}
                        disabled={toggle.isPending && toggle.variables?.id === server.id}
                        onCheckedChange={(enabled) => toggle.mutate({ id: server.id, enabled })}
                        aria-label={`Toggle DHCPv6 on ${server.interfaceName}`}
                      />
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-zinc-400 hover:text-blue-600"
                          aria-label={`Edit DHCPv6 on ${server.interfaceName}`}
                          onClick={() => props.onEdit(server)}
                        >
                          <Icons.Pencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-zinc-400 hover:text-rose-600"
                          aria-label={`Delete DHCPv6 on ${server.interfaceName}`}
                          onClick={() => props.onDelete(server)}
                        >
                          <Icons.Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ── main view ────────────────────────────────────────────────────────────────

export function Ipv6View() {
  const queryClient = useQueryClient();

  const nat66Query = useQuery({ queryKey: ["ipv6", "nat66"], queryFn: ipv6Api.listNat66 });
  const dhcpv6Query = useQuery({ queryKey: ["ipv6", "dhcpv6"], queryFn: ipv6Api.listDhcpv6 });
  const ifacesQuery = useQuery({ queryKey: ["ipv6", "ifaces"], queryFn: ipv6Api.listInterfaceNames });
  useLoadErrorToast(nat66Query, "NAT66 rules");
  useLoadErrorToast(dhcpv6Query, "DHCPv6 servers");
  const nat66Rules = nat66Query.data ?? [];
  const dhcpv6Servers = dhcpv6Query.data ?? [];
  const ifaces = ifacesQuery.data ?? FALLBACK_INTERFACES;

  // dialog state (nat66 + dhcpv6 editors, delete targets)
  const [nat66AddOpen, setNat66AddOpen] = useState(false);
  const [nat66Editing, setNat66Editing] = useState<Nat66RuleDTO | null>(null);
  const [nat66Deleting, setNat66Deleting] = useState<Nat66RuleDTO | null>(null);
  const [dhcpAddOpen, setDhcpAddOpen] = useState(false);
  const [dhcpEditing, setDhcpEditing] = useState<Dhcpv6ServerDTO | null>(null);
  const [dhcpDeleting, setDhcpDeleting] = useState<Dhcpv6ServerDTO | null>(null);

  const nat66Del = useMutation({
    mutationFn: (id: number) => ipv6Api.deleteNat66(id),
    onSuccess: () => {
      toastOk("NAT66 rule deleted");
      setNat66Deleting(null);
      invalidateAll(queryClient);
    },
    onError: (e) => {
      setNat66Deleting(null);
      toastLoadErr(e, "Delete failed");
    },
  });

  const dhcpDel = useMutation({
    mutationFn: (id: number) => ipv6Api.deleteDhcpv6(id),
    onSuccess: () => {
      toastOk("DHCPv6 server deleted");
      setDhcpDeleting(null);
      invalidateAll(queryClient);
    },
    onError: (e) => {
      setDhcpDeleting(null);
      toastLoadErr(e, "Delete failed");
    },
  });

  return (
    <div className="space-y-4">
      <StatusStrip />

      {/* IA_PD lease + dual-stack settings */}
      <div className="grid items-start gap-4 lg:grid-cols-[420px_1fr]">
        <PrefixDelegationCard />
        <SettingsCard ifaces={ifaces} />
      </div>

      {/* NAT66 rules */}
      <Nat66Card
        rules={nat66Rules}
        isLoading={nat66Query.isLoading}
        isError={nat66Query.isError}
        error={nat66Query.error}
        onRetry={() => void nat66Query.refetch()}
        onAdd={() => setNat66AddOpen(true)}
        onEdit={(rule) => setNat66Editing(rule)}
        onDelete={(rule) => setNat66Deleting(rule)}
      />

      {/* DHCPv6 servers */}
      <Dhcpv6Card
        servers={dhcpv6Servers}
        isLoading={dhcpv6Query.isLoading}
        isError={dhcpv6Query.isError}
        error={dhcpv6Query.error}
        onRetry={() => void dhcpv6Query.refetch()}
        onAdd={() => setDhcpAddOpen(true)}
        onEdit={(server) => setDhcpEditing(server)}
        onDelete={(server) => setDhcpDeleting(server)}
      />

      {/* dialogs */}
      {nat66AddOpen && <Nat66Editor rule={null} ifaces={ifaces} onClose={() => setNat66AddOpen(false)} />}
      {nat66Editing && <Nat66Editor rule={nat66Editing} ifaces={ifaces} onClose={() => setNat66Editing(null)} />}
      {dhcpAddOpen && <Dhcpv6Editor server={null} ifaces={ifaces} onClose={() => setDhcpAddOpen(false)} />}
      {dhcpEditing && <Dhcpv6Editor server={dhcpEditing} ifaces={ifaces} onClose={() => setDhcpEditing(null)} />}

      {/* delete confirmations */}
      <ConfirmDialog
        open={nat66Deleting !== null}
        onOpenChange={(o) => !o && setNat66Deleting(null)}
        title={`Delete NAT66 rule "${nat66Deleting?.name ?? ""}"?`}
        description="Traffic matching this rule falls back to the default translation behaviour."
        loading={nat66Del.isPending}
        onConfirm={() => nat66Deleting && nat66Del.mutate(nat66Deleting.id)}
      />
      <ConfirmDialog
        open={dhcpDeleting !== null}
        onOpenChange={(o) => !o && setDhcpDeleting(null)}
        title={`Delete DHCPv6 server on "${dhcpDeleting?.interfaceName ?? ""}"?`}
        description="Clients on this interface will no longer receive stateful addresses."
        loading={dhcpDel.isPending}
        onConfirm={() => dhcpDeleting && dhcpDel.mutate(dhcpDeleting.id)}
      />
    </div>
  );
}
