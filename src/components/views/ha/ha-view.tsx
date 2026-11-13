"use client";

/**
 * HA view (M10 §4 `#/ha`) — status card (role badge, VIP+iface, simulated peer
 * heartbeat, tracked-interface chips, sync chips, collapsible Keepalived/VRRP
 * explanation) + admin-gated config editor (priority higher-wins, holdDownSec
 * ≥ failAfterSec). Client pre-checks mirror the server zod grammar at submit
 * (§5.16 validation parity: rose ring, role="alert", focus first invalid);
 * server fieldErrors merge into the same bag on 400. Status polls ~4 s
 * (heartbeat age ticks); refetch after save. Simulated-peer labels per §4.
 */

import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";
import { EditorSection, FieldLabel, QueryError, toastErr, toastOk } from "../firewall/fw-ui";
import { INVALID_CLS } from "../network/net-ui";
import { usePermissions } from "../system/system-ui";
import { listInterfaceNames, type IfaceLite } from "../dns-dhcp/dns-dhcp-api";
import { haApi, fieldErrorsOf, type HaConfigDTO, type HaStatusDTO } from "./ha-api";

// ── badges ──────────────────────────────────────────────────────────────────

function RoleBadge({ role }: { role: string }) {
  if (role === "active") {
    return (
      <Badge className="border-transparent bg-emerald-600 text-white">
        <Icons.CircleDot className="mr-1 h-3 w-3" /> active
      </Badge>
    );
  }
  if (role === "standby") {
    return (
      <Badge className="border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400">
        <Icons.CirclePause className="mr-1 h-3 w-3" /> standby
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="border-zinc-300 text-zinc-500 dark:border-zinc-700">
      disabled
    </Badge>
  );
}

function SyncChip({ label, on }: { label: string; on: boolean }) {
  return (
    <Badge
      variant="outline"
      className={cn(
        "gap-1",
        on
          ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
          : "border-zinc-300 text-zinc-500 dark:border-zinc-700",
      )}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full", on ? "bg-emerald-500" : "bg-zinc-400")} />
      {label}
      <span className="text-[10px] text-zinc-400">simulated</span>
    </Badge>
  );
}

// ── status card ─────────────────────────────────────────────────────────────

function StatusCard({ status }: { status: HaStatusDTO }) {
  const disabled = status.localRole === "disabled";
  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between space-y-0">
        <div>
          <CardTitle className="flex items-center gap-2 text-base">
            <Icons.Network className="h-4.5 w-4.5 text-zinc-500 dark:text-zinc-400" />
            HA status
          </CardTitle>
          <CardDescription>Keepalived/VRRP pair — the sandbox peer is fictional</CardDescription>
        </div>
        <RoleBadge role={status.localRole} />
      </CardHeader>
      <CardContent>
        {disabled ? (
          <p className="rounded-lg border border-dashed border-zinc-200 px-4 py-6 text-center text-sm text-zinc-500 dark:border-zinc-800">
            HA is disabled — configure the pair below to bring it up.
          </p>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2 text-sm">
              <div className="flex items-center justify-between gap-2">
                <span className="text-zinc-500">Virtual IP</span>
                <span className="font-mono text-xs">{status.virtualIp ?? "—"}</span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-zinc-500">Interface</span>
                <span className="font-mono text-xs">{status.ifaceName}</span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-zinc-500">Priority</span>
                <span className="tabular-nums">{status.priority} <span className="text-[10px] text-zinc-400">higher wins</span></span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-zinc-500">Fail over after</span>
                <span className="tabular-nums">{status.failAfterSec}s silence</span>
              </div>
            </div>
            <div className="space-y-2 text-sm">
              <div className="flex items-center justify-between gap-2">
                <span className="text-zinc-500">Peer</span>
                <span className="flex items-center gap-1.5 font-mono text-xs">
                  {status.peerIp ?? "—"}
                  <span
                    className={cn(
                      "h-2 w-2 rounded-full",
                      status.peerReachable ? "bg-emerald-500" : "bg-rose-500",
                    )}
                    aria-label={status.peerReachable ? "peer reachable" : "peer lost"}
                  />
                </span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-zinc-500">Last heartbeat</span>
                <span className="tabular-nums">{status.heartbeatAgeSec}s ago <span className="text-[10px] text-zinc-400">simulated</span></span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-zinc-500">Last failover</span>
                <span className="text-xs text-zinc-400">{status.lastFailover ?? "—"}</span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-zinc-500">Hold-down</span>
                <span className="tabular-nums text-xs">
                  {status.holdDownRemainingSec > 0 ? `${status.holdDownRemainingSec}s remaining` : `${status.holdDownSec}s policy`}
                </span>
              </div>
            </div>

            <div className="sm:col-span-2">
              <FieldLabel hint="Keepalived track_interface — a down iface demotes the node regardless of priority">
                Tracked interfaces
              </FieldLabel>
              {status.trackedInterfaces.length === 0 ? (
                <p className="text-xs text-zinc-400">none tracked</p>
              ) : (
                <div className="flex flex-wrap gap-1.5">
                  {status.trackedInterfaces.map((t) => (
                    <Badge
                      key={t.name}
                      variant="outline"
                      className={cn(
                        "gap-1",
                        t.up
                          ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                          : "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400",
                      )}
                    >
                      {t.up ? <Icons.Link2 className="h-3 w-3" /> : <Icons.Unlink2 className="h-3 w-3" />}
                      {t.name} {t.up ? "up" : "down"}
                    </Badge>
                  ))}
                </div>
              )}
            </div>

            <div className="sm:col-span-2 flex flex-wrap items-center gap-1.5">
              <SyncChip label="configSynced" on={status.configSynced} />
              <SyncChip label="sessionSynced" on={status.sessionSynced} />
            </div>
          </div>
        )}

        <ExplanationPanel />
      </CardContent>
    </Card>
  );
}

function ExplanationPanel() {
  const [open, setOpen] = useState(false);
  return (
    <Collapsible open={open} onOpenChange={setOpen} className="mt-4">
      <CollapsibleTrigger asChild>
        <Button variant="ghost" size="sm" className="h-auto gap-1.5 whitespace-normal text-start text-zinc-500">
          <Icons.ChevronDown className={cn("h-3.5 w-3.5 transition-transform", open && "rotate-180")} />
          How failover / failback works (Keepalived semantics)
        </Button>
      </CollapsibleTrigger>
      <CollapsibleContent>
        <div className="mt-2 space-y-2 rounded-lg border border-zinc-200 p-4 text-xs leading-relaxed text-zinc-600 dark:border-zinc-800 dark:text-zinc-300">
          <p>
            The peers exchange VRRP advertisement packets (heartbeats). If the master goes silent beyond
            <span className="mx-1 font-mono">failAfterSec</span>, the standby promotes to <em>active</em> and the
            virtual IP floats to it — VPN tunnels ride the floating VIP (StrongSwan + Keepalived tunnel failover).
          </p>
          <p>
            A hold-down of <span className="mx-1 font-mono">holdDownSec</span> delays failback to the preferred node
            after recovery, which prevents address flapping when a link bounces.
          </p>
          <p>
            Any tracked interface failure demotes the node regardless of priority (link monitoring). With
            <span className="mx-1 font-mono">sessionSync</span>, conntrackd mirrors firewall session state so
            established flows survive the failover.
          </p>
          <p>
            The state machine (standby ⇄ active on heartbeat loss, hold-down before failback) lives in
            SIMULATION_LAYER §5 — it is not redrawn here.
          </p>
        </div>
      </CollapsibleContent>
    </Collapsible>
  );
}

// ── config editor (admin-gated) ─────────────────────────────────────────────

function HaEditor({ config, ifaces, isAdmin }: { config: HaConfigDTO; ifaces: IfaceLite[]; isAdmin: boolean }) {
  const queryClient = useQueryClient();
  const [form, setForm] = useState<HaConfigDTO>(config);
  const [errors, setErrors] = useState<Record<string, string[]>>({});

  // re-seed the form when the server config changes (render-time derived reset)
  const [prevConfig, setPrevConfig] = useState(config);
  if (prevConfig !== config) {
    setPrevConfig(config);
    setForm(config);
  }

  // client pre-checks mirror the server zod grammar (M10 §5.1) — server stays authoritative
  const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  const IPV4_CIDR_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\/(3[0-2]|[12]?\d)$/;
  const intIn = (v: number, min: number, max: number) => Number.isInteger(v) && v >= min && v <= max;

  const validate = (): Record<string, string[]> => {
    const errs: Record<string, string[]> = {};
    if (!intIn(form.priority, 1, 255)) errs.priority = ["Priority must be an integer between 1 and 255"];
    const vip = form.virtualIp?.trim() ?? "";
    if (vip && !IPV4_CIDR_RE.test(vip)) errs.virtualIp = ["Must be a valid IPv4 CIDR (e.g. 192.168.10.254/24)"];
    const peer = form.peerIp?.trim() ?? "";
    if (peer && !IPV4_RE.test(peer)) errs.peerIp = ["Must be a valid IPv4 address"];
    if (!intIn(form.failAfterSec, 3, 3600)) errs.failAfterSec = ["failAfterSec must be an integer between 3 and 3600"];
    if (!intIn(form.holdDownSec, 0, 86_400)) errs.holdDownSec = ["holdDownSec must be an integer between 0 and 86400"];
    else if (form.holdDownSec < form.failAfterSec) errs.holdDownSec = ["holdDownSec must be ≥ failAfterSec (failback waits at least as long as detection)"];
    if (form.enabled) {
      if (form.role === "disabled") errs.role = ["Enabling HA requires a role (active or standby)"];
      if (!peer) errs.peerIp = ["Enabling HA requires a peer IP"];
    }
    return errs;
  };

  const clearErr = (k: string) =>
    setErrors((e) => {
      if (!(k in e)) return e;
      const { [k]: _drop, ...rest } = e;
      return rest;
    });

  const save = useMutation({
    mutationFn: () =>
      haApi.putConfig({
        enabled: form.enabled,
        role: form.role,
        priority: form.priority,
        virtualIp: form.virtualIp?.trim() || null,
        ifaceName: form.ifaceName,
        peerIp: form.peerIp?.trim() || null,
        syncConfig: form.syncConfig,
        sessionSync: form.sessionSync,
        trackedInterfaces: form.trackedInterfaces,
        failAfterSec: form.failAfterSec,
        holdDownSec: form.holdDownSec,
      }),
    onSuccess: () => {
      setErrors({});
      toastOk("HA config saved", "Snapshot written for section ha; status refetched.");
      void queryClient.invalidateQueries({ queryKey: ["ha"] });
    },
    onError: (err) => {
      setErrors(fieldErrorsOf(err));
      toastErr(err, "Save failed");
    },
  });

  const submit = () => {
    const errs = validate();
    if (Object.keys(errs).length > 0) {
      setErrors(errs);
      const first = ["priority", "virtualIp", "peerIp", "failAfterSec", "holdDownSec", "role"].find((k) => errs[k]);
      if (first) document.getElementById(`ha-${first}`)?.focus();
      return;
    }
    save.mutate();
  };

  const toggleTracked = (name: string) =>
    setForm((f) => ({
      ...f,
      trackedInterfaces: f.trackedInterfaces.includes(name)
        ? f.trackedInterfaces.filter((t) => t !== name)
        : [...f.trackedInterfaces, name],
    }));

  const err = (k: string) => errors[k]?.[0];

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between space-y-0">
        <div>
          <CardTitle className="flex items-center gap-2 text-base">
            <Icons.Settings2 className="h-4.5 w-4.5 text-zinc-500 dark:text-zinc-400" />
            HA configuration
          </CardTitle>
          <CardDescription>Pair settings — saved as a single audited apply (section ha)</CardDescription>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {!isAdmin ? (
          <p className="flex items-center gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-400">
            <Icons.Lock className="h-3.5 w-3.5 shrink-0" />
            Read-only — HA administration requires an admin role.
          </p>
        ) : null}

        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <Label htmlFor="ha-enabled">HA enabled</Label>
              <Switch
                id="ha-enabled"
                checked={form.enabled}
                disabled={!isAdmin}
                onCheckedChange={(v) => {
                  setForm((f) => ({ ...f, enabled: v }));
                  clearErr("role");
                  clearErr("peerIp");
                }}
              />
            </div>
            {err("role") ? (
              <p id="ha-role-err" role="alert" className="text-[11px] text-rose-600 dark:text-rose-400">
                {err("role")}
              </p>
            ) : null}
          </div>
          <div className="space-y-1.5">
            <FieldLabel hint="Keepalived semantics — higher wins master election">Role</FieldLabel>
            <Select
              value={form.role}
              disabled={!isAdmin}
              onValueChange={(v) => {
                setForm((f) => ({ ...f, role: v as HaConfigDTO["role"] }));
                clearErr("role");
              }}
            >
              <SelectTrigger id="ha-role" aria-invalid={!!err("role")} aria-describedby={err("role") ? "ha-role-err" : undefined} className={cn(err("role") && INVALID_CLS)}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="disabled">disabled</SelectItem>
                <SelectItem value="active">active</SelectItem>
                <SelectItem value="standby">standby</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-1.5">
            <FieldLabel hint="1-255 — higher wins">Priority</FieldLabel>
            <Input
              id="ha-priority"
              type="number"
              min={1}
              max={255}
              value={form.priority}
              disabled={!isAdmin}
              onChange={(e) => {
                setForm((f) => ({ ...f, priority: Number(e.target.value) }));
                clearErr("priority");
              }}
              aria-invalid={!!err("priority")}
              aria-describedby={err("priority") ? "ha-priority-err" : undefined}
              className={cn(err("priority") && INVALID_CLS)}
            />
            {err("priority") ? (
              <p id="ha-priority-err" role="alert" className="text-[11px] text-rose-600 dark:text-rose-400">
                {err("priority")}
              </p>
            ) : null}
          </div>
          <div className="space-y-1.5">
            <FieldLabel hint="CIDR, e.g. 192.168.10.254/24">Virtual IP</FieldLabel>
            <Input
              id="ha-virtualIp"
              value={form.virtualIp ?? ""}
              placeholder="192.168.10.254/24"
              disabled={!isAdmin}
              onChange={(e) => {
                setForm((f) => ({ ...f, virtualIp: e.target.value }));
                clearErr("virtualIp");
              }}
              aria-invalid={!!err("virtualIp")}
              aria-describedby={err("virtualIp") ? "ha-virtualIp-err" : undefined}
              className={cn(err("virtualIp") && INVALID_CLS)}
            />
            {err("virtualIp") ? (
              <p id="ha-virtualIp-err" role="alert" className="text-[11px] text-rose-600 dark:text-rose-400">
                {err("virtualIp")}
              </p>
            ) : null}
          </div>

          <div className="space-y-1.5">
            <FieldLabel>Interface</FieldLabel>
            <Select
              value={form.ifaceName}
              disabled={!isAdmin}
              onValueChange={(v) => setForm((f) => ({ ...f, ifaceName: v }))}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {ifaces.map((i) => (
                  <SelectItem key={i.name} value={i.name}>
                    {i.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {err("ifaceName") ? <p className="text-[11px] text-rose-600">{err("ifaceName")}</p> : null}
          </div>
          <div className="space-y-1.5">
            <FieldLabel hint="must not be a local interface address">Peer IP</FieldLabel>
            <Input
              id="ha-peerIp"
              value={form.peerIp ?? ""}
              placeholder="192.168.10.253"
              disabled={!isAdmin}
              onChange={(e) => {
                setForm((f) => ({ ...f, peerIp: e.target.value }));
                clearErr("peerIp");
              }}
              aria-invalid={!!err("peerIp")}
              aria-describedby={err("peerIp") ? "ha-peerIp-err" : undefined}
              className={cn(err("peerIp") && INVALID_CLS)}
            />
            {err("peerIp") ? (
              <p id="ha-peerIp-err" role="alert" className="text-[11px] text-rose-600 dark:text-rose-400">
                {err("peerIp")}
              </p>
            ) : null}
          </div>
        </div>

        <EditorSection title="Sync & monitoring">
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-3">
              <div>
                <p className="text-sm font-medium">Configuration sync</p>
                <p className="text-[11px] text-zinc-500">Sync configuration to peer — simulated in Phase 1.</p>
              </div>
              <Switch
                checked={form.syncConfig}
                disabled={!isAdmin}
                onCheckedChange={(v) => setForm((f) => ({ ...f, syncConfig: v }))}
              />
            </div>
            <div className="flex items-center justify-between gap-3">
              <div>
                <p className="text-sm font-medium">Session sync (conntrackd)</p>
                <p className="text-[11px] text-zinc-500">
                  Replicate firewall sessions via conntrackd — simulated in Phase 1.
                </p>
              </div>
              <Switch
                checked={form.sessionSync}
                disabled={!isAdmin}
                onCheckedChange={(v) => setForm((f) => ({ ...f, sessionSync: v }))}
              />
            </div>
            <div>
              <FieldLabel hint="Keepalived track_interface — any down iface pins this node out of election">
                Tracked interfaces
              </FieldLabel>
              <div className="flex flex-wrap gap-1.5">
                {ifaces.map((i) => {
                  const active = form.trackedInterfaces.includes(i.name);
                  return (
                    <button
                      key={i.name}
                      type="button"
                      disabled={!isAdmin}
                      onClick={() => toggleTracked(i.name)}
                      aria-pressed={active}
                      className={cn(
                        "h-11 rounded-full border px-3 text-xs transition-colors disabled:cursor-not-allowed disabled:opacity-60 lg:h-7 lg:px-2.5",
                        active
                          ? "border-zinc-500/30 bg-zinc-500/10 font-medium text-zinc-600 dark:text-zinc-300"
                          : "border-zinc-200 text-zinc-500 hover:bg-zinc-100 dark:border-zinc-800 dark:hover:bg-zinc-800",
                      )}
                    >
                      {i.name}
                    </button>
                  );
                })}
              </div>
              {err("trackedInterfaces") ? <p className="mt-1 text-[11px] text-rose-600">{err("trackedInterfaces")}</p> : null}
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <FieldLabel hint="≥ 3 s">Fail over after (seconds of silence)</FieldLabel>
                <Input
                  id="ha-failAfterSec"
                  type="number"
                  min={3}
                  value={form.failAfterSec}
                  disabled={!isAdmin}
                  onChange={(e) => {
                    setForm((f) => ({ ...f, failAfterSec: Number(e.target.value) }));
                    clearErr("failAfterSec");
                    clearErr("holdDownSec");
                  }}
                  aria-invalid={!!err("failAfterSec")}
                  aria-describedby={err("failAfterSec") ? "ha-failAfterSec-err" : undefined}
                  className={cn(err("failAfterSec") && INVALID_CLS)}
                />
                {err("failAfterSec") ? (
                  <p id="ha-failAfterSec-err" role="alert" className="text-[11px] text-rose-600 dark:text-rose-400">
                    {err("failAfterSec")}
                  </p>
                ) : null}
              </div>
              <div className="space-y-1.5">
                <FieldLabel hint="must be ≥ failAfterSec">Hold-down before failback (seconds)</FieldLabel>
                <Input
                  id="ha-holdDownSec"
                  type="number"
                  min={0}
                  value={form.holdDownSec}
                  disabled={!isAdmin}
                  onChange={(e) => {
                    setForm((f) => ({ ...f, holdDownSec: Number(e.target.value) }));
                    clearErr("holdDownSec");
                  }}
                  aria-invalid={!!err("holdDownSec")}
                  aria-describedby={err("holdDownSec") ? "ha-holdDownSec-err" : undefined}
                  className={cn(err("holdDownSec") && INVALID_CLS)}
                />
                {err("holdDownSec") ? (
                  <p id="ha-holdDownSec-err" role="alert" className="text-[11px] text-rose-600 dark:text-rose-400">
                    {err("holdDownSec")}
                  </p>
                ) : null}
              </div>
            </div>
          </div>
        </EditorSection>

        <div className="flex justify-end">
          <Button onClick={submit} disabled={!isAdmin || save.isPending}>
            {save.isPending ? (
              <>
                <Icons.Loader2 className="mr-2 h-4 w-4 animate-spin" /> Saving…
              </>
            ) : (
              <>
                <Icons.Save className="mr-2 h-4 w-4" /> Save HA config
              </>
            )}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ── view root ───────────────────────────────────────────────────────────────

export function HaView() {
  const { canWrite } = usePermissions();
  const status = useQuery({
    queryKey: ["ha", "status"],
    queryFn: () => haApi.getStatus(),
    refetchInterval: 4000, // heartbeat age ticks
  });
  const config = useQuery({ queryKey: ["ha", "config"], queryFn: () => haApi.getConfig() });
  const ifaces = useQuery({
    queryKey: ["interfaces", "lite"],
    queryFn: () => listInterfaceNames(),
  });

  const ifacesSafe = useMemo(() => ifaces.data ?? [], [ifaces.data]);

  return (
    <div className="grid gap-4">
      {status.isError ? (
        <QueryError error={status.error} onRetry={() => void status.refetch()} />
      ) : status.isLoading ? (
        <Card>
          <CardContent className="space-y-3 p-6">
            <Skeleton className="h-5 w-40" />
            <Skeleton className="h-24 w-full" />
          </CardContent>
        </Card>
      ) : (
        <StatusCard status={status.data!} />
      )}

      {config.isError ? (
        <QueryError error={config.error} onRetry={() => void config.refetch()} />
      ) : config.isLoading || ifaces.isLoading ? (
        <Card>
          <CardContent className="space-y-3 p-6">
            <Skeleton className="h-5 w-48" />
            <Skeleton className="h-40 w-full" />
          </CardContent>
        </Card>
      ) : (
        <HaEditor config={config.data!} ifaces={ifacesSafe} isAdmin={canWrite("ha")} />
      )}
    </div>
  );
}
