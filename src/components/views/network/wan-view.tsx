"use client";

/**
 * #/network/wan — multi-WAN policy cards with probe-driven failover (M02 §4).
 * One policy per WAN iface. Live `wan:status` events flip card badges, toast
 * ONLY on down↔up/degraded transitions, and debounce a 1 s list refetch.
 * config:updated (interfaces/routing sections) invalidates the policies.
 */

import { useEffect, useMemo, useRef, useState } from "react";
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
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";
import { useRealtime } from "@/lib/realtime";
import { toast as showToast } from "@/hooks/use-toast";
import {
  ConfirmDialog,
  EmptyBlock,
  FieldLabel,
  QueryError,
  toastErr,
  toastOk,
} from "@/components/views/firewall/fw-ui";
import {
  PROBE_TARGET_DEFAULTS,
  netApi,
  type Iface,
  type ProbeType,
  type WanMode,
  type WanPolicy,
  type WanPolicyBody,
  type WanState,
} from "./net-api";
import { ModeChip, StateBadge } from "./net-ui";

const WAN_KEY = ["network", "wan-policies"] as const;
const IFACES_KEY = ["network", "interfaces"] as const;

const WAN_MODES: WanMode[] = ["priority", "failover", "load_balance"];
const PROBE_TYPES: ProbeType[] = ["icmp", "tcp", "dns", "http"];

const MODE_LABEL: Record<WanMode, string> = {
  priority: "priority",
  failover: "failover",
  load_balance: "load balance",
};

export function WanView() {
  const queryClient = useQueryClient();

  const policiesQuery = useQuery({ queryKey: WAN_KEY, queryFn: () => netApi.listWanPolicies() });
  const ifacesQuery = useQuery({ queryKey: IFACES_KEY, queryFn: () => netApi.listIfaces() });

  // live state overlay from wan:status + last-known states for transition toasts
  const [overlay, setOverlay] = useState<Record<string, WanState>>({});
  const lastStatesRef = useRef<Record<string, WanState>>({});
  const refetchTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const policies = useMemo(() => policiesQuery.data?.data ?? [], [policiesQuery.data]);

  // seed / re-sync the transition ref from authoritative list data (no toasts)
  useEffect(() => {
    for (const p of policies) lastStatesRef.current[p.interfaceName] = p.state;
  }, [policies]);

  useRealtime(["metrics", "config"], {
    onWanStatus: (w) => {
      const next = w.state as WanState;
      const prev = lastStatesRef.current[w.iface];
      lastStatesRef.current[w.iface] = next;
      setOverlay((o) => ({ ...o, [w.iface]: next }));
      if (next === "down" && prev !== "down") {
        showToast({ variant: "destructive", title: `WAN ${w.iface} is down`, description: "Probe failed — failover engages per policy." });
      } else if (prev === "down" && (next === "up" || next === "degraded")) {
        toastOk("WAN recovered", `${w.iface} is ${next}`);
      }
      if (refetchTimerRef.current) clearTimeout(refetchTimerRef.current);
      refetchTimerRef.current = setTimeout(() => {
        refetchTimerRef.current = null;
        void queryClient.invalidateQueries({ queryKey: WAN_KEY });
      }, 1000);
    },
    onConfigUpdated: (c) => {
      if (c.section === "interfaces" || c.section === "routing") {
        void queryClient.invalidateQueries({ queryKey: WAN_KEY });
      }
    },
  });

  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<WanPolicy | null>(null);
  const [deleting, setDeleting] = useState<WanPolicy | null>(null);

  const ifaces = useMemo(() => ifacesQuery.data?.data ?? [], [ifacesQuery.data]);
  const coveredIfaces = useMemo(() => new Set(policies.map((p) => p.interfaceName)), [policies]);
  const candidates = useMemo(() => ifaces.filter((i) => i.role === "wan" && !coveredIfaces.has(i.name)), [ifaces, coveredIfaces]);

  const probeMut = useMutation({
    mutationFn: (policy: WanPolicy) => netApi.probeWanPolicy(policy.id),
    onSuccess: (updated) => {
      // card updates straight from the returned fresh state
      setOverlay((o) => ({ ...o, [updated.interfaceName]: updated.state }));
      lastStatesRef.current[updated.interfaceName] = updated.state;
      toastOk("Probe complete", `${updated.interfaceName} is ${updated.state}`);
      void queryClient.invalidateQueries({ queryKey: WAN_KEY });
    },
    onError: (err) => toastErr(err, "Probe failed"),
  });

  const deleteMut = useMutation({
    mutationFn: (id: number) => netApi.deleteWanPolicy(id),
    onSuccess: () => {
      toastOk("WAN policy deleted");
      setDeleting(null);
    },
    onError: (err) => toastErr(err, "Delete failed"),
    onSettled: () => void queryClient.invalidateQueries({ queryKey: WAN_KEY }),
  });

  // enabled toggle — PUT with the full body (flipped enabled)
  const toggleEnabledMut = useMutation({
    mutationFn: ({ id, body }: { id: number; body: WanPolicyBody }) => netApi.updateWanPolicy(id, body),
    onSuccess: (updated) => {
      lastStatesRef.current[updated.interfaceName] = updated.state;
      toastOk(updated.enabled ? "WAN policy enabled" : "WAN policy disabled", updated.interfaceName);
    },
    onError: (err) => toastErr(err, "Toggle failed"),
    onSettled: () => void queryClient.invalidateQueries({ queryKey: WAN_KEY }),
  });

  // active egress = lowest priority among state=up (else degraded, else offline)
  const activeIface = useMemo(() => {
    const stateOf = (p: WanPolicy): WanState => overlay[p.interfaceName] ?? p.state;
    const enabled = policies.filter((p) => p.enabled);
    const pick = (states: WanState[]) =>
      enabled
        .filter((p) => states.includes(stateOf(p)))
        .sort((a, b) => a.priority - b.priority)[0]?.interfaceName;
    return pick(["up"]) ?? pick(["degraded"]) ?? null;
  }, [policies, overlay]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs text-zinc-500">
          One policy per WAN interface — probes drive the up/degraded/down state machine and egress selection.
        </p>
        <Button
          size="sm"
          onClick={() => {
            setEditing(null);
            setEditorOpen(true);
          }}
          className="bg-zinc-700 text-white hover:bg-zinc-800"
        >
          <Icons.Plus className="mr-1 h-4 w-4" /> Add WAN policy
        </Button>
      </div>

      {/* failover explainer (static) */}
      <Card className="border-zinc-200 bg-zinc-50/60 p-4 dark:border-zinc-800 dark:bg-zinc-900/40">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-start">
          <Icons.Globe className="mt-0.5 h-4 w-4 shrink-0 text-zinc-500 dark:text-zinc-400" />
          <div className="min-w-0 flex-1 space-y-1 text-xs text-zinc-600 dark:text-zinc-300">
            <p className="text-sm font-medium text-zinc-800 dark:text-zinc-100">How multi-WAN egress is chosen</p>
            <p>
              <span className="font-medium">priority</span> — lower number is preferred; the best up interface carries all traffic.{" "}
              <span className="font-medium">failover</span> — standby stays idle until the active interface fails its probes.{" "}
              <span className="font-medium">load balance</span> — new connections are hashed per-flow across up interfaces, weighted by weight %.
            </p>
            <p className="text-zinc-500 dark:text-zinc-400">
              Active egress right now:{" "}
              {activeIface ? (
                <Badge variant="outline" className="mx-0.5 border-zinc-500/30 bg-zinc-500/10 font-mono text-[11px] text-zinc-600 dark:text-zinc-300">
                  {activeIface}
                </Badge>
              ) : (
                <span className="ml-1 font-medium text-rose-600 dark:text-rose-400">— offline —</span>
              )}
              <span className="ml-1">(lowest priority among state = up; degraded candidates otherwise)</span>
            </p>
          </div>
        </div>
      </Card>

      {policiesQuery.error ? (
        <QueryError error={policiesQuery.error} onRetry={() => void policiesQuery.refetch()} />
      ) : policiesQuery.isLoading ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-52 rounded-xl" />
          ))}
        </div>
      ) : policies.length === 0 ? (
        <Card className="p-0">
          <CardContent className="p-0">
            <EmptyBlock
              icon={<Icons.Globe className="h-6 w-6" />}
              title="No WAN policies"
              description="Add a probe policy per WAN interface to get health-driven failover, priority selection or per-flow load balancing."
              action={
                <Button
                  onClick={() => {
                    setEditing(null);
                    setEditorOpen(true);
                  }}
                  className="bg-zinc-700 text-white hover:bg-zinc-800"
                >
                  <Icons.Plus className="mr-1 h-4 w-4" /> Add WAN policy
                </Button>
              }
            />
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {policies.map((p) => {
            const state = overlay[p.interfaceName] ?? p.state;
            return (
              <Card key={p.id} className={cn("flex flex-col p-4", !p.enabled && "opacity-60")}>
                <CardHeader className="flex-row items-start justify-between space-y-0 p-0 pb-3">
                  <div>
                    <CardTitle className="font-mono text-lg font-semibold">{p.interfaceName}</CardTitle>
                    <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                      <StateBadge state={state} />
                      <Badge
                        variant="outline"
                        className="border-zinc-300 bg-zinc-100 text-[10px] font-semibold uppercase text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
                      >
                        {MODE_LABEL[p.mode]}
                      </Badge>
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8"
                      aria-label={`Edit WAN policy for ${p.interfaceName}`}
                      onClick={() => {
                        setEditing(p);
                        setEditorOpen(true);
                      }}
                    >
                      <Icons.Pencil className="h-3.5 w-3.5" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8 text-rose-600 hover:text-rose-700 dark:text-rose-400"
                      aria-label={`Delete WAN policy for ${p.interfaceName}`}
                      onClick={() => setDeleting(p)}
                    >
                      <Icons.Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="flex flex-1 flex-col gap-2 p-0">
                  <div className="space-y-1 text-xs text-zinc-500">
                    <p className="font-mono text-zinc-600 dark:text-zinc-300">
                      {p.probeType} → {p.probeTarget} <span className="text-zinc-400">every {p.intervalSec} s</span>
                    </p>
                    <p className="flex flex-wrap gap-x-3">
                      {p.mode === "load_balance" ? <span>weight <span className="tabular-nums text-zinc-800 dark:text-zinc-200">{p.weight}%</span></span> : null}
                      <span>priority <span className="tabular-nums text-zinc-800 dark:text-zinc-200">{p.priority}</span></span>
                      <span>timeout <span className="tabular-nums text-zinc-800 dark:text-zinc-200">{p.timeoutMs} ms</span></span>
                    </p>
                    <p>
                      thresholds: fail <span className="tabular-nums text-zinc-800 dark:text-zinc-200">{p.failThreshold}</span> / ok{" "}
                      <span className="tabular-nums text-zinc-800 dark:text-zinc-200">{p.okThreshold}</span>
                    </p>
                  </div>
                  <div className="mt-auto flex items-center justify-between gap-2 pt-2">
                    <Label className="flex items-center gap-2 text-xs">
                      <Switch
                        checked={p.enabled}
                        disabled={toggleEnabledMut.isPending}
                        aria-label={`Toggle WAN policy for ${p.interfaceName}`}
                        onCheckedChange={(checked) => {
                          const body: WanPolicyBody = {
                            interfaceName: p.interfaceName,
                            mode: p.mode,
                            weight: p.weight,
                            priority: p.priority,
                            probeType: p.probeType,
                            probeTarget: p.probeTarget,
                            intervalSec: p.intervalSec,
                            timeoutMs: p.timeoutMs,
                            failThreshold: p.failThreshold,
                            okThreshold: p.okThreshold,
                            enabled: checked,
                          };
                          toggleEnabledMut.mutate({ id: p.id, body });
                        }}
                      />
                      {p.enabled ? "enabled" : "disabled"}
                    </Label>
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={probeMut.isPending || !p.enabled}
                      onClick={() => probeMut.mutate(p)}
                      aria-label={`Force probe now for ${p.interfaceName}`}
                    >
                      {probeMut.isPending && probeMut.variables?.id === p.id ? (
                        <Icons.LoaderCircle className="mr-1 h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <Icons.Radar className="mr-1 h-3.5 w-3.5" />
                      )}
                      Probe now
                    </Button>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {editorOpen && (
        <WanPolicyEditor
          key={editing?.id ?? "new"}
          open={editorOpen}
          onOpenChange={setEditorOpen}
          editing={editing}
          candidates={candidates}
          onSaved={() => void queryClient.invalidateQueries({ queryKey: WAN_KEY })}
        />
      )}

      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title="Delete WAN policy?"
        description={`Delete the WAN policy for '${deleting?.interfaceName ?? ""}'? The interface loses probe-driven health monitoring and egress selection.`}
        loading={deleteMut.isPending}
        onConfirm={() => deleting && deleteMut.mutate(deleting.id)}
      />
    </div>
  );
}

// ── policy editor dialog ────────────────────────────────────────────────────

function WanPolicyEditor(props: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editing: WanPolicy | null;
  candidates: Iface[];
  onSaved: () => void;
}) {
  const queryClient = useQueryClient();
  const editing = props.editing;
  const isEdit = editing != null;

  const [interfaceName, setInterfaceName] = useState(editing?.interfaceName ?? "");
  const [mode, setMode] = useState<WanMode>(editing?.mode ?? "priority");
  const [weight, setWeight] = useState(editing?.weight ?? 50);
  const [priority, setPriority] = useState(String(editing?.priority ?? 1));
  const [probeType, setProbeType] = useState<ProbeType>(editing?.probeType ?? "icmp");
  const [probeTarget, setProbeTarget] = useState(editing?.probeTarget ?? PROBE_TARGET_DEFAULTS[editing?.probeType ?? "icmp"]);
  const [intervalSec, setIntervalSec] = useState(String(editing?.intervalSec ?? 5));
  const [timeoutMs, setTimeoutMs] = useState(String(editing?.timeoutMs ?? 2000));
  const [failThreshold, setFailThreshold] = useState(String(editing?.failThreshold ?? 3));
  const [okThreshold, setOkThreshold] = useState(String(editing?.okThreshold ?? 3));
  const [enabled, setEnabled] = useState(editing?.enabled ?? true);
  const [error, setError] = useState<string | null>(null);

  const mut = useMutation({
    mutationFn: (body: WanPolicyBody) =>
      isEdit && editing ? netApi.updateWanPolicy(editing.id, body) : netApi.createWanPolicy(body),
    onSuccess: (saved) => {
      toastOk(isEdit ? "WAN policy updated" : "WAN policy created", saved.interfaceName);
      props.onOpenChange(false);
      props.onSaved();
    },
    onError: (err) => toastErr(err, isEdit ? "Update failed" : "Create failed"),
  });

  const submit = () => {
    if (!interfaceName) return setError("Pick a WAN interface");
    const prio = Number(priority);
    if (!Number.isInteger(prio) || prio < 1 || prio > 10) return setError("Priority must be an integer between 1 and 10");
    const interval = Number(intervalSec);
    if (!Number.isInteger(interval) || interval < 1) return setError("Probe interval must be a positive integer (seconds)");
    const timeout = Number(timeoutMs);
    if (!Number.isInteger(timeout) || timeout < 100) return setError("Probe timeout must be at least 100 ms");
    const failN = Number(failThreshold);
    const okN = Number(okThreshold);
    if (!Number.isInteger(failN) || failN < 1) return setError("Fail threshold must be a positive integer");
    if (!Number.isInteger(okN) || okN < 1) return setError("OK threshold must be a positive integer");
    if (!probeTarget.trim()) return setError("Probe target is required");
    setError(null);
    mut.mutate({
      interfaceName,
      mode,
      weight,
      priority: prio,
      probeType,
      probeTarget: probeTarget.trim(),
      intervalSec: interval,
      timeoutMs: timeout,
      failThreshold: failN,
      okThreshold: okN,
      enabled,
    });
  };

  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent className="max-h-[90vh] w-[calc(100vw-1rem)] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{isEdit ? `WAN policy — ${editing.interfaceName}` : "Add WAN policy"}</DialogTitle>
          <DialogDescription>
            {isEdit
              ? "New targets/thresholds take effect after the next config apply — the probe generator picks them up live."
              : "One policy per interface — pick a WAN interface that has no policy yet."}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div>
            <FieldLabel hint={isEdit ? "locked while editing" : props.candidates.length === 0 ? "no uncovered WAN interfaces" : undefined}>
              Interface
            </FieldLabel>
            <Select
              value={interfaceName || undefined}
              onValueChange={setInterfaceName}
              disabled={isEdit}
            >
              <SelectTrigger aria-label="WAN interface">
                <SelectValue placeholder={props.candidates.length === 0 ? "all WAN interfaces covered" : "select interface…"} />
              </SelectTrigger>
              <SelectContent>
                {(isEdit ? [{ id: 0, name: editing.interfaceName }] : props.candidates).map((c) => (
                  <SelectItem key={c.id} value={c.name}>
                    {c.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {!isEdit && props.candidates.length === 0 && (
              <p className="mt-1 text-[11px] text-amber-600 dark:text-amber-400">
                Every interface with role &ldquo;wan&rdquo; already has a policy. Assign the wan role in the Interfaces tab first.
              </p>
            )}
          </div>

          <div>
            <FieldLabel>Mode</FieldLabel>
            <RadioGroup value={mode} onValueChange={(v) => setMode(v as WanMode)} className="flex flex-wrap gap-4">
              {WAN_MODES.map((m) => (
                <Label key={m} className="flex cursor-pointer items-center gap-2 text-sm">
                  <RadioGroupItem value={m} /> {MODE_LABEL[m]}
                </Label>
              ))}
            </RadioGroup>
          </div>

          {mode === "load_balance" && (
            <div>
              <FieldLabel hint={`${weight}% of new connections`}>Weight</FieldLabel>
              <div className="flex items-center gap-3">
                <Slider
                  value={[weight]}
                  min={1}
                  max={99}
                  step={1}
                  onValueChange={(vals) => setWeight(vals[0] ?? weight)}
                  aria-label="Load balance weight"
                  className="flex-1"
                />
                <span className="w-12 text-right text-sm font-medium tabular-nums">{weight}%</span>
              </div>
            </div>
          )}

          <div className="grid grid-cols-2 gap-3">
            <div>
              <FieldLabel hint="1–10, lower preferred">Priority</FieldLabel>
              <Input type="number" min={1} max={10} value={priority} onChange={(e) => setPriority(e.target.value)} aria-label="Priority" />
            </div>
            <div>
              <FieldLabel>Probe type</FieldLabel>
              <Select
                value={probeType}
                onValueChange={(v) => {
                  const t = v as ProbeType;
                  setProbeType(t);
                  setProbeTarget(PROBE_TARGET_DEFAULTS[t]);
                }}
              >
                <SelectTrigger aria-label="Probe type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PROBE_TYPES.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div>
            <FieldLabel hint="editable — defaults per type">Probe target</FieldLabel>
            <Input
              value={probeTarget}
              onChange={(e) => setProbeTarget(e.target.value)}
              placeholder={PROBE_TARGET_DEFAULTS[probeType]}
              className="font-mono"
              aria-label="Probe target"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <FieldLabel hint="seconds">Interval</FieldLabel>
              <Input type="number" min={1} value={intervalSec} onChange={(e) => setIntervalSec(e.target.value)} aria-label="Probe interval" />
            </div>
            <div>
              <FieldLabel hint="ms">Timeout</FieldLabel>
              <Input type="number" min={100} step={100} value={timeoutMs} onChange={(e) => setTimeoutMs(e.target.value)} aria-label="Probe timeout" />
            </div>
            <div>
              <FieldLabel hint="bad probes → down">Fail threshold</FieldLabel>
              <Input type="number" min={1} value={failThreshold} onChange={(e) => setFailThreshold(e.target.value)} aria-label="Fail threshold" />
            </div>
            <div>
              <FieldLabel hint="good probes → up">OK threshold</FieldLabel>
              <Input type="number" min={1} value={okThreshold} onChange={(e) => setOkThreshold(e.target.value)} aria-label="OK threshold" />
            </div>
          </div>

          <Label className="flex items-center gap-2 text-sm">
            <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="Toggle policy enabled" /> Enabled
          </Label>
          {error && <p className="text-xs font-medium text-rose-600 dark:text-rose-400">{error}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => props.onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={mut.isPending || (!isEdit && props.candidates.length === 0)} className="bg-amber-700 text-white hover:bg-amber-800">
            {mut.isPending ? "Saving…" : isEdit ? "Save changes" : "Create policy"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
