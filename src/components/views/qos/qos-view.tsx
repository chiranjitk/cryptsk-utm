"use client";

/**
 * QoS view (M08 §4) — hash #/qos/policies, master-detail:
 * left = policy cards (template badge, humanized bandwidth, iface chip,
 * enabled toggle, rule count); right = rules table (priority asc, ties by id),
 * effect-explanation panel ("what tc does with this") and the utilization
 * sparkline proving the engine honors the caps (§5.4).
 * Quick-create toolbar "Limit user…" / "Limit application…" per spec §1.11.
 * Theme per ADR-019 (white & blue) — charts use the locked charts palette.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Slider } from "@/components/ui/slider";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  ConfirmDialog,
  EditorSection,
  EmptyBlock,
  FieldLabel,
  PopoverMulti,
  QueryError,
  TableSkeleton,
  toastErr,
  toastOk,
} from "../firewall/fw-ui";
import { PALETTE } from "@/components/charts/palette";
import { useRealtime, type MetricsTickPayload } from "@/lib/realtime";
import { cn } from "@/lib/utils";
import { QOS_TEMPLATES, type QosTemplateName } from "@/lib/qos/templates";
import {
  fieldErrorsOf,
  fmtKbpsAxis,
  humanizeKbps,
  listAddresses,
  listApps,
  listInterfaceNames,
  listUsers,
  qosApi,
  referencedByOf,
  type AddressLite,
  type IfaceLite,
  type QosPolicyDTO,
  type QosRuleDTO,
} from "./qos-api";
import {
  DscpBadge,
  DSCP_WELL_KNOWN,
  HardLimitBadge,
  MatcherChips,
  PriorityBadge,
  TemplateBadge,
  TemplateExplanationTable,
  useQosConfigInvalidation,
} from "./qos-ui";

export function QosView() {
  useQosConfigInvalidation();
  const queryClient = useQueryClient();
  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ["qos"] });
  const policies = useQuery({ queryKey: ["qos", "policies"], queryFn: qosApi.listPolicies });
  const ifaces = useQuery({ queryKey: ["qos", "ifaces"], queryFn: listInterfaceNames, staleTime: 30_000 });
  const users = useQuery({ queryKey: ["qos", "users-meta"], queryFn: listUsers, staleTime: 60_000 });

  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<QosPolicyDTO | null>(null);
  const [deleting, setDeleting] = useState<QosPolicyDTO | null>(null);
  const [deleteConflict, setDeleteConflict] = useState<{ message: string; refs: Array<{ ruleName: string; ruleType: string }> } | null>(null);

  // deep link opens with the first policy selected (M08 §7) — derived fallback, no effect needed
  const effectiveSelectedId = selectedId ?? policies.data?.[0]?.id ?? null;

  const selected = useMemo(
    () => (policies.data ?? []).find((p) => p.id === effectiveSelectedId) ?? null,
    [policies.data, effectiveSelectedId],
  );
  const usersById = useMemo(() => {
    const m = new Map<string, string>();
    for (const u of users.data ?? []) m.set(String(u.id), u.username);
    return m;
  }, [users.data]);

  const del = useMutation({
    mutationFn: (id: number) => qosApi.deletePolicy(id),
    onSuccess: (res) => {
      const n = res.cascaded?.cascadedRules ?? 0;
      toastOk("Policy deleted", n > 0 ? `Cascaded ${n} rule(s)` : undefined);
      setSelectedId(null);
      setDeleting(null);
      invalidate();
    },
    onError: (err) => {
      const refs = referencedByOf(err);
      if (refs.length > 0) {
        setDeleting(null);
        setDeleteConflict({ message: err instanceof Error ? err.message : "Policy is referenced", refs });
      } else {
        toastErr(err, "Delete failed");
      }
    },
  });

  const rows = policies.data ?? [];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs text-zinc-500">
          Egress traffic shaping · one HTB shaper per policy, rules classify into priority classes (0 highest – 7 lowest)
        </p>
        <Button
          size="sm"
          className="bg-red-700 text-white hover:bg-red-800"
          onClick={() => {
            setEditing(null);
            setEditorOpen(true);
          }}
        >
          <Icons.Plus className="mr-1 h-4 w-4" /> Add Policy
        </Button>
      </div>

      {policies.isLoading ? (
        <div className="grid gap-3 lg:grid-cols-2">
          {[...Array(2)].map((_, i) => (
            <Card key={i}>
              <CardContent className="space-y-3 pt-6">
                {[...Array(4)].map((_, j) => (
                  <div key={j} className="h-5 w-full animate-pulse rounded bg-zinc-100 dark:bg-zinc-800" />
                ))}
              </CardContent>
            </Card>
          ))}
        </div>
      ) : policies.isError ? (
        <QueryError error={policies.error} onRetry={() => void policies.refetch()} />
      ) : rows.length === 0 ? (
        <Card>
          <CardContent className="p-0">
            <EmptyBlock
              icon={<Icons.Gauge className="h-6 w-6" />}
              title="No shaper policies"
              description="Create a policy to cap your WAN — templates seed starter classes for VoIP, video, gaming or bulk traffic."
              action={
                <Button
                  size="sm"
                  className="bg-red-700 text-white hover:bg-red-800"
                  onClick={() => {
                    setEditing(null);
                    setEditorOpen(true);
                  }}
                >
                  Add Policy
                </Button>
              }
            />
          </CardContent>
        </Card>
      ) : (
        <div className="grid items-start gap-4 xl:grid-cols-5">
          {/* ── left: policy list ── */}
          <div className="space-y-3 xl:col-span-2">
            {rows.map((p) => (
              <PolicyCard
                key={p.id}
                policy={p}
                active={p.id === selected?.id}
                onSelect={() => setSelectedId(p.id)}
                onEdit={() => {
                  setEditing(p);
                  setEditorOpen(true);
                }}
                onDelete={() => setDeleting(p)}
                onToggled={invalidate}
              />
            ))}
          </div>

          {/* ── right: selected policy detail ── */}
          <div className="space-y-4 xl:col-span-3">
            {selected ? (
              <PolicyDetail policy={selected} usersById={usersById} onChanged={invalidate} />
            ) : (
              <Card>
                <CardContent className="p-0">
                  <EmptyBlock icon={<Icons.MousePointerClick className="h-6 w-6" />} title="Select a policy" description="Pick a shaper on the left to manage its classes." />
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      )}

      <PolicyDialog
        open={editorOpen}
        onOpenChange={setEditorOpen}
        editing={editing}
        ifaces={ifaces.data ?? []}
        onSaved={() => {
          setEditorOpen(false);
          invalidate();
        }}
      />

      <ConfirmDialog
        open={deleting != null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete policy ${deleting?.name ?? ""}?`}
        description={
          deleting
            ? `Cascades ${deleting.ruleCount} rule(s). Deleting a policy referenced by firewall rules is refused with the referencing rule names. This cannot be undone.`
            : ""
        }
        confirmLabel="Delete policy"
        loading={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting.id)}
      />

      <AlertDialog open={deleteConflict != null} onOpenChange={(open) => !open && setDeleteConflict(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <Icons.TriangleAlert className="h-5 w-5 text-amber-500" />
              Policy is referenced by firewall rules
            </AlertDialogTitle>
            <AlertDialogDescription>{deleteConflict?.message}</AlertDialogDescription>
          </AlertDialogHeader>
          {deleteConflict && deleteConflict.refs.length > 0 && (
            <div className="rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
              <p className="mb-2 text-xs font-medium text-zinc-500">Referenced by these rules:</p>
              <div className="flex flex-wrap gap-1.5">
                {deleteConflict.refs.map((r, i) => (
                  <a key={`${r.ruleName}-${i}`} href="#/firewall/rules" className="inline-flex">
                    <Badge variant="outline" className="border-red-600/40 bg-red-600/10 text-red-700 hover:bg-red-600/20 dark:text-red-500">
                      <Icons.ShieldCheck className="mr-1 h-3 w-3" />
                      {r.ruleName}
                      <span className="ml-1 text-[10px] uppercase text-zinc-400">{r.ruleType}</span>
                    </Badge>
                  </a>
                ))}
              </div>
            </div>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel>Close</AlertDialogCancel>
            <AlertDialogAction
              className="bg-red-700 text-white hover:bg-red-800 focus-visible:ring-red-700"
              onClick={(e) => {
                e.preventDefault();
                window.location.hash = "#/firewall/rules";
                setDeleteConflict(null);
              }}
            >
              Open firewall rules
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

// ── left: policy card ───────────────────────────────────────────────────────

function PolicyCard({
  policy,
  active,
  onSelect,
  onEdit,
  onDelete,
  onToggled,
}: {
  policy: QosPolicyDTO;
  active: boolean;
  onSelect: () => void;
  onEdit: () => void;
  onDelete: () => void;
  onToggled: () => void;
}) {
  const toggle = useMutation({
    mutationFn: (enabled: boolean) => qosApi.updatePolicy(policy.id, { enabled }),
    onSuccess: onToggled,
    onError: (err) => toastErr(err, "Toggle failed"),
  });

  return (
    <Card
      className={cn(
        "cursor-pointer transition-colors",
        active ? "border-zinc-500/40 bg-zinc-500/[0.04] ring-1 ring-zinc-500/30" : "hover:border-zinc-300 dark:hover:border-zinc-700",
        !policy.enabled && "opacity-70",
      )}
      onClick={onSelect}
    >
      <CardContent className="space-y-2.5 pt-5">
        <div className="flex items-center justify-between gap-2">
          <p className="flex items-center gap-2 truncate text-sm font-medium" onClick={(e) => e.stopPropagation()}>
            {policy.name} <TemplateBadge template={policy.template} />
          </p>
          <span onClick={(e) => e.stopPropagation()}>
            <Switch
              checked={policy.enabled}
              onCheckedChange={(v) => toggle.mutate(v)}
              disabled={toggle.isPending}
              aria-label={`Toggle policy ${policy.name}`}
            />
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <Badge variant="outline" className="border-zinc-500/30 bg-zinc-500/10 px-1.5 py-0 font-mono text-[10px] text-zinc-600 dark:text-zinc-300">
            {humanizeKbps(policy.bandwidthKbps)}
          </Badge>
          {policy.ifaceName ? (
            <Badge variant="outline" className="px-1.5 py-0 font-mono text-[10px] text-zinc-600 dark:text-zinc-300">
              <Icons.EthernetPort className="mr-1 h-3 w-3" />
              {policy.ifaceName}
              {policy.ifaceAttached === false && <span className="ml-1 text-[9px] text-amber-600 dark:text-amber-400">missing iface</span>}
            </Badge>
          ) : (
            <Badge variant="outline" className="px-1.5 py-0 text-[10px] text-zinc-500">
              all WAN
            </Badge>
          )}
          <Badge variant="outline" className="px-1.5 py-0 text-[10px] text-zinc-500">
            {policy.ruleCount} rule{policy.ruleCount === 1 ? "" : "s"}
          </Badge>
          {policy.guaranteedSumKbps > 0 && (
            <Badge variant="outline" className="px-1.5 py-0 text-[10px] text-zinc-500">
              {Math.min(100, Math.round((policy.guaranteedSumKbps / policy.bandwidthKbps) * 100))}% guaranteed
            </Badge>
          )}
        </div>
        <div className="flex items-center justify-end gap-1.5 border-t border-zinc-100 pt-2 dark:border-zinc-800" onClick={(e) => e.stopPropagation()}>
          <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={onEdit}>
            <Icons.Pencil className="mr-1 h-3.5 w-3.5" /> Edit
          </Button>
          <Button variant="ghost" size="sm" className="h-7 text-xs text-rose-600 hover:text-rose-600 dark:text-rose-400" onClick={onDelete}>
            <Icons.Trash2 className="mr-1 h-3.5 w-3.5" /> Delete
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ── right: policy detail ────────────────────────────────────────────────────

function PolicyDetail({
  policy,
  usersById,
  onChanged,
}: {
  policy: QosPolicyDTO;
  usersById: Map<string, string>;
  onChanged: () => void;
}) {
  const rules = useQuery({
    queryKey: ["qos", "rules", policy.id],
    queryFn: () => qosApi.listRules(policy.id),
  });
  const ifaces = useQuery({ queryKey: ["qos", "ifaces"], queryFn: listInterfaceNames, staleTime: 30_000 });

  const [ruleEditorOpen, setRuleEditorOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<QosRuleDTO | null>(null);
  const [prefill, setPrefill] = useState<RulePrefill | null>(null);
  const [deletingRule, setDeletingRule] = useState<QosRuleDTO | null>(null);

  const del = useMutation({
    mutationFn: (id: number) => qosApi.deleteRule(id),
    onSuccess: () => {
      toastOk("Rule deleted");
      setDeletingRule(null);
      onChanged();
    },
    onError: (err) => toastErr(err, "Delete failed"),
  });

  const openEditor = (rule: QosRuleDTO | null, pre: RulePrefill | null = null) => {
    setEditingRule(rule);
    setPrefill(pre);
    setRuleEditorOpen(true);
  };

  const rows = rules.data ?? [];

  return (
    <div className="space-y-4">
      {/* rules table */}
      <Card>
        <CardContent className="p-0">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-200 px-4 py-3 dark:border-zinc-800">
            <div>
              <p className="text-sm font-medium">
                Rules — {policy.name} <span className="ml-1 text-xs text-zinc-400">({rows.length})</span>
              </p>
              <p className="text-[11px] text-zinc-400">
                Evaluation order = priority asc, ties by creation order · budget {humanizeKbps(policy.bandwidthKbps)}
                {policy.ifaceName ? ` on ${policy.ifaceName}` : " across all WAN egress"}
              </p>
            </div>
            <div className="flex flex-wrap gap-1.5">
              <Button size="sm" variant="outline" className="h-8 text-xs" onClick={() => openEditor(null, { mode: "user" })}>
                <Icons.User className="mr-1 h-3.5 w-3.5" /> Limit user…
              </Button>
              <Button size="sm" variant="outline" className="h-8 text-xs" onClick={() => openEditor(null, { mode: "app" })}>
                <Icons.AppWindow className="mr-1 h-3.5 w-3.5" /> Limit application…
              </Button>
              <Button size="sm" className="h-8 bg-red-700 text-xs text-white hover:bg-red-800" onClick={() => openEditor(null)}>
                <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add Rule
              </Button>
            </div>
          </div>

          {rules.isLoading ? (
            <div className="pt-2">
              <TableSkeleton rows={3} cols={6} />
            </div>
          ) : rules.isError ? (
            <div className="p-4">
              <QueryError error={rules.error} onRetry={() => void rules.refetch()} />
            </div>
          ) : rows.length === 0 ? (
            <EmptyBlock
              icon={<Icons.ListTree className="h-6 w-6" />}
              title="No rules in this policy"
              description="Add a class with matchers and rates — or use the quick limit actions above."
              action={
                <Button size="sm" className="bg-red-700 text-white hover:bg-red-800" onClick={() => openEditor(null)}>
                  Add Rule
                </Button>
              }
            />
          ) : (
            <div className="max-h-[420px] overflow-auto [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-zinc-300 dark:[&::-webkit-scrollbar-thumb]:bg-zinc-700">
              <Table>
                <TableHeader className="sticky top-0 z-[1] bg-zinc-50 dark:bg-zinc-900">
                  <TableRow>
                    <TableHead className="w-14">Prio</TableHead>
                    <TableHead>Name</TableHead>
                    <TableHead>Matchers</TableHead>
                    <TableHead>Guaranteed → Max</TableHead>
                    <TableHead>DSCP</TableHead>
                    <TableHead>Hard limit</TableHead>
                    <TableHead className="w-20" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((r) => (
                    <TableRow key={r.id}>
                      <TableCell><PriorityBadge priority={r.priority} /></TableCell>
                      <TableCell className="text-xs font-medium">{r.name}</TableCell>
                      <TableCell><MatcherChips apps={r.matchApps} users={r.matchUsers} addresses={r.matchAddresses} usersById={usersById} /></TableCell>
                      <TableCell className="whitespace-nowrap font-mono text-xs tabular-nums">
                        {r.guaranteedKbps != null ? humanizeKbps(r.guaranteedKbps) : "—"} → {r.maxKbps != null ? humanizeKbps(r.maxKbps) : "∞"}
                      </TableCell>
                      <TableCell><DscpBadge mark={r.dscpMark} /></TableCell>
                      <TableCell>{r.hardLimit ? <HardLimitBadge /> : <span className="text-[11px] text-zinc-400">—</span>}</TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={`Edit rule ${r.name}`} onClick={() => openEditor(r)}>
                            <Icons.Pencil className="h-3.5 w-3.5" />
                          </Button>
                          <Button variant="ghost" size="icon" className="h-8 w-8 text-rose-500 hover:text-rose-600" aria-label={`Delete rule ${r.name}`} onClick={() => setDeletingRule(r)}>
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

      <div className="grid gap-4 lg:grid-cols-2">
        <EffectPanel policy={policy} rules={rows} />
        <UtilizationSparkline policy={policy} ifaces={ifaces.data ?? []} />
      </div>

      <RuleDialog
        open={ruleEditorOpen}
        onOpenChange={setRuleEditorOpen}
        policy={policy}
        editing={editingRule}
        prefill={prefill}
        onSaved={() => {
          setRuleEditorOpen(false);
          onChanged();
        }}
      />

      <ConfirmDialog
        open={deletingRule != null}
        onOpenChange={(open) => !open && setDeletingRule(null)}
        title={`Delete rule ${deletingRule?.name ?? ""}?`}
        description="The class and its DSCP mark are removed from the shaper on the next apply."
        confirmLabel="Delete rule"
        loading={del.isPending}
        onConfirm={() => deletingRule && del.mutate(deletingRule.id)}
      />
    </div>
  );
}

// ── effect panel ("what tc does with this") ─────────────────────────────────

function EffectPanel({ policy, rules }: { policy: QosPolicyDTO; rules: QosRuleDTO[] }) {
  const target = policy.ifaceName ?? "aggregate WAN egress";
  const maxSum = rules.reduce((s, r) => s + (r.maxKbps ?? 0), 0);
  const multiplexing = maxSum > policy.bandwidthKbps;

  return (
    <Card>
      <CardContent className="space-y-3 pt-5">
        <div className="flex items-center gap-2">
          <Icons.Terminal className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
          <p className="text-sm font-medium">Effect — what tc does with this</p>
        </div>
        <ol className="space-y-1.5 font-mono text-[11px] text-zinc-600 dark:text-zinc-300">
          <li className="text-zinc-500 dark:text-zinc-400">1 · root qdisc on {target}</li>
          <li className="pl-3">tc qdisc add dev {policy.ifaceName ?? "wan"} root handle 1: htb default 99</li>
          <li className="pl-3">tc class add dev {policy.ifaceName ?? "wan"} parent 1: classid 1:1 htb rate {policy.bandwidthKbps}kbit ceil {policy.bandwidthKbps}kbit</li>
          {policy.enabled && rules.length > 0 ? (
            <>
              <li className="pt-1 text-zinc-500 dark:text-zinc-400">2 · one child class per rule + fq_codel leaf</li>
              {rules.map((r, i) => {
                const cls = `1:${10 + i}`;
                return (
                  <li key={r.id} className="pl-3">
                    <span>
                      tc class add … parent 1:1 classid {cls} htb rate {r.guaranteedKbps ?? 1}kbit ceil{" "}
                      {r.maxKbps ?? policy.bandwidthKbps}kbit prio {r.priority} · qdisc {cls.replace("1:", "")}: fq_codel
                    </span>
                  </li>
                );
              })}
              <li className="pt-1 text-zinc-500 dark:text-zinc-400">3 · nftables classify + DSCP marks</li>
              {rules.some((r) => r.matchApps.length > 0) && (
                <li className="pl-3">nft add rule … meta mark set &lt;class&gt; comment &quot;ndpi: {rules.flatMap((r) => r.matchApps).join(", ")}&quot;</li>
              )}
              {rules.some((r) => r.matchUsers.length > 0) && (
                <li className="pl-3">nft add rule … identity map &lt;user → class&gt; comment &quot;per-user match&quot;</li>
              )}
              {rules.some((r) => r.matchAddresses.length > 0) && (
                <li className="pl-3">nft add rule … ip saddr @qos_addresses meta mark set &lt;class&gt;</li>
              )}
              {rules.some((r) => r.dscpMark != null) && (
                <li className="pl-3">nft add rule … ip dscp set {rules.filter((r) => r.dscpMark != null).map((r) => r.dscpMark).join(" / ")}</li>
              )}
            </>
          ) : (
            <li className="pt-1 text-amber-600 dark:text-amber-400">
              {policy.enabled ? "no rules — no child classes installed (traffic passes BE)" : "policy disabled — classes are removed from the shaper on the next tick"}
            </li>
          )}
        </ol>
        {multiplexing && (
          <p className="rounded-md bg-zinc-50 px-2.5 py-2 text-[11px] text-zinc-500 dark:bg-zinc-800/60">
            Σ max = {humanizeKbps(maxSum)} exceeds the {humanizeKbps(policy.bandwidthKbps)} budget — statistical multiplexing is intended; classes only borrow within the root rate.
          </p>
        )}
        <p className="border-t border-zinc-100 pt-2 text-[11px] leading-relaxed text-zinc-400 dark:border-zinc-800">
          The sandbox does <strong className="font-medium text-zinc-500 dark:text-zinc-400">not</strong> run tc — this panel documents the would-be appliance
          configuration (DATA_PLANE.md, tc stage); it is not a live config viewer. The metrics generator honors the budget instead (§5.4).
        </p>
      </CardContent>
    </Card>
  );
}

// ── utilization sparkline (metrics:tick, cap line rose) ─────────────────────

const SPARK_POINTS = 30; // 30 × 2 s ≈ last 60 s (M08 §4)

function UtilizationSparkline({ policy, ifaces }: { policy: QosPolicyDTO; ifaces: IfaceLite[] }) {
  const [series, setSeries] = useState<Array<{ ts: string; label: string; tx: number }>>([]);
  const wanNames = useMemo(
    () => new Set((ifaces ?? []).filter((i) => i.role === "wan").map((i) => i.name)),
    [ifaces],
  );
  const wanNamesRef = useRef(wanNames);
  useEffect(() => {
    wanNamesRef.current = wanNames;
  }, [wanNames]);

  useRealtime(["metrics"], {
    onMetricsTick: (t: MetricsTickPayload) => {
      const tx = policy.ifaceName
        ? (t.ifaces.find((i) => i.name === policy.ifaceName)?.txKbps ?? 0)
        : t.ifaces.filter((i) => wanNamesRef.current.has(i.name)).reduce((s, i) => s + i.txKbps, 0);
      const label = new Date(t.ts).toLocaleTimeString(undefined, { hour12: false, minute: "2-digit", second: "2-digit" });
      setSeries((cur) => [...cur, { ts: t.ts, label, tx }].slice(-SPARK_POINTS));
    },
  });

  const cap = policy.bandwidthKbps;
  const peak = Math.max(cap, ...series.map((p) => p.tx), 1);
  const yMax = Math.ceil((peak * 1.2) / 5000) * 5000;
  const atCap = series.length > 0 && series.every((p) => p.tx >= cap * 0.97);

  return (
    <Card>
      <CardContent className="space-y-2 pt-5">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Icons.Activity className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
            <p className="text-sm font-medium">Utilization — egress tx</p>
          </div>
          <p className="text-[11px] text-zinc-400">
            last ~60 s · {policy.ifaceName ?? "aggregate WAN"} · cap {humanizeKbps(cap)}
          </p>
        </div>
        <div className="h-[120px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={series} margin={{ top: 6, right: 8, left: 0, bottom: 0 }}>
              <defs>
                <linearGradient id="qosTxGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={PALETTE.blue} stopOpacity={0.35} />
                  <stop offset="100%" stopColor={PALETTE.blue} stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke={PALETTE.slate} strokeOpacity={0.25} vertical={false} />
              <XAxis dataKey="label" tick={{ fontSize: 9 }} stroke={PALETTE.slate} tickLine={false} axisLine={false} minTickGap={40} />
              <YAxis domain={[0, yMax]} tickFormatter={fmtKbpsAxis} tick={{ fontSize: 9 }} stroke={PALETTE.slate} tickLine={false} axisLine={false} width={44} />
              <Tooltip
                formatter={(value: number) => [`${value.toLocaleString()} kbps`, "tx"]}
                labelFormatter={(l) => `at ${l}`}
                contentStyle={{ borderRadius: 8, fontSize: 12 }}
              />
              <ReferenceLine
                y={cap}
                stroke={PALETTE.rose}
                strokeDasharray="6 4"
                label={{ value: `cap ${humanizeKbps(cap)}`, position: "insideTopRight", fontSize: 10, fill: PALETTE.rose }}
              />
              <Area type="monotone" dataKey="tx" stroke={PALETTE.blue} strokeWidth={2} fill="url(#qosTxGrad)" isAnimationActive={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
        <p className="text-[11px] text-zinc-400">
          {series.length === 0
            ? "waiting for ticks…"
            : atCap
              ? "series rides the cap — the generator is honoring the policy budget (§5.4)"
              : "rose dashed line = policy budget; the series flattens when traffic exceeds it"}
        </p>
      </CardContent>
    </Card>
  );
}

// ── policy editor dialog ────────────────────────────────────────────────────

type PolicyForm = {
  name: string;
  template: QosTemplateName | null;
  bandwidthKbps: string;
  ifaceName: string; // "none" = aggregate WAN
  enabled: boolean;
};

function policyFormFrom(p: QosPolicyDTO | null): PolicyForm {
  return {
    name: p?.name ?? "",
    template: (p?.template as QosTemplateName | null) ?? null,
    bandwidthKbps: String(p?.bandwidthKbps ?? 50_000),
    ifaceName: p?.ifaceName ?? "none",
    enabled: p?.enabled ?? true,
  };
}

function PolicyDialog({
  open,
  onOpenChange,
  editing,
  ifaces,
  onSaved,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editing: QosPolicyDTO | null;
  ifaces: IfaceLite[];
  onSaved: () => void;
}) {
  const [form, setForm] = useState(() => policyFormFrom(editing));
  const [serverErrors, setServerErrors] = useState<Record<string, string[]>>({});
  const [bandwidthTouched, setBandwidthTouched] = useState(editing != null);
  const [templateChanged, setTemplateChanged] = useState(false);

  const seedKey = editing?.id ?? "new";
  const [lastKey, setLastKey] = useState(seedKey);
  if (seedKey !== lastKey) {
    setLastKey(seedKey);
    setServerErrors({});
    setBandwidthTouched(editing != null);
    setTemplateChanged(false);
    setForm(policyFormFrom(editing));
  }

  const save = useMutation({
    mutationFn: () => {
      const body: Record<string, unknown> = {
        name: form.name.trim(),
        bandwidthKbps: Number(form.bandwidthKbps) || 0,
        ifaceName: form.ifaceName === "none" ? null : form.ifaceName,
        enabled: form.enabled,
      };
      if (form.template) body.template = form.template;
      return editing ? qosApi.updatePolicy(editing.id, body) : qosApi.createPolicy(body);
    },
    onSuccess: () => {
      toastOk(editing ? "Policy updated" : "Policy created");
      onSaved();
    },
    onError: (err) => {
      setServerErrors(fieldErrorsOf(err));
      toastErr(err, "Save failed");
    },
  });

  const err = (path: string) => serverErrors[path]?.join("; ");
  const set = <K extends keyof PolicyForm>(k: K, v: PolicyForm[K]) => setForm((f) => ({ ...f, [k]: v }));
  const bandwidth = Number(form.bandwidthKbps) || 0;
  // wan-role options first (M08 §4)
  const sortedIfaces = useMemo(
    () => [...(ifaces ?? [])].sort((a, b) => (a.role === "wan" ? 0 : 1) - (b.role === "wan" ? 0 : 1) || a.name.localeCompare(b.name)),
    [ifaces],
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{editing ? `Edit policy — ${editing.name}` : "Add shaper policy"}</DialogTitle>
          <DialogDescription>
            Total egress budget, optional interface attachment and a creation-time template seed.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <EditorSection title="Identity & budget">
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <FieldLabel>Policy name</FieldLabel>
                <Input className="h-9 text-sm" value={form.name} onChange={(e) => set("name", e.currentTarget.value)} aria-label="Policy name" placeholder="e.g. WAN-SHAPER" />
                {err("name") && <p className="text-[11px] text-rose-500">{err("name")}</p>}
              </div>
              <div>
                <FieldLabel hint="units are kbps — 50 Mbps = 50000">Total bandwidth (kbps)</FieldLabel>
                <Input
                  type="number"
                  className="h-9 font-mono text-sm"
                  value={form.bandwidthKbps}
                  min={1000}
                  onChange={(e) => {
                    setBandwidthTouched(true);
                    set("bandwidthKbps", e.currentTarget.value);
                  }}
                  aria-label="Bandwidth kbps"
                />
                <p className="text-[11px] text-zinc-400">{bandwidth >= 1000 ? `≈ ${humanizeKbps(bandwidth)}` : "minimum 1000 kbps"}</p>
                {err("bandwidthKbps") && <p className="text-[11px] text-rose-500">{err("bandwidthKbps")}</p>}
              </div>
            </div>
          </EditorSection>

          <EditorSection title="Template (creation-time seed)">
            <div>
              <FieldLabel hint={editing ? "informational after create" : "seeds starter rules"}>Template</FieldLabel>
              <Select
                value={form.template ?? "custom"}
                onValueChange={(v) => {
                  const t = v as QosTemplateName;
                  set("template", t);
                  if (editing) setTemplateChanged(true);
                  if (!editing && !bandwidthTouched) {
                    set("bandwidthKbps", String(QOS_TEMPLATES[t].defaultBandwidthKbps));
                  }
                }}
              >
                <SelectTrigger className="h-9 text-sm"><SelectValue placeholder="pick a template" /></SelectTrigger>
                <SelectContent>
                  {(Object.keys(QOS_TEMPLATES) as QosTemplateName[]).map((t) => (
                    <SelectItem key={t} value={t}>
                      {QOS_TEMPLATES[t].label} <span className="text-[10px] text-zinc-400">— {QOS_TEMPLATES[t].intent}</span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {editing && templateChanged && (
                <p className="mt-1.5 flex items-start gap-1.5 rounded-md bg-amber-500/10 px-2.5 py-2 text-[11px] text-amber-700 dark:text-amber-400">
                  <Icons.Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  Changing the template does not rewrite existing rules — seeding happens on create only (M08 §5.1).
                </p>
              )}
              {!editing && <div className="mt-2"><TemplateExplanationTable template={form.template} bandwidthKbps={bandwidth || 50_000} /></div>}
            </div>
          </EditorSection>

          <EditorSection title="Attachment">
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <FieldLabel hint="one enabled policy per interface">Interface</FieldLabel>
                <Select value={form.ifaceName} onValueChange={(v) => set("ifaceName", v)}>
                  <SelectTrigger className="h-9 text-sm"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">none — aggregate WAN egress</SelectItem>
                    {sortedIfaces.map((i) => (
                      <SelectItem key={i.id} value={i.name}>
                        {i.name} <span className="text-[10px] text-zinc-400">({i.role}{i.enabled ? "" : ", disabled"})</span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {err("ifaceName") && <p className="text-[11px] text-rose-500">{err("ifaceName")}</p>}
              </div>
              <div className="flex items-end pb-1">
                <Label className="flex w-full cursor-pointer items-center justify-between gap-3 text-xs font-medium text-zinc-700 dark:text-zinc-300">
                  Enabled
                  <Switch checked={form.enabled} onCheckedChange={(v) => set("enabled", v)} aria-label="Toggle policy enabled" />
                </Label>
              </div>
            </div>
          </EditorSection>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={() => save.mutate()} disabled={save.isPending} className="bg-red-700 text-white hover:bg-red-800">
            {save.isPending ? "Saving…" : editing ? "Save changes" : "Create policy"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── rule editor dialog ──────────────────────────────────────────────────────

interface RulePrefill {
  mode: "user" | "app";
}

type RuleForm = {
  name: string;
  priority: number;
  guaranteedKbps: string; // "" = unset
  maxKbps: string; // "" = unset
  dscpMode: string; // "none" | well-known value | "custom"
  dscpCustom: string;
  matchApps: string[];
  matchUsers: string[];
  matchAddresses: string[];
};

const DSCP_CUSTOM = "custom";

function dscpModeOf(mark: number | null): string {
  if (mark == null) return "none";
  return String(mark);
}

function ruleFormFrom(r: QosRuleDTO | null, prefill: RulePrefill | null): RuleForm {
  const wellKnown = r?.dscpMark != null && [46, 34, 32, 26, 24, 18, 8, 0].includes(r.dscpMark);
  return {
    name: r?.name ?? (prefill?.mode === "user" ? "Limit user" : prefill?.mode === "app" ? "Limit application" : ""),
    priority: r?.priority ?? (prefill ? 5 : 4),
    guaranteedKbps: r?.guaranteedKbps != null ? String(r.guaranteedKbps) : "",
    maxKbps: r?.maxKbps != null ? String(r.maxKbps) : prefill ? "5000" : "",
    dscpMode: r == null ? "none" : wellKnown ? dscpModeOf(r.dscpMark) : r.dscpMark != null ? DSCP_CUSTOM : "none",
    dscpCustom: r?.dscpMark != null && !wellKnown ? String(r.dscpMark) : "",
    matchApps: r?.matchApps ?? [],
    matchUsers: r?.matchUsers ?? [],
    matchAddresses: r?.matchAddresses ?? [],
  };
}

function RuleDialog({
  open,
  onOpenChange,
  policy,
  editing,
  prefill,
  onSaved,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  policy: QosPolicyDTO;
  editing: QosRuleDTO | null;
  prefill: RulePrefill | null;
  onSaved: () => void;
}) {
  const apps = useQuery({ queryKey: ["qos", "apps"], queryFn: listApps, enabled: open, staleTime: 5 * 60_000 });
  const users = useQuery({ queryKey: ["qos", "users-meta"], queryFn: listUsers, enabled: open, staleTime: 60_000 });
  const addresses = useQuery({ queryKey: ["qos", "addresses-meta"], queryFn: listAddresses, enabled: open, staleTime: 60_000 });

  const [form, setForm] = useState(() => ruleFormFrom(editing, prefill));
  const [serverErrors, setServerErrors] = useState<Record<string, string[]>>({});

  const seedKey = `${editing?.id ?? "new"}:${prefill?.mode ?? "plain"}:${policy.id}`;
  const [lastKey, setLastKey] = useState(seedKey);
  if (seedKey !== lastKey) {
    setLastKey(seedKey);
    setServerErrors({});
    setForm(ruleFormFrom(editing, prefill));
  }

  const set = <K extends keyof RuleForm>(k: K, v: RuleForm[K]) => setForm((f) => ({ ...f, [k]: v }));
  const guaranteed = form.guaranteedKbps === "" ? null : Number(form.guaranteedKbps);
  const max = form.maxKbps === "" ? null : Number(form.maxKbps);
  const invalidPair = guaranteed != null && max != null && guaranteed > max;
  const overBudget = guaranteed != null && guaranteed > policy.bandwidthKbps;
  const previewHardLimit =
    form.matchAddresses.length === 0 &&
    max != null &&
    guaranteed == null &&
    (form.matchUsers.length > 0 ? form.matchApps.length === 0 : form.matchApps.length > 0);

  const appOptions = useMemo(() => (apps.data ?? []).map((a) => ({ id: a, label: a })), [apps.data]);
  const userOptions = useMemo(() => (users.data ?? []).map((u) => ({ id: String(u.id), label: u.username, sub: u.role })), [users.data]);
  const addrOptions = useMemo(() => (addresses.data ?? []).map((a: AddressLite) => ({ id: String(a.id), label: a.name, sub: a.value })), [addresses.data]);
  const dscpCustomInvalid = form.dscpMode === DSCP_CUSTOM && !(Number(form.dscpCustom) >= 0 && Number(form.dscpCustom) <= 63);

  const save = useMutation({
    mutationFn: () => {
      const dscpMark =
        form.dscpMode === "none" ? null : form.dscpMode === DSCP_CUSTOM ? Number(form.dscpCustom) : Number(form.dscpMode);
      const body: Record<string, unknown> = {
        name: form.name.trim(),
        priority: form.priority,
        guaranteedKbps: guaranteed,
        maxKbps: max,
        dscpMark,
        matchApps: form.matchApps,
        matchUsers: form.matchUsers,
        matchAddresses: form.matchAddresses,
      };
      if (editing) return qosApi.updateRule(editing.id, body);
      body.policyId = policy.id;
      return qosApi.createRule(body);
    },
    onSuccess: () => {
      toastOk(editing ? "Rule updated" : "Rule created");
      onSaved();
    },
    onError: (err) => {
      setServerErrors(fieldErrorsOf(err));
      toastErr(err, "Save failed");
    },
  });

  const err = (path: string) => serverErrors[path]?.join("; ");
  const canSave =
    form.name.trim().length > 0 && !invalidPair && !overBudget && !dscpCustomInvalid && !(form.dscpMode === DSCP_CUSTOM && form.dscpCustom === "");

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            {editing ? `Edit rule — ${editing.name}` : prefill ? (prefill.mode === "user" ? "Add hard limit — user" : "Add hard limit — application") : "Add rule"}
            {previewHardLimit && <HardLimitBadge />}
          </DialogTitle>
          <DialogDescription>
            {prefill
              ? "Hard limit class: pick exactly one matcher dimension, set maxKbps and leave guaranteed empty (spec §1.11)."
              : `Class in ${policy.name} — priority ${form.priority}, order = priority asc, ties by creation order.`}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <EditorSection title="Class">
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <FieldLabel>Rule name</FieldLabel>
                <Input className="h-9 text-sm" value={form.name} onChange={(e) => set("name", e.currentTarget.value)} aria-label="Rule name" placeholder={prefill?.mode === "user" ? "e.g. cap-j.tanaka" : "e.g. VOIP-PRIORITY"} />
                {err("name") && <p className="text-[11px] text-rose-500">{err("name")}</p>}
              </div>
              <div>
                <FieldLabel hint="sum of max rates may exceed the budget (multiplexing)">Max kbps</FieldLabel>
                <Input
                  type="number"
                  className="h-9 font-mono text-sm"
                  min={0}
                  value={form.maxKbps}
                  onChange={(e) => set("maxKbps", e.currentTarget.value)}
                  aria-label="Max kbps"
                  placeholder="unlimited"
                />
                {err("maxKbps") && <p className="text-[11px] text-rose-500">{err("maxKbps")}</p>}
              </div>
            </div>
            <div>
              <FieldLabel hint="0 = highest precedence; ties break by creation order">Priority — {form.priority}</FieldLabel>
              <Slider
                min={0}
                max={7}
                step={1}
                value={[form.priority]}
                onValueChange={(v) => set("priority", v[0] ?? form.priority)}
                aria-label="Priority"
              />
              <div className="mt-1 flex justify-between font-mono text-[10px] text-zinc-400">
                {[0, 1, 2, 3, 4, 5, 6, 7].map((n) => (
                  <span key={n}>{n}</span>
                ))}
              </div>
              {err("priority") && <p className="text-[11px] text-rose-500">{err("priority")}</p>}
            </div>
            <div>
              <FieldLabel hint="optional — reserved share of the budget">Guaranteed kbps</FieldLabel>
              <Input
                type="number"
                className="h-9 font-mono text-sm"
                min={0}
                value={form.guaranteedKbps}
                onChange={(e) => set("guaranteedKbps", e.currentTarget.value)}
                aria-label="Guaranteed kbps"
                placeholder="none"
              />
              {invalidPair ? (
                <p className="text-[11px] text-rose-500">guaranteedKbps ({guaranteed}) must be ≤ maxKbps ({max})</p>
              ) : overBudget ? (
                <p className="text-[11px] text-rose-500">exceeds the policy budget of {humanizeKbps(policy.bandwidthKbps)}</p>
              ) : (
                guaranteed != null && <p className="text-[11px] text-zinc-400">{humanizeKbps(guaranteed)} of {humanizeKbps(policy.bandwidthKbps)}</p>
              )}
              {err("guaranteedKbps") && <p className="text-[11px] text-rose-500">{err("guaranteedKbps")}</p>}
            </div>
          </EditorSection>

          <EditorSection title="DSCP mark">
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <FieldLabel hint="well-known table (M08 §4)">Mark</FieldLabel>
                <Select value={form.dscpMode} onValueChange={(v) => set("dscpMode", v)}>
                  <SelectTrigger className="h-9 text-sm"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">none — no marking</SelectItem>
                    {DSCP_WELL_KNOWN.map((d) => (
                      <SelectItem key={d.value} value={String(d.value)}>
                        {d.name} · {d.value} <span className="text-[10px] text-zinc-400">— {d.use}</span>
                      </SelectItem>
                    ))}
                    <SelectItem value={DSCP_CUSTOM}>Custom… (0–63)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              {form.dscpMode === DSCP_CUSTOM && (
                <div>
                  <FieldLabel hint="0–63">Custom DSCP value</FieldLabel>
                  <Input
                    type="number"
                    className="h-9 font-mono text-sm"
                    min={0}
                    max={63}
                    value={form.dscpCustom}
                    onChange={(e) => set("dscpCustom", e.currentTarget.value)}
                    aria-label="Custom DSCP value"
                  />
                  {dscpCustomInvalid && <p className="text-[11px] text-rose-500">DSCP mark must be 0-63</p>}
                </div>
              )}
            </div>
          </EditorSection>

          <EditorSection title="Matchers (empty dimension = wildcard)">
            <div className="space-y-3">
              <div>
                <FieldLabel hint="nDPI labels">Applications</FieldLabel>
                <PopoverMulti
                  options={appOptions}
                  selected={form.matchApps}
                  onChange={(next) => set("matchApps", next)}
                  placeholder="Filter apps…"
                  triggerLabel="Apps"
                  icon={<Icons.AppWindow className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />}
                />
                {err("matchApps") && <p className="text-[11px] text-rose-500">{err("matchApps")}</p>}
              </div>
              <div>
                <FieldLabel hint="single dimension + maxKbps = hard limit">Users</FieldLabel>
                <PopoverMulti
                  options={userOptions}
                  selected={form.matchUsers}
                  onChange={(next) => set("matchUsers", next)}
                  placeholder="Filter users…"
                  triggerLabel="Users"
                  icon={<Icons.User className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />}
                />
                {err("matchUsers") && <p className="text-[11px] text-rose-500">{err("matchUsers")}</p>}
              </div>
              <div>
                <FieldLabel hint="address objects (groups not selectable here)">Addresses</FieldLabel>
                <PopoverMulti
                  options={addrOptions}
                  selected={form.matchAddresses}
                  onChange={(next) => set("matchAddresses", next)}
                  placeholder="Filter addresses…"
                  triggerLabel="Addresses"
                  icon={<Icons.MapPin className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />}
                />
                {err("matchAddresses") && <p className="text-[11px] text-rose-500">{err("matchAddresses")}</p>}
              </div>
              {previewHardLimit && (
                <p className="rounded-md bg-rose-600/10 px-2.5 py-2 text-[11px] text-rose-600 dark:text-rose-400">
                  Hard limit class — traffic of the matched {form.matchUsers.length > 0 ? "user(s)" : "application(s)"} is clamped at{" "}
                  {humanizeKbps(max ?? 0)} regardless of spare capacity.
                </p>
              )}
              {form.matchApps.length === 0 && form.matchUsers.length === 0 && form.matchAddresses.length === 0 && (
                <p className="rounded-md bg-zinc-50 px-2.5 py-2 text-[11px] text-zinc-500 dark:bg-zinc-800/60">
                  No matchers — this becomes the catch-all class (&quot;Any traffic&quot;); only one is allowed per policy.
                </p>
              )}
            </div>
          </EditorSection>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={() => save.mutate()} disabled={save.isPending || !canSave} className="bg-red-700 text-white hover:bg-red-800">
            {save.isPending ? "Saving…" : editing ? "Save changes" : "Create rule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
