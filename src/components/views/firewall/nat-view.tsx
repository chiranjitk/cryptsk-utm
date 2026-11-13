"use client";

/**
 * #/firewall/nat — ordered NAT table (M03 §4): snat/dnat/hairpin/exempt with
 * translation summaries, optimistic toggle + dnd-kit reorder, the 1:1 static
 * NAT helper (POST /nat-rules {oneToOne}) and the port-forward helper that
 * optionally emits a matching allow firewall rule.
 */

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  DndContext,
  KeyboardSensor,
  PointerSensor,
  closestCenter,
  useSensor,
  useSensors,
  type DragEndEvent,
} from "@dnd-kit/core";
import {
  SortableContext,
  arrayMove,
  sortableKeyboardCoordinates,
  useSortable,
  verticalListSortingStrategy,
} from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
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
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { isValidPortList } from "@/lib/validators/firewall";
import { poolRange } from "@/lib/firewall/nft-gen";
import {
  api,
  IPV4_RE,
  fmtDateTime,
  isOneToOnePair,
  type AddressObject,
  type LoggingLevel,
  type NamedWithMembers,
  type NatRule,
  type NatRuleBody,
  type NatType,
  type ServiceObject,
  type Zone,
} from "./fw-api";
import { FirewallOsSync } from "./os-apply";
import {
  ConfirmDialog,
  EditorSection,
  EmptyBlock,
  FieldLabel,
  NatTypeChip,
  ObjectPicker,
  QueryError,
  TableSkeleton,
  toastErr,
  toastOk,
  useFwConfigInvalidation,
} from "./fw-ui";

const NAT_KEY = ["nat", "rules"] as const;

function translationSummary(r: NatRule): string {
  switch (r.type) {
    case "snat": {
      // seed rows may carry "masq" in translatedDst; canonical form is translatedSrc
      if (r.translatedSrc === "masq" || r.translatedDst === "masq") return "→ masquerade";
      const pool = r.translatedSrcPool.filter((p): p is string => typeof p === "string");
      if (pool.length > 0) return `→ pool ${pool.join(", ")}${r.overload ? " · PAT" : ""}`;
      if (r.translatedSrc) return `→ ${r.translatedSrc}`;
      return "—";
    }
    case "dnat":
    case "hairpin": {
      if (!r.translatedDst) return "—";
      const suffix = r.translatedPort != null ? `:${r.translatedPort}` : r.translatedPortRange ? ` ports ${r.translatedPortRange}` : "";
      const ext = r.translatedPort != null ? `${r.translatedPort} ` : r.translatedPortRange ? `${r.translatedPortRange} ` : "";
      return `${ext}→ ${r.translatedDst}${suffix}`;
    }
    case "exempt":
      return "no translation";
  }
}

interface NatForm {
  name: string;
  type: NatType;
  srcAddrIds: number[];
  dstAddrIds: number[];
  serviceIds: number[];
  outgoingIface: string;
  snatMode: "masq" | "ip" | "pool";
  translatedSrcIp: string;
  poolRaw: string;
  overload: boolean;
  translatedDst: string;
  hairpinTranslatedSrc: string;
  portMode: "single" | "range";
  translatedPort: string;
  translatedPortRange: string;
  logging: LoggingLevel;
  comment: string;
}

function formFromRule(r: NatRule | null): NatForm {
  if (!r) {
    return {
      name: "",
      type: "snat",
      srcAddrIds: [],
      dstAddrIds: [],
      serviceIds: [],
      outgoingIface: "",
      snatMode: "masq",
      translatedSrcIp: "",
      poolRaw: "",
      overload: true,
      translatedDst: "",
      hairpinTranslatedSrc: "",
      portMode: "single",
      translatedPort: "",
      translatedPortRange: "",
      logging: "none",
      comment: "",
    };
  }
  const pool = r.translatedSrcPool.filter((p): p is string => typeof p === "string");
  let snatMode: NatForm["snatMode"] = "ip";
  if (r.translatedSrc === "masq" || r.translatedDst === "masq") snatMode = "masq";
  else if (pool.length > 0) snatMode = "pool";
  else if (r.translatedSrc) snatMode = "ip";
  else snatMode = "masq";
  return {
    name: r.name ?? "",
    type: r.type,
    srcAddrIds: [...r.srcAddrIds],
    dstAddrIds: [...r.dstAddrIds],
    serviceIds: [...r.serviceIds],
    outgoingIface: r.outgoingIface ?? "",
    snatMode,
    translatedSrcIp: r.translatedSrc && r.translatedSrc !== "masq" ? r.translatedSrc : "",
    poolRaw: pool.join(", "),
    overload: r.overload,
    translatedDst: r.translatedDst ?? "",
    hairpinTranslatedSrc: r.translatedSrc && r.translatedSrc !== "masq" ? r.translatedSrc : "",
    portMode: r.translatedPortRange ? "range" : "single",
    translatedPort: r.translatedPort == null ? "" : String(r.translatedPort),
    translatedPortRange: r.translatedPortRange ?? "",
    logging: r.logging,
    comment: r.comment ?? "",
  };
}

function buildNatBody(f: NatForm): NatRuleBody {
  const base: NatRuleBody = {
    name: f.name.trim() || null,
    enabled: true,
    type: f.type,
    srcAddrIds: f.srcAddrIds,
    dstAddrIds: f.dstAddrIds,
    serviceIds: f.serviceIds,
    outgoingIface: f.outgoingIface.trim() || null,
    translatedSrc: null,
    translatedSrcPool: [],
    overload: f.overload,
    translatedDst: null,
    translatedPort: null,
    translatedPortRange: null,
    logging: f.logging,
    comment: f.comment.trim() || null,
  };
  if (f.type === "snat") {
    if (f.snatMode === "masq") base.translatedSrc = "masq";
    else if (f.snatMode === "ip") base.translatedSrc = f.translatedSrcIp.trim();
    else base.translatedSrcPool = f.poolRaw.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
  }
  if (f.type === "dnat" || f.type === "hairpin") {
    base.translatedDst = f.translatedDst.trim() || null;
    if (f.portMode === "single") {
      const p = Number(f.translatedPort);
      base.translatedPort = f.translatedPort.trim() && Number.isFinite(p) ? p : null;
    } else {
      base.translatedPortRange = f.translatedPortRange.trim() || null;
    }
  }
  if (f.type === "hairpin") base.translatedSrc = f.hairpinTranslatedSrc.trim() || null;
  return base;
}

function validateNatForm(f: NatForm): string | null {
  if (!f.name.trim()) return "Name is required";
  if (f.type === "snat") {
    if (f.snatMode === "ip" && !IPV4_RE.test(f.translatedSrcIp.trim())) return "translatedSrc must be a valid IPv4";
    if (f.snatMode === "pool") {
      const ips = f.poolRaw.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
      if (ips.length < 2 || ips.length > 16) return "NAT pool accepts 2–16 IPv4 addresses";
      if (ips.some((ip) => !IPV4_RE.test(ip))) return "Pool contains an invalid IPv4";
    }
  }
  if (f.type === "dnat" || f.type === "hairpin") {
    if (!IPV4_RE.test(f.translatedDst.trim())) return "translatedDst must be a valid IPv4";
    if (f.type === "hairpin" && f.hairpinTranslatedSrc.trim() && !IPV4_RE.test(f.hairpinTranslatedSrc.trim()))
      return "hairpin translatedSrc must be a valid IPv4";
    if (f.portMode === "single" && f.translatedPort.trim()) {
      const p = Number(f.translatedPort);
      if (!Number.isInteger(p) || p < 1 || p > 65535) return "Translated port must be 1–65535";
    }
    if (f.portMode === "range" && f.translatedPortRange.trim() && !isValidPortList(f.translatedPortRange.trim()))
      return "Port range must look like 80 or 5000-5100,6000";
  }
  return null;
}

export function NatView() {
  useFwConfigInvalidation();
  const queryClient = useQueryClient();

  const natQuery = useQuery({ queryKey: NAT_KEY, queryFn: api.listNat });
  const addrQuery = useQuery({ queryKey: ["firewall", "objects", "address"], queryFn: api.listAddressObjects });
  const addrGrpQuery = useQuery({ queryKey: ["firewall", "objects", "address-groups"], queryFn: api.listAddressGroups });
  const svcQuery = useQuery({ queryKey: ["firewall", "objects", "service"], queryFn: api.listServiceObjects });
  const svcGrpQuery = useQuery({ queryKey: ["firewall", "objects", "service-groups"], queryFn: api.listServiceGroups });
  const zonesQuery = useQuery({ queryKey: ["firewall", "zones"], queryFn: api.listZones });

  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<NatRule | null>(null);
  const [duplicateSeed, setDuplicateSeed] = useState<NatRule | null>(null);
  const [deleting, setDeleting] = useState<NatRule | null>(null);
  const [oneToOneOpen, setOneToOneOpen] = useState(false);
  const [portFwdOpen, setPortFwdOpen] = useState(false);
  const [filter, setFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState<"all" | NatType>("all");

  const allRules = useMemo(() => natQuery.data?.data ?? [], [natQuery.data]);
  const rules = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return allRules.filter((r) => {
      if (typeFilter !== "all" && r.type !== typeFilter) return false;
      if (!q) return true;
      return (
        (r.name ?? "").toLowerCase().includes(q) ||
        (r.comment ?? "").toLowerCase().includes(q) ||
        (r.outgoingIface ?? "").toLowerCase().includes(q) ||
        (r.translatedDst ?? "").toLowerCase().includes(q) ||
        (r.translatedSrc ?? "").toLowerCase().includes(q) ||
        r.translatedSrcPool.some((p) => p.toLowerCase().includes(q))
      );
    });
  }, [allRules, filter, typeFilter]);

  const addrMap = useMemo(() => {
    const m = new Map<number, { name: string; isGroup: boolean; count: number }>();
    (addrQuery.data?.data ?? []).forEach((a) => m.set(a.id, { name: a.name, isGroup: false, count: 0 }));
    (addrGrpQuery.data?.data ?? []).forEach((g) => m.set(g.id, { name: g.name, isGroup: true, count: g.memberIds.length }));
    return m;
  }, [addrQuery.data, addrGrpQuery.data]);

  const svcMap = useMemo(() => {
    const m = new Map<number, string>();
    (svcQuery.data?.data ?? []).forEach((s) => m.set(s.id, `${s.protocol}${s.dstPort ? `/${s.dstPort}` : ""}`));
    (svcGrpQuery.data?.data ?? []).forEach((g) => m.set(g.id, `${g.name} +${g.memberIds.length}`));
    return m;
  }, [svcQuery.data, svcGrpQuery.data]);

  const ifaceNames = useMemo(() => {
    const set = new Set<string>();
    (zonesQuery.data?.data ?? []).forEach((z) => z.interfaceNames.forEach((n) => set.add(n)));
    return [...set].sort();
  }, [zonesQuery.data]);

  const toggleMut = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => api.toggleNat(id, enabled),
    onMutate: async ({ id, enabled }) => {
      await queryClient.cancelQueries({ queryKey: NAT_KEY });
      const prev = queryClient.getQueryData<{ data: NatRule[] }>(NAT_KEY);
      queryClient.setQueryData<{ data: NatRule[] }>(NAT_KEY, (old) =>
        old ? { ...old, data: old.data.map((r) => (r.id === id ? { ...r, enabled } : r)) } : old,
      );
      return { prev };
    },
    onError: (err, vars, ctx) => {
      if (ctx?.prev) queryClient.setQueryData(NAT_KEY, ctx.prev);
      toastErr(err, `Failed to ${vars.enabled ? "enable" : "disable"} NAT rule`);
    },
    onSettled: () => void queryClient.invalidateQueries({ queryKey: NAT_KEY }),
  });

  const reorderMut = useMutation({
    mutationFn: (next: NatRule[]) => api.reorderNat(next.map((r) => r.id)),
    onMutate: async (next) => {
      await queryClient.cancelQueries({ queryKey: NAT_KEY });
      const prev = queryClient.getQueryData<{ data: NatRule[] }>(NAT_KEY);
      queryClient.setQueryData<{ data: NatRule[] }>(NAT_KEY, (old) =>
        old ? { ...old, data: next.map((r, i) => ({ ...r, position: i + 1 })) } : old,
      );
      return { prev };
    },
    onError: (err, _vars, ctx) => {
      if (ctx?.prev) queryClient.setQueryData(NAT_KEY, ctx.prev);
      toastErr(err, "Reorder failed");
    },
    onSettled: () => void queryClient.invalidateQueries({ queryKey: NAT_KEY }),
  });

  const deleteMut = useMutation({
    mutationFn: (id: number) => api.deleteNat(id),
    onSuccess: () => {
      toastOk("NAT rule deleted");
      setDeleting(null);
    },
    onError: (err) => toastErr(err, "Delete failed"),
    onSettled: () => void queryClient.invalidateQueries({ queryKey: NAT_KEY }),
  });

  const resetHitsMut = useMutation({
    mutationFn: (id: number) => api.resetNatHits(id),
    onSuccess: () => {
      toastOk("Hit counters reset");
      setHitsMenuFor(null);
    },
    onError: (err) => toastErr(err, "Reset failed"),
    onSettled: () => void queryClient.invalidateQueries({ queryKey: NAT_KEY }),
  });

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 4 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }),
  );

  const [hitsMenuFor, setHitsMenuFor] = useState<number | null>(null);

  const onDragEnd = (e: DragEndEvent) => {
    const { active, over } = e;
    if (!over || active.id === over.id) return;
    const from = rules.findIndex((r) => r.id === active.id);
    const to = rules.findIndex((r) => r.id === over.id);
    if (from < 0 || to < 0) return;
    reorderMut.mutate(arrayMove(rules, from, to));
  };

  return (
    <div className="space-y-4">
      <FirewallOsSync />
      <div className="flex flex-wrap items-center gap-2">
        <p className="mr-auto text-xs text-zinc-500">
          NAT is evaluated before the firewall rules — dnat/hairpin rewrite first, exempt skips NAT, snat translates on the way out.
        </p>
        <Button size="sm" variant="outline" onClick={() => setPortFwdOpen(true)}>
          <Icons.ArrowRightToLine className="mr-1 h-4 w-4" /> Port forward
        </Button>
        <Button size="sm" variant="outline" onClick={() => setOneToOneOpen(true)}>
          <Icons.ArrowLeftRight className="mr-1 h-4 w-4" /> 1:1 NAT
        </Button>
        <Button
          size="sm"
          onClick={() => {
            setEditing(null);
            setEditorOpen(true);
          }}
          className="bg-zinc-700 text-white hover:bg-zinc-800"
        >
          <Icons.Plus className="mr-1 h-4 w-4" /> Add NAT rule
        </Button>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative">
          <Icons.Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-400" />
          <Input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter by name, comment, interface, IP…"
            className="h-8 w-64 pl-8 text-xs"
            aria-label="Filter NAT rules"
          />
        </div>
        <div className="flex flex-wrap gap-1">
          {(["all", "snat", "dnat", "hairpin", "exempt"] as const).map((t) => (
            <Button
              key={t}
              size="sm"
              variant={typeFilter === t ? "default" : "outline"}
              className={cn(
                "h-7 px-2.5 text-xs",
                typeFilter === t ? "bg-zinc-700 text-white hover:bg-zinc-800" : "text-zinc-600 dark:text-zinc-300",
              )}
              onClick={() => setTypeFilter(t)}
            >
              {t}
            </Button>
          ))}
        </div>
        {rules.length !== allRules.length && (
          <span className="text-[11px] text-zinc-400">
            {rules.length} of {allRules.length} rules
          </span>
        )}
      </div>

      <Card className="p-0">
        <CardContent className="p-0">
          {natQuery.error ? (
            <div className="p-4">
              <QueryError error={natQuery.error} onRetry={() => void natQuery.refetch()} />
            </div>
          ) : natQuery.isLoading ? (
            <div className="p-4">
              <TableSkeleton rows={5} cols={8} />
            </div>
          ) : rules.length === 0 ? (
            <EmptyBlock
              icon={<Icons.ArrowLeftRight className="h-6 w-6" />}
              title="No NAT rules yet"
              description="Without NAT, internal hosts cannot reach the internet through the WAN interfaces. Add a masquerade SNAT to get started."
              action={
                <Button onClick={() => setEditorOpen(true)} className="bg-zinc-700 text-white hover:bg-zinc-800">
                  <Icons.Plus className="mr-1 h-4 w-4" /> Add NAT rule
                </Button>
              }
            />
          ) : (
            <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={onDragEnd}>
              <div className="max-h-[70vh] overflow-auto [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-zinc-300 dark:[&::-webkit-scrollbar-thumb]:bg-zinc-700">
                <Table className="min-w-[980px] text-sm">
                  <TableHeader className="sticky top-0 z-10 bg-card">
                    <TableRow>
                      <TableHead className="w-10 pl-2" aria-label="Reorder" />
                      <TableHead className="w-10">#</TableHead>
                      <TableHead className="w-14">On</TableHead>
                      <TableHead>Name</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Match</TableHead>
                      <TableHead>Translation</TableHead>
                      <TableHead className="text-right">Hits</TableHead>
                      <TableHead className="w-10" aria-label="Actions" />
                    </TableRow>
                  </TableHeader>
                  <SortableContext items={rules.map((r) => r.id)} strategy={verticalListSortingStrategy}>
                    <TableBody>
                      {rules.map((r) => (
                        <SortableNatRow
                          key={r.id}
                          rule={r}
                          addrMap={addrMap}
                          svcMap={svcMap}
                          toggling={toggleMut.isPending}
                          onToggle={(rule) => toggleMut.mutate({ id: rule.id, enabled: !rule.enabled })}
                          onEdit={(rule) => {
                            setEditing(rule);
                            setEditorOpen(true);
                          }}
                          onDuplicate={(rule) => {
                            setEditing(null);
                            setDuplicateSeed(rule);
                            setEditorOpen(true);
                          }}
                          onDelete={(rule) => setDeleting(rule)}
                          onResetHits={(rule) => resetHitsMut.mutate(rule.id)}
                          resetHitsPending={resetHitsMut.isPending}
                        />
                      ))}
                    </TableBody>
                  </SortableContext>
                </Table>
              </div>
            </DndContext>
          )}
        </CardContent>
      </Card>

      {editorOpen && (
        <NatEditor
          open={editorOpen}
          onOpenChange={setEditorOpen}
          editing={editing}
          duplicateSeed={duplicateSeed}
          addresses={addrQuery.data?.data ?? []}
          addressGroups={addrGrpQuery.data?.data ?? []}
          services={svcQuery.data?.data ?? []}
          serviceGroups={svcGrpQuery.data?.data ?? []}
          ifaceNames={ifaceNames}
          onSaved={() => void queryClient.invalidateQueries({ queryKey: NAT_KEY })}
        />
      )}

      {oneToOneOpen && (
        <OneToOneDialog
          open={oneToOneOpen}
          onOpenChange={setOneToOneOpen}
          ifaceNames={ifaceNames}
          onSaved={() => void queryClient.invalidateQueries({ queryKey: NAT_KEY })}
        />
      )}

      {portFwdOpen && (
        <PortForwardDialog
          open={portFwdOpen}
          onOpenChange={setPortFwdOpen}
          zones={zonesQuery.data?.data ?? []}
          addresses={addrQuery.data?.data ?? []}
          services={svcQuery.data?.data ?? []}
          ifaceNames={ifaceNames}
          onSaved={() => {
            void queryClient.invalidateQueries({ queryKey: NAT_KEY });
            void queryClient.invalidateQueries({ queryKey: ["firewall", "rules"] });
            void queryClient.invalidateQueries({ queryKey: ["firewall", "objects", "service"] });
          }}
        />
      )}

      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title="Delete NAT rule?"
        description={`Delete NAT rule '${deleting?.name ?? `#${deleting?.id ?? ""}`}'? Remaining rules are renumbered densely.`}
        loading={deleteMut.isPending}
        onConfirm={() => deleting && deleteMut.mutate(deleting.id)}
      />
    </div>
  );
}

function SortableNatRow(props: {
  rule: NatRule;
  addrMap: Map<number, { name: string; isGroup: boolean; count: number }>;
  svcMap: Map<number, string>;
  toggling: boolean;
  onToggle: (r: NatRule) => void;
  onEdit: (r: NatRule) => void;
  onDuplicate: (r: NatRule) => void;
  onDelete: (r: NatRule) => void;
  onResetHits: (r: NatRule) => void;
  resetHitsPending: boolean;
}) {
  const { rule: r } = props;
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({ id: r.id });

  const addrChips = (ids: number[]) =>
    ids.length === 0 ? (
      <span className="text-xs text-zinc-400">any</span>
    ) : (
      <div className="flex flex-wrap gap-1">
        {ids.map((id) => {
          const info = props.addrMap.get(id);
          return (
            <Badge
              key={id}
              variant="outline"
              className={cn(
                "max-w-32 truncate font-normal",
                info?.isGroup
                  ? "border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300"
                  : "border-zinc-300 text-zinc-600 dark:border-zinc-700 dark:text-zinc-300",
              )}
            >
              {info ? (info.isGroup ? `${info.name} +${info.count}` : info.name) : `#${id}`}
            </Badge>
          );
        })}
      </div>
    );

  return (
    <TableRow
      ref={setNodeRef}
      style={{ transform: CSS.Transform.toString(transform), transition }}
      className={cn(!r.enabled && "opacity-55", isDragging && "z-50 relative bg-zinc-500/5")}
    >
      <TableCell className="w-10 pl-2 pr-0">
        <button
          type="button"
          aria-label={`Reorder ${r.name ?? r.id}`}
          className="cursor-grab touch-none rounded p-1 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-600 dark:hover:bg-zinc-800"
          {...attributes}
          {...listeners}
        >
          <Icons.GripVertical className="h-4 w-4" />
        </button>
      </TableCell>
      <TableCell className="w-10 tabular-nums text-zinc-500">{r.position}</TableCell>
      <TableCell className="w-14">
        <Switch
          checked={r.enabled}
          disabled={props.toggling}
          aria-label={`Toggle NAT rule ${r.name ?? r.id}`}
          onCheckedChange={() => props.onToggle(r)}
        />
      </TableCell>
      <TableCell className="min-w-40">
        <span className="block max-w-48 truncate text-sm font-medium">{r.name ?? `#${r.id}`}</span>
        {isOneToOnePair(r.comment) && (
          <Badge variant="outline" className="mt-0.5 border-zinc-500/30 bg-zinc-500/10 text-[10px] text-zinc-600 dark:text-zinc-300">
            <Icons.Link2 className="mr-1 h-3 w-3" /> 1:1 pair
          </Badge>
        )}
      </TableCell>
      <TableCell>
        <NatTypeChip type={r.type} />
      </TableCell>
      <TableCell className="min-w-64">
        <div className="flex flex-wrap items-center gap-1 text-xs">
          {addrChips(r.srcAddrIds)}
          <Icons.ArrowRight className="h-3 w-3 text-zinc-400" />
          {addrChips(r.dstAddrIds)}
          {r.serviceIds.length > 0 && (
            <span className="ml-1 flex flex-wrap items-center gap-1">
              <span className="text-zinc-300">·</span>
              {r.serviceIds.map((id) => (
                <Badge key={id} variant="outline" className="border-zinc-300 font-normal text-zinc-600 dark:border-zinc-700 dark:text-zinc-300">
                  {props.svcMap.get(id) ?? `#${id}`}
                </Badge>
              ))}
            </span>
          )}
          {r.outgoingIface && (
            <span className="ml-1 flex items-center gap-1 text-zinc-400">
              <span className="text-zinc-300">·</span>
              <span className="font-mono">{r.outgoingIface}</span>
            </span>
          )}
        </div>
      </TableCell>
      <TableCell className="min-w-40">
        <TooltipProvider delayDuration={150}>
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="block max-w-56 truncate font-mono text-xs">{translationSummary(r)}</span>
            </TooltipTrigger>
            <TooltipContent className="font-mono text-xs">{translationSummary(r)}</TooltipContent>
          </Tooltip>
        </TooltipProvider>
      </TableCell>
      <TableCell className="text-right tabular-nums">
        <TooltipProvider delayDuration={150}>
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="cursor-default">{r.hitCount.toLocaleString()}</span>
            </TooltipTrigger>
            <TooltipContent className="text-xs">
              {r.hitCount > 0 ? `last hit ${fmtDateTime(r.lastHitAt)}` : "no hits yet — sync from kernel (Apply to Host → sync-hits)"}
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      </TableCell>
      <TableCell className="w-10 pr-2">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={`Actions for ${r.name ?? "NAT rule"}`}>
              <Icons.EllipsisVertical className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-44">
            <DropdownMenuItem onClick={() => props.onEdit(r)}>
              <Icons.Pencil className="mr-2 h-4 w-4" /> Edit
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => props.onDuplicate(r)}>
              <Icons.Copy className="mr-2 h-4 w-4" /> Duplicate
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={() => props.onResetHits(r)}
              disabled={props.resetHitsPending || r.hitCount === 0}
            >
              <Icons.RotateCcw className="mr-2 h-4 w-4" /> Reset hit counters
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={() => props.onDelete(r)} className="text-rose-600 focus:text-rose-600 dark:text-rose-400">
              <Icons.Trash2 className="mr-2 h-4 w-4" /> Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </TableCell>
    </TableRow>
  );
}

function NatEditor(props: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editing: NatRule | null;
  duplicateSeed: NatRule | null;
  addresses: AddressObject[];
  addressGroups: NamedWithMembers[];
  services: ServiceObject[];
  serviceGroups: NamedWithMembers[];
  ifaceNames: string[];
  onSaved: () => void;
}) {
  const { editing } = props;
  const base = editing ?? props.duplicateSeed;
  const [form, setForm] = useState<NatForm>(() => {
    const f = formFromRule(base);
    if (!editing && props.duplicateSeed) f.name = `${props.duplicateSeed.name ?? "nat-rule"}-copy`;
    return f;
  });
  const [error, setError] = useState<string | null>(null);
  const [validation, setValidation] = useState<{
    conflicts: Array<{ reason: string; withRuleName: string; leg?: string }>;
    warnings: Array<{ code: string; message: string }>;
    blocking: boolean;
  } | null>(null);

  const set = <K extends keyof NatForm>(key: K, value: NatForm[K]) => {
    setForm((prev) => ({ ...prev, [key]: value }));
    setValidation(null); // stale once any field changes
  };

  /** contiguous pools compile to a kernel round-robin range; gapped pools are
   *  excluded from enforcement — surface that BEFORE saving, not at apply. */
  const poolAdvisory = useMemo(() => {
    if (form.type !== "snat" || form.snatMode !== "pool") return null;
    const ips = form.poolRaw.split(/[,\s]+/).map((s) => s.trim()).filter((s) => IPV4_RE.test(s));
    if (ips.length < 2) return null;
    const range = poolRange(ips);
    return range ? `Contiguous pool ${range.lo}–${range.hi} — enforced as a kernel round-robin range.` : "Non-contiguous pool — nftables cannot express it as one statement; this rule will be EXCLUDED from enforcement. Use consecutive addresses (e.g. .5–.10).";
  }, [form.type, form.snatMode, form.poolRaw]);

  const addrPickerObjects = useMemo(
    () => props.addresses.map((a) => ({ id: a.id, name: a.name, sub: a.value })),
    [props.addresses],
  );
  const addrPickerGroups = useMemo(
    () => props.addressGroups.map((g) => ({ id: g.id, name: g.name, memberCount: g.memberIds.length })),
    [props.addressGroups],
  );
  const svcPickerObjects = useMemo(
    () => props.services.map((s) => ({ id: s.id, name: s.name, sub: s.dstPort ?? s.protocol })),
    [props.services],
  );
  const svcPickerGroups = useMemo(
    () => props.serviceGroups.map((g) => ({ id: g.id, name: g.name, memberCount: g.memberIds.length })),
    [props.serviceGroups],
  );

  const saveMut = useMutation({
    mutationFn: async () => {
      const body = buildNatBody(form);
      if (editing) return api.updateNat(editing.id, body);
      return api.createNat(body);
    },
    onSuccess: () => {
      toastOk(editing ? "NAT rule updated" : "NAT rule created", form.name.trim());
      props.onSaved();
      props.onOpenChange(false);
    },
    onError: (err) => toastErr(err, editing ? "Update failed" : "Create failed"),
  });

  // validate-then-save: shadow/conflict detection + generator-faithful
  // advisories — a shadowed NAT rule silently never fires in the kernel
  const validateMut = useMutation({
    mutationFn: async () => {
      const body = buildNatBody(form);
      return api.validateNat(body, editing?.id);
    },
  });

  const submit = async () => {
    const v = validateNatForm(form);
    if (v) {
      setError(v);
      return;
    }
    setError(null);
    try {
      const res = await validateMut.mutateAsync();
      const blocking = res.conflicts.filter((c) => c.reason !== "redundant");
      setValidation({
        conflicts: res.conflicts,
        warnings: res.warnings ?? [],
        blocking: blocking.length > 0,
      });
      if (blocking.length > 0) return; // operator must fix the shadow first
    } catch {
      // validator unavailable → save anyway (server still enforces integrity)
    }
    saveMut.mutate();
  };

  return (
    <Dialog open onOpenChange={props.onOpenChange}>
      <DialogContent className="max-h-[90vh] w-[calc(100vw-1rem)] max-w-2xl overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>
            {editing ? `Edit NAT rule — ${editing.name ?? `#${editing.id}`}` : props.duplicateSeed ? "Duplicate NAT rule" : "Add NAT rule"}
          </DialogTitle>
          <DialogDescription>
            {form.type === "hairpin"
              ? "Hairpin NAT serves LAN clients reaching a DNAT'd public IP from inside."
              : form.type === "exempt"
                ? "Exempt NAT is identity NAT — matching traffic skips all translation."
                : "Match dimensions are optional wildcards."}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <EditorSection title="General">
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <Label htmlFor="nat-name" className="text-xs font-medium">
                  Name
                </Label>
                <Input id="nat-name" value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="MASQ_LAN_WAN" className="mt-1.5" />
              </div>
              <div>
                <FieldLabel hint={editing ? "changing type resets the translation fields" : undefined}>Type</FieldLabel>
                <Select
                  value={form.type}
                  onValueChange={(v) => {
                    const next = v as NatType;
                    setForm((prev) => ({
                      ...prev,
                      type: next,
                      // reset translation fields that belong to other types
                      snatMode: "masq",
                      translatedSrcIp: "",
                      poolRaw: "",
                      translatedDst: "",
                      hairpinTranslatedSrc: "",
                      portMode: "single",
                      translatedPort: "",
                      translatedPortRange: "",
                    }));
                    setValidation(null);
                  }}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="snat">snat — source NAT</SelectItem>
                    <SelectItem value="dnat">dnat — destination NAT</SelectItem>
                    <SelectItem value="hairpin">hairpin — loopback NAT</SelectItem>
                    <SelectItem value="exempt">exempt — no translation</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </EditorSection>

          <EditorSection title="Match">
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <FieldLabel>Source addresses / groups</FieldLabel>
                <ObjectPicker
                  kind="address"
                  objects={addrPickerObjects}
                  groups={addrPickerGroups}
                  value={form.srcAddrIds}
                  onChange={(v) => set("srcAddrIds", v)}
                  triggerLabel="Pick source"
                />
              </div>
              <div>
                <FieldLabel>Destination addresses / groups</FieldLabel>
                <ObjectPicker
                  kind="address"
                  objects={addrPickerObjects}
                  groups={addrPickerGroups}
                  value={form.dstAddrIds}
                  onChange={(v) => set("dstAddrIds", v)}
                  triggerLabel="Pick destination"
                />
              </div>
              <div>
                <FieldLabel>Services / service groups</FieldLabel>
                <ObjectPicker
                  kind="service"
                  objects={svcPickerObjects}
                  groups={svcPickerGroups}
                  value={form.serviceIds}
                  onChange={(v) => set("serviceIds", v)}
                  triggerLabel="Pick services"
                />
              </div>
              <div>
                <FieldLabel hint="egress interface name">Outgoing interface</FieldLabel>
                <Input
                  value={form.outgoingIface}
                  onChange={(e) => set("outgoingIface", e.target.value)}
                  placeholder="wan0"
                  list="nat-iface-names"
                  className="font-mono text-xs"
                />
                <datalist id="nat-iface-names">
                  {props.ifaceNames.map((n) => (
                    <option key={n} value={n} />
                  ))}
                </datalist>
              </div>
            </div>
          </EditorSection>

          {form.type === "snat" && (
            <EditorSection title="Translation (SNAT)">
              <RadioGroup value={form.snatMode} onValueChange={(v) => set("snatMode", v as NatForm["snatMode"])} className="flex flex-wrap gap-4">
                <Label className="flex cursor-pointer items-center gap-2 text-sm">
                  <RadioGroupItem value="masq" /> Masquerade
                </Label>
                <Label className="flex cursor-pointer items-center gap-2 text-sm">
                  <RadioGroupItem value="ip" /> Translated IP
                </Label>
                <Label className="flex cursor-pointer items-center gap-2 text-sm">
                  <RadioGroupItem value="pool" /> NAT pool
                </Label>
              </RadioGroup>
              {form.snatMode === "masq" && (
                <p className="rounded-md bg-zinc-500/10 px-3 py-2 text-xs text-zinc-700 dark:text-zinc-300">
                  Stores translatedSrc = <span className="font-mono">masq</span> — the egress interface address is used per flow.
                </p>
              )}
              {form.snatMode === "ip" && (
                <div>
                  <FieldLabel>Translated source IP</FieldLabel>
                  <Input
                    value={form.translatedSrcIp}
                    onChange={(e) => set("translatedSrcIp", e.target.value)}
                    placeholder="203.0.113.10"
                    className="font-mono text-xs"
                  />
                </div>
              )}
              {form.snatMode === "pool" && (
                <>
                  <div>
                    <FieldLabel hint="2–16 IPv4s, comma or newline separated">NAT pool addresses</FieldLabel>
                    <Textarea
                      value={form.poolRaw}
                      onChange={(e) => set("poolRaw", e.target.value)}
                      rows={2}
                      placeholder={"198.51.100.10, 198.51.100.11"}
                      className="font-mono text-xs"
                    />
                  </div>
                  {poolAdvisory && (
                    <p
                      className={cn(
                        "rounded-md px-3 py-2 text-xs",
                        poolAdvisory.includes("EXCLUDED")
                          ? "border border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400"
                          : "border border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
                      )}
                    >
                      {poolAdvisory}
                    </p>
                  )}
                  <div className="flex items-center justify-between rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
                    <div>
                      <p className="text-sm font-medium">Overload (PAT)</p>
                      <p className="text-[11px] text-zinc-500">Port-address translation across the pool; off = 1:1 rotation (kernel enforces PAT regardless)</p>
                    </div>
                    <Switch checked={form.overload} onCheckedChange={(v) => set("overload", v)} />
                  </div>
                </>
              )}
            </EditorSection>
          )}

          {(form.type === "dnat" || form.type === "hairpin") && (
            <EditorSection title="Translation (DNAT)">
              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <FieldLabel>Translated destination IP</FieldLabel>
                  <Input
                    value={form.translatedDst}
                    onChange={(e) => set("translatedDst", e.target.value)}
                    placeholder="172.16.20.5"
                    className="font-mono text-xs"
                  />
                </div>
                {form.type === "hairpin" && (
                  <div>
                    <FieldLabel hint="optional">Translated source IP</FieldLabel>
                    <Input
                      value={form.hairpinTranslatedSrc}
                      onChange={(e) => set("hairpinTranslatedSrc", e.target.value)}
                      placeholder="192.168.10.1"
                      className="font-mono text-xs"
                    />
                  </div>
                )}
              </div>
              <div>
                <FieldLabel>Port mode</FieldLabel>
                <RadioGroup value={form.portMode} onValueChange={(v) => set("portMode", v as NatForm["portMode"])} className="flex gap-4">
                  <Label className="flex cursor-pointer items-center gap-2 text-sm">
                    <RadioGroupItem value="single" /> Single port
                  </Label>
                  <Label className="flex cursor-pointer items-center gap-2 text-sm">
                    <RadioGroupItem value="range" /> Range list
                  </Label>
                </RadioGroup>
              </div>
              {form.portMode === "single" ? (
                <div className="max-w-48">
                  <FieldLabel hint="1–65535">Translated port</FieldLabel>
                  <Input
                    type="number"
                    value={form.translatedPort}
                    onChange={(e) => set("translatedPort", e.target.value)}
                    placeholder="80"
                  />
                </div>
              ) : (
                <div className="max-w-64">
                  <FieldLabel hint='"80" or "5000-5100,6000"'>Translated port range</FieldLabel>
                  <Input
                    value={form.translatedPortRange}
                    onChange={(e) => set("translatedPortRange", e.target.value)}
                    placeholder="5000-5100,6000"
                    className="font-mono text-xs"
                  />
                </div>
              )}
            </EditorSection>
          )}

          {form.type === "exempt" && (
            <p className="rounded-md bg-zinc-100 px-3 py-2 text-xs text-zinc-600 dark:bg-zinc-800 dark:text-zinc-300">
              Exempt NAT carries no translation fields — the rule only exempts matching flows from every other NAT rule.
            </p>
          )}

          <EditorSection title="Logging & comment">
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <FieldLabel hint="translation logging">Logging</FieldLabel>
                <Select value={form.logging} onValueChange={(v) => set("logging", v as LoggingLevel)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">none</SelectItem>
                    <SelectItem value="summary">summary</SelectItem>
                    <SelectItem value="detail">detail</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label htmlFor="nat-comment" className="text-xs font-medium">
                  Comment
                </Label>
                <Input id="nat-comment" value={form.comment} onChange={(e) => set("comment", e.target.value)} className="mt-1.5" />
              </div>
            </div>
          </EditorSection>

          {error && (
            <p className="rounded-md border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-600 dark:text-rose-400">{error}</p>
          )}

          {validation && validation.conflicts.length > 0 && (
            <div
              className={cn(
                "rounded-md border px-3 py-2 text-xs",
                validation.blocking
                  ? "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400"
                  : "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400",
              )}
            >
              <p className="font-medium">{validation.blocking ? "Save blocked — NAT conflicts:" : "NAT advisories (non-blocking):"}</p>
              <ul className="mt-1 list-disc pl-4">
                {validation.conflicts.map((c, i) => (
                  <li key={i}>
                    {c.reason.replace("_", " ")} by <span className="font-medium">{c.withRuleName}</span> ({c.leg} leg)
                  </li>
                ))}
              </ul>
            </div>
          )}
          {validation && validation.warnings.length > 0 && (
            <div className="rounded-md border border-zinc-300 px-3 py-2 text-xs text-zinc-600 dark:border-zinc-700 dark:text-zinc-300">
              <p className="font-medium">Enforcement notes (how this rule reaches nftables):</p>
              <ul className="mt-1 list-disc pl-4">
                {validation.warnings.map((w, i) => (
                  <li key={i}>{w.message}</li>
                ))}
              </ul>
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="ghost" onClick={() => props.onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={saveMut.isPending || validateMut.isPending} className="bg-amber-700 text-white hover:bg-amber-800">
            {saveMut.isPending ? "Saving…" : validateMut.isPending ? "Validating…" : editing ? "Save changes" : "Create NAT rule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function OneToOneDialog(props: { open: boolean; onOpenChange: (open: boolean) => void; ifaceNames: string[]; onSaved: () => void }) {
  const [publicIp, setPublicIp] = useState("");
  const [internalHost, setInternalHost] = useState("");
  const [iface, setIface] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);

  const mut = useMutation({
    mutationFn: () =>
      api.createOneToOne({
        publicIp: publicIp.trim(),
        internalHost: internalHost.trim(),
        ...(iface.trim() ? { iface: iface.trim() } : {}),
        ...(name.trim() ? { name: name.trim() } : {}),
      }),
    onSuccess: (res) => {
      toastOk("1:1 pair created", `dnat #${res.dnat.id} + snat #${res.snat.id} — both rows carry the 1:1 pair chip`);
      props.onOpenChange(false);
      props.onSaved();
    },
    onError: (err) => toastErr(err, "1:1 NAT failed"),
  });

  const submit = () => {
    if (!IPV4_RE.test(publicIp.trim())) return setError("Public IP must be a valid IPv4");
    if (!IPV4_RE.test(internalHost.trim())) return setError("Internal host must be a valid IPv4");
    setError(null);
    mut.mutate();
  };

  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent className="w-[calc(100vw-1rem)] max-w-md">
        <DialogHeader>
          <DialogTitle>1:1 static NAT</DialogTitle>
          <DialogDescription>
            Creates the paired dnat (no port) + snat rows atomically in one transaction and one audit entry. Both rows are marked as a 1:1 pair.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div>
            <Label htmlFor="ot1-public" className="text-xs font-medium">
              Public IP
            </Label>
            <Input id="ot1-public" value={publicIp} onChange={(e) => setPublicIp(e.target.value)} placeholder="203.0.113.50" className="mt-1.5 font-mono text-xs" />
          </div>
          <div>
            <Label htmlFor="ot1-host" className="text-xs font-medium">
              Internal host IP
            </Label>
            <Input id="ot1-host" value={internalHost} onChange={(e) => setInternalHost(e.target.value)} placeholder="172.16.20.5" className="mt-1.5 font-mono text-xs" />
          </div>
          <div>
            <Label htmlFor="ot1-iface" className="text-xs font-medium">
              Outgoing interface <span className="text-zinc-400">(optional)</span>
            </Label>
            <Input id="ot1-iface" value={iface} onChange={(e) => setIface(e.target.value)} placeholder="wan0" list="ot1-ifaces" className="mt-1.5 font-mono text-xs" />
            <datalist id="ot1-ifaces">
              {props.ifaceNames.map((n) => (
                <option key={n} value={n} />
              ))}
            </datalist>
          </div>
          <div>
            <Label htmlFor="ot1-name" className="text-xs font-medium">
              Name <span className="text-zinc-400">(optional)</span>
            </Label>
            <Input id="ot1-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="WEB_1TO1" className="mt-1.5" />
          </div>
          {error && <p className="text-xs text-rose-600 dark:text-rose-400">{error}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => props.onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={mut.isPending} className="bg-amber-700 text-white hover:bg-amber-800">
            {mut.isPending ? "Creating…" : "Create 1:1 pair"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function PortForwardDialog(props: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  zones: Zone[];
  addresses: AddressObject[];
  services: ServiceObject[];
  ifaceNames: string[];
  onSaved: () => void;
}) {
  const [outIface, setOutIface] = useState("wan0");
  const [extPort, setExtPort] = useState("");
  const [proto, setProto] = useState<"tcp" | "udp">("tcp");
  const [internalHost, setInternalHost] = useState("");
  const [internalPort, setInternalPort] = useState("");
  const [alsoAllow, setAlsoAllow] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const mut = useMutation({
    mutationFn: async () => {
      const ext = extPort.trim(); // single port or list "8080-8090,9000"
      const inPort = Number(internalPort);
      // 1) reuse or create the matching service object so dnat + allow rule match precisely
      const existing = props.services.find(
        (s) => s.protocol === proto && (s.dstPort ?? "") === ext,
      );
      const svcId = existing
        ? existing.id
        : (
            await api.generic.create<ServiceObject>("/api/v1/service-objects", {
              name: `pf-${proto}-${ext.replace(/[^a-z0-9-]/gi, "-")}`,
              protocol: proto,
              dstPort: ext,
            })
          ).id;

      // 2) the dnat rule — external ports map to the internal port
      await api.createNat({
        name: `port-fwd-${proto}-${ext.replace(/[^a-z0-9-]/gi, "-")}`,
        enabled: true,
        type: "dnat",
        srcAddrIds: [],
        dstAddrIds: [],
        serviceIds: [svcId],
        outgoingIface: outIface.trim() || null,
        translatedSrc: null,
        translatedSrcPool: [],
        overload: true,
        translatedDst: internalHost.trim(),
        translatedPort: inPort,
        translatedPortRange: null,
        logging: "none",
        comment: `port forward ${proto}/${ext} → ${internalHost.trim()}:${inPort}`,
      });

      // 3) optional matching allow rule
      if (alsoAllow) {
        const hostObj = props.addresses.find((a) => a.value === internalHost.trim());
        const wanZone = props.zones.find((z) => z.name === "WAN");
        await api.createRule({
          name: `allow-port-fwd-${proto}-${ext.replace(/[^a-z0-9-]/gi, "-")}`,
          enabled: true,
          action: "allow",
          logging: "summary",
          srcZoneIds: wanZone ? [wanZone.id] : [],
          dstZoneIds: [],
          srcAddrIds: [],
          dstAddrIds: hostObj ? [hostObj.id] : [],
          serviceIds: [svcId],
          applicationIds: [],
          userIds: [],
          srcMacs: [],
          synProtection: false,
          tags: ["port-forward"],
          comment: `allow port forward ${proto}/${ext} → ${internalHost.trim()}:${inPort}`,
        });
      }
    },
    onSuccess: () => {
      toastOk("Port forward created", `${proto}/${extPort} → ${internalHost}:${internalPort}${alsoAllow ? " + allow rule" : ""}`);
      props.onOpenChange(false);
      props.onSaved();
    },
    onError: (err) => toastErr(err, "Port forward failed"),
  });

  const submit = () => {
    const ext = extPort.trim();
    const inPort = Number(internalPort);
    if (!isValidPortList(ext) || ext === "0") return setError("External port must be 1–65535 or a list like 8080-8090,9000");
    if (!IPV4_RE.test(internalHost.trim())) return setError("Internal host must be a valid IPv4");
    if (!Number.isInteger(inPort) || inPort < 1 || inPort > 65535) return setError("Internal port must be 1–65535");
    setError(null);
    mut.mutate();
  };

  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent className="w-[calc(100vw-1rem)] max-w-md">
        <DialogHeader>
          <DialogTitle>Port forward</DialogTitle>
          <DialogDescription>
            Creates a dnat rule; optionally also creates the matching allow firewall rule and service object.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <Label htmlFor="pf-iface" className="text-xs font-medium">
              WAN interface
            </Label>
            <Input id="pf-iface" value={outIface} onChange={(e) => setOutIface(e.target.value)} list="pf-ifaces" className="mt-1.5 font-mono text-xs" />
            <datalist id="pf-ifaces">
              {props.ifaceNames.map((n) => (
                <option key={n} value={n} />
              ))}
            </datalist>
          </div>
          <div>
            <Label htmlFor="pf-ext" className="text-xs font-medium">
              External port <span className="text-zinc-400">(single or range list)</span>
            </Label>
            <Input
              id="pf-ext"
              value={extPort}
              onChange={(e) => setExtPort(e.target.value)}
              placeholder="8080 or 8080-8090,9000"
              className="mt-1.5 font-mono text-xs"
            />
          </div>
          <div>
            <FieldLabel>Protocol</FieldLabel>
            <RadioGroup value={proto} onValueChange={(v) => setProto(v as "tcp" | "udp")} className="flex gap-4">
              <Label className="flex cursor-pointer items-center gap-2 text-sm">
                <RadioGroupItem value="tcp" /> TCP
              </Label>
              <Label className="flex cursor-pointer items-center gap-2 text-sm">
                <RadioGroupItem value="udp" /> UDP
              </Label>
            </RadioGroup>
          </div>
          <div>
            <Label htmlFor="pf-ihost" className="text-xs font-medium">
              Internal host
            </Label>
            <Input id="pf-ihost" value={internalHost} onChange={(e) => setInternalHost(e.target.value)} placeholder="172.16.20.5" className="mt-1.5 font-mono text-xs" />
          </div>
          <div>
            <Label htmlFor="pf-iport" className="text-xs font-medium">
              Internal port
            </Label>
            <Input id="pf-iport" type="number" value={internalPort} onChange={(e) => setInternalPort(e.target.value)} placeholder="80" className="mt-1.5" />
          </div>
          <Label className="flex cursor-pointer items-start gap-2 self-end pb-1 text-sm sm:col-span-1">
            <Checkbox checked={alsoAllow} onCheckedChange={(v) => setAlsoAllow(v === true)} className="mt-0.5" />
            <span className="text-xs leading-snug text-zinc-600 dark:text-zinc-300">
              Also create the matching allow rule (source zone WAN)
            </span>
          </Label>
        </div>
        {error && <p className="text-xs text-rose-600 dark:text-rose-400">{error}</p>}
        <DialogFooter>
          <Button variant="ghost" onClick={() => props.onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={mut.isPending} className="bg-amber-700 text-white hover:bg-amber-800">
            {mut.isPending ? "Creating…" : "Create forward"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
