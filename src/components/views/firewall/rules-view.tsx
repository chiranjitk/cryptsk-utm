"use client";

/**
 * #/firewall/rules — ordered policy table (M03 §4). First match wins;
 * position # = evaluation order. dnd-kit sortable rows → POST /reorder with
 * the full id permutation; optimistic toggle; import/export; validate-aware
 * RuleEditor.
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
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
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
import { useQuery as rqUseQuery } from "@tanstack/react-query";
import {
  api,
  fmtDateTime,
  importRowErrors,
  type AddressObject,
  type FwRule,
  type ImportRowError,
  type NamedWithMembers,
  type ScheduleObject,
  type ServiceObject,
  type Zone,
} from "./fw-api";
import {
  ActionBadge,
  ConfirmDialog,
  EmptyBlock,
  QueryError,
  TableSkeleton,
  toastErr,
  toastOk,
  useFwConfigInvalidation,
} from "./fw-ui";
import { RuleEditor } from "./rule-editor";

const RULES_KEY = ["firewall", "rules"] as const;
/** sessionStorage handoff key written by M04 events-view "Block source". */
const IPS_PREFILL_KEY = "ips:prefill-rule";

/**
 * One-shot deep-link read at first render (view remounts per navigation):
 * `#/firewall/rules?search=<name>` prefills the search box; `?prefill=1`
 * consumes the sessionStorage draft from M04 "Create firewall block rule".
 */
function readRulesDeepLink(): { search: string; prefill: FwRule | null } {
  if (typeof window === "undefined") return { search: "", prefill: null };
  const qs = window.location.hash.split("?")[1];
  if (!qs) return { search: "", prefill: null };
  const params = new URLSearchParams(qs);
  const out = { search: params.get("search") ?? "", prefill: null as FwRule | null };
  if (params.get("prefill")) {
    const raw = sessionStorage.getItem(IPS_PREFILL_KEY);
    sessionStorage.removeItem(IPS_PREFILL_KEY);
    if (raw) {
      try {
        out.prefill = JSON.parse(raw) as FwRule;
      } catch {
        // corrupted handoff — ignore, plain create flow still works
      }
    }
  }
  return out;
}

interface NameMaps {
  zoneById: Map<number, Zone>;
  addrById: Map<number, { name: string; sub: string; isGroup: boolean; memberCount: number }>;
  svcById: Map<number, { name: string; sub: string; isGroup: boolean; memberCount: number }>;
  scheduleById: Map<number, ScheduleObject>;
}

function useNameMaps(zones: Zone[], addresses: AddressObject[], addrGroups: NamedWithMembers[], services: ServiceObject[], svcGroups: NamedWithMembers[], schedules: ScheduleObject[]): NameMaps {
  return useMemo(() => {
    const addrById = new Map<number, { name: string; sub: string; isGroup: boolean; memberCount: number }>();
    addresses.forEach((a) => addrById.set(a.id, { name: a.name, sub: a.value, isGroup: false, memberCount: 0 }));
    addrGroups.forEach((g) => addrById.set(g.id, { name: g.name, sub: "group", isGroup: true, memberCount: g.memberIds.length }));
    const svcById = new Map<number, { name: string; sub: string; isGroup: boolean; memberCount: number }>();
    services.forEach((s) => svcById.set(s.id, { name: s.name, sub: s.dstPort ?? s.protocol, isGroup: false, memberCount: 0 }));
    svcGroups.forEach((g) => svcById.set(g.id, { name: g.name, sub: "group", isGroup: true, memberCount: g.memberIds.length }));
    const zoneById = new Map(zones.map((z) => [z.id, z]));
    const scheduleById = new Map(schedules.map((s) => [s.id, s]));
    return { zoneById, addrById, svcById, scheduleById };
  }, [zones, addresses, addrGroups, services, svcGroups, schedules]);
}

function IdChips({ ids, map }: { ids: number[]; map: NameMaps["addrById"] }) {
  if (ids.length === 0) return <span className="text-xs text-zinc-400">any</span>;
  return (
    <TooltipProvider delayDuration={150}>
      <div className="flex flex-wrap gap-1">
        {ids.map((id) => {
          const info = map.get(id);
          const label = info ? (info.isGroup ? `${info.name} +${info.memberCount}` : info.name) : `#${id}`;
          return (
            <Tooltip key={id}>
              <TooltipTrigger asChild>
                <Badge
                  variant="outline"
                  className={cn(
                    "max-w-36 cursor-default gap-1 truncate font-normal",
                    info?.isGroup
                      ? "border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300"
                      : "border-zinc-300 text-zinc-600 dark:border-zinc-700 dark:text-zinc-300",
                  )}
                >
                  {info?.isGroup ? <Icons.FolderOpen className="h-3 w-3 shrink-0" /> : null}
                  <span className="truncate">{label}</span>
                </Badge>
              </TooltipTrigger>
              <TooltipContent className="text-xs">{info?.sub ?? `unknown id ${id}`}</TooltipContent>
            </Tooltip>
          );
        })}
      </div>
    </TooltipProvider>
  );
}

function ZoneChips({ ids, map }: { ids: number[]; map: NameMaps["zoneById"] }) {
  if (ids.length === 0) return <span className="text-xs text-zinc-400">any</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {ids.map((id) => (
        <Badge key={id} variant="outline" className="border-zinc-300 font-normal text-zinc-600 dark:border-zinc-700 dark:text-zinc-300">
          {map.get(id)?.name ?? `#${id}`}
        </Badge>
      ))}
    </div>
  );
}

function HitsCell({ rule }: { rule: FwRule }) {
  const [open, setOpen] = useState(false);
  const hitsQuery = rqUseQuery({
    queryKey: ["firewall", "rules", rule.id, "hits"],
    queryFn: () => api.ruleHits(rule.id),
    enabled: open,
  });
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button
          type="button"
          aria-label={`Hit counters for ${rule.name}`}
          className="rounded-md px-1.5 py-0.5 text-right tabular-nums hover:bg-zinc-500/10"
        >
          <span className="text-sm font-medium tabular-nums">{rule.hitCount.toLocaleString()}</span>
          <span className="block text-[10px] text-zinc-400">{fmtDateTime(rule.lastHitAt)}</span>
        </button>
      </PopoverTrigger>
      <PopoverContent className="w-56 p-3" align="end">
        <p className="text-xs font-semibold">{hitsQuery.data?.name ?? rule.name}</p>
        <div className="mt-2 space-y-1 text-xs text-zinc-500">
          <p className="flex justify-between">
            <span>hitCount</span>
            <span className="font-mono tabular-nums text-zinc-800 dark:text-zinc-200">
              {(hitsQuery.data?.hitCount ?? rule.hitCount).toLocaleString()}
            </span>
          </p>
          <p className="flex justify-between">
            <span>lastHitAt</span>
            <span className="font-mono">{fmtDateTime(hitsQuery.data?.lastHitAt ?? rule.lastHitAt)}</span>
          </p>
        </div>
        <p className="mt-2 border-t border-zinc-200 pt-1.5 text-[10px] text-zinc-400 dark:border-zinc-800">
          Counters increment per matched flow (generator).
        </p>
      </PopoverContent>
    </Popover>
  );
}

function SortableRow(props: {
  rule: FwRule;
  maps: NameMaps;
  onToggle: (rule: FwRule) => void;
  onEdit: (rule: FwRule) => void;
  onDuplicate: (rule: FwRule) => void;
  onReset: (rule: FwRule) => void;
  onDelete: (rule: FwRule) => void;
  toggling: boolean;
}) {
  const { rule: r, maps } = props;
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({ id: r.id });

  const schedule = r.scheduleId != null ? maps.scheduleById.get(r.scheduleId) : undefined;

  return (
    <TableRow
      ref={setNodeRef}
      style={{ transform: CSS.Transform.toString(transform), transition }}
      className={cn(!r.enabled && "opacity-55", isDragging && "z-50 relative bg-zinc-500/5")}
    >
      <TableCell className="w-10 pl-2 pr-0">
        <button
          type="button"
          aria-label={`Reorder ${r.name}`}
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
          aria-label={`Toggle rule ${r.name}`}
          onCheckedChange={() => props.onToggle(r)}
        />
      </TableCell>
      <TableCell className="min-w-44">
        <TooltipProvider delayDuration={200}>
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="block max-w-52 truncate text-sm font-medium">{r.name}</span>
            </TooltipTrigger>
            <TooltipContent className="max-w-72 text-xs">
              <p className="font-medium">{r.name}</p>
              {r.description ? <p>{r.description}</p> : null}
              {r.comment ? <p className="mt-1 border-t border-zinc-700 pt-1 text-zinc-400">comment: {r.comment}</p> : null}
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
        {r.tags.length > 0 && (
          <div className="mt-0.5 flex flex-wrap gap-1">
            {r.tags.map((t) => (
              <span key={t} className="rounded bg-zinc-100 px-1 text-[10px] text-zinc-500 dark:bg-zinc-800 dark:text-zinc-400">
                {t}
              </span>
            ))}
          </div>
        )}
      </TableCell>
      <TableCell>
        <ActionBadge action={r.action} />
      </TableCell>
      <TableCell className="min-w-28">
        <div className="flex items-center gap-1">
          <ZoneChips ids={r.srcZoneIds} map={maps.zoneById} />
          <Icons.ArrowRight className="h-3 w-3 shrink-0 text-zinc-400" />
          <ZoneChips ids={r.dstZoneIds} map={maps.zoneById} />
        </div>
      </TableCell>
      <TableCell className="min-w-36">
        <IdChips ids={r.srcAddrIds} map={maps.addrById} />
      </TableCell>
      <TableCell className="min-w-36">
        <IdChips ids={r.dstAddrIds} map={maps.addrById} />
      </TableCell>
      <TableCell className="min-w-28">
        <IdChips ids={r.serviceIds} map={maps.svcById} />
      </TableCell>
      <TableCell>
        {schedule ? (
          <TooltipProvider delayDuration={150}>
            <Tooltip>
              <TooltipTrigger asChild>
                <Icons.Clock className="h-4 w-4 text-amber-500" />
              </TooltipTrigger>
              <TooltipContent className="text-xs">
                Schedule: {schedule.name}
                {schedule.recurrence ? ` (${schedule.recurrence.days.join("/")} ${schedule.recurrence.start}–${schedule.recurrence.end} ${schedule.timezone})` : ""}
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        ) : (
          <span className="text-xs text-zinc-300 dark:text-zinc-700">—</span>
        )}
      </TableCell>
      <TableCell>
        <div className="flex items-center gap-1.5 text-zinc-500">
          {r.connLimit != null && (
            <TooltipProvider delayDuration={150}>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Icons.Link2 className="h-3.5 w-3.5" />
                </TooltipTrigger>
                <TooltipContent className="text-xs">conn limit: {r.connLimit}/source</TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )}
          {r.rateLimit != null && (
            <TooltipProvider delayDuration={150}>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Icons.Gauge className="h-3.5 w-3.5" />
                </TooltipTrigger>
                <TooltipContent className="text-xs">rate limit: {r.rateLimit} conn/s/source</TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )}
          {r.synProtection && (
            <TooltipProvider delayDuration={150}>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Icons.ShieldAlert className="h-3.5 w-3.5 text-rose-500" />
                </TooltipTrigger>
                <TooltipContent className="text-xs">SYN protection{r.synThreshold ? ` ≥ ${r.synThreshold} pps` : ""}</TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )}
          {r.connLimit == null && r.rateLimit == null && !r.synProtection && (
            <span className="text-xs text-zinc-300 dark:text-zinc-700">—</span>
          )}
        </div>
      </TableCell>
      <TableCell className="text-right">
        <HitsCell rule={r} />
      </TableCell>
      <TableCell className="w-10 pr-2">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={`Actions for ${r.name}`}>
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
            <DropdownMenuItem onClick={() => props.onReset(r)}>
              <Icons.RotateCcw className="mr-2 h-4 w-4" /> Reset counters
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

function ImportDialog(props: { open: boolean; onOpenChange: (open: boolean) => void; onImported: () => void }) {
  const [format, setFormat] = useState<"json" | "csv">("json");
  const [payload, setPayload] = useState("");
  const [rowErrors, setRowErrors] = useState<ImportRowError[]>([]);
  const [fileName, setFileName] = useState<string | null>(null);

  const previewCount = useMemo(() => {
    const t = payload.trim();
    if (!t) return null;
    if (format === "json") {
      try {
        const v: unknown = JSON.parse(t);
        return Array.isArray(v) ? v.length : 1;
      } catch {
        return null;
      }
    }
    const lines = t.split("\n").map((l) => l.trim()).filter(Boolean);
    return Math.max(0, lines.length - 1);
  }, [format, payload]);

  const importMut = useMutation({
    mutationFn: () => api.importRules(format, payload),
    onSuccess: (res) => {
      toastOk("Import complete", `${res.imported} rule(s) imported`);
      setRowErrors([]);
      setPayload("");
      props.onOpenChange(false);
      props.onImported();
    },
    onError: (err) => {
      setRowErrors(importRowErrors(err));
      toastErr(err, "Import failed");
    },
  });

  const readFile = async (file: File) => {
    setFileName(file.name);
    const text = await file.text();
    setPayload(text);
    setFormat(file.name.toLowerCase().endsWith(".csv") ? "csv" : "json");
  };

  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent className="w-[calc(100vw-1rem)] max-w-xl">
        <DialogHeader>
          <DialogTitle>Import rules</DialogTitle>
          <DialogDescription>
            All-or-nothing: if any row is invalid nothing is persisted. CSV columns: position,name,enabled,action,srcZones,dstZones,srcAddrs,dstAddrs,services,logging,tags,comment.
          </DialogDescription>
        </DialogHeader>

        <RadioGroup
          value={format}
          onValueChange={(v) => setFormat(v as "json" | "csv")}
          className="flex gap-4"
        >
          <Label className="flex cursor-pointer items-center gap-2 text-sm">
            <RadioGroupItem value="json" /> JSON
          </Label>
          <Label className="flex cursor-pointer items-center gap-2 text-sm">
            <RadioGroupItem value="csv" /> CSV
          </Label>
        </RadioGroup>

        <div
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => {
            e.preventDefault();
            const f = e.dataTransfer.files?.[0];
            if (f) void readFile(f);
          }}
          className="rounded-lg border border-dashed border-zinc-300 p-3 text-center dark:border-zinc-700"
        >
          <Label
            htmlFor="import-file"
            className="flex cursor-pointer flex-col items-center gap-1 text-xs text-zinc-500"
          >
            <Icons.Upload className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
            {fileName ? (
              <span className="font-medium text-zinc-700 dark:text-zinc-300">{fileName}</span>
            ) : (
              <span>Drop a file here or click to browse</span>
            )}
          </Label>
          <input
            id="import-file"
            type="file"
            accept=".json,.csv,application/json,text/csv"
            className="sr-only"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void readFile(f);
            }}
          />
        </div>

        <Textarea
          value={payload}
          onChange={(e) => setPayload(e.target.value)}
          rows={7}
          className="font-mono text-xs"
          placeholder={format === "json" ? '[{ "name": "allow-x", "action": "allow", … }]' : "position,name,enabled,action,…"}
        />

        <p className="text-xs text-zinc-500">
          Preview:{" "}
          {previewCount == null ? (
            <span className="text-amber-600 dark:text-amber-400">payload not parseable yet</span>
          ) : (
            <span className="font-medium">{previewCount} row(s) parsed</span>
          )}
        </p>

        {rowErrors.length > 0 && (
          <div className="max-h-32 space-y-1 overflow-y-auto rounded-md border border-rose-500/40 bg-rose-500/5 p-2">
            {rowErrors.map((r, i) => (
              <p key={i} className="text-xs text-rose-600 dark:text-rose-400">
                <span className="font-mono">row {r.row}:</span> {r.message}
              </p>
            ))}
          </div>
        )}

        <DialogFooter>
          <Button variant="ghost" onClick={() => props.onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={() => importMut.mutate()}
            disabled={importMut.isPending || !payload.trim()}
            className="bg-red-700 text-white hover:bg-red-800"
          >
            {importMut.isPending ? "Importing…" : "Import"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function RulesView() {
  useFwConfigInvalidation();
  const queryClient = useQueryClient();

  const rulesQuery = useQuery({ queryKey: RULES_KEY, queryFn: api.listRules });
  const zonesQuery = useQuery({ queryKey: ["firewall", "zones"], queryFn: api.listZones });
  const addrQuery = useQuery({ queryKey: ["firewall", "objects", "address"], queryFn: api.listAddressObjects });
  const addrGrpQuery = useQuery({ queryKey: ["firewall", "objects", "address-groups"], queryFn: api.listAddressGroups });
  const svcQuery = useQuery({ queryKey: ["firewall", "objects", "service"], queryFn: api.listServiceObjects });
  const svcGrpQuery = useQuery({ queryKey: ["firewall", "objects", "service-groups"], queryFn: api.listServiceGroups });
  const schedQuery = useQuery({ queryKey: ["firewall", "objects", "schedules"], queryFn: api.listSchedules });

  const loading =
    rulesQuery.isLoading || zonesQuery.isLoading || addrQuery.isLoading || svcQuery.isLoading;

  const [zoneFilter, setZoneFilter] = useState<number | null>(null);
  const [tagFilter, setTagFilter] = useState<string[]>([]);
  const [deepLink] = useState(readRulesDeepLink);
  const [search, setSearch] = useState(deepLink.search);
  const [editorOpen, setEditorOpen] = useState(() => deepLink.prefill != null);
  const [editing, setEditing] = useState<FwRule | null>(null);
  const [duplicateOf, setDuplicateOf] = useState<FwRule | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [deleting, setDeleting] = useState<FwRule | null>(null);
  /** create-mode draft handed over from M04 (IPS event block-source) */
  const [prefillRule, setPrefillRule] = useState<FwRule | null>(deepLink.prefill);

  const rules = useMemo(() => rulesQuery.data?.data ?? [], [rulesQuery.data]);
  const zones = useMemo(() => zonesQuery.data?.data ?? [], [zonesQuery.data]);
  const maps = useNameMaps(
    zones,
    addrQuery.data?.data ?? [],
    addrGrpQuery.data?.data ?? [],
    svcQuery.data?.data ?? [],
    svcGrpQuery.data?.data ?? [],
    schedQuery.data?.data ?? [],
  );

  const allTags = useMemo(() => [...new Set(rules.flatMap((r) => r.tags))].sort(), [rules]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return rules.filter((r) => {
      if (zoneFilter != null && !(r.srcZoneIds.includes(zoneFilter) || r.dstZoneIds.includes(zoneFilter))) return false;
      if (tagFilter.length > 0 && !tagFilter.every((t) => r.tags.includes(t))) return false;
      if (q) {
        const hay = `${r.name} ${r.description ?? ""} ${r.comment ?? ""} ${r.tags.join(" ")}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [rules, zoneFilter, tagFilter, search]);

  // ── mutations ─────────────────────────────────────────────────────────────

  const toggleMut = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => api.toggleRule(id, enabled),
    onMutate: async ({ id, enabled }) => {
      await queryClient.cancelQueries({ queryKey: RULES_KEY });
      const prev = queryClient.getQueryData<{ data: FwRule[] }>(RULES_KEY);
      queryClient.setQueryData<{ data: FwRule[] }>(RULES_KEY, (old) =>
        old ? { ...old, data: old.data.map((r) => (r.id === id ? { ...r, enabled } : r)) } : old,
      );
      return { prev };
    },
    onError: (err, vars, ctx) => {
      if (ctx?.prev) queryClient.setQueryData(RULES_KEY, ctx.prev);
      toastErr(err, `Failed to ${vars.enabled ? "enable" : "disable"} rule`);
    },
    onSettled: () => void queryClient.invalidateQueries({ queryKey: RULES_KEY }),
  });

  const reorderMut = useMutation({
    mutationFn: (next: FwRule[]) => api.reorderRules(next.map((r) => r.id)),
    onMutate: async (next) => {
      await queryClient.cancelQueries({ queryKey: RULES_KEY });
      const prev = queryClient.getQueryData<{ data: FwRule[] }>(RULES_KEY);
      queryClient.setQueryData<{ data: FwRule[] }>(RULES_KEY, (old) =>
        old ? { ...old, data: next.map((r, i) => ({ ...r, position: i + 1 })) } : old,
      );
      return { prev };
    },
    onError: (err, _vars, ctx) => {
      if (ctx?.prev) queryClient.setQueryData(RULES_KEY, ctx.prev);
      toastErr(err, "Reorder failed");
    },
    onSettled: () => void queryClient.invalidateQueries({ queryKey: RULES_KEY }),
  });

  const deleteMut = useMutation({
    mutationFn: (id: number) => api.deleteRule(id),
    onSuccess: (_d, _id) => {
      toastOk("Rule deleted");
      setDeleting(null);
    },
    onError: (err) => toastErr(err, "Delete failed"),
    onSettled: () => void queryClient.invalidateQueries({ queryKey: RULES_KEY }),
  });

  const resetMut = useMutation({
    mutationFn: (id: number) => api.resetRuleHits(id),
    onSuccess: () => toastOk("Counters reset"),
    onError: (err) => toastErr(err, "Reset failed"),
    onSettled: () => void queryClient.invalidateQueries({ queryKey: RULES_KEY }),
  });

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 4 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }),
  );

  const onDragEnd = (e: DragEndEvent) => {
    const { active, over } = e;
    if (!over || active.id === over.id) return;
    const from = rules.findIndex((r) => r.id === active.id);
    const to = rules.findIndex((r) => r.id === over.id);
    if (from < 0 || to < 0) return;
    reorderMut.mutate(arrayMove(rules, from, to));
  };

  const openCreate = () => {
    setEditing(null);
    setDuplicateOf(null);
    setEditorOpen(true);
  };
  const openEdit = (r: FwRule) => {
    setEditing(r);
    setDuplicateOf(null);
    setEditorOpen(true);
  };
  const openDuplicate = (r: FwRule) => {
    setEditing(null);
    setDuplicateOf(r);
    setEditorOpen(true);
  };

  const error = rulesQuery.error;

  return (
    <div className="space-y-4">
      {/* toolbar */}
      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Icons.Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-400" />
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search rules…"
              className="h-9 w-52 pl-8"
              aria-label="Search rules"
            />
          </div>
          <div className="ml-auto flex flex-wrap items-center gap-2">
            <Button size="sm" onClick={openCreate} className="bg-red-700 text-white hover:bg-red-800">
              <Icons.Plus className="mr-1 h-4 w-4" /> Add rule
            </Button>
            <Button size="sm" variant="outline" onClick={() => setImportOpen(true)}>
              <Icons.Upload className="mr-1 h-4 w-4" /> Import
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button size="sm" variant="outline">
                  <Icons.Download className="mr-1 h-4 w-4" /> Export
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => window.open("/api/v1/firewall-rules/export?format=json")}>
                  <Icons.FileJson className="mr-2 h-4 w-4" /> Export JSON
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => window.open("/api/v1/firewall-rules/export?format=csv")}>
                  <Icons.FileSpreadsheet className="mr-2 h-4 w-4" /> Export CSV
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <span className="mr-1 text-[11px] font-semibold uppercase tracking-wide text-zinc-400">Zone</span>
          <button
            type="button"
            onClick={() => setZoneFilter(null)}
            aria-pressed={zoneFilter === null}
            className={cn(
              "rounded-full border px-2.5 py-1 text-xs transition-colors",
              zoneFilter === null
                ? "border-zinc-500/30 bg-zinc-500/10 font-medium text-zinc-600 dark:text-zinc-300"
                : "border-zinc-200 text-zinc-500 hover:bg-zinc-100 dark:border-zinc-800 dark:hover:bg-zinc-800",
            )}
          >
            All
          </button>
          {zones.map((z) => (
            <button
              key={z.id}
              type="button"
              onClick={() => setZoneFilter(zoneFilter === z.id ? null : z.id)}
              aria-pressed={zoneFilter === z.id}
              className={cn(
                "rounded-full border px-2.5 py-1 text-xs transition-colors",
                zoneFilter === z.id
                  ? "border-zinc-500/30 bg-zinc-500/10 font-medium text-zinc-600 dark:text-zinc-300"
                  : "border-zinc-200 text-zinc-500 hover:bg-zinc-100 dark:border-zinc-800 dark:hover:bg-zinc-800",
              )}
            >
              {z.name}
            </button>
          ))}
          {allTags.length > 0 && (
            <>
              <span className="mx-1 hidden h-4 w-px bg-zinc-200 sm:inline dark:bg-zinc-800" />
              <span className="mr-1 text-[11px] font-semibold uppercase tracking-wide text-zinc-400">Tags</span>
              {allTags.map((t) => {
                const active = tagFilter.includes(t);
                return (
                  <button
                    key={t}
                    type="button"
                    onClick={() => setTagFilter(active ? tagFilter.filter((x) => x !== t) : [...tagFilter, t])}
                    aria-pressed={active}
                    className={cn(
                      "rounded-full border px-2.5 py-1 text-xs transition-colors",
                      active
                        ? "border-zinc-500/30 bg-zinc-500/10 font-medium text-zinc-600 dark:text-zinc-300"
                        : "border-dashed border-zinc-300 text-zinc-500 hover:bg-zinc-100 dark:border-zinc-700 dark:hover:bg-zinc-800",
                    )}
                  >
                    {t}
                  </button>
                );
              })}
            </>
          )}
          {(zoneFilter !== null || tagFilter.length > 0 || search) && (
            <Button
              size="sm"
              variant="ghost"
              className="h-7 px-2 text-xs text-zinc-500"
              onClick={() => {
                setZoneFilter(null);
                setTagFilter([]);
                setSearch("");
              }}
            >
              <Icons.X className="mr-1 h-3 w-3" /> Clear ({filtered.length}/{rules.length})
            </Button>
          )}
        </div>
      </div>

      <Card className="p-0">
        <CardContent className="p-0">
          {error ? (
            <div className="p-4">
              <QueryError error={error} onRetry={() => void rulesQuery.refetch()} />
            </div>
          ) : loading ? (
            <div className="p-4">
              <TableSkeleton rows={8} cols={13} />
            </div>
          ) : rules.length === 0 ? (
            <EmptyBlock
              icon={<Icons.ShieldOff className="h-6 w-6" />}
              title="No firewall rules yet"
              description="All traffic falls through to the implicit deny — every unmatched flow is dropped and logged as deny. Add your first rule to start allowing traffic."
              action={
                <Button onClick={openCreate} className="bg-red-700 text-white hover:bg-red-800">
                  <Icons.Plus className="mr-1 h-4 w-4" /> Add rule
                </Button>
              }
            />
          ) : (
            <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={onDragEnd}>
              <div className="max-h-[70vh] overflow-auto [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-zinc-300 dark:[&::-webkit-scrollbar-thumb]:bg-zinc-700">
                <Table className="min-w-[1150px] text-sm">
                  <TableHeader className="sticky top-0 z-10 bg-card">
                    <TableRow>
                      <TableHead className="w-10 pl-2" aria-label="Reorder" />
                      <TableHead className="w-10">#</TableHead>
                      <TableHead className="w-14">On</TableHead>
                      <TableHead>Name</TableHead>
                      <TableHead>Action</TableHead>
                      <TableHead>Src → Dst zones</TableHead>
                      <TableHead>Source</TableHead>
                      <TableHead>Destination</TableHead>
                      <TableHead>Services</TableHead>
                      <TableHead>Sched</TableHead>
                      <TableHead>Guard</TableHead>
                      <TableHead className="text-right">Hits</TableHead>
                      <TableHead className="w-10" aria-label="Actions" />
                    </TableRow>
                  </TableHeader>
                  <SortableContext items={rules.map((r) => r.id)} strategy={verticalListSortingStrategy}>
                    <TableBody>
                      {filtered.map((r) => (
                        <SortableRow
                          key={r.id}
                          rule={r}
                          maps={maps}
                          toggling={toggleMut.isPending}
                          onToggle={(rule) => toggleMut.mutate({ id: rule.id, enabled: !rule.enabled })}
                          onEdit={openEdit}
                          onDuplicate={openDuplicate}
                          onReset={(rule) => resetMut.mutate(rule.id)}
                          onDelete={(rule) => setDeleting(rule)}
                        />
                      ))}
                    </TableBody>
                  </SortableContext>
                </Table>
              </div>
            </DndContext>
          )}
          {rules.length > 0 && filtered.length === 0 && (
            <div className="border-t border-zinc-200 px-4 py-6 text-center text-sm text-zinc-500 dark:border-zinc-800">
              No rules match the current filters.
            </div>
          )}
        </CardContent>
      </Card>

      <p className="flex items-center gap-1.5 text-xs text-zinc-400">
        <Icons.Info className="h-3.5 w-3.5" />
        Drag rows to reorder — evaluation is strictly top-down, first match wins. Traffic that matches no rule hits the implicit deny.
      </p>

      {editorOpen && (
        <RuleEditor
          open={editorOpen}
          onOpenChange={(open) => {
            setEditorOpen(open);
            if (!open) setPrefillRule(null);
          }}
          editing={editing}
          duplicateOf={duplicateOf}
          prefill={prefillRule}
          zones={zones}
          addresses={addrQuery.data?.data ?? []}
          addressGroups={addrGrpQuery.data?.data ?? []}
          services={svcQuery.data?.data ?? []}
          serviceGroups={svcGrpQuery.data?.data ?? []}
          schedules={schedQuery.data?.data ?? []}
          tagSuggestions={allTags}
          onSaved={() => void queryClient.invalidateQueries({ queryKey: RULES_KEY })}
        />
      )}

      {importOpen && (
        <ImportDialog
          open={importOpen}
          onOpenChange={setImportOpen}
          onImported={() => void queryClient.invalidateQueries({ queryKey: RULES_KEY })}
        />
      )}

      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title="Delete rule?"
        description={`Delete rule '${deleting?.name ?? ""}'? Remaining rules are renumbered densely.`}
        loading={deleteMut.isPending}
        onConfirm={() => deleting && deleteMut.mutate(deleting.id)}
      />

    </div>
  );
}
