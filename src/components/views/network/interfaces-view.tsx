"use client";

/**
 * #/network/interfaces — 4 tabs: Interfaces | LLDP Neighbors | MAC Table |
 * Mirroring (M02 §4). Live per-row rx/tx + 60-tick sparklines ride the
 * metrics:tick socket channel (ref map + debounced render tick);
 * config:updated (section=interfaces) invalidates the network queries.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import { useRealtime, type MetricsTickPayload } from "@/lib/realtime";
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
} from "@/components/views/firewall/fw-ui";
import {
  BOND_MODES,
  STP_MODES,
  IFACE_NAME_RE,
  NetApiError,
  fmtAge,
  fmtBytes,
  fmtKbps,
  fmtUptime,
  ifaceBodyOf,
  isValidIpv4,
  mirrorBodyOf,
  netApi,
  cfgBool,
  cfgNumber,
  cfgString,
  cfgStringArray,
  type BondMode,
  type Iface,
  type IfaceLive,
  type IfaceMode,
  type IfaceRole,
  type IfaceType,
  type IfaceBody,
  type ArpEntry,
  type OsRouteEntry,
  type DiagPingResult,
  type HostPort,
  type MacRow,
  type Mirror,
  type MirrorDirection,
  type OsApplyResp,
  type SecondaryIp,
  type StpMode,
  type ZoneRef,
} from "./net-api";
import {
  groupIssues,
  lintIface,
  suggestMssClamp,
  type IfaceRuleView,
} from "@/lib/network/iface-rules";
import {
  DirectionChip,
  IfaceConfigSummary,
  LinkDot,
  ModeChip,
  RoleBadge,
  Sparkline,
  TypeBadge,
} from "./net-ui";

const IFACES_KEY = ["network", "interfaces"] as const;
const LLDP_KEY = ["network", "lldp"] as const;
const MAC_KEY = ["network", "mac-table"] as const;
const MIRRORS_KEY = ["network", "port-mirrors"] as const;
const NET_ZONES_KEY = ["network", "zones"] as const;
const HOST_PORTS_KEY = ["network", "host-ports"] as const;
const ARP_KEY = ["network", "arp"] as const;
const OS_ROUTES_KEY = ["network", "os-routes"] as const;

/** Role semantics surfaced under the role select (enterprise UX). */
const ROLE_HINTS: Record<IfaceRole, string> = {
  wan: "Uplink toward the ISP — NAT source, multi-WAN probes attach here",
  lan: "Trusted internal segment — firewall zones typically allow LAN→WAN",
  dmz: "Isolated services segment — inbound publishing terminates here",
  vpn: "Tunnel/overlay terminations — IPsec, WireGuard, GRE endpoints",
  mgmt: "Administrative access (SSH/HTTPS) — never disabled to zero",
  unused: "No role assigned — safe default for spare ports",
};

const CREATE_TYPES: IfaceType[] = ["vlan", "bridge", "bond", "gre", "ipip", "loopback"];
const IFACE_TYPES: IfaceType[] = ["physical", "vlan", "bridge", "bond", "gre", "ipip", "loopback"];
const IFACE_ROLES: IfaceRole[] = ["wan", "lan", "dmz", "vpn", "mgmt", "unused"];
const SPEEDS = ["auto", "10", "100", "1000", "10000"] as const;
const DUPLEXES = ["half", "full"] as const;

/** Secondary-address rows editor — enterprise alias IPs (max 8). */
function SecondaryIpsEditor(props: {
  value: SecondaryIp[];
  onChange: (next: SecondaryIp[]) => void;
  disabled?: boolean;
}) {
  return (
    <div className="space-y-2">
      {props.value.length === 0 && (
        <p className="text-[11px] text-zinc-400">No secondary (alias) addresses.</p>
      )}
      {props.value.map((row, idx) => (
        <div key={idx} className="flex items-center gap-2">
          <Input
            value={row.ip}
            onChange={(e) => {
              const next = [...props.value];
              next[idx] = { ...row, ip: e.target.value };
              props.onChange(next);
            }}
            placeholder="192.168.30.10"
            className="h-8 font-mono text-xs"
            disabled={props.disabled}
            aria-label={`Secondary address ${idx + 1} IP`}
          />
          <Input
            type="number"
            min={1}
            max={32}
            value={Number.isFinite(row.cidrPrefix) ? row.cidrPrefix : ""}
            onChange={(e) => {
              const next = [...props.value];
              next[idx] = { ...row, cidrPrefix: Number(e.target.value) };
              props.onChange(next);
            }}
            placeholder="24"
            className="h-8 w-20 text-xs"
            disabled={props.disabled}
            aria-label={`Secondary address ${idx + 1} prefix`}
          />
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="h-8 w-8 shrink-0 text-rose-600 hover:text-rose-700 dark:text-rose-400"
            disabled={props.disabled}
            aria-label={`Remove secondary address ${idx + 1}`}
            onClick={() => props.onChange(props.value.filter((_, i) => i !== idx))}
          >
            <Icons.Trash2 className="h-3.5 w-3.5" />
          </Button>
        </div>
      ))}
      <Button
        type="button"
        variant="outline"
        size="sm"
        className="h-8"
        disabled={props.disabled || props.value.length >= 8}
        onClick={() => props.onChange([...props.value, { ip: "", cidrPrefix: 24 }])}
      >
        <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add address
      </Button>
      {props.value.length >= 8 && <p className="text-[11px] text-zinc-400">Maximum of 8 secondary addresses reached.</p>}
    </div>
  );
}
const SPARK_CAP = 60;

type SparkPoint = { ts: string; rxKbps: number; txKbps: number };

function useDebounced<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(t);
  }, [value, delayMs]);
  return debounced;
}

/** Shaped row → pure rule-engine view (client-side live validation). */
function ifaceToRuleView(i: Iface): IfaceRuleView {
  return {
    id: i.id,
    name: i.name,
    type: i.type,
    mode: i.mode,
    role: i.role,
    mtu: i.mtu,
    mssClamp: i.mssClamp,
    enabled: i.enabled,
    parentName: i.parentName,
    vlanId: i.vlanId,
    config: i.config ?? {},
  };
}

/** Shared scroll shell for the long tables (mirrors the M03 table wrapper). */
function ScrollWrap({ children }: { children: React.ReactNode }) {
  return (
    <div className="max-h-[480px] overflow-auto [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-zinc-300 dark:[&::-webkit-scrollbar-thumb]:bg-zinc-700">
      {children}
    </div>
  );
}

function InfoBanner(props: { title: string; children: React.ReactNode }) {
  return (
    <Alert className="border-zinc-500/30 bg-zinc-500/10 text-zinc-700 dark:text-zinc-300">
      <Icons.Info className="h-4 w-4" />
      <AlertTitle>{props.title}</AlertTitle>
      <AlertDescription>{props.children}</AlertDescription>
    </Alert>
  );
}

// ── main view ───────────────────────────────────────────────────────────────

export function InterfacesView() {
  const queryClient = useQueryClient();

  // realtime: per-iface rates + sparkline ring buffers (capped at 60 ticks) are
  // buffered in refs by the socket handler, then copied into state at most
  // every 300 ms — the debounced flush is what triggers the re-render.
  const ratesRef = useRef<Record<string, { rxKbps: number; txKbps: number }>>({});
  const sparksRef = useRef<Record<string, SparkPoint[]>>({});
  const flushRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [live, setLive] = useState<{
    rates: Record<string, { rxKbps: number; txKbps: number }>;
    sparks: Record<string, SparkPoint[]>;
  }>({ rates: {}, sparks: {} });

  const ifacesQuery = useQuery({ queryKey: IFACES_KEY, queryFn: () => netApi.listIfaces() });
  const zonesQuery = useQuery({ queryKey: NET_ZONES_KEY, queryFn: () => netApi.listZones() });

  useRealtime(["metrics", "config"], {
    onMetricsTick: (t: MetricsTickPayload) => {
      for (const row of t.ifaces) {
        ratesRef.current[row.name] = { rxKbps: row.rxKbps, txKbps: row.txKbps };
        const arr = sparksRef.current[row.name] ?? (sparksRef.current[row.name] = []);
        arr.push({ ts: t.ts, rxKbps: row.rxKbps, txKbps: row.txKbps });
        if (arr.length > SPARK_CAP) arr.splice(0, arr.length - SPARK_CAP);
      }
      if (flushRef.current) return;
      flushRef.current = setTimeout(() => {
        flushRef.current = null;
        setLive({
          rates: { ...ratesRef.current },
          sparks: Object.fromEntries(Object.entries(sparksRef.current).map(([k, v]) => [k, [...v]])),
        });
      }, 300);
    },
    onConfigUpdated: (c) => {
      if (c.section === "interfaces") {
        void queryClient.invalidateQueries({ queryKey: IFACES_KEY });
        void queryClient.invalidateQueries({ queryKey: MIRRORS_KEY });
        void queryClient.invalidateQueries({ queryKey: NET_ZONES_KEY });
      }
    },
  });

  const ifaces = useMemo(() => ifacesQuery.data?.data ?? [], [ifacesQuery.data]);
  const zones = useMemo(() => zonesQuery.data?.data ?? [], [zonesQuery.data]);
  const zoneNameById = useMemo(() => new Map(zones.map((z) => [z.id, z.name])), [zones]);

  const [tab, setTab] = useState("interfaces");
  const [typeFilter, setTypeFilter] = useState<IfaceType | "all">("all");
  const [roleFilter, setRoleFilter] = useState<IfaceRole | "all">("all");

  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<Iface | null>(null);
  const [statsIface, setStatsIface] = useState<Iface | null>(null);
  const [deleting, setDeleting] = useState<Iface | null>(null);
  const [pendingDisable, setPendingDisable] = useState<{
    iface: Iface;
    refs: Array<{ kind: string; label: string }>;
  } | null>(null);

  const [refsDialog, setRefsDialog] = useState<Iface | null>(null);
  const [plan, setPlan] = useState<OsApplyResp | null>(null);
  const [pingResult, setPingResult] = useState<{ target: string; result: DiagPingResult } | null>(null);

  const planMut = useMutation({
    mutationFn: (name: string) => netApi.applyIfaceOs(name),
    onSuccess: (d) => setPlan(d),
    onError: (err) => toastErr(err, "Apply plan failed"),
  });

  const pingMut = useMutation({
    mutationFn: (args: { host: string; iface: string }) => netApi.pingDiag(args.host, args.iface, 3),
    onSuccess: (r, args) => setPingResult({ target: `${args.host} via ${args.iface}`, result: r }),
    onError: (err) => toastErr(err, "Ping failed"),
  });

  const pingGateway = (iface: Iface) => {
    const gw = typeof iface.config["gateway"] === "string" ? (iface.config["gateway"] as string) : null;
    if (!gw) {
      toastErr(new NetApiError("VALIDATION_ERROR", `No gateway configured on ${iface.name}`), "Ping gateway");
      return;
    }
    pingMut.mutate({ host: gw, iface: iface.name });
  };

  const toggleMut = useMutation({
    mutationFn: ({ iface, force }: { iface: Iface; force?: boolean }) =>
      netApi.updateIface(
        iface.id,
        ifaceBodyOf(iface, { enabled: !iface.enabled, ...(force ? { force: true } : {}) }),
      ),
    onSuccess: (updated) => {
      toastOk(updated.enabled ? "Interface enabled" : "Interface disabled", updated.name);
      setPendingDisable(null);
    },
    onError: (err, vars) => {
      // 409 with reference list → confirmation flow instead of a bare toast
      if (err instanceof NetApiError && err.code === "CONFLICT") {
        const refs = (err.details as { refs?: Array<{ kind: string; label: string }> } | undefined)?.refs;
        if (refs && refs.length > 0) {
          setPendingDisable({ iface: vars.iface, refs });
          return;
        }
      }
      toastErr(err, "Toggle failed");
    },
    onSettled: () => void queryClient.invalidateQueries({ queryKey: IFACES_KEY }),
  });

  const deleteMut = useMutation({
    mutationFn: (id: number) => netApi.deleteIface(id),
    onSuccess: (_d, id) => {
      toastOk("Interface deleted", `#${id} and its references were cleaned up`);
      setDeleting(null);
    },
    onError: (err) => toastErr(err, "Delete failed"),
    onSettled: () => void queryClient.invalidateQueries({ queryKey: IFACES_KEY }),
  });

  const filtered = useMemo(() => {
    return ifaces.filter((i) => {
      if (typeFilter !== "all" && i.type !== typeFilter) return false;
      if (roleFilter !== "all" && i.role !== roleFilter) return false;
      return true;
    });
  }, [ifaces, typeFilter, roleFilter]);

  const openCreate = () => {
    setEditing(null);
    setEditorOpen(true);
  };
  const openEdit = (iface: Iface) => {
    setEditing(iface);
    setEditorOpen(true);
  };

  return (
    <Tabs value={tab} onValueChange={setTab} className="gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <TabsList aria-label="Network interface tabs">
          <TabsTrigger value="interfaces">Interfaces</TabsTrigger>
          <TabsTrigger value="diagnostics">Diagnostics</TabsTrigger>
          <TabsTrigger value="lldp">LLDP Neighbors</TabsTrigger>
          <TabsTrigger value="mac">MAC Table</TabsTrigger>
          <TabsTrigger value="mirroring">Mirroring</TabsTrigger>
        </TabsList>
        {tab === "interfaces" && (
          <Button size="sm" onClick={openCreate} className="bg-zinc-700 text-white hover:bg-zinc-800">
            <Icons.Plus className="mr-1 h-4 w-4" /> Add interface
          </Button>
        )}
        {tab === "mirroring" && <AddMirrorButton ifaces={ifaces} />}
      </div>

      <TabsContent value="interfaces" className="space-y-3">
        {/* filter chips row */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[11px] font-semibold uppercase tracking-wide text-zinc-400">Type</span>
          <Select value={typeFilter} onValueChange={(v) => setTypeFilter(v as IfaceType | "all")}>
            <SelectTrigger className="h-8 w-36" aria-label="Filter by interface type">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">all types</SelectItem>
              {IFACE_TYPES.map((t) => (
                <SelectItem key={t} value={t}>
                  {t}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <span className="ml-2 text-[11px] font-semibold uppercase tracking-wide text-zinc-400">Role</span>
          <Select value={roleFilter} onValueChange={(v) => setRoleFilter(v as IfaceRole | "all")}>
            <SelectTrigger className="h-8 w-32" aria-label="Filter by interface role">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">all roles</SelectItem>
              {IFACE_ROLES.map((r) => (
                <SelectItem key={r} value={r}>
                  {r}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {(typeFilter !== "all" || roleFilter !== "all") && (
            <Button
              size="sm"
              variant="ghost"
              className="h-8 px-2 text-xs text-zinc-500"
              onClick={() => {
                setTypeFilter("all");
                setRoleFilter("all");
              }}
            >
              <Icons.X className="mr-1 h-3 w-3" /> Clear ({filtered.length}/{ifaces.length})
            </Button>
          )}
        </div>

        <Card className="p-0">
          <CardContent className="p-0">
            {ifacesQuery.error ? (
              <div className="p-4">
                <QueryError error={ifacesQuery.error} onRetry={() => void ifacesQuery.refetch()} />
              </div>
            ) : ifacesQuery.isLoading ? (
              <div className="p-4">
                <TableSkeleton rows={7} cols={9} />
              </div>
            ) : ifaces.length === 0 ? (
              <EmptyBlock
                icon={<Icons.Cable className="h-6 w-6" />}
                title="No interfaces"
                description="No interfaces matched the current filters."
              />
            ) : (
              <ScrollWrap>
                <Table className="min-w-[1240px] text-sm">
                  <TableHeader className="sticky top-0 z-10 bg-card">
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead className="w-20">Role</TableHead>
                      <TableHead className="w-24">Zone</TableHead>
                      <TableHead>Address / config</TableHead>
                      <TableHead className="w-24">MTU / MSS</TableHead>
                      <TableHead className="w-28">Link</TableHead>
                      <TableHead className="w-14">Ref.</TableHead>
                      <TableHead className="w-36">MAC</TableHead>
                      <TableHead className="w-44">Live rx / tx</TableHead>
                      <TableHead className="w-24 pr-2 text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filtered.map((iface) => {
                      const liveRates = live.rates[iface.name] ?? { rxKbps: iface.rxKbps, txKbps: iface.txKbps };
                      const liveSparks = live.sparks[iface.name] ?? [];
                      return (
                        <TableRow key={iface.id} className={cn(!iface.enabled && "opacity-60")}>
                          <TableCell>
                            <div className="flex flex-col gap-1">
                              <span className="font-mono text-sm font-medium">
                                {iface.name}
                                {iface.live?.isDefaultRoute ? (
                                  <Badge variant="outline" className="ml-1.5 border-zinc-400 px-1 py-0 text-[9px] font-normal text-zinc-500">
                                    gw*
                                  </Badge>
                                ) : null}
                              </span>
                              <div className="flex items-center gap-1">
                                <TypeBadge type={iface.type} className="w-fit" />
                                {iface.mode === "l2" ? <ModeChip mode={iface.mode} /> : null}
                              </div>
                            </div>
                          </TableCell>
                          <TableCell>
                            <RoleBadge role={iface.role} />
                          </TableCell>
                          <TableCell className="text-xs text-zinc-500">
                            {iface.zoneName ?? zoneNameById.get(iface.zoneId ?? -1) ?? "—"}
                          </TableCell>
                          <TableCell>
                            <span className="inline-flex items-center gap-1">
                              <IfaceConfigSummary iface={iface} />
                              {mtuDrift(iface) ? (
                                <span
                                  className="inline-block h-1.5 w-1.5 shrink-0 rounded-full bg-amber-500"
                                  title={`MTU changed out-of-band — OS reports ${iface.live?.mtu}`}
                                />
                              ) : null}
                              {ipDrift(iface) ? (
                                <span
                                  className="inline-block h-1.5 w-1.5 shrink-0 rounded-full bg-amber-500"
                                  title={`Address changed out-of-band — OS reports ${(iface.live?.ipv4 ?? []).join(", ") || "none"}`}
                                />
                              ) : null}
                            </span>
                            {iface.description ? (
                              <p className="mt-0.5 max-w-56 truncate text-[11px] text-zinc-400">{iface.description}</p>
                            ) : null}
                          </TableCell>
                          <TableCell className="tabular-nums">
                            {iface.mtu}
                            {iface.mssClamp != null ? (
                              <span className="ml-1 text-[10px] font-medium text-zinc-500 dark:text-zinc-400">MSS {iface.mssClamp}</span>
                            ) : null}
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              {iface.enabled ? (
                                <LinkDot up={iface.linkUp} degraded={iface.degraded} />
                              ) : (
                                <LinkDot up={false} neutral />
                              )}
                              <span
                                className={cn(
                                  "font-mono text-[11px]",
                                  iface.enabled && iface.live
                                    ? iface.live.operState === "up"
                                      ? "text-emerald-600 dark:text-emerald-400"
                                      : iface.live.operState === "down"
                                        ? "text-rose-500"
                                        : "text-zinc-400"
                                    : "text-zinc-400",
                                )}
                              >
                                {iface.live ? iface.live.operState : iface.enabled ? iface.linkUp ? "up" : "down" : "off"}
                              </span>
                              <Switch
                                checked={iface.enabled}
                                disabled={toggleMut.isPending}
                                aria-label={`Toggle interface ${iface.name}`}
                                onCheckedChange={() => toggleMut.mutate({ iface })}
                              />
                            </div>
                          </TableCell>
                          <TableCell>
                            <RefsCell iface={iface} onOpen={(target) => setRefsDialog(target)} />
                          </TableCell>
                          <TableCell className="font-mono text-xs text-zinc-500">
                            {iface.live?.mac ?? "—"}
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <div className="w-24 shrink-0 text-right tabular-nums">
                                <span className="block text-xs text-rose-700 dark:text-rose-500">↓ {fmtKbps(liveRates.rxKbps)}</span>
                                <span className="block text-xs text-zinc-500 dark:text-zinc-400">↑ {fmtKbps(liveRates.txKbps)}</span>
                              </div>
                              <Sparkline points={liveSparks} />
                            </div>
                          </TableCell>
                          <TableCell className="pr-2 text-right">
                            <div className="flex items-center justify-end gap-0.5">
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-8 w-8"
                                aria-label={`Edit interface ${iface.name}`}
                                onClick={() => openEdit(iface)}
                              >
                                <Icons.Pencil className="h-3.5 w-3.5" />
                              </Button>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-8 w-8"
                                aria-label={`Stats for interface ${iface.name}`}
                                onClick={() => setStatsIface(iface)}
                              >
                                <Icons.Activity className="h-3.5 w-3.5" />
                              </Button>
                              <DropdownMenu>
                                <DropdownMenuTrigger asChild>
                                  <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={`More actions for ${iface.name}`}>
                                    <Icons.MoreVertical className="h-3.5 w-3.5" />
                                  </Button>
                                </DropdownMenuTrigger>
                                <DropdownMenuContent align="end" className="w-52">
                                  <DropdownMenuItem onClick={() => pingGateway(iface)}>
                                    <Icons.Radar className="mr-2 h-3.5 w-3.5" /> Ping gateway
                                  </DropdownMenuItem>
                                  <DropdownMenuItem onClick={() => setRefsDialog(iface)}>
                                    <Icons.ListTree className="mr-2 h-3.5 w-3.5" /> Search references
                                  </DropdownMenuItem>
                                  <DropdownMenuSeparator />
                                  <DropdownMenuItem onClick={() => planMut.mutate(iface.name)} disabled={planMut.isPending}>
                                    <Icons.Terminal className="mr-2 h-3.5 w-3.5" /> Preview apply plan
                                  </DropdownMenuItem>
                                </DropdownMenuContent>
                              </DropdownMenu>
                              {iface.type !== "physical" && (iface.refs?.count ?? 0) === 0 && (
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  className="h-8 w-8 text-rose-600 hover:text-rose-700 dark:text-rose-400"
                                  aria-label={`Delete interface ${iface.name}`}
                                  onClick={() => setDeleting(iface)}
                                >
                                  <Icons.Trash2 className="h-3.5 w-3.5" />
                                </Button>
                              )}
                            </div>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </ScrollWrap>
            )}
            {ifaces.length > 0 && filtered.length === 0 && (
              <div className="border-t border-zinc-200 px-4 py-6 text-center text-sm text-zinc-500 dark:border-zinc-800">
                No interfaces match the current filters.
              </div>
            )}
          </CardContent>
        </Card>
        <p className="flex items-center gap-1.5 text-xs text-zinc-400">
          <Icons.Info className="h-3.5 w-3.5" />
          Physical ports are never deletable — disable instead. Ref. = objects referencing the interface (delete is hidden while &gt; 0). Amber dots mark out-of-band kernel changes; apply is plan-preview on this install.
        </p>
      </TabsContent>

      <TabsContent value="diagnostics" className="space-y-3">
        <DiagnosticsTab ifaces={ifaces} />
      </TabsContent>

      <TabsContent value="lldp" className="space-y-3">
        <LldpTab />
      </TabsContent>

      <TabsContent value="mac" className="space-y-3">
        <MacTab ifaces={ifaces} />
      </TabsContent>

      <TabsContent value="mirroring" className="space-y-3">
        <MirrorsTab ifaces={ifaces} />
      </TabsContent>

      {editorOpen && (
        <IfaceEditor
          key={editing?.id ?? "new"}
          open={editorOpen}
          onOpenChange={setEditorOpen}
          editing={editing}
          ifaces={ifaces}
          zones={zones}
          onSaved={() => void queryClient.invalidateQueries({ queryKey: IFACES_KEY })}
        />
      )}

      <IfaceStatsDialog iface={statsIface} onOpenChange={(open) => !open && setStatsIface(null)} />

      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title="Delete interface?"
        description={`Delete interface '${deleting?.name ?? ""}'? Its zone membership is detached, routes pointing at it lose the interface reference, and an attached WAN policy is removed first.`}
        loading={deleteMut.isPending}
        onConfirm={() => deleting && deleteMut.mutate(deleting.id)}
      />

      <ConfirmDialog
        open={pendingDisable !== null}
        onOpenChange={(open) => !open && setPendingDisable(null)}
        title="Disable interface with active references?"
        description={`'${
          pendingDisable?.iface.name ?? ""
        }' is referenced by active configuration: ${
          pendingDisable?.refs.map((r) => `${r.kind} ${r.label}`).join(", ") ?? ""
        }. Disabling it takes those features down until the interface is re-enabled.`}
        confirmLabel="Disable anyway"
        loading={toggleMut.isPending}
        onConfirm={() =>
          pendingDisable && toggleMut.mutate({ iface: pendingDisable.iface, force: true })
        }
      />

      {/* Used-by dialog (FortiGate Ref. parity) */}
      <Dialog open={refsDialog !== null} onOpenChange={(open) => !open && setRefsDialog(null)}>
        <DialogContent className="w-[calc(100vw-1rem)] max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Icons.ListTree className="h-4 w-4 text-zinc-500" />
              Used by — {refsDialog?.name}
            </DialogTitle>
            <DialogDescription>
              Objects referencing this interface. Delete stays hidden while references exist.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-1.5">
            {(refsDialog?.refs?.count ?? 0) === 0 ? (
              <p className="py-4 text-center text-sm text-zinc-500">No references — safe to remove.</p>
            ) : (
              (refsDialog?.refs?.items ?? []).map((r, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between rounded-md border border-zinc-200 px-3 py-2 dark:border-zinc-800"
                >
                  <span className="text-[10px] font-semibold uppercase tracking-wide text-zinc-400">{r.kind}</span>
                  <span className="font-mono text-xs text-zinc-700 dark:text-zinc-200">{r.label}</span>
                </div>
              ))
            )}
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setRefsDialog(null)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ping result (per-row "Ping gateway") */}
      <Dialog open={pingResult !== null} onOpenChange={(open) => !open && setPingResult(null)}>
        <DialogContent className="w-[calc(100vw-1rem)] max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Icons.Radar className="h-4 w-4 text-zinc-500" />
              Ping — {pingResult?.target}
            </DialogTitle>
            <DialogDescription>Scoped ICMP probe from the interface (3 packets, 1 s wait).</DialogDescription>
          </DialogHeader>
          {pingResult && (
            <div className="space-y-3">
              <div className="flex items-center gap-3 text-sm">
                {pingResult.result.lossPct != null ? (
                  <Badge
                    variant="outline"
                    className={cn(
                      "text-xs",
                      pingResult.result.lossPct === 0
                        ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                        : "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
                    )}
                  >
                    loss {pingResult.result.lossPct}%
                  </Badge>
                ) : (
                  <Badge variant="outline" className="text-xs text-rose-500">failed</Badge>
                )}
                {pingResult.result.avgMs != null && (
                  <span className="tabular-nums text-zinc-600 dark:text-zinc-300">avg {pingResult.result.avgMs} ms</span>
                )}
              </div>
              <pre className="max-h-56 overflow-auto rounded-lg border border-zinc-200 bg-zinc-50 p-3 font-mono text-[11px] leading-snug dark:border-zinc-800 dark:bg-zinc-900">
                {pingResult.result.error ?? pingResult.result.output}
              </pre>
            </div>
          )}
          <DialogFooter>
            <Button variant="ghost" onClick={() => setPingResult(null)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* single-interface apply plan (gated preview / exec) */}
      <Dialog open={plan !== null} onOpenChange={(open) => !open && setPlan(null)}>
        <DialogContent className="max-h-[85vh] w-[calc(100vw-1rem)] overflow-y-auto sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Icons.Terminal className="h-4 w-4 text-zinc-500" />
              OS apply plan {plan?.applied ? "(executed)" : "(preview)"}
            </DialogTitle>
            <DialogDescription>{plan?.reason}</DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            {(plan?.plans ?? [])
              .filter((p) => p.steps.length > 0)
              .map((p) => (
                <div key={p.name} className="rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
                  <p className="mb-1.5 font-mono text-xs font-semibold">{p.name}</p>
                  <ul className="space-y-1">
                    {p.steps.map((s, i) => (
                      <li key={i} className="flex items-start gap-2 text-xs">
                        <span className="font-mono text-zinc-700 dark:text-zinc-300">$ {s.cmd}</span>
                        <span className="ml-auto shrink-0 text-[10px] text-zinc-400">{s.summary}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            {(plan?.plans ?? []).every((p) => p.steps.length === 0) && (
              <p className="text-sm text-zinc-500">No convergence steps needed — the host already matches the console.</p>
            )}
            {plan?.results && plan.results.length > 0 && (
              <div className="rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
                <p className="mb-1.5 text-xs font-semibold">Execution results</p>
                {plan.results.map((r, i) => (
                  <p key={i} className="flex items-center gap-2 font-mono text-xs">
                    {r.ok ? (
                      <Icons.CircleCheck className="h-3 w-3 text-emerald-500" />
                    ) : (
                      <Icons.CircleX className="h-3 w-3 text-rose-500" />
                    )}
                    <span className="truncate">{r.cmd}</span>
                    {!r.ok && r.stderr ? <span className="ml-auto text-[10px] text-rose-500">{r.stderr}</span> : null}
                  </p>
                ))}
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setPlan(null)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Tabs>
  );
}

/** Out-of-band change detectors — exceptions only, silence is healthy (vendor convention). */
function mtuDrift(iface: Iface): boolean {
  return iface.live?.mtu != null && iface.live.mtu !== iface.mtu;
}

function ipDrift(iface: Iface): boolean {
  const ip = typeof iface.config["ip"] === "string" ? (iface.config["ip"] as string) : null;
  if (!ip || iface.mode !== "l3" || !iface.live) return false;
  return !iface.live.ipv4.includes(ip);
}

/** FortiGate-style Ref. cell — count badge, click opens the "Used by" dialog. */
function RefsCell({ iface, onOpen }: { iface: Iface; onOpen: (i: Iface) => void }) {
  const count = iface.refs?.count ?? 0;
  return (
    <button
      type="button"
      onClick={() => onOpen(iface)}
      aria-label={`Show ${count} references of ${iface.name}`}
      title={count > 0 ? (iface.refs?.items ?? []).map((r) => `${r.kind} ${r.label}`).join(", ") : "No references"}
      className="inline-flex h-6 min-w-7 items-center justify-center rounded-md border border-zinc-200 px-1.5 text-xs tabular-nums text-zinc-600 transition-colors hover:border-zinc-400 dark:border-zinc-700 dark:text-zinc-300"
    >
      {count > 0 ? count : <span className="text-zinc-300 dark:text-zinc-600">0</span>}
    </button>
  );
}

function AddMirrorButton({ ifaces }: { ifaces: Iface[] }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button size="sm" onClick={() => setOpen(true)} className="bg-zinc-700 text-white hover:bg-zinc-800">
        <Icons.Plus className="mr-1 h-4 w-4" /> Add mirror
      </Button>
      <MirrorEditor open={open} onOpenChange={setOpen} ifaces={ifaces} />
    </>
  );
}

// ── iface create/edit dialog ────────────────────────────────────────────────

function IfaceEditor(props: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editing: Iface | null;
  ifaces: Iface[];
  zones: ZoneRef[];
  onSaved: () => void;
}) {
  const editing = props.editing;
  const isEdit = editing != null;

  const [type, setType] = useState<IfaceType>(editing?.type ?? "vlan");
  const [name, setName] = useState(editing?.name ?? "");
  const [nameTouched, setNameTouched] = useState(isEdit);
  const [mode, setMode] = useState<IfaceMode>(editing?.mode ?? "l3");
  const [role, setRole] = useState<IfaceRole>(editing?.role ?? "unused");
  const [zoneId, setZoneId] = useState(editing?.zoneId != null ? String(editing.zoneId) : "none");
  const [mtu, setMtu] = useState(String(editing?.mtu ?? 1500));
  const [mss, setMss] = useState(editing?.mssClamp != null ? String(editing.mssClamp) : "");
  const [description, setDescription] = useState(editing?.description ?? "");

  // type-specific state
  const [parentName, setParentName] = useState(editing?.parentName ?? "");
  const [vlanId, setVlanId] = useState(editing?.vlanId != null ? String(editing.vlanId) : "");
  const [members, setMembers] = useState<string[]>(cfgStringArray(editing?.config, "members"));
  const [stp, setStp] = useState(cfgBool(editing?.config, "stp"));
  const [stpMode, setStpMode] = useState<StpMode>(
    (cfgString(editing?.config, "stpMode") as StpMode | null) ?? "stp",
  );
  const [igmpSnooping, setIgmpSnooping] = useState(cfgBool(editing?.config, "igmpSnooping"));
  const [bondMode, setBondMode] = useState<BondMode>(
    (cfgString(editing?.config, "mode") as BondMode | null) ?? "active-backup",
  );
  const [local, setLocal] = useState(cfgString(editing?.config, "local") ?? "");
  const [remote, setRemote] = useState(cfgString(editing?.config, "remote") ?? "");
  const [ttl, setTtl] = useState(cfgNumber(editing?.config, "ttl")?.toString() ?? "");
  const [loIp, setLoIp] = useState(cfgString(editing?.config, "ip") ?? "");
  const [loPrefix, setLoPrefix] = useState(cfgNumber(editing?.config, "cidrPrefix")?.toString() ?? "32");

  // physical edit state
  const pppoeCfg = (editing?.config?.["pppoe"] ?? {}) as { user?: string; password?: string; service?: string };
  const [wanType, setWanType] = useState<"static" | "dhcp" | "pppoe">(
    (cfgString(editing?.config, "wanType") as "static" | "dhcp" | "pppoe" | null) ?? "static",
  );
  const [ip, setIp] = useState(cfgString(editing?.config, "ip") ?? "");
  const [prefix, setPrefix] = useState(cfgNumber(editing?.config, "cidrPrefix")?.toString() ?? "24");
  const [gateway, setGateway] = useState(cfgString(editing?.config, "gateway") ?? "");
  const [dnsRaw, setDnsRaw] = useState(
    Array.isArray(editing?.config?.["dns"]) ? (editing.config["dns"] as unknown[]).filter((d): d is string => typeof d === "string").join("\n") : "",
  );
  const [pppoeUser, setPppoeUser] = useState(pppoeCfg.user ?? "");
  const [pppoePassword, setPppoePassword] = useState(pppoeCfg.password ?? "");
  const [pppoeService, setPppoeService] = useState(pppoeCfg.service ?? "");
  const [lldp, setLldp] = useState(editing ? cfgBool(editing.config, "lldp") : true);

  // enterprise extras — secondary addresses, NIC hints, bond/bridge tuning
  const secCfg = Array.isArray(editing?.config?.["secondaryIps"])
    ? (editing.config["secondaryIps"] as SecondaryIp[])
    : [];
  const [secondaryIps, setSecondaryIps] = useState<SecondaryIp[]>(
    secCfg.map((s) => ({ ip: String(s.ip ?? ""), cidrPrefix: Number(s.cidrPrefix ?? 24) })),
  );
  const [speed, setSpeed] = useState<(typeof SPEEDS)[number]>(
    (cfgString(editing?.config, "speed") as (typeof SPEEDS)[number] | null) ?? "auto",
  );
  const [duplex, setDuplex] = useState<(typeof DUPLEXES)[number]>(
    (cfgString(editing?.config, "duplex") as (typeof DUPLEXES)[number] | null) ?? "full",
  );
  const [lacpRate, setLacpRate] = useState<"slow" | "fast">(
    (cfgString(editing?.config, "lacpRate") as "slow" | "fast" | null) ?? "slow",
  );
  const [miimon, setMiimon] = useState(cfgNumber(editing?.config, "miimon")?.toString() ?? "100");
  const [stpPriority, setStpPriority] = useState(cfgNumber(editing?.config, "stpPriority")?.toString() ?? "32768");
  const [forwardDelay, setForwardDelay] = useState(cfgNumber(editing?.config, "forwardDelay")?.toString() ?? "15");

  const [error, setError] = useState<string | null>(null);

  const applyVlanNameSuggestion = (nextType: IfaceType, nextVlanId: string, touched: boolean) => {
    if (nextType === "vlan" && !touched && /^\d+$/.test(nextVlanId)) setName(`vlan${nextVlanId}`);
  };

  const vlanParentOptions = useMemo(
    () => props.ifaces.filter((i) => ["physical", "bridge", "bond"].includes(i.type)),
    [props.ifaces],
  );
  const memberOptions = useMemo(
    () =>
      props.ifaces
        .filter((i) => ["physical", "vlan"].includes(i.type))
        .filter((i) => !isEdit || i.name !== editing.name)
        .map((i) => ({ id: i.name, label: i.name, sub: i.type })),
    [props.ifaces, isEdit, editing],
  );

  const mut = useMutation({
    mutationFn: (body: IfaceBody) =>
      isEdit && editing ? netApi.updateIface(editing.id, body) : netApi.createIface(body),
    onSuccess: (saved) => {
      toastOk(isEdit ? "Interface updated" : "Interface created", saved.name);
      props.onOpenChange(false);
      props.onSaved();
    },
    onError: (err) => toastErr(err, isEdit ? "Update failed" : "Create failed"),
  });

  // create-time flat addressing (vlan/bridge/bond) — mirrors ifaceCreateSchema
  const flatAddr = () => {
    const p = Number(prefix);
    const dnsList = dnsRaw
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    return {
      ...(isValidIpv4(ip) && Number.isInteger(p) && p >= 1 && p <= 32 ? { ip: ip.trim(), cidrPrefix: p } : {}),
      ...(isValidIpv4(gateway.trim()) ? { gateway: gateway.trim() } : {}),
      ...(dnsList.length ? { dns: dnsList } : {}),
      ...(secondaryIps.length ? { secondaryIps } : {}),
    };
  };
  // update-time config-patch addressing (vlan/bridge/bond)
  const patchAddr = (): Record<string, unknown> => {
    const p = Number(prefix);
    const dnsList = dnsRaw
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    const out: Record<string, unknown> = {};
    if (isValidIpv4(ip) && Number.isInteger(p) && p >= 1 && p <= 32) {
      out.ip = ip.trim();
      out.cidrPrefix = p;
    }
    if (isValidIpv4(gateway.trim())) out.gateway = gateway.trim();
    if (dnsList.length) out.dns = dnsList;
    out.secondaryIps = secondaryIps; // always sent so removals persist
    return out;
  };

  const buildBody = (): IfaceBody | string => {
    const trimmedName = name.trim();
    if (!IFACE_NAME_RE.test(trimmedName)) return "Name must be 1–15 chars of a-z, 0-9 or '-'";
    const mtuNum = Number(mtu);
    if (!Number.isInteger(mtuNum) || mtuNum < 68 || mtuNum > 9000) return "MTU must be an integer between 68 and 9000";
    let mssNum: number | null = null;
    if (mss.trim() !== "") {
      mssNum = Number(mss);
      if (!Number.isInteger(mssNum) || mssNum < 536 || mssNum > 1460) return "MSS clamp must be between 536 and 1460";
    }
    const zone = zoneId === "none" ? null : Number(zoneId);

    const common = {
      role,
      zoneId: zone,
      mtu: mtuNum,
      ...(mssNum != null ? { mssClamp: mssNum } : {}),
      description: description.trim() || null,
    };

    if (!isEdit) {
      // CREATE — flat per-type payloads (validators/network.ts ifaceCreateSchema)
      switch (type) {
        case "vlan": {
          if (!parentName) return "A parent interface is required for a VLAN";
          const v = Number(vlanId);
          if (!Number.isInteger(v) || v < 1 || v > 4094) return "VLAN ID must be an integer between 1 and 4094";
          return { type, name: trimmedName, parent: parentName, vlanId: v, enabled: true, mode, ...common, ...flatAddr() };
        }
        case "bridge": {
          if (members.length < 1) return "A bridge needs at least 1 member";
          const stpPriorityNum = Number(stpPriority);
          const forwardDelayNum = Number(forwardDelay);
          return {
            type,
            name: trimmedName,
            members,
            stp,
            ...(stp ? { stpMode } : {}),
            ...(stp && Number.isInteger(stpPriorityNum) ? { stpPriority: stpPriorityNum } : {}),
            ...(stp && Number.isInteger(forwardDelayNum) ? { forwardDelay: forwardDelayNum } : {}),
            igmpSnooping,
            enabled: true,
            mode,
            ...common,
            ...flatAddr(),
          };
        }
        case "bond": {
          if (members.length < 2) return "bond needs at least 2 members";
          const miimonNum = Number(miimon);
          // on create a bond's `mode` IS the aggregation mode (l2|l3 defaults l3, settable via PUT)
          return {
            type,
            name: trimmedName,
            members,
            mode: bondMode,
            ...(bondMode === "802.3ad" ? { lacpRate } : {}),
            ...(Number.isInteger(miimonNum) ? { miimon: miimonNum } : {}),
            enabled: true,
            ...common,
            ...flatAddr(),
          };
        }
        case "gre":
        case "ipip": {
          if (!isValidIpv4(local)) return "A valid local tunnel IPv4 is required";
          if (!isValidIpv4(remote)) return "A valid remote tunnel IPv4 is required";
          if (local.trim() === remote.trim()) return "Tunnel local and remote addresses must differ";
          let ttlNum: number | null = null;
          if (type === "gre" && ttl.trim() !== "") {
            ttlNum = Number(ttl);
            if (!Number.isInteger(ttlNum) || ttlNum < 1 || ttlNum > 255)
              return "TTL must be an integer between 1 and 255";
          }
          return {
            type,
            name: trimmedName,
            local: local.trim(),
            remote: remote.trim(),
            ...(ttlNum != null ? { ttl: ttlNum } : {}),
            enabled: true,
            mode,
            ...common,
          };
        }
        case "loopback": {
          if (mode === "l3") {
            if (!isValidIpv4(loIp)) return "A valid loopback IPv4 is required";
            const p = Number(loPrefix);
            if (!Number.isInteger(p) || p < 0 || p > 32) return "Loopback prefix must be between 0 and 32";
            return { type, name: trimmedName, ip: loIp.trim(), cidrPrefix: p, enabled: true, mode, ...common };
          }
          return { type, name: trimmedName, enabled: true, mode, ...common };
        }
        default:
          return "Physical interfaces are provisioned by the appliance";
      }
    }

    // UPDATE — flat schema (ifaceUpdateSchema): physical WAN fields top-level,
    // logical per-type fields ride the validated `config` patch.
    if (editing.type === "physical") {
      if (mode === "l3") {
        if (wanType === "static") {
          if (!isValidIpv4(ip)) return "A valid IPv4 address is required for static WAN";
          if (gateway.trim() !== "" && !isValidIpv4(gateway)) return "Gateway must be a valid IPv4 address";
          const dnsList = dnsRaw
            .split("\n")
            .map((s) => s.trim())
            .filter(Boolean);
          return {
            name: editing.name,
            mode,
            enabled: editing.enabled,
            ...common,
            wanType,
            ip: ip.trim(),
            cidrPrefix: Number(prefix),
            ...(gateway.trim() !== "" ? { gateway: gateway.trim() } : { gateway: null }),
            ...(dnsList.length ? { dns: dnsList } : {}),
            secondaryIps,
            speed,
            duplex,
            lldp,
          };
        }
        if (wanType === "pppoe") {
          if (!pppoeUser.trim()) return "PPPoE user is required";
          return {
            name: editing.name,
            mode,
            enabled: editing.enabled,
            ...common,
            wanType,
            pppoe: {
              user: pppoeUser.trim(),
              password: pppoePassword,
              ...(pppoeService.trim() !== "" ? { service: pppoeService.trim() } : {}),
            },
            speed,
            duplex,
            lldp,
          };
        }
        return { name: editing.name, mode, enabled: editing.enabled, ...common, wanType: "dhcp", speed, duplex, lldp };
      }
      // l2 physical — switching only
      return { name: editing.name, mode, enabled: editing.enabled, ...common, speed, duplex, lldp };
    }

    const patch: Record<string, unknown> = {};
    if (type === "vlan") {
      if (!parentName) return "A parent interface is required for a VLAN";
      patch.parent = parentName;
      Object.assign(patch, patchAddr());
    }
    if (type === "bridge") {
      if (members.length < 1) return "A bridge needs at least 1 member";
      patch.members = members;
      patch.stp = stp;
      if (stp) {
        patch.stpMode = stpMode;
        const stpPriorityNum = Number(stpPriority);
        const forwardDelayNum = Number(forwardDelay);
        if (Number.isInteger(stpPriorityNum)) patch.stpPriority = stpPriorityNum;
        if (Number.isInteger(forwardDelayNum)) patch.forwardDelay = forwardDelayNum;
      }
      patch.igmpSnooping = igmpSnooping;
      Object.assign(patch, patchAddr());
    }
    if (type === "bond") {
      if (members.length < 2) return "bond needs at least 2 members";
      patch.members = members;
      patch.mode = bondMode;
      if (bondMode === "802.3ad") patch.lacpRate = lacpRate;
      const miimonNum = Number(miimon);
      if (Number.isInteger(miimonNum)) patch.miimon = miimonNum;
      Object.assign(patch, patchAddr());
    }
    if ((type === "gre" || type === "ipip") && mode === "l3") {
      if (!isValidIpv4(local)) return "A valid local tunnel IPv4 is required";
      if (!isValidIpv4(remote)) return "A valid remote tunnel IPv4 is required";
      if (local.trim() === remote.trim()) return "Tunnel local and remote addresses must differ";
      patch.local = local.trim();
      patch.remote = remote.trim();
      if (type === "gre" && ttl.trim() !== "") {
        const ttlNum = Number(ttl);
        if (!Number.isInteger(ttlNum) || ttlNum < 1 || ttlNum > 255) return "TTL must be an integer between 1 and 255";
        patch.ttl = ttlNum;
      }
    }
    if (type === "loopback" && mode === "l3") {
      if (!isValidIpv4(loIp)) return "A valid loopback IPv4 is required";
      const p = Number(loPrefix);
      if (!Number.isInteger(p) || p < 0 || p > 32) return "Loopback prefix must be between 0 and 32";
      patch.ip = loIp.trim();
      patch.cidrPrefix = p;
    }
    return {
      ...(trimmedName !== editing.name ? { name: trimmedName } : {}),
      mode,
      enabled: editing.enabled,
      ...common,
      ...(Object.keys(patch).length ? { config: patch } : {}),
    };
  };
  const submit = () => {
    const result = buildBody();
    if (typeof result === "string") {
      setError(result);
      return;
    }
    setError(null);
    mut.mutate(result);
  };

  const mtuNum = Number(mtu);
  const showMssHint = role === "wan" && Number.isFinite(mtuNum) && mtuNum < 1500 && mss.trim() === "";
  const isPhysicalEdit = isEdit && editing.type === "physical";
  const showWanFields = isPhysicalEdit && mode === "l3";
  const l3Editable = mode === "l3";

  // ── live business-rule validation (same engine the API enforces) ──────────
  const dnsListForLint = dnsRaw
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
  const lintConfig: Record<string, unknown> = {};
  if (type === "vlan") {
    if (parentName) lintConfig.parent = parentName;
    Object.assign(lintConfig, patchAddr());
  } else if (type === "bridge") {
    lintConfig.members = members;
    lintConfig.stp = stp;
    if (stp) {
      lintConfig.stpMode = stpMode;
      const sp = Number(stpPriority);
      if (Number.isInteger(sp)) lintConfig.stpPriority = sp;
      const fd = Number(forwardDelay);
      if (Number.isInteger(fd)) lintConfig.forwardDelay = fd;
    }
    lintConfig.igmpSnooping = igmpSnooping;
    Object.assign(lintConfig, patchAddr());
  } else if (type === "bond") {
    lintConfig.members = members;
    lintConfig.mode = bondMode;
    if (bondMode === "802.3ad") lintConfig.lacpRate = lacpRate;
    const mm = Number(miimon);
    if (Number.isInteger(mm)) lintConfig.miimon = mm;
    Object.assign(lintConfig, patchAddr());
  } else if (type === "gre" || type === "ipip") {
    lintConfig.local = local.trim();
    lintConfig.remote = remote.trim();
    if (type === "gre" && ttl.trim() !== "") lintConfig.ttl = Number(ttl);
  } else if (type === "loopback") {
    if (isValidIpv4(loIp)) {
      lintConfig.ip = loIp.trim();
      lintConfig.cidrPrefix = Number(loPrefix) || 0;
    }
  } else if (isPhysicalEdit) {
    if (mode === "l3" && wanType === "static") {
      if (isValidIpv4(ip)) {
        lintConfig.ip = ip.trim();
        lintConfig.cidrPrefix = Number(prefix);
      }
      if (isValidIpv4(gateway.trim())) lintConfig.gateway = gateway.trim();
      if (dnsListForLint.length) lintConfig.dns = dnsListForLint;
    }
    if (mode === "l3") lintConfig.wanType = wanType;
    lintConfig.lldp = lldp;
    lintConfig.speed = speed;
    lintConfig.duplex = duplex;
  }
  if (secondaryIps.length && (isPhysicalEdit ? mode === "l3" : type !== "gre" && type !== "ipip" && type !== "loopback")) {
    lintConfig.secondaryIps = secondaryIps;
  }
  const lintSelf: IfaceRuleView = {
    id: editing?.id,
    name: name.trim(),
    type,
    mode: type === "bond" ? "l3" : mode,
    role,
    mtu: Number.isFinite(mtuNum) ? mtuNum : 1500,
    mssClamp: mss.trim() !== "" && Number.isFinite(Number(mss)) ? Number(mss) : null,
    enabled: isEdit ? editing.enabled : true,
    parentName: type === "vlan" ? parentName || null : null,
    vlanId: type === "vlan" && /^\d+$/.test(vlanId) ? Number(vlanId) : null,
    config: lintConfig,
  };
  const lintOthers = useMemo(
    () => props.ifaces.filter((i) => i.name !== editing?.name).map(ifaceToRuleView),
    [props.ifaces, editing],
  );
  const lintIssues = lintIface({ self: lintSelf, others: lintOthers, roleFrom: null });
  const lintGrouped = groupIssues(lintIssues);
  const lintErrorCount = Object.keys(lintGrouped.errors).length;
  const lintWarningCount = Object.keys(lintGrouped.warnings).length;

  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent className="max-h-[90vh] w-[calc(100vw-1rem)] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{isEdit ? `Edit interface — ${editing.name}` : "Add interface"}</DialogTitle>
          <DialogDescription>
            {isEdit
              ? "Changes re-apply the interfaces section of the appliance config."
              : "Logical interfaces only — physical ports are provisioned by the platform and can be disabled but never deleted."}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {!isEdit && (
            <div>
              <FieldLabel hint="gates the fields below">Type</FieldLabel>
              <Select
                value={type}
                onValueChange={(v) => {
                  const t = v as IfaceType;
                  setType(t);
                  applyVlanNameSuggestion(t, vlanId, nameTouched);
                }}
              >
                <SelectTrigger aria-label="Interface type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CREATE_TYPES.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}

          <div className="grid grid-cols-2 gap-3">
            <div>
              <FieldLabel hint="^[a-z0-9-]{1,15}$">Name</FieldLabel>
              <Input
                value={name}
                onChange={(e) => {
                  setName(e.target.value);
                  setNameTouched(true);
                }}
                placeholder={type === "vlan" ? "vlan10" : "br-lan"}
                className="font-mono"
                aria-label="Interface name"
              />
            </div>
            <div>
              <FieldLabel>Role</FieldLabel>
              <Select value={role} onValueChange={(v) => setRole(v as IfaceRole)}>
                <SelectTrigger aria-label="Interface role">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {IFACE_ROLES.map((r) => (
                    <SelectItem key={r} value={r}>
                      {r}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="mt-1 text-[11px] leading-snug text-zinc-400" aria-live="polite">
                {ROLE_HINTS[role]}
              </p>
            </div>
          </div>

          {/* type-specific sections */}
          {type === "vlan" && (
            <EditorSection title="VLAN">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <FieldLabel hint="physical / bridge / bond">Parent</FieldLabel>
                  <Select value={parentName || undefined} onValueChange={setParentName}>
                    <SelectTrigger aria-label="VLAN parent interface">
                      <SelectValue placeholder="select parent…" />
                    </SelectTrigger>
                    <SelectContent>
                      {vlanParentOptions.map((p) => (
                        <SelectItem key={p.id} value={p.name}>
                          {p.name} ({p.type})
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <FieldLabel hint="1–4094">VLAN ID</FieldLabel>
                  <Input
                    type="number"
                    min={1}
                    max={4094}
                    value={vlanId}
                    onChange={(e) => {
                      setVlanId(e.target.value);
                      applyVlanNameSuggestion(type, e.target.value, nameTouched);
                    }}
                    placeholder="10"
                    aria-label="VLAN ID"
                  />
                </div>
              </div>
              <p className="text-[11px] text-zinc-400">Name auto-suggests to vlan&lt;id&gt; until you edit it manually.</p>
            </EditorSection>
          )}

          {type === "bridge" && (
            <EditorSection title="Bridge">
              <div>
                <FieldLabel hint={members.length === 0 ? "at least 1 member" : `${members.length} selected`}>Members</FieldLabel>
                <PopoverMulti
                  options={memberOptions}
                  selected={members}
                  onChange={setMembers}
                  triggerLabel="Pick members"
                  placeholder="Filter interfaces…"
                  icon={<Icons.Network className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />}
                />
              </div>
              <div className="flex flex-wrap items-center gap-4">
                <Label className="flex items-center gap-2 text-sm">
                  <Switch checked={stp} onCheckedChange={setStp} aria-label="Toggle STP" /> STP
                </Label>
                {stp && (
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-zinc-500">mode</span>
                    <Select value={stpMode} onValueChange={(v) => setStpMode(v as StpMode)}>
                      <SelectTrigger className="h-8 w-28" aria-label="STP mode">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {STP_MODES.map((m) => (
                          <SelectItem key={m} value={m}>
                            {m}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                )}
                <Label className="flex items-center gap-2 text-sm">
                  <Switch checked={igmpSnooping} onCheckedChange={setIgmpSnooping} aria-label="Toggle IGMP snooping" /> IGMP snooping
                </Label>
              </div>
              {stp && (
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <FieldLabel hint="0–65535, lower = root">STP priority</FieldLabel>
                    <Input
                      type="number"
                      min={0}
                      max={65535}
                      value={stpPriority}
                      onChange={(e) => setStpPriority(e.target.value)}
                      aria-label="STP bridge priority"
                    />
                  </div>
                  <div>
                    <FieldLabel hint="4–30 s">Forward delay</FieldLabel>
                    <Input
                      type="number"
                      min={4}
                      max={30}
                      value={forwardDelay}
                      onChange={(e) => setForwardDelay(e.target.value)}
                      aria-label="STP forward delay"
                    />
                  </div>
                </div>
              )}
            </EditorSection>
          )}

          {type === "bond" && (
            <EditorSection title="Bond">
              <div>
                <FieldLabel hint={members.length < 2 ? "at least 2 members" : `${members.length} selected`}>Members</FieldLabel>
                <PopoverMulti
                  options={memberOptions}
                  selected={members}
                  onChange={setMembers}
                  triggerLabel="Pick members"
                  placeholder="Filter interfaces…"
                  icon={<Icons.Link2 className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />}
                />
              </div>
              <div>
                <FieldLabel>Mode</FieldLabel>
                <Select value={bondMode} onValueChange={(v) => setBondMode(v as BondMode)}>
                  <SelectTrigger aria-label="Bond mode">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {BOND_MODES.map((m) => (
                      <SelectItem key={m} value={m}>
                        {m}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <FieldLabel hint="802.3ad only">LACP rate</FieldLabel>
                  <Select value={lacpRate} onValueChange={(v) => setLacpRate(v as "slow" | "fast")} disabled={bondMode !== "802.3ad"}>
                    <SelectTrigger aria-label="LACP rate">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="slow">slow (30 s)</SelectItem>
                      <SelectItem value="fast">fast (1 s)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <FieldLabel hint="0 = off, ms">MII monitor</FieldLabel>
                  <Input
                    type="number"
                    min={0}
                    max={1000}
                    value={miimon}
                    onChange={(e) => setMiimon(e.target.value)}
                    aria-label="Bond MII monitor interval"
                  />
                </div>
              </div>
            </EditorSection>
          )}

          {(type === "gre" || type === "ipip") && (
            <EditorSection title={type === "gre" ? "GRE tunnel" : "IPIP tunnel (proto-41)"}>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <FieldLabel>Local IPv4</FieldLabel>
                  <Input
                    value={local}
                    onChange={(e) => setLocal(e.target.value)}
                    placeholder="203.0.113.2"
                    disabled={!l3Editable}
                    className="font-mono"
                    aria-label="Tunnel local IPv4"
                  />
                </div>
                <div>
                  <FieldLabel>Remote IPv4</FieldLabel>
                  <Input
                    value={remote}
                    onChange={(e) => setRemote(e.target.value)}
                    placeholder="198.51.100.7"
                    disabled={!l3Editable}
                    className="font-mono"
                    aria-label="Tunnel remote IPv4"
                  />
                </div>
              </div>
              {type === "gre" && (
                <div className="w-32">
                  <FieldLabel hint="1–255">TTL</FieldLabel>
                  <Input
                    type="number"
                    min={1}
                    max={255}
                    value={ttl}
                    onChange={(e) => setTtl(e.target.value)}
                    placeholder="64"
                    disabled={!l3Editable}
                    aria-label="GRE TTL"
                  />
                </div>
              )}
              {!l3Editable && <p className="text-[11px] text-amber-600 dark:text-amber-400">L2 mode hides tunnel addressing.</p>}
            </EditorSection>
          )}

          {type === "loopback" && (
            <EditorSection title="Loopback address">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <FieldLabel>IPv4</FieldLabel>
                  <Input
                    value={loIp}
                    onChange={(e) => setLoIp(e.target.value)}
                    placeholder="10.255.0.1"
                    disabled={!l3Editable}
                    className="font-mono"
                    aria-label="Loopback IPv4"
                  />
                </div>
                <div>
                  <FieldLabel hint="0–32">Prefix</FieldLabel>
                  <Input
                    type="number"
                    min={0}
                    max={32}
                    value={loPrefix}
                    onChange={(e) => setLoPrefix(e.target.value)}
                    disabled={!l3Editable}
                    aria-label="Loopback prefix"
                  />
                </div>
              </div>
            </EditorSection>
          )}

          {isPhysicalEdit && (
            <EditorSection title="WAN addressing">
              <RadioGroup
                value={wanType}
                onValueChange={(v) => setWanType(v as "static" | "dhcp" | "pppoe")}
                disabled={!l3Editable}
                className="flex gap-4"
              >
                {(["static", "dhcp", "pppoe"] as const).map((wt) => (
                  <Label key={wt} className="flex cursor-pointer items-center gap-2 text-sm">
                    <RadioGroupItem value={wt} /> {wt}
                  </Label>
                ))}
              </RadioGroup>

              {showWanFields && wanType === "static" && (
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <FieldLabel>IPv4</FieldLabel>
                    <Input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="203.0.113.2" className="font-mono" aria-label="Static IPv4" />
                  </div>
                  <div>
                    <FieldLabel hint="0–32">Prefix</FieldLabel>
                    <Input type="number" min={0} max={32} value={prefix} onChange={(e) => setPrefix(e.target.value)} aria-label="Static prefix" />
                  </div>
                  <div>
                    <FieldLabel hint="must sit inside the subnet">Gateway</FieldLabel>
                    <Input value={gateway} onChange={(e) => setGateway(e.target.value)} placeholder="203.0.113.1" className="font-mono" aria-label="Gateway" />
                  </div>
                  <div className="col-span-2">
                    <FieldLabel hint="one per line">DNS servers</FieldLabel>
                    <Textarea
                      value={dnsRaw}
                      onChange={(e) => setDnsRaw(e.target.value)}
                      rows={3}
                      placeholder={"1.1.1.1\n8.8.8.8"}
                      className="font-mono text-xs"
                      aria-label="DNS servers"
                    />
                  </div>
                  <div className="col-span-2">
                    <FieldLabel hint="aliases, max 8">Secondary addresses</FieldLabel>
                    <SecondaryIpsEditor value={secondaryIps} onChange={setSecondaryIps} disabled={!l3Editable} />
                  </div>
                </div>
              )}
              {showWanFields && wanType === "dhcp" && (
                <p className="text-xs text-zinc-500">
                  Addressing is leased from the upstream network — no static fields apply. Hostname override is not exposed in Phase 1.
                </p>
              )}
              {showWanFields && wanType === "pppoe" && (
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <FieldLabel>User</FieldLabel>
                    <Input value={pppoeUser} onChange={(e) => setPppoeUser(e.target.value)} autoComplete="off" aria-label="PPPoE user" />
                  </div>
                  <div>
                    <FieldLabel>Password</FieldLabel>
                    <Input type="password" value={pppoePassword} onChange={(e) => setPppoePassword(e.target.value)} autoComplete="new-password" aria-label="PPPoE password" />
                  </div>
                  <div className="col-span-2">
                    <FieldLabel hint="optional">Service name</FieldLabel>
                    <Input value={pppoeService} onChange={(e) => setPppoeService(e.target.value)} aria-label="PPPoE service" />
                  </div>
                </div>
              )}
              {!l3Editable && (
                <p className="text-[11px] text-amber-600 dark:text-amber-400">
                  L2 mode: this port switches — WAN/IP addressing is disabled and stripped on save.
                </p>
              )}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <FieldLabel hint="NIC-dependent, apply best-effort">Speed</FieldLabel>
                  <Select value={speed} onValueChange={(v) => setSpeed(v as (typeof SPEEDS)[number])}>
                    <SelectTrigger aria-label="Port speed">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {SPEEDS.map((s) => (
                        <SelectItem key={s} value={s}>
                          {s === "auto" ? "auto-negotiate" : `${s} Mbps`}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <FieldLabel>Duplex</FieldLabel>
                  <Select value={duplex} onValueChange={(v) => setDuplex(v as (typeof DUPLEXES)[number])}>
                    <SelectTrigger aria-label="Port duplex">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {DUPLEXES.map((d) => (
                        <SelectItem key={d} value={d}>
                          {d}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <Label className="flex items-center gap-2 text-sm">
                <Switch checked={lldp} onCheckedChange={setLldp} aria-label="Toggle LLDP transmit" /> LLDP transmit (lldpd)
              </Label>
            </EditorSection>
          )}

          {isPhysicalEdit && mode === "l3" && wanType !== "static" && (
            <p className="text-[11px] text-zinc-400">
              Secondary alias addresses apply to statically addressed interfaces — switch to static to manage them here.
            </p>
          )}

          {/* L3 addressing for logical interfaces (vlan / bridge / bond) */}
          {(type === "vlan" || type === "bridge" || type === "bond") && l3Editable && (
            <EditorSection title="Addressing (L3)">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <FieldLabel hint="optional">IPv4</FieldLabel>
                  <Input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="10.20.30.1" className="font-mono" aria-label="Logical interface IPv4" />
                </div>
                <div>
                  <FieldLabel hint="1–32">Prefix</FieldLabel>
                  <Input type="number" min={1} max={32} value={prefix} onChange={(e) => setPrefix(e.target.value)} aria-label="Logical interface prefix" />
                </div>
                <div>
                  <FieldLabel hint="must sit inside the subnet">Gateway</FieldLabel>
                  <Input value={gateway} onChange={(e) => setGateway(e.target.value)} placeholder="10.20.30.254" className="font-mono" aria-label="Logical interface gateway" />
                </div>
                <div className="col-span-2">
                  <FieldLabel hint="one per line, max 4">DNS servers</FieldLabel>
                  <Textarea
                    value={dnsRaw}
                    onChange={(e) => setDnsRaw(e.target.value)}
                    rows={2}
                    placeholder={"1.1.1.1\n8.8.8.8"}
                    className="font-mono text-xs"
                    aria-label="Logical interface DNS servers"
                  />
                </div>
                <div className="col-span-2">
                  <FieldLabel hint="aliases, max 8">Secondary addresses</FieldLabel>
                  <SecondaryIpsEditor value={secondaryIps} onChange={setSecondaryIps} />
                </div>
              </div>
              <p className="text-[11px] text-zinc-400">
                Subnets must not overlap any other L3 interface — the same rule engine that enforces this server-side runs live here.
              </p>
            </EditorSection>
          )}

          <EditorSection title="Common">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <FieldLabel>Zone</FieldLabel>
                <Select value={zoneId} onValueChange={setZoneId}>
                  <SelectTrigger aria-label="Zone assignment">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">no zone</SelectItem>
                    {props.zones.map((z) => (
                      <SelectItem key={z.id} value={String(z.id)}>
                        {z.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <FieldLabel>Mode</FieldLabel>
                <RadioGroup value={mode} onValueChange={(v) => setMode(v as IfaceMode)} className="flex gap-4 pt-1">
                  <Label className="flex cursor-pointer items-center gap-2 text-sm">
                    <RadioGroupItem value="l3" /> L3 (route)
                  </Label>
                  <Label className="flex cursor-pointer items-center gap-2 text-sm">
                    <RadioGroupItem value="l2" /> L2 (switch)
                  </Label>
                </RadioGroup>
              </div>
              <div>
                <FieldLabel hint="68–9000">MTU</FieldLabel>
                <Input type="number" min={68} max={9000} value={mtu} onChange={(e) => setMtu(e.target.value)} aria-label="MTU" />
              </div>
              <div>
                <FieldLabel hint="536–1460, optional">MSS clamp</FieldLabel>
                <div className="flex items-center gap-2">
                  <Input type="number" min={536} max={1460} value={mss} onChange={(e) => setMss(e.target.value)} placeholder="—" aria-label="MSS clamp" />
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="h-9 shrink-0"
                    disabled={!Number.isInteger(mtuNum) || mtuNum < 68 || mtuNum > 9000}
                    onClick={() => {
                      const s = suggestMssClamp(mtuNum);
                      if (s != null) setMss(String(s));
                    }}
                    aria-label="Auto-derive MSS clamp from MTU"
                  >
                    auto (mtu-40)
                  </Button>
                </div>
              </div>
            </div>
            {showMssHint && (
              <p className="flex items-center gap-1.5 text-xs text-amber-600 dark:text-amber-400">
                <Icons.TriangleAlert className="h-3.5 w-3.5" />
                Set an MSS clamp for tunneling/PPPoE links
              </p>
            )}
            <div>
              <FieldLabel hint="optional">Description</FieldLabel>
              <Textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2} aria-label="Description" />
            </div>
          </EditorSection>

          {/* live business-rule validation (mirror of the server engine) */}
          {(lintErrorCount > 0 || lintWarningCount > 0) && (
            <div className="space-y-1.5 rounded-lg border border-zinc-200 p-3 dark:border-zinc-800" aria-live="polite">
              <p className="text-[11px] font-semibold uppercase tracking-wide text-zinc-400">
                Business rules — {lintErrorCount} error{lintErrorCount === 1 ? "" : "s"}, {lintWarningCount} warning{lintWarningCount === 1 ? "" : "s"}
              </p>
              {lintIssues
                .filter((i) => i.severity === "error")
                .map((i, idx) => (
                  <p key={`err-${idx}`} className="flex items-start gap-1.5 text-xs font-medium text-rose-600 dark:text-rose-400">
                    <Icons.CircleX className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                    <span>
                      <span className="font-mono text-[10px] opacity-70">{i.code}</span> {i.message}
                    </span>
                  </p>
                ))}
              {lintIssues
                .filter((i) => i.severity === "warning")
                .map((i, idx) => (
                  <p key={`warn-${idx}`} className="flex items-start gap-1.5 text-xs text-amber-600 dark:text-amber-400">
                    <Icons.TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                    <span>
                      <span className="font-mono text-[10px] opacity-70">{i.code}</span> {i.message}
                    </span>
                  </p>
                ))}
            </div>
          )}

          {error && <p className="text-xs font-medium text-rose-600 dark:text-rose-400">{error}</p>}
        </div>

        <DialogFooter>
          <Button variant="ghost" onClick={() => props.onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={submit}
            disabled={mut.isPending || lintErrorCount > 0}
            className="bg-amber-700 text-white hover:bg-amber-800"
          >
            {mut.isPending ? "Saving…" : isEdit ? "Save changes" : "Create interface"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── stats dialog ────────────────────────────────────────────────────────────

function IfaceStatsDialog(props: { iface: Iface | null; onOpenChange: (open: boolean) => void }) {
  const open = props.iface != null;
  const ifaceId = props.iface?.id ?? 0;
  const statsQuery = useQuery({
    queryKey: ["network", "interfaces", ifaceId, "stats"],
    queryFn: () => netApi.ifaceStats(ifaceId),
    enabled: open,
    refetchInterval: 5000,
  });
  const stats = statsQuery.data;

  return (
    <Dialog open={open} onOpenChange={props.onOpenChange}>
      <DialogContent className="w-[calc(100vw-1rem)] max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 font-mono">
            <Icons.Activity className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
            {props.iface?.name ?? "Interface"} — stats
          </DialogTitle>
          <DialogDescription>Per-interface counters from the engine — auto-refreshes every 5 s while open.</DialogDescription>
        </DialogHeader>

        {statsQuery.error ? (
          <QueryError error={statsQuery.error} onRetry={() => void statsQuery.refetch()} />
        ) : !stats ? (
          <div className="space-y-2">
            <Skeleton className="h-16 w-full rounded-lg" />
            <Skeleton className="h-24 w-full rounded-lg" />
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-4 text-sm">
              <span className="flex items-center gap-1.5">
                <LinkDot up={props.iface?.linkUp ?? true} degraded={props.iface?.degraded} />
                {props.iface?.linkUp ? "link up" : "link down"}
              </span>
              <span className="text-zinc-500">
                uptime <span className="font-mono tabular-nums text-zinc-800 dark:text-zinc-200">{fmtUptime(stats.uptimeSec)}</span>
              </span>
              <span className="ml-auto tabular-nums">
                <span className="text-zinc-700 dark:text-zinc-500">↓ {fmtKbps(stats.rates.rxKbps)}</span>
                <span className="ml-3 text-zinc-500 dark:text-zinc-400">↑ {fmtKbps(stats.rates.txKbps)}</span>
              </span>
            </div>

            <div className="grid grid-cols-3 gap-2">
              {[
                { label: "rx bytes", value: fmtBytes(stats.totals.rxBytes) },
                { label: "tx bytes", value: fmtBytes(stats.totals.txBytes) },
                { label: "rx packets", value: stats.totals.rxPackets.toLocaleString() },
                { label: "tx packets", value: stats.totals.txPackets.toLocaleString() },
                { label: "errors", value: stats.totals.errors.toLocaleString() },
                { label: "drops", value: stats.totals.drops.toLocaleString() },
              ].map((cell) => (
                <div key={cell.label} className="rounded-lg border border-zinc-200 p-2 dark:border-zinc-800">
                  <p className="text-[10px] uppercase tracking-wide text-zinc-400">{cell.label}</p>
                  <p className="text-sm font-semibold tabular-nums">{cell.value}</p>
                </div>
              ))}
            </div>

            <div>
              <p className="mb-1 text-xs font-medium text-zinc-500">Last 60 ticks</p>
              <Sparkline points={stats.sparkline} className="h-24 w-full" />
              <div className="mt-1 flex items-center gap-4 text-[10px] text-zinc-400">
                <span className="flex items-center gap-1">
                  <span className="inline-block h-1.5 w-3 rounded-full bg-rose-700" /> rx
                </span>
                <span className="flex items-center gap-1">
                  <span className="inline-block h-1.5 w-3 rounded-full bg-zinc-500" /> tx
                </span>
              </div>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

// ── LLDP neighbors tab ──────────────────────────────────────────────────────

function LldpTab() {
  const query = useQuery({ queryKey: LLDP_KEY, queryFn: () => netApi.listLldp(), refetchInterval: 10_000 });
  const rows = useMemo(() => query.data?.data ?? [], [query.data]);

  const [ifaceFilter, setIfaceFilter] = useState("all");
  const [qRaw, setQRaw] = useState("");
  const q = useDebounced(qRaw, 300);

  const localIfaces = useMemo(() => [...new Set(rows.map((r) => r.localIface))].sort(), [rows]);
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rows.filter((r) => {
      if (ifaceFilter !== "all" && r.localIface !== ifaceFilter) return false;
      if (needle) {
        const hay = `${r.systemName} ${r.chassisId} ${r.portId} ${r.portDesc ?? ""}`.toLowerCase();
        if (!hay.includes(needle)) return false;
      }
      return true;
    });
  }, [rows, ifaceFilter, q]);

  return (
    <div className="space-y-3">
      <InfoBanner title="Derived switching view">
        Churned by the simulated switching generator — not persisted. Per-iface LLDP transmit toggles live in the Interfaces tab (config.lldp).
      </InfoBanner>

      <div className="flex flex-wrap items-center gap-2">
        <Select value={ifaceFilter} onValueChange={setIfaceFilter}>
          <SelectTrigger className="h-8 w-44" aria-label="Filter by local interface">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">all interfaces</SelectItem>
            {localIfaces.map((n) => (
              <SelectItem key={n} value={n}>
                {n}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <div className="relative">
          <Icons.Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-400" />
          <Input
            value={qRaw}
            onChange={(e) => setQRaw(e.target.value)}
            placeholder="Search neighbors…"
            className="h-8 w-52 pl-8"
            aria-label="Search LLDP neighbors"
          />
        </div>
      </div>

      <Card className="p-0">
        <CardContent className="p-0">
          {query.error ? (
            <div className="p-4">
              <QueryError error={query.error} onRetry={() => void query.refetch()} />
            </div>
          ) : query.isLoading ? (
            <div className="p-4">
              <TableSkeleton rows={5} cols={6} />
            </div>
          ) : filtered.length === 0 ? (
            <EmptyBlock
              icon={<Icons.RadioTower className="h-6 w-6" />}
              title="No LLDP neighbors"
              description={rows.length === 0 ? "No neighbors seen yet — the generator repopulates this table continuously." : "No neighbors match the current filters."}
            />
          ) : (
            <ScrollWrap>
              <Table className="min-w-[760px] text-sm">
                <TableHeader className="sticky top-0 z-10 bg-card">
                  <TableRow>
                    <TableHead>Local iface</TableHead>
                    <TableHead>Chassis ID</TableHead>
                    <TableHead>System name</TableHead>
                    <TableHead>Port</TableHead>
                    <TableHead>Capabilities</TableHead>
                    <TableHead className="text-right">Last seen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.map((r, i) => (
                    <TableRow key={`${r.localIface}-${r.chassisId}-${r.portId}-${i}`}>
                      <TableCell className="font-mono text-xs">{r.localIface}</TableCell>
                      <TableCell className="font-mono text-xs">{r.chassisId}</TableCell>
                      <TableCell className="text-sm">{r.systemName}</TableCell>
                      <TableCell>
                        <span className="font-mono text-xs">{r.portId}</span>
                        {r.portDesc ? <p className="text-[11px] text-zinc-400">{r.portDesc}</p> : null}
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {r.capabilities.length === 0 ? (
                            <span className="text-xs text-zinc-400">—</span>
                          ) : (
                            r.capabilities.map((cap) => (
                              <Badge key={cap} variant="outline" className="border-zinc-300 text-[10px] font-normal text-zinc-500 dark:border-zinc-700 dark:text-zinc-400">
                                {cap}
                              </Badge>
                            ))
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="text-right tabular-nums text-zinc-500">{fmtAge(r.lastSeenSec)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </ScrollWrap>
          )}
        </CardContent>
      </Card>
      <p className="text-xs text-zinc-400">Auto-refreshes every 10 s.</p>
    </div>
  );
}

// ── MAC table tab ───────────────────────────────────────────────────────────

function MacTab({ ifaces }: { ifaces: Iface[] }) {
  const [ifaceFilter, setIfaceFilter] = useState("all");
  const [vlanRaw, setVlanRaw] = useState("");
  const [qRaw, setQRaw] = useState("");
  const q = useDebounced(qRaw, 300);

  const params = useMemo(() => {
    const p = new URLSearchParams();
    if (ifaceFilter !== "all") p.set("iface", ifaceFilter);
    if (vlanRaw.trim() !== "" && Number.isInteger(Number(vlanRaw))) p.set("vlan", vlanRaw.trim());
    if (q.trim() !== "") p.set("q", q.trim());
    return p.toString();
  }, [ifaceFilter, vlanRaw, q]);

  const query = useQuery({
    queryKey: [...MAC_KEY, params],
    queryFn: () => netApi.listMacTable(params || undefined),
    refetchInterval: 10_000,
  });
  const rows = useMemo(() => query.data?.data ?? [], [query.data]);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Select value={ifaceFilter} onValueChange={setIfaceFilter}>
          <SelectTrigger className="h-8 w-44" aria-label="Filter by interface">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">all interfaces</SelectItem>
            {ifaces.map((i) => (
              <SelectItem key={i.id} value={i.name}>
                {i.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Input
          type="number"
          min={1}
          max={4094}
          value={vlanRaw}
          onChange={(e) => setVlanRaw(e.target.value)}
          placeholder="VLAN"
          className="h-8 w-24"
          aria-label="Filter by VLAN"
        />
        <div className="relative">
          <Icons.Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-400" />
          <Input
            value={qRaw}
            onChange={(e) => setQRaw(e.target.value)}
            placeholder="Search MAC…"
            className="h-8 w-52 pl-8"
            aria-label="Search MAC table"
          />
        </div>
        <Button size="sm" variant="outline" className="ml-auto" onClick={() => void query.refetch()} disabled={query.isFetching}>
          <Icons.RefreshCw className={cn("mr-1 h-3.5 w-3.5", query.isFetching && "animate-spin")} /> Refresh
        </Button>
      </div>

      <Card className="p-0">
        <CardContent className="p-0">
          {query.error ? (
            <div className="p-4">
              <QueryError error={query.error} onRetry={() => void query.refetch()} />
            </div>
          ) : query.isLoading ? (
            <div className="p-4">
              <TableSkeleton rows={5} cols={5} />
            </div>
          ) : rows.length === 0 ? (
            <EmptyBlock
              icon={<Icons.Network className="h-6 w-6" />}
              title="MAC table is empty"
              description="The bridge FDB fills as hosts talk through the switch — static entries surface from DHCP reservations and bridge membership."
            />
          ) : (
            <ScrollWrap>
              <Table className="min-w-[620px] text-sm">
                <TableHeader className="sticky top-0 z-10 bg-card">
                  <TableRow>
                    <TableHead>MAC</TableHead>
                    <TableHead className="w-20">VLAN</TableHead>
                    <TableHead>Interface</TableHead>
                    <TableHead className="w-24">Type</TableHead>
                    <TableHead className="text-right">Age</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((r, i) => (
                    <TableRow key={`${r.mac}-${r.vlan}-${r.iface}-${i}`}>
                      <TableCell className="font-mono text-xs">{r.mac}</TableCell>
                      <TableCell className="tabular-nums">{r.vlan}</TableCell>
                      <TableCell className="font-mono text-xs">{r.iface}</TableCell>
                      <TableCell>
                        {r.type === "static" ? (
                          <Badge variant="outline" className="border-zinc-500/30 bg-zinc-500/10 text-[10px] font-medium text-zinc-600 dark:text-zinc-300">
                            static
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="border-zinc-300 text-[10px] font-normal text-zinc-500 dark:border-zinc-700 dark:text-zinc-400">
                            dynamic
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-right tabular-nums text-zinc-500">{fmtAge(r.ageSec)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </ScrollWrap>
          )}
        </CardContent>
      </Card>
      <p className="text-xs text-zinc-400">Auto-refreshes every 10 s; static entries derive from DHCP reservations and bridge membership.</p>
    </div>
  );
}

// ── mirroring (SPAN) tab ────────────────────────────────────────────────────

function MirrorsTab({ ifaces }: { ifaces: Iface[] }) {
  const queryClient = useQueryClient();
  const query = useQuery({ queryKey: MIRRORS_KEY, queryFn: () => netApi.listMirrors() });
  const rows = useMemo(() => query.data?.data ?? [], [query.data]);

  const [deleting, setDeleting] = useState<Mirror | null>(null);

  const toggleMut = useMutation({
    mutationFn: (mirror: Mirror) =>
      netApi.updateMirror(mirror.id, mirrorBodyOf(mirror, { enabled: !mirror.enabled })),
    onSuccess: (updated) => toastOk(updated.enabled ? "Mirror enabled" : "Mirror disabled", updated.name),
    onError: (err) => toastErr(err, "Toggle failed"),
    onSettled: () => void queryClient.invalidateQueries({ queryKey: MIRRORS_KEY }),
  });

  const deleteMut = useMutation({
    mutationFn: (id: number) => netApi.deleteMirror(id),
    onSuccess: () => {
      toastOk("Mirror session deleted");
      setDeleting(null);
    },
    onError: (err) => toastErr(err, "Delete failed"),
    onSettled: () => void queryClient.invalidateQueries({ queryKey: MIRRORS_KEY }),
  });

  return (
    <div className="space-y-3">
      <InfoBanner title="SPAN sessions">
        Mirrored traffic feeds the IPS passive (IDS) tap on the appliance (tc mirred). In the sandbox mirrors are recorded config only — one active mirror per source interface (409 otherwise).
      </InfoBanner>

      <Card className="p-0">
        <CardContent className="p-0">
          {query.error ? (
            <div className="p-4">
              <QueryError error={query.error} onRetry={() => void query.refetch()} />
            </div>
          ) : query.isLoading ? (
            <div className="p-4">
              <TableSkeleton rows={3} cols={5} />
            </div>
          ) : rows.length === 0 ? (
            <EmptyBlock
              icon={<Icons.ScanLine className="h-6 w-6" />}
              title="No mirror sessions"
              description="Add a SPAN session to copy ingress/egress traffic of a source interface to a capture interface."
            />
          ) : (
            <ScrollWrap>
              <Table className="min-w-[680px] text-sm">
                <TableHeader className="sticky top-0 z-10 bg-card">
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Source → capture</TableHead>
                    <TableHead className="w-24">Direction</TableHead>
                    <TableHead className="w-20">On</TableHead>
                    <TableHead className="w-20 pr-2 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((m) => (
                    <TableRow key={m.id} className={cn(!m.enabled && "opacity-60")}>
                      <TableCell className="font-medium">{m.name}</TableCell>
                      <TableCell>
                        <span className="inline-flex items-center gap-1.5 font-mono text-xs">
                          {m.srcIface}
                          <Icons.ArrowRight className="h-3.5 w-3.5 text-zinc-400" />
                          {m.dstIface}
                        </span>
                      </TableCell>
                      <TableCell>
                        <DirectionChip direction={m.direction} />
                      </TableCell>
                      <TableCell>
                        <Switch
                          checked={m.enabled}
                          disabled={toggleMut.isPending}
                          aria-label={`Toggle mirror ${m.name}`}
                          onCheckedChange={() => toggleMut.mutate(m)}
                        />
                      </TableCell>
                      <TableCell className="pr-2 text-right">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8 text-rose-600 hover:text-rose-700 dark:text-rose-400"
                          aria-label={`Delete mirror ${m.name}`}
                          onClick={() => setDeleting(m)}
                        >
                          <Icons.Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </ScrollWrap>
          )}
        </CardContent>
      </Card>

      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title="Delete mirror session?"
        description={`Delete SPAN session '${deleting?.name ?? ""}'? The capture interface stops receiving mirrored traffic.`}
        loading={deleteMut.isPending}
        onConfirm={() => deleting && deleteMut.mutate(deleting.id)}
      />
    </div>
  );
}

function MirrorEditor(props: { open: boolean; onOpenChange: (open: boolean) => void; ifaces: Iface[] }) {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [srcIface, setSrcIface] = useState("");
  const [dstIface, setDstIface] = useState("");
  const [direction, setDirection] = useState<MirrorDirection>("both");
  const [enabled, setEnabled] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const mut = useMutation({
    mutationFn: () =>
      netApi.createMirror({ name: name.trim(), srcIface, dstIface, direction, enabled, description: null }),
    onSuccess: (created) => {
      toastOk("Mirror session created", created.name);
      props.onOpenChange(false);
      void queryClient.invalidateQueries({ queryKey: MIRRORS_KEY });
    },
    onError: (err) => toastErr(err, "Create failed"),
  });

  const submit = () => {
    if (!name.trim()) return setError("Name is required");
    if (!srcIface) return setError("Source interface is required");
    if (!dstIface) return setError("Capture interface is required");
    if (srcIface === dstIface) return setError("Source and capture interfaces must differ");
    setError(null);
    mut.mutate();
  };

  const ifaceNames = useMemo(() => props.ifaces.map((i) => ({ name: i.name, type: i.type })), [props.ifaces]);

  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent className="w-[calc(100vw-1rem)] max-w-md">
        <DialogHeader>
          <DialogTitle>Add mirror session</DialogTitle>
          <DialogDescription>
            Copy traffic from a source interface to a capture interface. Only one active mirror per source interface is allowed.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div>
            <FieldLabel>Name</FieldLabel>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="span-lan0" aria-label="Mirror session name" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <FieldLabel>Source interface</FieldLabel>
              <Select value={srcIface || undefined} onValueChange={setSrcIface}>
                <SelectTrigger aria-label="Source interface">
                  <SelectValue placeholder="select…" />
                </SelectTrigger>
                <SelectContent>
                  {ifaceNames.map((i) => (
                    <SelectItem key={i.name} value={i.name}>
                      {i.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel hint="capture">Capture interface</FieldLabel>
              <Select value={dstIface || undefined} onValueChange={setDstIface}>
                <SelectTrigger aria-label="Capture interface">
                  <SelectValue placeholder="select…" />
                </SelectTrigger>
                <SelectContent>
                  {ifaceNames.map((i) => (
                    <SelectItem key={i.name} value={i.name}>
                      {i.name} (capture)
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div>
            <FieldLabel>Direction</FieldLabel>
            <RadioGroup value={direction} onValueChange={(v) => setDirection(v as MirrorDirection)} className="flex gap-4">
              {(["ingress", "egress", "both"] as const).map((d) => (
                <Label key={d} className="flex cursor-pointer items-center gap-2 text-sm">
                  <RadioGroupItem value={d} /> {d}
                </Label>
              ))}
            </RadioGroup>
          </div>
          <Label className="flex items-center gap-2 text-sm">
            <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="Enable mirror session" /> Enabled
          </Label>
          {error && <p className="text-xs font-medium text-rose-600 dark:text-rose-400">{error}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => props.onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={mut.isPending} className="bg-amber-700 text-white hover:bg-amber-800">
            {mut.isPending ? "Creating…" : "Create mirror"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── Diagnostics tab (vendor-style: host ports / ARP / routes / ping) ────────

function DiagnosticsTab({ ifaces }: { ifaces: Iface[] }) {
  const portsQuery = useQuery({ queryKey: HOST_PORTS_KEY, queryFn: () => netApi.listHostPorts(), refetchInterval: 10_000 });
  const arpQuery = useQuery({ queryKey: ARP_KEY, queryFn: () => netApi.listArp(), refetchInterval: 10_000 });
  const routesQuery = useQuery({ queryKey: OS_ROUTES_KEY, queryFn: () => netApi.listOsRoutes(), refetchInterval: 10_000 });

  const dbNames = useMemo(() => new Set(ifaces.map((i) => i.name)), [ifaces]);

  // ping tool state
  const [pingHost, setPingHost] = useState("");
  const [pingIface, setPingIface] = useState("");
  const [pingCount, setPingCount] = useState("3");
  const [pingResult2, setPingResult2] = useState<DiagPingResult | null>(null);
  const pingMut2 = useMutation({
    mutationFn: () => netApi.pingDiag(pingHost.trim(), pingIface || undefined, Number(pingCount) || 3),
    onSuccess: (r) => setPingResult2(r),
    onError: (err) => toastErr(err, "Ping failed"),
  });

  const ports = useMemo(() => portsQuery.data?.data ?? [], [portsQuery.data]);
  const arp = useMemo(() => arpQuery.data?.data ?? [], [arpQuery.data]);
  const routes = useMemo(() => routesQuery.data?.data ?? [], [routesQuery.data]);

  return (
    <div className="space-y-4">
      <InfoBanner title="Live host diagnostics">
        Read straight from the Linux host (/sys/class/net, /proc/net/dev · arp · route) — the same kernel the appliance
        forwards packets with. Ping binds to the selected source interface (pfSense-style scoped probe).
      </InfoBanner>

      {/* host ports inventory */}
      <Card className="p-0">
        <CardContent className="p-0">
          <div className="flex items-center justify-between border-b border-zinc-200 px-4 py-2 dark:border-zinc-800">
            <p className="text-xs font-semibold uppercase tracking-wide text-zinc-400">Host ports (kernel inventory)</p>
            <Button size="sm" variant="outline" className="h-7" onClick={() => void portsQuery.refetch()} disabled={portsQuery.isFetching}>
              <Icons.RefreshCw className={cn("mr-1 h-3 w-3", portsQuery.isFetching && "animate-spin")} /> Refresh
            </Button>
          </div>
          {portsQuery.isLoading ? (
            <div className="p-4">
              <TableSkeleton rows={4} cols={8} />
            </div>
          ) : (
            <ScrollWrap>
              <Table className="min-w-[900px] text-sm">
                <TableHeader className="sticky top-0 z-10 bg-card">
                  <TableRow>
                    <TableHead>Port</TableHead>
                    <TableHead>Oper state</TableHead>
                    <TableHead>Carrier</TableHead>
                    <TableHead>MTU</TableHead>
                    <TableHead>MAC</TableHead>
                    <TableHead>IPv4</TableHead>
                    <TableHead className="text-right">rx err/drop</TableHead>
                    <TableHead className="text-right">tx err/drop</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {ports.map((p) => (
                    <TableRow key={p.name}>
                      <TableCell className="font-mono text-xs font-medium">
                        {p.name}
                        {p.isDefaultRoute ? (
                          <Badge variant="outline" className="ml-1.5 border-zinc-400 px-1 py-0 text-[9px] font-normal text-zinc-500">
                            default route
                          </Badge>
                        ) : null}
                        {!dbNames.has(p.name) ? (
                          <Badge variant="outline" className="ml-1.5 border-zinc-300 px-1 py-0 text-[9px] font-normal text-zinc-400">
                            unadopted
                          </Badge>
                        ) : null}
                      </TableCell>
                      <TableCell>
                        <span
                          className={cn(
                            "font-mono text-xs",
                            p.operState === "up" ? "text-emerald-600 dark:text-emerald-400" : p.operState === "down" ? "text-rose-500" : "text-zinc-500",
                          )}
                        >
                          {p.operState}
                        </span>
                      </TableCell>
                      <TableCell className="text-xs text-zinc-500">{p.carrier == null ? "—" : p.carrier ? "yes" : "no"}</TableCell>
                      <TableCell className="tabular-nums">{p.mtu ?? "—"}</TableCell>
                      <TableCell className="font-mono text-xs text-zinc-500">{p.mac ?? "—"}</TableCell>
                      <TableCell className="font-mono text-xs text-zinc-500">{p.ipv4.length ? p.ipv4.join(", ") : "—"}</TableCell>
                      <TableCell className={cn("text-right tabular-nums", (p.counters?.rxErrors ?? 0) + (p.counters?.rxDrops ?? 0) > 0 && "font-semibold text-amber-600 dark:text-amber-400")}>
                        {p.counters ? `${p.counters.rxErrors} / ${p.counters.rxDrops}` : "—"}
                      </TableCell>
                      <TableCell className={cn("text-right tabular-nums", (p.counters?.txErrors ?? 0) + (p.counters?.txDrops ?? 0) > 0 && "font-semibold text-amber-600 dark:text-amber-400")}>
                        {p.counters ? `${p.counters.txErrors} / ${p.counters.txDrops}` : "—"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </ScrollWrap>
          )}
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        {/* ARP table */}
        <Card className="p-0">
          <CardContent className="p-0">
            <div className="border-b border-zinc-200 px-4 py-2 text-xs font-semibold uppercase tracking-wide text-zinc-400 dark:border-zinc-800">
              ARP / neighbor cache
            </div>
            <ScrollWrap>
              <Table className="min-w-[420px] text-sm">
                <TableHeader className="sticky top-0 z-10 bg-card">
                  <TableRow>
                    <TableHead>IP</TableHead>
                    <TableHead>MAC</TableHead>
                    <TableHead>Device</TableHead>
                    <TableHead className="text-right">State</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {arp.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={4} className="py-6 text-center text-sm text-zinc-500">
                        Neighbor cache is empty.
                      </TableCell>
                    </TableRow>
                  ) : (
                    arp.map((a, i) => (
                      <TableRow key={`${a.ip}-${a.device}-${i}`}>
                        <TableCell className="font-mono text-xs">{a.ip}</TableCell>
                        <TableCell className="font-mono text-xs text-zinc-500">{a.mac ?? "—"}</TableCell>
                        <TableCell className="font-mono text-xs">{a.device}</TableCell>
                        <TableCell className="text-right">
                          <Badge
                            variant="outline"
                            className={cn(
                              "text-[10px]",
                              a.complete
                                ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                                : "border-zinc-300 text-zinc-400 dark:border-zinc-700",
                            )}
                          >
                            {a.complete ? "reachable" : "incomplete"}
                          </Badge>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </ScrollWrap>
          </CardContent>
        </Card>

        {/* routes table */}
        <Card className="p-0">
          <CardContent className="p-0">
            <div className="border-b border-zinc-200 px-4 py-2 text-xs font-semibold uppercase tracking-wide text-zinc-400 dark:border-zinc-800">
              Kernel route table (IPv4)
            </div>
            <ScrollWrap>
              <Table className="min-w-[420px] text-sm">
                <TableHeader className="sticky top-0 z-10 bg-card">
                  <TableRow>
                    <TableHead>Destination</TableHead>
                    <TableHead>Gateway</TableHead>
                    <TableHead>Device</TableHead>
                    <TableHead className="text-right">Metric</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {routes.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={4} className="py-6 text-center text-sm text-zinc-500">
                        No routes.
                      </TableCell>
                    </TableRow>
                  ) : (
                    routes.map((r, i) => (
                      <TableRow key={`${r.destination}-${r.iface}-${i}`} className={cn(r.isDefault && "bg-zinc-500/5")}>
                        <TableCell className="font-mono text-xs">
                          {r.isDefault ? (
                            <Badge variant="outline" className="mr-1 border-zinc-400 px-1 py-0 text-[9px] font-normal text-zinc-500">
                              default
                            </Badge>
                          ) : null}
                          {r.destination}
                        </TableCell>
                        <TableCell className="font-mono text-xs text-zinc-500">{r.gateway}</TableCell>
                        <TableCell className="font-mono text-xs">{r.iface}</TableCell>
                        <TableCell className="text-right tabular-nums text-zinc-500">{r.metric}</TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </ScrollWrap>
          </CardContent>
        </Card>
      </div>

      {/* ping tool */}
      <Card className="p-0">
        <CardContent className="space-y-3 p-4">
          <p className="text-xs font-semibold uppercase tracking-wide text-zinc-400">Ping probe (source-interface scoped)</p>
          <div className="flex flex-wrap items-end gap-2">
            <div className="w-56">
              <FieldLabel hint="IPv4 or hostname">Host</FieldLabel>
              <Input
                value={pingHost}
                onChange={(e) => setPingHost(e.target.value)}
                placeholder="1.1.1.1"
                className="h-9 font-mono text-xs"
                aria-label="Ping host"
              />
            </div>
            <div className="w-44">
              <FieldLabel hint="binds -I">Source interface</FieldLabel>
              <Select value={pingIface || "any"} onValueChange={(v) => setPingIface(v === "any" ? "" : v)}>
                <SelectTrigger className="h-9" aria-label="Ping source interface">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="any">any (routing table)</SelectItem>
                  {ports.map((p) => (
                    <SelectItem key={p.name} value={p.name}>
                      {p.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="w-24">
              <FieldLabel hint="max 4">Packets</FieldLabel>
              <Select value={pingCount} onValueChange={setPingCount}>
                <SelectTrigger className="h-9" aria-label="Ping packet count">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {["1", "2", "3", "4"].map((n) => (
                    <SelectItem key={n} value={n}>
                      {n}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <Button
              size="sm"
              className="h-9 bg-zinc-700 text-white hover:bg-zinc-800"
              disabled={pingMut2.isPending || pingHost.trim() === ""}
              onClick={() => pingMut2.mutate()}
              aria-label="Run ping"
            >
              <Icons.Radar className="mr-1 h-3.5 w-3.5" /> {pingMut2.isPending ? "Probing…" : "Run"}
            </Button>
            {pingResult2?.lossPct != null && (
              <Badge
                variant="outline"
                className={cn(
                  "text-xs",
                  pingResult2.lossPct === 0
                    ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                    : "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
                )}
              >
                loss {pingResult2.lossPct}%
                {pingResult2.avgMs != null ? ` · avg ${pingResult2.avgMs} ms` : ""}
              </Badge>
            )}
          </div>
          {pingResult2 && (
            <pre className="max-h-48 overflow-auto rounded-lg border border-zinc-200 bg-zinc-50 p-3 font-mono text-[11px] leading-snug dark:border-zinc-800 dark:bg-zinc-900">
              {pingResult2.error ?? pingResult2.output}
            </pre>
          )}
        </CardContent>
      </Card>
      <p className="text-xs text-zinc-400">Inventory/ARP/routes auto-refresh every 10 s. Errors/drops ≠ 0 are highlighted — check them first when a link misbehaves.</p>
    </div>
  );
}
