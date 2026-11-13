"use client";

/**
 * #/network/routing — 2 tabs: Static Routes | Policy-Based Routes (M02 §4).
 * Static routes sort by destinationCidr then distance; PBR rules evaluate by
 * position. Egress is outgoingIface XOR gateway (server enforces with 400).
 * config:updated (section=routing) invalidates the routes + pbr queries.
 */

import { useMemo, useState } from "react";
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
import { useRealtime } from "@/lib/realtime";
import {
  ConfirmDialog,
  EditorSection,
  EmptyBlock,
  FieldLabel,
  ObjectPicker,
  QueryError,
  TableSkeleton,
  toastErr,
  toastOk,
} from "@/components/views/firewall/fw-ui";
import {
  isValidCidr,
  isValidIpv4,
  netApi,
  routeBodyOf,
  NetApiError,
  type Iface,
  type ObjectRef,
  type PbrBody,
  type PbrRow,
  type RouteApplyOutcome,
  type RouteIssueDTO,
  type StaticRouteRow,
} from "./net-api";
import { BfdChip, PbrKernelBadge, RouteOsBadge } from "./net-ui";

const ROUTES_KEY = ["network", "routes"] as const;
const PBR_KEY = ["network", "pbr"] as const;
const PBR_PLANS_KEY = ["network", "pbr-plans"] as const;
const IFACES_KEY = ["network", "interfaces"] as const;

/** Runtime extensions of the shared M03 endpoints (contract pins id+name). */
type AddrObjectExt = ObjectRef & { value?: string };
type GroupExt = ObjectRef & { memberIds?: number[] };
type ServiceExt = ObjectRef & { protocol?: string; dstPort?: string | null };

interface ObjectInfo {
  name: string;
  isGroup: boolean;
  memberCount: number;
  sub: string;
}

function ScrollWrap({ children }: { children: React.ReactNode }) {
  return (
    <div className="max-h-[480px] overflow-auto [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-zinc-300 dark:[&::-webkit-scrollbar-thumb]:bg-zinc-700">
      {children}
    </div>
  );
}

/** Toast summary of a gated OS-apply outcome (plan + results). */
function applyOutcomeToToast(outcomes: RouteApplyOutcome[] | Array<{ os: { applied: boolean; gate: "on" | "off"; reason: string } }>, label: string) {
  for (const o of outcomes) {
    if (o.os.gate === "off") toastOk(`${label} — plan preview only`, o.os.reason);
    else if (o.os.applied) toastOk(label, "applied to the kernel");
    else toastErr(new NetApiError("OS_APPLY", o.os.reason), label);
  }
}

function ObjectChips({ ids, map }: { ids: number[]; map: Map<number, ObjectInfo> }) {
  if (ids.length === 0) return <span className="text-xs text-zinc-400">any</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {ids.map((id) => {
        const info = map.get(id);
        const label = info ? (info.isGroup ? `${info.name} +${info.memberCount}` : info.name) : `#${id}`;
        return (
          <Badge
            key={id}
            variant="outline"
            className={cn(
              "max-w-36 gap-1 truncate font-normal",
              info?.isGroup
                ? "border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300"
                : "border-zinc-300 text-zinc-600 dark:border-zinc-700 dark:text-zinc-300",
            )}
          >
            {info?.isGroup ? <Icons.FolderOpen className="h-3 w-3 shrink-0" /> : null}
            <span className="truncate">{label}</span>
          </Badge>
        );
      })}
    </div>
  );
}

// ── main view ───────────────────────────────────────────────────────────────

export function RoutingView() {
  const queryClient = useQueryClient();

  useRealtime(["metrics", "config"], {
    onConfigUpdated: (c) => {
      if (c.section === "routing") {
        void queryClient.invalidateQueries({ queryKey: ROUTES_KEY });
        void queryClient.invalidateQueries({ queryKey: PBR_KEY });
      }
    },
  });

  const [tab, setTab] = useState("static");

  return (
    <Tabs value={tab} onValueChange={setTab} className="gap-4">
      <TabsList aria-label="Routing tabs">
        <TabsTrigger value="static">Static Routes</TabsTrigger>
        <TabsTrigger value="pbr">Policy-Based Routes</TabsTrigger>
      </TabsList>
      <TabsContent value="static">
        <StaticRoutesTab />
      </TabsContent>
      <TabsContent value="pbr">
        <PbrTab />
      </TabsContent>
    </Tabs>
  );
}

// ── static routes tab ───────────────────────────────────────────────────────

function StaticRoutesTab() {
  const queryClient = useQueryClient();
  const routesQuery = useQuery({ queryKey: ROUTES_KEY, queryFn: () => netApi.listRoutes() });
  const ifacesQuery = useQuery({ queryKey: IFACES_KEY, queryFn: () => netApi.listIfaces() });
  const ifaces = useMemo(() => ifacesQuery.data?.data ?? [], [ifacesQuery.data]);

  const routes = useMemo(
    () =>
      [...(routesQuery.data?.data ?? [])].sort(
        (a, b) => a.destinationCidr.localeCompare(b.destinationCidr, undefined, { numeric: true }) || a.distance - b.distance,
      ),
    [routesQuery.data],
  );

  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<StaticRouteRow | null>(null);
  const [deleting, setDeleting] = useState<StaticRouteRow | null>(null);
  /** 409 conflict → force-save confirm (BR-ROUTE-DUP / BR-ROUTE-DEFAULT-PRIMARY) */
  const [conflict, setConflict] = useState<{ body: Parameters<typeof netApi.createRoute>[0]; editingId: number | null; issues: RouteIssueDTO[] } | null>(null);
  const [applying, setApplying] = useState<StaticRouteRow | "all" | null>(null);

  const toggleMut = useMutation({
    mutationFn: (route: StaticRouteRow) =>
      netApi.updateRoute(route.id, { ...routeBodyOf(route, { enabled: !route.enabled }), force: true }),
    onSuccess: (updated) => toastOk(updated.enabled ? "Route enabled" : "Route disabled", updated.destinationCidr),
    onError: (err) => toastErr(err, "Toggle failed"),
    onSettled: () => void queryClient.invalidateQueries({ queryKey: ROUTES_KEY }),
  });

  const applyMut = useMutation({
    mutationFn: (target: StaticRouteRow | "all") => netApi.applyRoutes(target === "all" ? undefined : target.id),
    onSuccess: (outcomes) => {
      applyOutcomeToToast(outcomes, "Kernel sync");
      setApplying(null);
    },
    onError: (err) => toastErr(err, "Kernel sync failed"),
    onSettled: () => void queryClient.invalidateQueries({ queryKey: ROUTES_KEY }),
  });

  const deleteMut = useMutation({
    mutationFn: (id: number) => netApi.deleteRoute(id),
    onSuccess: () => {
      toastOk("Route deleted", "kernel entries withdrawn (best effort)");
      setDeleting(null);
    },
    onError: (err) => toastErr(err, "Delete failed"),
    onSettled: () => void queryClient.invalidateQueries({ queryKey: ROUTES_KEY }),
  });

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs text-zinc-500">
          Floating static routes via distance (lower wins); the default route is a static route with 0.0.0.0/0. Rows sync to the kernel FIB with <code className="font-mono">ip route</code> — metric = distance, so the interface-managed primary default (metric 0) always stays authoritative.
        </p>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="outline"
            disabled={applyMut.isPending}
            onClick={() => setApplying("all")}
            aria-label="Apply all routes to kernel"
          >
            <Icons.RefreshCw className={cn("mr-1 h-4 w-4", applyMut.isPending && "animate-spin")} /> Sync to kernel
          </Button>
          <Button
            size="sm"
            onClick={() => {
              setEditing(null);
              setEditorOpen(true);
            }}
            className="bg-zinc-700 text-white hover:bg-zinc-800"
          >
            <Icons.Plus className="mr-1 h-4 w-4" /> Add route
          </Button>
        </div>
      </div>

      <Card className="p-0">
        <CardContent className="p-0">
          {routesQuery.error ? (
            <div className="p-4">
              <QueryError error={routesQuery.error} onRetry={() => void routesQuery.refetch()} />
            </div>
          ) : routesQuery.isLoading ? (
            <div className="p-4">
              <TableSkeleton rows={5} cols={7} />
            </div>
          ) : routes.length === 0 ? (
            <EmptyBlock
              icon={<Icons.Signpost className="h-6 w-6" />}
              title="No static routes"
              description="Add a static or blackhole route — e.g. 0.0.0.0/0 via your WAN gateway as the default route."
              action={
                <Button
                  onClick={() => {
                    setEditing(null);
                    setEditorOpen(true);
                  }}
                  className="bg-zinc-700 text-white hover:bg-zinc-800"
                >
                  <Icons.Plus className="mr-1 h-4 w-4" /> Add route
                </Button>
              }
            />
          ) : (
            <ScrollWrap>
              <Table className="min-w-[820px] text-sm">
                <TableHeader className="sticky top-0 z-10 bg-card">
                  <TableRow>
                    <TableHead>Destination</TableHead>
                    <TableHead>Gateway</TableHead>
                    <TableHead>Interface</TableHead>
                    <TableHead className="w-20">Distance</TableHead>
                    <TableHead className="w-20">Kernel</TableHead>
                    <TableHead className="w-36">BFD</TableHead>
                    <TableHead className="w-16">On</TableHead>
                    <TableHead className="w-28 pr-2 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {routes.map((r) => (
                    <TableRow key={r.id} className={cn(!r.enabled && "opacity-55")}>
                      <TableCell className="font-mono text-xs font-medium">{r.destinationCidr}</TableCell>
                      <TableCell>
                        {r.blackhole ? (
                          <Badge variant="outline" className="border-rose-600/60 bg-transparent text-rose-500">
                            <Icons.CircleX className="mr-1 h-3 w-3" />
                            blackhole
                          </Badge>
                        ) : r.gateway ? (
                          <span className="font-mono text-xs">{r.gateway}</span>
                        ) : (
                          <span className="text-xs text-zinc-400">—</span>
                        )}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{r.interfaceName ?? "—"}</TableCell>
                      <TableCell className="tabular-nums">{r.distance}</TableCell>
                      <TableCell>
                        <RouteOsBadge state={r.osState} />
                      </TableCell>
                      <TableCell>
                        <BfdChip state={r.bfd ? r.bfdState : null} />
                      </TableCell>
                      <TableCell>
                        <Switch
                          checked={r.enabled}
                          disabled={toggleMut.isPending}
                          aria-label={`Toggle route ${r.destinationCidr}`}
                          onCheckedChange={() => toggleMut.mutate(r)}
                        />
                      </TableCell>
                      <TableCell className="pr-2 text-right">
                        <div className="flex items-center justify-end gap-0.5">
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8"
                            aria-label={`Sync route ${r.destinationCidr} to kernel`}
                            title="Install/withdraw this route in the kernel FIB"
                            disabled={applyMut.isPending}
                            onClick={() => setApplying(r)}
                          >
                            <Icons.RefreshCw className="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8"
                            aria-label={`Edit route ${r.destinationCidr}`}
                            onClick={() => {
                              setEditing(r);
                              setEditorOpen(true);
                            }}
                          >
                            <Icons.Pencil className="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8 text-rose-600 hover:text-rose-700 dark:text-rose-400"
                            aria-label={`Delete route ${r.destinationCidr}`}
                            onClick={() => setDeleting(r)}
                          >
                            <Icons.Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </ScrollWrap>
          )}
        </CardContent>
      </Card>

      {editorOpen && (
        <RouteEditor
          key={editing?.id ?? "new"}
          open={editorOpen}
          onOpenChange={setEditorOpen}
          editing={editing}
          ifaces={ifaces}
          onSaved={() => void queryClient.invalidateQueries({ queryKey: ROUTES_KEY })}
          onConflict={(body, editingId, issues) => setConflict({ body, editingId, issues })}
        />
      )}

      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title="Delete route?"
        description={`Delete route '${deleting?.destinationCidr ?? ""}'? Traffic that relied on it falls back to shorter matches or the default route. Kernel entries are withdrawn best-effort.`}
        loading={deleteMut.isPending}
        onConfirm={() => deleting && deleteMut.mutate(deleting.id)}
      />

      <ConfirmDialog
        open={applying !== null}
        onOpenChange={(open) => !open && setApplying(null)}
        title="Sync routes to the kernel FIB?"
        description={
          applying === "all"
            ? "Every route row converges: enabled rows install via ip route replace (metric = distance), disabled rows withdraw stale entries. ECMP members of other rows are never removed."
            : `Converge '${applying?.destinationCidr ?? ""}' into the kernel FIB via ip route (gated by the appliance OS-apply policy).`
        }
        loading={applyMut.isPending}
        onConfirm={() => applying && applyMut.mutate(applying)}
      />

      <ConfirmDialog
        open={conflict !== null}
        onOpenChange={(open) => !open && setConflict(null)}
        title="Route conflicts — save anyway?"
        description={(conflict?.issues ?? []).map((i) => `• ${i.message}`).join("\n")}
        confirmLabel="Save anyway"
        loading={false}
        onConfirm={() => {
          if (!conflict) return;
          const body = { ...conflict.body, force: true } as Parameters<typeof netApi.createRoute>[0];
          if (conflict.editingId != null) {
            netApi
              .updateRoute(conflict.editingId, body)
              .then((saved) => {
                toastOk("Route updated", saved.destinationCidr);
                setEditorOpen(false);
              })
              .catch((err) => toastErr(err, "Update failed"))
              .finally(() => {
                setConflict(null);
                void queryClient.invalidateQueries({ queryKey: ROUTES_KEY });
              });
          } else {
            netApi
              .createRoute(body)
              .then((saved) => {
                toastOk("Route created", saved.destinationCidr);
                setEditorOpen(false);
              })
              .catch((err) => toastErr(err, "Create failed"))
              .finally(() => {
                setConflict(null);
                void queryClient.invalidateQueries({ queryKey: ROUTES_KEY });
              });
          }
        }}
      />
    </div>
  );
}

function RouteEditor(props: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editing: StaticRouteRow | null;
  ifaces: Iface[];
  onSaved: () => void;
  /** 409 conflicts surface here for the force-save confirm flow */
  onConflict?: (body: Parameters<typeof netApi.createRoute>[0], editingId: number | null, issues: RouteIssueDTO[]) => void;
}) {
  const editing = props.editing;
  const isEdit = editing != null;

  const [name, setName] = useState(editing?.name ?? "");
  const [destinationCidr, setDestinationCidr] = useState(editing?.destinationCidr ?? "");
  const [gateway, setGateway] = useState(editing?.gateway ?? "");
  const [interfaceName, setInterfaceName] = useState(editing?.interfaceName ?? "none");
  const [distance, setDistance] = useState(String(editing?.distance ?? 1));
  const [bfd, setBfd] = useState(editing?.bfd ?? false);
  const [blackhole, setBlackhole] = useState(editing?.blackhole ?? false);
  const [enabled, setEnabled] = useState(editing?.enabled ?? true);
  const [description, setDescription] = useState(editing?.description ?? "");
  const [error, setError] = useState<string | null>(null);

  const mut = useMutation({
    mutationFn: (body: Parameters<typeof netApi.createRoute>[0]) =>
      isEdit && editing ? netApi.updateRoute(editing.id, body) : netApi.createRoute(body),
    onSuccess: (saved) => {
      toastOk(isEdit ? "Route updated" : "Route created", saved.destinationCidr);
      props.onOpenChange(false);
      props.onSaved();
    },
    onError: (err, body) => {
      // 409 with issue list → force-save confirm flow instead of a bare toast
      if (err instanceof NetApiError && err.code === "CONFLICT") {
        const issues = (err.details as { issues?: RouteIssueDTO[] } | undefined)?.issues;
        if (issues && issues.length > 0) {
          props.onConflict?.(body as Parameters<typeof netApi.createRoute>[0], isEdit && editing ? editing.id : null, issues);
          return;
        }
      }
      toastErr(err, isEdit ? "Update failed" : "Create failed");
    },
  });

  const submit = () => {
    const cidr = destinationCidr.trim();
    if (!isValidCidr(cidr)) return setError("Destination must be a valid IPv4 CIDR (e.g. 10.0.0.0/8)");
    const dist = Number(distance);
    if (!Number.isInteger(dist) || dist < 1 || dist > 255) return setError("Distance must be an integer between 1 and 255");
    if (!blackhole && gateway.trim() !== "" && !isValidIpv4(gateway)) return setError("Gateway must be a valid IPv4 address");
    setError(null);
    const body = {
      name: name.trim() || null,
      destinationCidr: cidr,
      gateway: blackhole || gateway.trim() === "" ? null : gateway.trim(),
      interfaceName: interfaceName === "none" ? null : interfaceName,
      distance: dist,
      bfd: blackhole ? false : bfd,
      blackhole,
      enabled,
      description: description.trim() || null,
    };
    mut.mutate(body);
  };

  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent className="w-[calc(100vw-1rem)] max-w-md">
        <DialogHeader>
          <DialogTitle>{isEdit ? "Edit route" : "Add route"}</DialogTitle>
          <DialogDescription>
            Blackhole routes drop matched traffic silently — gateway and BFD are cleared when blackhole is on.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <FieldLabel hint="optional">Name</FieldLabel>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="dc-default" aria-label="Route name" />
            </div>
            <div>
              <FieldLabel hint="1–255">Distance</FieldLabel>
              <Input type="number" min={1} max={255} value={distance} onChange={(e) => setDistance(e.target.value)} aria-label="Administrative distance" />
            </div>
          </div>
          <div>
            <FieldLabel hint="IPv4 CIDR">Destination</FieldLabel>
            <Input
              value={destinationCidr}
              onChange={(e) => setDestinationCidr(e.target.value)}
              placeholder="0.0.0.0/0"
              className="font-mono"
              aria-label="Destination CIDR"
            />
          </div>
          <div>
            <FieldLabel hint={blackhole ? "cleared while blackhole is on" : "optional"}>Gateway</FieldLabel>
            <Input
              value={gateway}
              onChange={(e) => setGateway(e.target.value)}
              placeholder="203.0.113.1"
              disabled={blackhole}
              className="font-mono"
              aria-label="Gateway"
            />
          </div>
          <div>
            <FieldLabel hint="optional">Interface</FieldLabel>
            <Select value={interfaceName} onValueChange={setInterfaceName}>
              <SelectTrigger aria-label="Outgoing interface">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">auto</SelectItem>
                {props.ifaces.map((i) => (
                  <SelectItem key={i.id} value={i.name}>
                    {i.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex flex-wrap gap-6">
            <Label className="flex items-center gap-2 text-sm">
              <Switch checked={blackhole} onCheckedChange={setBlackhole} aria-label="Toggle blackhole" /> Blackhole
            </Label>
            <Label className="flex items-center gap-2 text-sm">
              <Switch checked={bfd} disabled={blackhole} onCheckedChange={setBfd} aria-label="Toggle BFD monitoring" /> BFD monitoring
            </Label>
            <Label className="flex items-center gap-2 text-sm">
              <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="Toggle route enabled" /> Enabled
            </Label>
          </div>
          <div>
            <FieldLabel hint="optional">Description</FieldLabel>
            <Textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2} aria-label="Route description" />
          </div>
          {error && <p className="text-xs font-medium text-rose-600 dark:text-rose-400">{error}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => props.onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={mut.isPending} className="bg-amber-700 text-white hover:bg-amber-800">
            {mut.isPending ? "Saving…" : isEdit ? "Save changes" : "Create route"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── policy-based routes tab ─────────────────────────────────────────────────

function PbrTab() {
  const queryClient = useQueryClient();

  const pbrQuery = useQuery({ queryKey: PBR_KEY, queryFn: () => netApi.listPbr() });
  const addrQuery = useQuery({ queryKey: ["network", "objects", "address"], queryFn: () => netApi.listAddressObjects() });
  const addrGrpQuery = useQuery({ queryKey: ["network", "objects", "address-groups"], queryFn: () => netApi.listAddressGroups() });
  const svcQuery = useQuery({ queryKey: ["network", "objects", "service"], queryFn: () => netApi.listServiceObjects() });
  const svcGrpQuery = useQuery({ queryKey: ["network", "objects", "service-groups"], queryFn: () => netApi.listServiceGroups() });

  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<PbrRow | null>(null);
  const [deleting, setDeleting] = useState<PbrRow | null>(null);
  const [applyingRule, setApplyingRule] = useState<PbrRow | "all" | null>(null);
  const [planDialogRule, setPlanDialogRule] = useState<PbrRow | "all" | null>(null);

  // plan preview (GET /pbr-rules/apply) — shown in the per-rule plan dialog
  const planPreviewQuery = useQuery({ queryKey: PBR_PLANS_KEY, queryFn: () => netApi.previewPbrPlans(), enabled: false, staleTime: 15_000 });

  const rules = useMemo(() => [...(pbrQuery.data?.data ?? [])].sort((a, b) => a.position - b.position), [pbrQuery.data]);

  const pbrApplyMut = useMutation({
    mutationFn: (target: PbrRow | "all") => netApi.applyPbr(target === "all" ? undefined : target.id),
    onSuccess: (outcomes) => {
      for (const o of outcomes) {
        if (o.os.gate === "off") toastOk(`Policy route ${o.name} — plan preview only`, o.os.reason);
        else if (o.configOnly) toastOk(`Policy route ${o.name} — config-only`, "kernel cannot express this match — see the plan preview for the reason");
        else if (o.os.applied) toastOk(`Policy route ${o.name}`, "applied to the kernel");
        else toastErr(new NetApiError("OS_APPLY", o.os.reason), `Policy route ${o.name}`);
      }
      setApplyingRule(null);
    },
    onError: (err) => toastErr(err, "Kernel sync failed"),
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: PBR_KEY });
      void queryClient.invalidateQueries({ queryKey: PBR_PLANS_KEY });
    },
  });

  const moveMut = useMutation({
    mutationFn: ({ id, position }: { id: number; position: number }) => netApi.movePbr(id, position),
    onSuccess: (res) => {
      if (res.moved) toastOk("Policy route moved", res.swappedWith ? `swapped with ${res.swappedWith}` : undefined);
    },
    onError: (err) => toastErr(err, "Move failed"),
    onSettled: () => void queryClient.invalidateQueries({ queryKey: PBR_KEY }),
  });

  const addrById = useMemo(() => {
    const m = new Map<number, ObjectInfo>();
    (addrQuery.data?.data as AddrObjectExt[] | undefined)?.forEach((a) =>
      m.set(a.id, { name: a.name, isGroup: false, memberCount: 0, sub: a.value ?? "" }),
    );
    (addrGrpQuery.data?.data as GroupExt[] | undefined)?.forEach((g) =>
      m.set(g.id, { name: g.name, isGroup: true, memberCount: g.memberIds?.length ?? 0, sub: "group" }),
    );
    return m;
  }, [addrQuery.data, addrGrpQuery.data]);

  const svcById = useMemo(() => {
    const m = new Map<number, ObjectInfo>();
    (svcQuery.data?.data as ServiceExt[] | undefined)?.forEach((s) =>
      m.set(s.id, { name: s.name, isGroup: false, memberCount: 0, sub: s.dstPort ?? s.protocol ?? "" }),
    );
    (svcGrpQuery.data?.data as GroupExt[] | undefined)?.forEach((g) =>
      m.set(g.id, { name: g.name, isGroup: true, memberCount: g.memberIds?.length ?? 0, sub: "group" }),
    );
    return m;
  }, [svcQuery.data, svcGrpQuery.data]);

  const toggleMut = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => netApi.togglePbr(id, enabled),
    onMutate: async ({ id, enabled }) => {
      await queryClient.cancelQueries({ queryKey: PBR_KEY });
      const prev = queryClient.getQueryData<{ data: PbrRow[] }>(PBR_KEY);
      queryClient.setQueryData<{ data: PbrRow[] }>(PBR_KEY, (old) =>
        old ? { ...old, data: old.data.map((r) => (r.id === id ? { ...r, enabled } : r)) } : old,
      );
      return { prev };
    },
    onError: (err, vars, ctx) => {
      if (ctx?.prev) queryClient.setQueryData(PBR_KEY, ctx.prev);
      toastErr(err, `Failed to ${vars.enabled ? "enable" : "disable"} policy route`);
    },
    onSettled: () => void queryClient.invalidateQueries({ queryKey: PBR_KEY }),
  });

  const deleteMut = useMutation({
    mutationFn: (id: number) => netApi.deletePbr(id),
    onSuccess: () => {
      toastOk("Policy route deleted");
      setDeleting(null);
    },
    onError: (err) => toastErr(err, "Delete failed"),
    onSettled: () => void queryClient.invalidateQueries({ queryKey: PBR_KEY }),
  });

  const openCreate = () => {
    setEditing(null);
    setEditorOpen(true);
  };

  return (
    <div className="space-y-3">
      <Alert className="border-zinc-500/30 bg-zinc-500/10 text-zinc-700 dark:text-zinc-300">
        <Icons.Info className="h-4 w-4" />
        <AlertTitle>Policy-based routing</AlertTitle>
        <AlertDescription>
          Rules converge into real kernel policy tables (<code className="font-mono">ip rule</code> + dedicated lookup tables, priorities 5000+). Address matches use from/to selectors; <b>service</b> matches compile to kernel protocol selectors (<code className="font-mono">ipproto tcp dport 443</code> style). Only matches the kernel cannot express stay config-only — the Kernel column reports it honestly. PBR evaluates before multi-WAN mode selection.
        </AlertDescription>
      </Alert>

      <div className="flex flex-wrap items-center justify-end gap-2">
        <Button
          size="sm"
          variant="outline"
          disabled={planPreviewQuery.isFetching}
          onClick={() => {
            setPlanDialogRule("all");
            void planPreviewQuery.refetch();
          }}
          aria-label="Preview apply plans"
        >
          <Icons.Terminal className={cn("mr-1 h-4 w-4", planPreviewQuery.isFetching && "animate-spin")} /> Preview plans
        </Button>
        <Button
          size="sm"
          variant="outline"
          disabled={pbrApplyMut.isPending}
          onClick={() => setApplyingRule("all")}
          aria-label="Apply all policy routes to kernel"
        >
          <Icons.RefreshCw className={cn("mr-1 h-4 w-4", pbrApplyMut.isPending && "animate-spin")} /> Sync to kernel
        </Button>
        <Button size="sm" onClick={openCreate} className="bg-zinc-700 text-white hover:bg-zinc-800">
          <Icons.Plus className="mr-1 h-4 w-4" /> Add policy route
        </Button>
      </div>

      <Card className="p-0">
        <CardContent className="p-0">
          {pbrQuery.error ? (
            <div className="p-4">
              <QueryError error={pbrQuery.error} onRetry={() => void pbrQuery.refetch()} />
            </div>
          ) : pbrQuery.isLoading ? (
            <div className="p-4">
              <TableSkeleton rows={4} cols={6} />
            </div>
          ) : rules.length === 0 ? (
            <EmptyBlock
              icon={<Icons.GitBranch className="h-6 w-6" />}
              title="No policy routes"
              description="PBR rules steer matching connections to a specific WAN interface or gateway before multi-WAN mode selection applies."
              action={
                <Button onClick={openCreate} className="bg-zinc-700 text-white hover:bg-zinc-800">
                  <Icons.Plus className="mr-1 h-4 w-4" /> Add policy route
                </Button>
              }
            />
          ) : (
            <ScrollWrap>
              <Table className="min-w-[860px] text-sm">
                <TableHeader className="sticky top-0 z-10 bg-card">
                  <TableRow>
                    <TableHead className="w-12">Pos</TableHead>
                    <TableHead className="w-14">On</TableHead>
                    <TableHead>Name</TableHead>
                    <TableHead>Match (src → dst · service)</TableHead>
                    <TableHead>Action</TableHead>
                    <TableHead className="w-32">Kernel</TableHead>
                    <TableHead className="w-28 pr-2 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rules.map((r) => (
                    <TableRow key={r.id} className={cn(!r.enabled && "opacity-55")}>
                      <TableCell className="tabular-nums text-zinc-500">{r.position}</TableCell>
                      <TableCell>
                        <Switch
                          checked={r.enabled}
                          disabled={toggleMut.isPending}
                          aria-label={`Toggle policy route ${r.name}`}
                          onCheckedChange={(checked) => toggleMut.mutate({ id: r.id, enabled: checked })}
                        />
                      </TableCell>
                      <TableCell>
                        <span className="block max-w-40 truncate text-sm font-medium">{r.name}</span>
                        {r.description ? <p className="max-w-40 truncate text-[11px] text-zinc-400">{r.description}</p> : null}
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap items-center gap-1.5">
                          <ObjectChips ids={r.srcAddrIds} map={addrById} />
                          <Icons.ArrowRight className="h-3 w-3 shrink-0 text-zinc-400" />
                          <ObjectChips ids={r.dstAddrIds} map={addrById} />
                          <span className="text-zinc-300 dark:text-zinc-700">·</span>
                          <ObjectChips ids={r.serviceIds} map={svcById} />
                        </div>
                        {r.matches && (r.matches.src.length > 0 || r.matches.dst.length > 0 || r.matches.services.length > 0) ? (
                          <p className="mt-1 max-w-md truncate font-mono text-[10px] text-zinc-400" title={`${r.matches.src.join(", ") || "any"} → ${r.matches.dst.join(", ") || "any"}${r.matches.services.length ? ` · ${r.matches.services.join(" · ")}` : ""}`}>
                            {r.matches.src.join(", ") || "any"} → {r.matches.dst.join(", ") || "any"}
                            {r.matches.services.length ? ` · ${r.matches.services.join(" · ")}` : ""}
                            {r.matches.srcUnresolved + r.matches.dstUnresolved > 0
                              ? ` (+${r.matches.srcUnresolved + r.matches.dstUnresolved} non-CIDR objects skipped)`
                              : ""}
                          </p>
                        ) : null}
                      </TableCell>
                      <TableCell>
                        <span className="font-mono text-xs">
                          {r.outgoingIface ? `→ ${r.outgoingIface}` : r.gateway ? `→ ${r.gateway}` : "—"}
                        </span>
                      </TableCell>
                      <TableCell>
                        <PbrKernelBadge state={r.kernelState} />
                      </TableCell>
                      <TableCell className="pr-2 text-right">
                        <div className="flex items-center justify-end gap-0.5">
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8"
                            aria-label={`Move ${r.name} up`}
                            disabled={r.position <= 1 || moveMut.isPending}
                            onClick={() => moveMut.mutate({ id: r.id, position: r.position - 1 })}
                          >
                            <Icons.ChevronUp className="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8"
                            aria-label={`Move ${r.name} down`}
                            disabled={r.position >= rules.length || moveMut.isPending}
                            onClick={() => moveMut.mutate({ id: r.id, position: r.position + 1 })}
                          >
                            <Icons.ChevronDown className="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8"
                            aria-label={`Preview kernel plan for ${r.name}`}
                            title="Preview the ip rule / table commands for this policy route"
                            onClick={() => {
            setPlanDialogRule(r);
            void planPreviewQuery.refetch();
          }}
                          >
                            <Icons.Terminal className="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8"
                            aria-label={`Sync policy route ${r.name} to kernel`}
                            title="Install/withdraw this policy route in the kernel"
                            disabled={pbrApplyMut.isPending}
                            onClick={() => setApplyingRule(r)}
                          >
                            <Icons.RefreshCw className="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8"
                            aria-label={`Edit policy route ${r.name}`}
                            onClick={() => {
                              setEditing(r);
                              setEditorOpen(true);
                            }}
                          >
                            <Icons.Pencil className="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8 text-rose-600 hover:text-rose-700 dark:text-rose-400"
                            aria-label={`Delete policy route ${r.name}`}
                            onClick={() => setDeleting(r)}
                          >
                            <Icons.Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </ScrollWrap>
          )}
        </CardContent>
      </Card>

      {editorOpen && (
        <PbrEditor
          key={editing?.id ?? "new"}
          open={editorOpen}
          onOpenChange={setEditorOpen}
          editing={editing}
          nextPosition={rules.reduce((max, r) => Math.max(max, r.position), 0) + 1}
          onSaved={() => void queryClient.invalidateQueries({ queryKey: PBR_KEY })}
        />
      )}

      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title="Delete policy route?"
        description={`Delete policy route '${deleting?.name ?? ""}'? Matching connections fall back to multi-WAN mode selection. Kernel policy entries are withdrawn best-effort.`}
        loading={deleteMut.isPending}
        onConfirm={() => deleting && deleteMut.mutate(deleting.id)}
      />

      <ConfirmDialog
        open={applyingRule !== null}
        onOpenChange={(open) => !open && setApplyingRule(null)}
        title="Sync policy routes to the kernel?"
        description={
          applyingRule === "all"
            ? "Every rule converges: enabled rules install ip rule entries (priorities 5000+) + dedicated lookup tables — address matches use from/to selectors, service matches compile to ipproto/sport/dport selectors; disabled rules withdraw theirs. Kernel-inexpressible matches stay config-only."
            : `Converge '${applyingRule?.name ?? ""}' into the kernel (gated by the appliance OS-apply policy).`
        }
        loading={pbrApplyMut.isPending}
        onConfirm={() => applyingRule && pbrApplyMut.mutate(applyingRule)}
      />

      {/* plan preview dialog (GET /pbr-rules/apply — no exec) */}
      <Dialog
        open={planDialogRule !== null}
        onOpenChange={(open) => {
          if (!open) setPlanDialogRule(null);
        }}
      >
        <DialogContent className="max-h-[85vh] w-[calc(100vw-1rem)] overflow-y-auto sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Icons.Terminal className="h-4 w-4 text-zinc-500" />
              Kernel apply plans {planDialogRule === "all" ? "— all rules" : planDialogRule ? `— ${planDialogRule.name}` : ""}
            </DialogTitle>
            <DialogDescription>Preview only — nothing is executed until you use Sync to kernel.</DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            {planPreviewQuery.isFetching && <p className="text-xs text-zinc-400">Building plans…</p>}
            {planPreviewQuery.error ? (
              <QueryError error={planPreviewQuery.error} onRetry={() => void planPreviewQuery.refetch()} />
            ) : (
              (planPreviewQuery.data ?? [])
                .filter((p) => (planDialogRule === "all" ? true : planDialogRule != null && p.id === planDialogRule.id))
                .map((p) => (
                  <div key={p.id} className="rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
                    <div className="mb-1.5 flex flex-wrap items-center gap-2">
                      <p className="font-mono text-xs font-semibold">{p.name}</p>
                      <PbrKernelBadge state={p.state} />
                      {p.configOnly ? <Badge variant="outline" className="border-amber-500/40 bg-amber-500/10 text-[10px] text-amber-600 dark:text-amber-400">config-only</Badge> : null}
                    </div>
                    <p className="mb-1.5 text-[11px] text-zinc-500">{p.reason}</p>
                    {p.plan.length === 0 ? (
                      <p className="text-xs text-zinc-400">No kernel steps needed.</p>
                    ) : (
                      <ul className="space-y-1">
                        {p.plan.map((s, i) => (
                          <li key={i} className="flex items-start gap-2 text-xs">
                            <span className="font-mono text-zinc-700 dark:text-zinc-300">$ {s.cmd}</span>
                            <span className="ml-auto shrink-0 text-[10px] text-zinc-400">{s.summary}</span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                ))
            )}
            {!planPreviewQuery.isFetching && !planPreviewQuery.error && (planPreviewQuery.data ?? []).length === 0 && (
              <p className="text-sm text-zinc-500">No policy routes to preview.</p>
            )}
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setPlanDialogRule(null)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function PbrEditor(props: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editing: PbrRow | null;
  nextPosition: number;
  onSaved: () => void;
}) {
  const editing = props.editing;
  const isEdit = editing != null;

  const addrQuery = useQuery({ queryKey: ["network", "objects", "address"], queryFn: () => netApi.listAddressObjects() });
  const addrGrpQuery = useQuery({ queryKey: ["network", "objects", "address-groups"], queryFn: () => netApi.listAddressGroups() });
  const svcQuery = useQuery({ queryKey: ["network", "objects", "service"], queryFn: () => netApi.listServiceObjects() });
  const svcGrpQuery = useQuery({ queryKey: ["network", "objects", "service-groups"], queryFn: () => netApi.listServiceGroups() });
  const ifacesQuery = useQuery({ queryKey: IFACES_KEY, queryFn: () => netApi.listIfaces() });

  const [name, setName] = useState(editing?.name ?? "");
  const [position, setPosition] = useState(String(editing?.position ?? props.nextPosition));
  const [srcIds, setSrcIds] = useState<number[]>(editing?.srcAddrIds ?? []);
  const [dstIds, setDstIds] = useState<number[]>(editing?.dstAddrIds ?? []);
  const [svcIds, setSvcIds] = useState<number[]>(editing?.serviceIds ?? []);
  const [egress, setEgress] = useState<"iface" | "gateway">(
    editing?.outgoingIface ? "iface" : editing?.gateway ? "gateway" : "iface",
  );
  const [outgoingIface, setOutgoingIface] = useState(editing?.outgoingIface ?? "");
  const [gateway, setGateway] = useState(editing?.gateway ?? "");
  const [enabled, setEnabled] = useState(editing?.enabled ?? true);
  const [description, setDescription] = useState(editing?.description ?? "");
  const [error, setError] = useState<string | null>(null);

  const ifaces = useMemo(() => ifacesQuery.data?.data ?? [], [ifacesQuery.data]);

  const mut = useMutation({
    mutationFn: (body: PbrBody) => (isEdit && editing ? netApi.updatePbr(editing.id, body) : netApi.createPbr(body)),
    onSuccess: (saved) => {
      toastOk(isEdit ? "Policy route updated" : "Policy route created", saved.name);
      props.onOpenChange(false);
      props.onSaved();
    },
    onError: (err) => toastErr(err, isEdit ? "Update failed" : "Create failed"),
  });

  const submit = () => {
    if (!name.trim()) return setError("Name is required");
    const pos = Number(position);
    if (!Number.isInteger(pos) || pos < 1) return setError("Position must be a positive integer");
    const gw = gateway.trim();
    if (egress === "gateway" && gw === "") return setError("Exactly one of outgoing interface or gateway is required");
    if (egress === "gateway" && !isValidIpv4(gw)) return setError("Gateway must be a valid IPv4 address");
    if (egress === "iface" && outgoingIface === "") return setError("Exactly one of outgoing interface or gateway is required");
    setError(null);
    const body: PbrBody = {
      name: name.trim(),
      position: pos,
      enabled,
      srcAddrIds: srcIds,
      dstAddrIds: dstIds,
      serviceIds: svcIds,
      outgoingIface: egress === "iface" ? outgoingIface : null,
      gateway: egress === "gateway" ? gw : null,
      description: description.trim() || null,
    };
    mut.mutate(body);
  };

  const addrObjects = useMemo(
    () => ((addrQuery.data?.data ?? []) as AddrObjectExt[]).map((o) => ({ id: o.id, name: o.name, sub: o.value ?? "" })),
    [addrQuery.data],
  );
  const addrGroups = useMemo(
    () => ((addrGrpQuery.data?.data ?? []) as GroupExt[]).map((g) => ({ id: g.id, name: g.name, memberCount: g.memberIds?.length ?? 0 })),
    [addrGrpQuery.data],
  );
  const svcObjects = useMemo(
    () => ((svcQuery.data?.data ?? []) as ServiceExt[]).map((s) => ({ id: s.id, name: s.name, sub: s.dstPort ?? s.protocol ?? "" })),
    [svcQuery.data],
  );
  const svcGroups = useMemo(
    () => ((svcGrpQuery.data?.data ?? []) as GroupExt[]).map((g) => ({ id: g.id, name: g.name, memberCount: g.memberIds?.length ?? 0 })),
    [svcGrpQuery.data],
  );

  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent className="max-h-[90vh] w-[calc(100vw-1rem)] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{isEdit ? `Edit policy route — ${editing.name}` : "Add policy route"}</DialogTitle>
          <DialogDescription>
            Empty match fields mean &ldquo;any&rdquo;. Egress is one of outgoing interface or gateway — never both (server rejects with 400).
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <FieldLabel>Name</FieldLabel>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="voip-via-wan1" aria-label="Policy route name" />
            </div>
            <div>
              <FieldLabel hint="lower evaluates first">Position</FieldLabel>
              <Input type="number" min={1} value={position} onChange={(e) => setPosition(e.target.value)} aria-label="Position" />
            </div>
          </div>

          <EditorSection title="Match">
            <div>
              <FieldLabel hint="objects + groups">Source addresses</FieldLabel>
              <ObjectPicker
                kind="address"
                objects={addrObjects}
                groups={addrGroups}
                value={srcIds}
                onChange={setSrcIds}
                triggerLabel="Pick sources"
              />
            </div>
            <div>
              <FieldLabel hint="objects + groups">Destination addresses</FieldLabel>
              <ObjectPicker
                kind="address"
                objects={addrObjects}
                groups={addrGroups}
                value={dstIds}
                onChange={setDstIds}
                triggerLabel="Pick destinations"
              />
            </div>
            <div>
              <FieldLabel hint="objects + groups">Services</FieldLabel>
              <ObjectPicker
                kind="service"
                objects={svcObjects}
                groups={svcGroups}
                value={svcIds}
                onChange={setSvcIds}
                triggerLabel="Pick services"
              />
            </div>
          </EditorSection>

          <EditorSection title="Egress">
            <RadioGroup value={egress} onValueChange={(v) => setEgress(v as "iface" | "gateway")} className="flex gap-4">
              <Label className="flex cursor-pointer items-center gap-2 text-sm">
                <RadioGroupItem value="iface" /> Outgoing interface
              </Label>
              <Label className="flex cursor-pointer items-center gap-2 text-sm">
                <RadioGroupItem value="gateway" /> Gateway
              </Label>
            </RadioGroup>
            {egress === "iface" ? (
              <Select value={outgoingIface || undefined} onValueChange={setOutgoingIface}>
                <SelectTrigger aria-label="Outgoing interface">
                  <SelectValue placeholder="select interface…" />
                </SelectTrigger>
                <SelectContent>
                  {ifaces.map((i) => (
                    <SelectItem key={i.id} value={i.name}>
                      {i.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            ) : (
              <Input
                value={gateway}
                onChange={(e) => setGateway(e.target.value)}
                placeholder="192.0.2.1"
                className="font-mono"
                aria-label="Next-hop gateway"
              />
            )}
            <p className="text-[11px] text-zinc-400">Exactly one required — switching the radio clears the other on save.</p>
          </EditorSection>

          <div className="flex items-center justify-between">
            <Label className="flex items-center gap-2 text-sm">
              <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="Toggle policy route enabled" /> Enabled
            </Label>
          </div>
          <div>
            <FieldLabel hint="optional">Description</FieldLabel>
            <Textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2} aria-label="Policy route description" />
          </div>
          {error && <p className="text-xs font-medium text-rose-600 dark:text-rose-400">{error}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => props.onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={mut.isPending} className="bg-amber-700 text-white hover:bg-amber-800">
            {mut.isPending ? "Saving…" : isEdit ? "Save changes" : "Create policy route"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
