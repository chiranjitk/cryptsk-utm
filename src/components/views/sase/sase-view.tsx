"use client";

/**
 * SASE view (spec §4.2) — console-side mesh config: a four-tab workspace over
 * the node registry (cloud firewall nodes with cloud/role/status badges),
 * the tunnel registry (from → to with an arrow icon, state badges, subnet
 * chips), the PLAN-ONLY WireGuard mesh renderer (per-node wg-quick config
 * cards with copy-to-clipboard, validation errors as destructive alerts) and
 * the identity-aware routing stub (user → region → resolved node table,
 * upsert dialog + resolve test box).
 *
 * The mesh tab is preview-only by contract: configs carry redacted key
 * placeholders and nothing is applied to the host OS. Tone map (UI_DESIGN_SYSTEM
 * §2): active = emerald, planned = zinc, down = rose; clouds zinc/amber/cyan/
 * emerald — no indigo/blue.
 */

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";
import {
  SASE_CLOUDS,
  SASE_ENDPOINT_RE,
  SASE_ROLES,
  SASE_STATUSES,
  SASE_TUNNEL_STATES,
  parseCidrInput,
  saseApi,
  type SaseCloud,
  type SaseMeshPlanDTO,
  type SaseNodeDTO,
  type SaseRole,
  type SaseStatus,
  type SaseTunnelDTO,
  type SaseTunnelState,
} from "./sase-api";
import { ConfirmDialog, EmptyBlock, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";
import { usePermissions } from "../system/system-ui";

function invalidateAll(queryClient: ReturnType<typeof useQueryClient>) {
  void queryClient.invalidateQueries({ queryKey: ["sase"] });
}

// ── badge recipes (UI_DESIGN_SYSTEM §2 — active=emerald, planned=zinc, down=rose) ──

const STATUS_BADGE: Record<SaseStatus | SaseTunnelState, { cls: string; icon: React.ComponentType<{ className?: string }> }> = {
  planned: { cls: "border-zinc-400/60 bg-zinc-500/5 text-zinc-600 dark:text-zinc-300", icon: Icons.CircleDashed },
  active: { cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400", icon: Icons.CircleCheck },
  down: { cls: "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400", icon: Icons.Ban },
};

function StatusBadge({ status }: { status: SaseStatus | SaseTunnelState }) {
  const def = STATUS_BADGE[status] ?? STATUS_BADGE.planned;
  const Icon = def.icon;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium capitalize", def.cls)}>
      <Icon className="h-3 w-3" />
      {status}
    </Badge>
  );
}

const CLOUD_BADGE: Record<SaseCloud, { cls: string; icon: React.ComponentType<{ className?: string }> }> = {
  onprem: { cls: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300", icon: Icons.Server },
  aws: { cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400", icon: Icons.Cloud },
  azure: { cls: "border-cyan-500/40 bg-cyan-500/10 text-cyan-600 dark:text-cyan-400", icon: Icons.Cloud },
  gcp: { cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400", icon: Icons.Cloud },
};

function CloudBadge({ cloud }: { cloud: SaseCloud }) {
  const def = CLOUD_BADGE[cloud] ?? CLOUD_BADGE.onprem;
  const Icon = def.icon;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium uppercase", def.cls)} title={`cloud: ${cloud}`}>
      <Icon className="h-3 w-3" />
      {cloud}
    </Badge>
  );
}

function RoleBadge({ role }: { role: SaseRole }) {
  const gateway = role === "gateway";
  const Icon = gateway ? Icons.Waypoints : Icons.Router;
  return (
    <Badge
      variant="outline"
      className={cn(
        "gap-1 font-medium capitalize",
        gateway
          ? "border-orange-500/40 bg-orange-500/10 text-orange-600 dark:text-orange-400"
          : "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
      )}
      title={gateway ? "mesh gateway" : "edge node"}
    >
      <Icon className="h-3 w-3" />
      {role}
    </Badge>
  );
}

function SubnetChips({ subnets }: { subnets: string[] }) {
  if (subnets.length === 0) return <span className="text-xs text-zinc-400">—</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {subnets.slice(0, 3).map((s) => (
        <Badge key={s} variant="outline" className="px-1.5 font-mono text-[10px] text-zinc-600 dark:text-zinc-300">
          {s}
        </Badge>
      ))}
      {subnets.length > 3 && (
        <Badge variant="outline" className="px-1.5 text-[10px] text-zinc-500">
          +{subnets.length - 3}
        </Badge>
      )}
    </div>
  );
}

// ── nodes tab ───────────────────────────────────────────────────────────────

function NodeEditor(props: { node: SaseNodeDTO | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = props.node !== null;
  const [name, setName] = useState(props.node?.name ?? "");
  const [cloud, setCloud] = useState<SaseCloud>(props.node?.cloud ?? "onprem");
  const [region, setRegion] = useState(props.node?.region ?? "");
  const [role, setRole] = useState<SaseRole>(props.node?.role ?? "edge");
  const [endpoint, setEndpoint] = useState(props.node?.tunnelEndpoint ?? "");
  const [subnets, setSubnets] = useState(props.node?.publicSubnets.join(", ") ?? "");
  const [status, setStatus] = useState<SaseStatus>(props.node?.status ?? "planned");
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => {
      const id = props.node?.id;
      if (isEdit && id !== undefined) return saseApi.updateNode(id, body);
      return saseApi.createNode(body);
    },
    onSuccess: (n) => {
      toastOk(isEdit ? "Node updated" : "Node created", n.name);
      invalidateAll(queryClient);
      props.onClose();
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Save failed"),
  });

  const submit = () => {
    if (!name.trim()) {
      setErr("Name is required");
      return;
    }
    const trimmedEndpoint = endpoint.trim();
    if (trimmedEndpoint && !SASE_ENDPOINT_RE.test(trimmedEndpoint)) {
      setErr("Endpoint must be host[:port] without spaces (e.g. edge.example.com:51820)");
      return;
    }
    const parsed = parseCidrInput(subnets);
    if (parsed === null) {
      setErr("Public subnets must be comma-separated IPv4 CIDRs (e.g. 10.10.0.0/16)");
      return;
    }
    setErr(null);
    save.mutate({
      name: name.trim(),
      cloud,
      region: region.trim(),
      role,
      tunnelEndpoint: trimmedEndpoint,
      publicSubnets: parsed,
      status,
    });
  };

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-base">{isEdit ? "Edit node" : "New SASE node"}</DialogTitle>
          <DialogDescription>
            Registry entry for a cloud firewall node — the mesh renderer turns it into a wg-quick plan.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label className="text-xs font-medium">Name</Label>
              <Input className="mt-1.5" value={name} onChange={(e) => setName(e.target.value)} placeholder="edge-nyc" />
            </div>
            <div>
              <Label className="text-xs font-medium">Cloud</Label>
              <Select value={cloud} onValueChange={(v) => setCloud(v as SaseCloud)}>
                <SelectTrigger className="mt-1.5">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SASE_CLOUDS.map((c) => (
                    <SelectItem key={c} value={c}>
                      {c}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label className="text-xs font-medium">Region</Label>
              <Input className="mt-1.5" value={region} onChange={(e) => setRegion(e.target.value)} placeholder="us-east-1" />
            </div>
            <div>
              <Label className="text-xs font-medium">Role</Label>
              <Select value={role} onValueChange={(v) => setRole(v as SaseRole)}>
                <SelectTrigger className="mt-1.5">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SASE_ROLES.map((r) => (
                    <SelectItem key={r} value={r}>
                      {r}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div>
            <Label className="text-xs font-medium">Tunnel endpoint</Label>
            <Input
              className="mt-1.5 font-mono"
              value={endpoint}
              onChange={(e) => setEndpoint(e.target.value)}
              placeholder="edge.example.com:51820"
            />
            <p className="mt-1 text-[11px] text-zinc-400">host:port — the renderer flags endpoints without a port.</p>
          </div>
          <div>
            <Label className="text-xs font-medium">Public subnets</Label>
            <Input
              className="mt-1.5 font-mono"
              value={subnets}
              onChange={(e) => setSubnets(e.target.value)}
              placeholder="10.10.0.0/16, 10.20.0.0/16"
            />
            <p className="mt-1 text-[11px] text-zinc-400">Comma-separated IPv4 CIDRs routed behind this node.</p>
          </div>
          <div>
            <Label className="text-xs font-medium">Status</Label>
            <Select value={status} onValueChange={(v) => setStatus(v as SaseStatus)}>
              <SelectTrigger className="mt-1.5">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {SASE_STATUSES.map((s) => (
                  <SelectItem key={s} value={s}>
                    {s}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="mt-1 text-[11px] text-zinc-400">Only active nodes win identity-aware routing.</p>
          </div>
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button
            className="bg-zinc-700 text-white hover:bg-zinc-800"
            disabled={save.isPending || !name.trim()}
            onClick={submit}
          >
            {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create node"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function NodesTab() {
  const queryClient = useQueryClient();
  const { canWrite } = usePermissions();
  const canEdit = canWrite("sase");
  const nodesQuery = useQuery({ queryKey: ["sase", "nodes"], queryFn: saseApi.listNodes });
  const nodes = nodesQuery.data ?? [];

  const [addOpen, setAddOpen] = useState(false);
  const [editing, setEditing] = useState<SaseNodeDTO | null>(null);
  const [deleting, setDeleting] = useState<SaseNodeDTO | null>(null);

  const del = useMutation({
    mutationFn: (id: number) => saseApi.deleteNode(id),
    onSuccess: () => {
      toastOk("Node deleted");
      setDeleting(null);
      invalidateAll(queryClient);
    },
    onError: (e) => {
      setDeleting(null);
      toastErr(e, "Delete failed");
    },
  });

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
        <div className="min-w-0">
          <CardTitle className="text-sm">Nodes</CardTitle>
          <CardDescription className="mt-0.5 text-xs">
            Cloud firewall nodes (on-prem + AWS/Azure/GCP) managed by the central controller.
          </CardDescription>
        </div>
        {canEdit && (
          <Button
            size="sm"
            className="h-8 bg-zinc-700 text-white hover:bg-zinc-800"
            onClick={() => setAddOpen(true)}
          >
            <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add node
          </Button>
        )}
      </CardHeader>
      <CardContent className="p-4 pt-0">
        {nodesQuery.isError ? (
          <QueryError error={nodesQuery.error} onRetry={() => void nodesQuery.refetch()} />
        ) : nodesQuery.isLoading ? (
          <TableSkeleton rows={4} cols={7} />
        ) : nodes.length === 0 ? (
          <EmptyBlock
            icon={<Icons.Server className="h-6 w-6" />}
            title="No SASE nodes yet"
            description="Register the on-prem edge and cloud firewall nodes to build the edge-to-cloud mesh."
            action={
              canEdit ? (
                <Button size="sm" className="bg-zinc-700 text-white hover:bg-zinc-800" onClick={() => setAddOpen(true)}>
                  <Icons.Plus className="mr-1 h-3.5 w-3.5" /> New node
                </Button>
              ) : undefined
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Cloud</TableHead>
                  <TableHead>Region</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Endpoint</TableHead>
                  <TableHead>Subnets</TableHead>
                  <TableHead>Status</TableHead>
                  {canEdit && <TableHead className="w-16" />}
                </TableRow>
              </TableHeader>
              <TableBody>
                {nodes.map((n) => (
                  <TableRow key={n.id}>
                    <TableCell className="font-medium">{n.name}</TableCell>
                    <TableCell>
                      <CloudBadge cloud={n.cloud} />
                    </TableCell>
                    <TableCell className="text-zinc-500">{n.region || "—"}</TableCell>
                    <TableCell>
                      <RoleBadge role={n.role} />
                    </TableCell>
                    <TableCell className="font-mono text-xs">{n.tunnelEndpoint || <span className="text-zinc-400">—</span>}</TableCell>
                    <TableCell>
                      <SubnetChips subnets={n.publicSubnets} />
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={n.status} />
                    </TableCell>
                    {canEdit && (
                      <TableCell>
                        <div className="flex justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 px-2"
                            aria-label={`Edit ${n.name}`}
                            onClick={() => setEditing(n)}
                          >
                            <Icons.Pencil className="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 px-2 text-rose-600 hover:text-rose-700"
                            aria-label={`Delete ${n.name}`}
                            onClick={() => setDeleting(n)}
                          >
                            <Icons.Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                      </TableCell>
                    )}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>

      {addOpen && <NodeEditor node={null} onClose={() => setAddOpen(false)} />}
      {editing && <NodeEditor node={editing} onClose={() => setEditing(null)} />}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(o) => !o && setDeleting(null)}
        title="Delete node"
        description={`Delete SASE node '${deleting?.name ?? ""}'? Nodes still referenced by tunnels are refused.`}
        loading={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting.id)}
      />
    </Card>
  );
}

// ── tunnels tab ─────────────────────────────────────────────────────────────

function TunnelEditor(props: {
  tunnel: SaseTunnelDTO | null;
  nodes: SaseNodeDTO[];
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const isEdit = props.tunnel !== null;
  const [name, setName] = useState(props.tunnel?.name ?? "");
  const [fromNodeId, setFromNodeId] = useState<string>(
    props.tunnel ? String(props.tunnel.fromNodeId) : (props.nodes[0] ? String(props.nodes[0].id) : ""),
  );
  const [toNodeId, setToNodeId] = useState<string>(
    props.tunnel ? String(props.tunnel.toNodeId) : (props.nodes[1] ? String(props.nodes[1].id) : ""),
  );
  const [state, setState] = useState<SaseTunnelState>(props.tunnel?.state ?? "planned");
  const [pskRef, setPskRef] = useState(props.tunnel?.pskRef ?? "");
  const [subnets, setSubnets] = useState(props.tunnel?.allowedSubnets.join(", ") ?? "");
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => {
      const id = props.tunnel?.id;
      if (isEdit && id !== undefined) return saseApi.updateTunnel(id, body);
      return saseApi.createTunnel(body);
    },
    onSuccess: (t) => {
      toastOk(isEdit ? "Tunnel updated" : "Tunnel created", t.name);
      invalidateAll(queryClient);
      props.onClose();
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Save failed"),
  });

  const submit = () => {
    if (!name.trim()) {
      setErr("Name is required");
      return;
    }
    if (!fromNodeId || !toNodeId) {
      setErr("Both endpoints must reference existing nodes");
      return;
    }
    if (fromNodeId === toNodeId) {
      setErr("A tunnel cannot connect a node to itself");
      return;
    }
    const parsed = parseCidrInput(subnets);
    if (parsed === null) {
      setErr("Allowed subnets must be comma-separated IPv4 CIDRs (e.g. 10.10.0.0/16)");
      return;
    }
    setErr(null);
    save.mutate({
      name: name.trim(),
      fromNodeId: Number(fromNodeId),
      toNodeId: Number(toNodeId),
      state,
      pskRef: pskRef.trim(),
      allowedSubnets: parsed,
    });
  };

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-base">{isEdit ? "Edit tunnel" : "New tunnel"}</DialogTitle>
          <DialogDescription>
            A planned WireGuard mesh link — the renderer emits a [Peer] block on BOTH endpoints.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label className="text-xs font-medium">Name</Label>
              <Input className="mt-1.5" value={name} onChange={(e) => setName(e.target.value)} placeholder="edge-to-aws" />
            </div>
            <div>
              <Label className="text-xs font-medium">State</Label>
              <Select value={state} onValueChange={(v) => setState(v as SaseTunnelState)}>
                <SelectTrigger className="mt-1.5">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SASE_TUNNEL_STATES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {s}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div>
            <Label className="text-xs font-medium">From node</Label>
            <Select value={fromNodeId} onValueChange={setFromNodeId}>
              <SelectTrigger className="mt-1.5">
                <SelectValue placeholder="Select a node" />
              </SelectTrigger>
              <SelectContent>
                {props.nodes.map((n) => (
                  <SelectItem key={n.id} value={String(n.id)}>
                    {n.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label className="text-xs font-medium">To node</Label>
            <Select value={toNodeId} onValueChange={setToNodeId}>
              <SelectTrigger className="mt-1.5">
                <SelectValue placeholder="Select a node" />
              </SelectTrigger>
              <SelectContent>
                {props.nodes.map((n) => (
                  <SelectItem key={n.id} value={String(n.id)}>
                    {n.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label className="text-xs font-medium">Allowed subnets</Label>
            <Input
              className="mt-1.5 font-mono"
              value={subnets}
              onChange={(e) => setSubnets(e.target.value)}
              placeholder="10.10.0.0/16 (falls back to the remote node subnets)"
            />
          </div>
          <div>
            <Label className="text-xs font-medium">PSK reference</Label>
            <Input
              className="mt-1.5 font-mono"
              value={pskRef}
              onChange={(e) => setPskRef(e.target.value)}
              placeholder="vault:wg/edge-to-aws"
            />
            <p className="mt-1 text-[11px] text-zinc-400">
              Secret-store REFERENCE only — never paste key material; configs render a redacted placeholder.
            </p>
          </div>
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button
            className="bg-zinc-700 text-white hover:bg-zinc-800"
            disabled={save.isPending || !name.trim() || props.nodes.length < 2}
            onClick={submit}
          >
            {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create tunnel"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function TunnelsTab() {
  const queryClient = useQueryClient();
  const { canWrite } = usePermissions();
  const canEdit = canWrite("sase");
  const tunnelsQuery = useQuery({ queryKey: ["sase", "tunnels"], queryFn: saseApi.listTunnels });
  const nodesQuery = useQuery({ queryKey: ["sase", "nodes"], queryFn: saseApi.listNodes });
  const tunnels = tunnelsQuery.data ?? [];
  const nodes = nodesQuery.data ?? [];

  const [addOpen, setAddOpen] = useState(false);
  const [editing, setEditing] = useState<SaseTunnelDTO | null>(null);
  const [deleting, setDeleting] = useState<SaseTunnelDTO | null>(null);

  const del = useMutation({
    mutationFn: (id: number) => saseApi.deleteTunnel(id),
    onSuccess: () => {
      toastOk("Tunnel deleted");
      setDeleting(null);
      invalidateAll(queryClient);
    },
    onError: (e) => {
      setDeleting(null);
      toastErr(e, "Delete failed");
    },
  });

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
        <div className="min-w-0">
          <CardTitle className="text-sm">Tunnels</CardTitle>
          <CardDescription className="mt-0.5 text-xs">
            Edge-to-cloud WireGuard mesh links — every tunnel renders peers on both endpoints.
          </CardDescription>
        </div>
        {canEdit && (
          <Button
            size="sm"
            className="h-8 bg-zinc-700 text-white hover:bg-zinc-800"
            disabled={nodes.length < 2}
            title={nodes.length < 2 ? "Register at least two nodes first" : undefined}
            onClick={() => setAddOpen(true)}
          >
            <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add tunnel
          </Button>
        )}
      </CardHeader>
      <CardContent className="p-4 pt-0">
        {tunnelsQuery.isError ? (
          <QueryError error={tunnelsQuery.error} onRetry={() => void tunnelsQuery.refetch()} />
        ) : tunnelsQuery.isLoading ? (
          <TableSkeleton rows={3} cols={6} />
        ) : tunnels.length === 0 ? (
          <EmptyBlock
            icon={<Icons.Waypoints className="h-6 w-6" />}
            title="No tunnels yet"
            description="Plan an edge-to-cloud link between two nodes to complete the mesh."
            action={
              canEdit && nodes.length >= 2 ? (
                <Button size="sm" className="bg-zinc-700 text-white hover:bg-zinc-800" onClick={() => setAddOpen(true)}>
                  <Icons.Plus className="mr-1 h-3.5 w-3.5" /> New tunnel
                </Button>
              ) : undefined
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Endpoints</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead>Allowed subnets</TableHead>
                  <TableHead>PSK ref</TableHead>
                  {canEdit && <TableHead className="w-16" />}
                </TableRow>
              </TableHeader>
              <TableBody>
                {tunnels.map((t) => (
                  <TableRow key={t.id}>
                    <TableCell className="font-medium">{t.name}</TableCell>
                    <TableCell>
                      <span className="flex items-center gap-1.5 font-mono text-xs">
                        <span>{t.fromNodeName}</span>
                        <Icons.ArrowRight className="h-3.5 w-3.5 shrink-0 text-zinc-400" />
                        <span>{t.toNodeName}</span>
                      </span>
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={t.state} />
                    </TableCell>
                    <TableCell>
                      <SubnetChips subnets={t.allowedSubnets} />
                    </TableCell>
                    <TableCell className="max-w-40 truncate font-mono text-xs" title={t.pskRef || undefined}>
                      {t.pskRef || <span className="text-zinc-400">—</span>}
                    </TableCell>
                    {canEdit && (
                      <TableCell>
                        <div className="flex justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 px-2"
                            aria-label={`Edit ${t.name}`}
                            onClick={() => setEditing(t)}
                          >
                            <Icons.Pencil className="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 px-2 text-rose-600 hover:text-rose-700"
                            aria-label={`Delete ${t.name}`}
                            onClick={() => setDeleting(t)}
                          >
                            <Icons.Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                      </TableCell>
                    )}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>

      {addOpen && <TunnelEditor tunnel={null} nodes={nodes} onClose={() => setAddOpen(false)} />}
      {editing && <TunnelEditor tunnel={editing} nodes={nodes} onClose={() => setEditing(null)} />}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(o) => !o && setDeleting(null)}
        title="Delete tunnel"
        description={`Delete tunnel '${deleting?.name ?? ""}'? Both endpoint configs lose its [Peer] block on the next render.`}
        loading={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting.id)}
      />
    </Card>
  );
}

// ── mesh config tab (plan-only preview) ─────────────────────────────────────

function CopyButton(props: { label: string; content: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(props.content);
      setCopied(true);
      toastOk("Copied to clipboard", props.label);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      toastErr(new Error("Clipboard unavailable"), "Copy failed");
    }
  };
  return (
    <Button variant="outline" size="sm" className="h-7 px-2" onClick={() => void copy()}>
      {copied ? <Icons.Check className="h-3.5 w-3.5 text-emerald-600" /> : <Icons.Copy className="h-3.5 w-3.5" />}
      <span className="ml-1 hidden sm:inline">{copied ? "Copied" : "Copy"}</span>
    </Button>
  );
}

function MeshTab() {
  // enabled: false — the plan is generated ONLY on explicit "Render config"
  // (pure preview, never a background write; the endpoint cannot mutate).
  const planQuery = useQuery({ queryKey: ["sase", "mesh"], queryFn: saseApi.renderMesh, enabled: false });
  const plan: SaseMeshPlanDTO | undefined = planQuery.data;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
        <div className="min-w-0">
          <CardTitle className="text-sm">WireGuard mesh config</CardTitle>
          <CardDescription className="mt-0.5 text-xs">
            Plan-only preview — keys redacted ([REDACTED-SEE-SECRET-STORE]); nothing is applied to the host OS.
          </CardDescription>
        </div>
        <Button
          size="sm"
          className="h-8 bg-zinc-700 text-white hover:bg-zinc-800"
          disabled={planQuery.isFetching}
          onClick={() => void planQuery.refetch()}
        >
          <Icons.RefreshCw className={cn("mr-1 h-3.5 w-3.5", planQuery.isFetching && "animate-spin")} />
          Render config
        </Button>
      </CardHeader>
      <CardContent className="space-y-4 p-4 pt-0">
        {planQuery.isError ? (
          <QueryError error={planQuery.error} onRetry={() => void planQuery.refetch()} />
        ) : !plan ? (
          <EmptyBlock
            icon={<Icons.FileText className="h-6 w-6" />}
            title="No plan rendered yet"
            description="Press Render config to generate the per-node wg-quick preview from the current registry."
          />
        ) : (
          <>
            {plan.valid ? (
              <Alert className="border-emerald-500/40 bg-emerald-500/5">
                <Icons.CircleCheck className="h-4 w-4 text-emerald-600" />
                <AlertTitle>Plan valid</AlertTitle>
                <AlertDescription>
                  {plan.configs.length} node config{plan.configs.length === 1 ? "" : "s"} generated — deploy
                  happens out-of-band via the cloud VM workflow, never from this console.
                </AlertDescription>
              </Alert>
            ) : (
              plan.errors.map((e, i) => (
                <Alert key={`${e.code}-${i}`} variant="destructive" className="border-rose-600/40 bg-rose-600/5">
                  <Icons.TriangleAlert className="h-4 w-4" />
                  <AlertTitle className="font-mono text-xs">{e.code}</AlertTitle>
                  <AlertDescription>{e.message}</AlertDescription>
                </Alert>
              ))
            )}
            {plan.configs.length === 0 ? (
              <EmptyBlock
                icon={<Icons.Server className="h-6 w-6" />}
                title="Nothing to render"
                description="Register SASE nodes first — the renderer emits one wg-quick config per node."
              />
            ) : (
              <div className="grid gap-4 xl:grid-cols-2">
                {plan.configs.map((c) => (
                  <Card key={c.nodeId} className="overflow-hidden">
                    <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 border-b border-zinc-200 py-2.5 dark:border-zinc-800">
                      <CardTitle className="min-w-0 truncate font-mono text-xs font-semibold" title={c.filename}>
                        {c.filename}
                      </CardTitle>
                      <div className="flex shrink-0 items-center gap-1.5">
                        <Badge variant="outline" className="font-medium capitalize text-zinc-500">{c.nodeName}</Badge>
                        <CopyButton label={c.filename} content={c.content} />
                      </div>
                    </CardHeader>
                    <CardContent className="p-0">
                      <pre className="max-h-96 overflow-y-auto bg-zinc-950 p-3 font-mono text-[11px] leading-relaxed text-zinc-100">
                        {c.content}
                      </pre>
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}

// ── identity-aware routing tab (§4.2 stub) ──────────────────────────────────

function RoutingEditor(props: { regions: string[]; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [userEmail, setUserEmail] = useState("");
  const [region, setRegion] = useState(props.regions[0] ?? "");
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: () => saseApi.upsertRouting({ userEmail: userEmail.trim().toLowerCase(), region: region.trim() }),
    onSuccess: (e) => {
      toastOk("Mapping saved", `${e.userEmail} → ${e.region}`);
      invalidateAll(queryClient);
      props.onClose();
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Save failed"),
  });

  const submit = () => {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(userEmail.trim())) {
      setErr("Enter a valid user email");
      return;
    }
    if (!region.trim()) {
      setErr("Region is required");
      return;
    }
    setErr(null);
    save.mutate();
  };

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-base">Add routing mapping</DialogTitle>
          <DialogDescription>
            Map a user to a region — resolution prefers the gateway node, then any active node in that region.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div>
            <Label className="text-xs font-medium">User email</Label>
            <Input
              className="mt-1.5"
              type="email"
              value={userEmail}
              onChange={(e) => setUserEmail(e.target.value)}
              placeholder="alice@corp.example"
            />
          </div>
          <div>
            <Label className="text-xs font-medium">Region</Label>
            <Input
              className="mt-1.5 font-mono"
              value={region}
              onChange={(e) => setRegion(e.target.value)}
              placeholder="us-east-1"
              list="sase-region-options"
            />
            <datalist id="sase-region-options">
              {props.regions.map((r) => (
                <option key={r} value={r} />
              ))}
            </datalist>
            {props.regions.length > 0 && (
              <p className="mt-1 text-[11px] text-zinc-400">Known node regions: {props.regions.join(", ")}</p>
            )}
          </div>
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button className="bg-zinc-700 text-white hover:bg-zinc-800" disabled={save.isPending} onClick={submit}>
            {save.isPending ? "Saving…" : "Save mapping"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function RoutingTab() {
  const queryClient = useQueryClient();
  const { canWrite } = usePermissions();
  const canEdit = canWrite("sase");
  const routingQuery = useQuery({ queryKey: ["sase", "routing"], queryFn: saseApi.listRouting });
  const nodesQuery = useQuery({ queryKey: ["sase", "nodes"], queryFn: saseApi.listNodes });
  const entries = routingQuery.data ?? [];
  const regions = [...new Set((nodesQuery.data ?? []).map((n) => n.region).filter((r) => r.length > 0))];

  const [addOpen, setAddOpen] = useState(false);
  const [testEmail, setTestEmail] = useState("");
  const [testResult, setTestResult] = useState<string | null>(null);
  const [testErr, setTestErr] = useState<string | null>(null);

  const resolve = useMutation({
    mutationFn: (email: string) => saseApi.resolveRouting(email),
    onSuccess: (r) => {
      setTestErr(null);
      setTestResult(
        r.node
          ? `${r.userEmail} → ${r.region} → ${r.node.name} (${r.node.cloud}, ${r.node.region}, ${r.node.role})`
          : r.region
            ? `${r.userEmail} → ${r.region} → no active node available`
            : `${r.userEmail} → no mapping`,
      );
    },
    onError: (e) => {
      setTestResult(null);
      setTestErr(e instanceof Error ? e.message : "Resolve failed");
    },
  });

  const runResolve = () => {
    const email = testEmail.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setTestErr("Enter a valid user email");
      setTestResult(null);
      return;
    }
    setTestErr(null);
    resolve.mutate(email);
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
          <div className="min-w-0">
            <CardTitle className="text-sm">Identity-aware routing map</CardTitle>
            <CardDescription className="mt-0.5 text-xs">
              User → region → nearest routable node (same-region gateway first, else first active). Stub —
              resolution runs at policy evaluation time.
            </CardDescription>
          </div>
          {canEdit && (
            <Button
              size="sm"
              className="h-8 bg-zinc-700 text-white hover:bg-zinc-800"
              onClick={() => setAddOpen(true)}
            >
              <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add mapping
            </Button>
          )}
        </CardHeader>
        <CardContent className="p-4 pt-0">
          {routingQuery.isError ? (
            <QueryError error={routingQuery.error} onRetry={() => void routingQuery.refetch()} />
          ) : routingQuery.isLoading ? (
            <TableSkeleton rows={3} cols={4} />
          ) : entries.length === 0 ? (
            <EmptyBlock
              icon={<Icons.MapPin className="h-6 w-6" />}
              title="No routing mappings yet"
              description="Map users to regions so policy evaluation can anchor them to the nearest SASE node."
              action={
                canEdit ? (
                  <Button size="sm" className="bg-zinc-700 text-white hover:bg-zinc-800" onClick={() => setAddOpen(true)}>
                    <Icons.Plus className="mr-1 h-3.5 w-3.5" /> New mapping
                  </Button>
                ) : undefined
              }
            />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>User email</TableHead>
                    <TableHead>Region</TableHead>
                    <TableHead>Resolved node</TableHead>
                    <TableHead>Updated</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {entries.map((e) => (
                    <TableRow key={e.userEmail}>
                      <TableCell className="font-medium">{e.userEmail}</TableCell>
                      <TableCell className="font-mono text-xs">{e.region}</TableCell>
                      <TableCell>
                        {e.resolvedNode ? (
                          <span className="flex flex-wrap items-center gap-1.5">
                            <span className="font-medium">{e.resolvedNode.name}</span>
                            <CloudBadge cloud={e.resolvedNode.cloud} />
                            <RoleBadge role={e.resolvedNode.role} />
                            <StatusBadge status={e.resolvedNode.status} />
                          </span>
                        ) : (
                          <span className="text-xs text-zinc-400">no active node</span>
                        )}
                      </TableCell>
                      <TableCell className="text-xs text-zinc-500">
                        {e.updatedAt ? new Date(e.updatedAt).toLocaleString() : "—"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Resolve test</CardTitle>
          <CardDescription className="mt-0.5 text-xs">
            Dry-run the routing stub for one user — no policy change, read-only.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 p-4 pt-0">
          <div className="flex flex-col gap-2 sm:flex-row">
            <Input
              type="email"
              className="sm:max-w-xs"
              value={testEmail}
              onChange={(e) => setTestEmail(e.target.value)}
              placeholder="alice@corp.example"
              aria-label="User email to resolve"
            />
            <Button
              variant="outline"
              className="bg-zinc-700 text-white hover:bg-zinc-800"
              disabled={resolve.isPending || testEmail.trim().length === 0}
              onClick={runResolve}
            >
              <Icons.Search className="mr-1 h-3.5 w-3.5" />
              {resolve.isPending ? "Resolving…" : "Resolve"}
            </Button>
          </div>
          {testErr && <p className="text-xs text-rose-600">{testErr}</p>}
          {testResult && (
            <div className="rounded-lg border border-zinc-200 bg-zinc-500/5 p-3 font-mono text-xs dark:border-zinc-800">
              {testResult}
            </div>
          )}
        </CardContent>
      </Card>

      {addOpen && <RoutingEditor regions={regions} onClose={() => setAddOpen(false)} />}
    </div>
  );
}

// ── main view ───────────────────────────────────────────────────────────────

export function SaseView() {
  return (
    <div className="space-y-4">
      <Tabs defaultValue="nodes">
        <TabsList className="h-auto w-full flex-wrap justify-start">
          <TabsTrigger value="nodes" className="gap-1.5">
            <Icons.Server className="h-3.5 w-3.5" /> Nodes
          </TabsTrigger>
          <TabsTrigger value="tunnels" className="gap-1.5">
            <Icons.Waypoints className="h-3.5 w-3.5" /> Tunnels
          </TabsTrigger>
          <TabsTrigger value="mesh" className="gap-1.5">
            <Icons.FileText className="h-3.5 w-3.5" /> Mesh Config
          </TabsTrigger>
          <TabsTrigger value="routing" className="gap-1.5">
            <Icons.MapPin className="h-3.5 w-3.5" /> Identity-Aware Routing
          </TabsTrigger>
        </TabsList>
        <TabsContent value="nodes" className="mt-4">
          <NodesTab />
        </TabsContent>
        <TabsContent value="tunnels" className="mt-4">
          <TunnelsTab />
        </TabsContent>
        <TabsContent value="mesh" className="mt-4">
          <MeshTab />
        </TabsContent>
        <TabsContent value="routing" className="mt-4">
          <RoutingTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
