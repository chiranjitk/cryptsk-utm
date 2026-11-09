"use client";

/**
 * #/routing/sdwan — SD-WAN (M20, spec 2.5). Single-view layout: an overview
 * strip (overlays / sites / paths-by-state pills / average latency), a grid of
 * selectable overlay cards, a per-overlay detail (sites table + per-site WAN
 * path matrix with mini-meters and state badges + simulated "Probe now") and
 * a policies table next to an SLA profile mini-table. Theme: red-700 for
 * healthy/up/hub, amber for degraded/full-mesh, rose for down/destructive.
 */

import { useState } from "react";
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
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useRealtime } from "@/lib/realtime";
import {
  DSCP_RE,
  ENCRYPTIONS,
  FALLBACK_SLA,
  IPV4_CIDR_RE,
  IPV4_RE,
  PREFERRED_PATHS,
  PATH_LABELS,
  PATH_STATES,
  SITE_ROLES,
  SLA_ACTIONS,
  TOPOLOGIES,
  WAN_INTERFACES,
  WG_PUBKEY_RE,
  fmtRelative,
  sdwanApi,
  topologyLabel,
  type OverlayDTO,
  type PathDTO,
  type PathLabel,
  type PathState,
  type PolicyDTO,
  type PreferredPath,
  type SdwanStatsDTO,
  type SiteDTO,
  type SiteRole,
  type SlaAction,
  type SlaProfileDTO,
  type Topology,
  type WanInterface,
} from "./sdwan-api";
import { ConfirmDialog, EmptyBlock, FieldLabel, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";

function invalidateAll(queryClient: ReturnType<typeof useQueryClient>) {
  void queryClient.invalidateQueries({ queryKey: ["sdwan"] });
}

// ── badge recipes (UI_DESIGN_SYSTEM: up=blue, degraded=amber, down=rose) ────

function TopologyBadge({ topology }: { topology: Topology }) {
  return (
    <Badge
      variant="outline"
      className={
        topology === "hub_spoke"
          ? "gap-1 border-zinc-500/30 bg-zinc-500/10 font-medium text-zinc-600 dark:text-zinc-300"
          : "gap-1 border-amber-500/40 bg-amber-500/10 font-medium text-amber-600 dark:text-amber-400"
      }
    >
      <Icons.Network className="h-3 w-3" />
      {topologyLabel(topology)}
    </Badge>
  );
}

function EncryptionChip({ encryption }: { encryption: string }) {
  return (
    <Badge variant="outline" className="gap-1 border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
      <Icons.Lock className="h-3 w-3" />
      {encryption}
    </Badge>
  );
}

function RoleBadge({ role }: { role: SiteRole }) {
  return role === "hub" ? (
    <Badge className="gap-1 border-transparent bg-zinc-600 font-medium text-white">
      <Icons.Server className="h-3 w-3" /> hub
    </Badge>
  ) : (
    <Badge variant="outline" className="gap-1 border-zinc-300 font-medium text-zinc-500 dark:border-zinc-700 dark:text-zinc-400">
      <Icons.Building2 className="h-3 w-3" /> spoke
    </Badge>
  );
}

function LabelChip({ label }: { label: PathLabel }) {
  const cls =
    label === "mpls"
      ? "border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300"
      : label === "lte"
        ? "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400"
        : "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300";
  return (
    <Badge variant="outline" className={cls}>
      {label}
    </Badge>
  );
}

function StateBadge({ state }: { state: PathState }) {
  if (state === "down") {
    return (
      <Badge className="gap-1 border-transparent bg-rose-600 font-medium text-white">
        <Icons.CircleX className="h-3 w-3" /> down
      </Badge>
    );
  }
  return (
    <Badge
      variant="outline"
      className={
        state === "up"
          ? "gap-1 border-zinc-500/30 bg-zinc-500/10 font-medium text-zinc-600 dark:text-zinc-300"
          : "gap-1 border-amber-500/40 bg-amber-500/10 font-medium text-amber-600 dark:text-amber-400"
      }
    >
      {state === "up" ? <Icons.CircleCheck className="h-3 w-3" /> : <Icons.TriangleAlert className="h-3 w-3" />}
      {state}
    </Badge>
  );
}

function PreferredPathBadge({ policy }: { policy: PolicyDTO }) {
  const icon =
    policy.preferredPath === "latency"
      ? Icons.Gauge
      : policy.preferredPath === "jitter"
        ? Icons.Activity
        : policy.preferredPath === "loss"
          ? Icons.Percent
          : Icons.ArrowRightLeft;
  const Icon = icon;
  return (
    <Badge variant="outline" className="gap-1 border-zinc-500/30 bg-zinc-500/10 font-medium text-zinc-600 dark:text-zinc-300">
      <Icon className="h-3 w-3" />
      {policy.preferredPath}
      {policy.preferredPath === "fixed" && policy.fixedWanInterface ? (
        <span className="font-mono text-[10px]">{policy.fixedWanInterface}</span>
      ) : null}
    </Badge>
  );
}

function SlaChip({ name }: { name: string | null }) {
  if (!name) {
    return <span className="text-[11px] text-zinc-400">—</span>;
  }
  return (
    <Badge variant="outline" className="gap-1 border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
      <Icons.Target className="h-3 w-3" />
      {name}
    </Badge>
  );
}

function MatchChip({ label, value }: { label: string; value: string }) {
  return (
    <Badge variant="outline" className="border-zinc-300 bg-zinc-100 font-mono text-[10px] text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
      {label}: {value}
    </Badge>
  );
}

// ── mini meter (blue fill relative to the SLA threshold) ────────────────────

function MiniMeter(props: { label: string; value: number; max: number; unit: string }) {
  const pct = props.max > 0 ? Math.min(100, (props.value / props.max) * 100) : 0;
  const breached = props.value > props.max;
  const near = !breached && props.value > props.max * 0.8;
  return (
    <div className="w-full min-w-20">
      <div className="flex items-baseline justify-between gap-1">
        <span className="text-[10px] uppercase tracking-wide text-zinc-400">{props.label}</span>
        <span
          className={`text-[11px] font-medium tabular-nums ${
            breached ? "text-rose-500" : near ? "text-amber-600 dark:text-amber-400" : "text-zinc-600 dark:text-zinc-300"
          }`}
        >
          {props.value.toFixed(1)}
          {props.unit}
        </span>
      </div>
      <div className="mt-0.5 h-1.5 w-full overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800">
        <div className="h-full rounded-full bg-zinc-500" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

// ── stat cards (url-filter StatCard pattern) ────────────────────────────────

function StatCard(props: { label: string; value: number | string; icon: React.ReactNode; tone: string; sub?: React.ReactNode }) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs font-medium text-zinc-500">{props.label}</span>
          <span className={props.tone}>{props.icon}</span>
        </div>
        <p className="mt-1 text-2xl font-semibold tabular-nums">{props.value}</p>
        {props.sub ? <div className="mt-1">{props.sub}</div> : null}
      </CardContent>
    </Card>
  );
}

function StatePill(props: { state: PathState; count: number }) {
  const cls =
    props.state === "up"
      ? "border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300"
      : props.state === "degraded"
        ? "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400"
        : "border-rose-500/40 bg-rose-500/10 text-rose-500";
  return (
    <Badge variant="outline" className={`gap-1 ${cls}`}>
      {props.state}: {props.count}
    </Badge>
  );
}

function StatsStrip() {
  const statsQuery = useQuery({ queryKey: ["sdwan", "stats"], queryFn: sdwanApi.getStats });
  const stats: SdwanStatsDTO | undefined = statsQuery.data;
  const totalPaths = stats ? stats.pathsByState.up + stats.pathsByState.degraded + stats.pathsByState.down : 0;

  return (
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <StatCard
        label="Overlays"
        value={stats?.overlays ?? "—"}
        tone="text-zinc-500 dark:text-zinc-400"
        icon={<Icons.Network className="h-4 w-4" />}
      />
      <StatCard
        label="Sites"
        value={stats?.sites ?? "—"}
        tone="text-zinc-500 dark:text-zinc-400"
        icon={<Icons.Building2 className="h-4 w-4" />}
      />
      <StatCard
        label="WAN paths"
        value={stats ? totalPaths : "—"}
        tone="text-zinc-500 dark:text-zinc-400"
        icon={<Icons.Route className="h-4 w-4" />}
        sub={
          stats ? (
            <div className="flex flex-wrap gap-1">
              <StatePill state="up" count={stats.pathsByState.up} />
              <StatePill state="degraded" count={stats.pathsByState.degraded} />
              <StatePill state="down" count={stats.pathsByState.down} />
            </div>
          ) : null
        }
      />
      <StatCard
        label="Average latency"
        value={stats ? `${stats.avgLatencyMs.toFixed(1)} ms` : "—"}
        tone="text-zinc-500 dark:text-zinc-400"
        icon={<Icons.Gauge className="h-4 w-4" />}
        sub={
          stats?.worstPath ? (
            <p className="truncate text-[11px] text-zinc-400">
              worst: <span className="font-mono">{stats.worstPath.siteName}</span> {stats.worstPath.wanInterface} ·{" "}
              {stats.worstPath.latencyMs.toFixed(1)} ms
            </p>
          ) : null
        }
      />
    </div>
  );
}

// ── overlay editor (create + edit) ──────────────────────────────────────────

function OverlayEditor(props: { overlay: OverlayDTO | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = props.overlay !== null;
  const [name, setName] = useState(props.overlay?.name ?? "");
  const [topology, setTopology] = useState<Topology>(props.overlay?.topology ?? "hub_spoke");
  const [encryption, setEncryption] = useState(props.overlay?.encryption ?? "wireguard");
  const [enabled, setEnabled] = useState(props.overlay?.enabled ?? true);
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => {
      const id = props.overlay?.id;
      if (isEdit && id !== undefined) return sdwanApi.updateOverlay(id, body);
      return sdwanApi.createOverlay(body);
    },
    onSuccess: (o) => {
      toastOk(isEdit ? "Overlay updated" : "Overlay created", o.name);
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
    setErr(null);
    save.mutate({ name: name.trim(), topology, encryption, enabled });
  };

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-base">{isEdit ? "Edit overlay" : "New overlay"}</DialogTitle>
          <DialogDescription>An overlay groups sites into one routed fabric with a shared encryption domain.</DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div>
            <FieldLabel>Name</FieldLabel>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="HQ mesh" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel>Topology</FieldLabel>
              <Select value={topology} onValueChange={(v) => setTopology(v as Topology)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {TOPOLOGIES.map((t) => (
                    <SelectItem key={t} value={t}>
                      {topologyLabel(t)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel>Encryption</FieldLabel>
              <Select value={encryption} onValueChange={(v) => setEncryption(v as OverlayDTO["encryption"])}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ENCRYPTIONS.map((e) => (
                    <SelectItem key={e} value={e}>
                      {e}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="flex items-center justify-between gap-4 rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
            <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Overlay enabled</span>
            <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="Overlay enabled" />
          </div>
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button
            className="bg-red-700 text-white hover:bg-red-800"
            disabled={save.isPending || !name.trim()}
            onClick={submit}
          >
            {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create overlay"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── site editor (create + edit, scoped to the selected overlay) ─────────────

function SiteEditor(props: { overlayId: number; site: SiteDTO | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = props.site !== null;
  const [name, setName] = useState(props.site?.name ?? "");
  const [role, setRole] = useState<SiteRole>(props.site?.role ?? "spoke");
  const [publicIp, setPublicIp] = useState(props.site?.publicIp ?? "");
  const [wgPubKey, setWgPubKey] = useState(props.site?.wgPubKey ?? "");
  const [region, setRegion] = useState(props.site?.region ?? "");
  const [enabled, setEnabled] = useState(props.site?.enabled ?? true);
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => {
      const id = props.site?.id;
      if (isEdit && id !== undefined) return sdwanApi.updateSite(id, body);
      return sdwanApi.createSite({ ...body, overlayId: props.overlayId });
    },
    onSuccess: (s) => {
      toastOk(isEdit ? "Site updated" : "Site created", s.name);
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
    if (!IPV4_RE.test(publicIp.trim())) {
      setErr("Public IP must be a valid IPv4 address");
      return;
    }
    const key = wgPubKey.trim();
    if (key && !WG_PUBKEY_RE.test(key)) {
      setErr("WireGuard public key must be at least 40 base64 characters");
      return;
    }
    setErr(null);
    save.mutate({
      name: name.trim(),
      role,
      publicIp: publicIp.trim(),
      wgPubKey: key || null,
      region: region.trim() || null,
      enabled,
    });
  };

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-base">{isEdit ? "Edit site" : "New site"}</DialogTitle>
          <DialogDescription>Sites are the overlay endpoints — one hub plus one or more spokes.</DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div>
            <FieldLabel>Name</FieldLabel>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="branch-a" className="font-mono" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel>Role</FieldLabel>
              <Select value={role} onValueChange={(v) => setRole(v as SiteRole)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SITE_ROLES.map((r) => (
                    <SelectItem key={r} value={r}>
                      {r}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel hint="optional">Region</FieldLabel>
              <Input value={region} onChange={(e) => setRegion(e.target.value)} placeholder="eu" className="font-mono" />
            </div>
          </div>
          <div>
            <FieldLabel hint="IPv4">Public IP</FieldLabel>
            <Input value={publicIp} onChange={(e) => setPublicIp(e.target.value)} placeholder="198.51.100.10" className="font-mono" />
          </div>
          <div>
            <FieldLabel hint="base64, 40+ chars — optional">WireGuard public key</FieldLabel>
            <Input
              value={wgPubKey}
              onChange={(e) => setWgPubKey(e.target.value)}
              placeholder="e.g. 8FvLt…  (leave empty for IPsec-only)"
              className="font-mono text-xs"
            />
          </div>
          <div className="flex items-center justify-between gap-4 rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
            <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Site enabled</span>
            <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="Site enabled" />
          </div>
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button
            className="bg-red-700 text-white hover:bg-red-800"
            disabled={save.isPending || !name.trim()}
            onClick={submit}
          >
            {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create site"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── path editor (create + edit, scoped to a site) ───────────────────────────

function PathEditor(props: { site: Pick<SiteDTO, "id" | "name">; path: PathDTO | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = props.path !== null;
  const [wanInterface, setWanInterface] = useState<WanInterface>(props.path?.wanInterface ?? "wan0");
  const [label, setLabel] = useState<PathLabel>(props.path?.label ?? "broadband");
  const [latency, setLatency] = useState(props.path ? String(props.path.latencyMs) : "20");
  const [jitter, setJitter] = useState(props.path ? String(props.path.jitterMs) : "3");
  const [loss, setLoss] = useState(props.path ? String(props.path.lossPct) : "0");
  const [state, setState] = useState<PathState>(props.path?.state ?? "up");
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => {
      const id = props.path?.id;
      if (isEdit && id !== undefined) return sdwanApi.updatePath(id, body);
      return sdwanApi.createPath(props.site.id, body);
    },
    onSuccess: (p) => {
      toastOk(isEdit ? "Path updated" : "Path added", `${props.site.name} · ${p.wanInterface}`);
      invalidateAll(queryClient);
      props.onClose();
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Save failed"),
  });

  const submit = () => {
    const latencyMs = Number(latency);
    const jitterMs = Number(jitter);
    const lossPct = Number(loss);
    if (Number.isNaN(latencyMs) || latencyMs < 0) {
      setErr("Latency must be a number ≥ 0");
      return;
    }
    if (Number.isNaN(jitterMs) || jitterMs < 0) {
      setErr("Jitter must be a number ≥ 0");
      return;
    }
    if (Number.isNaN(lossPct) || lossPct < 0) {
      setErr("Loss must be a number ≥ 0");
      return;
    }
    setErr(null);
    save.mutate({ wanInterface, label, latencyMs, jitterMs, lossPct, state });
  };

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-base">{isEdit ? "Edit WAN path" : `Add WAN path — ${props.site.name}`}</DialogTitle>
          <DialogDescription>One path per WAN interface; the probe cycle keeps the measurements current.</DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel>WAN interface</FieldLabel>
              <Select value={wanInterface} onValueChange={(v) => setWanInterface(v as WanInterface)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {WAN_INTERFACES.map((w) => (
                    <SelectItem key={w} value={w}>
                      {w}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel>Label</FieldLabel>
              <Select value={label} onValueChange={(v) => setLabel(v as PathLabel)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PATH_LABELS.map((l) => (
                    <SelectItem key={l} value={l}>
                      {l}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <FieldLabel hint="ms">Latency</FieldLabel>
              <Input type="number" min={0} value={latency} onChange={(e) => setLatency(e.target.value)} className="tabular-nums" />
            </div>
            <div>
              <FieldLabel hint="ms">Jitter</FieldLabel>
              <Input type="number" min={0} value={jitter} onChange={(e) => setJitter(e.target.value)} className="tabular-nums" />
            </div>
            <div>
              <FieldLabel hint="%">Loss</FieldLabel>
              <Input type="number" min={0} step="0.1" value={loss} onChange={(e) => setLoss(e.target.value)} className="tabular-nums" />
            </div>
          </div>
          <div>
            <FieldLabel hint="manual override until the next probe">State</FieldLabel>
            <Select value={state} onValueChange={(v) => setState(v as PathState)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {PATH_STATES.map((s) => (
                  <SelectItem key={s} value={s}>
                    {s}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button className="bg-red-700 text-white hover:bg-red-800" disabled={save.isPending} onClick={submit}>
            {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Add path"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── policy editor (create + edit; needs overlays + SLA profiles) ────────────

function PolicyEditor(props: {
  policy: PolicyDTO | null;
  overlays: OverlayDTO[];
  slaProfiles: SlaProfileDTO[];
  defaultOverlayId: number | null;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const isEdit = props.policy !== null;
  const [name, setName] = useState(props.policy?.name ?? "");
  const [overlayId, setOverlayId] = useState<string>(
    props.policy ? String(props.policy.overlayId) : props.defaultOverlayId ? String(props.defaultOverlayId) : "",
  );
  const [matchApp, setMatchApp] = useState(props.policy?.matchApp ?? "");
  const [matchDscp, setMatchDscp] = useState(props.policy?.matchDscp ?? "");
  const [matchDestCidr, setMatchDestCidr] = useState(props.policy?.matchDestCidr ?? "");
  const [preferredPath, setPreferredPath] = useState<PreferredPath>(props.policy?.preferredPath ?? "latency");
  const [fixedWanInterface, setFixedWanInterface] = useState<WanInterface | null>(props.policy?.fixedWanInterface ?? null);
  const [slaProfileId, setSlaProfileId] = useState<string>(
    props.policy?.slaProfileId ? String(props.policy.slaProfileId) : "none",
  );
  const [enabled, setEnabled] = useState(props.policy?.enabled ?? true);
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => {
      const id = props.policy?.id;
      if (isEdit && id !== undefined) return sdwanApi.updatePolicy(id, body);
      return sdwanApi.createPolicy(body);
    },
    onSuccess: (p) => {
      toastOk(isEdit ? "Policy updated" : "Policy created", p.name);
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
    if (!overlayId) {
      setErr("An overlay is required");
      return;
    }
    const dscp = matchDscp.trim();
    if (dscp && !DSCP_RE.test(dscp)) {
      setErr("DSCP must be CS0–CS6, EF or AFxy (e.g. EF, AF31)");
      return;
    }
    const cidr = matchDestCidr.trim();
    if (cidr && !IPV4_CIDR_RE.test(cidr)) {
      setErr("Destination must be an IPv4 CIDR like 10.0.0.0/8");
      return;
    }
    if (preferredPath === "fixed" && !fixedWanInterface) {
      setErr("A fixed WAN interface is required when preferred path is fixed");
      return;
    }
    setErr(null);
    save.mutate({
      name: name.trim(),
      overlayId: Number(overlayId),
      matchApp: matchApp.trim() || null,
      matchDscp: dscp || null,
      matchDestCidr: cidr || null,
      preferredPath,
      fixedWanInterface: preferredPath === "fixed" ? fixedWanInterface : null,
      slaProfileId: slaProfileId === "none" ? null : Number(slaProfileId),
      enabled,
    });
  };

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-base">{isEdit ? "Edit policy" : "New path-selection policy"}</DialogTitle>
          <DialogDescription>
            Traffic matching the criteria is steered by the preferred-path rule; the SLA profile guards breaches.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div>
            <FieldLabel>Name</FieldLabel>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="voice-prefer-latency" />
          </div>
          <div>
            <FieldLabel>Overlay</FieldLabel>
            <Select value={overlayId} onValueChange={setOverlayId}>
              <SelectTrigger>
                <SelectValue placeholder="Select an overlay" />
              </SelectTrigger>
              <SelectContent>
                {props.overlays.map((o) => (
                  <SelectItem key={o.id} value={String(o.id)}>
                    {o.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <FieldLabel hint="optional">App</FieldLabel>
              <Input value={matchApp} onChange={(e) => setMatchApp(e.target.value)} placeholder="teams" className="font-mono text-xs" />
            </div>
            <div>
              <FieldLabel hint="optional">DSCP</FieldLabel>
              <Input value={matchDscp} onChange={(e) => setMatchDscp(e.target.value)} placeholder="EF" className="font-mono text-xs" />
            </div>
            <div>
              <FieldLabel hint="optional">Dest CIDR</FieldLabel>
              <Input
                value={matchDestCidr}
                onChange={(e) => setMatchDestCidr(e.target.value)}
                placeholder="10.0.0.0/8"
                className="font-mono text-xs"
              />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel>Preferred path</FieldLabel>
              <Select value={preferredPath} onValueChange={(v) => setPreferredPath(v as PreferredPath)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PREFERRED_PATHS.map((p) => (
                    <SelectItem key={p} value={p}>
                      {p}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel hint={preferredPath === "fixed" ? "required" : "fixed only"}>Fixed WAN interface</FieldLabel>
              <Select
                value={fixedWanInterface ?? ""}
                onValueChange={(v) => setFixedWanInterface(v as WanInterface)}
                disabled={preferredPath !== "fixed"}
              >
                <SelectTrigger aria-disabled={preferredPath !== "fixed"}>
                  <SelectValue placeholder="Select interface" />
                </SelectTrigger>
                <SelectContent>
                  {WAN_INTERFACES.map((w) => (
                    <SelectItem key={w} value={w}>
                      {w}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div>
            <FieldLabel hint="guards breaches — optional">SLA profile</FieldLabel>
            <Select value={slaProfileId} onValueChange={setSlaProfileId}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">none (global defaults)</SelectItem>
                {props.slaProfiles.map((s) => (
                  <SelectItem key={s.id} value={String(s.id)}>
                    {s.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex items-center justify-between gap-4 rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
            <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Policy enabled</span>
            <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="Policy enabled" />
          </div>
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button
            className="bg-red-700 text-white hover:bg-red-800"
            disabled={save.isPending || !name.trim()}
            onClick={submit}
          >
            {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create policy"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── SLA profile editor (create + edit) ──────────────────────────────────────

function SlaProfileEditor(props: { profile: SlaProfileDTO | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = props.profile !== null;
  const [name, setName] = useState(props.profile?.name ?? "");
  const [latencyMsMax, setLatency] = useState(props.profile ? String(props.profile.latencyMsMax) : "150");
  const [jitterMsMax, setJitter] = useState(props.profile ? String(props.profile.jitterMsMax) : "30");
  const [lossPctMax, setLoss] = useState(props.profile ? String(props.profile.lossPctMax) : "1");
  const [actionOnBreach, setAction] = useState<SlaAction>(props.profile?.actionOnBreach ?? "switch");
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => {
      const id = props.profile?.id;
      if (isEdit && id !== undefined) return sdwanApi.updateSlaProfile(id, body);
      return sdwanApi.createSlaProfile(body);
    },
    onSuccess: (s) => {
      toastOk(isEdit ? "SLA profile updated" : "SLA profile created", s.name);
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
    const lat = Number(latencyMsMax);
    const jit = Number(jitterMsMax);
    const los = Number(lossPctMax);
    if (!Number.isInteger(lat) || lat < 5 || lat > 1000) {
      setErr("Latency max must be an integer between 5 and 1000 ms");
      return;
    }
    if (!Number.isInteger(jit) || jit < 1 || jit > 500) {
      setErr("Jitter max must be an integer between 1 and 500 ms");
      return;
    }
    if (Number.isNaN(los) || los < 0 || los > 50) {
      setErr("Loss max must be between 0 and 50 %");
      return;
    }
    setErr(null);
    save.mutate({ name: name.trim(), latencyMsMax: lat, jitterMsMax: jit, lossPctMax: los, actionOnBreach });
  };

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-base">{isEdit ? "Edit SLA profile" : "New SLA profile"}</DialogTitle>
          <DialogDescription>
            Breaching paths are flagged degraded; on switch the steering engine moves traffic to a compliant path.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div>
            <FieldLabel>Name</FieldLabel>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="voice" />
          </div>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <FieldLabel hint="5–1000 ms">Latency max</FieldLabel>
              <Input type="number" min={5} max={1000} value={latencyMsMax} onChange={(e) => setLatency(e.target.value)} className="tabular-nums" />
            </div>
            <div>
              <FieldLabel hint="1–500 ms">Jitter max</FieldLabel>
              <Input type="number" min={1} max={500} value={jitterMsMax} onChange={(e) => setJitter(e.target.value)} className="tabular-nums" />
            </div>
            <div>
              <FieldLabel hint="0–50 %">Loss max</FieldLabel>
              <Input type="number" min={0} max={50} step="0.1" value={lossPctMax} onChange={(e) => setLoss(e.target.value)} className="tabular-nums" />
            </div>
          </div>
          <div>
            <FieldLabel>Action on breach</FieldLabel>
            <Select value={actionOnBreach} onValueChange={(v) => setAction(v as SlaAction)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {SLA_ACTIONS.map((a) => (
                  <SelectItem key={a} value={a}>
                    {a}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button
            className="bg-red-700 text-white hover:bg-red-800"
            disabled={save.isPending || !name.trim()}
            onClick={submit}
          >
            {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create profile"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── overlays grid (master list) ─────────────────────────────────────────────

function OverlayCard(props: {
  overlay: OverlayDTO;
  selected: boolean;
  onSelect: () => void;
  onEdit: () => void;
  onDelete: () => void;
  onToggle: (enabled: boolean) => void;
  toggling: boolean;
}) {
  const { overlay } = props;
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={props.onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          props.onSelect();
        }
      }}
      aria-pressed={props.selected}
      className={`w-full cursor-pointer rounded-xl border p-4 text-left transition-colors ${
        props.selected
          ? "border-zinc-500/50 bg-zinc-500/5 ring-1 ring-zinc-500/30"
          : "border-zinc-200 hover:bg-zinc-50 dark:border-zinc-800 dark:hover:bg-zinc-800/50"
      }`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="truncate text-sm font-semibold">{overlay.name}</p>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            <TopologyBadge topology={overlay.topology} />
            <EncryptionChip encryption={overlay.encryption} />
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-1">
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-300"
            aria-label={`Edit ${overlay.name}`}
            onClick={(e) => {
              e.stopPropagation();
              props.onEdit();
            }}
          >
            <Icons.Pencil className="h-3.5 w-3.5" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 text-zinc-400 hover:text-rose-600"
            aria-label={`Delete ${overlay.name}`}
            onClick={(e) => {
              e.stopPropagation();
              props.onDelete();
            }}
          >
            <Icons.Trash2 className="h-3.5 w-3.5" />
          </Button>
          <span onClick={(e) => e.stopPropagation()} className="pl-0.5">
            <Switch
              checked={overlay.enabled}
              disabled={props.toggling}
              onCheckedChange={props.onToggle}
              aria-label={`Toggle ${overlay.name}`}
            />
          </span>
        </div>
      </div>
      <p className="mt-3 text-[11px] text-zinc-400">
        {overlay.siteCount} site{overlay.siteCount === 1 ? "" : "s"} · {overlay.policyCount} polic
        {overlay.policyCount === 1 ? "y" : "ies"}
        {!overlay.enabled && " · disabled"}
      </p>
    </div>
  );
}

// ── sites table (per selected overlay) ──────────────────────────────────────

function SitesCard(props: {
  overlayId: number;
  sites: SiteDTO[];
  isLoading: boolean;
  isError: boolean;
  error: unknown;
  onRetry: () => void;
  onEdit: (site: SiteDTO) => void;
  onAdd: () => void;
  onDelete: (site: SiteDTO) => void;
}) {
  const queryClient = useQueryClient();
  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => sdwanApi.updateSite(id, { enabled }),
    onSuccess: () => invalidateAll(queryClient),
    onError: (e) => toastErr(e, "Toggle failed"),
  });

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.Building2 className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
          Sites
        </CardTitle>
        <Button size="sm" className="h-8 bg-red-700 text-white hover:bg-red-800" onClick={props.onAdd}>
          <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add site
        </Button>
      </CardHeader>
      <CardContent className="p-0">
        {props.isError ? (
          <div className="p-4">
            <QueryError error={props.error} onRetry={props.onRetry} />
          </div>
        ) : props.isLoading ? (
          <TableSkeleton rows={3} cols={6} />
        ) : props.sites.length === 0 ? (
          <EmptyBlock
            icon={<Icons.Building2 className="h-6 w-6" />}
            title="No sites in this overlay"
            description="Add a hub first, then attach spokes to build the fabric."
            action={
              <Button size="sm" className="bg-red-700 text-white hover:bg-red-800" onClick={props.onAdd}>
                <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add site
              </Button>
            }
          />
        ) : (
          <div className="max-h-96 overflow-y-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead className="w-24">Role</TableHead>
                  <TableHead className="w-36">Public IP</TableHead>
                  <TableHead className="w-20">Region</TableHead>
                  <TableHead className="w-20">WAN</TableHead>
                  <TableHead className="w-16">On</TableHead>
                  <TableHead className="w-20 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {props.sites.map((site) => (
                  <TableRow key={site.id} className={site.enabled ? undefined : "opacity-70"}>
                    <TableCell>
                      <span className="font-mono text-sm">{site.name}</span>
                    </TableCell>
                    <TableCell>
                      <RoleBadge role={site.role} />
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-xs text-zinc-600 dark:text-zinc-300">{site.publicIp}</span>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs text-zinc-500">{site.region ?? "—"}</span>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs tabular-nums text-zinc-500">{site.pathCount}</span>
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={site.enabled}
                        disabled={toggle.isPending && toggle.variables?.id === site.id}
                        onCheckedChange={(enabled) => toggle.mutate({ id: site.id, enabled })}
                        aria-label={`Toggle ${site.name}`}
                      />
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-300"
                          aria-label={`Edit ${site.name}`}
                          onClick={() => props.onEdit(site)}
                        >
                          <Icons.Pencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-zinc-400 hover:text-rose-600"
                          aria-label={`Delete ${site.name}`}
                          onClick={() => props.onDelete(site)}
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

// ── paths matrix (per site of the selected overlay) ─────────────────────────

function PathsCard(props: {
  sites: SiteDTO[];
  paths: PathDTO[];
  sla: { latencyMsMax: number; jitterMsMax: number; lossPctMax: number };
  isLoading: boolean;
  isError: boolean;
  error: unknown;
  onRetry: () => void;
  onAdd: (site: SiteDTO) => void;
  onEdit: (path: PathDTO) => void;
  onDelete: (path: PathDTO) => void;
}) {
  const bySite = new Map<number, PathDTO[]>();
  for (const p of props.paths) {
    const list = bySite.get(p.siteId) ?? [];
    list.push(p);
    bySite.set(p.siteId, list);
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.Route className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
          WAN paths
        </CardTitle>
        <span className="text-[11px] text-zinc-400">meters relative to the overlay SLA</span>
      </CardHeader>
      <CardContent className="p-0">
        {props.isError ? (
          <div className="p-4">
            <QueryError error={props.error} onRetry={props.onRetry} />
          </div>
        ) : props.isLoading ? (
          <TableSkeleton rows={4} cols={5} />
        ) : props.sites.length === 0 ? (
          <EmptyBlock
            icon={<Icons.Route className="h-6 w-6" />}
            title="No sites yet"
            description="WAN paths attach to sites — add a site first."
          />
        ) : (
          <div className="max-h-96 space-y-4 overflow-y-auto p-4">
            {props.sites.map((site) => {
              const sitePaths = bySite.get(site.id) ?? [];
              return (
                <div key={site.id} className="rounded-lg border border-zinc-200 dark:border-zinc-800">
                  <div className="flex items-center justify-between gap-2 border-b border-zinc-200 px-3 py-2 dark:border-zinc-800">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-semibold">{site.name}</span>
                      <RoleBadge role={site.role} />
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7 gap-1 text-xs"
                      onClick={() => props.onAdd(site)}
                      aria-label={`Add path to ${site.name}`}
                    >
                      <Icons.Plus className="h-3 w-3" /> Add path
                    </Button>
                  </div>
                  {sitePaths.length === 0 ? (
                    <p className="px-3 py-4 text-center text-xs text-zinc-400">No WAN paths on this site yet</p>
                  ) : (
                    <div className="divide-y divide-zinc-100 dark:divide-zinc-800">
                      {sitePaths.map((path) => (
                        <div key={path.id} className="grid grid-cols-[92px_1fr_auto] items-center gap-3 px-3 py-2 sm:grid-cols-[112px_1fr_auto_auto]">
                          <div>
                            <p className="font-mono text-xs font-medium">{path.wanInterface}</p>
                            <div className="mt-0.5">
                              <LabelChip label={path.label} />
                            </div>
                          </div>
                          <div className="grid gap-1.5 sm:grid-cols-3 sm:gap-3">
                            <MiniMeter label="latency" value={path.latencyMs} max={props.sla.latencyMsMax} unit="ms" />
                            <MiniMeter label="jitter" value={path.jitterMs} max={props.sla.jitterMsMax} unit="ms" />
                            <MiniMeter label="loss" value={path.lossPct} max={props.sla.lossPctMax} unit="%" />
                          </div>
                          <div className="hidden w-20 text-right sm:block">
                            <StateBadge state={path.state} />
                          </div>
                          <div className="flex items-center gap-1.5">
                            <div className="hidden text-right lg:block">
                              <p className="text-[10px] text-zinc-400">{fmtRelative(path.lastProbeAt)}</p>
                              <div className="mt-0.5 flex justify-end sm:hidden">
                                <StateBadge state={path.state} />
                              </div>
                            </div>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-7 w-7 text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-300"
                              aria-label={`Edit ${path.wanInterface} on ${path.siteName}`}
                              onClick={() => props.onEdit(path)}
                            >
                              <Icons.Pencil className="h-3.5 w-3.5" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-7 w-7 text-zinc-400 hover:text-rose-600"
                              aria-label={`Delete ${path.wanInterface} on ${path.siteName}`}
                              onClick={() => props.onDelete(path)}
                            >
                              <Icons.Trash2 className="h-3.5 w-3.5" />
                            </Button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ── policies table + SLA profiles mini-table ────────────────────────────────

function PoliciesCard(props: {
  policies: PolicyDTO[];
  isLoading: boolean;
  isError: boolean;
  error: unknown;
  onRetry: () => void;
  onAdd: () => void;
  onEdit: (policy: PolicyDTO) => void;
  onDelete: (policy: PolicyDTO) => void;
}) {
  const queryClient = useQueryClient();
  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => sdwanApi.updatePolicy(id, { enabled }),
    onSuccess: () => invalidateAll(queryClient),
    onError: (e) => toastErr(e, "Toggle failed"),
  });

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.GitBranch className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
          Path-selection policies
        </CardTitle>
        <Button size="sm" className="h-8 bg-red-700 text-white hover:bg-red-800" onClick={props.onAdd}>
          <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add policy
        </Button>
      </CardHeader>
      <CardContent className="p-0">
        {props.isError ? (
          <div className="p-4">
            <QueryError error={props.error} onRetry={props.onRetry} />
          </div>
        ) : props.isLoading ? (
          <TableSkeleton rows={3} cols={6} />
        ) : props.policies.length === 0 ? (
          <EmptyBlock
            icon={<Icons.GitBranch className="h-6 w-6" />}
            title="No policies yet"
            description="Create a policy to steer matching traffic onto the best WAN path."
            action={
              <Button size="sm" className="bg-red-700 text-white hover:bg-red-800" onClick={props.onAdd}>
                <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add policy
              </Button>
            }
          />
        ) : (
          <div className="max-h-96 overflow-y-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Match</TableHead>
                  <TableHead className="w-32">Preferred path</TableHead>
                  <TableHead className="w-32">SLA profile</TableHead>
                  <TableHead className="w-16">On</TableHead>
                  <TableHead className="w-20 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {props.policies.map((policy) => (
                  <TableRow key={policy.id} className={policy.enabled ? undefined : "opacity-70"}>
                    <TableCell>
                      <span className="text-sm font-medium">{policy.name}</span>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {policy.matchApp ? <MatchChip label="app" value={policy.matchApp} /> : null}
                        {policy.matchDscp ? <MatchChip label="dscp" value={policy.matchDscp} /> : null}
                        {policy.matchDestCidr ? <MatchChip label="dest" value={policy.matchDestCidr} /> : null}
                        {!policy.matchApp && !policy.matchDscp && !policy.matchDestCidr ? (
                          <span className="text-[11px] text-zinc-400">any traffic</span>
                        ) : null}
                      </div>
                    </TableCell>
                    <TableCell>
                      <PreferredPathBadge policy={policy} />
                    </TableCell>
                    <TableCell>
                      <SlaChip name={policy.slaProfileName} />
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={policy.enabled}
                        disabled={toggle.isPending && toggle.variables?.id === policy.id}
                        onCheckedChange={(enabled) => toggle.mutate({ id: policy.id, enabled })}
                        aria-label={`Toggle ${policy.name}`}
                      />
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-300"
                          aria-label={`Edit ${policy.name}`}
                          onClick={() => props.onEdit(policy)}
                        >
                          <Icons.Pencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-zinc-400 hover:text-rose-600"
                          aria-label={`Delete ${policy.name}`}
                          onClick={() => props.onDelete(policy)}
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

function SlaProfilesCard(props: {
  profiles: SlaProfileDTO[];
  isLoading: boolean;
  isError: boolean;
  error: unknown;
  onRetry: () => void;
  onAdd: () => void;
  onEdit: (profile: SlaProfileDTO) => void;
  onDelete: (profile: SlaProfileDTO) => void;
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.Target className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
          SLA profiles
        </CardTitle>
        <Button size="sm" variant="outline" className="h-8" onClick={props.onAdd}>
          <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add
        </Button>
      </CardHeader>
      <CardContent className="p-0">
        {props.isError ? (
          <div className="p-4">
            <QueryError error={props.error} onRetry={props.onRetry} />
          </div>
        ) : props.isLoading ? (
          <TableSkeleton rows={2} cols={4} />
        ) : props.profiles.length === 0 ? (
          <EmptyBlock
            icon={<Icons.Target className="h-6 w-6" />}
            title="No SLA profiles"
            description="Profiles define latency/jitter/loss budgets and the breach action."
            action={
              <Button size="sm" variant="outline" onClick={props.onAdd}>
                <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add profile
              </Button>
            }
          />
        ) : (
          <div className="max-h-96 overflow-y-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead className="w-44">Budgets</TableHead>
                  <TableHead className="w-20">Breach</TableHead>
                  <TableHead className="w-14 text-right">Used</TableHead>
                  <TableHead className="w-20 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {props.profiles.map((profile) => (
                  <TableRow key={profile.id}>
                    <TableCell>
                      <span className="text-sm font-medium">{profile.name}</span>
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-[11px] tabular-nums text-zinc-600 dark:text-zinc-300">
                        {profile.latencyMsMax}ms / {profile.jitterMsMax}ms / {profile.lossPctMax}%
                      </span>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant="outline"
                        className={
                          profile.actionOnBreach === "switch"
                            ? "border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300"
                            : "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400"
                        }
                      >
                        {profile.actionOnBreach}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <span className="text-xs tabular-nums text-zinc-500">{profile.policyCount}</span>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-300"
                          aria-label={`Edit ${profile.name}`}
                          onClick={() => props.onEdit(profile)}
                        >
                          <Icons.Pencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-zinc-400 hover:text-rose-600"
                          aria-label={`Delete ${profile.name}`}
                          onClick={() => props.onDelete(profile)}
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

// ── main view ───────────────────────────────────────────────────────────────

export function SdwanView() {
  const queryClient = useQueryClient();

  useRealtime(["config"], {
    onConfigUpdated: (c) => {
      if (c.section === "sdwan") void queryClient.invalidateQueries({ queryKey: ["sdwan"] });
    },
  });

  const overlaysQuery = useQuery({ queryKey: ["sdwan", "overlays"], queryFn: sdwanApi.listOverlays });
  const policiesQuery = useQuery({ queryKey: ["sdwan", "policies"], queryFn: sdwanApi.listPolicies });
  const slaQuery = useQuery({ queryKey: ["sdwan", "sla"], queryFn: sdwanApi.listSlaProfiles });
  const overlays = overlaysQuery.data ?? [];
  const policies = policiesQuery.data ?? [];
  const slaProfiles = slaQuery.data ?? [];

  const [selectedId, setSelectedId] = useState<number | null>(null);
  const selected = overlays.find((o) => o.id === selectedId) ?? overlays[0] ?? null;

  const sitesQuery = useQuery({
    queryKey: ["sdwan", "sites", selected?.id ?? null],
    queryFn: () => sdwanApi.listSites(selected?.id),
    enabled: selected !== null,
  });
  const pathsQuery = useQuery({ queryKey: ["sdwan", "paths"], queryFn: () => sdwanApi.listPaths() });
  const sites = sitesQuery.data ?? [];
  const paths = pathsQuery.data ?? [];

  // per-overlay SLA thresholds for the meters — first attached policy's profile
  const selectedSla = (() => {
    if (!selected) return { ...FALLBACK_SLA };
    const firstWithSla = policies.find((p) => p.overlayId === selected.id && p.slaProfileId !== null);
    const profile = firstWithSla ? slaProfiles.find((s) => s.id === firstWithSla.slaProfileId) : undefined;
    return profile
      ? { latencyMsMax: profile.latencyMsMax, jitterMsMax: profile.jitterMsMax, lossPctMax: profile.lossPctMax }
      : { ...FALLBACK_SLA };
  })();

  // dialog state (overlay, site, path, policy, sla + delete targets)
  const [overlayAddOpen, setOverlayAddOpen] = useState(false);
  const [overlayEditing, setOverlayEditing] = useState<OverlayDTO | null>(null);
  const [overlayDeleting, setOverlayDeleting] = useState<OverlayDTO | null>(null);
  const [siteAddOpen, setSiteAddOpen] = useState(false);
  const [siteEditing, setSiteEditing] = useState<SiteDTO | null>(null);
  const [siteDeleting, setSiteDeleting] = useState<SiteDTO | null>(null);
  const [pathAddFor, setPathAddFor] = useState<SiteDTO | null>(null);
  const [pathEditing, setPathEditing] = useState<PathDTO | null>(null);
  const [pathDeleting, setPathDeleting] = useState<PathDTO | null>(null);
  const [policyAddOpen, setPolicyAddOpen] = useState(false);
  const [policyEditing, setPolicyEditing] = useState<PolicyDTO | null>(null);
  const [policyDeleting, setPolicyDeleting] = useState<PolicyDTO | null>(null);
  const [slaAddOpen, setSlaAddOpen] = useState(false);
  const [slaEditing, setSlaEditing] = useState<SlaProfileDTO | null>(null);
  const [slaDeleting, setSlaDeleting] = useState<SlaProfileDTO | null>(null);

  const overlayToggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => sdwanApi.updateOverlay(id, { enabled }),
    onSuccess: () => invalidateAll(queryClient),
    onError: (e) => toastErr(e, "Toggle failed"),
  });

  const overlayDel = useMutation({
    mutationFn: (id: number) => sdwanApi.deleteOverlay(id),
    onSuccess: () => {
      toastOk("Overlay deleted");
      setOverlayDeleting(null);
      setSelectedId(null);
      invalidateAll(queryClient);
    },
    onError: (e) => {
      setOverlayDeleting(null);
      toastErr(e, "Delete failed");
    },
  });

  const siteDel = useMutation({
    mutationFn: (id: number) => sdwanApi.deleteSite(id),
    onSuccess: () => {
      toastOk("Site deleted", "Its WAN paths were removed too");
      setSiteDeleting(null);
      invalidateAll(queryClient);
    },
    onError: (e) => {
      setSiteDeleting(null);
      toastErr(e, "Delete failed");
    },
  });

  const pathDel = useMutation({
    mutationFn: (id: number) => sdwanApi.deletePath(id),
    onSuccess: () => {
      toastOk("Path deleted");
      setPathDeleting(null);
      invalidateAll(queryClient);
    },
    onError: (e) => {
      setPathDeleting(null);
      toastErr(e, "Delete failed");
    },
  });

  const policyDel = useMutation({
    mutationFn: (id: number) => sdwanApi.deletePolicy(id),
    onSuccess: () => {
      toastOk("Policy deleted");
      setPolicyDeleting(null);
      invalidateAll(queryClient);
    },
    onError: (e) => {
      setPolicyDeleting(null);
      toastErr(e, "Delete failed");
    },
  });

  const slaDel = useMutation({
    mutationFn: (id: number) => sdwanApi.deleteSlaProfile(id),
    onSuccess: () => {
      toastOk("SLA profile deleted");
      setSlaDeleting(null);
      invalidateAll(queryClient);
    },
    onError: (e) => {
      setSlaDeleting(null);
      toastErr(e, "Delete failed");
    },
  });

  const probe = useMutation({
    mutationFn: (overlayId: number) => sdwanApi.probe(overlayId),
    onSuccess: (summary) => {
      toastOk(
        "Probe complete",
        `${summary.probed} path${summary.probed === 1 ? "" : "s"} probed — ${summary.up} up, ${summary.degraded} degraded, ${summary.down} down`,
      );
      invalidateAll(queryClient);
    },
    onError: (e) => toastErr(e, "Probe failed"),
  });

  return (
    <div className="space-y-4">
      <StatsStrip />

      {/* overlays */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
          <CardTitle className="text-sm">Overlays</CardTitle>
          <Button
            size="sm"
            className="h-8 bg-red-700 text-white hover:bg-red-800"
            onClick={() => setOverlayAddOpen(true)}
          >
            <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add overlay
          </Button>
        </CardHeader>
        <CardContent className="p-4 pt-0">
          {overlaysQuery.isError ? (
            <QueryError error={overlaysQuery.error} onRetry={() => void overlaysQuery.refetch()} />
          ) : overlaysQuery.isLoading ? (
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
              {Array.from({ length: 2 }).map((_, i) => (
                <div key={i} className="h-28 animate-pulse rounded-xl bg-zinc-100 dark:bg-zinc-800" />
              ))}
            </div>
          ) : overlays.length === 0 ? (
            <EmptyBlock
              icon={<Icons.Network className="h-6 w-6" />}
              title="No overlays yet"
              description="Create an overlay to group sites into one routed fabric."
              action={
                <Button size="sm" className="bg-red-700 text-white hover:bg-red-800" onClick={() => setOverlayAddOpen(true)}>
                  <Icons.Plus className="mr-1 h-3.5 w-3.5" /> New overlay
                </Button>
              }
            />
          ) : (
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
              {overlays.map((overlay) => (
                <OverlayCard
                  key={overlay.id}
                  overlay={overlay}
                  selected={selected?.id === overlay.id}
                  onSelect={() => setSelectedId(overlay.id)}
                  onEdit={() => {
                    setSelectedId(overlay.id);
                    setOverlayEditing(overlay);
                  }}
                  onDelete={() => setOverlayDeleting(overlay)}
                  onToggle={(enabled) => overlayToggle.mutate({ id: overlay.id, enabled })}
                  toggling={overlayToggle.isPending && overlayToggle.variables?.id === overlay.id}
                />
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* selected overlay detail */}
      {selected && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-2">
              <Icons.Network className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
              <h2 className="text-sm font-semibold">{selected.name}</h2>
              <TopologyBadge topology={selected.topology} />
              <EncryptionChip encryption={selected.encryption} />
              {!selected.enabled && (
                <Badge variant="outline" className="border-zinc-300 text-[10px] uppercase text-zinc-400 dark:border-zinc-700">
                  disabled
                </Badge>
              )}
            </div>
            <Button
              className="h-9 bg-red-700 px-5 text-white hover:bg-red-800"
              disabled={probe.isPending}
              onClick={() => probe.mutate(selected.id)}
            >
              {probe.isPending ? (
                <Icons.Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
              ) : (
                <Icons.Radar className="mr-1 h-3.5 w-3.5" />
              )}
              Probe now
            </Button>
          </div>

          <div className="grid items-start gap-4 lg:grid-cols-2">
            <SitesCard
              overlayId={selected.id}
              sites={sites}
              isLoading={sitesQuery.isLoading}
              isError={sitesQuery.isError}
              error={sitesQuery.error}
              onRetry={() => void sitesQuery.refetch()}
              onAdd={() => setSiteAddOpen(true)}
              onEdit={(site) => {
                setSelectedId(selected.id);
                setSiteEditing(site);
              }}
              onDelete={(site) => setSiteDeleting(site)}
            />
            <PathsCard
              sites={sites}
              paths={paths.filter((p) => sites.some((s) => s.id === p.siteId))}
              sla={selectedSla}
              isLoading={pathsQuery.isLoading}
              isError={pathsQuery.isError}
              error={pathsQuery.error}
              onRetry={() => void pathsQuery.refetch()}
              onAdd={(site) => setPathAddFor(site)}
              onEdit={(path) => setPathEditing(path)}
              onDelete={(path) => setPathDeleting(path)}
            />
          </div>
        </div>
      )}

      {/* policies + SLA profiles */}
      <div className="grid items-start gap-4 xl:grid-cols-[1fr_420px]">
        <PoliciesCard
          policies={policies}
          isLoading={policiesQuery.isLoading}
          isError={policiesQuery.isError}
          error={policiesQuery.error}
          onRetry={() => void policiesQuery.refetch()}
          onAdd={() => setPolicyAddOpen(true)}
          onEdit={(policy) => setPolicyEditing(policy)}
          onDelete={(policy) => setPolicyDeleting(policy)}
        />
        <SlaProfilesCard
          profiles={slaProfiles}
          isLoading={slaQuery.isLoading}
          isError={slaQuery.isError}
          error={slaQuery.error}
          onRetry={() => void slaQuery.refetch()}
          onAdd={() => setSlaAddOpen(true)}
          onEdit={(profile) => setSlaEditing(profile)}
          onDelete={(profile) => setSlaDeleting(profile)}
        />
      </div>

      {/* dialogs */}
      {overlayAddOpen && <OverlayEditor overlay={null} onClose={() => setOverlayAddOpen(false)} />}
      {overlayEditing && <OverlayEditor overlay={overlayEditing} onClose={() => setOverlayEditing(null)} />}
      {siteAddOpen && selected && (
        <SiteEditor overlayId={selected.id} site={null} onClose={() => setSiteAddOpen(false)} />
      )}
      {siteEditing && <SiteEditor overlayId={siteEditing.overlayId} site={siteEditing} onClose={() => setSiteEditing(null)} />}
      {pathAddFor && <PathEditor site={pathAddFor} path={null} onClose={() => setPathAddFor(null)} />}
      {pathEditing && (
        <PathEditor
          site={{ id: pathEditing.siteId, name: pathEditing.siteName }}
          path={pathEditing}
          onClose={() => setPathEditing(null)}
        />
      )}
      {policyAddOpen && (
        <PolicyEditor
          policy={null}
          overlays={overlays}
          slaProfiles={slaProfiles}
          defaultOverlayId={selected?.id ?? null}
          onClose={() => setPolicyAddOpen(false)}
        />
      )}
      {policyEditing && (
        <PolicyEditor
          policy={policyEditing}
          overlays={overlays}
          slaProfiles={slaProfiles}
          defaultOverlayId={null}
          onClose={() => setPolicyEditing(null)}
        />
      )}
      {slaAddOpen && <SlaProfileEditor profile={null} onClose={() => setSlaAddOpen(false)} />}
      {slaEditing && <SlaProfileEditor profile={slaEditing} onClose={() => setSlaEditing(null)} />}

      {/* delete confirmations */}
      <ConfirmDialog
        open={overlayDeleting !== null}
        onOpenChange={(o) => !o && setOverlayDeleting(null)}
        title={`Delete overlay "${overlayDeleting?.name ?? ""}"?`}
        description="Overlays with sites or policies cannot be deleted — detach them first."
        loading={overlayDel.isPending}
        onConfirm={() => overlayDeleting && overlayDel.mutate(overlayDeleting.id)}
      />
      <ConfirmDialog
        open={siteDeleting !== null}
        onOpenChange={(o) => !o && setSiteDeleting(null)}
        title={`Delete site "${siteDeleting?.name ?? ""}"?`}
        description="The site and all of its WAN paths will be removed."
        loading={siteDel.isPending}
        onConfirm={() => siteDeleting && siteDel.mutate(siteDeleting.id)}
      />
      <ConfirmDialog
        open={pathDeleting !== null}
        onOpenChange={(o) => !o && setPathDeleting(null)}
        title={`Delete WAN path ${pathDeleting?.wanInterface ?? ""} on ${pathDeleting?.siteName ?? ""}?`}
        description="Traffic using this path fails over to the remaining paths."
        loading={pathDel.isPending}
        onConfirm={() => pathDeleting && pathDel.mutate(pathDeleting.id)}
      />
      <ConfirmDialog
        open={policyDeleting !== null}
        onOpenChange={(o) => !o && setPolicyDeleting(null)}
        title={`Delete policy "${policyDeleting?.name ?? ""}"?`}
        description="Matching traffic falls back to default steering."
        loading={policyDel.isPending}
        onConfirm={() => policyDeleting && policyDel.mutate(policyDeleting.id)}
      />
      <ConfirmDialog
        open={slaDeleting !== null}
        onOpenChange={(o) => !o && setSlaDeleting(null)}
        title={`Delete SLA profile "${slaDeleting?.name ?? ""}"?`}
        description="Profiles referenced by policies cannot be deleted — detach them first."
        loading={slaDel.isPending}
        onConfirm={() => slaDeleting && slaDel.mutate(slaDeleting.id)}
      />
    </div>
  );
}
