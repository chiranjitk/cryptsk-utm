"use client";

/**
 * M19 BGP tab — neighbors table (state/uptime/prefixes/BFD/password chips,
 * enabled switch, session start/stop) + add/edit dialog with policy-object
 * selects and the show-once password note. Queries under ["dynamic-routing"].
 */

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Button } from "@/components/ui/button";
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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  ConfirmDialog,
  EditorSection,
  EmptyBlock,
  FieldLabel,
  QueryError,
  TableSkeleton,
  toastErr,
  toastOk,
} from "@/components/views/firewall/fw-ui";
import { cn } from "@/lib/utils";
import {
  drApi,
  fieldErrorsOf,
  humanizeUptime,
  type BgpNeighborDTO,
} from "./dynamic-routing-api";
import { BfdFlagChip, BgpStateBadge, FieldError } from "./dr-ui";

const BGP_KEY = ["dynamic-routing", "bgp"] as const;
const PL_KEY = ["dynamic-routing", "prefix-lists"] as const;
const RM_KEY = ["dynamic-routing", "route-maps"] as const;
const BFD_KEY = ["dynamic-routing", "bfd"] as const;

type EditorOpen = { mode: "create" } | { mode: "edit"; neighbor: BgpNeighborDTO } | null;

interface NeighborFormState {
  name: string;
  peerIp: string;
  remoteAs: string;
  localAs: string;
  peerIface: string;
  password: string;
  keepaliveSec: string;
  holdtimeSec: string;
  gracefulRestart: boolean;
  bfdEnabled: boolean;
  bfdProfileId: string;
  prefixListInId: string;
  prefixListOutId: string;
  routeMapInId: string;
  routeMapOutId: string;
  ebgpMultihop: boolean;
  enabled: boolean;
}

const initialForm: NeighborFormState = {
  name: "",
  peerIp: "",
  remoteAs: "",
  localAs: "",
  peerIface: "",
  password: "",
  keepaliveSec: "60",
  holdtimeSec: "180",
  gracefulRestart: false,
  bfdEnabled: false,
  bfdProfileId: "",
  prefixListInId: "",
  prefixListOutId: "",
  routeMapInId: "",
  routeMapOutId: "",
  ebgpMultihop: false,
  enabled: true,
};

function formOf(n: BgpNeighborDTO): NeighborFormState {
  return {
    name: n.name,
    peerIp: n.peerIp,
    remoteAs: String(n.remoteAs),
    localAs: n.localAs === null ? "" : String(n.localAs),
    peerIface: n.peerIface ?? "",
    password: "",
    keepaliveSec: String(n.keepaliveSec),
    holdtimeSec: String(n.holdtimeSec),
    gracefulRestart: n.gracefulRestart,
    bfdEnabled: n.bfdEnabled,
    bfdProfileId: n.bfdProfileId === null ? "" : String(n.bfdProfileId),
    prefixListInId: n.prefixListInId === null ? "" : String(n.prefixListInId),
    prefixListOutId: n.prefixListOutId === null ? "" : String(n.prefixListOutId),
    routeMapInId: n.routeMapInId === null ? "" : String(n.routeMapInId),
    routeMapOutId: n.routeMapOutId === null ? "" : String(n.routeMapOutId),
    ebgpMultihop: n.ebgpMultihop,
    enabled: n.enabled,
  };
}

/** "" → omitted on create (defaults apply) / null on edit (clears). */
function bodyOf(f: NeighborFormState, mode: "create" | "edit"): Record<string, unknown> {
  const num = (v: string, field: string): Record<string, unknown> => {
    if (mode === "edit") return { [field]: v.trim() === "" ? null : Number(v) };
    return v.trim() === "" ? {} : { [field]: Number(v) };
  };
  const str = (v: string, field: string): Record<string, unknown> => {
    if (mode === "edit") return { [field]: v.trim() === "" ? null : v.trim() };
    return v.trim() === "" ? {} : { [field]: v.trim() };
  };
  const ref = (v: string, field: string): Record<string, unknown> => {
    if (mode === "edit") return { [field]: v === "" ? null : Number(v) };
    return v === "" ? {} : { [field]: Number(v) };
  };
  return {
    name: f.name.trim(),
    peerIp: f.peerIp.trim(),
    remoteAs: Number(f.remoteAs),
    keepaliveSec: Number(f.keepaliveSec),
    holdtimeSec: Number(f.holdtimeSec),
    gracefulRestart: f.gracefulRestart,
    bfdEnabled: f.bfdEnabled,
    ebgpMultihop: f.ebgpMultihop,
    enabled: f.enabled,
    ...str(f.peerIface, "peerIface"),
    ...(f.password.trim() === "" ? {} : { password: f.password.trim() }),
    ...num(f.localAs, "localAs"),
    ...ref(f.bfdProfileId, "bfdProfileId"),
    ...ref(f.prefixListInId, "prefixListInId"),
    ...ref(f.prefixListOutId, "prefixListOutId"),
    ...ref(f.routeMapInId, "routeMapInId"),
    ...ref(f.routeMapOutId, "routeMapOutId"),
  };
}

export function BgpTab() {
  const qc = useQueryClient();
  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ["dynamic-routing"] });
  };

  const neighborsQ = useQuery({ queryKey: BGP_KEY, queryFn: drApi.listBgpNeighbors });
  const prefixListsQ = useQuery({ queryKey: PL_KEY, queryFn: drApi.listPrefixLists });
  const routeMapsQ = useQuery({ queryKey: RM_KEY, queryFn: drApi.listRouteMaps });
  const bfdQ = useQuery({ queryKey: BFD_KEY, queryFn: drApi.listBfdProfiles });

  const [editor, setEditor] = useState<EditorOpen>(null);
  const [form, setForm] = useState<NeighborFormState>(initialForm);
  const [formErrors, setFormErrors] = useState<Record<string, string[]>>({});
  const [formAlert, setFormAlert] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<{ id: number; name: string } | null>(null);

  const openCreate = () => {
    setForm(initialForm);
    setFormErrors({});
    setFormAlert(null);
    setEditor({ mode: "create" });
  };
  const openEdit = (n: BgpNeighborDTO) => {
    setForm(formOf(n));
    setFormErrors({});
    setFormAlert(null);
    setEditor({ mode: "edit", neighbor: n });
  };

  const saveMut = useMutation({
    mutationFn: (vars: { mode: "create" | "edit"; id?: number }) =>
      vars.mode === "create"
        ? drApi.createBgpNeighbor(bodyOf(form, "create"))
        : drApi.updateBgpNeighbor(vars.id ?? 0, bodyOf(form, "edit")),
    onSuccess: (n, vars) => {
      invalidate();
      setEditor(null);
      toastOk(vars.mode === "create" ? "Neighbor created" : "Neighbor updated", `${n.name} (${n.peerIp}) AS ${n.remoteAs}`);
    },
    onError: (err) => {
      const fe = fieldErrorsOf(err);
      setFormErrors(fe);
      const first = Object.values(fe)[0];
      setFormAlert(first ? first[0] : err instanceof Error ? err.message : "Save failed");
    },
  });

  const deleteMut = useMutation({
    mutationFn: (id: number) => drApi.deleteBgpNeighbor(id),
    onSuccess: (_d, id) => {
      invalidate();
      setPendingDelete(null);
      toastOk("Neighbor deleted", `#${id} removed`);
    },
    onError: (err) => toastErr(err, "Delete failed"),
  });

  const sessionMut = useMutation({
    mutationFn: (vars: { id: number; name: string; action: "start" | "stop" }) =>
      drApi.bgpSession(vars.id, vars.action),
    onSuccess: (n, vars) => {
      invalidate();
      toastOk(
        vars.action === "start" ? "Session started" : "Session stopped",
        `${vars.name} → ${n.state}${n.state === "established" ? ` · ${n.prefixesReceived} prefixes` : ""}`,
      );
    },
    onError: (err) => toastErr(err, "Session action failed"),
  });

  const toggleEnabled = useMutation({
    mutationFn: (n: BgpNeighborDTO) => drApi.updateBgpNeighbor(n.id, { enabled: !n.enabled }),
    onSuccess: () => invalidate(),
    onError: (err) => toastErr(err, "Update failed"),
  });

  const neighbors = neighborsQ.data ?? [];
  const bfdProfiles = bfdQ.data ?? [];
  const ipv4PrefixLists = (prefixListsQ.data ?? []).filter((pl) => pl.family === "ipv4");
  const routeMaps = routeMapsQ.data ?? [];
  const bfdNameOf = (id: number | null): string | null =>
    id === null ? null : bfdProfiles.find((p) => p.id === id)?.name ?? null;
  const set = <K extends keyof NeighborFormState>(key: K, value: NeighborFormState[K]) =>
    setForm((f) => ({ ...f, [key]: value }));

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-2">
        <p className="text-sm text-zinc-500">
          eBGP/iBGP peering sessions — filters, route-maps and BFD attach per neighbor.
        </p>
        <Button onClick={openCreate} className="gap-1.5 bg-zinc-700 text-white hover:bg-zinc-800">
          <Icons.Plus className="h-4 w-4" />
          Add neighbor
        </Button>
      </div>

      {neighborsQ.isLoading ? (
        <TableSkeleton rows={4} cols={9} />
      ) : neighborsQ.isError ? (
        <QueryError error={neighborsQ.error} onRetry={() => void neighborsQ.refetch()} />
      ) : neighbors.length === 0 ? (
        <EmptyBlock
          icon={<Icons.Network className="h-6 w-6" />}
          title="No BGP neighbors"
          description="Add an upstream or iBGP neighbor to start exchanging routes."
          action={
            <Button size="sm" variant="outline" onClick={openCreate}>
              Add neighbor
            </Button>
          }
        />
      ) : (
        <div className="max-h-96 overflow-y-auto rounded-lg border border-zinc-200 dark:border-zinc-800 [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-zinc-300 dark:[&::-webkit-scrollbar-thumb]:bg-zinc-700">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Neighbor</TableHead>
                <TableHead>Peer IP</TableHead>
                <TableHead>Remote AS</TableHead>
                <TableHead>State</TableHead>
                <TableHead>Uptime</TableHead>
                <TableHead>Prefixes</TableHead>
                <TableHead>BFD</TableHead>
                <TableHead>Enabled</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {neighbors.map((n) => (
                <TableRow key={n.id}>
                  <TableCell className="font-medium">
                    <span className="flex items-center gap-1.5">
                      {n.name}
                      {n.hasPassword ? (
                        <Icons.Lock className="h-3.5 w-3.5 text-zinc-400" aria-label="password set" />
                      ) : null}
                    </span>
                  </TableCell>
                  <TableCell className="font-mono text-xs">{n.peerIp}</TableCell>
                  <TableCell className="font-mono text-xs">{n.remoteAs}</TableCell>
                  <TableCell>
                    <BgpStateBadge state={n.state} />
                  </TableCell>
                  <TableCell className="text-xs text-zinc-500">
                    {n.state === "established" ? humanizeUptime(n.uptimeSec) : "—"}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {n.state === "established" ? n.prefixesReceived : "—"}
                  </TableCell>
                  <TableCell>
                    <BfdFlagChip enabled={n.bfdEnabled} profileName={bfdNameOf(n.bfdProfileId)} />
                  </TableCell>
                  <TableCell>
                    <Switch
                      checked={n.enabled}
                      onCheckedChange={() => toggleEnabled.mutate(n)}
                      aria-label={`Toggle neighbor ${n.name}`}
                    />
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="inline-flex items-center gap-1">
                      {n.state === "established" ? (
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-8 gap-1"
                          disabled={sessionMut.isPending}
                          onClick={() => sessionMut.mutate({ id: n.id, name: n.name, action: "stop" })}
                        >
                          <Icons.Square className="h-3.5 w-3.5" />
                          Stop
                        </Button>
                      ) : (
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-8 gap-1 text-zinc-600 hover:bg-zinc-500/10 dark:text-zinc-300"
                          disabled={sessionMut.isPending || !n.enabled}
                          onClick={() => sessionMut.mutate({ id: n.id, name: n.name, action: "start" })}
                        >
                          <Icons.Play className="h-3.5 w-3.5" />
                          Start
                        </Button>
                      )}
                      <Button
                        size="icon"
                        variant="ghost"
                        className="h-8 w-8"
                        aria-label={`Edit ${n.name}`}
                        onClick={() => openEdit(n)}
                      >
                        <Icons.Pencil className="h-3.5 w-3.5" />
                      </Button>
                      <Button
                        size="icon"
                        variant="ghost"
                        className="h-8 w-8 text-rose-600 hover:bg-rose-500/10 dark:text-rose-400"
                        aria-label={`Delete ${n.name}`}
                        onClick={() => setPendingDelete({ id: n.id, name: n.name })}
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

      {/* ── add / edit dialog ──────────────────────────────────────────── */}
      <Dialog
        open={editor !== null}
        onOpenChange={(open) => {
          if (!open) setEditor(null);
        }}
      >
        <DialogContent className="max-h-[90vh] max-w-2xl overflow-y-auto">
          <DialogHeader>
            <DialogTitle>
              {editor?.mode === "edit" ? `Edit neighbor — ${editor.neighbor.name}` : "Add BGP neighbor"}
            </DialogTitle>
            <DialogDescription>
              Session password is write-only: it is stored as-is and never returned by the API.
            </DialogDescription>
          </DialogHeader>

          {formAlert ? (
            <div className="rounded-md border border-rose-500/40 bg-rose-500/5 px-3 py-2 text-xs font-medium text-rose-600 dark:text-rose-400">
              {formAlert}
            </div>
          ) : null}

          <div className="space-y-4">
            <EditorSection title="Session basics">
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div>
                  <FieldLabel>Name</FieldLabel>
                  <Input value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="upstream-1" />
                  <FieldError errors={formErrors} field="name" />
                </div>
                <div>
                  <FieldLabel hint="IPv4">Peer IP</FieldLabel>
                  <Input
                    value={form.peerIp}
                    onChange={(e) => set("peerIp", e.target.value)}
                    placeholder="203.0.113.9"
                    className="font-mono"
                  />
                  <FieldError errors={formErrors} field="peerIp" />
                </div>
                <div>
                  <FieldLabel>Remote AS</FieldLabel>
                  <Input
                    value={form.remoteAs}
                    onChange={(e) => set("remoteAs", e.target.value)}
                    placeholder="65000"
                    inputMode="numeric"
                  />
                  <FieldError errors={formErrors} field="remoteAs" />
                </div>
                <div>
                  <FieldLabel hint="optional">Local AS</FieldLabel>
                  <Input
                    value={form.localAs}
                    onChange={(e) => set("localAs", e.target.value)}
                    placeholder="same as router AS"
                    inputMode="numeric"
                  />
                  <FieldError errors={formErrors} field="localAs" />
                </div>
                <div>
                  <FieldLabel hint="optional">Peer interface</FieldLabel>
                  <Input
                    value={form.peerIface}
                    onChange={(e) => set("peerIface", e.target.value)}
                    placeholder="wan0"
                    className="font-mono"
                  />
                  <FieldError errors={formErrors} field="peerIface" />
                </div>
                <div>
                  <FieldLabel hint="shown once">Password</FieldLabel>
                  <Input
                    type="password"
                    value={form.password}
                    onChange={(e) => set("password", e.target.value)}
                    placeholder={editor?.mode === "edit" ? "leave blank to keep" : "MD5 session key"}
                    autoComplete="new-password"
                  />
                  <FieldError errors={formErrors} field="password" />
                </div>
              </div>
            </EditorSection>

            <EditorSection title="Timers & features">
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div>
                  <FieldLabel hint="3–3600 s">Keepalive (s)</FieldLabel>
                  <Input value={form.keepaliveSec} onChange={(e) => set("keepaliveSec", e.target.value)} inputMode="numeric" />
                  <FieldError errors={formErrors} field="keepaliveSec" />
                </div>
                <div>
                  <FieldLabel hint="≥ 3× keepalive">Holdtime (s)</FieldLabel>
                  <Input value={form.holdtimeSec} onChange={(e) => set("holdtimeSec", e.target.value)} inputMode="numeric" />
                  <FieldError errors={formErrors} field="holdtimeSec" />
                </div>
                <label className="flex items-center justify-between gap-3 rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
                  <span className="text-sm font-medium">Graceful restart</span>
                  <Switch checked={form.gracefulRestart} onCheckedChange={(v) => set("gracefulRestart", v)} />
                </label>
                <label className="flex items-center justify-between gap-3 rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
                  <span className="text-sm font-medium">eBGP multihop</span>
                  <Switch checked={form.ebgpMultihop} onCheckedChange={(v) => set("ebgpMultihop", v)} />
                </label>
              </div>
            </EditorSection>

            <EditorSection title="Policy objects & BFD">
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div>
                  <FieldLabel hint="family ipv4">Prefix-list in</FieldLabel>
                  <Select value={form.prefixListInId || "none"} onValueChange={(v) => set("prefixListInId", v === "none" ? "" : v)}>
                    <SelectTrigger className="w-full">
                      <SelectValue placeholder="none" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="none">none</SelectItem>
                      {ipv4PrefixLists.map((pl) => (
                        <SelectItem key={pl.id} value={String(pl.id)}>
                          {pl.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FieldError errors={formErrors} field="prefixListInId" />
                </div>
                <div>
                  <FieldLabel hint="family ipv4">Prefix-list out</FieldLabel>
                  <Select value={form.prefixListOutId || "none"} onValueChange={(v) => set("prefixListOutId", v === "none" ? "" : v)}>
                    <SelectTrigger className="w-full">
                      <SelectValue placeholder="none" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="none">none</SelectItem>
                      {ipv4PrefixLists.map((pl) => (
                        <SelectItem key={pl.id} value={String(pl.id)}>
                          {pl.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FieldError errors={formErrors} field="prefixListOutId" />
                </div>
                <div>
                  <FieldLabel>Route-map in</FieldLabel>
                  <Select value={form.routeMapInId || "none"} onValueChange={(v) => set("routeMapInId", v === "none" ? "" : v)}>
                    <SelectTrigger className="w-full">
                      <SelectValue placeholder="none" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="none">none</SelectItem>
                      {routeMaps.map((rm) => (
                        <SelectItem key={rm.id} value={String(rm.id)}>
                          {rm.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FieldError errors={formErrors} field="routeMapInId" />
                </div>
                <div>
                  <FieldLabel>Route-map out</FieldLabel>
                  <Select value={form.routeMapOutId || "none"} onValueChange={(v) => set("routeMapOutId", v === "none" ? "" : v)}>
                    <SelectTrigger className="w-full">
                      <SelectValue placeholder="none" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="none">none</SelectItem>
                      {routeMaps.map((rm) => (
                        <SelectItem key={rm.id} value={String(rm.id)}>
                          {rm.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FieldError errors={formErrors} field="routeMapOutId" />
                </div>
                <label className="flex items-center justify-between gap-3 rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
                  <span className="text-sm font-medium">BFD monitoring</span>
                  <Switch checked={form.bfdEnabled} onCheckedChange={(v) => set("bfdEnabled", v)} />
                </label>
                <div>
                  <FieldLabel hint={form.bfdEnabled ? undefined : "enable BFD first"}>BFD profile</FieldLabel>
                  <Select value={form.bfdProfileId || "none"} onValueChange={(v) => set("bfdProfileId", v === "none" ? "" : v)} disabled={!form.bfdEnabled}>
                    <SelectTrigger className={cn("w-full", !form.bfdEnabled && "opacity-50")}>
                      <SelectValue placeholder="none" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="none">none</SelectItem>
                      {bfdProfiles.map((p) => (
                        <SelectItem key={p.id} value={String(p.id)}>
                          {p.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FieldError errors={formErrors} field="bfdProfileId" />
                </div>
              </div>
            </EditorSection>

            <label className="flex items-center justify-between gap-3 rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
              <span className="text-sm font-medium">Enabled</span>
              <Switch checked={form.enabled} onCheckedChange={(v) => set("enabled", v)} />
            </label>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setEditor(null)}>
              Cancel
            </Button>
            <Button
              className="bg-zinc-700 text-white hover:bg-zinc-800"
              disabled={saveMut.isPending}
              onClick={() =>
                editor && saveMut.mutate(editor.mode === "edit" ? { mode: "edit", id: editor.neighbor.id } : { mode: "create" })
              }
            >
              {saveMut.isPending ? "Saving…" : editor?.mode === "edit" ? "Save changes" : "Create neighbor"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── delete confirm ─────────────────────────────────────────────── */}
      <ConfirmDialog
        open={pendingDelete !== null}
        onOpenChange={(open) => {
          if (!open) setPendingDelete(null);
        }}
        title={`Delete neighbor ${pendingDelete?.name ?? ""}?`}
        description="The BGP session and its learned routes are removed from the simulated RIB on the next refresh."
        loading={deleteMut.isPending}
        onConfirm={() => pendingDelete && deleteMut.mutate(pendingDelete.id)}
      />
    </div>
  );
}
