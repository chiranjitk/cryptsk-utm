"use client";

/**
 * M19 OSPF tab — global settings card (routerId, reference bandwidth,
 * graceful restart, enabled) + interfaces table with the dead ≥ 2×hello rule
 * enforced server-side (field errors render inline).
 */

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
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
  EmptyBlock,
  FieldLabel,
  QueryError,
  TableSkeleton,
  toastErr,
  toastOk,
} from "@/components/views/firewall/fw-ui";
import {
  drApi,
  fieldErrorsOf,
  type OspfInterfaceDTO,
  type OspfSettingsDTO,
} from "./dynamic-routing-api";
import { NetTypeChip, OspfStateBadge, PassiveChip, FieldError } from "./dr-ui";

const OSPF_KEY = ["dynamic-routing", "ospf"] as const;

type IfaceEditor = { mode: "create" } | { mode: "edit"; iface: OspfInterfaceDTO } | null;

interface IfaceFormState {
  interfaceName: string;
  area: string;
  helloSec: string;
  deadSec: string;
  cost: string;
  networkType: "broadcast" | "p2p" | "nbma";
  passive: boolean;
  enabled: boolean;
}

const initialIfaceForm: IfaceFormState = {
  interfaceName: "",
  area: "0.0.0.0",
  helloSec: "10",
  deadSec: "40",
  cost: "10",
  networkType: "broadcast",
  passive: false,
  enabled: true,
};

function ifaceFormOf(i: OspfInterfaceDTO): IfaceFormState {
  return {
    interfaceName: i.interfaceName,
    area: i.area,
    helloSec: String(i.helloSec),
    deadSec: String(i.deadSec),
    cost: String(i.cost),
    networkType: (i.networkType === "p2p" || i.networkType === "nbma" ? i.networkType : "broadcast") as
      | "broadcast"
      | "p2p"
      | "nbma",
    passive: i.passive,
    enabled: i.enabled,
  };
}

function ifaceBodyOf(f: IfaceFormState): Record<string, unknown> {
  return {
    interfaceName: f.interfaceName.trim(),
    area: f.area.trim(),
    helloSec: Number(f.helloSec),
    deadSec: Number(f.deadSec),
    cost: Number(f.cost),
    networkType: f.networkType,
    passive: f.passive,
    enabled: f.enabled,
  };
}

export function OspfTab() {
  const qc = useQueryClient();
  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ["dynamic-routing"] });
  };

  const settingsQ = useQuery({ queryKey: ["dynamic-routing", "ospf-settings"], queryFn: drApi.getOspfSettings });
  const ifacesQ = useQuery({ queryKey: OSPF_KEY, queryFn: drApi.listOspfInterfaces });

  const [routerId, setRouterId] = useState<string>("");
  const [refBw, setRefBw] = useState<string>("");
  const [hydrated, setHydrated] = useState<OspfSettingsDTO | null>(null);
  const settings: OspfSettingsDTO | undefined = settingsQ.data;
  if (settings && hydrated?.id !== settings.id) {
    // hydrate local inputs once per loaded row (keeps typing responsive)
    setHydrated(settings);
    setRouterId(settings.routerId);
    setRefBw(String(settings.referenceBandwidth));
  }

  const [settingsErrors, setSettingsErrors] = useState<Record<string, string[]>>({});

  const saveSettings = useMutation({
    mutationFn: () =>
      drApi.updateOspfSettings({
        routerId: routerId.trim(),
        referenceBandwidth: Number(refBw),
        gracefulRestart: settings?.gracefulRestart ?? false,
        enabled: settings?.enabled ?? false,
      }),
    onSuccess: (s) => {
      invalidate();
      setSettingsErrors({});
      toastOk("OSPF settings saved", `router-id ${s.routerId} · reference bw ${s.referenceBandwidth} Mbps`);
    },
    onError: (err) => setSettingsErrors(fieldErrorsOf(err)),
  });

  const toggleSettingsEnabled = useMutation({
    mutationFn: (enabled: boolean) =>
      drApi.updateOspfSettings({
        routerId: settings?.routerId ?? "10.10.0.1",
        referenceBandwidth: settings?.referenceBandwidth ?? 100,
        gracefulRestart: settings?.gracefulRestart ?? false,
        enabled,
      }),
    onSuccess: (s) => {
      invalidate();
      toastOk(s.enabled ? "OSPF enabled" : "OSPF disabled");
    },
    onError: (err) => toastErr(err, "Update failed"),
  });

  const toggleGraceful = useMutation({
    mutationFn: (gracefulRestart: boolean) =>
      drApi.updateOspfSettings({
        routerId: settings?.routerId ?? "10.10.0.1",
        referenceBandwidth: settings?.referenceBandwidth ?? 100,
        gracefulRestart,
        enabled: settings?.enabled ?? false,
      }),
    onSuccess: (s) => {
      invalidate();
      toastOk(s.gracefulRestart ? "Graceful restart on" : "Graceful restart off");
    },
    onError: (err) => toastErr(err, "Update failed"),
  });

  // ── interface editor ─────────────────────────────────────────────────────
  const [editor, setEditor] = useState<IfaceEditor>(null);
  const [form, setForm] = useState<IfaceFormState>(initialIfaceForm);
  const [formErrors, setFormErrors] = useState<Record<string, string[]>>({});
  const [pendingDelete, setPendingDelete] = useState<{ id: number; name: string } | null>(null);

  const saveIface = useMutation({
    mutationFn: (vars: { mode: "create" | "edit"; id?: number }) =>
      vars.mode === "create"
        ? drApi.createOspfInterface(ifaceBodyOf(form))
        : drApi.updateOspfInterface(vars.id ?? 0, ifaceBodyOf(form)),
    onSuccess: (i, vars) => {
      invalidate();
      setEditor(null);
      toastOk(vars.mode === "create" ? "Interface added" : "Interface updated", `${i.interfaceName} area ${i.area}`);
    },
    onError: (err) => setFormErrors(fieldErrorsOf(err)),
  });

  const deleteIface = useMutation({
    mutationFn: (id: number) => drApi.deleteOspfInterface(id),
    onSuccess: (_d, id) => {
      invalidate();
      setPendingDelete(null);
      toastOk("Interface removed", `#${id}`);
    },
    onError: (err) => toastErr(err, "Delete failed"),
  });

  const ifaces = ifacesQ.data ?? [];
  const set = <K extends keyof IfaceFormState>(key: K, value: IfaceFormState[K]) =>
    setForm((f) => ({ ...f, [key]: value }));

  return (
    <div className="space-y-6">
      {/* ── global settings card ─────────────────────────────────────────── */}
      <Card>
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2 text-base">
            <Icons.Cog className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
            OSPF process
          </CardTitle>
          <CardDescription>Single process per appliance — router-id and SPF costs.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {settingsQ.isError ? (
            <QueryError error={settingsQ.error} onRetry={() => void settingsQ.refetch()} />
          ) : (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <FieldLabel hint="IPv4">Router ID</FieldLabel>
                <Input
                  value={routerId}
                  onChange={(e) => setRouterId(e.target.value)}
                  placeholder="10.10.0.1"
                  className="font-mono"
                  disabled={settingsQ.isLoading}
                />
                <FieldError errors={settingsErrors} field="routerId" />
              </div>
              <div>
                <FieldLabel hint="1–100000 Mbps">Reference bandwidth</FieldLabel>
                <Input
                  value={refBw}
                  onChange={(e) => setRefBw(e.target.value)}
                  inputMode="numeric"
                  disabled={settingsQ.isLoading}
                />
                <FieldError errors={settingsErrors} field="referenceBandwidth" />
              </div>
              <label className="flex items-center justify-between gap-3 rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
                <span className="text-sm font-medium">Graceful restart</span>
                <Switch
                  checked={settings?.gracefulRestart ?? false}
                  onCheckedChange={(v) => toggleGraceful.mutate(v)}
                  disabled={settingsQ.isLoading || toggleGraceful.isPending}
                />
              </label>
              <label className="flex items-center justify-between gap-3 rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
                <span className="text-sm font-medium">OSPF enabled</span>
                <Switch
                  checked={settings?.enabled ?? false}
                  onCheckedChange={(v) => toggleSettingsEnabled.mutate(v)}
                  disabled={settingsQ.isLoading || toggleSettingsEnabled.isPending}
                />
              </label>
              <div className="sm:col-span-2 lg:col-span-4">
                <Button
                  className="bg-red-700 text-white hover:bg-red-800"
                  disabled={settingsQ.isLoading || saveSettings.isPending}
                  onClick={() => saveSettings.mutate()}
                >
                  {saveSettings.isPending ? "Saving…" : "Save settings"}
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── interfaces table ─────────────────────────────────────────────── */}
      <div className="space-y-4">
        <div className="flex items-center justify-between gap-2">
          <p className="text-sm text-zinc-500">Interfaces participating in OSPF — hello/dead, cost and network type.</p>
          <Button
            className="gap-1.5 bg-red-700 text-white hover:bg-red-800"
            onClick={() => {
              setForm(initialIfaceForm);
              setFormErrors({});
              setEditor({ mode: "create" });
            }}
          >
            <Icons.Plus className="h-4 w-4" />
            Add interface
          </Button>
        </div>

        {ifacesQ.isLoading ? (
          <TableSkeleton rows={3} cols={8} />
        ) : ifacesQ.isError ? (
          <QueryError error={ifacesQ.error} onRetry={() => void ifacesQ.refetch()} />
        ) : ifaces.length === 0 ? (
          <EmptyBlock
            icon={<Icons.EthernetPort className="h-6 w-6" />}
            title="No OSPF interfaces"
            description="Enable interfaces to form adjacencies and learn OSPF routes."
          />
        ) : (
          <div className="max-h-96 overflow-y-auto rounded-lg border border-zinc-200 dark:border-zinc-800 [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-zinc-300 dark:[&::-webkit-scrollbar-thumb]:bg-zinc-700">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Interface</TableHead>
                  <TableHead>Area</TableHead>
                  <TableHead>Hello / Dead</TableHead>
                  <TableHead>Cost</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Passive</TableHead>
                  <TableHead>Neighbor state</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {ifaces.map((i) => (
                  <TableRow key={i.id} className={i.enabled ? undefined : "opacity-50"}>
                    <TableCell className="font-mono text-xs font-medium">{i.interfaceName}</TableCell>
                    <TableCell className="font-mono text-xs">{i.area}</TableCell>
                    <TableCell className="text-xs">
                      {i.helloSec}s / {i.deadSec}s
                    </TableCell>
                    <TableCell className="font-mono text-xs">{i.cost}</TableCell>
                    <TableCell>
                      <NetTypeChip type={i.networkType} />
                    </TableCell>
                    <TableCell>
                      <PassiveChip passive={i.passive} />
                    </TableCell>
                    <TableCell>
                      <OspfStateBadge state={i.neighborState} />
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="inline-flex items-center gap-1">
                        <Button
                          size="icon"
                          variant="ghost"
                          className="h-8 w-8"
                          aria-label={`Edit ${i.interfaceName}`}
                          onClick={() => {
                            setForm(ifaceFormOf(i));
                            setFormErrors({});
                            setEditor({ mode: "edit", iface: i });
                          }}
                        >
                          <Icons.Pencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          className="h-8 w-8 text-rose-600 hover:bg-rose-500/10 dark:text-rose-400"
                          aria-label={`Delete ${i.interfaceName}`}
                          onClick={() => setPendingDelete({ id: i.id, name: i.interfaceName })}
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
      </div>

      {/* ── interface dialog ─────────────────────────────────────────────── */}
      <Dialog
        open={editor !== null}
        onOpenChange={(open) => {
          if (!open) setEditor(null);
        }}
      >
        <DialogContent className="max-h-[90vh] max-w-xl overflow-y-auto">
          <DialogHeader>
            <DialogTitle>
              {editor?.mode === "edit" ? `Edit interface — ${editor.iface.interfaceName}` : "Add OSPF interface"}
            </DialogTitle>
            <DialogDescription>Dead interval must be at least 2× the hello interval.</DialogDescription>
          </DialogHeader>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <FieldLabel hint="unique">Interface</FieldLabel>
              <Input value={form.interfaceName} onChange={(e) => set("interfaceName", e.target.value)} placeholder="lan0" className="font-mono" />
              <FieldError errors={formErrors} field="interfaceName" />
            </div>
            <div>
              <FieldLabel hint="0.0.0.0 format">Area</FieldLabel>
              <Input value={form.area} onChange={(e) => set("area", e.target.value)} className="font-mono" />
              <FieldError errors={formErrors} field="area" />
            </div>
            <div>
              <FieldLabel>Hello interval (s)</FieldLabel>
              <Input value={form.helloSec} onChange={(e) => set("helloSec", e.target.value)} inputMode="numeric" />
              <FieldError errors={formErrors} field="helloSec" />
            </div>
            <div>
              <FieldLabel hint="≥ 2× hello">Dead interval (s)</FieldLabel>
              <Input value={form.deadSec} onChange={(e) => set("deadSec", e.target.value)} inputMode="numeric" />
              <FieldError errors={formErrors} field="deadSec" />
            </div>
            <div>
              <FieldLabel>Cost</FieldLabel>
              <Input value={form.cost} onChange={(e) => set("cost", e.target.value)} inputMode="numeric" />
              <FieldError errors={formErrors} field="cost" />
            </div>
            <div>
              <FieldLabel>Network type</FieldLabel>
              <Select value={form.networkType} onValueChange={(v) => set("networkType", v as IfaceFormState["networkType"])}>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="broadcast">broadcast</SelectItem>
                  <SelectItem value="p2p">p2p</SelectItem>
                  <SelectItem value="nbma">nbma</SelectItem>
                </SelectContent>
              </Select>
              <FieldError errors={formErrors} field="networkType" />
            </div>
            <label className="flex items-center justify-between gap-3 rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
              <span className="text-sm font-medium">Passive</span>
              <Switch checked={form.passive} onCheckedChange={(v) => set("passive", v)} />
            </label>
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
              className="bg-red-700 text-white hover:bg-red-800"
              disabled={saveIface.isPending}
              onClick={() =>
                editor && saveIface.mutate(editor.mode === "edit" ? { mode: "edit", id: editor.iface.id } : { mode: "create" })
              }
            >
              {saveIface.isPending ? "Saving…" : editor?.mode === "edit" ? "Save changes" : "Add interface"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={pendingDelete !== null}
        onOpenChange={(open) => {
          if (!open) setPendingDelete(null);
        }}
        title={`Remove interface ${pendingDelete?.name ?? ""} from OSPF?`}
        description="Adjacencies over this interface are torn down and its routes withdrawn on the next RIB refresh."
        loading={deleteIface.isPending}
        onConfirm={() => pendingDelete && deleteIface.mutate(pendingDelete.id)}
      />
    </div>
  );
}
