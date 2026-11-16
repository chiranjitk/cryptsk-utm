"use client";

/**
 * #/firewall/zones — zone cards (M03 §4). WAN/LAN are service-layer protected:
 * Delete is hidden and the editor locks name/type (tooltip explains).
 *
 * Enterprise upgrade (2026-11-16): the editor picks interfaces from the REAL
 * /api/v1/interfaces catalog (checkbox list, live state shown) instead of a
 * free-text input; each zone shows its rule usage ("Referenced by N rules");
 * the page carries the OS apply/sync surface (FirewallOsSync) because zones
 * materialize as iifname/oifname interface sets inside the kernel table.
 */

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
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
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import {
  api,
  isProtectedZone,
  referencedByOf,
  type Zone,
  type ZoneType,
} from "./fw-api";
import { FirewallOsSync } from "./os-apply";
import {
  ConfirmDialog,
  ConflictDialog,
  EmptyBlock,
  FieldLabel,
  QueryError,
  toastErr,
  toastOk,
  useFwConfigInvalidation,
} from "./fw-ui";

const ZONES_KEY = ["firewall", "zones"] as const;
const IFACES_KEY = ["firewall", "iface-names"] as const;

const ZONE_TYPES: ZoneType[] = ["L3", "L2", "VPN"];

const ZONE_TYPE_HINTS: Record<ZoneType, string> = {
  L3: "Routed L3 segments — policy matches iifname/oifname interface sets",
  L2: "Bridged segments — members participate in L2 forwarding",
  VPN: "Tunnel terminations — encrypted flows land in this zone",
};

export function ZonesView() {
  useFwConfigInvalidation();
  const queryClient = useQueryClient();

  const zonesQuery = useQuery({ queryKey: ZONES_KEY, queryFn: api.listZones });
  const rulesQuery = useQuery({ queryKey: ["firewall", "rules"], queryFn: api.listRules, staleTime: 15_000 });
  const zones = useMemo(() => zonesQuery.data?.data ?? [], [zonesQuery.data]);
  const rules = useMemo(() => rulesQuery.data?.data ?? [], [rulesQuery.data]);

  // server-truth usage: zone id → referencing firewall rules (src/dst zone ids)
  const usage = useMemo(() => {
    const m = new Map<number, string[]>();
    for (const r of rules) {
      for (const zid of [...r.srcZoneIds, ...r.dstZoneIds]) {
        const arr = m.get(zid) ?? [];
        arr.push(r.name);
        m.set(zid, arr);
      }
    }
    return m;
  }, [rules]);

  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<Zone | null>(null);
  const [deleting, setDeleting] = useState<Zone | null>(null);
  const [conflict, setConflict] = useState<{ open: boolean; title: string; message: string; error: unknown }>({
    open: false,
    title: "",
    message: "",
    error: null,
  });

  const knownIfaces = useMemo(() => {
    const set = new Set<string>();
    zones.forEach((z) => z.interfaceNames.forEach((n) => set.add(n)));
    return [...set].sort();
  }, [zones]);

  const deleteMut = useMutation({
    mutationFn: (id: number) => api.deleteZone(id),
    onSuccess: (_d, _id) => {
      toastOk("Zone deleted");
      setDeleting(null);
    },
    onError: (err) => {
      if (referencedByOf(err).length > 0) {
        setConflict({
          open: true,
          title: "Cannot delete zone",
          message: err instanceof Error ? err.message : "Zone is referenced by rules",
          error: err,
        });
        setDeleting(null);
      } else {
        toastErr(err, "Delete failed");
      }
    },
    onSettled: () => void queryClient.invalidateQueries({ queryKey: ZONES_KEY }),
  });

  const openCreate = () => {
    setEditing(null);
    setEditorOpen(true);
  };
  const openEdit = (z: Zone) => {
    setEditing(z);
    setEditorOpen(true);
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <p className="mr-auto text-xs text-zinc-500">
          Zones group interfaces for zone-based policy. WAN and LAN are protected — they cannot be deleted or renamed.
        </p>
        <FirewallOsSync />
        <Button size="sm" onClick={openCreate} className="bg-zinc-700 text-white hover:bg-zinc-800">
          <Icons.Plus className="mr-1 h-4 w-4" /> Add zone
        </Button>
      </div>

      {zonesQuery.error ? (
        <QueryError error={zonesQuery.error} onRetry={() => void zonesQuery.refetch()} />
      ) : zonesQuery.isLoading ? (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-40 rounded-xl" />
          ))}
        </div>
      ) : zones.length === 0 ? (
        <Card className="p-0">
          <CardContent className="p-0">
            <EmptyBlock
              icon={<Icons.Landmark className="h-6 w-6" />}
              title="No zones yet"
              description="Create a zone (L3, L2 or VPN) and assign interfaces so firewall rules can match on it."
              action={
                <Button onClick={openCreate} className="bg-zinc-700 text-white hover:bg-zinc-800">
                  <Icons.Plus className="mr-1 h-4 w-4" /> Add zone
                </Button>
              }
            />
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {zones.map((z) => {
            const protectedZone = isProtectedZone(z.name);
            const usedBy = usage.get(z.id) ?? [];
            return (
              <Card key={z.id} className="flex flex-col p-4">
                <CardHeader className="flex-row items-start justify-between space-y-0 p-0 pb-3">
                  <div>
                    <CardTitle className="flex items-center gap-2 text-sm font-medium">
                      {z.name}
                      {protectedZone && (
                        <TooltipProvider delayDuration={100}>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Icons.Lock className="h-3.5 w-3.5 text-zinc-400" />
                            </TooltipTrigger>
                            <TooltipContent className="text-xs">Protected zone — name/type locked, delete disabled</TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      )}
                    </CardTitle>
                    <div className="mt-1 flex flex-wrap items-center gap-1">
                      <Badge variant="outline" className="w-fit border-zinc-500/30 bg-zinc-500/10 text-[10px] font-semibold text-zinc-600 dark:text-zinc-300">
                        {z.type}
                      </Badge>
                      <TooltipProvider delayDuration={100}>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Badge
                              variant="outline"
                              className={cn(
                                "w-fit cursor-default text-[10px] font-semibold",
                                usedBy.length > 0
                                  ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400"
                                  : "border-zinc-400/30 bg-zinc-400/10 text-zinc-500",
                              )}
                            >
                              <Icons.ShieldCheck className="mr-1 h-3 w-3" />
                              {usedBy.length > 0 ? `used by ${usedBy.length} rule${usedBy.length === 1 ? "" : "s"}` : "unused"}
                            </Badge>
                          </TooltipTrigger>
                          <TooltipContent className="max-w-64 text-xs">
                            {usedBy.length > 0 ? usedBy.slice(0, 12).join(", ") + (usedBy.length > 12 ? ` +${usedBy.length - 12} more` : "") : "No firewall rules reference this zone"}
                          </TooltipContent>
                        </Tooltip>
                      </TooltipProvider>
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={`Edit zone ${z.name}`} onClick={() => openEdit(z)}>
                      <Icons.Pencil className="h-3.5 w-3.5" />
                    </Button>
                    {!protectedZone && (
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8 text-rose-600 hover:text-rose-700 dark:text-rose-400"
                        aria-label={`Delete zone ${z.name}`}
                        onClick={() => setDeleting(z)}
                      >
                        <Icons.Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    )}
                  </div>
                </CardHeader>
                <CardContent className="flex flex-1 flex-col gap-2 p-0">
                  <div className="flex flex-wrap gap-1">
                    {z.interfaceNames.length === 0 ? (
                      <span className="text-xs text-zinc-400">no interfaces</span>
                    ) : (
                      z.interfaceNames.map((n) => (
                        <Badge key={n} variant="outline" className="border-zinc-300 font-mono text-[11px] font-normal text-zinc-600 dark:border-zinc-700 dark:text-zinc-300">
                          {n}
                        </Badge>
                      ))
                    )}
                  </div>
                  <p className="mt-auto text-xs text-zinc-500">{z.description ?? ZONE_TYPE_HINTS[z.type]}</p>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {editorOpen && (
        <ZoneEditor
          open={editorOpen}
          onOpenChange={setEditorOpen}
          editing={editing}
          fallbackIfaces={knownIfaces}
          onSaved={() => {
            void queryClient.invalidateQueries({ queryKey: ZONES_KEY });
            void queryClient.invalidateQueries({ queryKey: IFACES_KEY });
          }}
        />
      )}

      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title="Delete zone?"
        description={`Delete zone '${deleting?.name ?? ""}'? Deletion is rejected while firewall rules (or NAT rules on its interfaces) still reference it; member interfaces are detached (zoneId cleared).`}
        loading={deleteMut.isPending}
        onConfirm={() => deleting && deleteMut.mutate(deleting.id)}
      />

      <ConflictDialog
        open={conflict.open}
        onOpenChange={(open) => setConflict((c) => ({ ...c, open }))}
        title={conflict.title}
        message={conflict.message}
        error={conflict.error}
      />
    </div>
  );
}

function ZoneEditor(props: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editing: Zone | null;
  fallbackIfaces: string[];
  onSaved: () => void;
}) {
  const editing = props.editing;
  const locked = editing != null && isProtectedZone(editing.name);

  const ifacesQuery = useQuery({ queryKey: IFACES_KEY, queryFn: api.listInterfaceNames, staleTime: 10_000 });
  const catalog = useMemo(() => ifacesQuery.data?.data ?? [], [ifacesQuery.data]);

  const [name, setName] = useState(editing?.name ?? "");
  const [type, setType] = useState<ZoneType>(editing?.type ?? "L3");
  const [selected, setSelected] = useState<string[]>(editing?.interfaceNames ?? []);
  const [extraRaw, setExtraRaw] = useState("");
  const [description, setDescription] = useState(editing?.description ?? "");
  const [error, setError] = useState<string | null>(null);

  // names in the catalog are checkbox-pickable; anything else typed into the
  // extra field is appended (virtual ifaces not yet modeled stay possible)
  const extraNames = useMemo(
    () =>
      extraRaw
        .split(",")
        .map((s) => s.trim())
        .filter((n) => n && !catalog.some((c) => c.name === n) && !selected.includes(n)),
    [extraRaw, catalog, selected],
  );

  const toggle = (ifaceName: string, on: boolean) => {
    setSelected((prev) => (on ? [...new Set([...prev, ifaceName])] : prev.filter((n) => n !== ifaceName)));
  };

  const mut = useMutation({
    mutationFn: () => {
      const interfaceNames = [...selected, ...extraNames];
      const body = { name: name.trim(), type, interfaceNames, description: description.trim() || null };
      return editing ? api.updateZone(editing.id, body) : api.createZone(body);
    },
    onSuccess: () => {
      toastOk(editing ? "Zone updated" : "Zone created", name.trim());
      props.onOpenChange(false);
      props.onSaved();
    },
    onError: (err) => toastErr(err, editing ? "Update failed" : "Create failed"),
  });

  const submit = () => {
    if (!name.trim()) return setError("Name is required");
    setError(null);
    mut.mutate();
  };

  const inOtherZone = (zoneId: number | null) =>
    zoneId != null && (!editing || zoneId !== editing.id)
      ? catalog.find((c) => c.zoneId === zoneId)
      : null;

  return (
    <Dialog open onOpenChange={props.onOpenChange}>
      <DialogContent className="w-[calc(100vw-1rem)] max-w-lg">
        <DialogHeader>
          <DialogTitle>{editing ? `Edit zone — ${editing.name}` : "Add zone"}</DialogTitle>
          <DialogDescription>
            {locked
              ? "WAN/LAN are protected: name and type are locked, interface membership and description remain editable."
              : "Assign interfaces to the zone — membership syncs NetworkInterface.zoneId on both sides; an interface moving here leaves its previous zone automatically."}
          </DialogDescription>
        </DialogHeader>
        <div className="max-h-[60vh] space-y-3 overflow-y-auto pr-1">
          <div>
            <Label htmlFor="zone-name" className="text-xs font-medium">
              Name
            </Label>
            <Input
              id="zone-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              disabled={locked}
              placeholder="DMZ"
              className={cn("mt-1.5", locked && "cursor-not-allowed opacity-70")}
            />
          </div>
          <div>
            <FieldLabel hint={locked ? "locked for protected zones" : undefined}>Type</FieldLabel>
            <RadioGroup
              value={type}
              onValueChange={(v) => setType(v as ZoneType)}
              disabled={locked}
              className="flex gap-4"
            >
              {ZONE_TYPES.map((t) => (
                <TooltipProvider key={t} delayDuration={100}>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Label key={t} className={cn("flex items-center gap-2 text-sm", !locked && "cursor-pointer")}>
                        <RadioGroupItem value={t} /> {t}
                      </Label>
                    </TooltipTrigger>
                    <TooltipContent className="text-xs">{ZONE_TYPE_HINTS[t]}</TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              ))}
            </RadioGroup>
          </div>
          <div>
            <Label className="text-xs font-medium">
              Interfaces <span className="text-zinc-400">({selected.length} selected)</span>
            </Label>
            {ifacesQuery.isLoading ? (
              <div className="mt-2 space-y-2">
                {Array.from({ length: 3 }).map((_, i) => (
                  <Skeleton key={i} className="h-8 rounded-md" />
                ))}
              </div>
            ) : catalog.length === 0 ? (
              <p className="mt-2 text-xs text-zinc-500">
                No interfaces modeled yet — type names below (validated against the interface catalog on save).
              </p>
            ) : (
              <div className="mt-2 max-h-48 space-y-1 overflow-y-auto rounded-lg border border-zinc-200 p-2 dark:border-zinc-800">
                {catalog.map((i) => {
                  const other = inOtherZone(i.zoneId);
                  return (
                    <Label
                      key={i.id}
                      className={cn(
                        "flex cursor-pointer items-center justify-between gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-zinc-100 dark:hover:bg-zinc-900",
                        locked && "cursor-not-allowed opacity-70",
                      )}
                    >
                      <span className="flex items-center gap-2">
                        <Checkbox
                          checked={selected.includes(i.name)}
                          onCheckedChange={(v) => !locked && toggle(i.name, v === true)}
                          disabled={locked}
                          aria-label={`Assign ${i.name} to zone`}
                        />
                        <span className="font-mono text-xs">{i.name}</span>
                        {!i.enabled && (
                          <Badge variant="outline" className="border-amber-500/40 text-[10px] text-amber-600">
                            down
                          </Badge>
                        )}
                      </span>
                      {other && (
                        <span className="text-[10px] text-zinc-400">in {other.zoneName ?? "another zone"} — moves here</span>
                      )}
                    </Label>
                  );
                })}
              </div>
            )}
            <Input
              value={extraRaw}
              onChange={(e) => setExtraRaw(e.target.value)}
              placeholder="extra names, comma-separated (optional)"
              disabled={locked}
              className="mt-2 font-mono text-xs"
            />
            {extraNames.length > 0 && (
              <div className="mt-1 flex flex-wrap gap-1">
                {extraNames.map((n) => (
                  <Badge key={n} variant="outline" className="border-dashed border-zinc-400 font-mono text-[11px] text-zinc-500">
                    {n}
                  </Badge>
                ))}
              </div>
            )}
          </div>
          <div>
            <Label htmlFor="zone-desc" className="text-xs font-medium">
              Description <span className="text-zinc-400">(optional)</span>
            </Label>
            <Textarea id="zone-desc" value={description} onChange={(e) => setDescription(e.target.value)} rows={2} className="mt-1.5" />
          </div>
          {error && <p className="text-xs text-rose-600 dark:text-rose-400">{error}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => props.onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={mut.isPending} className="bg-amber-700 text-white hover:bg-amber-800">
            {mut.isPending ? "Saving…" : editing ? "Save changes" : "Create zone"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
