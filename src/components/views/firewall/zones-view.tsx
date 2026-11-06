"use client";

/**
 * #/firewall/zones — zone cards (M03 §4). WAN/LAN are service-layer protected:
 * Delete is hidden and the editor locks name/type (tooltip explains).
 * GET /api/v1/interfaces is not part of the live API yet, so the interface
 * multiselect degrades to a comma-separated input with suggestions.
 */

import { useMemo, useState } from "react";
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

const ZONE_TYPES: ZoneType[] = ["L3", "L2", "VPN"];

export function ZonesView() {
  useFwConfigInvalidation();
  const queryClient = useQueryClient();

  const zonesQuery = useQuery({ queryKey: ZONES_KEY, queryFn: api.listZones });
  const zones = useMemo(() => zonesQuery.data?.data ?? [], [zonesQuery.data]);

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
        <Button size="sm" onClick={openCreate} className="bg-blue-600 text-white hover:bg-blue-700">
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
                <Button onClick={openCreate} className="bg-blue-600 text-white hover:bg-blue-700">
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
                    <Badge variant="outline" className="mt-1 w-fit border-blue-500/40 bg-blue-500/10 text-[10px] font-semibold text-blue-600 dark:text-blue-400">
                      {z.type}
                    </Badge>
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
                  <p className="mt-auto text-xs text-zinc-500">{z.description ?? "—"}</p>
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
          knownIfaces={knownIfaces}
          onSaved={() => void queryClient.invalidateQueries({ queryKey: ZONES_KEY })}
        />
      )}

      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title="Delete zone?"
        description={`Delete zone '${deleting?.name ?? ""}'? Deletion is rejected while firewall rules still reference it; member interfaces are detached (zoneId cleared).`}
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
  knownIfaces: string[];
  onSaved: () => void;
}) {
  const editing = props.editing;
  const locked = editing != null && isProtectedZone(editing.name);

  const [name, setName] = useState(editing?.name ?? "");
  const [type, setType] = useState<ZoneType>(editing?.type ?? "L3");
  const [ifacesRaw, setIfacesRaw] = useState((editing?.interfaceNames ?? []).join(", "));
  const [description, setDescription] = useState(editing?.description ?? "");
  const [error, setError] = useState<string | null>(null);

  const mut = useMutation({
    mutationFn: () => {
      const interfaceNames = ifacesRaw
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
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

  return (
    <Dialog open onOpenChange={props.onOpenChange}>
      <DialogContent className="w-[calc(100vw-1rem)] max-w-md">
        <DialogHeader>
          <DialogTitle>{editing ? `Edit zone — ${editing.name}` : "Add zone"}</DialogTitle>
          <DialogDescription>
            {locked
              ? "WAN/LAN are protected: name and type are locked, interface membership and description remain editable."
              : "Assign interfaces to the zone — membership syncs NetworkInterface.zoneId on both sides."}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
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
                <Label key={t} className={cn("flex items-center gap-2 text-sm", !locked && "cursor-pointer")}>
                  <RadioGroupItem value={t} /> {t}
                </Label>
              ))}
            </RadioGroup>
          </div>
          <div>
            <Label htmlFor="zone-ifaces" className="text-xs font-medium">
              Interfaces
            </Label>
            <Input
              id="zone-ifaces"
              value={ifacesRaw}
              onChange={(e) => setIfacesRaw(e.target.value)}
              placeholder="lan0, vlan10"
              list="zone-iface-names"
              className="mt-1.5 font-mono text-xs"
            />
            <datalist id="zone-iface-names">
              {props.knownIfaces.map((n) => (
                <option key={n} value={n} />
              ))}
            </datalist>
            <p className="mt-1 text-[11px] text-zinc-400">
              Comma-separated interface names. Known: {props.knownIfaces.length ? props.knownIfaces.join(", ") : "none yet"}
            </p>
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
          <Button onClick={submit} disabled={mut.isPending} className="bg-blue-600 text-white hover:bg-blue-700">
            {mut.isPending ? "Saving…" : editing ? "Save changes" : "Create zone"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
