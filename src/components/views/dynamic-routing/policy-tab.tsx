"use client";

/**
 * M19 policy objects tab — three sub-cards: prefix lists (repeatable
 * seq/action/prefix/ge/le entry rows), route maps (repeatable match/set rows)
 * and community lists (AS:NN chips). Entries are stored server-side as JSON;
 * the editors post parsed arrays.
 */

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
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
  parseEntries,
  type CommunityListDTO,
  type PrefixListDTO,
  type RouteMapDTO,
} from "./dynamic-routing-api";
import { FamilyBadge, ListTypeBadge } from "./dr-ui";

const PL_KEY = ["dynamic-routing", "prefix-lists"] as const;
const RM_KEY = ["dynamic-routing", "route-maps"] as const;
const CL_KEY = ["dynamic-routing", "community-lists"] as const;

// ── prefix lists ─────────────────────────────────────────────────────────────

interface PlEntryForm {
  seq: string;
  action: "permit" | "deny";
  prefix: string;
  ge: string;
  le: string;
}

interface PlFormState {
  name: string;
  family: "ipv4" | "ipv6";
  entries: PlEntryForm[];
}

const initialPlForm: PlFormState = { name: "", family: "ipv4", entries: [{ seq: "10", action: "permit", prefix: "", ge: "", le: "" }] };

function plFormOf(pl: PrefixListDTO): PlFormState {
  const entries = parseEntries<{ seq: number; action: "permit" | "deny"; prefix: string; ge?: number | null; le?: number | null }>(pl.entries);
  return {
    name: pl.name,
    family: pl.family === "ipv6" ? "ipv6" : "ipv4",
    entries: entries.map((e) => ({
      seq: String(e.seq),
      action: e.action === "deny" ? "deny" : "permit",
      prefix: e.prefix,
      ge: e.ge === null || e.ge === undefined ? "" : String(e.ge),
      le: e.le === null || e.le === undefined ? "" : String(e.le),
    })),
  };
}

function plBodyOf(f: PlFormState): Record<string, unknown> {
  return {
    name: f.name.trim(),
    family: f.family,
    entries: f.entries.map((e) => ({
      seq: Number(e.seq),
      action: e.action,
      prefix: e.prefix.trim(),
      ge: e.ge.trim() === "" ? null : Number(e.ge),
      le: e.le.trim() === "" ? null : Number(e.le),
    })),
  };
}

// ── route maps ───────────────────────────────────────────────────────────────

interface RmEntryForm {
  seq: string;
  action: "permit" | "deny";
  matchPrefixListId: string;
  setLocalPref: string;
  setMetric: string;
  setCommunity: string;
}

interface RmFormState {
  name: string;
  entries: RmEntryForm[];
}

const initialRmForm: RmFormState = {
  name: "",
  entries: [{ seq: "10", action: "permit", matchPrefixListId: "", setLocalPref: "", setMetric: "", setCommunity: "" }],
};

function rmFormOf(rm: RouteMapDTO): RmFormState {
  const entries = parseEntries<{
    seq: number;
    action: "permit" | "deny";
    matchPrefixListId?: number | null;
    setLocalPref?: number | null;
    setMetric?: number | null;
    setCommunity?: string | null;
  }>(rm.entries);
  return {
    name: rm.name,
    entries: entries.map((e) => ({
      seq: String(e.seq),
      action: e.action === "deny" ? "deny" : "permit",
      matchPrefixListId: e.matchPrefixListId == null ? "" : String(e.matchPrefixListId),
      setLocalPref: e.setLocalPref == null ? "" : String(e.setLocalPref),
      setMetric: e.setMetric == null ? "" : String(e.setMetric),
      setCommunity: e.setCommunity ?? "",
    })),
  };
}

function rmBodyOf(f: RmFormState): Record<string, unknown> {
  return {
    name: f.name.trim(),
    entries: f.entries.map((e) => ({
      seq: Number(e.seq),
      action: e.action,
      matchPrefixListId: e.matchPrefixListId === "" ? null : Number(e.matchPrefixListId),
      setLocalPref: e.setLocalPref.trim() === "" ? null : Number(e.setLocalPref),
      setMetric: e.setMetric.trim() === "" ? null : Number(e.setMetric),
      setCommunity: e.setCommunity.trim() === "" ? null : e.setCommunity.trim(),
    })),
  };
}

// ── community lists ──────────────────────────────────────────────────────────

interface ClFormState {
  name: string;
  type: "standard" | "expanded";
  entries: string[];
}

const initialClForm: ClFormState = { name: "", type: "standard", entries: [] };

function clFormOf(cl: CommunityListDTO): ClFormState {
  return { name: cl.name, type: cl.type === "expanded" ? "expanded" : "standard", entries: parseEntries<string>(cl.entries) };
}

function clBodyOf(f: ClFormState): Record<string, unknown> {
  return { name: f.name.trim(), type: f.type, entries: f.entries.map((e) => e.trim()).filter((e) => e.length > 0) };
}

// ── component ────────────────────────────────────────────────────────────────

type PlEditor = { mode: "create" } | { mode: "edit"; list: PrefixListDTO } | null;
type RmEditor = { mode: "create" } | { mode: "edit"; map: RouteMapDTO } | null;
type ClEditor = { mode: "create" } | { mode: "edit"; list: CommunityListDTO } | null;

export function PolicyObjectsTab() {
  const qc = useQueryClient();
  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ["dynamic-routing"] });
  };

  const plQ = useQuery({ queryKey: PL_KEY, queryFn: drApi.listPrefixLists });
  const rmQ = useQuery({ queryKey: RM_KEY, queryFn: drApi.listRouteMaps });
  const clQ = useQuery({ queryKey: CL_KEY, queryFn: drApi.listCommunityLists });

  // ── editor states ────────────────────────────────────────────────────────
  const [plEditor, setPlEditor] = useState<PlEditor>(null);
  const [plForm, setPlForm] = useState<PlFormState>(initialPlForm);
  const [plErrors, setPlErrors] = useState<Record<string, string[]>>({});

  const [rmEditor, setRmEditor] = useState<RmEditor>(null);
  const [rmForm, setRmForm] = useState<RmFormState>(initialRmForm);
  const [rmErrors, setRmErrors] = useState<Record<string, string[]>>({});

  const [clEditor, setClEditor] = useState<ClEditor>(null);
  const [clForm, setClForm] = useState<ClFormState>(initialClForm);
  const [clEntryInput, setClEntryInput] = useState("");
  const [clErrors, setClErrors] = useState<Record<string, string[]>>({});

  const [pendingDelete, setPendingDelete] = useState<
    { kind: "pl" | "rm" | "cl"; id: number; name: string } | null
  >(null);

  // ── mutations ────────────────────────────────────────────────────────────
  const savePl = useMutation({
    mutationFn: (vars: { mode: "create" | "edit"; id?: number }) =>
      vars.mode === "create" ? drApi.createPrefixList(plBodyOf(plForm)) : drApi.updatePrefixList(vars.id ?? 0, plBodyOf(plForm)),
    onSuccess: (pl, vars) => {
      invalidate();
      setPlEditor(null);
      toastOk(vars.mode === "create" ? "Prefix list created" : "Prefix list updated", `${pl.name} · ${pl.entryCount} entries`);
    },
    onError: (err) => setPlErrors(fieldErrorsOf(err)),
  });

  const saveRm = useMutation({
    mutationFn: (vars: { mode: "create" | "edit"; id?: number }) =>
      vars.mode === "create" ? drApi.createRouteMap(rmBodyOf(rmForm)) : drApi.updateRouteMap(vars.id ?? 0, rmBodyOf(rmForm)),
    onSuccess: (rm, vars) => {
      invalidate();
      setRmEditor(null);
      toastOk(vars.mode === "create" ? "Route map created" : "Route map updated", `${rm.name} · ${rm.entryCount} entries`);
    },
    onError: (err) => setRmErrors(fieldErrorsOf(err)),
  });

  const saveCl = useMutation({
    mutationFn: (vars: { mode: "create" | "edit"; id?: number }) =>
      vars.mode === "create" ? drApi.createCommunityList(clBodyOf(clForm)) : drApi.updateCommunityList(vars.id ?? 0, clBodyOf(clForm)),
    onSuccess: (cl, vars) => {
      invalidate();
      setClEditor(null);
      toastOk(vars.mode === "create" ? "Community list created" : "Community list updated", `${cl.name} · ${cl.entryCount} entries`);
    },
    onError: (err) => setClErrors(fieldErrorsOf(err)),
  });

  const deleteMut = useMutation({
    mutationFn: (target: { kind: "pl" | "rm" | "cl"; id: number }) => {
      if (target.kind === "pl") return drApi.deletePrefixList(target.id);
      if (target.kind === "rm") return drApi.deleteRouteMap(target.id);
      return drApi.deleteCommunityList(target.id);
    },
    onSuccess: () => {
      invalidate();
      setPendingDelete(null);
      toastOk("Deleted", "Policy object removed");
    },
    onError: (err) => toastErr(err, "Delete failed"),
  });

  const plLists = plQ.data ?? [];
  const rmMaps = rmQ.data ?? [];
  const clLists = clQ.data ?? [];
  const deleteTargetName =
    pendingDelete === null ? "" : pendingDelete.kind === "pl" ? "prefix list" : pendingDelete.kind === "rm" ? "route map" : "community list";

  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
      {/* ── prefix lists ─────────────────────────────────────────────────── */}
      <Card className="flex flex-col">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center justify-between gap-2 text-base">
            <span className="flex items-center gap-2">
              <Icons.ListFilter className="h-4 w-4 text-blue-600 dark:text-blue-400" />
              Prefix lists
            </span>
            <Button
              size="sm"
              variant="outline"
              className="h-8 gap-1"
              onClick={() => {
                setPlForm(initialPlForm);
                setPlErrors({});
                setPlEditor({ mode: "create" });
              }}
            >
              <Icons.Plus className="h-3.5 w-3.5" />
              Add
            </Button>
          </CardTitle>
          <CardDescription>Match filters for BGP in/out policy.</CardDescription>
        </CardHeader>
        <CardContent className="flex-1">
          {plQ.isLoading ? (
            <TableSkeleton rows={2} cols={4} />
          ) : plQ.isError ? (
            <QueryError error={plQ.error} onRetry={() => void plQ.refetch()} />
          ) : plLists.length === 0 ? (
            <EmptyBlock icon={<Icons.ListFilter className="h-5 w-5" />} title="No prefix lists" />
          ) : (
            <div className="max-h-96 overflow-y-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Family</TableHead>
                    <TableHead>Entries</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {plLists.map((pl) => (
                    <TableRow key={pl.id}>
                      <TableCell className="font-medium">{pl.name}</TableCell>
                      <TableCell>
                        <FamilyBadge family={pl.family} />
                      </TableCell>
                      <TableCell className="font-mono text-xs">{pl.entryCount}</TableCell>
                      <TableCell className="text-right">
                        <div className="inline-flex items-center gap-1">
                          <Button
                            size="icon"
                            variant="ghost"
                            className="h-8 w-8"
                            aria-label={`Edit ${pl.name}`}
                            onClick={() => {
                              setPlForm(plFormOf(pl));
                              setPlErrors({});
                              setPlEditor({ mode: "edit", list: pl });
                            }}
                          >
                            <Icons.Pencil className="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            className="h-8 w-8 text-rose-600 hover:bg-rose-500/10 dark:text-rose-400"
                            aria-label={`Delete ${pl.name}`}
                            onClick={() => setPendingDelete({ kind: "pl", id: pl.id, name: pl.name })}
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

      {/* ── route maps ───────────────────────────────────────────────────── */}
      <Card className="flex flex-col">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center justify-between gap-2 text-base">
            <span className="flex items-center gap-2">
              <Icons.GitBranch className="h-4 w-4 text-blue-600 dark:text-blue-400" />
              Route maps
            </span>
            <Button
              size="sm"
              variant="outline"
              className="h-8 gap-1"
              onClick={() => {
                setRmForm(initialRmForm);
                setRmErrors({});
                setRmEditor({ mode: "create" });
              }}
            >
              <Icons.Plus className="h-3.5 w-3.5" />
              Add
            </Button>
          </CardTitle>
          <CardDescription>Match + set clauses applied to BGP routes.</CardDescription>
        </CardHeader>
        <CardContent className="flex-1">
          {rmQ.isLoading ? (
            <TableSkeleton rows={2} cols={3} />
          ) : rmQ.isError ? (
            <QueryError error={rmQ.error} onRetry={() => void rmQ.refetch()} />
          ) : rmMaps.length === 0 ? (
            <EmptyBlock icon={<Icons.GitBranch className="h-5 w-5" />} title="No route maps" />
          ) : (
            <div className="max-h-96 overflow-y-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Entries</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rmMaps.map((rm) => (
                    <TableRow key={rm.id}>
                      <TableCell className="font-medium">{rm.name}</TableCell>
                      <TableCell className="font-mono text-xs">{rm.entryCount}</TableCell>
                      <TableCell className="text-right">
                        <div className="inline-flex items-center gap-1">
                          <Button
                            size="icon"
                            variant="ghost"
                            className="h-8 w-8"
                            aria-label={`Edit ${rm.name}`}
                            onClick={() => {
                              setRmForm(rmFormOf(rm));
                              setRmErrors({});
                              setRmEditor({ mode: "edit", map: rm });
                            }}
                          >
                            <Icons.Pencil className="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            className="h-8 w-8 text-rose-600 hover:bg-rose-500/10 dark:text-rose-400"
                            aria-label={`Delete ${rm.name}`}
                            onClick={() => setPendingDelete({ kind: "rm", id: rm.id, name: rm.name })}
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

      {/* ── community lists ──────────────────────────────────────────────── */}
      <Card className="flex flex-col">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center justify-between gap-2 text-base">
            <span className="flex items-center gap-2">
              <Icons.Tags className="h-4 w-4 text-blue-600 dark:text-blue-400" />
              Community lists
            </span>
            <Button
              size="sm"
              variant="outline"
              className="h-8 gap-1"
              onClick={() => {
                setClForm(initialClForm);
                setClEntryInput("");
                setClErrors({});
                setClEditor({ mode: "create" });
              }}
            >
              <Icons.Plus className="h-3.5 w-3.5" />
              Add
            </Button>
          </CardTitle>
          <CardDescription>Standard AS:NN tags or expanded regex matchers.</CardDescription>
        </CardHeader>
        <CardContent className="flex-1">
          {clQ.isLoading ? (
            <TableSkeleton rows={2} cols={4} />
          ) : clQ.isError ? (
            <QueryError error={clQ.error} onRetry={() => void clQ.refetch()} />
          ) : clLists.length === 0 ? (
            <EmptyBlock icon={<Icons.Tags className="h-5 w-5" />} title="No community lists" />
          ) : (
            <div className="max-h-96 space-y-4 overflow-y-auto">
              {clLists.map((cl) => (
                <div key={cl.id} className="rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
                  <div className="mb-2 flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{cl.name}</span>
                      <ListTypeBadge type={cl.type} />
                      <span className="text-[11px] text-zinc-400">{cl.entryCount} entries</span>
                    </div>
                    <div className="inline-flex items-center gap-1">
                      <Button
                        size="icon"
                        variant="ghost"
                        className="h-8 w-8"
                        aria-label={`Edit ${cl.name}`}
                        onClick={() => {
                          setClForm(clFormOf(cl));
                          setClEntryInput("");
                          setClErrors({});
                          setClEditor({ mode: "edit", list: cl });
                        }}
                      >
                        <Icons.Pencil className="h-3.5 w-3.5" />
                      </Button>
                      <Button
                        size="icon"
                        variant="ghost"
                        className="h-8 w-8 text-rose-600 hover:bg-rose-500/10 dark:text-rose-400"
                        aria-label={`Delete ${cl.name}`}
                        onClick={() => setPendingDelete({ kind: "cl", id: cl.id, name: cl.name })}
                      >
                        <Icons.Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {parseEntries<string>(cl.entries).map((e, idx) => (
                      <Badge key={`${cl.id}-e-${idx}`} variant="outline" className="font-mono text-[10px]">
                        {e}
                      </Badge>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── prefix list dialog ───────────────────────────────────────────── */}
      <Dialog
        open={plEditor !== null}
        onOpenChange={(open) => {
          if (!open) setPlEditor(null);
        }}
      >
        <DialogContent className="max-h-[90vh] max-w-2xl overflow-y-auto">
          <DialogHeader>
            <DialogTitle>
              {plEditor?.mode === "edit" ? `Edit prefix list — ${plEditor.list.name}` : "Add prefix list"}
            </DialogTitle>
            <DialogDescription>Prefixes must match the list family; seq values must be unique.</DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <FieldLabel>Name</FieldLabel>
                <Input value={plForm.name} onChange={(e) => setPlForm((f) => ({ ...f, name: e.target.value }))} placeholder="UPSTREAM-IN" />
                {plErrors.entries ? <p className="mt-1 text-[11px] font-medium text-rose-600">{plErrors.entries[0]}</p> : null}
              </div>
              <div>
                <FieldLabel>Family</FieldLabel>
                <Select
                  value={plForm.family}
                  onValueChange={(v) => setPlForm((f) => ({ ...f, family: v === "ipv6" ? "ipv6" : "ipv4" }))}
                >
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="ipv4">ipv4</SelectItem>
                    <SelectItem value="ipv6">ipv6</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="space-y-2">
              <FieldLabel hint="ge/le optional">Entries</FieldLabel>
              {plForm.entries.map((entry, idx) => (
                <div key={idx} className="grid grid-cols-11 items-start gap-2">
                  <Input
                    className="col-span-2"
                    value={entry.seq}
                    inputMode="numeric"
                    placeholder="seq"
                    aria-label="sequence"
                    onChange={(e) =>
                      setPlForm((f) => ({
                        ...f,
                        entries: f.entries.map((x, i) => (i === idx ? { ...x, seq: e.target.value } : x)),
                      }))
                    }
                  />
                  <div className="col-span-2">
                    <Select
                      value={entry.action}
                      onValueChange={(v) =>
                        setPlForm((f) => ({
                          ...f,
                          entries: f.entries.map((x, i) => (i === idx ? { ...x, action: v === "deny" ? "deny" : "permit" } : x)),
                        }))
                      }
                    >
                      <SelectTrigger className="w-full">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="permit">permit</SelectItem>
                        <SelectItem value="deny">deny</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <Input
                    className="col-span-3 font-mono"
                    value={entry.prefix}
                    placeholder={plForm.family === "ipv4" ? "10.0.0.0/8" : "2001:db8::/32"}
                    aria-label="prefix"
                    onChange={(e) =>
                      setPlForm((f) => ({
                        ...f,
                        entries: f.entries.map((x, i) => (i === idx ? { ...x, prefix: e.target.value } : x)),
                      }))
                    }
                  />
                  <Input
                    className="col-span-2"
                    value={entry.ge}
                    inputMode="numeric"
                    placeholder="ge"
                    aria-label="greater-or-equal"
                    onChange={(e) =>
                      setPlForm((f) => ({
                        ...f,
                        entries: f.entries.map((x, i) => (i === idx ? { ...x, ge: e.target.value } : x)),
                      }))
                    }
                  />
                  <Input
                    className="col-span-2"
                    value={entry.le}
                    inputMode="numeric"
                    placeholder="le"
                    aria-label="less-or-equal"
                    onChange={(e) =>
                      setPlForm((f) => ({
                        ...f,
                        entries: f.entries.map((x, i) => (i === idx ? { ...x, le: e.target.value } : x)),
                      }))
                    }
                  />
                  <Button
                    type="button"
                    size="icon"
                    variant="ghost"
                    className="col-span-11 h-8 w-8 justify-self-end text-rose-600 sm:col-span-1"
                    aria-label="Remove entry"
                    disabled={plForm.entries.length === 1}
                    onClick={() =>
                      setPlForm((f) => ({ ...f, entries: f.entries.filter((_, i) => i !== idx) }))
                    }
                  >
                    <Icons.X className="h-3.5 w-3.5" />
                  </Button>
                </div>
              ))}
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="gap-1"
                onClick={() =>
                  setPlForm((f) => ({
                    ...f,
                    entries: [...f.entries, { seq: String((f.entries.length + 1) * 10), action: "permit", prefix: "", ge: "", le: "" }],
                  }))
                }
              >
                <Icons.Plus className="h-3.5 w-3.5" />
                Add entry
              </Button>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setPlEditor(null)}>
              Cancel
            </Button>
            <Button
              className="bg-blue-600 text-white hover:bg-blue-700"
              disabled={savePl.isPending}
              onClick={() =>
                plEditor && savePl.mutate(plEditor.mode === "edit" ? { mode: "edit", id: plEditor.list.id } : { mode: "create" })
              }
            >
              {savePl.isPending ? "Saving…" : plEditor?.mode === "edit" ? "Save changes" : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── route map dialog ─────────────────────────────────────────────── */}
      <Dialog
        open={rmEditor !== null}
        onOpenChange={(open) => {
          if (!open) setRmEditor(null);
        }}
      >
        <DialogContent className="max-h-[90vh] max-w-2xl overflow-y-auto">
          <DialogHeader>
            <DialogTitle>
              {rmEditor?.mode === "edit" ? `Edit route map — ${rmEditor.map.name}` : "Add route map"}
            </DialogTitle>
            <DialogDescription>Each entry needs a match clause (prefix list or community).</DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div>
              <FieldLabel>Name</FieldLabel>
              <Input value={rmForm.name} onChange={(e) => setRmForm((f) => ({ ...f, name: e.target.value }))} placeholder="UPSTREAM-PREF" />
              {rmErrors.entries ? <p className="mt-1 text-[11px] font-medium text-rose-600">{rmErrors.entries[0]}</p> : null}
            </div>

            <div className="space-y-2">
              <FieldLabel hint="match + optional set clauses">Entries</FieldLabel>
              {rmForm.entries.map((entry, idx) => (
                <div key={idx} className="grid grid-cols-11 items-start gap-2">
                  <Input
                    className="col-span-2"
                    value={entry.seq}
                    inputMode="numeric"
                    placeholder="seq"
                    aria-label="sequence"
                    onChange={(e) =>
                      setRmForm((f) => ({
                        ...f,
                        entries: f.entries.map((x, i) => (i === idx ? { ...x, seq: e.target.value } : x)),
                      }))
                    }
                  />
                  <div className="col-span-2">
                    <Select
                      value={entry.action}
                      onValueChange={(v) =>
                        setRmForm((f) => ({
                          ...f,
                          entries: f.entries.map((x, i) => (i === idx ? { ...x, action: v === "deny" ? "deny" : "permit" } : x)),
                        }))
                      }
                    >
                      <SelectTrigger className="w-full">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="permit">permit</SelectItem>
                        <SelectItem value="deny">deny</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="col-span-3">
                    <Select
                      value={entry.matchPrefixListId || "none"}
                      onValueChange={(v) =>
                        setRmForm((f) => ({
                          ...f,
                          entries: f.entries.map((x, i) => (i === idx ? { ...x, matchPrefixListId: v === "none" ? "" : v } : x)),
                        }))
                      }
                    >
                      <SelectTrigger className="w-full">
                        <SelectValue placeholder="match prefix-list" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="none">no match</SelectItem>
                        {plLists.map((pl) => (
                          <SelectItem key={pl.id} value={String(pl.id)}>
                            {pl.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <Input
                    className="col-span-2"
                    value={entry.setLocalPref}
                    inputMode="numeric"
                    placeholder="localPref"
                    aria-label="set local preference"
                    onChange={(e) =>
                      setRmForm((f) => ({
                        ...f,
                        entries: f.entries.map((x, i) => (i === idx ? { ...x, setLocalPref: e.target.value } : x)),
                      }))
                    }
                  />
                  <Input
                    className="col-span-2 font-mono"
                    value={entry.setCommunity}
                    placeholder="AS:NN"
                    aria-label="set community"
                    onChange={(e) =>
                      setRmForm((f) => ({
                        ...f,
                        entries: f.entries.map((x, i) => (i === idx ? { ...x, setCommunity: e.target.value } : x)),
                      }))
                    }
                  />
                  <Button
                    type="button"
                    size="icon"
                    variant="ghost"
                    className="col-span-11 h-8 w-8 justify-self-end text-rose-600 sm:col-span-1"
                    aria-label="Remove entry"
                    disabled={rmForm.entries.length === 1}
                    onClick={() => setRmForm((f) => ({ ...f, entries: f.entries.filter((_, i) => i !== idx) }))}
                  >
                    <Icons.X className="h-3.5 w-3.5" />
                  </Button>
                </div>
              ))}
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="gap-1"
                onClick={() =>
                  setRmForm((f) => ({
                    ...f,
                    entries: [
                      ...f.entries,
                      { seq: String((f.entries.length + 1) * 10), action: "permit", matchPrefixListId: "", setLocalPref: "", setMetric: "", setCommunity: "" },
                    ],
                  }))
                }
              >
                <Icons.Plus className="h-3.5 w-3.5" />
                Add entry
              </Button>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setRmEditor(null)}>
              Cancel
            </Button>
            <Button
              className="bg-blue-600 text-white hover:bg-blue-700"
              disabled={saveRm.isPending}
              onClick={() =>
                rmEditor && saveRm.mutate(rmEditor.mode === "edit" ? { mode: "edit", id: rmEditor.map.id } : { mode: "create" })
              }
            >
              {saveRm.isPending ? "Saving…" : rmEditor?.mode === "edit" ? "Save changes" : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── community list dialog ────────────────────────────────────────── */}
      <Dialog
        open={clEditor !== null}
        onOpenChange={(open) => {
          if (!open) setClEditor(null);
        }}
      >
        <DialogContent className="max-h-[90vh] max-w-lg overflow-y-auto">
          <DialogHeader>
            <DialogTitle>
              {clEditor?.mode === "edit" ? `Edit community list — ${clEditor.list.name}` : "Add community list"}
            </DialogTitle>
            <DialogDescription>Standard entries are "AS:NN" tags (e.g. 65000:100).</DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <FieldLabel>Name</FieldLabel>
                <Input value={clForm.name} onChange={(e) => setClForm((f) => ({ ...f, name: e.target.value }))} placeholder="TRANSIT-COMM" />
                {clErrors.entries ? <p className="mt-1 text-[11px] font-medium text-rose-600">{clErrors.entries[0]}</p> : null}
              </div>
              <div>
                <FieldLabel>Type</FieldLabel>
                <Select
                  value={clForm.type}
                  onValueChange={(v) => setClForm((f) => ({ ...f, type: v === "expanded" ? "expanded" : "standard" }))}
                >
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="standard">standard</SelectItem>
                    <SelectItem value="expanded">expanded</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div>
              <FieldLabel hint="press Enter to add">Entries</FieldLabel>
              <Input
                value={clEntryInput}
                onChange={(e) => setClEntryInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    const v = clEntryInput.trim();
                    if (v.length === 0) return;
                    setClForm((f) => ({ ...f, entries: f.entries.includes(v) ? f.entries : [...f.entries, v] }));
                    setClEntryInput("");
                  }
                }}
                placeholder={clForm.type === "standard" ? "65000:100" : "^65000_"}
                className="font-mono"
              />
              <div className="mt-2 flex flex-wrap gap-1.5">
                {clForm.entries.map((e) => (
                  <Badge key={e} variant="outline" className="gap-1 font-mono text-[10px]">
                    {e}
                    <button
                      type="button"
                      aria-label={`Remove ${e}`}
                      className="rounded-sm p-0.5 hover:bg-zinc-200 dark:hover:bg-zinc-700"
                      onClick={() => setClForm((f) => ({ ...f, entries: f.entries.filter((x) => x !== e) }))}
                    >
                      <Icons.X className="h-3 w-3" />
                    </button>
                  </Badge>
                ))}
                {clForm.entries.length === 0 ? <span className="text-xs text-zinc-400">no entries yet</span> : null}
              </div>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setClEditor(null)}>
              Cancel
            </Button>
            <Button
              className="bg-blue-600 text-white hover:bg-blue-700"
              disabled={saveCl.isPending}
              onClick={() =>
                clEditor && saveCl.mutate(clEditor.mode === "edit" ? { mode: "edit", id: clEditor.list.id } : { mode: "create" })
              }
            >
              {saveCl.isPending ? "Saving…" : clEditor?.mode === "edit" ? "Save changes" : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── delete confirm ───────────────────────────────────────────────── */}
      <ConfirmDialog
        open={pendingDelete !== null}
        onOpenChange={(open) => {
          if (!open) setPendingDelete(null);
        }}
        title={`Delete ${deleteTargetName} ${pendingDelete?.name ?? ""}?`}
        description="Objects still referenced by BGP neighbors cannot be deleted."
        loading={deleteMut.isPending}
        onConfirm={() => pendingDelete && deleteMut.mutate({ kind: pendingDelete.kind, id: pendingDelete.id })}
      />
    </div>
  );
}
