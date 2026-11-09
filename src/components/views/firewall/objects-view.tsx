"use client";

/**
 * #/firewall/objects — the five M03 object stores in tabs: Address objects,
 * Address groups, Services, Service groups, Schedules. Deletes that hit 409
 * CONFLICT render details.referencedBy rule names with a link to
 * #/firewall/rules (ER_DIAGRAM §3 integrity surfacing).
 */

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { isValidPortList, isValidTimezone, validateAddressValue } from "@/lib/validators/firewall";
import {
  api,
  fmtDateTime,
  referencedByOf,
  type AddressObject,
  type AddressType,
  type NamedWithMembers,
  type NatRule,
  type FwRule,
  type ScheduleObject,
  type ServiceObject,
  type ServiceProtocol,
} from "./fw-api";
import {
  ConfirmDialog,
  ConflictDialog,
  EmptyBlock,
  FieldLabel,
  QueryError,
  TableSkeleton,
  TransferList,
  toastErr,
  toastOk,
  useFwConfigInvalidation,
} from "./fw-ui";

type TabKey = "address" | "address-groups" | "service" | "service-groups" | "schedules";

const ADDRESS_PLACEHOLDER: Record<AddressType, string> = {
  ip: "10.0.0.5",
  range: "10.0.0.5-10.0.0.20",
  subnet: "10.0.0.0/24",
  fqdn: "portal.example.com",
  geo: "DE",
  wildcard: "10.0.0.0 255.0.0.0",
};

const WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

function weekdayInTz(tz: string): number {
  const s = new Intl.DateTimeFormat("en-US", { timeZone: tz, weekday: "short" }).format(new Date());
  return WEEKDAYS.indexOf(s) + 1;
}

function timeInTz(tz: string): string {
  return new Intl.DateTimeFormat("en-GB", { timeZone: tz, hour: "2-digit", minute: "2-digit", hour12: false }).format(new Date());
}

export function scheduleIsActiveNow(s: ScheduleObject): boolean {
  try {
    if (s.type === "always") return true;
    if (s.type === "recurring" && s.recurrence) {
      const day = weekdayInTz(s.timezone || "UTC");
      if (!s.recurrence.days.includes(day)) return false;
      const now = timeInTz(s.timezone || "UTC");
      return now >= s.recurrence.start && now < s.recurrence.end;
    }
    if (s.type === "onetime") {
      if (!s.startsAt || !s.endsAt) return false;
      const now = Date.now();
      return new Date(s.startsAt).getTime() <= now && now < new Date(s.endsAt).getTime();
    }
    return false;
  } catch {
    return false;
  }
}

function scheduleSummary(s: ScheduleObject): string {
  if (s.type === "always") return "always";
  if (s.type === "recurring" && s.recurrence) {
    const days = s.recurrence.days.map((d) => WEEKDAYS[d - 1] ?? String(d)).join(",");
    return `${days} ${s.recurrence.start}–${s.recurrence.end} · ${s.timezone}`;
  }
  if (s.type === "onetime") return `${fmtDateTime(s.startsAt)} → ${fmtDateTime(s.endsAt)}`;
  return s.type;
}

function toLocalInput(iso: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function RefCell({ names }: { names: string[] }) {
  if (names.length === 0) return <span className="text-xs text-zinc-300 dark:text-zinc-700">—</span>;
  return (
    <TooltipProvider delayDuration={150}>
      <Tooltip>
        <TooltipTrigger asChild>
          <Badge variant="outline" className="border-zinc-300 font-normal tabular-nums text-zinc-600 dark:border-zinc-700 dark:text-zinc-300">
            {names.length} rule{names.length === 1 ? "" : "s"}
          </Badge>
        </TooltipTrigger>
        <TooltipContent className="max-w-64 text-xs">
          {names.slice(0, 8).map((n) => (
            <p key={n} className="truncate font-mono">
              {n}
            </p>
          ))}
          {names.length > 8 ? <p className="text-zinc-400">+{names.length - 8} more</p> : null}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

interface ConflictState {
  open: boolean;
  title: string;
  message: string;
  error: unknown;
}

export function ObjectsView() {
  useFwConfigInvalidation();
  const queryClient = useQueryClient();

  const addrQuery = useQuery({ queryKey: ["firewall", "objects", "address"], queryFn: api.listAddressObjects });
  const addrGrpQuery = useQuery({ queryKey: ["firewall", "objects", "address-groups"], queryFn: api.listAddressGroups });
  const svcQuery = useQuery({ queryKey: ["firewall", "objects", "service"], queryFn: api.listServiceObjects });
  const svcGrpQuery = useQuery({ queryKey: ["firewall", "objects", "service-groups"], queryFn: api.listServiceGroups });
  const schedQuery = useQuery({ queryKey: ["firewall", "objects", "schedules"], queryFn: api.listSchedules });
  const fwRulesQuery = useQuery({ queryKey: ["firewall", "rules"], queryFn: api.listRules });
  const natRulesQuery = useQuery({ queryKey: ["nat", "rules"], queryFn: api.listNat });

  const [tab, setTab] = useState<TabKey>("address");
  const [search, setSearch] = useState("");
  const [conflict, setConflict] = useState<ConflictState | null>(null);
  const [deleting, setDeleting] = useState<{ path: string; name: string } | null>(null);
  const [addressDialog, setAddressDialog] = useState<AddressDialogState>({ open: false, editing: null });
  const [groupDialog, setGroupDialog] = useState<GroupDialogState>({ open: false, kind: "address", editing: null });
  const [serviceDialog, setServiceDialog] = useState<ServiceDialogState>({ open: false, editing: null });
  const [scheduleDialog, setScheduleDialog] = useState<ScheduleDialogState>({ open: false, editing: null });

  const invalidateAll = () => {
    void queryClient.invalidateQueries({ queryKey: ["firewall"] });
  };

  const del = useMutation({
    mutationFn: (target: { path: string; name: string }) => api.generic.remove(target.path),
    onSuccess: (_d, target) => {
      toastOk("Deleted", target.name);
      setDeleting(null);
      invalidateAll();
    },
    onError: (err, target) => {
      if (referencedByOf(err).length > 0) {
        setConflict({
          open: true,
          title: `Cannot delete '${target.name}'`,
          message: err instanceof Error ? err.message : "Object is referenced by rules",
          error: err,
        });
        setDeleting(null);
      } else {
        toastErr(err, "Delete failed");
      }
    },
  });

  const fwRules = useMemo(() => fwRulesQuery.data?.data ?? [], [fwRulesQuery.data]);
  const natRules = useMemo(() => natRulesQuery.data?.data ?? [], [natRulesQuery.data]);

  // referenced-by hint (client-side, cheap: we already hold both rule lists)
  const refNames = useMemo(() => {
    const m = new Map<number, string[]>();
    const bump = (id: number, name: string) => {
      const arr = m.get(id) ?? [];
      if (!arr.includes(name)) arr.push(name);
      m.set(id, arr);
    };
    fwRules.forEach((r: FwRule) => {
      r.srcAddrIds.forEach((id) => bump(id, r.name));
      r.dstAddrIds.forEach((id) => bump(id, r.name));
      r.serviceIds.forEach((id) => bump(id, r.name));
      if (r.scheduleId != null) bump(r.scheduleId, r.name);
    });
    natRules.forEach((r: NatRule) => {
      r.srcAddrIds.forEach((id) => bump(id, r.name ?? `#${r.id}`));
      r.dstAddrIds.forEach((id) => bump(id, r.name ?? `#${r.id}`));
      r.serviceIds.forEach((id) => bump(id, r.name ?? `#${r.id}`));
    });
    return m;
  }, [fwRules, natRules]);

  const q = search.trim().toLowerCase();

  const addresses = useMemo(
    () => (addrQuery.data?.data ?? []).filter((a) => (q ? a.name.toLowerCase().includes(q) : true)),
    [addrQuery.data, q],
  );
  const addrGroups = useMemo(
    () => (addrGrpQuery.data?.data ?? []).filter((g) => (q ? g.name.toLowerCase().includes(q) : true)),
    [addrGrpQuery.data, q],
  );
  const services = useMemo(
    () => (svcQuery.data?.data ?? []).filter((s) => (q ? s.name.toLowerCase().includes(q) : true)),
    [svcQuery.data, q],
  );
  const svcGroups = useMemo(
    () => (svcGrpQuery.data?.data ?? []).filter((g) => (q ? g.name.toLowerCase().includes(q) : true)),
    [svcGrpQuery.data, q],
  );
  const schedules = useMemo(
    () => (schedQuery.data?.data ?? []).filter((s) => (q ? s.name.toLowerCase().includes(q) : true)),
    [schedQuery.data, q],
  );

  const rowActions = (path: string, name: string, id: number, onEdit: () => void) => (
    <div className="flex items-center justify-end gap-1">
      <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={`Edit ${name}`} onClick={onEdit}>
        <Icons.Pencil className="h-3.5 w-3.5" />
      </Button>
      <Button
        variant="ghost"
        size="icon"
        className="h-8 w-8 text-rose-600 hover:text-rose-700 dark:text-rose-400"
        aria-label={`Delete ${name}`}
        onClick={() => setDeleting({ path: `${path}/${id}`, name })}
      >
        <Icons.Trash2 className="h-3.5 w-3.5" />
      </Button>
    </div>
  );

  const tableShell = (isEmpty: boolean, emptyNode: React.ReactNode, body: React.ReactNode, headers: string[]) => (
    <>
      {isEmpty ? (
        emptyNode
      ) : (
        <div className="max-h-[60vh] overflow-auto [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-zinc-300 dark:[&::-webkit-scrollbar-thumb]:bg-zinc-700">
          <Table className="min-w-[640px] text-sm">
            <TableHeader>
              <TableRow>
                {headers.map((h) => (
                  <TableHead key={h}>{h}</TableHead>
                ))}
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>{body}</TableBody>
          </Table>
        </div>
      )}
    </>
  );

  return (
    <div className="space-y-4">
      <Tabs value={tab} onValueChange={(v) => setTab(v as TabKey)}>
        <div className="flex flex-wrap items-center gap-2">
          <TabsList>
            <TabsTrigger value="address">Address</TabsTrigger>
            <TabsTrigger value="address-groups">Address Groups</TabsTrigger>
            <TabsTrigger value="service">Services</TabsTrigger>
            <TabsTrigger value="service-groups">Service Groups</TabsTrigger>
            <TabsTrigger value="schedules">Schedules</TabsTrigger>
          </TabsList>
          <div className="relative ml-auto">
            <Icons.Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-400" />
            <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search objects…" className="h-9 w-48 pl-8" aria-label="Search objects" />
          </div>
        </div>

        {/* ── Address objects ── */}
        <TabsContent value="address" className="mt-4">
          <Card className="p-0">
            <CardContent className="p-0">
              <ToolbarRow
                label={`${(addrQuery.data?.data ?? []).length} address objects`}
                addLabel="Add address object"
                onAdd={() => setAddressDialog({ open: true, editing: null })}
              />
              {addrQuery.error ? (
                <div className="p-4">
                  <QueryError error={addrQuery.error} onRetry={() => void addrQuery.refetch()} />
                </div>
              ) : addrQuery.isLoading ? (
                <div className="p-4">
                  <TableSkeleton rows={4} cols={5} />
                </div>
              ) : (addrQuery.data?.data ?? []).length === 0 ? (
                <EmptyBlock icon={<Icons.MapPin className="h-6 w-6" />} title="No address objects" description="Define IPs, subnets, FQDNs or geo codes that rules can reference." />
              ) : (
                tableShell(
                  false,
                  null,
                  addresses.map((a) => (
                    <TableRow key={a.id}>
                      <TableCell className="font-medium">{a.name}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className="border-zinc-300 font-normal text-zinc-600 dark:border-zinc-700 dark:text-zinc-300">
                          {a.type}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{a.value}</TableCell>
                      <TableCell>
                        <RefCell names={refNames.get(a.id) ?? []} />
                      </TableCell>
                      <TableCell className="text-right">
                        {rowActions("/api/v1/address-objects", a.name, a.id, () => setAddressDialog({ open: true, editing: a }))}
                      </TableCell>
                    </TableRow>
                  )),
                  ["Name", "Type", "Value", "Referenced by"],
                )
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Address groups ── */}
        <TabsContent value="address-groups" className="mt-4">
          <Card className="p-0">
            <CardContent className="p-0">
              <ToolbarRow
                label={`${(addrGrpQuery.data?.data ?? []).length} address groups`}
                addLabel="Add address group"
                onAdd={() => setGroupDialog({ open: true, kind: "address", editing: null })}
              />
              {addrGrpQuery.error ? (
                <div className="p-4">
                  <QueryError error={addrGrpQuery.error} onRetry={() => void addrGrpQuery.refetch()} />
                </div>
              ) : addrGrpQuery.isLoading ? (
                <div className="p-4">
                  <TableSkeleton rows={3} cols={4} />
                </div>
              ) : (addrGrpQuery.data?.data ?? []).length === 0 ? (
                <EmptyBlock icon={<Icons.FolderOpen className="h-6 w-6" />} title="No address groups" description="Group address objects so rules can match them with a single id." />
              ) : (
                tableShell(
                  false,
                  null,
                  addrGroups.map((g) => (
                    <TableRow key={g.id}>
                      <TableCell className="font-medium">{g.name}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className="border-zinc-500/30 bg-zinc-500/10 font-normal text-zinc-600 tabular-nums dark:text-zinc-300">
                          {g.memberIds.length} members
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-72 truncate text-xs text-zinc-500">{g.description ?? "—"}</TableCell>
                      <TableCell>
                        <RefCell names={refNames.get(g.id) ?? []} />
                      </TableCell>
                      <TableCell className="text-right">
                        {rowActions("/api/v1/address-groups", g.name, g.id, () => setGroupDialog({ open: true, kind: "address", editing: g }))}
                      </TableCell>
                    </TableRow>
                  )),
                  ["Name", "Members", "Description", "Referenced by"],
                )
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Service objects ── */}
        <TabsContent value="service" className="mt-4">
          <Card className="p-0">
            <CardContent className="p-0">
              <ToolbarRow
                label={`${(svcQuery.data?.data ?? []).length} service objects`}
                addLabel="Add service"
                onAdd={() => setServiceDialog({ open: true, editing: null })}
              />
              {svcQuery.error ? (
                <div className="p-4">
                  <QueryError error={svcQuery.error} onRetry={() => void svcQuery.refetch()} />
                </div>
              ) : svcQuery.isLoading ? (
                <div className="p-4">
                  <TableSkeleton rows={4} cols={5} />
                </div>
              ) : (svcQuery.data?.data ?? []).length === 0 ? (
                <EmptyBlock icon={<Icons.Network className="h-6 w-6" />} title="No service objects" description="Define protocol/port tuples (tcp, udp, icmp, any) that rules can reference." />
              ) : (
                tableShell(
                  false,
                  null,
                  services.map((s) => (
                    <TableRow key={s.id}>
                      <TableCell className="font-medium">{s.name}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className="border-zinc-300 font-normal uppercase text-zinc-600 dark:border-zinc-700 dark:text-zinc-300">
                          {s.protocol}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {s.protocol === "icmp"
                          ? `type ${s.icmpType ?? "*"} / code ${s.icmpCode ?? "*"}`
                          : `${s.srcPort ? `src ${s.srcPort}` : ""}${s.srcPort && s.dstPort ? " · " : ""}${s.dstPort ? `dst ${s.dstPort}` : ""}` || "any"}
                      </TableCell>
                      <TableCell>
                        <RefCell names={refNames.get(s.id) ?? []} />
                      </TableCell>
                      <TableCell className="text-right">
                        {rowActions("/api/v1/service-objects", s.name, s.id, () => setServiceDialog({ open: true, editing: s }))}
                      </TableCell>
                    </TableRow>
                  )),
                  ["Name", "Protocol", "Ports", "Referenced by"],
                )
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Service groups ── */}
        <TabsContent value="service-groups" className="mt-4">
          <Card className="p-0">
            <CardContent className="p-0">
              <ToolbarRow
                label={`${(svcGrpQuery.data?.data ?? []).length} service groups`}
                addLabel="Add service group"
                onAdd={() => setGroupDialog({ open: true, kind: "service", editing: null })}
              />
              {svcGrpQuery.error ? (
                <div className="p-4">
                  <QueryError error={svcGrpQuery.error} onRetry={() => void svcGrpQuery.refetch()} />
                </div>
              ) : svcGrpQuery.isLoading ? (
                <div className="p-4">
                  <TableSkeleton rows={3} cols={4} />
                </div>
              ) : (svcGrpQuery.data?.data ?? []).length === 0 ? (
                <EmptyBlock icon={<Icons.FolderOpen className="h-6 w-6" />} title="No service groups" description="Group service objects so rules can match them with a single id." />
              ) : (
                tableShell(
                  false,
                  null,
                  svcGroups.map((g) => (
                    <TableRow key={g.id}>
                      <TableCell className="font-medium">{g.name}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className="border-zinc-500/30 bg-zinc-500/10 font-normal text-zinc-600 tabular-nums dark:text-zinc-300">
                          {g.memberIds.length} members
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-72 truncate text-xs text-zinc-500">{g.description ?? "—"}</TableCell>
                      <TableCell>
                        <RefCell names={refNames.get(g.id) ?? []} />
                      </TableCell>
                      <TableCell className="text-right">
                        {rowActions("/api/v1/service-groups", g.name, g.id, () => setGroupDialog({ open: true, kind: "service", editing: g }))}
                      </TableCell>
                    </TableRow>
                  )),
                  ["Name", "Members", "Description", "Referenced by"],
                )
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Schedules ── */}
        <TabsContent value="schedules" className="mt-4">
          <Card className="p-0">
            <CardContent className="p-0">
              <ToolbarRow
                label={`${(schedQuery.data?.data ?? []).length} schedules`}
                addLabel="Add schedule"
                onAdd={() => setScheduleDialog({ open: true, editing: null })}
              />
              {schedQuery.error ? (
                <div className="p-4">
                  <QueryError error={schedQuery.error} onRetry={() => void schedQuery.refetch()} />
                </div>
              ) : schedQuery.isLoading ? (
                <div className="p-4">
                  <TableSkeleton rows={3} cols={5} />
                </div>
              ) : (schedQuery.data?.data ?? []).length === 0 ? (
                <EmptyBlock icon={<Icons.Clock className="h-6 w-6" />} title="No schedules" description="Time-gate rules: always, recurring weekly windows or one-time windows." />
              ) : (
                tableShell(
                  false,
                  null,
                  schedules.map((s) => {
                    const active = scheduleIsActiveNow(s);
                    return (
                      <TableRow key={s.id}>
                        <TableCell className="font-medium">{s.name}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="border-zinc-300 font-normal text-zinc-600 dark:border-zinc-700 dark:text-zinc-300">
                            {s.type}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs">{scheduleSummary(s)}</TableCell>
                        <TableCell>
                          {active ? (
                            <Badge variant="outline" className="border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                              <Icons.CircleCheck className="mr-1 h-3 w-3" /> active now
                            </Badge>
                          ) : (
                            <Badge variant="outline" className="border-zinc-300 text-zinc-500 dark:border-zinc-700 dark:text-zinc-400">
                              <Icons.CircleDashed className="mr-1 h-3 w-3" /> inactive
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell>
                          <RefCell names={refNames.get(s.id) ?? []} />
                        </TableCell>
                        <TableCell className="text-right">
                          {rowActions("/api/v1/schedule-objects", s.name, s.id, () => setScheduleDialog({ open: true, editing: s }))}
                        </TableCell>
                      </TableRow>
                    );
                  }),
                  ["Name", "Type", "Window", "Now", "Referenced by"],
                )
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* ── dialogs (mounted only while open → fresh state per open) ── */}
      {addressDialog.open && (
        <AddressObjectDialog
          state={addressDialog}
          onOpenChange={(open) => setAddressDialog((s) => ({ ...s, open }))}
          onSaved={invalidateAll}
        />
      )}
      {groupDialog.open && (
        <GroupDialog
          state={groupDialog}
          onOpenChange={(open) => setGroupDialog((s) => ({ ...s, open }))}
          addressObjects={addrQuery.data?.data ?? []}
          serviceObjects={svcQuery.data?.data ?? []}
          onSaved={invalidateAll}
        />
      )}
      {serviceDialog.open && (
        <ServiceDialog
          state={serviceDialog}
          onOpenChange={(open) => setServiceDialog((s) => ({ ...s, open }))}
          onSaved={invalidateAll}
        />
      )}
      {scheduleDialog.open && (
        <ScheduleDialog
          state={scheduleDialog}
          onOpenChange={(open) => setScheduleDialog((s) => ({ ...s, open }))}
          onSaved={invalidateAll}
        />
      )}

      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title="Delete object?"
        description={`Delete '${deleting?.name ?? ""}'? Deletion is rejected while firewall or NAT rules still reference it.`}
        loading={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting)}
      />

      <ConflictDialog
        open={conflict?.open ?? false}
        onOpenChange={() => setConflict((c) => (c ? { ...c, open: false } : c))}
        title={conflict?.title ?? ""}
        message={conflict?.message ?? ""}
        error={conflict?.error}
      />
    </div>
  );
}

function ToolbarRow({ label, addLabel, onAdd }: { label: string; addLabel: string; onAdd: () => void }) {
  return (
    <div className="flex items-center justify-between gap-2 border-b border-zinc-200 px-4 py-2.5 dark:border-zinc-800">
      <p className="text-xs text-zinc-500">{label}</p>
      <Button size="sm" onClick={onAdd} className="bg-red-700 text-white hover:bg-red-800">
        <Icons.Plus className="mr-1 h-4 w-4" /> {addLabel}
      </Button>
    </div>
  );
}

// ── Address object dialog ───────────────────────────────────────────────────

interface AddressDialogState {
  open: boolean;
  editing: AddressObject | null;
}

function AddressObjectDialog(props: { state: AddressDialogState; onOpenChange: (open: boolean) => void; onSaved: () => void }) {
  const editing = props.state.editing;
  const [name, setName] = useState(editing?.name ?? "");
  const [type, setType] = useState<AddressType>(editing?.type ?? "ip");
  const [value, setValue] = useState(editing?.value ?? "");
  const [description, setDescription] = useState(editing?.description ?? "");
  const [error, setError] = useState<string | null>(null);

  const mut = useMutation({
    mutationFn: () => {
      const body = { name: name.trim(), type, value: value.trim(), description: description.trim() || null };
      return editing ? api.generic.update<AddressObject>(`/api/v1/address-objects/${editing.id}`, body) : api.generic.create<AddressObject>("/api/v1/address-objects", body);
    },
    onSuccess: () => {
      toastOk(editing ? "Address object updated" : "Address object created", name.trim());
      props.onOpenChange(false);
      props.onSaved();
    },
    onError: (err) => toastErr(err, editing ? "Update failed" : "Create failed"),
  });

  const submit = () => {
    if (!name.trim()) return setError("Name is required");
    const v = validateAddressValue(type, value.trim());
    if (v) return setError(v);
    setError(null);
    mut.mutate();
  };

  return (
    <Dialog open={props.state.open} onOpenChange={props.onOpenChange}>
      <DialogContent className="w-[calc(100vw-1rem)] max-w-md">
        <DialogHeader>
          <DialogTitle>{editing ? `Edit address object — ${editing.name}` : "Add address object"}</DialogTitle>
          <DialogDescription>Address objects are referenced by firewall and NAT rules.</DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div>
            <Label htmlFor="ao-name" className="text-xs font-medium">
              Name
            </Label>
            <Input id="ao-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="LAN_NET" className="mt-1.5" />
          </div>
          <div>
            <FieldLabel>Type</FieldLabel>
            <Select value={type} onValueChange={(v) => setType(v as AddressType)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ip">ip — single IPv4</SelectItem>
                <SelectItem value="range">range — IPv4 range</SelectItem>
                <SelectItem value="subnet">subnet — CIDR</SelectItem>
                <SelectItem value="fqdn">fqdn — hostname</SelectItem>
                <SelectItem value="geo">geo — country code</SelectItem>
                <SelectItem value="wildcard">wildcard — addr mask</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label htmlFor="ao-value" className="text-xs font-medium">
              Value
            </Label>
            <Input
              id="ao-value"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder={ADDRESS_PLACEHOLDER[type]}
              className="mt-1.5 font-mono text-xs"
            />
          </div>
          <div>
            <Label htmlFor="ao-desc" className="text-xs font-medium">
              Description <span className="text-zinc-400">(optional)</span>
            </Label>
            <Input id="ao-desc" value={description} onChange={(e) => setDescription(e.target.value)} className="mt-1.5" />
          </div>
          {error && <p className="text-xs text-rose-600 dark:text-rose-400">{error}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => props.onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={mut.isPending} className="bg-red-700 text-white hover:bg-red-800">
            {mut.isPending ? "Saving…" : editing ? "Save changes" : "Create object"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── Group dialog (address + service groups share the transfer-list editor) ──

interface GroupDialogState {
  open: boolean;
  kind: "address" | "service";
  editing: NamedWithMembers | null;
}

function GroupDialog(props: {
  state: GroupDialogState;
  onOpenChange: (open: boolean) => void;
  addressObjects: AddressObject[];
  serviceObjects: ServiceObject[];
  onSaved: () => void;
}) {
  const editing = props.state.editing;
  const kind = props.state.kind;
  const [name, setName] = useState(editing?.name ?? "");
  const [memberIds, setMemberIds] = useState<number[]>(editing?.memberIds ?? []);
  const [description, setDescription] = useState(editing?.description ?? "");
  const [error, setError] = useState<string | null>(null);

  const all = useMemo(() => {
    if (kind === "address") {
      return props.addressObjects.map((a) => ({ id: a.id, label: a.name, sub: a.value }));
    }
    return props.serviceObjects.map((s) => ({ id: s.id, label: s.name, sub: s.dstPort ?? s.protocol }));
  }, [kind, props.addressObjects, props.serviceObjects]);

  const path = kind === "address" ? "/api/v1/address-groups" : "/api/v1/service-groups";

  const mut = useMutation({
    mutationFn: () => {
      const body = { name: name.trim(), memberIds, description: description.trim() || null };
      return editing ? api.generic.update<NamedWithMembers>(`${path}/${editing.id}`, body) : api.generic.create<NamedWithMembers>(path, body);
    },
    onSuccess: () => {
      toastOk(editing ? "Group updated" : "Group created", name.trim());
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
    <Dialog open={props.state.open} onOpenChange={props.onOpenChange}>
      <DialogContent className="w-[calc(100vw-1rem)] max-w-2xl">
        <DialogHeader>
          <DialogTitle>{editing ? `Edit ${kind} group — ${editing.name}` : `Add ${kind} group`}</DialogTitle>
          <DialogDescription>Click an item to move it between columns. Members are stored as object ids (flat, no nesting).</DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <Label htmlFor="grp-name" className="text-xs font-medium">
                Name
              </Label>
              <Input id="grp-name" value={name} onChange={(e) => setName(e.target.value)} placeholder={kind === "address" ? "TRUSTED" : "WEB_SERVICES"} className="mt-1.5" />
            </div>
            <div>
              <Label htmlFor="grp-desc" className="text-xs font-medium">
                Description <span className="text-zinc-400">(optional)</span>
              </Label>
              <Input id="grp-desc" value={description} onChange={(e) => setDescription(e.target.value)} className="mt-1.5" />
            </div>
          </div>
          <TransferList all={all} value={memberIds} onChange={setMemberIds} availableTitle="Available objects" chosenTitle="Members" />
          {error && <p className="text-xs text-rose-600 dark:text-rose-400">{error}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => props.onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={mut.isPending} className="bg-red-700 text-white hover:bg-red-800">
            {mut.isPending ? "Saving…" : editing ? "Save changes" : "Create group"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── Service dialog ──────────────────────────────────────────────────────────

interface ServiceDialogState {
  open: boolean;
  editing: ServiceObject | null;
}

function ServiceDialog(props: { state: ServiceDialogState; onOpenChange: (open: boolean) => void; onSaved: () => void }) {
  const editing = props.state.editing;
  const [name, setName] = useState(editing?.name ?? "");
  const [protocol, setProtocol] = useState<ServiceProtocol>(editing?.protocol ?? "tcp");
  const [srcPort, setSrcPort] = useState(editing?.srcPort ?? "");
  const [dstPort, setDstPort] = useState(editing?.dstPort ?? "");
  const [icmpType, setIcmpType] = useState(editing?.icmpType == null ? "" : String(editing.icmpType));
  const [icmpCode, setIcmpCode] = useState(editing?.icmpCode == null ? "" : String(editing.icmpCode));
  const [description, setDescription] = useState(editing?.description ?? "");
  const [error, setError] = useState<string | null>(null);

  const mut = useMutation({
    mutationFn: () => {
      const num = (v: string) => {
        const t = v.trim();
        if (!t) return null;
        const n = Number(t);
        return Number.isInteger(n) && n >= 0 && n <= 255 ? n : undefined; // undefined → 400 path
      };
      const it = num(icmpType);
      const ic = num(icmpCode);
      const body = {
        name: name.trim(),
        protocol,
        srcPort: protocol === "tcp" || protocol === "udp" ? srcPort.trim() || null : null,
        dstPort: protocol === "tcp" || protocol === "udp" ? dstPort.trim() || null : null,
        icmpType: protocol === "icmp" ? (it === undefined ? undefined : it) : null,
        icmpCode: protocol === "icmp" ? (ic === undefined ? undefined : ic) : null,
        description: description.trim() || null,
      };
      // strip undefined keys so JSON.stringify omits them (null is meaningful)
      const clean = JSON.parse(JSON.stringify(body)) as Record<string, unknown>;
      return editing
        ? api.generic.update<ServiceObject>(`/api/v1/service-objects/${editing.id}`, clean)
        : api.generic.create<ServiceObject>("/api/v1/service-objects", clean);
    },
    onSuccess: () => {
      toastOk(editing ? "Service updated" : "Service created", name.trim());
      props.onOpenChange(false);
      props.onSaved();
    },
    onError: (err) => toastErr(err, editing ? "Update failed" : "Create failed"),
  });

  const submit = () => {
    if (!name.trim()) return setError("Name is required");
    if ((protocol === "tcp" || protocol === "udp") && !srcPort.trim() && !dstPort.trim())
      return setError("TCP/UDP services need a source or destination port list");
    for (const p of [srcPort, dstPort]) {
      if (p.trim() && !isValidPortList(p.trim())) return setError(`Invalid port list "${p}" — use 80 or 5000-5100,6000`);
    }
    if (protocol === "icmp") {
      for (const [label, v] of [
        ["ICMP type", icmpType],
        ["ICMP code", icmpCode],
      ] as const) {
        if (v.trim()) {
          const n = Number(v);
          if (!Number.isInteger(n) || n < 0 || n > 255) return setError(`${label} must be 0–255`);
        }
      }
    }
    setError(null);
    mut.mutate();
  };

  return (
    <Dialog open={props.state.open} onOpenChange={props.onOpenChange}>
      <DialogContent className="w-[calc(100vw-1rem)] max-w-md">
        <DialogHeader>
          <DialogTitle>{editing ? `Edit service — ${editing.name}` : "Add service"}</DialogTitle>
          <DialogDescription>Port lists follow the 80 / 5000-5100,6000 grammar.</DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <Label htmlFor="svc-name" className="text-xs font-medium">
                Name
              </Label>
              <Input id="svc-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="HTTPS" className="mt-1.5" />
            </div>
            <div>
              <Label htmlFor="svc-desc" className="text-xs font-medium">
                Description <span className="text-zinc-400">(optional)</span>
              </Label>
              <Input id="svc-desc" value={description} onChange={(e) => setDescription(e.target.value)} className="mt-1.5" />
            </div>
          </div>
          <div>
            <FieldLabel>Protocol</FieldLabel>
            <RadioGroup value={protocol} onValueChange={(v) => setProtocol(v as ServiceProtocol)} className="flex flex-wrap gap-4">
              {(["tcp", "udp", "icmp", "any"] as ServiceProtocol[]).map((p) => (
                <Label key={p} className="flex cursor-pointer items-center gap-2 text-sm uppercase">
                  <RadioGroupItem value={p} /> {p}
                </Label>
              ))}
            </RadioGroup>
          </div>
          {(protocol === "tcp" || protocol === "udp") && (
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <Label htmlFor="svc-src" className="text-xs font-medium">
                  Source ports
                </Label>
                <Input id="svc-src" value={srcPort} onChange={(e) => setSrcPort(e.target.value)} placeholder="5000-5100,6000" className="mt-1.5 font-mono text-xs" />
              </div>
              <div>
                <Label htmlFor="svc-dst" className="text-xs font-medium">
                  Destination ports
                </Label>
                <Input id="svc-dst" value={dstPort} onChange={(e) => setDstPort(e.target.value)} placeholder="443" className="mt-1.5 font-mono text-xs" />
              </div>
            </div>
          )}
          {protocol === "icmp" && (
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <Label htmlFor="svc-icmp-t" className="text-xs font-medium">
                  ICMP type <span className="text-zinc-400">(0–255)</span>
                </Label>
                <Input id="svc-icmp-t" type="number" min={0} max={255} value={icmpType} onChange={(e) => setIcmpType(e.target.value)} className="mt-1.5" />
              </div>
              <div>
                <Label htmlFor="svc-icmp-c" className="text-xs font-medium">
                  ICMP code <span className="text-zinc-400">(0–255)</span>
                </Label>
                <Input id="svc-icmp-c" type="number" min={0} max={255} value={icmpCode} onChange={(e) => setIcmpCode(e.target.value)} className="mt-1.5" />
              </div>
            </div>
          )}
          {error && <p className="text-xs text-rose-600 dark:text-rose-400">{error}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => props.onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={mut.isPending} className="bg-red-700 text-white hover:bg-red-800">
            {mut.isPending ? "Saving…" : editing ? "Save changes" : "Create service"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── Schedule dialog ─────────────────────────────────────────────────────────

interface ScheduleDialogState {
  open: boolean;
  editing: ScheduleObject | null;
}

function ScheduleDialog(props: { state: ScheduleDialogState; onOpenChange: (open: boolean) => void; onSaved: () => void }) {
  const editing = props.state.editing;
  const [name, setName] = useState(editing?.name ?? "");
  const [type, setType] = useState<ScheduleObject["type"]>(editing?.type ?? "always");
  const [days, setDays] = useState<number[]>(editing?.recurrence?.days ?? [1, 2, 3, 4, 5]);
  const [start, setStart] = useState(editing?.recurrence?.start ?? "09:00");
  const [end, setEnd] = useState(editing?.recurrence?.end ?? "17:00");
  const [timezone, setTimezone] = useState(editing?.timezone ?? "UTC");
  const [startsAt, setStartsAt] = useState(toLocalInput(editing?.startsAt ?? null));
  const [endsAt, setEndsAt] = useState(toLocalInput(editing?.endsAt ?? null));
  const [error, setError] = useState<string | null>(null);

  const draft: ScheduleObject = useMemo(
    () => ({
      id: 0,
      name,
      type,
      recurrence: type === "recurring" ? { days, start, end } : null,
      startsAt: type === "onetime" && startsAt ? new Date(startsAt).toISOString() : null,
      endsAt: type === "onetime" && endsAt ? new Date(endsAt).toISOString() : null,
      timezone,
    }),
    [name, type, days, start, end, startsAt, endsAt, timezone],
  );

  const activeNow = useMemo(() => {
    if (!name.trim()) return null;
    try {
      return scheduleIsActiveNow(draft);
    } catch {
      return null;
    }
  }, [draft, name]);

  const mut = useMutation({
    mutationFn: () => {
      const body: Record<string, unknown> = {
        name: name.trim(),
        type,
        timezone: timezone.trim() || "UTC",
      };
      if (type === "recurring") body.recurrence = { days, start, end };
      if (type === "onetime") {
        body.startsAt = startsAt ? new Date(startsAt).toISOString() : null;
        body.endsAt = endsAt ? new Date(endsAt).toISOString() : null;
      }
      return editing
        ? api.generic.update<ScheduleObject>(`/api/v1/schedule-objects/${editing.id}`, body)
        : api.generic.create<ScheduleObject>("/api/v1/schedule-objects", body);
    },
    onSuccess: () => {
      toastOk(editing ? "Schedule updated" : "Schedule created", name.trim());
      props.onOpenChange(false);
      props.onSaved();
    },
    onError: (err) => toastErr(err, editing ? "Update failed" : "Create failed"),
  });

  const submit = () => {
    if (!name.trim()) return setError("Name is required");
    if (type === "recurring") {
      if (days.length === 0) return setError("Pick at least one weekday");
      if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(start) || !/^([01]\d|2[0-3]):[0-5]\d$/.test(end)) return setError("Start/end must be HH:MM");
    }
    if (type === "onetime") {
      if (!startsAt || !endsAt) return setError("One-time schedules need start and end datetimes");
      if (new Date(startsAt).getTime() >= new Date(endsAt).getTime()) return setError("End must be after start");
    }
    if (!isValidTimezone(timezone.trim() || "UTC")) return setError(`Unknown IANA timezone "${timezone}"`);
    setError(null);
    mut.mutate();
  };

  return (
    <Dialog open={props.state.open} onOpenChange={props.onOpenChange}>
      <DialogContent className="w-[calc(100vw-1rem)] max-w-lg">
        <DialogHeader>
          <DialogTitle>{editing ? `Edit schedule — ${editing.name}` : "Add schedule"}</DialogTitle>
          <DialogDescription>Rules only match while their schedule is active in the schedule&apos;s timezone.</DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <Label htmlFor="sch-name" className="text-xs font-medium">
                Name
              </Label>
              <Input id="sch-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="BUSINESS_HOURS" className="mt-1.5" />
            </div>
            <div>
              <FieldLabel>Type</FieldLabel>
              <RadioGroup value={type} onValueChange={(v) => setType(v as ScheduleObject["type"])} className="flex gap-4">
                {(["always", "recurring", "onetime"] as const).map((t) => (
                  <Label key={t} className="flex cursor-pointer items-center gap-2 text-sm">
                    <RadioGroupItem value={t} /> {t}
                  </Label>
                ))}
              </RadioGroup>
            </div>
          </div>

          {type === "recurring" && (
            <>
              <div>
                <FieldLabel>Weekdays</FieldLabel>
                <div className="flex flex-wrap gap-1.5">
                  {WEEKDAYS.map((d, i) => {
                    const day = i + 1;
                    const on = days.includes(day);
                    return (
                      <button
                        key={d}
                        type="button"
                        aria-pressed={on}
                        onClick={() => setDays(on ? days.filter((x) => x !== day) : [...days, day])}
                        className={cn(
                          "rounded-md border px-2.5 py-1.5 text-xs transition-colors",
                          on
                            ? "border-zinc-500/30 bg-zinc-500/10 font-medium text-zinc-600 dark:text-zinc-300"
                            : "border-zinc-200 text-zinc-500 hover:bg-zinc-100 dark:border-zinc-800 dark:hover:bg-zinc-800",
                        )}
                      >
                        {d}
                      </button>
                    );
                  })}
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label htmlFor="sch-start" className="text-xs font-medium">
                    Start
                  </Label>
                  <Input id="sch-start" type="time" value={start} onChange={(e) => setStart(e.target.value)} className="mt-1.5" />
                </div>
                <div>
                  <Label htmlFor="sch-end" className="text-xs font-medium">
                    End
                  </Label>
                  <Input id="sch-end" type="time" value={end} onChange={(e) => setEnd(e.target.value)} className="mt-1.5" />
                </div>
              </div>
              <div>
                <Label htmlFor="sch-tz" className="text-xs font-medium">
                  IANA timezone
                </Label>
                <Input id="sch-tz" value={timezone} onChange={(e) => setTimezone(e.target.value)} placeholder="Asia/Calcutta" className="mt-1.5 font-mono text-xs" />
              </div>
            </>
          )}

          {type === "onetime" && (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div>
                <Label htmlFor="sch-iso-start" className="text-xs font-medium">
                  Starts at
                </Label>
                <Input id="sch-iso-start" type="datetime-local" value={startsAt} onChange={(e) => setStartsAt(e.target.value)} className="mt-1.5 text-xs" />
              </div>
              <div>
                <Label htmlFor="sch-iso-end" className="text-xs font-medium">
                  Ends at
                </Label>
                <Input id="sch-iso-end" type="datetime-local" value={endsAt} onChange={(e) => setEndsAt(e.target.value)} className="mt-1.5 text-xs" />
              </div>
            </div>
          )}

          {type === "always" && (
            <p className="rounded-md bg-zinc-100 px-3 py-2 text-xs text-zinc-600 dark:bg-zinc-800 dark:text-zinc-300">
              An &quot;always&quot; schedule is active at every instant — useful as an explicit placeholder.
            </p>
          )}

          <div className="flex items-center justify-between rounded-lg border border-zinc-200 px-3 py-2 dark:border-zinc-800">
            <span className="text-xs text-zinc-500">Computed live</span>
            {activeNow === null ? (
              <span className="text-xs text-zinc-400">enter a name…</span>
            ) : activeNow ? (
              <Badge variant="outline" className="border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                <Icons.CircleCheck className="mr-1 h-3 w-3" /> active now
              </Badge>
            ) : (
              <Badge variant="outline" className="border-zinc-300 text-zinc-500 dark:border-zinc-700 dark:text-zinc-400">
                <Icons.CircleDashed className="mr-1 h-3 w-3" /> not active now
              </Badge>
            )}
          </div>

          {error && <p className="text-xs text-rose-600 dark:text-rose-400">{error}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => props.onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={mut.isPending} className="bg-red-700 text-white hover:bg-red-800">
            {mut.isPending ? "Saving…" : editing ? "Save changes" : "Create schedule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
