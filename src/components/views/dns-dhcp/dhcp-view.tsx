"use client";

/**
 * DHCP view (M06 §4) — hash #/dns-dhcp/dhcp, 4 tabs:
 * Subnets | Reservations | Leases | Relay.
 * Leases refetch on focus (global) + 15 s safety-net poll; no leases:update
 * socket event exists (M06 §6 — do not invent one). Churn is IPv4-only in
 * simulation; v6 subnets are config-only and labeled as such (M06 §5.4).
 */

import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { ConfirmDialog, EditorSection, EmptyBlock, FieldLabel, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";
import {
  dhcpApi,
  fieldErrorsOf,
  fmtDateTime,
  fmtRemaining,
  humanizeSeconds,
  listInterfaceNames,
  type DhcpLeaseDTO,
  type DhcpReservationDTO,
  type DhcpSubnetDTO,
  type IfaceLite,
} from "./dns-dhcp-api";
import {
  FamilyChip,
  InfoNote,
  IpListEditor,
  LeaseStateBadge,
  OptionsEditor,
  useDhcpConfigInvalidation,
} from "./dns-dhcp-ui";
import { cn } from "@/lib/utils";

type TabKey = "subnets" | "reservations" | "leases" | "relay";

const TABS: Array<{ key: TabKey; label: string }> = [
  { key: "subnets", label: "Subnets" },
  { key: "reservations", label: "Reservations" },
  { key: "leases", label: "Leases" },
  { key: "relay", label: "Relay" },
];

function tabFromHash(): TabKey {
  const qs = window.location.hash.split("?")[1];
  const v = new URLSearchParams(qs ?? "").get("tab");
  return TABS.some((t) => t.key === v) ? (v as TabKey) : "subnets";
}

export function DhcpView() {
  useDhcpConfigInvalidation();
  const [tab, setTab] = useState<TabKey>(() => tabFromHash());
  useEffect(() => {
    history.replaceState(null, "", `#/dns-dhcp/dhcp?tab=${tab}`);
  }, [tab]);

  return (
    <Tabs value={tab} onValueChange={(v) => setTab(v as TabKey)}>
      <TabsList className="flex w-full flex-wrap justify-start gap-1 sm:w-auto">
        {TABS.map((t) => (
          <TabsTrigger key={t.key} value={t.key} className="text-xs sm:text-sm">
            {t.label}
          </TabsTrigger>
        ))}
      </TabsList>
      <TabsContent value="subnets" className="mt-3 space-y-3">
        <SubnetsTab goToReservations={() => setTab("reservations")} />
      </TabsContent>
      <TabsContent value="reservations" className="mt-3 space-y-3">
        <ReservationsTab />
      </TabsContent>
      <TabsContent value="leases" className="mt-3 space-y-3">
        <LeasesTab />
      </TabsContent>
      <TabsContent value="relay" className="mt-3 space-y-3">
        <RelayTab />
      </TabsContent>
    </Tabs>
  );
}

// ── Subnets ─────────────────────────────────────────────────────────────────

function SubnetsTab({ goToReservations }: { goToReservations: () => void }) {
  const queryClient = useQueryClient();
  const q = useQuery({ queryKey: ["dhcp", "subnets"], queryFn: dhcpApi.listSubnets });
  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<DhcpSubnetDTO | null>(null);
  const [deleting, setDeleting] = useState<DhcpSubnetDTO | null>(null);

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ["dhcp"] });

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => dhcpApi.updateSubnet(id, { enabled }),
    onSuccess: () => invalidate(),
    onError: (err) => toastErr(err, "Toggle failed"),
  });

  const del = useMutation({
    mutationFn: (id: number) => dhcpApi.deleteSubnet(id),
    onSuccess: (res) => {
      const c = res.cascaded;
      toastOk("Subnet deleted", c ? `Cascaded ${c.reservations} reservation(s) and ${c.leases} lease(s)` : undefined);
      setDeleting(null);
      invalidate();
    },
    onError: (err) => toastErr(err, "Delete failed"),
  });

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs text-zinc-500">DHCP scopes · deleting a subnet cascades its reservations and leases</p>
        <Button
          size="sm"
          className="bg-blue-600 text-white hover:bg-blue-700"
          onClick={() => {
            setEditing(null);
            setEditorOpen(true);
          }}
        >
          <Icons.Plus className="mr-1 h-4 w-4" /> Add Subnet
        </Button>
      </div>

      {q.isLoading ? (
        <div className="grid gap-3 lg:grid-cols-2">
          {[...Array(2)].map((_, i) => (
            <Card key={i}>
              <CardContent className="space-y-3 pt-6">
                {[...Array(4)].map((_, j) => (
                  <div key={j} className="h-5 w-full animate-pulse rounded bg-zinc-100 dark:bg-zinc-800" />
                ))}
              </CardContent>
            </Card>
          ))}
        </div>
      ) : q.isError ? (
        <QueryError error={q.error} onRetry={() => void q.refetch()} />
      ) : (q.data ?? []).length === 0 ? (
        <Card>
          <CardContent className="p-0">
            <EmptyBlock
              icon={<Icons.Router className="h-6 w-6" />}
              title="No DHCP subnets"
              description="Create a scope to start leasing addresses on an interface."
              action={
                <Button size="sm" className="bg-blue-600 text-white hover:bg-blue-700" onClick={() => { setEditing(null); setEditorOpen(true); }}>
                  Add Subnet
                </Button>
              }
            />
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-3 lg:grid-cols-2">
          {(q.data ?? []).map((s) => (
            <Card key={s.id} className={cn(!s.enabled && "opacity-60")}>
              <CardContent className="space-y-2.5 pt-5">
                <div className="flex items-center justify-between gap-2">
                  <p className="flex items-center gap-2 text-sm font-medium">
                    {s.interfaceName} <FamilyChip family={s.family} />
                  </p>
                  <Switch checked={s.enabled} onCheckedChange={(v) => toggle.mutate({ id: s.id, enabled: v })} aria-label={`Toggle subnet ${s.subnetCidr}`} />
                </div>
                <p className="font-mono text-xs text-zinc-700 dark:text-zinc-200">{s.subnetCidr}</p>
                <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-[11px] text-zinc-500">
                  <span>
                    pool <span className="font-mono text-zinc-700 dark:text-zinc-200">{s.rangeStart}</span> –{" "}
                    <span className="font-mono text-zinc-700 dark:text-zinc-200">{s.rangeEnd}</span>
                  </span>
                  <span>
                    gateway <span className="font-mono text-zinc-700 dark:text-zinc-200">{s.gateway ?? "—"}</span>
                  </span>
                  <span>
                    lease <span className="font-mono text-zinc-700 dark:text-zinc-200">{humanizeSeconds(s.leaseTime)}</span>
                  </span>
                  <span>
                    dns {s.dnsServers.length ? <span className="font-mono text-zinc-700 dark:text-zinc-200">{s.dnsServers.join(", ")}</span> : "—"}
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-1.5">
                  <Badge variant="outline" className="border-emerald-500/40 bg-emerald-500/10 px-1.5 py-0 text-[10px] text-emerald-600 dark:text-emerald-400">
                    {s.activeLeaseCount} active
                  </Badge>
                  <button
                    type="button"
                    onClick={goToReservations}
                    className="text-[11px] text-zinc-400 underline-offset-2 hover:text-blue-600 hover:underline dark:hover:text-blue-400"
                  >
                    {s.reservationCount} reservation{s.reservationCount === 1 ? "" : "s"}
                  </button>
                  {s.family === "ipv6" && <span className="text-[10px] text-zinc-400">config-only in simulation</span>}
                </div>
                <div className="flex items-center justify-end gap-1.5 border-t border-zinc-100 pt-2 dark:border-zinc-800">
                  <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => { setEditing(s); setEditorOpen(true); }}>
                    <Icons.Pencil className="mr-1 h-3.5 w-3.5" /> Edit
                  </Button>
                  <Button variant="ghost" size="sm" className="h-7 text-xs text-rose-600 hover:text-rose-600 dark:text-rose-400" onClick={() => setDeleting(s)}>
                    <Icons.Trash2 className="mr-1 h-3.5 w-3.5" /> Delete
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <SubnetEditor open={editorOpen} onOpenChange={setEditorOpen} editing={editing} onSaved={() => { setEditorOpen(false); invalidate(); }} />

      <ConfirmDialog
        open={deleting != null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete subnet ${deleting?.subnetCidr ?? ""}?`}
        description={
          deleting
            ? `Cascades ${deleting.reservationCount} reservation(s) and ${deleting.leaseCount} lease(s) (${deleting.activeLeaseCount} active). This cannot be undone.`
            : ""
        }
        confirmLabel="Delete subnet"
        loading={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting.id)}
      />
    </div>
  );
}

function SubnetEditor({
  open,
  onOpenChange,
  editing,
  onSaved,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editing: DhcpSubnetDTO | null;
  onSaved: () => void;
}) {
  const ifaces = useQuery({ queryKey: ["dhcp", "iface-names"], queryFn: listInterfaceNames, enabled: open, staleTime: 30_000 });
  const [form, setForm] = useState(() => subnetFormFrom(editing));
  const [serverErrors, setServerErrors] = useState<Record<string, string[]>>({});

  const seedKey = `${editing?.id ?? "new"}:${ifaces.data?.length ?? 0}`;
  const [lastKey, setLastKey] = useState(seedKey);
  if (seedKey !== lastKey) {
    setLastKey(seedKey);
    setServerErrors({});
    setForm(subnetFormFrom(editing));
  }

  const save = useMutation({
    mutationFn: () => {
      const body = {
        interfaceName: form.interfaceName,
        family: form.family,
        subnetCidr: form.subnetCidr.trim(),
        rangeStart: form.rangeStart.trim(),
        rangeEnd: form.rangeEnd.trim(),
        gateway: form.gateway.trim() || null,
        dnsServers: form.dnsServers,
        leaseTime: Number(form.leaseTime) || 86400,
        options: form.options,
        enabled: form.enabled,
      };
      return editing ? dhcpApi.updateSubnet(editing.id, body) : dhcpApi.createSubnet(body);
    },
    onSuccess: () => {
      toastOk(editing ? "Subnet updated" : "Subnet created");
      onSaved();
    },
    onError: (err) => {
      setServerErrors(fieldErrorsOf(err));
      toastErr(err, "Save failed");
    },
  });

  const err = (path: string) => serverErrors[path]?.join("; ");
  const set = <K extends keyof SubnetForm>(k: K, v: SubnetForm[K]) => setForm((f) => ({ ...f, [k]: v }));
  const isV6 = form.family === "ipv6";

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
      <DialogHeader>
        <DialogTitle>{editing ? `Edit subnet — ${editing.subnetCidr}` : "Add DHCP subnet"}</DialogTitle>
        <DialogDescription>Scope, pool range and lease options for one interface.</DialogDescription>
      </DialogHeader>
      <div className="space-y-4">
        <EditorSection title="Interface & family">
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <FieldLabel>Interface</FieldLabel>
              <Select value={form.interfaceName} onValueChange={(v) => set("interfaceName", v)}>
                <SelectTrigger className="h-9 text-sm"><SelectValue placeholder="select interface" /></SelectTrigger>
                <SelectContent>
                  {(ifaces.data ?? []).map((i: IfaceLite) => (
                    <SelectItem key={i.id} value={i.name}>
                      {i.name} <span className="text-[10px] text-zinc-400">({i.role})</span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {err("interfaceName") && <p className="text-[11px] text-rose-500">{err("interfaceName")}</p>}
            </div>
            <div>
              <FieldLabel hint="v6 = basic DHCPv6 (config-only in simulation)">Family</FieldLabel>
              <RadioGroup value={form.family} onValueChange={(v) => set("family", v)} className="flex gap-4 pt-1">
                <Label className="flex cursor-pointer items-center gap-2 text-xs font-normal">
                  <RadioGroupItem value="ipv4" /> IPv4
                </Label>
                <Label className="flex cursor-pointer items-center gap-2 text-xs font-normal">
                  <RadioGroupItem value="ipv6" /> IPv6
                </Label>
              </RadioGroup>
            </div>
          </div>
        </EditorSection>

        <EditorSection title="Scope & pool">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="sm:col-span-2">
              <FieldLabel hint={isV6 ? "e.g. 2001:db8:10::/64" : "e.g. 192.168.10.0/24"}>Subnet CIDR</FieldLabel>
              <Input className="h-9 font-mono text-xs" value={form.subnetCidr} onChange={(e) => set("subnetCidr", e.currentTarget.value)} aria-label="Subnet CIDR" />
              {err("subnetCidr") && <p className="text-[11px] text-rose-500">{err("subnetCidr")}</p>}
            </div>
            <div>
              <FieldLabel>Pool start</FieldLabel>
              <Input className="h-9 font-mono text-xs" value={form.rangeStart} onChange={(e) => set("rangeStart", e.currentTarget.value)} aria-label="Pool start" />
              {err("rangeStart") && <p className="text-[11px] text-rose-500">{err("rangeStart")}</p>}
            </div>
            <div>
              <FieldLabel>Pool end</FieldLabel>
              <Input className="h-9 font-mono text-xs" value={form.rangeEnd} onChange={(e) => set("rangeEnd", e.currentTarget.value)} aria-label="Pool end" />
              {err("rangeEnd") && <p className="text-[11px] text-rose-500">{err("rangeEnd")}</p>}
            </div>
            <div>
              <FieldLabel hint="optional, inside the subnet">Gateway</FieldLabel>
              <Input className="h-9 font-mono text-xs" value={form.gateway} onChange={(e) => set("gateway", e.currentTarget.value)} aria-label="Gateway" />
              {err("gateway") && <p className="text-[11px] text-rose-500">{err("gateway")}</p>}
            </div>
            <div>
              <FieldLabel hint="60–604800 s">Lease time (seconds)</FieldLabel>
              <Input type="number" className="h-9 font-mono text-xs" value={form.leaseTime} onChange={(e) => set("leaseTime", e.currentTarget.value)} aria-label="Lease time seconds" />
              <p className="text-[11px] text-zinc-400">{humanizeSeconds(Number(form.leaseTime) || 0)}</p>
              {err("leaseTime") && <p className="text-[11px] text-rose-500">{err("leaseTime")}</p>}
            </div>
          </div>
          <div>
            <FieldLabel hint="handed to clients (option 6)">DNS servers</FieldLabel>
            <IpListEditor values={form.dnsServers} onChange={(v) => set("dnsServers", v)} placeholder={isV6 ? "2001:db8:10::1" : "192.168.10.1"} addLabel="Add DNS server" />
            {err("dnsServers") && <p className="text-[11px] text-rose-500">{err("dnsServers")}</p>}
          </div>
          <div>
            <FieldLabel hint="DHCP option code → value, e.g. 42 → NTP server">Custom options</FieldLabel>
            <OptionsEditor value={form.options} onChange={(v) => set("options", v)} />
            {err("options") && <p className="text-[11px] text-rose-500">{err("options")}</p>}
          </div>
          <label className="flex items-center justify-between gap-3 pt-1">
            <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Enabled</span>
            <Switch checked={form.enabled} onCheckedChange={(v) => set("enabled", v)} aria-label="Toggle subnet enabled" />
          </label>
        </EditorSection>
      </div>
      <DialogFooter>
        <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
        <Button onClick={() => save.mutate()} disabled={save.isPending} className="bg-blue-600 text-white hover:bg-blue-700">
          {save.isPending ? "Saving…" : editing ? "Save changes" : "Create subnet"}
        </Button>
      </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

type SubnetForm = {
  interfaceName: string;
  family: string;
  subnetCidr: string;
  rangeStart: string;
  rangeEnd: string;
  gateway: string;
  dnsServers: string[];
  leaseTime: string;
  options: Record<string, string>;
  enabled: boolean;
};

function subnetFormFrom(s: DhcpSubnetDTO | null): SubnetForm {
  return {
    interfaceName: s?.interfaceName ?? "",
    family: s?.family ?? "ipv4",
    subnetCidr: s?.subnetCidr ?? "",
    rangeStart: s?.rangeStart ?? "",
    rangeEnd: s?.rangeEnd ?? "",
    gateway: s?.gateway ?? "",
    dnsServers: s?.dnsServers ?? [],
    leaseTime: String(s?.leaseTime ?? 86400),
    options: s?.options ?? {},
    enabled: s?.enabled ?? true,
  };
}

// ── Reservations ────────────────────────────────────────────────────────────

function ReservationsTab() {
  const queryClient = useQueryClient();
  const subnets = useQuery({ queryKey: ["dhcp", "subnets"], queryFn: dhcpApi.listSubnets });
  const q = useQuery({ queryKey: ["dhcp", "reservations"], queryFn: () => dhcpApi.listReservations() });
  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<DhcpReservationDTO | null>(null);
  const [deleting, setDeleting] = useState<DhcpReservationDTO | null>(null);
  const [conflict, setConflict] = useState<{ id: number; ip: string; hostname: string | null } | null>(null);

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["dhcp", "reservations"] });
    void queryClient.invalidateQueries({ queryKey: ["dhcp", "subnets"] });
  };

  const del = useMutation({
    mutationFn: (id: number) => dhcpApi.deleteReservation(id),
    onSuccess: () => {
      toastOk("Reservation deleted");
      setDeleting(null);
      invalidate();
    },
    onError: (err) => toastErr(err, "Delete failed"),
  });

  const rows = q.data ?? [];
  const subnetCidr = (id: number) => (subnets.data ?? []).find((s) => s.id === id)?.subnetCidr ?? "—";

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs text-zinc-500">Static MAC bindings — reserved IPs are excluded from the dynamic pool</p>
        <Button size="sm" className="bg-blue-600 text-white hover:bg-blue-700" onClick={() => { setEditing(null); setEditorOpen(true); }}>
          <Icons.Plus className="mr-1 h-4 w-4" /> Add Reservation
        </Button>
      </div>

      <Card>
        <CardContent className="p-0">
          {q.isLoading ? (
            <div className="pt-6">
              <TableSkeleton rows={4} cols={5} />
            </div>
          ) : q.isError ? (
            <div className="p-4">
              <QueryError error={q.error} onRetry={() => void q.refetch()} />
            </div>
          ) : rows.length === 0 ? (
            <EmptyBlock
              icon={<Icons.Pin className="h-6 w-6" />}
              title="No reservations"
              description="Pin a MAC address to an IP inside one of your subnets."
              action={
                <Button size="sm" className="bg-blue-600 text-white hover:bg-blue-700" onClick={() => { setEditing(null); setEditorOpen(true); }}>
                  Add Reservation
                </Button>
              }
            />
          ) : (
            <div className="max-h-[480px] overflow-auto [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-zinc-300 dark:[&::-webkit-scrollbar-thumb]:bg-zinc-700">
              <table className="w-full text-sm">
                <thead className="sticky top-0 border-b border-zinc-200 bg-zinc-50 text-left text-[11px] uppercase tracking-wide text-zinc-500 dark:border-zinc-800 dark:bg-zinc-900">
                  <tr>
                    <th className="px-4 py-2.5 font-medium">MAC</th>
                    <th className="px-4 py-2.5 font-medium">IP</th>
                    <th className="px-4 py-2.5 font-medium">Hostname</th>
                    <th className="px-4 py-2.5 font-medium">Subnet</th>
                    <th className="w-10 px-4 py-2.5" />
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.id} className="border-b border-zinc-100 last:border-0 hover:bg-zinc-50 dark:border-zinc-800/60 dark:hover:bg-zinc-800/40">
                      <td className="px-4 py-2.5 font-mono text-xs">{r.mac}</td>
                      <td className="px-4 py-2.5 font-mono text-xs">{r.ip}</td>
                      <td className="px-4 py-2.5 text-xs">{r.hostname ?? <span className="text-zinc-400">—</span>}</td>
                      <td className="px-4 py-2.5 font-mono text-xs text-zinc-500">{subnetCidr(r.subnetId)}</td>
                      <td className="px-4 py-2.5 text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={`Edit reservation ${r.mac}`} onClick={() => { setEditing(r); setEditorOpen(true); }}>
                            <Icons.Pencil className="h-3.5 w-3.5" />
                          </Button>
                          <Button variant="ghost" size="icon" className="h-8 w-8 text-rose-500 hover:text-rose-600" aria-label={`Delete reservation ${r.mac}`} onClick={() => setDeleting(r)}>
                            <Icons.Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      <ReservationEditor
        open={editorOpen}
        onOpenChange={(o) => {
          setEditorOpen(o);
          if (!o) setConflict(null);
        }}
        editing={editing}
        subnets={subnets.data ?? []}
        conflict={conflict}
        onSaved={() => {
          setEditorOpen(false);
          setConflict(null);
          invalidate();
        }}
      />

      <ConfirmDialog
        open={deleting != null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Release reservation ${deleting?.mac ?? ""}?`}
        description={`${deleting?.ip ?? ""} returns to the dynamic pool.`}
        confirmLabel="Delete"
        loading={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting.id)}
      />
    </div>
  );
}

function ReservationEditor({
  open,
  onOpenChange,
  editing,
  subnets,
  conflict,
  onSaved,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editing: DhcpReservationDTO | null;
  subnets: DhcpSubnetDTO[];
  conflict: { id: number; ip: string; hostname: string | null } | null;
  onSaved: () => void;
}) {
  const [form, setForm] = useState(() => resFormFrom(editing, subnets));
  const [serverErrors, setServerErrors] = useState<Record<string, string[]>>({});

  const seedKey = `${editing?.id ?? "new"}:${subnets.length}`;
  const [lastKey, setLastKey] = useState(seedKey);
  if (seedKey !== lastKey) {
    setLastKey(seedKey);
    setServerErrors({});
    setForm(resFormFrom(editing, subnets));
  }

  const save = useMutation({
    mutationFn: () => {
      const body = {
        subnetId: Number(form.subnetId),
        mac: form.mac.trim().toLowerCase(),
        ip: form.ip.trim(),
        hostname: form.hostname.trim() || null,
      };
      return editing ? dhcpApi.updateReservation(editing.id, body) : dhcpApi.createReservation(body);
    },
    onSuccess: () => {
      toastOk(editing ? "Reservation updated" : "Reservation created");
      onSaved();
    },
    onError: (err) => {
      setServerErrors(fieldErrorsOf(err));
      toastErr(err, "Save failed");
    },
  });

  const err = (path: string) => serverErrors[path]?.join("; ");
  const set = <K extends keyof ResForm>(k: K, v: ResForm[K]) => setForm((f) => ({ ...f, [k]: v }));
  const selectedSubnet = subnets.find((s) => String(s.id) === form.subnetId);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
      <DialogHeader>
        <DialogTitle>{editing ? "Edit reservation" : "Add reservation"}</DialogTitle>
        <DialogDescription>MAC ↔ IP binding inside a subnet pool.</DialogDescription>
      </DialogHeader>
      <div className="space-y-4">
        {conflict && (
          <div className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-400">
            MAC already held by reservation #{conflict.id} — {conflict.ip} ({conflict.hostname ?? "unnamed"})
          </div>
        )}
        <EditorSection title="Binding">
          <div>
            <FieldLabel>Subnet</FieldLabel>
            <Select value={form.subnetId} onValueChange={(v) => set("subnetId", v)}>
              <SelectTrigger className="h-9 text-sm"><SelectValue placeholder="select subnet" /></SelectTrigger>
              <SelectContent>
                {subnets.map((s) => (
                  <SelectItem key={s.id} value={String(s.id)}>
                    {s.subnetCidr} <span className="text-[10px] text-zinc-400">({s.interfaceName})</span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {err("subnetId") && <p className="text-[11px] text-rose-500">{err("subnetId")}</p>}
          </div>
          <div>
            <FieldLabel hint="aa:bb:cc:dd:ee:ff">MAC address</FieldLabel>
            <Input className="h-9 font-mono text-xs" value={form.mac} onChange={(e) => set("mac", e.currentTarget.value)} aria-label="MAC address" />
            {err("mac") && <p className="text-[11px] text-rose-500">{err("mac")}</p>}
          </div>
          <div>
            <FieldLabel hint={selectedSubnet ? `inside ${selectedSubnet.subnetCidr}` : "inside the subnet"}>
              IP address
            </FieldLabel>
            <Input className="h-9 font-mono text-xs" value={form.ip} onChange={(e) => set("ip", e.currentTarget.value)} aria-label="IP address" />
            {err("ip") && <p className="text-[11px] text-rose-500">{err("ip")}</p>}
          </div>
          <div>
            <FieldLabel hint="optional">Hostname</FieldLabel>
            <Input className="h-9 text-sm" value={form.hostname} onChange={(e) => set("hostname", e.currentTarget.value)} aria-label="Hostname" />
          </div>
        </EditorSection>
      </div>
      <DialogFooter>
        <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
        <Button onClick={() => save.mutate()} disabled={save.isPending} className="bg-blue-600 text-white hover:bg-blue-700">
          {save.isPending ? "Saving…" : editing ? "Save changes" : "Create reservation"}
        </Button>
      </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

type ResForm = { subnetId: string; mac: string; ip: string; hostname: string };

function resFormFrom(r: DhcpReservationDTO | null, subnets: DhcpSubnetDTO[]): ResForm {
  return {
    subnetId: r ? String(r.subnetId) : subnets[0] ? String(subnets[0].id) : "",
    mac: r?.mac ?? "",
    ip: r?.ip ?? "",
    hostname: r?.hostname ?? "",
  };
}

// ── Leases ──────────────────────────────────────────────────────────────────

function LeasesTab() {
  const queryClient = useQueryClient();
  const subnets = useQuery({ queryKey: ["dhcp", "subnets"], queryFn: dhcpApi.listSubnets });
  const [state, setState] = useState<"all" | "active" | "expired">("all");
  const [subnetId, setSubnetId] = useState("all");
  const [qInput, setQInput] = useState("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const [expiring, setExpiring] = useState<DhcpLeaseDTO | null>(null);

  useEffect(() => {
    const t = setTimeout(() => {
      setQ(qInput);
      setPage(1);
    }, 350);
    return () => clearTimeout(t);
  }, [qInput]);

  const params = useMemo(() => {
    const sp = new URLSearchParams({ page: String(page), limit: "25" });
    if (state !== "all") sp.set("state", state);
    if (subnetId !== "all") sp.set("subnetId", subnetId);
    if (q) sp.set("q", q);
    return sp.toString();
  }, [state, subnetId, q, page]);

  const list = useQuery({
    queryKey: ["dhcp", "leases", params],
    queryFn: () => dhcpApi.listLeases(params),
    refetchInterval: 15_000, // safety net — focus + config:updated are the fast paths (M06 §6)
  });

  const release = useMutation({
    mutationFn: (id: number) => dhcpApi.releaseLease(id),
    onSuccess: () => {
      toastOk("Lease released", "The IP returns to the pool on next churn");
      setExpiring(null);
      void queryClient.invalidateQueries({ queryKey: ["dhcp", "leases"] });
      void queryClient.invalidateQueries({ queryKey: ["dhcp", "subnets"] });
    },
    onError: (err) => toastErr(err, "Release failed"),
  });

  const rows = list.data?.data ?? [];
  const meta = list.data?.meta;
  const subnetCidr = (id: number) => (subnets.data ?? []).find((s) => s.id === id)?.subnetCidr ?? "—";

  const stateChips: Array<{ key: "all" | "active" | "expired"; label: string }> = [
    { key: "all", label: "All" },
    { key: "active", label: "Active" },
    { key: "expired", label: "Expired" },
  ];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex gap-1">
          {stateChips.map((c) => (
            <button
              key={c.key}
              type="button"
              aria-pressed={state === c.key}
              onClick={() => {
                setState(c.key);
                setPage(1);
              }}
              className={cn(
                "rounded-full border px-3 py-1 text-[11px] font-medium transition-colors",
                state === c.key
                  ? "border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400"
                  : "border-zinc-200 text-zinc-500 hover:text-zinc-700 dark:border-zinc-800 dark:text-zinc-400",
              )}
            >
              {c.label}
            </button>
          ))}
        </div>
        <Select value={subnetId} onValueChange={(v) => { setSubnetId(v); setPage(1); }}>
          <SelectTrigger className="h-9 w-48 text-sm"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All subnets</SelectItem>
            {(subnets.data ?? []).map((s) => (
              <SelectItem key={s.id} value={String(s.id)}>{s.subnetCidr}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <div className="relative">
          <Icons.Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-400" />
          <Input className="h-9 w-48 pl-8 text-sm" placeholder="MAC / IP / hostname…" value={qInput} onChange={(e) => setQInput(e.currentTarget.value)} aria-label="Search leases" />
        </div>
        <span className="ml-auto flex items-center gap-1.5 text-[11px] text-zinc-400">
          <Icons.Radio className="h-3.5 w-3.5 text-emerald-500" /> live churn · refresh 15 s
        </span>
      </div>

      <Card>
        <CardContent className="p-0">
          {list.isLoading ? (
            <div className="pt-6">
              <TableSkeleton rows={6} cols={7} />
            </div>
          ) : list.isError ? (
            <div className="p-4">
              <QueryError error={list.error} onRetry={() => void list.refetch()} />
            </div>
          ) : rows.length === 0 ? (
            <EmptyBlock icon={<Icons.Clock className="h-6 w-6" />} title="No leases match" description="The engine leases addresses from enabled IPv4 subnets every 2 s tick." />
          ) : (
            <div className="max-h-[480px] overflow-auto [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-zinc-300 dark:[&::-webkit-scrollbar-thumb]:bg-zinc-700">
              <table className="w-full text-sm">
                <thead className="sticky top-0 border-b border-zinc-200 bg-zinc-50 text-left text-[11px] uppercase tracking-wide text-zinc-500 dark:border-zinc-800 dark:bg-zinc-900">
                  <tr>
                    <th className="px-4 py-2.5 font-medium">MAC</th>
                    <th className="px-4 py-2.5 font-medium">IP</th>
                    <th className="px-4 py-2.5 font-medium">Hostname</th>
                    <th className="px-4 py-2.5 font-medium">Subnet</th>
                    <th className="px-4 py-2.5 font-medium">State</th>
                    <th className="px-4 py-2.5 font-medium">Expires</th>
                    <th className="w-10 px-4 py-2.5" />
                  </tr>
                </thead>
                <tbody>
                  {rows.map((l) => (
                    <tr key={l.id} className="border-b border-zinc-100 last:border-0 hover:bg-zinc-50 dark:border-zinc-800/60 dark:hover:bg-zinc-800/40">
                      <td className="px-4 py-2.5 font-mono text-xs">{l.mac}</td>
                      <td className="px-4 py-2.5 font-mono text-xs">{l.ip}</td>
                      <td className="px-4 py-2.5 text-xs">{l.hostname ?? <span className="text-zinc-400">—</span>}</td>
                      <td className="px-4 py-2.5 font-mono text-xs text-zinc-500">{subnetCidr(l.subnetId)}</td>
                      <td className="px-4 py-2.5"><LeaseStateBadge state={l.state} /></td>
                      <td className="px-4 py-2.5 text-xs">
                        <p className="tabular-nums">{fmtDateTime(l.endsAt)}</p>
                        <p className="text-[11px] text-zinc-400">{l.state === "active" ? `${fmtRemaining(l.endsAt)} left` : l.state === "expired" ? "ended" : "released"}</p>
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        {l.state === "active" && (
                          <Button variant="ghost" size="sm" className="h-7 text-xs text-amber-600 hover:text-amber-600 dark:text-amber-400" onClick={() => setExpiring(l)}>
                            <Icons.TimerOff className="mr-1 h-3.5 w-3.5" /> Expire
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {meta && meta.totalPages > 1 && (
        <div className="flex items-center justify-end gap-2 text-xs text-zinc-500">
          <Button variant="outline" size="sm" className="h-7" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
            <Icons.ChevronLeft className="mr-1 h-3.5 w-3.5" /> Prev
          </Button>
          <span className="tabular-nums">{meta.page} / {meta.totalPages}</span>
          <Button variant="outline" size="sm" className="h-7" disabled={page >= meta.totalPages} onClick={() => setPage((p) => p + 1)}>
            Next <Icons.ChevronRight className="ml-1 h-3.5 w-3.5" />
          </Button>
        </div>
      )}

      <ConfirmDialog
        open={expiring != null}
        onOpenChange={(open) => !open && setExpiring(null)}
        title={`Expire lease ${expiring?.ip ?? ""}?`}
        description="Calls the locked release endpoint — the client must re-request an address (state flips to released)."
        confirmLabel="Expire lease"
        loading={release.isPending}
        onConfirm={() => expiring && release.mutate(expiring.id)}
      />
    </div>
  );
}

// ── Relay ───────────────────────────────────────────────────────────────────

function RelayTab() {
  const queryClient = useQueryClient();
  const ifaces = useQuery({ queryKey: ["dhcp", "iface-names"], queryFn: listInterfaceNames, staleTime: 30_000 });
  const q = useQuery({ queryKey: ["dhcp", "relay"], queryFn: dhcpApi.getRelay });

  if (q.isLoading) {
    return (
      <Card>
        <CardContent className="space-y-3 pt-6">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="h-9 w-full animate-pulse rounded-md bg-zinc-100 dark:bg-zinc-800" />
          ))}
        </CardContent>
      </Card>
    );
  }
  if (q.isError) return <QueryError error={q.error} onRetry={() => void q.refetch()} />;
  if (!q.data) return null;
  return <RelayForm key={q.dataUpdatedAt} initial={q.data} ifaces={ifaces.data ?? []} onSaved={() => void queryClient.invalidateQueries({ queryKey: ["dhcp", "relay"] })} />;
}

function RelayForm({
  initial,
  ifaces,
  onSaved,
}: {
  initial: { enabled: boolean; servers: string[]; interfaces: string[] };
  ifaces: IfaceLite[];
  onSaved: () => void;
}) {
  const [enabled, setEnabled] = useState(initial.enabled);
  const [servers, setServers] = useState<string[]>(initial.servers);
  const [selected, setSelected] = useState<string[]>(initial.interfaces);
  const [serverErrors, setServerErrors] = useState<Record<string, string[]>>({});

  const toggleIface = (name: string) =>
    setSelected((cur) => (cur.includes(name) ? cur.filter((n) => n !== name) : [...cur, name]));

  const save = useMutation({
    mutationFn: () => dhcpApi.putRelay({ enabled, servers, interfaces: selected }),
    onSuccess: () => {
      setServerErrors({});
      toastOk("Relay configuration applied");
      onSaved();
    },
    onError: (err) => {
      setServerErrors(fieldErrorsOf(err));
      toastErr(err, "Save failed");
    },
  });

  const err = (path: string) => serverErrors[path]?.join("; ");

  return (
    <Card>
      <CardContent className="space-y-5 pt-6">
        <Alert className="border-blue-500/40 bg-blue-500/10 text-blue-700 dark:text-blue-300">
          <Icons.Info className="h-4 w-4" />
          <AlertTitle>DHCP relay (ip-helper)</AlertTitle>
          <AlertDescription>
            The appliance renders dhcrelay/Kea relay config per interface (spec §1.9); the sandbox records the config.
          </AlertDescription>
        </Alert>

        <EditorSection title="Relay">
          <label className="flex items-center justify-between gap-3">
            <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Enabled</span>
            <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="Toggle DHCP relay" />
          </label>
          <div>
            <FieldLabel hint="1–8 ip-helper targets">Relay servers</FieldLabel>
            <IpListEditor values={servers} onChange={setServers} placeholder="e.g. 192.168.10.254" addLabel="Add server" />
            {err("servers") && <p className="text-[11px] text-rose-500">{err("servers")}</p>}
          </div>
          <div>
            <FieldLabel hint="1–8 interfaces that forward DHCP broadcasts">Relayed interfaces</FieldLabel>
            <ScrollArea className="max-h-40 rounded-md border border-zinc-200 dark:border-zinc-800">
              <div className="space-y-0.5 p-2 pr-3">
                {ifaces.map((i) => {
                  const on = selected.includes(i.name);
                  return (
                    <label
                      key={i.id}
                      className={cn(
                        "flex cursor-pointer items-center justify-between gap-2 rounded-md border px-2.5 py-1.5 text-xs transition-colors",
                        on ? "border-blue-500/30 bg-blue-500/5" : "border-transparent hover:bg-zinc-50 dark:hover:bg-zinc-800/60",
                      )}
                    >
                      <span className="font-mono">{i.name}</span>
                      <span className="flex items-center gap-2 text-[10px] text-zinc-400">
                        {i.role}
                        <input type="checkbox" checked={on} onChange={() => toggleIface(i.name)} aria-label={`Relay interface ${i.name}`} className="accent-blue-600" />
                      </span>
                    </label>
                  );
                })}
                {ifaces.length === 0 && <p className="px-2 py-1 text-[11px] text-zinc-400">No interfaces found.</p>}
              </div>
            </ScrollArea>
            {err("interfaces") && <p className="text-[11px] text-rose-500">{err("interfaces")}</p>}
          </div>
        </EditorSection>

        <div className="flex justify-end">
          <Button onClick={() => save.mutate()} disabled={save.isPending} className="bg-blue-600 text-white hover:bg-blue-700">
            {save.isPending ? "Saving…" : "Save relay config"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
