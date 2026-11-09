"use client";

/**
 * #/identity/nac — NAC & Profiling (M23, spec 2.9). Stats strip (computed from
 * the device inventory), NAC profiles table + CRUD (802.1X/MAB, dynamic/guest/
 * auth-fail VLANs, posture switches), paged device inventory with optimistic
 * quarantine/release per row plus a simulated profiling rescan, and the BYOD
 * onboarding list (enroll with one-time token, approve, revoke).
 * Theme (ADR-019): red-700 enterprise accents, zinc neutrals, rose-600
 * danger (quarantine), amber-500 warning (pending).
 */

import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { z } from "zod";
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
import { byodCreateSchema, nacProfileCreateSchema } from "@/lib/validators/identity-advanced";
import {
  DEVICE_TYPES,
  NAC_METHODS,
  EAP_TYPES,
  fieldErrorsOf,
  fmtRelative,
  identityApi,
  qs,
  type ByodCreatedDTO,
  type ByodStatus,
  type DeviceDTO,
  type DeviceType,
  type NacMethod,
  type NacProfileDTO,
  type NacState,
} from "./identity-advanced-api";
import { ConfirmDialog, EmptyBlock, FieldLabel, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";

const ROOT_KEY = ["identity-advanced"] as const;
const DEVICES_KEY = [...ROOT_KEY, "devices"] as const;
const PAGE_SIZE = 100;

/** Long-list scroll wrapper with a slim custom scrollbar. */
const SCROLL =
  "max-h-96 overflow-y-auto [&::-webkit-scrollbar]:w-1.5 [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-zinc-300 dark:[&::-webkit-scrollbar-thumb]:bg-zinc-700";

function invalidateAll(queryClient: ReturnType<typeof useQueryClient>) {
  void queryClient.invalidateQueries({ queryKey: ROOT_KEY });
}

function feToMap(fe: Record<string, string[]>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(fe)) if (v.length > 0) out[k] = v[0];
  return out;
}

function zodToMap(error: z.ZodError): Record<string, string> {
  const out: Record<string, string> = {};
  for (const issue of error.issues) {
    const k = issue.path.join(".") || "_";
    if (!out[k]) out[k] = issue.message;
  }
  return out;
}

function FieldError({ msg }: { msg?: string }) {
  if (!msg) return null;
  return <p className="mt-1 text-xs text-rose-600">{msg}</p>;
}

function useDebounced(value: string, ms = 400): string {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

// ── badge + icon recipes (ADR-019 — blue/zinc/rose/amber only) ──────────────

const STATE_META: Record<NacState, { cls: string; icon: React.ComponentType<{ className?: string }> }> = {
  authenticated: { cls: "border-red-600/40 bg-red-600/10 text-red-700 dark:text-red-500", icon: Icons.ShieldCheck },
  mab: { cls: "border-red-600/40 bg-transparent text-red-700 dark:text-red-500", icon: Icons.KeyRound },
  quarantine: { cls: "border-transparent bg-rose-600 text-white", icon: Icons.ShieldAlert },
  pending: { cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400", icon: Icons.Clock },
  denied: { cls: "border-rose-600/60 bg-transparent text-rose-500", icon: Icons.Ban },
};

const TYPE_ICON: Record<DeviceType, React.ComponentType<{ className?: string }>> = {
  printer: Icons.Printer,
  phone: Icons.Smartphone,
  camera: Icons.Camera,
  workstation: Icons.Monitor,
  mobile: Icons.Tablet,
  iot: Icons.Cpu,
  unknown: Icons.HelpCircle,
};

const METHOD_CLS: Record<NacMethod, string> = {
  "802.1x": "border-red-600/40 bg-red-600/10 font-mono text-red-700 dark:text-red-500",
  mab: "border-zinc-300 bg-zinc-100 font-mono text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
  both: "border-red-600/40 bg-transparent font-mono text-red-700 dark:text-red-500",
};

const BYOD_META: Record<ByodStatus, { cls: string; icon: React.ComponentType<{ className?: string }> }> = {
  pending: { cls: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400", icon: Icons.Clock },
  approved: { cls: "border-red-600/40 bg-red-600/10 text-red-700 dark:text-red-500", icon: Icons.ShieldCheck },
  enrolled: { cls: "border-transparent bg-red-700 text-white", icon: Icons.CheckCircle2 },
  expired: { cls: "border-zinc-300 bg-zinc-100 text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-400", icon: Icons.Timer },
  revoked: { cls: "border-rose-600/60 bg-transparent text-rose-500", icon: Icons.Ban },
};

function StateBadge({ state }: { state: NacState }) {
  const meta = STATE_META[state];
  const Icon = meta.icon;
  return (
    <Badge variant="outline" className={`gap-1 font-medium ${meta.cls}`}>
      <Icon className="h-3 w-3" />
      {state}
    </Badge>
  );
}

function ByodStatusBadge({ status }: { status: ByodStatus }) {
  const meta = BYOD_META[status];
  const Icon = meta.icon;
  return (
    <Badge variant="outline" className={`gap-1 font-medium ${meta.cls}`}>
      <Icon className="h-3 w-3" />
      {status}
    </Badge>
  );
}

// ── stats strip (computed from the inventory — no dedicated stats endpoint) ─

function StatCard(props: { label: string; value: number | string; icon: React.ReactNode; tone: string; sub?: string }) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs font-medium text-zinc-500">{props.label}</span>
          <span className={props.tone}>{props.icon}</span>
        </div>
        <p className="mt-1 text-2xl font-semibold tabular-nums">{props.value}</p>
        {props.sub ? <p className="mt-1 text-[11px] text-zinc-400">{props.sub}</p> : null}
      </CardContent>
    </Card>
  );
}

function methodOfDevice(device: DeviceDTO, profiles: NacProfileDTO[]): NacMethod | null {
  const profile = profiles.find((p) => p.id === device.nacProfileId);
  if (profile) return profile.method;
  return device.nacState === "mab" ? "mab" : null;
}

function StatsStrip() {
  const devicesQuery = useQuery({
    queryKey: [...DEVICES_KEY, qs({ limit: PAGE_SIZE })],
    queryFn: () => identityApi.listDevices(qs({ limit: PAGE_SIZE })),
  });
  const profilesQuery = useQuery({ queryKey: [...ROOT_KEY, "nac-profiles"], queryFn: identityApi.listNacProfiles });

  const devices = devicesQuery.data ?? [];
  const profiles = profilesQuery.data ?? [];
  const quarantined = devices.filter((d) => d.nacState === "quarantine").length;
  const dot1x = devices.filter((d) => {
    const m = methodOfDevice(d, profiles);
    return m === "802.1x" || m === "both";
  }).length;
  const mab = devices.filter((d) => methodOfDevice(d, profiles) === "mab").length;

  return (
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <StatCard
        label="Profiled devices"
        value={devicesQuery.isLoading ? "—" : devices.length}
        sub={devices.length >= PAGE_SIZE ? `showing first ${PAGE_SIZE}` : "in inventory"}
        tone="text-red-700 dark:text-red-500"
        icon={<Icons.ScanLine className="h-4 w-4" />}
      />
      <StatCard
        label="Quarantined"
        value={devicesQuery.isLoading ? "—" : quarantined}
        sub="isolated on quarantine VLAN"
        tone="text-rose-500"
        icon={<Icons.ShieldAlert className="h-4 w-4" />}
      />
      <StatCard
        label="802.1X profiled"
        value={devicesQuery.isLoading ? "—" : dot1x}
        sub="EAP profiles (incl. both)"
        tone="text-red-700 dark:text-red-500"
        icon={<Icons.KeyRound className="h-4 w-4" />}
      />
      <StatCard
        label="MAB profiled"
        value={devicesQuery.isLoading ? "—" : mab}
        sub="MAC auth bypass endpoints"
        tone="text-red-700 dark:text-red-500"
        icon={<Icons.Cpu className="h-4 w-4" />}
      />
    </div>
  );
}

// ── NAC profile editor ──────────────────────────────────────────────────────

function NacProfileEditor(props: { profile: NacProfileDTO | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = props.profile !== null;
  const [name, setName] = useState(props.profile?.name ?? "");
  const [method, setMethod] = useState<NacMethod>(props.profile?.method ?? "802.1x");
  const [eapType, setEapType] = useState(props.profile?.eapType ?? "peap");
  const [dynamicVlan, setDynamicVlan] = useState(props.profile?.dynamicVlan ?? true);
  const [guestVlan, setGuestVlan] = useState(props.profile?.guestVlan != null ? String(props.profile.guestVlan) : "");
  const [authFailVlan, setAuthFailVlan] = useState(props.profile?.authFailVlan != null ? String(props.profile.authFailVlan) : "");
  const [profiling, setProfiling] = useState(props.profile?.profiling ?? true);
  const [byodOnboarding, setByodOnboarding] = useState(props.profile?.byodOnboarding ?? false);
  const [enabled, setEnabled] = useState(props.profile?.enabled ?? true);
  const [err, setErr] = useState<string | null>(null);
  const [fields, setFields] = useState<Record<string, string>>({});

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => {
      const id = props.profile?.id;
      if (isEdit && id !== undefined) return identityApi.updateNacProfile(id, body);
      return identityApi.createNacProfile(body);
    },
    onSuccess: (p) => {
      toastOk(isEdit ? "NAC profile updated" : "NAC profile created", p.name);
      invalidateAll(queryClient);
      props.onClose();
    },
    onError: (e) => {
      setErr(e instanceof Error ? e.message : "Save failed");
      setFields(feToMap(fieldErrorsOf(e)));
    },
  });

  const submit = () => {
    const payload = {
      name: name.trim(),
      method,
      eapType,
      dynamicVlan,
      guestVlan: guestVlan.trim() === "" ? null : guestVlan,
      authFailVlan: authFailVlan.trim() === "" ? null : authFailVlan,
      profiling,
      byodOnboarding,
      enabled,
    };
    const parsed = nacProfileCreateSchema.safeParse(payload);
    if (!parsed.success) {
      setFields(zodToMap(parsed.error));
      setErr(null);
      return;
    }
    setFields({});
    setErr(null);
    save.mutate(payload);
  };

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-base">{isEdit ? `Edit ${props.profile?.name}` : "New NAC profile"}</DialogTitle>
          <DialogDescription>
            Profiles define how endpoints authenticate (802.1X EAP or MAC auth bypass) and which VLANs are assigned.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div>
            <FieldLabel>Name</FieldLabel>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="corp-8021x" />
            <FieldError msg={fields.name} />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel>Auth method</FieldLabel>
              <Select value={method} onValueChange={(v) => setMethod(v as NacMethod)}>
                <SelectTrigger aria-label="Auth method">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {NAC_METHODS.map((m) => (
                    <SelectItem key={m} value={m}>
                      {m}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <FieldError msg={fields.method} />
            </div>
            <div>
              <FieldLabel hint="EAP">Inner type</FieldLabel>
              <Select value={eapType} onValueChange={(v) => setEapType(v as typeof EAP_TYPES[number])}>
                <SelectTrigger aria-label="EAP type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {EAP_TYPES.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <FieldError msg={fields.eapType} />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel hint="1–4094, optional">Guest VLAN</FieldLabel>
              <Input
                type="number"
                min={1}
                max={4094}
                value={guestVlan}
                onChange={(e) => setGuestVlan(e.target.value)}
                placeholder="900"
                className="font-mono text-xs"
              />
              <FieldError msg={fields.guestVlan} />
            </div>
            <div>
              <FieldLabel hint="1–4094, optional">Auth-fail VLAN</FieldLabel>
              <Input
                type="number"
                min={1}
                max={4094}
                value={authFailVlan}
                onChange={(e) => setAuthFailVlan(e.target.value)}
                placeholder="999"
                className="font-mono text-xs"
              />
              <FieldError msg={fields.authFailVlan} />
            </div>
          </div>

          <div className="grid gap-3 rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
            <div className="flex items-center justify-between gap-4">
              <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Dynamic VLAN assignment</span>
              <Switch checked={dynamicVlan} onCheckedChange={setDynamicVlan} aria-label="Dynamic VLAN" />
            </div>
            <div className="flex items-center justify-between gap-4">
              <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Endpoint profiling</span>
              <Switch checked={profiling} onCheckedChange={setProfiling} aria-label="Endpoint profiling" />
            </div>
            <div className="flex items-center justify-between gap-4">
              <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">BYOD onboarding</span>
              <Switch checked={byodOnboarding} onCheckedChange={setByodOnboarding} aria-label="BYOD onboarding" />
            </div>
            <div className="flex items-center justify-between gap-4">
              <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Profile enabled</span>
              <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="Profile enabled" />
            </div>
          </div>

          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button className="bg-red-700 text-white hover:bg-red-800" disabled={save.isPending || !name.trim()} onClick={submit}>
            {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create profile"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── NAC profiles section ────────────────────────────────────────────────────

function ProfilesCard() {
  const queryClient = useQueryClient();
  const profilesQuery = useQuery({ queryKey: [...ROOT_KEY, "nac-profiles"], queryFn: identityApi.listNacProfiles });
  const rows = profilesQuery.data ?? [];

  const [addOpen, setAddOpen] = useState(false);
  const [editing, setEditing] = useState<NacProfileDTO | null>(null);
  const [deleting, setDeleting] = useState<NacProfileDTO | null>(null);

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => identityApi.updateNacProfile(id, { enabled }),
    onSuccess: () => invalidateAll(queryClient),
    onError: (e) => toastErr(e, "Toggle failed"),
  });

  const del = useMutation({
    mutationFn: (id: number) => identityApi.deleteNacProfile(id),
    onSuccess: () => {
      toastOk("NAC profile deleted", "Its devices keep the last assigned VLAN until re-authentication.");
      setDeleting(null);
      invalidateAll(queryClient);
    },
    onError: (e) => toastErr(e, "Delete failed"),
  });

  return (
    <Card>
      <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2 space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.Fingerprint className="h-4 w-4 text-red-700 dark:text-red-500" />
          NAC Profiles
          <span className="text-xs font-normal text-zinc-400">{rows.length} configured</span>
        </CardTitle>
        <Button size="sm" className="h-8 bg-red-700 text-white hover:bg-red-800" onClick={() => setAddOpen(true)}>
          <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add profile
        </Button>
      </CardHeader>
      <CardContent className="p-0">
        {profilesQuery.isError ? (
          <div className="p-4">
            <QueryError error={profilesQuery.error} onRetry={() => void profilesQuery.refetch()} />
          </div>
        ) : profilesQuery.isLoading ? (
          <TableSkeleton rows={3} cols={6} />
        ) : rows.length === 0 ? (
          <EmptyBlock
            icon={<Icons.Fingerprint className="h-6 w-6" />}
            title="No NAC profiles"
            description="Create a profile to enforce 802.1X / MAB authentication with dynamic VLAN assignment."
            action={
              <Button size="sm" className="bg-red-700 text-white hover:bg-red-800" onClick={() => setAddOpen(true)}>
                <Icons.Plus className="mr-1 h-3.5 w-3.5" /> New profile
              </Button>
            }
          />
        ) : (
          <div className={SCROLL}>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Profile</TableHead>
                  <TableHead className="w-28">Method</TableHead>
                  <TableHead className="w-40">VLANs</TableHead>
                  <TableHead className="w-44">Features</TableHead>
                  <TableHead className="w-16 text-right">Devices</TableHead>
                  <TableHead className="w-20">Enabled</TableHead>
                  <TableHead className="w-20 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((p) => (
                  <TableRow key={p.id} className={p.enabled ? undefined : "opacity-70"}>
                    <TableCell>
                      <span className="text-sm font-semibold">{p.name}</span>
                      <span className="block text-[10px] uppercase text-zinc-400">eap {p.eapType}</span>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className={`text-[10px] ${METHOD_CLS[p.method]}`}>
                        {p.method}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {p.dynamicVlan && (
                          <Badge variant="outline" className="border-red-600/40 bg-red-600/10 text-[10px] text-red-700 dark:text-red-500">
                            dynamic
                          </Badge>
                        )}
                        {p.guestVlan != null && (
                          <Badge variant="outline" className="border-amber-500/40 bg-amber-500/10 font-mono text-[10px] text-amber-600 dark:text-amber-400">
                            guest {p.guestVlan}
                          </Badge>
                        )}
                        {p.authFailVlan != null && (
                          <Badge variant="outline" className="border-rose-600/40 bg-transparent font-mono text-[10px] text-rose-500">
                            fail {p.authFailVlan}
                          </Badge>
                        )}
                        {!p.dynamicVlan && p.guestVlan == null && p.authFailVlan == null && (
                          <span className="text-xs text-zinc-400">—</span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {p.profiling && (
                          <Badge variant="outline" className="border-red-600/40 bg-red-600/10 text-[10px] text-red-700 dark:text-red-500">
                            profiling
                          </Badge>
                        )}
                        {p.byodOnboarding && (
                          <Badge variant="outline" className="border-red-600/40 bg-red-600/10 text-[10px] text-red-700 dark:text-red-500">
                            byod
                          </Badge>
                        )}
                        {!p.profiling && !p.byodOnboarding && <span className="text-xs text-zinc-400">—</span>}
                      </div>
                    </TableCell>
                    <TableCell className="text-right text-sm tabular-nums text-zinc-600 dark:text-zinc-300">{p.deviceCount}</TableCell>
                    <TableCell>
                      <Switch
                        checked={p.enabled}
                        disabled={toggle.isPending && toggle.variables?.id === p.id}
                        onCheckedChange={(enabled) => toggle.mutate({ id: p.id, enabled })}
                        aria-label={`Toggle ${p.name}`}
                      />
                    </TableCell>
                    <TableCell>
                      <div className="flex justify-end gap-0.5">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-zinc-400 hover:text-red-700"
                          aria-label={`Edit ${p.name}`}
                          onClick={() => setEditing(p)}
                        >
                          <Icons.Pencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-rose-500 hover:text-rose-600"
                          aria-label={`Delete ${p.name}`}
                          onClick={() => setDeleting(p)}
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

      {addOpen && <NacProfileEditor profile={null} onClose={() => setAddOpen(false)} />}
      {editing && <NacProfileEditor profile={editing} onClose={() => setEditing(null)} />}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete NAC profile “${deleting?.name ?? ""}”?`}
        description="Assigned devices keep the dangling reference until their next authentication."
        loading={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting.id)}
      />
    </Card>
  );
}

// ── device inventory (optimistic quarantine / release) ──────────────────────

interface Snapshots {
  snapshots: Array<[readonly unknown[], DeviceDTO[] | undefined]>;
}

function DevicesCard() {
  const queryClient = useQueryClient();
  const [state, setState] = useState<"all" | NacState>("all");
  const [type, setType] = useState<"all" | DeviceType>("all");
  const [searchInput, setSearchInput] = useState("");
  const q = useDebounced(searchInput);

  const profilesQuery = useQuery({ queryKey: [...ROOT_KEY, "nac-profiles"], queryFn: identityApi.listNacProfiles });
  const profiles = profilesQuery.data ?? [];

  const params = useMemo(
    () => qs({ state: state === "all" ? undefined : state, deviceType: type === "all" ? undefined : type, q: q || undefined, limit: PAGE_SIZE }),
    [state, type, q],
  );
  const devicesQuery = useQuery({
    queryKey: [...DEVICES_KEY, params],
    queryFn: () => identityApi.listDevices(params),
  });
  const rows = devicesQuery.data ?? [];

  const quarantine = useMutation({
    mutationFn: (id: number) => identityApi.quarantineDevice(id, {}),
    onMutate: async (id: number): Promise<Snapshots> => {
      await queryClient.cancelQueries({ queryKey: DEVICES_KEY });
      const snapshots = queryClient.getQueriesData<DeviceDTO[]>({ queryKey: DEVICES_KEY });
      queryClient.setQueriesData<DeviceDTO[]>({ queryKey: DEVICES_KEY }, (old) =>
        (old ?? []).map((d) => (d.id === id ? { ...d, nacState: "quarantine" as const } : d)),
      );
      return { snapshots };
    },
    onSuccess: (device) => {
      toastOk("Device quarantined", `${device.macAddress} moved to the quarantine VLAN`);
      invalidateAll(queryClient);
    },
    onError: (e, _id, ctx) => {
      for (const [key, data] of ctx?.snapshots ?? []) queryClient.setQueryData(key, data);
      toastErr(e, "Quarantine failed");
    },
  });

  const release = useMutation({
    mutationFn: (id: number) => identityApi.restoreDevice(id),
    onMutate: async (id: number): Promise<Snapshots> => {
      await queryClient.cancelQueries({ queryKey: DEVICES_KEY });
      const snapshots = queryClient.getQueriesData<DeviceDTO[]>({ queryKey: DEVICES_KEY });
      queryClient.setQueriesData<DeviceDTO[]>({ queryKey: DEVICES_KEY }, (old) =>
        (old ?? []).map((d) => (d.id === id ? { ...d, nacState: "authenticated" as const, vlanId: null } : d)),
      );
      return { snapshots };
    },
    onSuccess: (device) => {
      toastOk("Device released", `${device.macAddress} restored to authenticated state`);
      invalidateAll(queryClient);
    },
    onError: (e, _id, ctx) => {
      for (const [key, data] of ctx?.snapshots ?? []) queryClient.setQueryData(key, data);
      toastErr(e, "Release failed");
    },
  });

  const rescan = useMutation({
    mutationFn: () => identityApi.rescanDevices(),
    onSuccess: (r) => {
      toastOk("Profiling rescan complete", `${r.typed} unknown device${r.typed === 1 ? "" : "s"} typed · ${r.rescanned} refreshed`);
      invalidateAll(queryClient);
    },
    onError: (e) => toastErr(e, "Rescan failed"),
  });

  return (
    <Card>
      <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2 space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.ScanLine className="h-4 w-4 text-red-700 dark:text-red-500" />
          Device Inventory
          <span className="text-xs font-normal text-zinc-400">{rows.length} shown</span>
        </CardTitle>
        <div className="flex flex-wrap items-center gap-2">
          <Input
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="MAC, IP or hostname…"
            aria-label="Search devices"
            className="h-8 w-40 text-xs"
          />
          <Select value={state} onValueChange={(v) => setState(v as "all" | NacState)}>
            <SelectTrigger className="h-8 w-32" aria-label="State filter">
              <SelectValue placeholder="All states" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All states</SelectItem>
              {(["authenticated", "mab", "quarantine", "pending", "denied"] as NacState[]).map((s) => (
                <SelectItem key={s} value={s}>
                  {s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={type} onValueChange={(v) => setType(v as "all" | DeviceType)}>
            <SelectTrigger className="h-8 w-32" aria-label="Device type filter">
              <SelectValue placeholder="All types" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All types</SelectItem>
              {DEVICE_TYPES.map((t) => (
                <SelectItem key={t} value={t}>
                  {t}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button
            variant="outline"
            size="sm"
            className="h-8 gap-1 text-xs"
            disabled={rescan.isPending}
            onClick={() => rescan.mutate()}
          >
            {rescan.isPending ? <Icons.Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Icons.ScanLine className="h-3.5 w-3.5" />}
            Rescan
          </Button>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        {devicesQuery.isError ? (
          <div className="p-4">
            <QueryError error={devicesQuery.error} onRetry={() => void devicesQuery.refetch()} />
          </div>
        ) : devicesQuery.isLoading ? (
          <TableSkeleton rows={6} cols={8} />
        ) : rows.length === 0 ? (
          <EmptyBlock
            icon={<Icons.ScanLine className="h-6 w-6" />}
            title="No devices match"
            description="Endpoints appear here as they connect and get profiled. Adjust the filters or run a rescan."
          />
        ) : (
          <div className={SCROLL}>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-44">MAC</TableHead>
                  <TableHead>Host</TableHead>
                  <TableHead className="w-36">Type / vendor</TableHead>
                  <TableHead className="w-32">Profile</TableHead>
                  <TableHead className="w-16">VLAN</TableHead>
                  <TableHead className="w-40">Posture</TableHead>
                  <TableHead className="w-20 text-right">Last seen</TableHead>
                  <TableHead className="w-32 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((d) => {
                  const Icon = TYPE_ICON[d.deviceType] ?? Icons.HelpCircle;
                  const quarantining = quarantine.isPending && quarantine.variables === d.id;
                  const releasing = release.isPending && release.variables === d.id;
                  return (
                    <TableRow key={d.id}>
                      <TableCell className="font-mono text-xs">{d.macAddress}</TableCell>
                      <TableCell>
                        <span className="block truncate text-sm" title={d.hostname ?? undefined}>
                          {d.hostname ?? "—"}
                        </span>
                        <span className="block font-mono text-[10px] text-zinc-400">{d.ip}</span>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1.5">
                          <Icon className="h-3.5 w-3.5 text-zinc-400" />
                          <span className="truncate text-xs text-zinc-500" title={d.vendor ?? undefined}>
                            {d.vendor ?? d.deviceType}
                          </span>
                        </div>
                        {d.osGuess && <span className="block truncate text-[10px] text-zinc-400">{d.osGuess}</span>}
                      </TableCell>
                      <TableCell className="text-xs text-zinc-500">{d.nacProfileName ?? "—"}</TableCell>
                      <TableCell className="font-mono text-xs tabular-nums text-zinc-600 dark:text-zinc-300">
                        {d.vlanId ?? "—"}
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap items-center gap-1.5">
                          <StateBadge state={d.nacState} />
                          <span
                            className={`text-[10px] font-medium tabular-nums ${
                              d.riskScore >= 70 ? "text-rose-500" : d.riskScore >= 50 ? "text-amber-600 dark:text-amber-400" : "text-zinc-400"
                            }`}
                            title="risk score"
                          >
                            risk {d.riskScore}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell className="whitespace-nowrap text-right text-xs text-zinc-500">{fmtRelative(d.lastSeen)}</TableCell>
                      <TableCell>
                        <div className="flex justify-end">
                          {d.nacState === "quarantine" ? (
                            <Button
                              variant="outline"
                              size="sm"
                              className="h-7 gap-1 border-red-600/40 px-2 text-[11px] text-red-700 hover:bg-red-600/10 dark:text-red-500"
                              disabled={releasing}
                              aria-label={`Release ${d.macAddress}`}
                              onClick={() => release.mutate(d.id)}
                            >
                              {releasing ? <Icons.Loader2 className="h-3 w-3 animate-spin" /> : <Icons.ShieldCheck className="h-3 w-3" />}
                              Release
                            </Button>
                          ) : (
                            <Button
                              variant="outline"
                              size="sm"
                              className="h-7 gap-1 border-rose-600/60 px-2 text-[11px] text-rose-500 hover:bg-rose-600/10 hover:text-rose-600"
                              disabled={quarantining}
                              aria-label={`Quarantine ${d.macAddress}`}
                              onClick={() => quarantine.mutate(d.id)}
                            >
                              {quarantining ? <Icons.Loader2 className="h-3 w-3 animate-spin" /> : <Icons.ShieldAlert className="h-3 w-3" />}
                              Quarantine
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        )}
        <p className="border-t border-zinc-200 px-4 py-2 text-[11px] text-zinc-400 dark:border-zinc-800">
          Quarantine isolates the endpoint on the quarantine VLAN; release restores authenticated access.
        </p>
      </CardContent>
    </Card>
  );
}

// ── BYOD onboarding ─────────────────────────────────────────────────────────

function EnrollDialog(props: { onClose: () => void }) {
  const queryClient = useQueryClient();
  const [userName, setUserName] = useState("");
  const [deviceId, setDeviceId] = useState("");
  const [ttlHours, setTtlHours] = useState("24");
  const [err, setErr] = useState<string | null>(null);
  const [fields, setFields] = useState<Record<string, string>>({});
  const [created, setCreated] = useState<ByodCreatedDTO | null>(null);

  const enroll = useMutation({
    mutationFn: (body: { userName: string; deviceId?: number; ttlHours: number }) => identityApi.createByod(body),
    onSuccess: (r) => {
      setCreated(r);
      toastOk("Enrollment token issued", `expires ${fmtRelative(r.expiresAt)}`);
      invalidateAll(queryClient);
    },
    onError: (e) => {
      setErr(e instanceof Error ? e.message : "Enrollment failed");
      setFields(feToMap(fieldErrorsOf(e)));
    },
  });

  const submit = () => {
    const payload = {
      userName: userName.trim(),
      deviceId: deviceId.trim() === "" ? undefined : deviceId,
      ttlHours,
    };
    const parsed = byodCreateSchema.safeParse(payload);
    if (!parsed.success) {
      setFields(zodToMap(parsed.error));
      setErr(null);
      return;
    }
    setFields({});
    setErr(null);
    enroll.mutate({
      userName: parsed.data.userName,
      ...(parsed.data.deviceId != null ? { deviceId: parsed.data.deviceId } : {}),
      ttlHours: parsed.data.ttlHours,
    });
  };

  const copyToken = async () => {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created.token);
      toastOk("Token copied to clipboard");
    } catch {
      toastErr(new Error("Clipboard is unavailable in this context"), "Copy failed");
    }
  };

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-md">
        {created ? (
          <>
            <DialogHeader>
              <DialogTitle className="text-base">Enrollment token issued</DialogTitle>
              <DialogDescription>
                Give this one-time token to {created.userName} — it is shown now and never again.
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-2">
              <div className="rounded-lg border border-red-600/40 bg-red-600/5 p-4 text-center">
                <p className="font-mono text-lg font-semibold tracking-widest text-red-700 dark:text-red-500">{created.token}</p>
                <p className="mt-1 text-[11px] text-zinc-400">expires {fmtRelative(created.expiresAt)}</p>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={copyToken}>
                <Icons.Copy className="mr-1 h-3.5 w-3.5" /> Copy token
              </Button>
              <Button className="bg-red-700 text-white hover:bg-red-800" onClick={props.onClose}>
                Done
              </Button>
            </DialogFooter>
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle className="text-base">New BYOD enrollment</DialogTitle>
              <DialogDescription>
                Issues a one-time enrollment token that links the user&apos;s personal device to a NAC profile.
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-2">
              <div>
                <FieldLabel>User name</FieldLabel>
                <Input value={userName} onChange={(e) => setUserName(e.target.value)} placeholder="socuser" className="font-mono text-xs" />
                <FieldError msg={fields.userName} />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <FieldLabel hint="optional">Device ID</FieldLabel>
                  <Input
                    type="number"
                    min={1}
                    value={deviceId}
                    onChange={(e) => setDeviceId(e.target.value)}
                    placeholder="—"
                    className="font-mono text-xs"
                  />
                  <FieldError msg={fields.deviceId} />
                </div>
                <div>
                  <FieldLabel hint="hours (1–720)">Token TTL</FieldLabel>
                  <Input
                    type="number"
                    min={1}
                    max={720}
                    value={ttlHours}
                    onChange={(e) => setTtlHours(e.target.value)}
                    className="font-mono text-xs"
                  />
                  <FieldError msg={fields.ttlHours} />
                </div>
              </div>
              {err && <p className="text-xs text-rose-600">{err}</p>}
            </div>
            <DialogFooter>
              <Button variant="ghost" onClick={props.onClose}>
                Cancel
              </Button>
              <Button className="bg-red-700 text-white hover:bg-red-800" disabled={enroll.isPending || !userName.trim()} onClick={submit}>
                {enroll.isPending ? "Issuing…" : "Issue token"}
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

function ByodCard() {
  const queryClient = useQueryClient();
  const byodQuery = useQuery({ queryKey: [...ROOT_KEY, "byod"], queryFn: identityApi.listByod });
  const rows = byodQuery.data ?? [];

  const [addOpen, setAddOpen] = useState(false);
  const [revoking, setRevoking] = useState<{ id: number; userName: string } | null>(null);

  const approve = useMutation({
    mutationFn: (id: number) => identityApi.approveByod(id),
    onSuccess: (r) => {
      toastOk("Enrollment approved", `${r.userName} can now enroll the device`);
      invalidateAll(queryClient);
    },
    onError: (e) => toastErr(e, "Approve failed"),
  });

  const revoke = useMutation({
    mutationFn: (id: number) => identityApi.revokeByod(id),
    onSuccess: () => {
      toastOk("Enrollment revoked");
      setRevoking(null);
      invalidateAll(queryClient);
    },
    onError: (e) => toastErr(e, "Revoke failed"),
  });

  return (
    <Card>
      <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2 space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.Smartphone className="h-4 w-4 text-red-700 dark:text-red-500" />
          BYOD Onboarding
          <span className="text-xs font-normal text-zinc-400">{rows.length} enrollment{rows.length === 1 ? "" : "s"}</span>
        </CardTitle>
        <Button size="sm" className="h-8 bg-red-700 text-white hover:bg-red-800" onClick={() => setAddOpen(true)}>
          <Icons.Plus className="mr-1 h-3.5 w-3.5" /> New enrollment
        </Button>
      </CardHeader>
      <CardContent className="p-0">
        {byodQuery.isError ? (
          <div className="p-4">
            <QueryError error={byodQuery.error} onRetry={() => void byodQuery.refetch()} />
          </div>
        ) : byodQuery.isLoading ? (
          <TableSkeleton rows={3} cols={5} />
        ) : rows.length === 0 ? (
          <EmptyBlock
            icon={<Icons.Smartphone className="h-6 w-6" />}
            title="No BYOD enrollments"
            description="Issue a one-time enrollment token so users can onboard personal devices onto profiled VLANs."
            action={
              <Button size="sm" className="bg-red-700 text-white hover:bg-red-800" onClick={() => setAddOpen(true)}>
                <Icons.Plus className="mr-1 h-3.5 w-3.5" /> New enrollment
              </Button>
            }
          />
        ) : (
          <div className={SCROLL}>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead className="w-24">Device</TableHead>
                  <TableHead className="w-32">Status</TableHead>
                  <TableHead className="w-28">Expires</TableHead>
                  <TableHead className="w-40 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((b) => (
                  <TableRow key={b.id}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-red-600/10 text-[10px] font-semibold text-red-700 dark:text-red-500">
                          {b.userName.slice(0, 2).toUpperCase()}
                        </span>
                        <span className="font-mono text-xs font-medium">{b.userName}</span>
                      </div>
                    </TableCell>
                    <TableCell className="text-xs text-zinc-500">{b.deviceId != null ? `#${b.deviceId}` : "—"}</TableCell>
                    <TableCell>
                      <ByodStatusBadge status={b.status} />
                    </TableCell>
                    <TableCell className="text-xs text-zinc-500">{fmtRelative(b.expiresAt)}</TableCell>
                    <TableCell>
                      <div className="flex justify-end gap-1.5">
                        {b.status === "pending" && (
                          <>
                            <Button
                              variant="outline"
                              size="sm"
                              className="h-7 gap-1 border-red-600/40 px-2 text-[11px] text-red-700 hover:bg-red-600/10 dark:text-red-500"
                              disabled={approve.isPending && approve.variables === b.id}
                              aria-label={`Approve enrollment for ${b.userName}`}
                              onClick={() => approve.mutate(b.id)}
                            >
                              {approve.isPending && approve.variables === b.id ? (
                                <Icons.Loader2 className="h-3 w-3 animate-spin" />
                              ) : (
                                <Icons.Check className="h-3 w-3" />
                              )}
                              Approve
                            </Button>
                            <Button
                              variant="outline"
                              size="sm"
                              className="h-7 gap-1 border-rose-600/60 px-2 text-[11px] text-rose-500 hover:bg-rose-600/10 hover:text-rose-600"
                              aria-label={`Revoke enrollment for ${b.userName}`}
                              onClick={() => setRevoking({ id: b.id, userName: b.userName })}
                            >
                              <Icons.X className="h-3 w-3" />
                              Deny
                            </Button>
                          </>
                        )}
                        {b.status !== "pending" && <span className="text-xs text-zinc-400">—</span>}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
        <p className="border-t border-zinc-200 px-4 py-2 text-[11px] text-zinc-400 dark:border-zinc-800">
          Enrollment tokens are one-time secrets — issued once, never displayed again.
        </p>
      </CardContent>

      {addOpen && <EnrollDialog onClose={() => setAddOpen(false)} />}
      <ConfirmDialog
        open={revoking !== null}
        onOpenChange={(open) => !open && setRevoking(null)}
        title={`Revoke enrollment for “${revoking?.userName ?? ""}”?`}
        description="The one-time token stops working immediately. Pending enrollments only."
        loading={revoke.isPending}
        onConfirm={() => revoking && revoke.mutate(revoking.id)}
      />
    </Card>
  );
}

// ── main view ───────────────────────────────────────────────────────────────

export function NacView() {
  return (
    <div className="space-y-4">
      <StatsStrip />
      <ProfilesCard />
      <DevicesCard />
      <ByodCard />
    </div>
  );
}
