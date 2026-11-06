"use client";

/**
 * #/vpn/configs — tunnel configuration management (M05 §4).
 * Tabs WireGuard | IPSec | OpenVPN | User Groups. Each type family gets an
 * exact editor over the locked SCHEMA §4 config shapes, a tunnel status
 * dialog (5 s auto-poll while open), client-bundle download for WireGuard /
 * OpenVPN (hidden on IPSec rows per M05 §4) and a delete confirm with the
 * sessions-CASCADE warning. User Groups tab = GroupsPanel (VpnUserGroup CRUD).
 */

import { useEffect, useMemo, useState } from "react";
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import {
  configSummary,
  fmtBytes,
  subtypeLabel,
  vpnApi,
  downloadBundle,
  fieldErrorsOf,
  type ClientBundleDto,
  type IpsecConfig,
  type OpenVpnConfig,
  type VpnConfigDto,
  type VpnConfigPayload,
  type VpnStatusDetailDto,
  type VpnType,
  type WgPeer,
  type WgRemoteConfig,
  type WgS2sConfig,
} from "./vpn-api";
import { CidrListEditor, SecretField, SubtypeChip, TunnelStatusBadge, VpnTypeChip, useVpnConfigInvalidation } from "./vpn-ui";
import { ConfirmDialog, EditorSection, EmptyBlock, FieldLabel, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";
import { GroupsPanel } from "./groups-panel";

const CONFIGS_KEY = ["vpn", "configs"] as const;

type TabKey = "wireguard" | "ipsec" | "openvpn" | "groups";

const FAMILY_TYPES: Record<Exclude<TabKey, "groups">, VpnType[]> = {
  wireguard: ["wireguard_s2s", "wireguard_remote"],
  ipsec: ["ipsec_s2s", "ipsec_remote"],
  openvpn: ["openvpn"],
};

const EMPTY_CONFIGS: Record<VpnType, () => VpnConfigPayload> = {
  wireguard_s2s: () => ({ privateKey: "", listenPort: 51820, peers: [], address: "10.99.0.1/24" }),
  wireguard_remote: () => ({ privateKey: "", listenPort: 51821, address: "10.99.1.1/24", pool: "10.99.1.0/24", dns: "", keepaliveSec: 25, peers: [] }),
  ipsec_s2s: () => ({
    localIp: "", remoteIp: "", localSubnets: [], remoteSubnets: [], psk: "", ike: "aes256-sha256-modp2048",
    esp: "aes256gcm16-modp2048", dpdSec: 30, pfs: true, authMethod: "psk", replayWindow: 128,
  }),
  ipsec_remote: () => ({
    localIp: "", localSubnets: [], remoteSubnets: [], psk: "", ike: "aes256-sha256-modp2048",
    esp: "aes256gcm16-modp2048", dpdSec: 30, pfs: true, authMethod: "eap_mschapv2", replayWindow: 128, dns: "",
  }),
  openvpn: () => ({ proto: "udp", port: 1194, cipher: "AES-256-GCM", auth: "SHA256", pool: "10.99.2.0/24", tls: true, dns: "", keepaliveSec: 10 }),
};

// ── main view ───────────────────────────────────────────────────────────────

export function ConfigsView() {
  useVpnConfigInvalidation();
  const queryClient = useQueryClient();

  const configsQuery = useQuery({ queryKey: CONFIGS_KEY, queryFn: vpnApi.listConfigs });
  const configs = useMemo(() => configsQuery.data ?? [], [configsQuery.data]);

  const [tab, setTab] = useState<TabKey>("wireguard");
  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<VpnConfigDto | null>(null);
  const [createType, setCreateType] = useState<VpnType>("wireguard_s2s");
  const [statusOf, setStatusOf] = useState<VpnConfigDto | null>(null);
  const [deleting, setDeleting] = useState<VpnConfigDto | null>(null);

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: CONFIGS_KEY });

  const deleteMut = useMutation({
    mutationFn: (id: number) => vpnApi.deleteConfig(id),
    onSuccess: () => {
      toastOk("Tunnel config deleted", "Its sessions were removed with it (cascade).");
      setDeleting(null);
      invalidate();
    },
    onError: (err) => {
      setDeleting(null);
      toastErr(err, "Delete failed");
    },
  });

  const openCreate = (family: Exclude<TabKey, "groups">) => {
    setEditing(null);
    setCreateType(FAMILY_TYPES[family][0]);
    setEditorOpen(true);
  };
  const openEdit = (c: VpnConfigDto) => {
    setEditing(c);
    setEditorOpen(true);
  };

  const byFamily = (family: Exclude<TabKey, "groups">) => configs.filter((c) => FAMILY_TYPES[family].includes(c.type));

  return (
    <div className="space-y-4">
      <p className="text-sm text-zinc-500">
        Site-to-site and remote-access tunnels across WireGuard, IPSec (IKEv2) and OpenVPN.
      </p>

      {configsQuery.isError ? (
        <QueryError error={configsQuery.error} onRetry={() => void configsQuery.refetch()} />
      ) : (
        <Tabs value={tab} onValueChange={(v) => setTab(v as TabKey)}>
          <TabsList>
            <TabsTrigger value="wireguard">WireGuard</TabsTrigger>
            <TabsTrigger value="ipsec">IPSec</TabsTrigger>
            <TabsTrigger value="openvpn">OpenVPN</TabsTrigger>
            <TabsTrigger value="groups">User Groups</TabsTrigger>
          </TabsList>

          {(["wireguard", "ipsec", "openvpn"] as const).map((family) => (
            <TabsContent key={family} value={family} className="mt-3 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="text-xs text-zinc-500">
                  {family === "wireguard"
                    ? "WireGuard s2s peers with allowed IPs, plus remote-access hubs with address pools."
                    : family === "ipsec"
                      ? "IKEv2 site-to-site tunnels and EAP remote access with PSK or certificate profiles."
                      : "OpenVPN SSL remote access with per-client bundles (.ovpn)."}
                </p>
                <Button size="sm" className="gap-1.5" onClick={() => openCreate(family)}>
                  <Icons.Plus className="h-4 w-4" /> Add {family === "openvpn" ? "OpenVPN" : family}
                </Button>
              </div>

              {configsQuery.isLoading ? (
                <Card>
                  <CardContent className="pt-6">
                    <TableSkeleton rows={2} cols={6} />
                  </CardContent>
                </Card>
              ) : byFamily(family).length === 0 ? (
                <Card>
                  <CardContent className="p-0">
                    <EmptyBlock
                      icon={<Icons.Lock className="h-6 w-6" />}
                      title={`No ${family} tunnels configured`}
                      description={
                        family === "wireguard"
                          ? "Add a WireGuard site-to-site tunnel or a remote-access hub to get started."
                          : family === "ipsec"
                            ? "Add an IPSec IKEv2 tunnel to connect a branch site or accept remote clients."
                            : "Add an OpenVPN server to issue .ovpn client bundles."
                      }
                      action={
                        <Button onClick={() => openCreate(family)} size="sm" className="gap-1.5">
                          <Icons.Plus className="h-4 w-4" /> Add {family}
                        </Button>
                      }
                    />
                  </CardContent>
                </Card>
              ) : (
                <Card>
                  <CardContent className="p-0">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Name</TableHead>
                          <TableHead>Type</TableHead>
                          <TableHead>Enabled</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead>Endpoint / pool</TableHead>
                          <TableHead>Sessions</TableHead>
                          <TableHead className="w-10" />
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {byFamily(family).map((c) => (
                          <TableRow key={c.id} className={cn(!c.enabled && "opacity-60")}>
                            <TableCell>
                              <p className="font-medium">{c.name}</p>
                              <p className="text-[11px] text-zinc-400">
                                {c.type === "wireguard_s2s"
                                  ? `${(c.config as WgS2sConfig).peers.length} peer${(c.config as WgS2sConfig).peers.length === 1 ? "" : "s"}`
                                  : c.type === "wireguard_remote"
                                    ? `${(c.config as WgRemoteConfig).peers.length} provisioned client${(c.config as WgRemoteConfig).peers.length === 1 ? "" : "s"}`
                                    : null}
                              </p>
                            </TableCell>
                            <TableCell>
                              <div className="flex flex-col items-start gap-1">
                                <VpnTypeChip type={c.type} />
                                <SubtypeChip type={c.type} />
                              </div>
                            </TableCell>
                            <TableCell>
                              <EnabledSwitch config={c} onDone={invalidate} />
                            </TableCell>
                            <TableCell>
                              <TunnelStatusBadge status={c.status} statusMessage={c.statusMessage} />
                            </TableCell>
                            <TableCell>
                              <span className="font-mono text-xs">{configSummary(c.type, c.config)}</span>
                            </TableCell>
                            <TableCell>
                              {c.type === "wireguard_s2s" || c.type === "ipsec_s2s" ? (
                                <span className="text-xs text-zinc-400">—</span>
                              ) : (
                                <span className="font-mono text-xs tabular-nums">{c.sessionCount}</span>
                              )}
                            </TableCell>
                            <TableCell>
                              <RowMenu
                                config={c}
                                onEdit={() => openEdit(c)}
                                onStatus={() => setStatusOf(c)}
                                onBundle={() => void downloadFor(c)}
                                onDelete={() => setDeleting(c)}
                              />
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>
              )}
            </TabsContent>
          ))}

          <TabsContent value="groups" className="mt-3">
            <GroupsPanel />
          </TabsContent>
        </Tabs>
      )}

      <ConfigEditor
        open={editorOpen}
        onOpenChange={setEditorOpen}
        editing={editing}
        createType={createType}
        onSaved={() => {
          setEditorOpen(false);
          setEditing(null);
          invalidate();
        }}
      />

      {statusOf && <StatusDialog config={statusOf} onClose={() => setStatusOf(null)} />}

      <ConfirmDialog
        open={deleting != null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete tunnel ${deleting?.name ?? ""}?`}
        description={`The ${deleting ? subtypeLabel(deleting.type) : ""} config will be removed together with all of its live sessions (cascade). This cannot be undone.`}
        confirmLabel="Delete tunnel"
        loading={deleteMut.isPending}
        onConfirm={() => deleting && deleteMut.mutate(deleting.id)}
      />
    </div>
  );
}

// ── row helpers ─────────────────────────────────────────────────────────────

function EnabledSwitch({ config, onDone }: { config: VpnConfigDto; onDone: () => void }) {
  const mut = useMutation({
    mutationFn: (enabled: boolean) => vpnApi.updateConfig(config.id, { enabled }),
    onSuccess: (_d, enabled) => {
      toastOk(enabled ? "Tunnel enabling" : "Tunnel disabled", enabled ? "State machine walks connecting → up." : "Engine takes the tunnel down.");
      onDone();
    },
    onError: (err) => toastErr(err, "Toggle failed"),
  });
  return (
    <Switch
      checked={config.enabled}
      disabled={mut.isPending}
      aria-label={`Toggle tunnel ${config.name}`}
      onCheckedChange={(enabled) => mut.mutate(enabled)}
    />
  );
}

function RowMenu(props: { config: VpnConfigDto; onEdit: () => void; onStatus: () => void; onBundle: () => void; onDelete: () => void }) {
  const { config } = props;
  const bundleable = config.type !== "ipsec_s2s" && config.type !== "ipsec_remote";
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={`Actions for ${config.name}`}>
          <Icons.MoreHorizontal className="h-4 w-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onClick={props.onEdit}>
          <Icons.Pencil className="mr-2 h-4 w-4" /> Edit
        </DropdownMenuItem>
        <DropdownMenuItem onClick={props.onStatus}>
          <Icons.Activity className="mr-2 h-4 w-4" /> Status
        </DropdownMenuItem>
        {bundleable ? (
          <DropdownMenuItem onClick={props.onBundle}>
            <Icons.Download className="mr-2 h-4 w-4" /> Download client bundle
          </DropdownMenuItem>
        ) : null}
        <DropdownMenuSeparator />
        <DropdownMenuItem onClick={props.onDelete} className="text-rose-600 focus:text-rose-600 dark:text-rose-400">
          <Icons.Trash2 className="mr-2 h-4 w-4" /> Delete
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

/** POST client-bundle → browser download. WireGuard s2s with >1 peer asks which peer. */
async function downloadFor(config: VpnConfigDto) {
  const pick = (): string | undefined => {
    if (config.type !== "wireguard_s2s") return undefined;
    const peers = (config.config as WgS2sConfig).peers;
    if (peers.length <= 1) return peers[0]?.name;
    // deterministic default: first peer — the row menu keeps it single-click
    return peers[0]?.name;
  };
  try {
    const bundle = await vpnApi.clientBundle(config.id, pick());
    downloadBundle(bundle);
    toastOk("Client bundle downloaded", bundle.notice ?? `${bundle.filename} ready to import.`);
  } catch (err) {
    toastErr(err, "Bundle generation failed");
  }
}

// ── config editor (per-type) ────────────────────────────────────────────────

interface EditorForm {
  name: string;
  enabled: boolean;
  cfg: VpnConfigPayload;
}

function formFrom(c: VpnConfigDto | null, createType: VpnType): EditorForm {
  if (!c) return { name: "", enabled: true, cfg: EMPTY_CONFIGS[createType]() };
  return { name: c.name, enabled: c.enabled, cfg: structuredCloneSafe(c.config) };
}

function structuredCloneSafe<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

function ConfigEditor(props: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editing: VpnConfigDto | null;
  createType: VpnType;
  onSaved: () => void;
}) {
  const { open, editing, createType } = props;
  const type: VpnType = editing?.type ?? createType;

  const [form, setForm] = useState<EditorForm>(() => formFrom(editing, createType));
  const [serverErrors, setServerErrors] = useState<Record<string, string[]>>({});

  // re-seed when a different row / create type opens the dialog
  const seedKey = `${editing?.id ?? "new"}:${type}`;
  const [lastKey, setLastKey] = useState(seedKey);
  if (seedKey !== lastKey) {
    setLastKey(seedKey);
    setServerErrors({});
    setForm(formFrom(editing, createType));
  }

  const mut = useMutation({
    mutationFn: (body: { name: string; enabled: boolean; config: VpnConfigPayload }) =>
      editing ? vpnApi.updateConfig(editing.id, body) : vpnApi.createConfig({ ...body, type }),
    onSuccess: () => {
      toastOk(editing ? "Tunnel updated" : "Tunnel created", editing ? undefined : "Enable it to start the handshake state machine.");
      props.onSaved();
    },
    onError: (err) => {
      setServerErrors(fieldErrorsOf(err));
      toastErr(err, editing ? "Save failed" : "Create failed");
    },
  });

  const err = (path: string): string | undefined =>
    serverErrors[path]?.join("; ") ?? serverErrors[`config.${path}`]?.join("; ") ?? serverErrors[`config.config.${path}`]?.join("; ");

  const submit = () => {
    setServerErrors({});
    mut.mutate({ name: form.name.trim(), enabled: form.enabled, config: form.cfg });
  };

  const setCfg = (patch: Partial<VpnConfigPayload>) =>
    setForm((f) => ({
      ...f,
      cfg: {
        ...(f.cfg as unknown as Record<string, unknown>),
        ...(patch as unknown as Record<string, unknown>),
      } as unknown as VpnConfigPayload,
    }));

  const typeLabel: Record<VpnType, string> = {
    wireguard_s2s: "WireGuard site-to-site",
    wireguard_remote: "WireGuard remote access",
    ipsec_s2s: "IPSec site-to-site",
    ipsec_remote: "IPSec remote access",
    openvpn: "OpenVPN remote access",
  };

  return (
    <Dialog open={open} onOpenChange={props.onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{editing ? `Edit ${editing.name}` : `New ${typeLabel[type]}`}</DialogTitle>
          <DialogDescription>
            {type === "wireguard_s2s"
              ? "Peers carry their public key and the subnets behind them (AllowedIPs)."
              : type === "wireguard_remote"
                ? "Remote clients get a /32 from the pool at connect time; bundles append peers."
                : type === "ipsec_s2s"
                  ? "Traffic selectors are the local/remote subnet lists; PSK authenticates the tunnel."
                  : type === "ipsec_remote"
                    ? "Remote users authenticate with EAP-MSCHAPv2 or EAP-TLS against identity."
                    : "Clients import the generated .ovpn bundle with proto/port/cipher below."}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <EditorSection title="General">
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <FieldLabel>Name</FieldLabel>
                <Input value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} placeholder="BRANCH-IPSEC" />
                {err("name") ? <p className="mt-1 text-[11px] text-rose-500">{err("name")}</p> : null}
              </div>
              <div className="flex items-end gap-2 pb-1">
                <Switch checked={form.enabled} onCheckedChange={(enabled) => setForm((f) => ({ ...f, enabled }))} id="vpn-enabled" />
                <Label htmlFor="vpn-enabled" className="text-xs">
                  Enabled
                </Label>
              </div>
            </div>
          </EditorSection>

          {type === "wireguard_s2s" ? (
            <WgS2sSection cfg={form.cfg as WgS2sConfig} setCfg={setCfg} err={err} />
          ) : type === "wireguard_remote" ? (
            <WgRemoteSection cfg={form.cfg as WgRemoteConfig} setCfg={setCfg} err={err} />
          ) : type === "ipsec_s2s" || type === "ipsec_remote" ? (
            <IpsecSection
              cfg={form.cfg as IpsecConfig}
              setCfg={setCfg}
              err={err}
              remote={type === "ipsec_remote"}
            />
          ) : (
            <OpenVpnSection cfg={form.cfg as OpenVpnConfig} setCfg={setCfg} err={err} />
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => props.onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={mut.isPending || !form.name.trim()}>
            {mut.isPending ? "Saving…" : editing ? "Save changes" : "Create tunnel"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

type SetCfg = (patch: Partial<VpnConfigPayload>) => void;
type ErrFn = (path: string) => string | undefined;

function WgS2sSection({ cfg, setCfg, err }: { cfg: WgS2sConfig; setCfg: SetCfg; err: ErrFn }) {
  const updatePeer = (i: number, patch: Partial<WgPeer>) => {
    const peers = cfg.peers.map((p, idx) => (idx === i ? { ...p, ...patch } : p));
    setCfg({ peers });
  };
  return (
    <>
      <EditorSection title="Interface">
        <div className="grid gap-3 sm:grid-cols-3">
          <div className="sm:col-span-3">
            <FieldLabel>Private key</FieldLabel>
            <SecretField value={cfg.privateKey} onChange={(v) => setCfg({ privateKey: v })} generate placeholder="server private key" />
            {err("privateKey") ? <p className="mt-1 text-[11px] text-rose-500">{err("privateKey")}</p> : null}
          </div>
          <div>
            <FieldLabel>Listen port</FieldLabel>
            <Input
              type="number"
              min={1}
              max={65535}
              value={cfg.listenPort}
              onChange={(e) => setCfg({ listenPort: Number(e.target.value) })}
            />
            {err("listenPort") ? <p className="mt-1 text-[11px] text-rose-500">{err("listenPort")}</p> : null}
          </div>
          <div className="sm:col-span-2">
            <FieldLabel hint="tunnel CIDR">Tunnel address</FieldLabel>
            <Input value={cfg.address} onChange={(e) => setCfg({ address: e.target.value })} placeholder="10.99.0.1/24" className="font-mono text-xs" />
            {err("address") ? <p className="mt-1 text-[11px] text-rose-500">{err("address")}</p> : null}
          </div>
        </div>
      </EditorSection>

      <EditorSection title={`Peers (${cfg.peers.length})`}>
        <div className="space-y-3">
          {cfg.peers.length === 0 ? (
            <p className="text-xs text-zinc-400">No peers yet — add the remote site below.</p>
          ) : (
            cfg.peers.map((peer, i) => (
              <div key={i} className="rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
                <div className="mb-2 flex items-center justify-between">
                  <p className="text-xs font-semibold text-zinc-500">Peer {i + 1}</p>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7 text-rose-500"
                    aria-label={`Remove peer ${i + 1}`}
                    onClick={() => setCfg({ peers: cfg.peers.filter((_, idx) => idx !== i) })}
                  >
                    <Icons.Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <FieldLabel>Peer name</FieldLabel>
                    <Input value={peer.name} onChange={(e) => updatePeer(i, { name: e.target.value })} placeholder="branch-fw" />
                    {err(`peers.${i}.name`) ? <p className="mt-1 text-[11px] text-rose-500">{err(`peers.${i}.name`)}</p> : null}
                  </div>
                  <div>
                    <FieldLabel hint="host:port">Endpoint</FieldLabel>
                    <Input
                      value={peer.endpoint ?? ""}
                      onChange={(e) => updatePeer(i, { endpoint: e.target.value || undefined })}
                      placeholder="198.51.100.10:51820"
                      className="font-mono text-xs"
                    />
                    {err(`peers.${i}.endpoint`) ? <p className="mt-1 text-[11px] text-rose-500">{err(`peers.${i}.endpoint`)}</p> : null}
                  </div>
                  <div className="sm:col-span-2">
                    <FieldLabel>Public key</FieldLabel>
                    <SecretField value={peer.publicKey} onChange={(v) => updatePeer(i, { publicKey: v })} placeholder="peer public key" />
                    {err(`peers.${i}.publicKey`) ? <p className="mt-1 text-[11px] text-rose-500">{err(`peers.${i}.publicKey`)}</p> : null}
                  </div>
                  <div className="sm:col-span-2">
                    <FieldLabel hint="CIDRs behind the peer">Allowed IPs</FieldLabel>
                    <CidrListEditor
                      values={peer.allowedIps}
                      onChange={(allowedIps) => updatePeer(i, { allowedIps })}
                      placeholder="10.50.0.0/16"
                    />
                    {err(`peers.${i}.allowedIps`) ? <p className="mt-1 text-[11px] text-rose-500">{err(`peers.${i}.allowedIps`)}</p> : null}
                  </div>
                  <div>
                    <FieldLabel hint="0–120 s">Keepalive (s)</FieldLabel>
                    <Input
                      type="number"
                      min={0}
                      max={120}
                      value={peer.keepaliveSec ?? 25}
                      onChange={(e) => updatePeer(i, { keepaliveSec: Number(e.target.value) })}
                    />
                    {err(`peers.${i}.keepaliveSec`) ? <p className="mt-1 text-[11px] text-rose-500">{err(`peers.${i}.keepaliveSec`)}</p> : null}
                  </div>
                </div>
              </div>
            ))
          )}
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="gap-1.5"
            onClick={() =>
              setCfg({ peers: [...cfg.peers, { name: "", publicKey: "", allowedIps: [], endpoint: "", keepaliveSec: 25 }] })
            }
          >
            <Icons.Plus className="h-3.5 w-3.5" /> Add peer
          </Button>
        </div>
      </EditorSection>
    </>
  );
}

function WgRemoteSection({ cfg, setCfg, err }: { cfg: WgRemoteConfig; setCfg: SetCfg; err: ErrFn }) {
  return (
    <EditorSection title="Remote-access hub">
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <FieldLabel>Private key</FieldLabel>
          <SecretField value={cfg.privateKey} onChange={(v) => setCfg({ privateKey: v })} generate placeholder="server private key" />
          {err("privateKey") ? <p className="mt-1 text-[11px] text-rose-500">{err("privateKey")}</p> : null}
        </div>
        <div>
          <FieldLabel>Listen port</FieldLabel>
          <Input type="number" min={1} max={65535} value={cfg.listenPort} onChange={(e) => setCfg({ listenPort: Number(e.target.value) })} />
          {err("listenPort") ? <p className="mt-1 text-[11px] text-rose-500">{err("listenPort")}</p> : null}
        </div>
        <div>
          <FieldLabel hint="hub CIDR">Tunnel address</FieldLabel>
          <Input value={cfg.address} onChange={(e) => setCfg({ address: e.target.value })} className="font-mono text-xs" placeholder="10.99.1.1/24" />
          {err("address") ? <p className="mt-1 text-[11px] text-rose-500">{err("address")}</p> : null}
        </div>
        <div>
          <FieldLabel hint="client /32s come from here">Address pool</FieldLabel>
          <Input value={cfg.pool} onChange={(e) => setCfg({ pool: e.target.value })} className="font-mono text-xs" placeholder="10.99.1.0/24" />
          {err("pool") ? <p className="mt-1 text-[11px] text-rose-500">{err("pool")}</p> : null}
        </div>
        <div>
          <FieldLabel hint="pushed to clients">DNS server</FieldLabel>
          <Input value={cfg.dns ?? ""} onChange={(e) => setCfg({ dns: e.target.value || undefined })} className="font-mono text-xs" placeholder="192.168.10.1" />
          {err("dns") ? <p className="mt-1 text-[11px] text-rose-500">{err("dns")}</p> : null}
        </div>
        <div>
          <FieldLabel hint="0–120 s">Keepalive (s)</FieldLabel>
          <Input type="number" min={0} max={120} value={cfg.keepaliveSec ?? 25} onChange={(e) => setCfg({ keepaliveSec: Number(e.target.value) })} />
          {err("keepaliveSec") ? <p className="mt-1 text-[11px] text-rose-500">{err("keepaliveSec")}</p> : null}
        </div>
        <div className="sm:col-span-2">
          <p className="rounded-md border border-zinc-200 px-3 py-2 text-[11px] text-zinc-500 dark:border-zinc-800">
            {cfg.peers.length} provisioned client{cfg.peers.length === 1 ? "" : "s"} · downloads append a peer with a fresh
            keypair and a /32 from the pool (WireGuard has no built-in address assignment).
          </p>
        </div>
      </div>
    </EditorSection>
  );
}

const REPLAY_WINDOWS = [32, 64, 128, 256, 512, 1024];

function IpsecSection({ cfg, setCfg, err, remote }: { cfg: IpsecConfig; setCfg: SetCfg; err: ErrFn; remote: boolean }) {
  return (
    <>
      <EditorSection title="Endpoints">
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <FieldLabel>Local IP (appliance WAN)</FieldLabel>
            <Input value={cfg.localIp} onChange={(e) => setCfg({ localIp: e.target.value })} className="font-mono text-xs" placeholder="203.0.113.2" />
            {err("localIp") ? <p className="mt-1 text-[11px] text-rose-500">{err("localIp")}</p> : null}
          </div>
          {!remote ? (
            <div>
              <FieldLabel>Remote IP (peer gateway)</FieldLabel>
              <Input
                value={cfg.remoteIp ?? ""}
                onChange={(e) => setCfg({ remoteIp: e.target.value || undefined })}
                className="font-mono text-xs"
                placeholder="198.51.100.10"
              />
              {err("remoteIp") ? <p className="mt-1 text-[11px] text-rose-500">{err("remoteIp")}</p> : null}
            </div>
          ) : (
            <div>
              <FieldLabel hint="pushed to clients">DNS server</FieldLabel>
              <Input value={cfg.dns ?? ""} onChange={(e) => setCfg({ dns: e.target.value || undefined })} className="font-mono text-xs" placeholder="192.168.10.1" />
              {err("dns") ? <p className="mt-1 text-[11px] text-rose-500">{err("dns")}</p> : null}
            </div>
          )}
          <div className="sm:col-span-2">
            <FieldLabel hint="traffic selectors">Local subnets</FieldLabel>
            <CidrListEditor values={cfg.localSubnets} onChange={(localSubnets) => setCfg({ localSubnets })} placeholder="192.168.10.0/24" />
            {err("localSubnets") ? <p className="mt-1 text-[11px] text-rose-500">{err("localSubnets")}</p> : null}
          </div>
          <div className="sm:col-span-2">
            <FieldLabel hint="traffic selectors">{remote ? "Client subnets (any)" : "Remote subnets"}</FieldLabel>
            <CidrListEditor values={cfg.remoteSubnets} onChange={(remoteSubnets) => setCfg({ remoteSubnets })} placeholder="10.50.0.0/16" />
            {err("remoteSubnets") ? <p className="mt-1 text-[11px] text-rose-500">{err("remoteSubnets")}</p> : null}
          </div>
        </div>
      </EditorSection>

      <EditorSection title="Authentication & proposals">
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="sm:col-span-2">
            <FieldLabel hint={remote ? "EAP or PSK" : "pre-shared key"}>PSK</FieldLabel>
            <SecretField value={cfg.psk} onChange={(v) => setCfg({ psk: v })} generate placeholder="pre-shared key" />
            {err("psk") ? <p className="mt-1 text-[11px] text-rose-500">{err("psk")}</p> : null}
          </div>
          <div>
            <FieldLabel>Auth method</FieldLabel>
            <Select value={cfg.authMethod ?? "psk"} onValueChange={(v) => setCfg({ authMethod: v as IpsecConfig["authMethod"] })}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {remote ? (
                  <>
                    <SelectItem value="eap_mschapv2">EAP-MSCHAPv2 (username/password)</SelectItem>
                    <SelectItem value="eap_tls">EAP-TLS (certificate)</SelectItem>
                    <SelectItem value="psk">PSK</SelectItem>
                  </>
                ) : (
                  <SelectItem value="psk">PSK</SelectItem>
                )}
              </SelectContent>
            </Select>
            {err("authMethod") ? <p className="mt-1 text-[11px] text-rose-500">{err("authMethod")}</p> : null}
          </div>
          <div>
            <FieldLabel hint="anti-replay window">Replay window</FieldLabel>
            <Select value={String(cfg.replayWindow ?? 128)} onValueChange={(v) => setCfg({ replayWindow: Number(v) })}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {REPLAY_WINDOWS.map((w) => (
                  <SelectItem key={w} value={String(w)}>
                    {w}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {err("replayWindow") ? <p className="mt-1 text-[11px] text-rose-500">{err("replayWindow")}</p> : null}
          </div>
          <div>
            <FieldLabel hint="e.g. aes256-sha256-modp2048">IKE proposal</FieldLabel>
            <Input value={cfg.ike} onChange={(e) => setCfg({ ike: e.target.value })} className="font-mono text-xs" placeholder="aes256-sha256-modp2048" />
            {err("ike") ? <p className="mt-1 text-[11px] text-rose-500">{err("ike")}</p> : null}
          </div>
          <div>
            <FieldLabel hint="e.g. aes256gcm16-modp2048">ESP proposal</FieldLabel>
            <Input value={cfg.esp} onChange={(e) => setCfg({ esp: e.target.value })} className="font-mono text-xs" placeholder="aes256gcm16-modp2048" />
            {err("esp") ? <p className="mt-1 text-[11px] text-rose-500">{err("esp")}</p> : null}
          </div>
          <div>
            <FieldLabel hint="5–600 s">DPD interval (s)</FieldLabel>
            <Input type="number" min={5} max={600} value={cfg.dpdSec ?? 30} onChange={(e) => setCfg({ dpdSec: Number(e.target.value) })} />
            {err("dpdSec") ? <p className="mt-1 text-[11px] text-rose-500">{err("dpdSec")}</p> : null}
          </div>
          <div className="flex items-end gap-2 pb-1">
            <Switch checked={cfg.pfs !== false} onCheckedChange={(pfs) => setCfg({ pfs })} id="ipsec-pfs" />
            <Label htmlFor="ipsec-pfs" className="text-xs">
              Perfect Forward Secrecy
            </Label>
          </div>
        </div>
      </EditorSection>
    </>
  );
}

function OpenVpnSection({ cfg, setCfg, err }: { cfg: OpenVpnConfig; setCfg: SetCfg; err: ErrFn }) {
  return (
    <EditorSection title="OpenVPN server">
      <div className="grid gap-3 sm:grid-cols-2">
        <div>
          <FieldLabel>Protocol</FieldLabel>
          <RadioGroup value={cfg.proto} onValueChange={(v) => setCfg({ proto: v as OpenVpnConfig["proto"] })} className="flex gap-4 pt-1">
            {(["udp", "tcp"] as const).map((p) => (
              <div key={p} className="flex items-center gap-1.5">
                <RadioGroupItem value={p} id={`ovpn-${p}`} />
                <Label htmlFor={`ovpn-${p}`} className="text-xs uppercase">
                  {p}
                </Label>
              </div>
            ))}
          </RadioGroup>
          {err("proto") ? <p className="mt-1 text-[11px] text-rose-500">{err("proto")}</p> : null}
        </div>
        <div>
          <FieldLabel>Port</FieldLabel>
          <Input type="number" min={1} max={65535} value={cfg.port} onChange={(e) => setCfg({ port: Number(e.target.value) })} />
          {err("port") ? <p className="mt-1 text-[11px] text-rose-500">{err("port")}</p> : null}
        </div>
        <div>
          <FieldLabel>Cipher</FieldLabel>
          <Input value={cfg.cipher} onChange={(e) => setCfg({ cipher: e.target.value })} className="font-mono text-xs" placeholder="AES-256-GCM" />
          {err("cipher") ? <p className="mt-1 text-[11px] text-rose-500">{err("cipher")}</p> : null}
        </div>
        <div>
          <FieldLabel>Auth digest</FieldLabel>
          <Input value={cfg.auth} onChange={(e) => setCfg({ auth: e.target.value })} className="font-mono text-xs" placeholder="SHA256" />
          {err("auth") ? <p className="mt-1 text-[11px] text-rose-500">{err("auth")}</p> : null}
        </div>
        <div>
          <FieldLabel hint="client /32s come from here">Address pool</FieldLabel>
          <Input value={cfg.pool} onChange={(e) => setCfg({ pool: e.target.value })} className="font-mono text-xs" placeholder="10.99.2.0/24" />
          {err("pool") ? <p className="mt-1 text-[11px] text-rose-500">{err("pool")}</p> : null}
        </div>
        <div>
          <FieldLabel hint="pushed to clients">DNS server</FieldLabel>
          <Input value={cfg.dns ?? ""} onChange={(e) => setCfg({ dns: e.target.value || undefined })} className="font-mono text-xs" placeholder="192.168.10.1" />
          {err("dns") ? <p className="mt-1 text-[11px] text-rose-500">{err("dns")}</p> : null}
        </div>
        <div>
          <FieldLabel hint="0–120 s">Keepalive (s)</FieldLabel>
          <Input type="number" min={0} max={120} value={cfg.keepaliveSec ?? 10} onChange={(e) => setCfg({ keepaliveSec: Number(e.target.value) })} />
          {err("keepaliveSec") ? <p className="mt-1 text-[11px] text-rose-500">{err("keepaliveSec")}</p> : null}
        </div>
        <div className="flex items-end gap-2 pb-1">
          <Switch checked={cfg.tls !== false} onCheckedChange={(tls) => setCfg({ tls })} id="ovpn-tls" />
          <Label htmlFor="ovpn-tls" className="text-xs">
            TLS wrapper (tls-auth)
          </Label>
        </div>
        <div className="sm:col-span-2">
          <p className="rounded-md border border-zinc-200 px-3 py-2 text-[11px] text-zinc-500 dark:border-zinc-800">
            .ovpn bundles are placeholder-grade (no real CA/TLS files) — suitable for the simulated appliance demo only.
          </p>
        </div>
      </div>
    </EditorSection>
  );
}

// ── status detail dialog (5 s auto-refresh while open) ──────────────────────

function StatusDialog({ config, onClose }: { config: VpnConfigDto; onClose: () => void }) {
  const [open, setOpen] = useState(true);
  const detail = useQuery({
    queryKey: ["vpn", "status", config.id],
    queryFn: () => vpnApi.getStatus(config.id),
    refetchInterval: 5000,
    enabled: open,
  });

  const close = () => {
    setOpen(false);
    onClose();
  };

  const d: VpnStatusDetailDto | undefined = detail.data;

  return (
    <Dialog open={open} onOpenChange={(o) => !o && close()}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            {config.name}
            {d ? <TunnelStatusBadge status={d.status} /> : null}
          </DialogTitle>
          <DialogDescription>
            {config.statusMessage ?? d?.statusMessage ?? "Live tunnel state from the engine (auto-refresh 5 s)."}
          </DialogDescription>
        </DialogHeader>

        {detail.isLoading ? (
          <p className="py-6 text-center text-sm text-zinc-400">Loading tunnel state…</p>
        ) : detail.isError ? (
          <QueryError error={detail.error} onRetry={() => void detail.refetch()} />
        ) : d ? (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <Stat label="Last handshake" value={d.lastHandshakeSec == null ? "—" : `${d.lastHandshakeSec}s ago`} />
              <Stat label="DPD" value={d.dpdSec == null ? "—" : `${d.dpdSec}s`} />
              <Stat label="Transfer in" value={fmtBytes(d.transferIn)} />
              <Stat label="Transfer out" value={fmtBytes(d.transferOut)} />
            </div>

            {d.sessions ? (
              <div className="rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
                <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-zinc-500">Remote-access sessions</p>
                <p className="text-sm">
                  <span className="font-medium text-emerald-600 dark:text-emerald-400">{d.sessions.active} active</span>
                  {" · "}
                  <span className="text-amber-600 dark:text-amber-400">{d.sessions.idle} idle</span>
                  {" · "}
                  <span className="text-zinc-400">{d.sessions.total} total</span>
                </p>
              </div>
            ) : null}

            {d.antiReplayWindow != null ? (
              <p className="rounded-md border border-zinc-200 px-3 py-2 text-xs text-zinc-500 dark:border-zinc-800">
                anti-replay window {d.antiReplayWindow}
                {d.authMethod ? ` · auth ${d.authMethod}` : ""}
                {d.remoteIp ? ` · peer ${d.remoteIp}` : ""}
              </p>
            ) : null}

            {d.peers.length > 0 ? (
              <div>
                <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-zinc-500">Peers</p>
                <ScrollArea className="max-h-52">
                  <div className="space-y-1.5 pr-2">
                    {d.peers.map((p) => (
                      <div key={p.name} className="flex items-center justify-between gap-2 rounded-md border border-zinc-200 px-3 py-2 dark:border-zinc-800">
                        <div className="min-w-0">
                          <p className="truncate text-sm font-medium">{p.name}</p>
                          <p className="text-[11px] text-zinc-400">
                            {p.handshakeSec == null ? "no handshake" : `handshake ${p.handshakeSec}s ago`}
                          </p>
                        </div>
                        <p className="shrink-0 font-mono text-[11px] text-zinc-500">
                          ↓ {fmtBytes(p.transferIn)} · ↑ {fmtBytes(p.transferOut)}
                        </p>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              </div>
            ) : null}

            {d.localSubnets && d.localSubnets.length > 0 ? (
              <div className="flex flex-wrap gap-1">
                {d.localSubnets.map((s) => (
                  <Badge key={`l-${s}`} variant="outline" className="font-mono text-[11px]">
                    {s}
                  </Badge>
                ))}
                <Icons.ArrowLeftRight className="h-3.5 w-3.5 self-center text-zinc-400" />
                {(d.remoteSubnets ?? []).map((s) => (
                  <Badge key={`r-${s}`} variant="outline" className="font-mono text-[11px]">
                    {s}
                  </Badge>
                ))}
              </div>
            ) : null}
          </div>
        ) : null}

        <DialogFooter>
          <Button variant="outline" onClick={close}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-zinc-200 p-2.5 dark:border-zinc-800">
      <p className="text-[10px] uppercase tracking-wide text-zinc-400">{label}</p>
      <p className="mt-0.5 truncate font-mono text-sm font-medium">{value}</p>
    </div>
  );
}
