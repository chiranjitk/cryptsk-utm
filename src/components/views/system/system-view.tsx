"use client";

/**
 * System settings view (M10 §4 `#/system/settings`) — 12 stacked cards:
 * health strip · General · NTP · SNMP · Hardening · Firmware · SSH keys ·
 * Notifications prefs · Logging retention · Advanced toggles · Policy
 * templates · Config history + diff viewer. Each card saves its own batch via
 * PUT /system/settings (audited, section system). SNMP community is
 * write-only: masked after save, the mask literal is ignored on PUT.
 */

import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
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
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import { ConfirmDialog, EmptyBlock, FieldLabel, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";
import { usePermissions, MASK, DiffViewer, JsonViewer, fmtDateTime, humanUptime } from "./system-ui";
import { systemApi, fieldErrorsOf, type SettingsEntry, type SettingsMap } from "./system-api";

// ── constants ───────────────────────────────────────────────────────────────

const TIMEZONES = [
  "Asia/Calcutta", "Asia/Karachi", "Asia/Dubai", "Asia/Singapore", "Asia/Tokyo",
  "Europe/London", "Europe/Berlin", "Europe/Paris", "America/New_York", "America/Chicago",
  "America/Los_Angeles", "America/Sao_Paulo", "Australia/Sydney", "UTC",
];

const CONFIG_SECTIONS = [
  "firewall", "nat", "interfaces", "routing", "dns", "dhcp",
  "vpn", "ips", "qos", "ha", "identity", "system",
] as const;

const RETENTION_TABLES = [
  { key: "firewall_logs", label: "Firewall logs", cap: 50_000 },
  { key: "ips_events", label: "IPS events", cap: 5_000 },
  { key: "audit_log", label: "Audit log", cap: 20_000 },
] as const;

// ── shared hooks ────────────────────────────────────────────────────────────

function useSettingsSave(onDone?: () => void) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (entries: SettingsEntry[]) => systemApi.putSettings(entries),
    onSuccess: (_data, entries) => {
      toastOk(
        "Settings saved",
        `${entries.length} setting${entries.length === 1 ? "" : "s"} written — audited, section system.`,
      );
      void queryClient.invalidateQueries({ queryKey: ["system"] });
      onDone?.();
    },
    onError: (err) => toastErr(err, "Save failed"),
  });
}

function settingOf<T>(settings: SettingsMap | undefined, category: string, key: string, fallback: T): T {
  const v = settings?.[category]?.[key];
  return (v === undefined || v === null ? fallback : v) as T;
}

function CardSkeleton({ rows = 3 }: { rows?: number }) {
  return (
    <Card>
      <CardContent className="space-y-3 p-6">
        <Skeleton className="h-5 w-48" />
        {Array.from({ length: rows }).map((_, i) => (
          <Skeleton key={i} className="h-9 w-full" />
        ))}
      </CardContent>
    </Card>
  );
}

// ── 1. health strip ─────────────────────────────────────────────────────────

function Gauge(props: { label: string; value: number; unit: string; warnAt: number; criticalAt: number }) {
  const tone =
    props.value >= props.criticalAt
      ? "bg-rose-500"
      : props.value >= props.warnAt
        ? "bg-amber-500"
        : "bg-red-700";
  const textTone =
    props.value >= props.criticalAt
      ? "text-rose-600 dark:text-rose-400"
      : props.value >= props.warnAt
        ? "text-amber-600 dark:text-amber-400"
        : "";
  return (
    <div className="space-y-1.5">
      <div className="flex items-baseline justify-between">
        <span className="text-xs text-zinc-500">{props.label}</span>
        <span className={cn("text-sm font-semibold tabular-nums", textTone)}>
          {props.value.toFixed(1)}
          {props.unit}
        </span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800">
        <div className={cn("h-full rounded-full transition-all", tone)} style={{ width: `${Math.min(100, props.value)}%` }} />
      </div>
      <p className="text-[10px] text-zinc-400">warn ≥ {props.warnAt}{props.unit} · crit ≥ {props.criticalAt}{props.unit}</p>
    </div>
  );
}

function HealthStripCard() {
  const { isAdmin } = usePermissions();
  const admin = isAdmin("system");
  const queryClient = useQueryClient();
  const status = useQuery({
    queryKey: ["system", "status"],
    queryFn: () => systemApi.getStatus(),
    refetchInterval: 5000,
  });
  const settings = useQuery({ queryKey: ["system", "settings"], queryFn: () => systemApi.getSettings() });
  const thresholds = settingOf(settings.data, "notifications", "thresholds", { cpuPct: 90, memPct: 90, diskPct: 85, tempC: 80 });

  const restart = useMutation({
    mutationFn: (name: string) => systemApi.restartService(name),
    onSuccess: (svc) => {
      toastOk(`Restarting ${svc.name}`, "Simulated apply (~2 s) — service returns to running shortly.");
      setTimeout(() => void queryClient.invalidateQueries({ queryKey: ["system", "status"] }), 2500);
    },
    onError: (err) => toastErr(err, "Restart failed"),
  });

  if (status.isError) return <QueryError error={status.error} onRetry={() => void status.refetch()} />;
  if (status.isLoading) return <CardSkeleton rows={2} />;
  const s = status.data!;

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between space-y-0">
        <div>
          <CardTitle className="flex items-center gap-2 text-base">
            <Icons.HeartPulse className="h-4.5 w-4.5 text-red-700 dark:text-red-500" />
            Appliance health
          </CardTitle>
          <CardDescription>
            {s.hostname} · firmware {s.firmwareVersion} · up {humanUptime(s.uptimeSec)}
          </CardDescription>
        </div>
        <Badge variant="outline" className="border-zinc-300 text-zinc-500 dark:border-zinc-700">
          plane: {s.dataPlane}
        </Badge>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Gauge label="CPU" value={s.cpuPct} unit="%" warnAt={thresholds.cpuPct} criticalAt={thresholds.cpuPct + 10} />
          <Gauge label="Memory" value={s.memPct} unit="%" warnAt={thresholds.memPct} criticalAt={thresholds.memPct + 10} />
          <Gauge label="Disk" value={s.diskPct} unit="%" warnAt={thresholds.diskPct} criticalAt={thresholds.diskPct + 10} />
          <Gauge label="Temperature" value={s.tempC} unit="°C" warnAt={thresholds.tempC} criticalAt={thresholds.tempC + 10} />
        </div>
        <div>
          <FieldLabel hint={admin ? undefined : "restart requires admin"}>Services</FieldLabel>
          <div className="flex flex-wrap gap-1.5">
            {s.services.map((svc) => {
              const stopped = svc.state === "stopped";
              const restarting = svc.state === "restarting";
              return (
                <span
                  key={svc.name}
                  className={cn(
                    "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs",
                    stopped
                      ? "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400"
                      : restarting
                        ? "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400"
                        : "border-zinc-200 text-zinc-600 dark:border-zinc-800 dark:text-zinc-300",
                  )}
                  title={svc.label}
                >
                  <span className={cn("h-2 w-2 rounded-full", stopped ? "bg-rose-500" : restarting ? "bg-amber-500 animate-pulse" : "bg-emerald-500")} />
                  {svc.name}
                  {admin ? (
                    <button
                      type="button"
                      aria-label={`Restart ${svc.name}`}
                      className="ml-0.5 rounded-sm p-0.5 hover:bg-zinc-200 dark:hover:bg-zinc-700"
                      onClick={() => restart.mutate(svc.name)}
                    >
                      <Icons.RotateCcw className="h-3 w-3" />
                    </button>
                  ) : null}
                </span>
              );
            })}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ── 2. general ──────────────────────────────────────────────────────────────

function GeneralCard({ settings }: { settings: SettingsMap | undefined }) {
  const [hostname, setHostname] = useState("");
  const [timezone, setTimezone] = useState("Asia/Calcutta");
  const seeded = useMemo(() => settingOf(settings, "general", "hostname", { value: "" }), [settings]);
  const seededTz = useMemo(() => settingOf(settings, "general", "timezone", { value: "Asia/Calcutta" }), [settings]);
  // re-seed when server settings arrive (render-time derived reset)
  const [prevSeed, setPrevSeed] = useState<{ h: typeof seeded; tz: typeof seededTz }>({ h: seeded, tz: seededTz });
  if (prevSeed.h !== seeded || prevSeed.tz !== seededTz) {
    setPrevSeed({ h: seeded, tz: seededTz });
    setHostname(seeded.value ?? "");
    setTimezone(seededTz.value ?? "Asia/Calcutta");
  }

  const save = useSettingsSave();
  const dirty = hostname !== (seeded.value ?? "") || timezone !== (seededTz.value ?? "");

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Icons.Type className="h-4.5 w-4.5 text-red-700 dark:text-red-500" /> General
        </CardTitle>
        <CardDescription>Hostname propagates to the topbar after the config fan-out</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-1.5">
            <FieldLabel hint="3-63 chars, DNS-safe">Hostname</FieldLabel>
            <Input value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="cryptsk-demo" />
          </div>
          <div className="space-y-1.5">
            <FieldLabel>Timezone (IANA)</FieldLabel>
            <Select value={timezone} onValueChange={setTimezone}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {TIMEZONES.map((tz) => (
                  <SelectItem key={tz} value={tz}>
                    {tz}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
        <div className="flex justify-end">
          <Button
            size="sm"
            disabled={!dirty || save.isPending}
            onClick={() =>
              save.mutate([
                { category: "general", key: "hostname", value: { value: hostname.trim() } },
                { category: "general", key: "timezone", value: { value: timezone } },
              ])
            }
          >
            {save.isPending ? "Saving…" : "Save general"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ── 3. NTP ──────────────────────────────────────────────────────────────────

function NtpCard({ settings }: { settings: SettingsMap | undefined }) {
  const seeded = useMemo(
    () => settingOf(settings, "general", "ntp", { enabled: true, servers: ["pool.debian.org"], synced: true, lastSyncAt: null }),
    [settings],
  );
  const [enabled, setEnabled] = useState(true);
  const [servers, setServers] = useState<string[]>([]);
  const [draft, setDraft] = useState("");
  // re-seed when server settings arrive (render-time derived reset)
  const [prevSeed, setPrevSeed] = useState(seeded);
  if (prevSeed !== seeded) {
    setPrevSeed(seeded);
    setEnabled(seeded.enabled ?? true);
    setServers(seeded.servers ?? []);
  }

  const save = useSettingsSave();
  const dirty = enabled !== seeded.enabled || JSON.stringify(servers) !== JSON.stringify(seeded.servers ?? []);
  const valid = servers.length > 0 && servers.every((s) => s.trim().length > 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Icons.Clock className="h-4.5 w-4.5 text-red-700 dark:text-red-500" /> System time (NTP)
        </CardTitle>
        <CardDescription>
          {seeded.synced ? (
            <span className="inline-flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-emerald-500" />
              synced — last {fmtDateTime(seeded.lastSyncAt ?? null)} <span className="text-zinc-400">(simulated sync in sandbox)</span>
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 text-amber-600 dark:text-amber-400">
              <span className="h-2 w-2 rounded-full bg-amber-500" /> not synced yet
            </span>
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex items-center justify-between">
          <Label htmlFor="ntp-enabled">NTP enabled</Label>
          <Switch id="ntp-enabled" checked={enabled} onCheckedChange={setEnabled} />
        </div>
        <div>
          <FieldLabel hint="hostname or IP — engine flips `synced` after the next tick">Servers</FieldLabel>
          <div className="mb-2 flex flex-wrap gap-1.5">
            {servers.map((srv) => (
              <Badge key={srv} variant="outline" className="gap-1 border-red-600/40 bg-red-600/10 font-mono text-xs text-red-700 dark:text-red-500">
                {srv}
                <button
                  type="button"
                  aria-label={`Remove ${srv}`}
                  className="rounded-sm p-0.5 hover:bg-red-600/20"
                  onClick={() => setServers((s) => s.filter((x) => x !== srv))}
                >
                  <Icons.X className="h-3 w-3" />
                </button>
              </Badge>
            ))}
            {servers.length === 0 ? <span className="text-xs text-zinc-400">at least one server required</span> : null}
          </div>
          <div className="flex gap-2">
            <Input
              value={draft}
              placeholder="time.google.com"
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && draft.trim()) {
                  setServers((s) => (s.includes(draft.trim()) ? s : [...s, draft.trim()]));
                  setDraft("");
                }
              }}
            />
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => {
                if (!draft.trim()) return;
                setServers((s) => (s.includes(draft.trim()) ? s : [...s, draft.trim()]));
                setDraft("");
              }}
            >
              <Icons.Plus className="h-4 w-4" /> Add
            </Button>
          </div>
        </div>
        <div className="flex justify-end">
          <Button
            size="sm"
            disabled={!dirty || !valid || save.isPending}
            onClick={() => save.mutate([{ category: "general", key: "ntp", value: { ...seeded, enabled, servers } }])}
          >
            {save.isPending ? "Saving…" : "Save NTP"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ── 4. SNMP ─────────────────────────────────────────────────────────────────

interface SnmpShape {
  enabled?: boolean;
  version?: string;
  community?: string;
  v3User?: string;
  authProtocol?: string;
  privProtocol?: string;
  port?: number;
  allowedIps?: string[];
}

function SnmpCard({ settings }: { settings: SettingsMap | undefined }) {
  const seeded = useMemo(
    () => settingOf<SnmpShape>(settings, "advanced", "snmp", { enabled: false, version: "v2c", port: 161, allowedIps: [] }),
    [settings],
  );
  const [form, setForm] = useState({
    enabled: false,
    version: "v2c" as "v2c" | "v3",
    community: "",
    v3User: "",
    authProtocol: "sha" as "sha" | "sha256",
    privProtocol: "aes" as "aes" | "des",
    port: 161,
    allowedIps: [] as string[],
  });
  const [ipDraft, setIpDraft] = useState("");
  const [errors, setErrors] = useState<Record<string, string[]>>({});
  // re-seed when server settings arrive (render-time derived reset)
  const [prevSeed, setPrevSeed] = useState(seeded);
  if (prevSeed !== seeded) {
    setPrevSeed(seeded);
    setForm({
      enabled: seeded.enabled ?? false,
      version: (seeded.version as "v2c" | "v3") ?? "v2c",
      community: "", // write-only: start blank; show mask hint when a community exists
      v3User: seeded.v3User ?? "",
      authProtocol: (seeded.authProtocol as "sha" | "sha256") ?? "sha",
      privProtocol: (seeded.privProtocol as "aes" | "des") ?? "aes",
      port: seeded.port ?? 161,
      allowedIps: seeded.allowedIps ?? [],
    });
  }

  const save = useSettingsSave();
  const hasStoredCommunity = typeof seeded.community === "string" && seeded.community.length > 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Icons.RadioTower className="h-4.5 w-4.5 text-red-700 dark:text-red-500" /> SNMP
        </CardTitle>
        <CardDescription>Appliance renders snmpd.conf — sandbox records config only</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex items-center justify-between">
          <Label htmlFor="snmp-enabled">SNMP enabled</Label>
          <Switch id="snmp-enabled" checked={form.enabled} onCheckedChange={(v) => setForm((f) => ({ ...f, enabled: v }))} />
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-1.5">
            <FieldLabel>Version</FieldLabel>
            <RadioGroup
              className="flex gap-4"
              value={form.version}
              onValueChange={(v) => setForm((f) => ({ ...f, version: v as "v2c" | "v3" }))}
            >
              {(["v2c", "v3"] as const).map((v) => (
                <div key={v} className="flex items-center gap-2">
                  <RadioGroupItem value={v} id={`snmp-${v}`} />
                  <Label htmlFor={`snmp-${v}`} className="font-normal">
                    {v}
                  </Label>
                </div>
              ))}
            </RadioGroup>
          </div>
          <div className="space-y-1.5">
            <FieldLabel hint="default 161">Port</FieldLabel>
            <Input
              type="number"
              min={1}
              max={65535}
              value={form.port}
              onChange={(e) => setForm((f) => ({ ...f, port: Number(e.target.value) }))}
            />
          </div>
          {form.version === "v2c" ? (
            <div className="space-y-1.5 sm:col-span-2">
              <FieldLabel hint="write-only — rendered masked after save">
                Community {hasStoredCommunity ? <span className="font-mono text-zinc-400">({MASK} stored)</span> : null}
              </FieldLabel>
              <Input
                type="password"
                value={form.community}
                placeholder={hasStoredCommunity ? MASK : "min 8 characters"}
                onChange={(e) => setForm((f) => ({ ...f, community: e.target.value }))}
              />
              {errors.community ? <p className="text-[11px] text-rose-600">{errors.community[0]}</p> : null}
            </div>
          ) : (
            <>
              <div className="space-y-1.5">
                <FieldLabel>v3 user</FieldLabel>
                <Input value={form.v3User} onChange={(e) => setForm((f) => ({ ...f, v3User: e.target.value }))} />
              </div>
              <div className="space-y-1.5">
                <FieldLabel>Auth protocol</FieldLabel>
                <Select value={form.authProtocol} onValueChange={(v) => setForm((f) => ({ ...f, authProtocol: v as "sha" | "sha256" }))}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="sha">sha</SelectItem>
                    <SelectItem value="sha256">sha256</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <FieldLabel>Privacy protocol</FieldLabel>
                <Select value={form.privProtocol} onValueChange={(v) => setForm((f) => ({ ...f, privProtocol: v as "aes" | "des" }))}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="aes">aes</SelectItem>
                    <SelectItem value="des">des</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </>
          )}
          <div className="space-y-1.5 sm:col-span-2">
            <FieldLabel hint="0 entries = unrestricted">
              Allowed IPs {form.allowedIps.length === 0 ? <span className="text-amber-600 dark:text-amber-400">(unrestricted — consider an allowlist)</span> : null}
            </FieldLabel>
            <div className="mb-2 flex flex-wrap gap-1.5">
              {form.allowedIps.map((ip) => (
                <Badge key={ip} variant="outline" className="gap-1 font-mono text-xs">
                  {ip}
                  <button
                    type="button"
                    aria-label={`Remove ${ip}`}
                    className="rounded-sm p-0.5 hover:bg-zinc-200 dark:hover:bg-zinc-700"
                    onClick={() => setForm((f) => ({ ...f, allowedIps: f.allowedIps.filter((x) => x !== ip) }))}
                  >
                    <Icons.X className="h-3 w-3" />
                  </button>
                </Badge>
              ))}
            </div>
            <div className="flex gap-2">
              <Input
                value={ipDraft}
                placeholder="10.0.0.0/24 or 10.0.0.5"
                onChange={(e) => setIpDraft(e.target.value)}
              />
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => {
                  const v = ipDraft.trim();
                  if (!v) return;
                  setForm((f) => (f.allowedIps.includes(v) ? f : { ...f, allowedIps: [...f.allowedIps, v] }));
                  setIpDraft("");
                }}
              >
                <Icons.Plus className="h-4 w-4" /> Add
              </Button>
            </div>
            {errors.allowedIps ? <p className="text-[11px] text-rose-600">{errors.allowedIps[0]}</p> : null}
          </div>
        </div>
        <div className="flex justify-end">
          <Button
            size="sm"
            disabled={save.isPending}
            onClick={() =>
              save.mutate(
                [
                  {
                    category: "advanced",
                    key: "snmp",
                    value: {
                      enabled: form.enabled,
                      version: form.version,
                      port: Number(form.port) || 161,
                      allowedIps: form.allowedIps,
                      ...(form.version === "v3"
                        ? { v3User: form.v3User || undefined, authProtocol: form.authProtocol, privProtocol: form.privProtocol }
                        : {}),
                      ...(form.community && form.community !== MASK ? { community: form.community } : {}),
                    },
                  },
                ],
                { onSuccess: () => setForm((f) => ({ ...f, community: "" })) },
              )
            }
          >
            {save.isPending ? "Saving…" : "Save SNMP"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ── 5. hardening ────────────────────────────────────────────────────────────

function HardeningCard({ settings }: { settings: SettingsMap | undefined }) {
  const seeded = useMemo(
    () => settingOf(settings, "advanced", "hardening", { sshPasswordAuth: true, managementAllowlist: [], stopUnusedServices: true }),
    [settings],
  );
  const [sshPasswordAuth, setSshPasswordAuth] = useState(true);
  const [stopUnusedServices, setStopUnusedServices] = useState(true);
  const [allowlist, setAllowlist] = useState<string[]>([]);
  const [draft, setDraft] = useState("");
  const sshKeys = useQuery({ queryKey: ["system", "sshKeys"], queryFn: () => systemApi.listSshKeys() });

  // re-seed when server settings arrive (render-time derived reset)
  const [prevSeed, setPrevSeed] = useState(seeded);
  if (prevSeed !== seeded) {
    setPrevSeed(seeded);
    setSshPasswordAuth(seeded.sshPasswordAuth ?? true);
    setStopUnusedServices(seeded.stopUnusedServices ?? true);
    setAllowlist(seeded.managementAllowlist ?? []);
  }

  const save = useSettingsSave();
  const passwordAuthRisk = !sshPasswordAuth && (sshKeys.data?.length ?? 0) === 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Icons.ShieldCheck className="h-4.5 w-4.5 text-red-700 dark:text-red-500" /> Hardening
        </CardTitle>
        <CardDescription>sshd_config · nftables mgmt allowlist · systemd masking — recorded only in sandbox</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="text-sm font-medium">SSH password authentication</p>
            <p className="text-[11px] text-zinc-500">Off = key-only SSH (sshd_config PasswordAuthentication no)</p>
          </div>
          <Switch checked={sshPasswordAuth} onCheckedChange={setSshPasswordAuth} />
        </div>
        {passwordAuthRisk ? (
          <p className="flex items-center gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-400">
            <Icons.TriangleAlert className="h-3.5 w-3.5 shrink-0" />
            No SSH keys are registered — you would lock yourself out.{" "}
            <a href="#/system/settings" className="font-medium underline">
              Add a key in the SSH keys card below
            </a>
            .
          </p>
        ) : null}
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="text-sm font-medium">Stop unused services</p>
            <p className="text-[11px] text-zinc-500">systemd-masks services with no active role</p>
          </div>
          <Switch checked={stopUnusedServices} onCheckedChange={setStopUnusedServices} />
        </div>
        <div>
          <FieldLabel hint="IP/CIDR — mgmt-plane access allowlist (nftables)">Management allowlist</FieldLabel>
          <div className="mb-2 flex flex-wrap gap-1.5">
            {allowlist.map((ip) => (
              <Badge key={ip} variant="outline" className="gap-1 font-mono text-xs">
                {ip}
                <button
                  type="button"
                  aria-label={`Remove ${ip}`}
                  className="rounded-sm p-0.5 hover:bg-zinc-200 dark:hover:bg-zinc-700"
                  onClick={() => setAllowlist((a) => a.filter((x) => x !== ip))}
                >
                  <Icons.X className="h-3 w-3" />
                </button>
              </Badge>
            ))}
            {allowlist.length === 0 ? <span className="text-xs text-zinc-400">no entries</span> : null}
          </div>
          <div className="flex gap-2">
            <Input value={draft} placeholder="192.168.1.0/24" onChange={(e) => setDraft(e.target.value)} />
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => {
                const v = draft.trim();
                if (!v) return;
                setAllowlist((a) => (a.includes(v) ? a : [...a, v]));
                setDraft("");
              }}
            >
              <Icons.Plus className="h-4 w-4" /> Add
            </Button>
          </div>
        </div>
        <div className="flex justify-end">
          <Button
            size="sm"
            disabled={save.isPending}
            onClick={() =>
              save.mutate([
                { category: "advanced", key: "hardening", value: { sshPasswordAuth, managementAllowlist: allowlist, stopUnusedServices } },
              ])
            }
          >
            {save.isPending ? "Saving…" : "Save hardening"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ── 6. firmware ─────────────────────────────────────────────────────────────

function FirmwareCard() {
  const { canWrite } = usePermissions();
  const admin = canWrite("firmware");
  const queryClient = useQueryClient();
  const firmware = useQuery({ queryKey: ["system", "firmware"], queryFn: () => systemApi.getFirmware() });
  const [dialog, setDialog] = useState<null | "upgrade" | "rollback">(null);

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["system", "firmware"] });
    void queryClient.invalidateQueries({ queryKey: ["system", "backups"] });
  };

  const check = useMutation({
    mutationFn: () => systemApi.checkFirmware(),
    onSuccess: (fw) => {
      toastOk("Update check complete", fw.available ? `Version ${fw.available} is available.` : "You are already on the latest version.");
      invalidate();
    },
    onError: (err) => toastErr(err, "Check failed"),
  });
  const upgrade = useMutation({
    mutationFn: () => systemApi.upgradeFirmware(),
    onSuccess: (fw) => {
      toastOk("Firmware upgraded", `Now on ${fw.current} — a safety backup was created first.`);
      invalidate();
      setDialog(null);
    },
    onError: (err) => toastErr(err, "Upgrade failed"),
  });
  const rollback = useMutation({
    mutationFn: () => systemApi.rollbackFirmware(),
    onSuccess: (fw) => {
      toastOk("Rolled back", `Restored ${fw.current} (simulated staged apply).`);
      invalidate();
      setDialog(null);
    },
    onError: (err) => toastErr(err, "Rollback failed"),
  });

  if (firmware.isError) return <QueryError error={firmware.error} onRetry={() => void firmware.refetch()} />;
  if (firmware.isLoading) return <CardSkeleton rows={2} />;
  const fw = firmware.data!;
  const canRollback = (fw.history?.length ?? 0) >= 2;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Icons.Cpu className="h-4.5 w-4.5 text-red-700 dark:text-red-500" /> Firmware
        </CardTitle>
        <CardDescription>Staged upgrade is simulated — appliance-side it is apt + systemd</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="outline" className="border-red-600/40 bg-red-600/10 font-mono text-red-700 dark:text-red-500">
            v{fw.current}
          </Badge>
          <Badge variant="outline" className="border-zinc-300 text-zinc-500 dark:border-zinc-700">
            channel: {fw.channel}
          </Badge>
          {fw.available ? (
            <Badge className="border-transparent bg-emerald-600 text-white">
              <Icons.ArrowUpCircle className="mr-1 h-3 w-3" /> {fw.available} available
            </Badge>
          ) : null}
          <div className="ml-auto flex gap-2">
            <Button size="sm" variant="outline" disabled={!admin || check.isPending} onClick={() => check.mutate()}>
              {check.isPending ? <Icons.Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Icons.Search className="mr-2 h-4 w-4" />}
              Check for updates
            </Button>
            <Button size="sm" disabled={!admin || !fw.available || upgrade.isPending} onClick={() => setDialog("upgrade")}>
              <Icons.Upload className="mr-2 h-4 w-4" /> Upgrade now
            </Button>
            <Button size="sm" variant="outline" disabled={!admin || !canRollback || rollback.isPending} onClick={() => setDialog("rollback")}>
              <Icons.Undo2 className="mr-2 h-4 w-4" /> Roll back
            </Button>
          </div>
        </div>
        {fw.lastCheckAt ? <p className="text-[11px] text-zinc-400">Last check {fmtDateTime(fw.lastCheckAt)}</p> : null}
        <div>
          <FieldLabel hint="upgrades and rollbacks append entries">History</FieldLabel>
          {fw.history.length === 0 ? (
            <p className="text-xs text-zinc-400">No upgrades recorded yet.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Version</TableHead>
                  <TableHead>Applied</TableHead>
                  <TableHead>Note</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {[...fw.history].reverse().map((h, i) => (
                  <TableRow key={`${h.version}-${i}`}>
                    <TableCell className="font-mono text-xs">v{h.version}</TableCell>
                    <TableCell className="text-xs">{fmtDateTime(h.appliedAt)}</TableCell>
                    <TableCell className="text-xs text-zinc-500">{h.note ?? "—"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </div>

        <ConfirmDialog
          open={dialog === "upgrade"}
          onOpenChange={(o) => !o && setDialog(null)}
          loading={upgrade.isPending}
          title={`Upgrade to v${fw.available ?? ""}?`}
          description="A safety backup is created first (see #/system/backups), then the appliance applies the staged upgrade. The console contract is one audited POST."
          confirmLabel="Upgrade now"
          onConfirm={() => upgrade.mutate()}
        />
        <ConfirmDialog
          open={dialog === "rollback"}
          onOpenChange={(o) => !o && setDialog(null)}
          loading={rollback.isPending}
          title="Roll back firmware?"
          description={`Restores the previous version from history (simulated staged apply). Current: v${fw.current}.`}
          confirmLabel="Roll back"
          onConfirm={() => rollback.mutate()}
        />
      </CardContent>
    </Card>
  );
}

// ── 7. SSH keys ─────────────────────────────────────────────────────────────

function SshKeysCard() {
  const { isAdmin } = usePermissions();
  const admin = isAdmin("system");
  const queryClient = useQueryClient();
  const keys = useQuery({ queryKey: ["system", "sshKeys"], queryFn: () => systemApi.listSshKeys() });
  const [addOpen, setAddOpen] = useState(false);
  const [removeId, setRemoveId] = useState<number | null>(null);
  const [name, setName] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [errors, setErrors] = useState<Record<string, string[]>>({});

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ["system", "sshKeys"] });

  const create = useMutation({
    mutationFn: () => systemApi.createSshKey({ name, publicKey }),
    onSuccess: (key) => {
      toastOk("SSH key added", `Fingerprint ${key.fingerprint} derived server-side.`);
      setAddOpen(false);
      setName("");
      setPublicKey("");
      setErrors({});
      invalidate();
    },
    onError: (err) => {
      setErrors(fieldErrorsOf(err));
      toastErr(err, "Add failed");
    },
  });
  const remove = useMutation({
    mutationFn: (id: number) => systemApi.deleteSshKey(id),
    onSuccess: () => {
      toastOk("SSH key removed", "authorized_keys entry deleted (audited).");
      setRemoveId(null);
      invalidate();
    },
    onError: (err) => toastErr(err, "Remove failed"),
  });

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between space-y-0">
        <div>
          <CardTitle className="flex items-center gap-2 text-base">
            <Icons.KeyRound className="h-4.5 w-4.5 text-red-700 dark:text-red-500" /> SSH keys
          </CardTitle>
          <CardDescription>Management-plane access — public keys only, fingerprint derived server-side</CardDescription>
        </div>
        <Button size="sm" disabled={!admin} onClick={() => setAddOpen(true)}>
          <Icons.Plus className="mr-2 h-4 w-4" /> Add key
        </Button>
      </CardHeader>
      <CardContent>
        {keys.isError ? (
          <QueryError error={keys.error} onRetry={() => void keys.refetch()} />
        ) : keys.isLoading ? (
          <TableSkeleton rows={3} cols={5} />
        ) : (keys.data?.length ?? 0) === 0 ? (
          <EmptyBlock icon={<Icons.KeyRound className="h-6 w-6" />} title="No SSH keys" description="Add a management key to enable key-only SSH (hardening)." />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Fingerprint</TableHead>
                <TableHead>Added by</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="w-16" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {keys.data!.map((k) => (
                <TableRow key={k.id}>
                  <TableCell className="text-sm font-medium">{k.name}</TableCell>
                  <TableCell className="font-mono text-xs">{k.fingerprint}</TableCell>
                  <TableCell className="text-xs">{k.addedBy ?? "—"}</TableCell>
                  <TableCell className="text-xs">{fmtDateTime(k.createdAt)}</TableCell>
                  <TableCell>
                    <Button
                      size="icon"
                      variant="ghost"
                      aria-label={`Remove ${k.name}`}
                      disabled={!admin}
                      onClick={() => setRemoveId(k.id)}
                    >
                      <Icons.Trash2 className="h-4 w-4 text-rose-600" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}

        <Dialog open={addOpen} onOpenChange={setAddOpen}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add SSH key</DialogTitle>
              <DialogDescription>
                Paste an OpenSSH <span className="font-mono">authorized_keys</span> line — the fingerprint is derived
                server-side. Private keys are rejected.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-3">
              <div className="space-y-1.5">
                <FieldLabel>Name</FieldLabel>
                <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="ops-laptop" />
                {errors.name ? <p className="text-[11px] text-rose-600">{errors.name[0]}</p> : null}
              </div>
              <div className="space-y-1.5">
                <FieldLabel hint="ssh-ed25519 AAAA… comment">Public key</FieldLabel>
                <Textarea
                  rows={4}
                  className="font-mono text-xs"
                  value={publicKey}
                  onChange={(e) => setPublicKey(e.target.value)}
                  placeholder="ssh-ed25519 AAAAC3Nza… user@host"
                />
                {errors.publicKey ? <p className="text-[11px] text-rose-600">{errors.publicKey[0]}</p> : null}
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setAddOpen(false)}>
                Cancel
              </Button>
              <Button disabled={!name.trim() || !publicKey.trim() || create.isPending} onClick={() => create.mutate()}>
                {create.isPending ? "Adding…" : "Add key"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        <ConfirmDialog
          open={removeId !== null}
          onOpenChange={(o) => !o && setRemoveId(null)}
          loading={remove.isPending}
          title="Remove SSH key?"
          description="The authorized_keys entry is deleted appliance-side. The action is audited."
          confirmLabel="Remove"
          onConfirm={() => removeId !== null && remove.mutate(removeId)}
        />
      </CardContent>
    </Card>
  );
}

// ── 8. notifications prefs ──────────────────────────────────────────────────

function NotificationsPrefsCard({ settings }: { settings: SettingsMap | undefined }) {
  const email = useMemo(() => settingOf(settings, "notifications", "email", { enabled: false, recipient: "" }), [settings]);
  const severity = useMemo(() => settingOf(settings, "notifications", "severity_threshold", { threshold: "info" }), [settings]);
  const thresholds = useMemo(
    () => settingOf(settings, "notifications", "thresholds", { cpuPct: 90, memPct: 90, diskPct: 85, tempC: 80 }),
    [settings],
  );
  const [emailEnabled, setEmailEnabled] = useState(false);
  const [recipient, setRecipient] = useState("");
  const [threshold, setThreshold] = useState("info");
  const [cpuPct, setCpu] = useState(90);
  const [memPct, setMem] = useState(90);
  const [diskPct, setDisk] = useState(85);
  const [tempC, setTemp] = useState(80);

  // re-seed when server settings arrive (render-time derived reset)
  const [prevSeed, setPrevSeed] = useState<{ e: typeof email; s: typeof severity; t: typeof thresholds }>({ e: email, s: severity, t: thresholds });
  if (prevSeed.e !== email || prevSeed.s !== severity || prevSeed.t !== thresholds) {
    setPrevSeed({ e: email, s: severity, t: thresholds });
    setEmailEnabled(email.enabled ?? false);
    setRecipient(email.recipient ?? "");
    setThreshold(severity.threshold ?? "info");
    setCpu(thresholds.cpuPct ?? 90);
    setMem(thresholds.memPct ?? 90);
    setDisk(thresholds.diskPct ?? 85);
    setTemp(thresholds.tempC ?? 80);
  }

  const save = useSettingsSave();
  const pctOk = (v: number) => Number.isInteger(v) && v >= 1 && v <= 100;
  const tempOk = Number.isInteger(tempC) && tempC >= 20 && tempC <= 120;
  const valid = pctOk(cpuPct) && pctOk(memPct) && pctOk(diskPct) && tempOk;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Icons.BellRing className="h-4.5 w-4.5 text-red-700 dark:text-red-500" /> Notifications
        </CardTitle>
        <CardDescription>
          The engine compares cpu/mem/disk/temp per tick and emits warning/critical notifications (edge-triggered)
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="text-sm font-medium">Email delivery</p>
            <p className="text-[11px] text-zinc-500">display-only in Phase 1 — no mailer exists in the sandbox</p>
          </div>
          <Switch checked={emailEnabled} onCheckedChange={setEmailEnabled} disabled />
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-1.5">
            <FieldLabel hint="display-only">Recipient</FieldLabel>
            <Input value={recipient} onChange={(e) => setRecipient(e.target.value)} placeholder="ops@example.com" disabled />
          </div>
          <div className="space-y-1.5">
            <FieldLabel hint="in-console minimum severity">Severity threshold</FieldLabel>
            <Select value={threshold} onValueChange={setThreshold}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="info">info and above</SelectItem>
                <SelectItem value="warning">warning and above</SelectItem>
                <SelectItem value="critical">critical only</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
        <div>
          <FieldLabel hint="engine re-reads these every ~30 s">Resource-alert thresholds</FieldLabel>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              { label: "CPU %", value: cpuPct, set: setCpu, min: 1, max: 100 },
              { label: "Memory %", value: memPct, set: setMem, min: 1, max: 100 },
              { label: "Disk %", value: diskPct, set: setDisk, min: 1, max: 100 },
              { label: "Temp °C", value: tempC, set: setTemp, min: 20, max: 120 },
            ].map((f) => (
              <div key={f.label} className="space-y-1.5">
                <Label className="text-xs text-zinc-500">{f.label}</Label>
                <Input
                  type="number"
                  value={f.value}
                  min={f.min}
                  max={f.max}
                  onChange={(e) => f.set(Number(e.target.value))}
                />
              </div>
            ))}
          </div>
          {!valid ? <p className="mt-1 text-[11px] text-rose-600">Thresholds out of range (pct 1-100, temp 20-120).</p> : null}
        </div>
        <div className="flex justify-end">
          <Button
            size="sm"
            disabled={save.isPending || !valid}
            onClick={() =>
              save.mutate([
                { category: "notifications", key: "email", value: { ...email, enabled: emailEnabled, recipient } },
                { category: "notifications", key: "severity_threshold", value: { threshold } },
                { category: "notifications", key: "thresholds", value: { cpuPct, memPct, diskPct, tempC } },
              ])
            }
          >
            {save.isPending ? "Saving…" : "Save notifications"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ── 9. logging retention ────────────────────────────────────────────────────

function RetentionCard({ settings }: { settings: SettingsMap | undefined }) {
  const initial = useMemo(
    () =>
      RETENTION_TABLES.map((t) => ({
        ...t,
        value: settingOf<{ days?: number; maxRows?: number }>(settings, "logging", `retention.${t.key}`, {}),
      })),
    [settings],
  );
  const [rows, setRows] = useState(initial);
  // re-seed when the settings query refetches (render-time derived reset)
  const [prevInitial, setPrevInitial] = useState(initial);
  if (prevInitial !== initial) {
    setPrevInitial(initial);
    setRows(initial);
  }

  const save = useSettingsSave();
  const dirty = rows.some((r) => JSON.stringify(r.value) !== JSON.stringify(initial.find((i) => i.key === r.key)?.value ?? {}));

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Icons.HardDriveDownload className="h-4.5 w-4.5 text-red-700 dark:text-red-500" /> Logging retention
        </CardTitle>
        <CardDescription>Overrides only tighten or extend within the hard ceilings (row caps)</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {rows.map((r, idx) => (
          <div key={r.key} className="grid items-end gap-3 sm:grid-cols-[1fr_auto_auto]">
            <div>
              <p className="text-sm font-medium">{r.label}</p>
              <p className="text-[11px] text-zinc-400">
                hard cap {r.cap.toLocaleString()} rows{r.value.maxRows ? ` · override ${r.value.maxRows.toLocaleString()}` : ""}
              </p>
            </div>
            <div className="space-y-1">
              <Label className="text-xs text-zinc-500">Days</Label>
              <Input
                type="number"
                min={1}
                max={3650}
                className="w-28"
                value={r.value.days ?? ""}
                placeholder="default"
                onChange={(e) =>
                  setRows((rs) => rs.map((x, i) => (i === idx ? { ...x, value: { ...x.value, days: e.target.value === "" ? undefined : Number(e.target.value) } } : x)))
                }
              />
            </div>
            <div className="space-y-1">
              <Label className="text-xs text-zinc-500">Max rows</Label>
              <Input
                type="number"
                min={500}
                max={r.cap}
                className="w-32"
                value={r.value.maxRows ?? ""}
                placeholder={String(r.cap)}
                onChange={(e) =>
                  setRows((rs) => rs.map((x, i) => (i === idx ? { ...x, value: { ...x.value, maxRows: e.target.value === "" ? undefined : Number(e.target.value) } } : x)))
                }
              />
            </div>
          </div>
        ))}
        <div className="flex justify-end">
          <Button
            size="sm"
            disabled={!dirty || save.isPending}
            onClick={() =>
              save.mutate(
                rows.map((r) => ({
                  category: "logging",
                  key: `retention.${r.key}`,
                  value: {
                    ...(r.value.days !== undefined ? { days: r.value.days } : {}),
                    ...(r.value.maxRows !== undefined ? { maxRows: r.value.maxRows } : {}),
                  },
                })),
              )
            }
          >
            {save.isPending ? "Saving…" : "Save retention"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ── 10. advanced toggles ────────────────────────────────────────────────────

function AdvancedCard({ settings }: { settings: SettingsMap | undefined }) {
  const diagnostics = useMemo(() => settingOf(settings, "advanced", "diagnostics", { verbosity: "standard" }), [settings]);
  const apiKeys = useMemo(() => settingOf(settings, "advanced", "apiKeysEnabled", { enabled: true }), [settings]);
  const status = useQuery({ queryKey: ["system", "status"], queryFn: () => systemApi.getStatus(), staleTime: 5000 });
  const [verbosity, setVerbosity] = useState("standard");
  const [apiKeysEnabled, setApiKeysEnabled] = useState(true);
  // re-seed when server settings arrive (render-time derived reset)
  const [prevSeed, setPrevSeed] = useState<{ d: typeof diagnostics; k: typeof apiKeys }>({ d: diagnostics, k: apiKeys });
  if (prevSeed.d !== diagnostics || prevSeed.k !== apiKeys) {
    setPrevSeed({ d: diagnostics, k: apiKeys });
    setVerbosity(diagnostics.verbosity ?? "standard");
    setApiKeysEnabled(apiKeys.enabled ?? true);
  }

  const save = useSettingsSave();
  const dirty = verbosity !== (diagnostics.verbosity ?? "standard") || apiKeysEnabled !== (apiKeys.enabled ?? true);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Icons.SlidersHorizontal className="h-4.5 w-4.5 text-red-700 dark:text-red-500" /> Advanced
        </CardTitle>
        <CardDescription>Diagnostics verbosity and the API-key master switch</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-1.5">
            <FieldLabel>Diagnostics verbosity</FieldLabel>
            <Select value={verbosity} onValueChange={setVerbosity}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="standard">standard</SelectItem>
                <SelectItem value="verbose">verbose</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <FieldLabel hint="read-only — set via the ADAPTER_MODE env">Data plane</FieldLabel>
            <Input value={status.data?.dataPlane ?? "host (real telemetry)"} disabled />
          </div>
        </div>
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="text-sm font-medium">Allow API-key access</p>
            <p className="text-[11px] text-zinc-500">Master switch — off means machine keys fail auth immediately</p>
          </div>
          <Switch checked={apiKeysEnabled} onCheckedChange={setApiKeysEnabled} />
        </div>
        <div className="flex justify-end">
          <Button
            size="sm"
            disabled={!dirty || save.isPending}
            onClick={() =>
              save.mutate([
                { category: "advanced", key: "diagnostics", value: { verbosity } },
                { category: "advanced", key: "apiKeysEnabled", value: { enabled: apiKeysEnabled } },
              ])
            }
          >
            {save.isPending ? "Saving…" : "Save advanced"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ── 11. policy templates ────────────────────────────────────────────────────

function TemplatesCard() {
  const { isAdmin } = usePermissions();
  const admin = isAdmin("system");
  const queryClient = useQueryClient();
  const templates = useQuery({ queryKey: ["system", "templates"], queryFn: () => systemApi.listTemplates() });
  const [applyId, setApplyId] = useState<string | null>(null);

  const apply = useMutation({
    mutationFn: (id: string) => systemApi.applyTemplate(id),
    onSuccess: (r) => {
      toastOk(`Template applied: ${r.template.name}`, `Replaced rows in: ${r.summary.sections.join(", ")} (audited, section all).`);
      setApplyId(null);
      void queryClient.invalidateQueries();
    },
    onError: (err) => toastErr(err, "Apply failed"),
  });

  if (templates.isError) return <QueryError error={templates.error} onRetry={() => void templates.refetch()} />;
  if (templates.isLoading) return <CardSkeleton rows={3} />;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Icons.LayoutTemplate className="h-4.5 w-4.5 text-red-700 dark:text-red-500" /> Policy templates
        </CardTitle>
        <CardDescription>Per-vertical starter bundles — applying overwrites matching sections (audited)</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid gap-3 lg:grid-cols-3">
          {templates.data!.map((t) => (
            <div key={t.id} className="flex flex-col rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
              <p className="text-sm font-semibold">{t.name}</p>
              <p className="mt-1 flex-1 text-xs text-zinc-500">{t.description}</p>
              <dl className="mt-3 space-y-1 text-[11px]">
                {Object.entries(t.sections).map(([k, v]) => (
                  <div key={k} className="flex gap-2">
                    <dt className="w-14 shrink-0 font-medium uppercase tracking-wide text-zinc-400">{k}</dt>
                    <dd className="text-zinc-600 dark:text-zinc-300">{v}</dd>
                  </div>
                ))}
              </dl>
              <Button className="mt-3" size="sm" variant="outline" disabled={!admin} onClick={() => setApplyId(t.id)}>
                <Icons.CheckCheck className="mr-2 h-4 w-4" /> Apply template
              </Button>
            </div>
          ))}
        </div>
        <ConfirmDialog
          open={applyId !== null}
          onOpenChange={(o) => !o && setApplyId(null)}
          loading={apply.isPending}
          title="Apply template?"
          description="Matching sections (firewall, NAT, IPS, DNS, QoS) are overwritten with the template's starter rows. The apply is audited and every view refetches via the config fan-out."
          confirmLabel="Apply"
          onConfirm={() => applyId !== null && apply.mutate(applyId)}
        />
      </CardContent>
    </Card>
  );
}

// ── 12. config history + diff viewer ────────────────────────────────────────

function ConfigHistoryCard() {
  const [section, setSection] = useState<string>("system");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<number[]>([]);
  const versions = useQuery({
    queryKey: ["system", "versions", section, page],
    queryFn: () => systemApi.listConfigVersions(`section=${section}&page=${page}&limit=8`),
  });

  const older = useQuery({
    enabled: selected.length === 2,
    queryKey: ["system", "version", selected[0]],
    queryFn: () => systemApi.getConfigVersion(selected[0]),
  });
  const newer = useQuery({
    enabled: selected.length === 2,
    queryKey: ["system", "version", selected[1]],
    queryFn: () => systemApi.getConfigVersion(selected[1]),
  });

  const toggle = (id: number) =>
    setSelected((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id].sort((a, b) => a - b).slice(-2)));

  const meta = versions.data?.meta;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Icons.History className="h-4.5 w-4.5 text-red-700 dark:text-red-500" /> Config history
        </CardTitle>
        <CardDescription>
          Versions are written on every significant apply and never pruned — pick two of the same section to diff
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <Select
            value={section}
            onValueChange={(v) => {
              setSection(v);
              setPage(1);
              setSelected([]);
            }}
          >
            <SelectTrigger className="w-44">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {CONFIG_SECTIONS.map((s) => (
                <SelectItem key={s} value={s}>
                  {s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {selected.length > 0 ? (
            <p className="text-xs text-zinc-500">
              {selected.length === 1 ? "select one more version" : "diffing two versions"}
              <button type="button" className="ml-2 underline" onClick={() => setSelected([])}>
                clear
              </button>
            </p>
          ) : null}
          <div className="ml-auto flex items-center gap-2 text-xs text-zinc-500">
            <Button size="icon" variant="outline" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>
              <Icons.ChevronLeft className="h-4 w-4" />
            </Button>
            page {meta?.page ?? page} / {meta?.totalPages ?? 1}
            <Button
              size="icon"
              variant="outline"
              disabled={page >= (meta?.totalPages ?? 1)}
              onClick={() => setPage((p) => p + 1)}
            >
              <Icons.ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>

        {versions.isLoading ? (
          <TableSkeleton rows={4} cols={4} />
        ) : (versions.data?.data.length ?? 0) === 0 ? (
          <EmptyBlock icon={<Icons.History className="h-6 w-6" />} title="No versions for this section yet" description="Save a config mutation in this section to create the first snapshot." />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-12" />
                <TableHead>Version</TableHead>
                <TableHead>Change</TableHead>
                <TableHead>Author</TableHead>
                <TableHead>Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {versions.data!.data.map((v) => (
                <TableRow key={v.id} className={cn(selected.includes(v.id) && "bg-red-600/5")}>
                  <TableCell>
                    <input
                      type="checkbox"
                      className="h-4 w-4 accent-red-700"
                      aria-label={`Select version ${v.version}`}
                      checked={selected.includes(v.id)}
                      onChange={() => toggle(v.id)}
                    />
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    v{v.version}
                    <Badge variant="outline" className="ml-2 border-teal-500/40 bg-teal-500/10 text-[10px] text-teal-600 dark:text-teal-400">
                      {v.section}
                    </Badge>
                  </TableCell>
                  <TableCell className="max-w-72 truncate text-xs">{v.changeSummary ?? "—"}</TableCell>
                  <TableCell className="text-xs">{v.authorUsername ?? `user #${v.createdBy ?? "?"}`}</TableCell>
                  <TableCell className="text-xs">{fmtDateTime(v.createdAt)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}

        {selected.length === 2 ? (
          <div className="space-y-2">
            <p className="text-xs font-medium text-zinc-500">
              Diff v{older.data?.version ?? "…"} → v{newer.data?.version ?? "…"}{" "}
              <span className="text-zinc-400">(emerald = added, rose = removed, zinc = unchanged)</span>
            </p>
            {older.isError || newer.isError ? (
              <QueryError error={older.error ?? newer.error} onRetry={() => { void older.refetch(); void newer.refetch(); }} />
            ) : older.isLoading || newer.isLoading ? (
              <Skeleton className="h-48 w-full" />
            ) : (
              <DiffViewer olderJson={older.data!.configSnapshot} newerJson={newer.data!.configSnapshot} />
            )}
          </div>
        ) : selected.length === 1 && older.isSuccess ? (
          <div className="space-y-1">
            <p className="text-xs font-medium text-zinc-500">Single snapshot — v{older.data.version}</p>
            <JsonViewer json={older.data.configSnapshot} />
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

// ── view root ───────────────────────────────────────────────────────────────

export function SystemView() {
  const settings = useQuery({ queryKey: ["system", "settings"], queryFn: () => systemApi.getSettings() });

  return (
    <div className="grid gap-4">
      <HealthStripCard />

      {settings.isError ? (
        <QueryError error={settings.error} onRetry={() => void settings.refetch()} />
      ) : (
        <>
          <GeneralCard settings={settings.data} />
          <NtpCard settings={settings.data} />
          <SnmpCard settings={settings.data} />
          <HardeningCard settings={settings.data} />
          <FirmwareCard />
          <SshKeysCard />
          <NotificationsPrefsCard settings={settings.data} />
          <RetentionCard settings={settings.data} />
          <AdvancedCard settings={settings.data} />
          <TemplatesCard />
          <ConfigHistoryCard />
        </>
      )}
    </div>
  );
}
