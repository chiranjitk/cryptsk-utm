"use client";

/**
 * First-time setup wizard (M10 §4 `#/setup`, view 29) — full-screen gate that
 * renders INSTEAD of the shell while SystemSetting system/setup.completed is
 * false (coordinator wires the gate; this file owns the component + the
 * useSetupCompleted hook). Linear steps: Welcome → WAN → LAN/DHCP → Policy
 * template → Finish. Every step saves through the regular module endpoints —
 * this view defines no new data.
 */

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
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
import { cn } from "@/lib/utils";
import { toastErr, toastOk } from "../firewall/fw-ui";
import { listInterfaceNames, dhcpApi, type IfaceLite } from "../dns-dhcp/dns-dhcp-api";
import { systemApi } from "../system/system-api";
import type { PolicyTemplateDTO } from "@/lib/system/service";

// ── gate hook (lightweight settings read) ───────────────────────────────────

export interface SetupGateState {
  completed: boolean;
  isLoading: boolean;
}

/**
 * Reads system/setup.completed from the settings endpoint. A failed read
 * (e.g. 403 for a role that cannot read settings) is treated as completed —
 * the gate must never trap an operator who cannot even read the flag.
 */
export function useSetupCompleted(): SetupGateState {
  const q = useQuery({
    queryKey: ["system", "setup-gate"],
    queryFn: async () => {
      const res = await fetch("/api/v1/system/settings", { credentials: "same-origin" });
      if (!res.ok) return { completed: true };
      const json = (await res.json()) as { data?: Record<string, Record<string, unknown>> };
      const completed = json.data?.system?.setup as { completed?: boolean } | undefined;
      return { completed: completed?.completed ?? true };
    },
    staleTime: 10_000,
  });
  return { completed: q.data?.completed ?? true, isLoading: q.isLoading };
}

// ── constants ───────────────────────────────────────────────────────────────

const TIMEZONES = [
  "Asia/Calcutta", "Asia/Karachi", "Asia/Dubai", "Asia/Singapore", "Asia/Tokyo",
  "Europe/London", "Europe/Berlin", "America/New_York", "America/Chicago", "America/Los_Angeles", "UTC",
];

const STEPS = ["Welcome", "WAN", "LAN / DHCP", "Policy template", "Finish"] as const;

// ── wizard shell ────────────────────────────────────────────────────────────

export function SetupWizard(props: { onFinished: () => void }) {
  const [step, setStep] = useState(0);
  const queryClient = useQueryClient();

  // shared wizard state (kept here so Back/Next never loses choices)
  const [timezone, setTimezone] = useState("Asia/Calcutta");
  const [wanIface, setWanIface] = useState<string>("");
  const [wanType, setWanType] = useState<"static" | "dhcp" | "pppoe">("dhcp");
  const [lanIface, setLanIface] = useState<string>("lan0");
  const [subnetCidr, setSubnetCidr] = useState("192.168.10.0/24");
  const [rangeStart, setRangeStart] = useState("192.168.10.100");
  const [rangeEnd, setRangeEnd] = useState("192.168.10.200");
  const [gateway, setGateway] = useState("192.168.10.1");
  const [appliedTemplate, setAppliedTemplate] = useState<string | null>(null);
  const [dhcpSaved, setDhcpSaved] = useState(false);
  const [tzSaved, setTzSaved] = useState(false);

  const ifaces = useQuery({ queryKey: ["setup", "ifaces"], queryFn: () => listInterfaceNames() });
  const ifacesSafe = useMemo(() => ifaces.data ?? [], [ifaces.data]);

  const templates = useQuery({ queryKey: ["system", "templates"], queryFn: () => systemApi.listTemplates() });

  // step 1: timezone confirm saves general/timezone
  const saveTz = useMutation({
    mutationFn: () =>
      fetch("/api/v1/system/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify([{ category: "general", key: "timezone", value: { value: timezone } }]),
      }).then(async (res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
      }),
    onSuccess: () => {
      setTzSaved(true);
      toastOk("Timezone confirmed", `general/timezone = ${timezone}`);
    },
    onError: (err) => toastErr(err, "Timezone save failed"),
  });

  // step 3: LAN/DHCP creates the starter subnet (existing M06 endpoint)
  const saveDhcp = useMutation({
    mutationFn: () =>
      dhcpApi.createSubnet({
        interfaceName: lanIface,
        family: "ipv4",
        subnetCidr,
        rangeStart,
        rangeEnd,
        gateway,
        dnsServers: [gateway],
        leaseTime: 86_400,
        options: {},
        enabled: true,
      }),
    onSuccess: () => {
      setDhcpSaved(true);
      toastOk("DHCP subnet created", `${subnetCidr} on ${lanIface} — edit it later in #/dns-dhcp/dhcp.`);
    },
    onError: (err) => {
      // overlap/already-exists is non-blocking in the wizard (demo defaults)
      toastErr(err, "Subnet not created — you can configure it later");
    },
  });

  // step 4: template apply (same audited endpoint as the settings card)
  const applyTemplate = useMutation({
    mutationFn: (id: string) => systemApi.applyTemplate(id),
    onSuccess: (r) => {
      setAppliedTemplate(r.template.id);
      toastOk(`Template applied: ${r.template.name}`, `Sections: ${r.summary.sections.join(", ")}.`);
    },
    onError: (err) => toastErr(err, "Apply failed"),
  });

  // finish: POST setup/complete → coordinator renders the shell
  const finish = useMutation({
    mutationFn: () => systemApi.completeSetup(),
    onSuccess: () => {
      void queryClient.invalidateQueries();
      toastOk("Setup complete", "Welcome to your Cryptsk appliance.");
      props.onFinished();
    },
    onError: (err) => toastErr(err, "Could not complete setup"),
  });

  const wanIfaces = ifacesSafe.filter((i) => i.role === "wan");

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-zinc-50 p-4 dark:bg-zinc-950">
      <div className="w-full max-w-2xl">
        {/* header */}
        <div className="mb-5 flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-600 text-white">
            <Icons.ShieldCheck className="h-6 w-6" />
          </div>
          <div>
            <p className="text-base font-semibold">Cryptsk UTM / NGFW</p>
            <p className="text-xs text-zinc-500">First-time setup — step {step + 1} of {STEPS.length}</p>
          </div>
          <Badge variant="outline" className="ml-auto border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400">
            simulated appliance
          </Badge>
        </div>

        {/* progress */}
        <div className="mb-5 flex items-center gap-1.5">
          {STEPS.map((label, i) => (
            <div key={label} className="flex flex-1 flex-col gap-1">
              <div className={cn("h-1.5 rounded-full", i <= step ? "bg-blue-600" : "bg-zinc-200 dark:bg-zinc-800")} />
              <p className={cn("text-[10px]", i === step ? "font-medium text-blue-600 dark:text-blue-400" : "text-zinc-400")}>
                {label}
              </p>
            </div>
          ))}
        </div>

        <Card>
          <CardContent className="p-6">
            {step === 0 ? (
              <WelcomeStep
                timezone={timezone}
                setTimezone={setTimezone}
                tzSaved={tzSaved}
                onSaveTz={() => saveTz.mutate()}
              />
            ) : step === 1 ? (
              <WanStep
                ifaces={ifacesSafe}
                wanIfaces={wanIfaces.map((i) => i.name)}
                wanIface={wanIface}
                setWanIface={setWanIface}
                wanType={wanType}
                setWanType={setWanType}
                loading={ifaces.isLoading}
              />
            ) : step === 2 ? (
              <LanStep
                ifaces={ifacesSafe}
                lanIface={lanIface}
                setLanIface={setLanIface}
                subnetCidr={subnetCidr}
                setSubnetCidr={setSubnetCidr}
                rangeStart={rangeStart}
                setRangeStart={setRangeStart}
                rangeEnd={rangeEnd}
                setRangeEnd={setRangeEnd}
                gateway={gateway}
                setGateway={setGateway}
                saved={dhcpSaved}
                onSave={() => saveDhcp.mutate()}
                saving={saveDhcp.isPending}
              />
            ) : step === 3 ? (
              <TemplateStep
                templates={templates.data ?? []}
                loading={templates.isLoading}
                applied={appliedTemplate}
                onApply={(id) => applyTemplate.mutate(id)}
                applying={applyTemplate.isPending}
              />
            ) : (
              <FinishStep
                summary={{ timezone, wanIface, wanType, lanIface, subnetCidr, dhcpSaved, appliedTemplate }}
              />
            )}
          </CardContent>
        </Card>

        {/* footer nav */}
        <div className="mt-4 flex items-center justify-between">
          <Button variant="ghost" disabled={step === 0} onClick={() => setStep((s) => Math.max(0, s - 1))}>
            <Icons.ArrowLeft className="mr-2 h-4 w-4" /> Back
          </Button>
          {step < STEPS.length - 1 ? (
            <Button onClick={() => setStep((s) => Math.min(STEPS.length - 1, s + 1))}>
              Next <Icons.ArrowRight className="ml-2 h-4 w-4" />
            </Button>
          ) : (
            <Button disabled={finish.isPending} onClick={() => finish.mutate()}>
              {finish.isPending ? (
                <>
                  <Icons.Loader2 className="mr-2 h-4 w-4 animate-spin" /> Finishing…
                </>
              ) : (
                <>
                  <Icons.CheckCircle2 className="mr-2 h-4 w-4" /> Finish setup
                </>
              )}
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}

// ── steps ───────────────────────────────────────────────────────────────────

function WelcomeStep(props: {
  timezone: string;
  setTimezone: (tz: string) => void;
  tzSaved: boolean;
  onSaveTz: () => void;
}) {
  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold">Welcome to Cryptsk</h2>
        <p className="mt-1 text-sm text-zinc-500">
          This wizard walks through the appliance essentials: WAN uplink, LAN/DHCP defaults and a policy template.
          You can revisit everything later in the console.
        </p>
      </div>
      <div className="rounded-lg border border-blue-500/40 bg-blue-500/10 p-3 text-xs text-blue-700 dark:text-blue-400">
        <p className="flex items-start gap-2">
          <Icons.KeyRound className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>
            The seed admin password is a known default — change it after setup in{" "}
            <span className="font-mono">#/identity/users</span> (password policy + MFA enrollment live in{" "}
            <span className="font-mono">#/identity/users</span> too).
          </span>
        </p>
      </div>
      <div className="space-y-1.5">
        <Label>Confirm timezone (IANA)</Label>
        <div className="flex gap-2">
          <Select value={props.timezone} onValueChange={props.setTimezone}>
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
          <Button variant="outline" onClick={props.onSaveTz} disabled={props.tzSaved}>
            {props.tzSaved ? <Icons.Check className="h-4 w-4" /> : "Confirm"}
          </Button>
        </div>
        {props.tzSaved ? <p className="text-[11px] text-emerald-600 dark:text-emerald-400">Saved to general/timezone.</p> : null}
      </div>
    </div>
  );
}

function WanStep(props: {
  ifaces: IfaceLite[];
  wanIfaces: string[];
  wanIface: string;
  setWanIface: (v: string) => void;
  wanType: "static" | "dhcp" | "pppoe";
  setWanType: (v: "static" | "dhcp" | "pppoe") => void;
  loading: boolean;
}) {
  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold">WAN uplink</h2>
        <p className="mt-1 text-sm text-zinc-500">
          Verify the WAN interface and uplink type. Detailed WAN policies and probes live in{" "}
          <span className="font-mono">#</span>⁠<span className="font-mono">/network/wan</span>.
        </p>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label>WAN interface</Label>
          <Select value={props.wanIface} onValueChange={props.setWanIface}>
            <SelectTrigger>
              <SelectValue placeholder={props.loading ? "Loading…" : "pick an interface"} />
            </SelectTrigger>
            <SelectContent>
              {(props.wanIfaces.length > 0 ? props.wanIfaces : props.ifaces.map((i) => i.name)).map((name) => (
                <SelectItem key={name} value={name}>
                  {name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1.5">
          <Label>Uplink type</Label>
          <RadioGroup className="flex gap-4 pt-1" value={props.wanType} onValueChange={(v) => props.setWanType(v as "static" | "dhcp" | "pppoe")}>
            {(["static", "dhcp", "pppoe"] as const).map((t) => (
              <div key={t} className="flex items-center gap-2">
                <RadioGroupItem value={t} id={`wan-${t}`} />
                <Label htmlFor={`wan-${t}`} className="font-normal">
                  {t}
                </Label>
              </div>
            ))}
          </RadioGroup>
        </div>
      </div>
      <p className="rounded-lg border border-dashed border-zinc-200 px-3 py-2 text-[11px] text-zinc-500 dark:border-zinc-800">
        Demo note: the wizard records your choice for the summary; the actual interface/wan-policy writes happen in{" "}
        <span className="font-mono">#</span>⁠<span className="font-mono">/network/interfaces</span> — this step saves
        nothing by design (M02 owns that surface).
      </p>
    </div>
  );
}

function LanStep(props: {
  ifaces: IfaceLite[];
  lanIface: string;
  setLanIface: (v: string) => void;
  subnetCidr: string;
  setSubnetCidr: (v: string) => void;
  rangeStart: string;
  setRangeStart: (v: string) => void;
  rangeEnd: string;
  setRangeEnd: (v: string) => void;
  gateway: string;
  setGateway: (v: string) => void;
  saved: boolean;
  onSave: () => void;
  saving: boolean;
}) {
  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold">LAN / DHCP</h2>
        <p className="mt-1 text-sm text-zinc-500">
          Creates a starter DHCP subnet through the regular DHCP endpoint (M06). Existing subnets are left alone —
          overlap is rejected by the API and non-blocking here.
        </p>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label>LAN interface</Label>
          <Select value={props.lanIface} onValueChange={props.setLanIface}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {props.ifaces.map((i) => (
                <SelectItem key={i.name} value={i.name}>
                  {i.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1.5">
          <Label>Subnet (CIDR)</Label>
          <Input value={props.subnetCidr} onChange={(e) => props.setSubnetCidr(e.target.value)} />
        </div>
        <div className="space-y-1.5">
          <Label>Pool start</Label>
          <Input value={props.rangeStart} onChange={(e) => props.setRangeStart(e.target.value)} />
        </div>
        <div className="space-y-1.5">
          <Label>Pool end</Label>
          <Input value={props.rangeEnd} onChange={(e) => props.setRangeEnd(e.target.value)} />
        </div>
        <div className="space-y-1.5">
          <Label>Gateway</Label>
          <Input value={props.gateway} onChange={(e) => props.setGateway(e.target.value)} />
        </div>
      </div>
      <div className="flex items-center justify-between">
        <p className={cn("text-[11px]", props.saved ? "text-emerald-600 dark:text-emerald-400" : "text-zinc-400")}>
          {props.saved ? "Subnet created — safe to continue." : "Defaults are applied on “Save subnet”; you can also just continue."}
        </p>
        <Button variant="outline" size="sm" disabled={props.saving || props.saved} onClick={props.onSave}>
          {props.saving ? <Icons.Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Icons.Save className="mr-2 h-4 w-4" />}
          Save subnet
        </Button>
      </div>
    </div>
  );
}

function TemplateStep(props: {
  templates: PolicyTemplateDTO[];
  loading: boolean;
  applied: string | null;
  onApply: (id: string) => void;
  applying: boolean;
}) {
  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold">Policy template</h2>
        <p className="mt-1 text-sm text-zinc-500">
          Optional starter bundle for firewall / NAT / IPS / DNS / QoS. Applying is audited and overwrites matching
          sections — or skip and stay on the seed policy.
        </p>
      </div>
      <div className="grid gap-3 sm:grid-cols-3">
        {props.templates.map((t) => (
          <div
            key={t.id}
            className={cn(
              "flex flex-col rounded-lg border p-3",
              props.applied === t.id ? "border-blue-500/60 bg-blue-500/5" : "border-zinc-200 dark:border-zinc-800",
            )}
          >
            <p className="text-sm font-semibold">{t.name}</p>
            <p className="mt-1 flex-1 text-[11px] text-zinc-500">{t.description}</p>
            <Button
              size="sm"
              variant={props.applied === t.id ? "secondary" : "outline"}
              className="mt-2"
              disabled={props.applying}
              onClick={() => props.onApply(t.id)}
            >
              {props.applied === t.id ? (
                <>
                  <Icons.Check className="mr-1.5 h-3.5 w-3.5" /> Applied
                </>
              ) : (
                "Apply"
              )}
            </Button>
          </div>
        ))}
      </div>
      {props.loading ? <p className="text-xs text-zinc-400">Loading templates…</p> : null}
    </div>
  );
}

function FinishStep(props: {
  summary: {
    timezone: string;
    wanIface: string;
    wanType: string;
    lanIface: string;
    subnetCidr: string;
    dhcpSaved: boolean;
    appliedTemplate: string | null;
  };
}) {
  const rows: Array<[string, string]> = [
    ["Timezone", props.summary.timezone],
    ["WAN", props.summary.wanIface ? `${props.summary.wanIface} (${props.summary.wanType})` : "unchanged"],
    [
      "LAN / DHCP",
      props.summary.dhcpSaved
        ? `${props.summary.subnetCidr} on ${props.summary.lanIface}`
        : `${props.summary.subnetCidr} on ${props.summary.lanIface} (not saved)`,
    ],
    ["Policy template", props.summary.appliedTemplate ?? "skipped — seed policy kept"],
  ];
  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold">Ready to finish</h2>
        <p className="mt-1 text-sm text-zinc-500">
          Finishing marks setup complete (audited) and opens the console on the dashboard.
        </p>
      </div>
      <dl className="divide-y divide-zinc-100 rounded-lg border border-zinc-200 dark:divide-zinc-800 dark:border-zinc-800">
        {rows.map(([k, v]) => (
          <div key={k} className="flex items-center justify-between gap-3 px-3 py-2 text-sm">
            <dt className="text-zinc-500">{k}</dt>
            <dd className="font-medium">{v}</dd>
          </div>
        ))}
      </dl>
      <p className="rounded-lg border border-dashed border-zinc-200 px-3 py-2 text-[11px] text-zinc-500 dark:border-zinc-800">
        The gate is hard in Phase 1 — the wizard completes only by finishing. Demo convenience trade-off (M10 §8).
      </p>
    </div>
  );
}
