"use client";

/**
 * #/web/waf — Web Application Firewall (M17 §2.4).
 * Vhost card grid (backend, TLS cert binding, mode badge, enabled switch) →
 * selected vhost shows its policy card (CRS badge, paranoia pills, anomaly
 * threshold sliders, learning mode, rate limit, geo-block chips, API
 * protection), exclusions table, a simulated CRS "test request" card and the
 * 24h WAF log feed + stats strip. Theme: white + enterprise red-700.
 */

import { useState } from "react";
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import { ConfirmDialog, EmptyBlock, FieldLabel, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";
import {
  CRS_VERSIONS,
  EXCLUSION_SCOPES,
  TEST_METHODS,
  TEST_PRESETS,
  fmtRelative,
  fieldErrorsOf,
  qs,
  wafApi,
  type CertOption,
  type CrsVersion,
  type ExclusionDTO,
  type ExclusionScope,
  type PolicyDTO,
  type TestMethod,
  type TestResultDTO,
  type VhostDTO,
  type WafAction,
  type WafStats,
} from "./waf-api";

const WAF_KEY = ["waf"] as const;

const SCROLLY =
  "max-h-96 overflow-y-auto [scrollbar-width:thin] [&::-webkit-scrollbar]:h-1.5 [&::-webkit-scrollbar]:w-1.5 [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-zinc-300 dark:[&::-webkit-scrollbar-thumb]:bg-zinc-700";

// ── badges ──────────────────────────────────────────────────────────────────

const ACTION_BADGE: Record<WafAction, string> = {
  pass: "border-red-600/40 bg-red-600/10 text-red-700 dark:text-red-500",
  log: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  block: "border-transparent bg-red-600 text-white",
};

export function ActionBadge({ action, className }: { action: WafAction; className?: string }) {
  const Icon = action === "pass" ? Icons.ShieldCheck : action === "log" ? Icons.Eye : Icons.Ban;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium", ACTION_BADGE[action] ?? ACTION_BADGE.pass, className)}>
      <Icon className="h-3 w-3" />
      {action}
    </Badge>
  );
}

function ModeBadge({ mode }: { mode: string }) {
  const waf = mode === "waf";
  return (
    <Badge
      variant="outline"
      className={cn(
        "text-[10px] font-semibold uppercase",
        waf
          ? "border-red-600/40 bg-red-600/10 text-red-700 dark:text-red-500"
          : "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
      )}
    >
      <Icons.Shield className="mr-1 h-3 w-3" />
      {mode.replace("_", " ")}
    </Badge>
  );
}

function ScopeBadge({ scope }: { scope: string }) {
  return (
    <Badge
      variant="outline"
      className="border-zinc-300 bg-zinc-100 font-mono text-[10px] uppercase text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
    >
      {scope}
    </Badge>
  );
}

/** First fieldError message (or the error message itself) for dialog footers. */
function errText(err: unknown, fallback: string): string {
  const fe = fieldErrorsOf(err);
  const first = Object.entries(fe)[0];
  if (first) return `${first[0]}: ${first[1].join(", ")}`;
  return err instanceof Error ? err.message : fallback;
}

// ── ISO country chips editor ────────────────────────────────────────────────

function IsoChips({
  value,
  onChange,
  editable,
}: {
  value: string[];
  onChange?: (next: string[]) => void;
  editable?: boolean;
}) {
  const [draft, setDraft] = useState("");
  const [invalid, setInvalid] = useState(false);

  if (!editable) {
    if (value.length === 0) return <span className="text-xs text-zinc-400">none</span>;
    return (
      <div className="flex flex-wrap gap-1.5">
        {value.map((c) => (
          <Badge
            key={c}
            variant="outline"
            className="border-zinc-300 bg-zinc-100 font-mono text-[10px] text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
          >
            {c}
          </Badge>
        ))}
      </div>
    );
  }

  const add = () => {
    const code = draft.trim().toUpperCase();
    if (!/^[A-Z]{2}$/.test(code)) {
      setInvalid(true);
      return;
    }
    setInvalid(false);
    if (!value.includes(code)) onChange?.([...value, code]);
    setDraft("");
  };

  return (
    <div className="space-y-2">
      <div className="flex gap-2">
        <Input
          value={draft}
          onChange={(e) => {
            setDraft(e.target.value.toUpperCase());
            setInvalid(false);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              add();
            }
          }}
          placeholder="ISO code, e.g. CN"
          className="h-9 w-40 font-mono text-xs uppercase"
          aria-label="Add country code"
        />
        <Button type="button" variant="outline" size="sm" className="h-9 gap-1" onClick={add}>
          <Icons.Plus className="h-3.5 w-3.5" /> Add
        </Button>
      </div>
      {invalid && <p className="text-xs text-rose-600">Enter a 2-letter uppercase ISO code</p>}
      {value.length > 0 ? (
        <div className="flex flex-wrap gap-1.5">
          {value.map((c) => (
            <Badge key={c} variant="outline" className="gap-1 border-zinc-300 pr-1 font-mono dark:border-zinc-700">
              {c}
              <button
                type="button"
                aria-label={`Remove ${c}`}
                className="rounded-sm p-0.5 hover:bg-zinc-200 dark:hover:bg-zinc-700"
                onClick={() => onChange?.(value.filter((v) => v !== c))}
              >
                <Icons.X className="h-3 w-3" />
              </button>
            </Badge>
          ))}
        </div>
      ) : (
        <p className="text-xs text-zinc-400">No countries blocked</p>
      )}
    </div>
  );
}

// ── vhost editor (create + edit) ────────────────────────────────────────────

function VhostEditor(props: { initial: VhostDTO | null; certs: CertOption[]; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = props.initial !== null;
  const [name, setName] = useState(props.initial?.name ?? "");
  const [hostname, setHostname] = useState(props.initial?.hostname ?? "");
  const [backendHost, setBackendHost] = useState(props.initial?.backendHost ?? "");
  const [backendPort, setBackendPort] = useState(String(props.initial?.backendPort ?? 8080));
  const [listenPort, setListenPort] = useState(String(props.initial?.listenPort ?? 443));
  const [tls, setTls] = useState(props.initial?.tls ?? true);
  const [certId, setCertId] = useState<string>(props.initial?.certId ? String(props.initial.certId) : "none");
  const [mode, setMode] = useState<"waf" | "reverse_proxy">(props.initial?.mode ?? "waf");
  const [enabled, setEnabled] = useState(props.initial?.enabled ?? true);
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      isEdit ? wafApi.updateVhost(props.initial!.id, body) : wafApi.createVhost(body),
    onSuccess: (v) => {
      toastOk(`${isEdit ? "Updated" : "Created"} vhost "${v.name}"`);
      void queryClient.invalidateQueries({ queryKey: WAF_KEY });
      props.onClose();
    },
    onError: (e) => setErr(errText(e, "Save failed")),
  });

  const backendPortNum = Number(backendPort);
  const listenPortNum = Number(listenPort);
  const valid =
    name.trim().length > 0 &&
    hostname.trim().length > 0 &&
    backendHost.trim().length > 0 &&
    Number.isInteger(backendPortNum) &&
    backendPortNum >= 1 &&
    backendPortNum <= 65535 &&
    Number.isInteger(listenPortNum) &&
    listenPortNum >= 1 &&
    listenPortNum <= 65535;

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-base">{isEdit ? "Edit vhost" : "Add virtual host"}</DialogTitle>
          <DialogDescription>
            Public hostname fronted by the WAF, proxied to an upstream backend. TLS vhosts can bind an active
            certificate (issued for WAF or general use).
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel>Display name</FieldLabel>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Shop frontend" />
            </div>
            <div>
              <FieldLabel hint="FQDN">Hostname</FieldLabel>
              <Input
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                placeholder="shop.corp.example"
                className="font-mono text-xs"
              />
            </div>
          </div>
          <div className="grid grid-cols-3 gap-4">
            <div className="col-span-2">
              <FieldLabel hint="FQDN or IPv4">Backend host</FieldLabel>
              <Input
                value={backendHost}
                onChange={(e) => setBackendHost(e.target.value)}
                placeholder="10.20.30.11"
                className="font-mono text-xs"
              />
            </div>
            <div>
              <FieldLabel hint="1–65535">Backend port</FieldLabel>
              <Input type="number" min={1} max={65535} value={backendPort} onChange={(e) => setBackendPort(e.target.value)} />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel hint="1–65535">Listen port</FieldLabel>
              <Input type="number" min={1} max={65535} value={listenPort} onChange={(e) => setListenPort(e.target.value)} />
            </div>
            <div>
              <FieldLabel>Mode</FieldLabel>
              <Select value={mode} onValueChange={(v) => setMode(v as "waf" | "reverse_proxy")}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="waf">WAF protected</SelectItem>
                  <SelectItem value="reverse_proxy">Reverse proxy only</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2">
              <Switch id="vh-tls" checked={tls} onCheckedChange={setTls} />
              <Label htmlFor="vh-tls" className="text-xs">
                TLS termination
              </Label>
            </div>
            <div className="flex items-center gap-2">
              <Switch id="vh-enabled" checked={enabled} onCheckedChange={setEnabled} />
              <Label htmlFor="vh-enabled" className="text-xs">
                Enabled
              </Label>
            </div>
          </div>
          {tls && (
            <div>
              <FieldLabel hint="active · waf | general">TLS certificate</FieldLabel>
              <Select value={certId} onValueChange={setCertId}>
                <SelectTrigger>
                  <SelectValue placeholder="Select a certificate" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">No certificate bound</SelectItem>
                  {props.certs.map((c) => (
                    <SelectItem key={c.id} value={String(c.id)}>
                      {c.name} <span className="font-mono text-[10px] text-zinc-400">({c.commonName})</span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button
            className="bg-red-700 text-white hover:bg-red-800"
            disabled={!valid || save.isPending}
            onClick={() =>
              save.mutate({
                name: name.trim(),
                hostname: hostname.trim(),
                backendHost: backendHost.trim(),
                backendPort: backendPortNum,
                listenPort: listenPortNum,
                tls,
                certId: tls && certId !== "none" ? Number(certId) : null,
                mode,
                enabled,
              })
            }
          >
            {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create vhost"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── policy editor (create + edit) ───────────────────────────────────────────

function PolicyEditor(props: {
  initial: PolicyDTO | null;
  vhosts: VhostDTO[];
  defaultVhostId?: number;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const isEdit = props.initial !== null;
  const [name, setName] = useState(props.initial?.name ?? "");
  const [vhostId, setVhostId] = useState<string>(
    String(props.initial?.vhostId ?? props.defaultVhostId ?? props.vhosts[0]?.id ?? ""),
  );
  const [owaspCrsEnabled, setOwasp] = useState(props.initial?.owaspCrsEnabled ?? true);
  const [crsVersion, setCrsVersion] = useState<CrsVersion>(props.initial?.crsVersion ?? "4.0");
  const [paranoiaLevel, setParanoiaLevel] = useState(props.initial?.paranoiaLevel ?? 1);
  const [anomalyInThreshold, setAnomalyIn] = useState(props.initial?.anomalyInThreshold ?? 5);
  const [anomalyOutThreshold, setAnomalyOut] = useState(props.initial?.anomalyOutThreshold ?? 4);
  const [learningMode, setLearningMode] = useState(props.initial?.learningMode ?? false);
  const [geoBlockCountries, setGeo] = useState<string[]>(props.initial?.geoBlockCountries ?? []);
  const [rateLimitRpm, setRpm] = useState(props.initial?.rateLimitRpm ? String(props.initial.rateLimitRpm) : "");
  const [rateLimitBurst, setBurst] = useState(props.initial?.rateLimitBurst ? String(props.initial.rateLimitBurst) : "");
  const [apiProtection, setApiProtection] = useState(props.initial?.apiProtection ?? false);
  const [enabled, setEnabled] = useState(props.initial?.enabled ?? true);
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      isEdit ? wafApi.updatePolicy(props.initial!.id, body) : wafApi.createPolicy(body),
    onSuccess: (p) => {
      toastOk(`${isEdit ? "Updated" : "Created"} policy "${p.name}"`);
      void queryClient.invalidateQueries({ queryKey: WAF_KEY });
      props.onClose();
    },
    onError: (e) => setErr(errText(e, "Save failed")),
  });

  const rpm = rateLimitRpm === "" ? null : Number(rateLimitRpm);
  const burst = rateLimitBurst === "" ? null : Number(rateLimitBurst);
  const rpmInvalid = rpm !== null && (!Number.isInteger(rpm) || rpm < 10 || rpm > 10000);
  const burstInvalid = burst !== null && (!Number.isInteger(burst) || burst < 1 || burst > 10000);
  const valid = name.trim().length > 0 && vhostId !== "" && !rpmInvalid && !burstInvalid;

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="max-h-[85vh] sm:max-w-xl">
        <DialogHeader>
          <DialogTitle className="text-base">{isEdit ? "Edit policy" : "Create policy"}</DialogTitle>
          <DialogDescription>
            One policy per vhost. OWASP CRS anomaly scoring: request bodies accumulate rule scores and are blocked
            above the inbound threshold.
          </DialogDescription>
        </DialogHeader>
        <div className="grid max-h-[60vh] gap-4 overflow-y-auto py-2 pr-1 [scrollbar-width:thin]">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel>Policy name</FieldLabel>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Shop WAF" />
            </div>
            <div>
              <FieldLabel hint={isEdit ? "moving re-checks uniqueness" : undefined}>Vhost</FieldLabel>
              <Select value={vhostId} onValueChange={setVhostId}>
                <SelectTrigger>
                  <SelectValue placeholder="Select vhost" />
                </SelectTrigger>
                <SelectContent>
                  {props.vhosts.map((v) => (
                    <SelectItem key={v.id} value={String(v.id)}>
                      {v.hostname}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
            <div className="flex items-center gap-2">
              <Switch id="pol-crs" checked={owaspCrsEnabled} onCheckedChange={setOwasp} />
              <Label htmlFor="pol-crs" className="text-xs">
                OWASP CRS rules
              </Label>
            </div>
            <div className="flex items-center gap-2">
              <Switch id="pol-learning" checked={learningMode} onCheckedChange={setLearningMode} />
              <Label htmlFor="pol-learning" className="text-xs">
                Learning mode
              </Label>
              {learningMode && (
                <Badge variant="outline" className="border-amber-500/40 bg-amber-500/10 text-[10px] text-amber-600 dark:text-amber-400">
                  log-only
                </Badge>
              )}
            </div>
            <div className="flex items-center gap-2">
              <Switch id="pol-api" checked={apiProtection} onCheckedChange={setApiProtection} />
              <Label htmlFor="pol-api" className="text-xs">
                API protection
              </Label>
            </div>
            <div className="flex items-center gap-2">
              <Switch id="pol-enabled" checked={enabled} onCheckedChange={setEnabled} />
              <Label htmlFor="pol-enabled" className="text-xs">
                Enabled
              </Label>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel>CRS version</FieldLabel>
              <Select value={crsVersion} onValueChange={(v) => setCrsVersion(v as CrsVersion)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CRS_VERSIONS.map((v) => (
                    <SelectItem key={v} value={v}>
                      CRS {v}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel hint="1–3">Paranoia level</FieldLabel>
              <div className="flex gap-1.5" role="radiogroup" aria-label="Paranoia level">
                {[1, 2, 3].map((lvl) => (
                  <button
                    key={lvl}
                    type="button"
                    role="radio"
                    aria-checked={paranoiaLevel === lvl}
                    onClick={() => setParanoiaLevel(lvl)}
                    className={cn(
                      "h-9 min-w-9 rounded-md border px-3 text-xs font-medium transition-colors",
                      paranoiaLevel === lvl
                        ? "border-red-700 bg-red-700 text-white"
                        : "border-zinc-200 text-zinc-500 hover:bg-zinc-100 dark:border-zinc-800 dark:hover:bg-zinc-800",
                    )}
                  >
                    PL{lvl}
                  </button>
                ))}
              </div>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel hint={`in-threshold: ${anomalyInThreshold}`}>Anomaly in-threshold</FieldLabel>
              <Slider
                value={[anomalyInThreshold]}
                onValueChange={(v) => setAnomalyIn(v[0] ?? 5)}
                min={1}
                max={50}
                step={1}
                aria-label="Anomaly in-threshold"
              />
            </div>
            <div>
              <FieldLabel hint={`out-threshold: ${anomalyOutThreshold}`}>Anomaly out-threshold</FieldLabel>
              <Slider
                value={[anomalyOutThreshold]}
                onValueChange={(v) => setAnomalyOut(v[0] ?? 4)}
                min={1}
                max={50}
                step={1}
                aria-label="Anomaly out-threshold"
              />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel hint="10–10000, empty = off">Rate limit (rpm)</FieldLabel>
              <Input
                type="number"
                min={10}
                max={10000}
                value={rateLimitRpm}
                onChange={(e) => setRpm(e.target.value)}
                placeholder="e.g. 300"
              />
            </div>
            <div>
              <FieldLabel hint="optional burst">Rate limit burst</FieldLabel>
              <Input
                type="number"
                min={1}
                max={10000}
                value={rateLimitBurst}
                onChange={(e) => setBurst(e.target.value)}
                placeholder="e.g. 100"
              />
            </div>
          </div>
          <div>
            <FieldLabel hint="2-letter ISO codes">Geo-block countries</FieldLabel>
            <IsoChips value={geoBlockCountries} onChange={setGeo} editable />
          </div>
          {(rpmInvalid || burstInvalid) && (
            <p className="text-xs text-rose-600">Rate limit must be 10–10000 rpm; burst 1–10000</p>
          )}
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button
            className="bg-red-700 text-white hover:bg-red-800"
            disabled={!valid || save.isPending}
            onClick={() =>
              save.mutate({
                name: name.trim(),
                vhostId: Number(vhostId),
                owaspCrsEnabled,
                crsVersion,
                paranoiaLevel,
                anomalyInThreshold,
                anomalyOutThreshold,
                learningMode,
                geoBlockCountries,
                rateLimitRpm: rpm,
                rateLimitBurst: burst,
                apiProtection,
                enabled,
              })
            }
          >
            {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create policy"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── exclusion editor (create) ───────────────────────────────────────────────

function ExclusionEditor(props: { policyId: number; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [scope, setScope] = useState<ExclusionScope>("rule_id");
  const [matchValue, setMatchValue] = useState("");
  const [ruleId, setRuleId] = useState("");
  const [note, setNote] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => wafApi.createExclusion(props.policyId, body),
    onSuccess: (x) => {
      toastOk(`Exclusion "${x.matchValue}" added`);
      void queryClient.invalidateQueries({ queryKey: WAF_KEY });
      props.onClose();
    },
    onError: (e) => setErr(errText(e, "Save failed")),
  });

  const ruleIdNum = ruleId === "" ? null : Number(ruleId);
  const valid = matchValue.trim().length > 0 && (ruleId === "" || (Number.isInteger(ruleIdNum) && (ruleIdNum ?? 0) > 0));

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-base">Add exclusion</DialogTitle>
          <DialogDescription>
            Exempt a rule id, a request parameter or a URL from inspection — the classic false-positive escape hatch.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel>Scope</FieldLabel>
              <Select value={scope} onValueChange={(v) => setScope(v as ExclusionScope)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {EXCLUSION_SCOPES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {s}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel
                hint={scope === "rule_id" ? "e.g. 942100" : scope === "param" ? "e.g. arg:password" : "e.g. /api/login"}
              >
                Match value
              </FieldLabel>
              <Input
                value={matchValue}
                onChange={(e) => setMatchValue(e.target.value)}
                className="font-mono text-xs"
                placeholder={scope === "rule_id" ? "942100" : scope === "param" ? "arg:password" : "/api/login"}
              />
            </div>
          </div>
          {scope === "rule_id" && (
            <div>
              <FieldLabel hint="optional numeric id">Rule id</FieldLabel>
              <Input type="number" min={1} value={ruleId} onChange={(e) => setRuleId(e.target.value)} placeholder="942100" />
            </div>
          )}
          <div>
            <FieldLabel hint="optional">Note</FieldLabel>
            <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="FP on checkout coupon" />
          </div>
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button
            className="bg-red-700 text-white hover:bg-red-800"
            disabled={!valid || save.isPending}
            onClick={() =>
              save.mutate({
                scope,
                matchValue: matchValue.trim(),
                ruleId: scope === "rule_id" ? ruleIdNum : null,
                note: note.trim() || null,
                enabled: true,
              })
            }
          >
            {save.isPending ? "Saving…" : "Add exclusion"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── policy card (selected vhost) ────────────────────────────────────────────

function PolicyCard(props: {
  vhost: VhostDTO;
  policy: PolicyDTO | null;
  onEdit: (p: PolicyDTO | null) => void;
  onDelete: (p: PolicyDTO) => void;
}) {
  const queryClient = useQueryClient();
  const p = props.policy;

  const toggle = useMutation({
    mutationFn: ({ id, body }: { id: number; body: Record<string, unknown> }) => wafApi.updatePolicy(id, body),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: WAF_KEY }),
    onError: (e) => toastErr(e, "Toggle failed"),
  });

  if (!p) {
    return (
      <Card className="p-0">
        <CardHeader className="flex-row items-center justify-between space-y-0 p-4 pb-0">
          <CardTitle className="text-sm font-medium">WAF policy</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <EmptyBlock
            icon={<Icons.ShieldAlert className="h-6 w-6" />}
            title="No policy attached to this vhost"
            description="Create a policy to enable OWASP CRS inspection, rate limiting and geo-blocking for this host."
            action={
              <Button className="bg-red-700 text-white hover:bg-red-800" onClick={() => props.onEdit(null)}>
                <Icons.Plus className="mr-1 h-4 w-4" /> Create policy
              </Button>
            }
          />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="p-0">
      <CardHeader className="flex-row items-start justify-between space-y-0 p-4 pb-3">
        <div className="min-w-0">
          <CardTitle className="flex flex-wrap items-center gap-2 text-sm font-medium">
            {p.name}
            {p.owaspCrsEnabled ? (
              <Badge variant="outline" className="border-red-600/40 bg-red-600/10 text-[10px] font-semibold text-red-700 dark:text-red-500">
                CRS {p.crsVersion}
              </Badge>
            ) : (
              <Badge variant="outline" className="border-zinc-300 bg-zinc-100 text-[10px] text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800">
                CRS off
              </Badge>
            )}
            {p.learningMode && (
              <Badge variant="outline" className="border-amber-500/40 bg-amber-500/10 text-[10px] font-semibold text-amber-600 dark:text-amber-400">
                log-only
              </Badge>
            )}
          </CardTitle>
          <p className="mt-1 text-[11px] text-zinc-500">Attached to {props.vhost.hostname}</p>
        </div>
        <Switch
          checked={p.enabled}
          onCheckedChange={(enabled) => toggle.mutate({ id: p.id, body: { enabled } })}
          aria-label={`Toggle policy ${p.name}`}
        />
      </CardHeader>
      <CardContent className="flex flex-col gap-4 p-4 pt-0">
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <FieldLabel hint={`blocks at in ≥ ${p.anomalyInThreshold}`}>Paranoia level</FieldLabel>
            <div className="flex gap-1.5">
              {[1, 2, 3].map((lvl) => (
                <span
                  key={lvl}
                  className={cn(
                    "inline-flex h-7 min-w-7 items-center justify-center rounded-full border px-2 text-[11px] font-semibold",
                    lvl === p.paranoiaLevel
                      ? "border-red-700 bg-red-700 text-white"
                      : "border-zinc-200 text-zinc-400 dark:border-zinc-800",
                  )}
                >
                  PL{lvl}
                </span>
              ))}
            </div>
          </div>
          <div>
            <FieldLabel>Thresholds (in / out)</FieldLabel>
            <div className="flex items-center gap-3">
              <span className="w-14 font-mono text-xs text-zinc-600 dark:text-zinc-300">
                in {p.anomalyInThreshold}
              </span>
              <Slider value={[p.anomalyInThreshold]} min={1} max={50} step={1} disabled aria-label="In threshold" className="flex-1" />
              <span className="w-14 text-right font-mono text-xs text-zinc-600 dark:text-zinc-300">
                out {p.anomalyOutThreshold}
              </span>
              <Slider value={[p.anomalyOutThreshold]} min={1} max={50} step={1} disabled aria-label="Out threshold" className="flex-1" />
            </div>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-[11px] text-zinc-500">
          <span className="inline-flex items-center gap-1">
            <Icons.Gauge className="h-3.5 w-3.5" />
            {p.rateLimitRpm ? `${p.rateLimitRpm} rpm${p.rateLimitBurst ? ` · burst ${p.rateLimitBurst}` : ""}` : "no rate limit"}
          </span>
          <span className="inline-flex items-center gap-1">
            <Icons.Globe className="h-3.5 w-3.5" />
            geo-block: {p.geoBlockCountries.length} countr{p.geoBlockCountries.length === 1 ? "y" : "ies"}
          </span>
          {p.apiProtection && (
            <span className="inline-flex items-center gap-1 font-medium text-red-700 dark:text-red-500">
              <Icons.Braces className="h-3.5 w-3.5" /> API protection
            </span>
          )}
        </div>
        <div>
          <FieldLabel>Geo-blocked countries</FieldLabel>
          <IsoChips value={p.geoBlockCountries} />
        </div>
        <div className="flex flex-wrap items-center gap-2 border-t border-zinc-200 pt-3 dark:border-zinc-800">
          <Button
            variant="outline"
            size="sm"
            className="h-8 gap-1.5"
            onClick={() => props.onEdit(p)}
          >
            <Icons.Pencil className="h-3.5 w-3.5" /> Edit policy
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="h-8 gap-1.5 text-rose-500 hover:text-rose-600"
            onClick={() => props.onDelete(p)}
          >
            <Icons.Trash2 className="h-3.5 w-3.5" /> Delete policy
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ── exclusions table (selected policy) ──────────────────────────────────────

function ExclusionsTable(props: { policy: PolicyDTO; onAdd: () => void; onDelete: (x: ExclusionDTO) => void }) {
  const exQuery = useQuery({
    queryKey: ["waf", "exclusions", props.policy.id],
    queryFn: () => wafApi.listExclusions(props.policy.id),
  });
  const rows = exQuery.data ?? [];

  return (
    <Card className="p-0">
      <CardHeader className="flex-row items-center justify-between space-y-0 p-4 pb-3">
        <CardTitle className="text-sm font-medium">
          Exclusions
          <span className="ml-2 text-[11px] font-normal text-zinc-400">{rows.length} rule(s)</span>
        </CardTitle>
        <Button variant="outline" size="sm" className="h-8 gap-1.5" onClick={props.onAdd}>
          <Icons.Plus className="h-3.5 w-3.5" /> Add exclusion
        </Button>
      </CardHeader>
      <CardContent className="p-4 pt-0">
        {exQuery.isLoading ? (
          <TableSkeleton rows={2} cols={5} />
        ) : rows.length === 0 ? (
          <EmptyBlock
            icon={<Icons.FilterX className="h-6 w-6" />}
            title="No exclusions"
            description="Tune false positives by exempting rule ids, parameters or URLs from inspection."
          />
        ) : (
          <div className={SCROLLY}>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-24">Scope</TableHead>
                  <TableHead>Match value</TableHead>
                  <TableHead className="w-20">Rule id</TableHead>
                  <TableHead>Note</TableHead>
                  <TableHead className="w-10" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((x) => (
                  <TableRow key={x.id}>
                    <TableCell>
                      <ScopeBadge scope={x.scope} />
                    </TableCell>
                    <TableCell className="font-mono text-xs">{x.matchValue}</TableCell>
                    <TableCell className="font-mono text-xs">{x.ruleId ?? "—"}</TableCell>
                    <TableCell className="max-w-48 truncate text-xs text-zinc-500">{x.note ?? "—"}</TableCell>
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7 text-rose-500 hover:text-rose-600"
                        aria-label={`Delete exclusion ${x.matchValue}`}
                        onClick={() => props.onDelete(x)}
                      >
                        <Icons.Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ── test request card (simulated CRS run) ───────────────────────────────────

interface RecentTest {
  method: string;
  url: string;
  action: WafAction;
  anomalyScore: number;
  at: string;
}

function TestRequestCard({ policy }: { policy: PolicyDTO }) {
  const [method, setMethod] = useState<TestMethod>("GET");
  const [url, setUrl] = useState("/shop/products?page=2");
  const [payload, setPayload] = useState("");
  const [result, setResult] = useState<TestResultDTO | null>(null);
  const [recent, setRecent] = useState<RecentTest[]>([]);

  const run = useMutation({
    mutationFn: () => wafApi.testPolicy(policy.id, { method, url: url.trim(), payload }),
    onSuccess: (r) => {
      setResult(r);
      setRecent((prev) =>
        [{ method, url: url.trim(), action: r.action, anomalyScore: r.anomalyScore, at: new Date().toISOString() }, ...prev].slice(0, 6),
      );
    },
    onError: (e) => toastErr(e, "Test failed"),
  });

  const score = result?.anomalyScore ?? 0;
  const threshold = result?.threshold ?? policy.anomalyInThreshold;
  const scale = Math.max(threshold * 2, score, 1);
  const pct = Math.min(100, Math.round((score / scale) * 100));
  const thresholdPct = Math.min(100, Math.round((threshold / scale) * 100));

  return (
    <Card className="p-0">
      <CardHeader className="flex-row items-center justify-between space-y-0 p-4 pb-3">
        <CardTitle className="flex items-center gap-2 text-sm font-medium">
          <Icons.FlaskConical className="h-4 w-4 text-red-700 dark:text-red-500" />
          Test request
          <Badge variant="outline" className="border-zinc-300 bg-zinc-100 text-[10px] font-normal text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800">
            simulated CRS
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-4 p-4 pt-0">
        <div className="flex flex-wrap gap-1.5">
          {TEST_PRESETS.map((preset) => (
            <button
              key={preset.label}
              type="button"
              onClick={() => {
                setMethod(preset.method);
                setUrl(preset.url);
                setPayload(preset.payload);
              }}
              className="rounded-full border border-zinc-200 px-2.5 py-1 text-[11px] text-zinc-500 transition-colors hover:bg-zinc-100 dark:border-zinc-800 dark:hover:bg-zinc-800"
            >
              {preset.label}
            </button>
          ))}
        </div>
        <div className="grid gap-3 sm:grid-cols-[110px_1fr]">
          <div>
            <FieldLabel>Method</FieldLabel>
            <Select value={method} onValueChange={(v) => setMethod(v as TestMethod)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {TEST_METHODS.map((m) => (
                  <SelectItem key={m} value={m}>
                    {m}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <FieldLabel>URL</FieldLabel>
            <Input value={url} onChange={(e) => setUrl(e.target.value)} className="font-mono text-xs" placeholder="/shop/checkout" />
          </div>
        </div>
        <div>
          <FieldLabel hint="max 4096 chars · try country=CN for geo sim">Payload</FieldLabel>
          <Textarea
            value={payload}
            onChange={(e) => setPayload(e.target.value)}
            className="min-h-20 font-mono text-xs"
            placeholder="user=admin' OR 1=1--&pass=x"
          />
        </div>
        <div>
          <Button
            className="min-h-9 bg-red-700 text-white hover:bg-red-800"
            disabled={run.isPending || url.trim().length === 0}
            onClick={() => run.mutate()}
          >
            {run.isPending ? (
              <>
                <Icons.Loader2 className="mr-1.5 h-4 w-4 animate-spin" /> Evaluating…
              </>
            ) : (
              <>
                <Icons.Play className="mr-1.5 h-4 w-4" /> Run
              </>
            )}
          </Button>
        </div>

        {result && (
          <div className="rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
            <div className="flex flex-wrap items-center gap-2">
              <ActionBadge action={result.action} />
              {result.reason && result.reason !== "anomaly" && (
                <Badge variant="outline" className="border-red-500/40 bg-red-500/10 text-[10px] uppercase text-red-600 dark:text-red-400">
                  {result.reason.replace("_", " ")}
                </Badge>
              )}
              <span className="ml-auto font-mono text-xs text-zinc-500">
                score {result.anomalyScore} / in-threshold {result.threshold}
              </span>
            </div>
            <div className="relative mt-3 h-2 w-full rounded-full bg-zinc-100 dark:bg-zinc-800" role="img" aria-label={`Anomaly score ${result.anomalyScore} of threshold ${result.threshold}`}>
              <div
                className={cn("h-2 rounded-full transition-all", score >= threshold ? "bg-red-600" : score > 0 ? "bg-amber-500" : "bg-red-700")}
                style={{ width: `${pct}%` }}
              />
              <div className="absolute top-[-3px] h-3.5 w-0.5 bg-zinc-500" style={{ left: `${thresholdPct}%` }} title={`in-threshold ${threshold}`} />
            </div>
            {result.action === "log" && policy.learningMode && (
              <p className="mt-2 flex items-center gap-1.5 text-[11px] text-amber-600 dark:text-amber-400">
                <Icons.Eye className="h-3.5 w-3.5" /> Learning mode — would have blocked, logged instead.
              </p>
            )}
            {result.matched.length > 0 ? (
              <div className="mt-3 space-y-1.5">
                <p className="text-[11px] font-semibold uppercase tracking-wide text-zinc-500">
                  Matched rules ({result.matched.length})
                </p>
                <div className="space-y-1">
                  {result.matched.map((m) => (
                    <div key={m.id} className="flex items-center gap-2 rounded-md bg-zinc-50 px-2 py-1.5 text-xs dark:bg-zinc-800/60">
                      <span className="font-mono font-semibold text-red-700 dark:text-red-500">{m.id}</span>
                      <span className="min-w-0 flex-1 truncate text-zinc-600 dark:text-zinc-300" title={m.msg}>
                        {m.msg}
                      </span>
                      <Badge variant="outline" className="border-zinc-300 bg-zinc-100 text-[10px] text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800">
                        {m.category} +{m.score}
                      </Badge>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <p className="mt-3 flex items-center gap-1.5 text-[11px] text-zinc-500">
                <Icons.CheckCircle2 className="h-3.5 w-3.5 text-red-700 dark:text-red-500" /> No CRS rule matched.
              </p>
            )}
          </div>
        )}

        {recent.length > 0 && (
          <div>
            <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-zinc-500">Recent tests</p>
            <div className="space-y-1">
              {recent.map((t, i) => (
                <div key={`${t.at}-${i}`} className="flex items-center gap-2 text-[11px] text-zinc-500">
                  <ActionBadge action={t.action} className="px-1.5 py-0" />
                  <span className="font-mono text-zinc-600 dark:text-zinc-300">{t.method}</span>
                  <span className="min-w-0 flex-1 truncate font-mono" title={t.url}>
                    {t.url}
                  </span>
                  <span className="font-mono">+{t.anomalyScore}</span>
                  <span className="shrink-0 text-zinc-400">{fmtRelative(t.at)}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ── stats strip + log feed ──────────────────────────────────────────────────

function StatsStrip({ stats }: { stats: WafStats | undefined }) {
  const top = stats?.topRules[0];
  const items = [
    {
      label: "Blocked (24h)",
      value: stats?.blocked24h ?? 0,
      icon: <Icons.Ban className="h-4 w-4 text-red-500" />,
      tone: (stats?.blocked24h ?? 0) > 0 ? "red" : undefined,
    },
    { label: "Logged (24h)", value: stats?.logged24h ?? 0, icon: <Icons.Eye className="h-4 w-4 text-amber-500" /> },
    { label: "Passed (24h)", value: stats?.passed24h ?? 0, icon: <Icons.ShieldCheck className="h-4 w-4 text-red-700 dark:text-red-500" /> },
    {
      label: top ? `Top rule ${top.ruleId} · ${top.count} hits` : "Top attacked rule",
      value: top?.count ?? 0,
      icon: <Icons.Crosshair className="h-4 w-4 text-red-700 dark:text-red-500" />,
      sub: top?.msg,
    },
  ];
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {items.map((it) => (
          <Card key={it.label} className="p-4">
            <CardContent className="flex items-center gap-3 p-0">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-red-600/10">{it.icon}</div>
              <div className="min-w-0">
                <p className={cn("text-xl font-semibold tabular-nums", it.tone === "red" ? "text-red-600 dark:text-red-400" : undefined)}>
                  {it.value.toLocaleString()}
                </p>
                <p className="truncate text-[11px] text-zinc-500" title={it.sub ?? it.label}>
                  {it.label}
                </p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
      {stats && stats.topRules.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="mr-1 text-[11px] font-semibold uppercase tracking-wide text-zinc-400">Top attacked</span>
          {stats.topRules.map((r) => (
            <Badge
              key={r.ruleId}
              variant="outline"
              className="gap-1.5 border-zinc-300 bg-zinc-100 font-mono text-[10px] text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
              title={r.msg}
            >
              {r.ruleId}
              <span className="rounded-full bg-red-600 px-1.5 text-[10px] font-semibold text-white">{r.count}</span>
            </Badge>
          ))}
        </div>
      )}
    </div>
  );
}

// ── main view ───────────────────────────────────────────────────────────────

export function WafView() {
  const queryClient = useQueryClient();
  const vhostsQuery = useQuery({ queryKey: ["waf", "vhosts"], queryFn: wafApi.listVhosts });
  const policiesQuery = useQuery({ queryKey: ["waf", "policies"], queryFn: wafApi.listPolicies });
  const statsQuery = useQuery({ queryKey: ["waf", "stats"], queryFn: wafApi.getStats });
  const [logAction, setLogAction] = useState<string>("all");
  const [logVhost, setLogVhost] = useState<string>("all");
  const logsQuery = useQuery({
    queryKey: ["waf", "logs", logAction, logVhost],
    queryFn: () => wafApi.listLogs(qs({ action: logAction === "all" ? undefined : logAction, vhostId: logVhost === "all" ? undefined : logVhost, limit: 100 })),
  });

  // certs only fetched while the vhost dialog is open (M14 PKI list)
  const [vhostEditor, setVhostEditor] = useState<{ open: boolean; initial: VhostDTO | null }>({ open: false, initial: null });
  const certsQuery = useQuery({
    queryKey: ["waf", "cert-options"],
    queryFn: wafApi.listActiveCerts,
    enabled: vhostEditor.open,
  });

  const [policyEditor, setPolicyEditor] = useState<{ open: boolean; initial: PolicyDTO | null }>({ open: false, initial: null });
  const [exclusionOpen, setExclusionOpen] = useState(false);
  const [deleting, setDeleting] = useState<{ kind: "vhost" | "policy" | "exclusion"; vhost?: VhostDTO; policy?: PolicyDTO; exclusion?: ExclusionDTO } | null>(null);
  const [selectedVhostId, setSelectedVhostId] = useState<number | null>(null);

  const vhosts = vhostsQuery.data ?? [];
  const policies = policiesQuery.data ?? [];
  const vhost = vhosts.find((v) => v.id === selectedVhostId) ?? vhosts[0] ?? null;
  const policy = vhost ? (policies.find((p) => p.vhostId === vhost.id) ?? null) : null;
  const logs = logsQuery.data ?? [];

  const toggleVhost = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => wafApi.updateVhost(id, { enabled }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: WAF_KEY }),
    onError: (e) => toastErr(e, "Toggle failed"),
  });

  const del = useMutation({
    mutationFn: async () => {
      if (deleting?.kind === "vhost" && deleting.vhost) return wafApi.deleteVhost(deleting.vhost.id);
      if (deleting?.kind === "policy" && deleting.policy) return wafApi.deletePolicy(deleting.policy.id);
      if (deleting?.kind === "exclusion" && deleting.policy && deleting.exclusion)
        return wafApi.deleteExclusion(deleting.policy.id, deleting.exclusion.id);
      throw new Error("Nothing to delete");
    },
    onSuccess: () => {
      toastOk(
        deleting?.kind === "vhost" ? "Vhost deleted" : deleting?.kind === "policy" ? "Policy deleted" : "Exclusion deleted",
      );
      setDeleting(null);
      void queryClient.invalidateQueries({ queryKey: WAF_KEY });
    },
    onError: (e) => {
      toastErr(e, "Delete failed");
      setDeleting(null);
    },
  });

  return (
    <div className="space-y-4">
      <StatsStrip stats={statsQuery.data} />

      <div className="flex flex-wrap items-center gap-2">
        <p className="mr-auto text-xs text-zinc-500">
          Reverse-proxy virtual hosts inspected by OWASP CRS. The sandbox evaluates a representative 12-rule sample
          engine — a real appliance runs Coraza with the full CRS bundle.
        </p>
        <Button
          size="sm"
          className="bg-red-700 text-white hover:bg-red-800"
          onClick={() => setVhostEditor({ open: true, initial: null })}
        >
          <Icons.Plus className="mr-1 h-4 w-4" /> Add vhost
        </Button>
      </div>

      {vhostsQuery.isError ? (
        <QueryError error={vhostsQuery.error} onRetry={() => void vhostsQuery.refetch()} />
      ) : vhostsQuery.isLoading ? (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-48 rounded-xl" />
          ))}
        </div>
      ) : vhosts.length === 0 ? (
        <Card className="p-0">
          <CardContent className="p-0">
            <EmptyBlock
              icon={<Icons.Globe className="h-6 w-6" />}
              title="No virtual hosts configured"
              description="Add a vhost to put a hostname behind the WAF, then attach a policy with CRS rules."
              action={
                <Button className="bg-red-700 text-white hover:bg-red-800" onClick={() => setVhostEditor({ open: true, initial: null })}>
                  <Icons.Plus className="mr-1 h-4 w-4" /> Add vhost
                </Button>
              }
            />
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {vhosts.map((v) => (
            <Card
              key={v.id}
              role="button"
              tabIndex={0}
              aria-pressed={vhost?.id === v.id}
              onClick={() => setSelectedVhostId(v.id)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  setSelectedVhostId(v.id);
                }
              }}
              className={cn(
                "flex cursor-pointer flex-col p-4 transition-colors",
                vhost?.id === v.id ? "border-red-700 ring-1 ring-red-700" : "hover:border-red-600/40",
              )}
            >
              <CardHeader className="flex-row items-start justify-between space-y-0 p-0 pb-3">
                <div className="min-w-0">
                  <CardTitle className="truncate font-mono text-sm font-medium">{v.hostname}</CardTitle>
                  <p className="mt-0.5 text-[11px] text-zinc-500">{v.name}</p>
                </div>
                <Switch
                  checked={v.enabled}
                  onCheckedChange={(enabled) => toggleVhost.mutate({ id: v.id, enabled })}
                  aria-label={`Toggle vhost ${v.hostname}`}
                  onClick={(e) => e.stopPropagation()}
                />
              </CardHeader>
              <CardContent className="flex flex-1 flex-col gap-2.5 p-0">
                <p className="truncate font-mono text-[11px] text-zinc-500" title={`${v.backendHost}:${v.backendPort}`}>
                  <Icons.ArrowRightLeft className="mr-1 inline h-3 w-3" />
                  {v.backendHost}:{v.backendPort}
                </p>
                <div className="flex flex-wrap items-center gap-1.5">
                  <ModeBadge mode={v.mode} />
                  {v.tls ? (
                    <Badge variant="outline" className="border-red-600/40 bg-red-600/10 text-[10px] text-red-700 dark:text-red-500">
                      <Icons.Lock className="mr-1 h-3 w-3" />
                      TLS{v.certName ? ` · ${v.certName}` : " · no cert"}
                    </Badge>
                  ) : (
                    <Badge variant="outline" className="border-zinc-300 bg-zinc-100 text-[10px] text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800">
                      <Icons.LockOpen className="mr-1 h-3 w-3" />
                      no TLS
                    </Badge>
                  )}
                  <Badge variant="outline" className="border-zinc-300 bg-zinc-100 font-mono text-[10px] text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800">
                    :{v.listenPort}
                  </Badge>
                  {v.policy ? (
                    <Badge variant="outline" className="border-red-600/40 bg-red-600/10 text-[10px] text-red-700 dark:text-red-500">
                      <Icons.Shield className="mr-1 h-3 w-3" />
                      {v.policy.name}
                    </Badge>
                  ) : (
                    <Badge variant="outline" className="border-zinc-300 bg-zinc-100 text-[10px] text-zinc-400 dark:border-zinc-700 dark:bg-zinc-800">
                      no policy
                    </Badge>
                  )}
                </div>
                <div className="mt-auto flex items-center gap-1 border-t border-zinc-200 pt-3 dark:border-zinc-800">
                  <span className="text-[11px] text-zinc-400">created {fmtRelative(v.createdAt)}</span>
                  <div className="ml-auto flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7"
                      aria-label={`Edit vhost ${v.hostname}`}
                      onClick={() => setVhostEditor({ open: true, initial: v })}
                    >
                      <Icons.Pencil className="h-3.5 w-3.5" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 text-rose-500 hover:text-rose-600"
                      aria-label={`Delete vhost ${v.hostname}`}
                      onClick={() => setDeleting({ kind: "vhost", vhost: v })}
                    >
                      <Icons.Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {vhost && (
        <>
          <PolicyCard
            vhost={vhost}
            policy={policy}
            onEdit={(p) => setPolicyEditor({ open: true, initial: p })}
            onDelete={(p) => setDeleting({ kind: "policy", policy: p })}
          />
          {policy && (
            <>
              <ExclusionsTable policy={policy} onAdd={() => setExclusionOpen(true)} onDelete={(x) => setDeleting({ kind: "exclusion", policy, exclusion: x })} />
              <TestRequestCard policy={policy} />
            </>
          )}
        </>
      )}

      <Card className="p-0">
        <CardHeader className="flex-row items-center justify-between space-y-0 p-4 pb-3">
          <CardTitle className="text-sm font-medium">
            <Icons.ScrollText className="mr-1.5 inline h-4 w-4 text-red-700 dark:text-red-500" />
            WAF log
            <span className="ml-2 text-[11px] font-normal text-zinc-400">last 24h feed</span>
          </CardTitle>
          <div className="flex items-center gap-2">
            <Select value={logVhost} onValueChange={setLogVhost}>
              <SelectTrigger className="h-8 w-44 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All vhosts</SelectItem>
                {vhosts.map((v) => (
                  <SelectItem key={v.id} value={String(v.id)}>
                    {v.hostname}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={logAction} onValueChange={setLogAction}>
              <SelectTrigger className="h-8 w-28 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All actions</SelectItem>
                <SelectItem value="pass">pass</SelectItem>
                <SelectItem value="log">log</SelectItem>
                <SelectItem value="block">block</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent className="p-4 pt-0">
          {logsQuery.isError ? (
            <QueryError error={logsQuery.error} onRetry={() => void logsQuery.refetch()} />
          ) : logsQuery.isLoading ? (
            <TableSkeleton rows={6} cols={8} />
          ) : logs.length === 0 ? (
            <EmptyBlock
              icon={<Icons.ScrollText className="h-6 w-6" />}
              title="No WAF events in the window"
              description="Run a test request against a policy or wait for traffic to flow through the vhosts."
            />
          ) : (
            <div className={SCROLLY}>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-20">Action</TableHead>
                    <TableHead className="w-40">Vhost</TableHead>
                    <TableHead>Request</TableHead>
                    <TableHead className="w-20">Rule</TableHead>
                    <TableHead>Message</TableHead>
                    <TableHead className="w-14 text-right">Score</TableHead>
                    <TableHead className="w-28">Client</TableHead>
                    <TableHead className="w-20 text-right">When</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {logs.map((l) => (
                    <TableRow key={l.id}>
                      <TableCell>
                        <ActionBadge action={l.action} />
                      </TableCell>
                      <TableCell className="max-w-40 truncate font-mono text-xs">{l.vhostHostname ?? `#${l.vhostId ?? "—"}`}</TableCell>
                      <TableCell className="max-w-56 truncate font-mono text-xs" title={`${l.method} ${l.url}`}>
                        <span className="mr-1.5 font-semibold text-zinc-600 dark:text-zinc-300">{l.method}</span>
                        {l.url}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{l.ruleId ?? "—"}</TableCell>
                      <TableCell className="max-w-64 truncate text-xs text-zinc-500" title={l.ruleMsg ?? undefined}>
                        {l.ruleMsg ?? "—"}
                      </TableCell>
                      <TableCell className="text-right font-mono text-xs tabular-nums">{l.anomalyScore}</TableCell>
                      <TableCell className="font-mono text-xs">{l.clientIp}</TableCell>
                      <TableCell className="text-right text-[11px] text-zinc-400">{fmtRelative(l.createdAt)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {vhostEditor.open && (
        <VhostEditor
          key={vhostEditor.initial?.id ?? "new-vhost"}
          initial={vhostEditor.initial}
          certs={certsQuery.data ?? []}
          onClose={() => setVhostEditor({ open: false, initial: null })}
        />
      )}
      {policyEditor.open && (
        <PolicyEditor
          key={policyEditor.initial?.id ?? `new-policy-${vhost?.id ?? 0}`}
          initial={policyEditor.initial}
          vhosts={vhosts}
          defaultVhostId={vhost?.id}
          onClose={() => setPolicyEditor({ open: false, initial: null })}
        />
      )}
      {exclusionOpen && policy && <ExclusionEditor policyId={policy.id} onClose={() => setExclusionOpen(false)} />}

      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={
          deleting?.kind === "vhost"
            ? `Delete vhost "${deleting.vhost?.hostname ?? ""}"?`
            : deleting?.kind === "policy"
              ? `Delete policy "${deleting.policy?.name ?? ""}"?`
              : `Delete exclusion "${deleting?.exclusion?.matchValue ?? ""}"?`
        }
        description={
          deleting?.kind === "vhost"
            ? "The vhost stops being fronted by the WAF. Its historical log entries are kept."
            : deleting?.kind === "policy"
              ? "The policy and its exclusions are removed; the vhost keeps serving traffic unprotected."
              : "The rule/param/URL will be inspected again (exclusion removed)."
        }
        loading={del.isPending}
        onConfirm={() => del.mutate()}
      />
    </div>
  );
}
