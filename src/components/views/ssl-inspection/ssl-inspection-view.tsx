"use client";

/**
 * #/web/ssl-inspection — SSL/TLS Inspection (M15 §2.1).
 * Top strip: 24h decision counters + certificate-expiry chip. Policy card
 * (master-detail): mode/signing-CA/HSTS/pinning/invalid-cert/min-TLS with
 * inline enabled switch, bypass-rules table with per-type validated editor.
 * "Test a connection" card runs the SIMULATED decision engine (the appliance
 * enforces for real) and appends to a mini recent-tests list; recent
 * inspection logs close the view. Theme: white + enterprise red-700.
 */

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Ban,
  CalendarClock,
  CircleSlash,
  Globe,
  KeyRound,
  LockKeyhole,
  Pencil,
  Play,
  Plus,
  RefreshCw,
  ShieldCheck,
  Trash2,
} from "lucide-react";
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
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { ConfirmDialog, EmptyBlock, FieldLabel, QueryError, toastErr, toastOk } from "../firewall/fw-ui";
import { pkiApi, type CaDto } from "../pki/pki-api";
import {
  HSTS_OPTIONS,
  INVALID_CERT_OPTIONS,
  MATCH_HINTS,
  MIN_TLS_OPTIONS,
  PINNING_OPTIONS,
  SSL_MATCH_TYPES,
  SSL_MODES,
  fmtRelative,
  qs,
  sslInspectionApi,
  type SslBypassRuleDTO,
  type SslDecision,
  type SslMatchType,
  type SslMode,
  type SslPolicyDTO,
  type SslStatsDTO,
  type SslTestResultDTO,
} from "./ssl-inspection-api";

const SSL_KEY = ["ssl-inspection"] as const;

// ── badges ──────────────────────────────────────────────────────────────────

const DECISION_BADGE: Record<SslDecision, { cls: string; icon: React.ComponentType<{ className?: string }>; label: string }> = {
  inspected: {
    cls: "border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300",
    icon: ShieldCheck,
    label: "inspected",
  },
  bypassed: {
    cls: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
    icon: CircleSlash,
    label: "bypassed",
  },
  blocked: {
    cls: "border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400",
    icon: Ban,
    label: "blocked",
  },
};

function DecisionBadge({ decision, big }: { decision: SslDecision; big?: boolean }) {
  const def = DECISION_BADGE[decision] ?? DECISION_BADGE.inspected;
  const Icon = def.icon;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium", def.cls, big && "px-3 py-1 text-sm")}>
      <Icon className={big ? "h-4 w-4" : "h-3 w-3"} />
      {def.label}
    </Badge>
  );
}

/** none = zinc, selective = blue, full = amber (module rule). */
function ModeBadge({ mode }: { mode: SslMode }) {
  const cls =
    mode === "selective"
      ? "border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300"
      : mode === "full"
        ? "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400"
        : "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300";
  return (
    <Badge variant="outline" className={cn("font-medium", cls)}>
      {mode}
    </Badge>
  );
}

function MatchTypeBadge({ type }: { type: SslMatchType }) {
  return (
    <Badge
      variant="outline"
      className="border-zinc-300 bg-zinc-100 font-mono text-[10px] uppercase text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
    >
      {type}
    </Badge>
  );
}

// ── detail row (label / value) ──────────────────────────────────────────────

function DetailRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-zinc-100 py-1.5 last:border-0 dark:border-zinc-800/60">
      <span className="text-xs text-zinc-500">{label}</span>
      <div className="flex items-center gap-1.5 text-xs font-medium">{children}</div>
    </div>
  );
}

// ── stats strip ─────────────────────────────────────────────────────────────

function StatsStrip({ stats }: { stats: SslStatsDTO | undefined }) {
  const items: Array<{ label: string; value: number; icon: React.ReactNode; tone: "blue" | "zinc" | "red" }> = [
    { label: "Inspected (24h)", value: stats?.inspected24h ?? 0, icon: <ShieldCheck className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />, tone: "blue" },
    { label: "Bypassed (24h)", value: stats?.bypassed24h ?? 0, icon: <CircleSlash className="h-4 w-4 text-zinc-500" />, tone: "zinc" },
    { label: "Blocked (24h)", value: stats?.blocked24h ?? 0, icon: <Ban className="h-4 w-4 text-red-500" />, tone: "red" },
  ];
  const expiring = stats?.certExpiring.count ?? 0;
  const nearest = stats?.certExpiring.nearest ?? [];
  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      {items.map((it) => (
        <Card key={it.label} className="p-4">
          <CardContent className="flex items-center gap-3 p-0">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-zinc-500/10">{it.icon}</div>
            <div className="min-w-0">
              <p className={cn("text-xl font-semibold tabular-nums", it.tone === "red" && it.value > 0 && "text-red-600 dark:text-red-400")}>
                {it.value.toLocaleString()}
              </p>
              <p className="truncate text-[11px] text-zinc-500">{it.label}</p>
            </div>
          </CardContent>
        </Card>
      ))}
      <Card className="p-4">
        <CardContent className="flex items-center gap-3 p-0">
          <div
            className={cn(
              "flex h-9 w-9 shrink-0 items-center justify-center rounded-lg",
              expiring > 0 ? "bg-amber-500/10" : "bg-zinc-500/10",
            )}
          >
            <CalendarClock className={cn("h-4 w-4", expiring > 0 ? "text-amber-600 dark:text-amber-400" : "text-zinc-500 dark:text-zinc-400")} />
          </div>
          <div className="min-w-0">
            <TooltipProvider delayDuration={100}>
              <Tooltip>
                <TooltipTrigger asChild>
                  <p className={cn("text-xl font-semibold tabular-nums", expiring > 0 && "text-amber-600 dark:text-amber-400")}>
                    {expiring}
                  </p>
                </TooltipTrigger>
                <TooltipContent className="text-xs">
                  {nearest.length === 0
                    ? "No certificates or CAs expiring within 45 days"
                    : nearest.map((n) => `${n.name} — ${n.notAfter ? fmtRelative(n.notAfter) : "—"}`).join(" · ")}
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
            <p className="truncate text-[11px] text-zinc-500">certs expiring ≤45d</p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ── policy editor (create + edit) ───────────────────────────────────────────

function PolicyEditor(props: { initial: SslPolicyDTO | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = props.initial !== null;
  const [name, setName] = useState(props.initial?.name ?? "");
  const [mode, setMode] = useState<SslMode>(props.initial?.mode ?? "selective");
  const [signingCaId, setSigningCaId] = useState<number | null>(props.initial?.signingCaId ?? null);
  const [hstsHandling, setHstsHandling] = useState<"honor" | "bypass">(props.initial?.hstsHandling ?? "honor");
  const [certPinningAction, setCertPinningAction] = useState<"bypass" | "block">(props.initial?.certPinningAction ?? "bypass");
  const [invalidCertAction, setInvalidCertAction] = useState<"block" | "warn_bypass">(props.initial?.invalidCertAction ?? "block");
  const [minTlsVersion, setMinTlsVersion] = useState<"1.2" | "1.3">(props.initial?.minTlsVersion ?? "1.2");
  const [enabled, setEnabled] = useState(props.initial?.enabled ?? true);
  const [err, setErr] = useState<string | null>(null);

  const casQuery = useQuery({ queryKey: ["pki", "cas"], queryFn: pkiApi.listCas });
  const eligibleCas = useMemo(
    () => (casQuery.data ?? []).filter((ca: CaDto) => ca.status === "active" && (ca.type === "root" || ca.type === "subordinate")),
    [casQuery.data],
  );

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      isEdit ? sslInspectionApi.updatePolicy(props.initial!.id, body) : sslInspectionApi.createPolicy(body),
    onSuccess: (saved) => {
      toastOk(`${isEdit ? "Updated" : "Created"} policy "${saved.name}"`);
      void queryClient.invalidateQueries({ queryKey: SSL_KEY });
      props.onClose();
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Save failed"),
  });

  const caSelectDisabled = mode === "none";
  const caValue = signingCaId === null ? "__none" : String(signingCaId);

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-base">{isEdit ? "Edit inspection policy" : "Add inspection policy"}</DialogTitle>
          <DialogDescription>
            Sandbox note — the appliance enforces MITM for real; here the same settings drive the simulated decision engine.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div>
            <FieldLabel>Name</FieldLabel>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Default MITM" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel hint="none = no MITM">Mode</FieldLabel>
              <Select value={mode} onValueChange={(v) => setMode(v as SslMode)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SSL_MODES.map((m) => (
                    <SelectItem key={m} value={m}>
                      {m}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel hint={caSelectDisabled ? "n/a in none mode" : "active CAs only"}>Signing CA</FieldLabel>
              <Select
                value={caValue}
                disabled={caSelectDisabled}
                onValueChange={(v) => setSigningCaId(v === "__none" ? null : Number(v))}
              >
                <SelectTrigger>
                  <SelectValue placeholder={caSelectDisabled ? "—" : "Select CA"} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__none">No CA</SelectItem>
                  {eligibleCas.map((ca) => (
                    <SelectItem key={ca.id} value={String(ca.id)}>
                      {ca.name} ({ca.type})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {!caSelectDisabled && eligibleCas.length === 0 && !casQuery.isLoading && (
                <p className="mt-1 text-[11px] text-amber-600 dark:text-amber-400">
                  No active CAs — create one under PKI → Authorities.
                </p>
              )}
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel hint="HSTS responses">HSTS handling</FieldLabel>
              <Select value={hstsHandling} onValueChange={(v) => setHstsHandling(v as "honor" | "bypass")}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {HSTS_OPTIONS.map((o) => (
                    <SelectItem key={o} value={o}>
                      {o === "honor" ? "honor (respect HSTS)" : "bypass (inspect anyway)"}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel hint="pinned connections">Cert pinning</FieldLabel>
              <Select value={certPinningAction} onValueChange={(v) => setCertPinningAction(v as "bypass" | "block")}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PINNING_OPTIONS.map((o) => (
                    <SelectItem key={o} value={o}>
                      {o === "bypass" ? "bypass pinned sites" : "block pinned sites"}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel hint="upstream cert invalid">Invalid certificate</FieldLabel>
              <Select value={invalidCertAction} onValueChange={(v) => setInvalidCertAction(v as "block" | "warn_bypass")}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {INVALID_CERT_OPTIONS.map((o) => (
                    <SelectItem key={o} value={o}>
                      {o === "block" ? "block" : "warn and bypass"}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel hint="client-facing minimum">Min TLS version</FieldLabel>
              <Select value={minTlsVersion} onValueChange={(v) => setMinTlsVersion(v as "1.2" | "1.3")}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {MIN_TLS_OPTIONS.map((o) => (
                    <SelectItem key={o} value={o}>
                      TLS {o}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Switch id="policy-enabled" checked={enabled} onCheckedChange={setEnabled} />
            <Label htmlFor="policy-enabled" className="text-xs">
              Enabled
            </Label>
          </div>
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button
            className="bg-red-700 text-white hover:bg-red-800"
            disabled={save.isPending || !name.trim() || (mode !== "none" && signingCaId === null)}
            onClick={() =>
              save.mutate({
                name: name.trim(),
                mode,
                signingCaId: mode === "none" ? null : signingCaId,
                hstsHandling,
                certPinningAction,
                invalidCertAction,
                minTlsVersion,
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

// ── bypass rule editor (add) ────────────────────────────────────────────────

/** Client-side mirrors of the server matchValue validators (instant feedback). */
const MATCH_RE: Record<SslMatchType, RegExp> = {
  domain: /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i,
  wildcard: /^\*\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i,
  category: /^[a-z0-9][a-z0-9_-]{0,63}$/i,
  ip: /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/,
  cidr: /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\/(3[0-2]|[12]?\d)$/,
};

function BypassEditor(props: { policies: SslPolicyDTO[]; defaultPolicyId: number | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [policyId, setPolicyId] = useState<number | null>(props.defaultPolicyId ?? props.policies[0]?.id ?? null);
  const [matchType, setMatchType] = useState<SslMatchType>("domain");
  const [matchValue, setMatchValue] = useState("");
  const [reason, setReason] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const hint = MATCH_HINTS[matchType];
  const valueValid = MATCH_RE[matchType].test(matchValue.trim());

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => sslInspectionApi.createBypassRule(body),
    onSuccess: (saved) => {
      toastOk(`Bypass rule "${saved.matchValue}" added`);
      void queryClient.invalidateQueries({ queryKey: SSL_KEY });
      props.onClose();
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Save failed"),
  });

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-base">Add bypass rule</DialogTitle>
          <DialogDescription>
            Bypass rules are evaluated in order before any policy decision — first hit wins.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div>
            <FieldLabel>Policy</FieldLabel>
            <Select
              value={policyId === null ? undefined : String(policyId)}
              onValueChange={(v) => setPolicyId(Number(v))}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select policy" />
              </SelectTrigger>
              <SelectContent>
                {props.policies.map((p) => (
                  <SelectItem key={p.id} value={String(p.id)}>
                    {p.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="grid grid-cols-[140px_1fr] gap-4">
            <div>
              <FieldLabel>Match type</FieldLabel>
              <Select value={matchType} onValueChange={(v) => setMatchType(v as SslMatchType)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SSL_MATCH_TYPES.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel hint={hint.hint}>Value</FieldLabel>
              <Input
                value={matchValue}
                onChange={(e) => setMatchValue(e.target.value)}
                placeholder={hint.placeholder}
                className={cn("font-mono text-xs", matchValue.length > 0 && !valueValid && "border-amber-500 focus-visible:ring-amber-500")}
              />
              {matchValue.length > 0 && !valueValid && (
                <p className="mt-1 text-[11px] text-amber-600 dark:text-amber-400">
                  Doesn&apos;t match the {matchType} shape — {hint.hint}
                </p>
              )}
            </div>
          </div>
          <div>
            <FieldLabel hint="optional">Reason</FieldLabel>
            <Input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="banking HSTS" />
          </div>
          <div className="flex items-center gap-2">
            <Switch id="bypass-enabled" checked={enabled} onCheckedChange={setEnabled} />
            <Label htmlFor="bypass-enabled" className="text-xs">
              Enabled
            </Label>
          </div>
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button
            className="bg-red-700 text-white hover:bg-red-800"
            disabled={save.isPending || policyId === null || !valueValid}
            onClick={() =>
              save.mutate({
                policyId,
                matchType,
                matchValue: matchValue.trim(),
                reason: reason.trim() || null,
                enabled,
              })
            }
          >
            {save.isPending ? "Saving…" : "Add rule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── test a connection ───────────────────────────────────────────────────────

const SNI_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const SNI_PRESETS = ["www.apple.com", "api.googleapis.com", "expired.portal.example", "pay.example.com"];

function TestConnectionCard({ policyId, policyName }: { policyId: number | null; policyName: string | null }) {
  const queryClient = useQueryClient();
  const [sni, setSni] = useState("");
  const [result, setResult] = useState<SslTestResultDTO | null>(null);
  const [recent, setRecent] = useState<SslTestResultDTO[]>([]);
  const sniValid = SNI_RE.test(sni.trim());

  const run = useMutation({
    mutationFn: (value: string) => sslInspectionApi.testPolicy(policyId ?? "auto", value),
    onSuccess: (r) => {
      setResult(r);
      setSni(r.sni);
      setRecent((prev) => [r, ...prev].slice(0, 8));
      // the decision was persisted — refresh counters + logs
      void queryClient.invalidateQueries({ queryKey: [...SSL_KEY, "stats"] });
      void queryClient.invalidateQueries({ queryKey: [...SSL_KEY, "logs"] });
    },
    onError: (e) => toastErr(e, "Test failed"),
  });

  return (
    <Card className="p-0">
      <CardHeader className="p-4 pb-0">
        <CardTitle className="flex items-center gap-2 text-sm font-medium">
          <Play className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
          Test a connection
        </CardTitle>
        <CardDescription className="text-xs">
          Simulated decision for SNI {policyName ? <span className="font-medium text-zinc-600 dark:text-zinc-300">against policy &quot;{policyName}&quot;</span> : "— the appliance enforces for real."}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3 p-4">
        <div className="flex flex-col gap-2 sm:flex-row">
          <Input
            value={sni}
            onChange={(e) => setSni(e.target.value)}
            placeholder="www.example.com"
            className="font-mono text-xs"
            aria-label="Server name to test"
            onKeyDown={(e) => {
              if (e.key === "Enter" && sniValid && !run.isPending) run.mutate(sni.trim());
            }}
          />
          <Button
            className="shrink-0 bg-red-700 text-white hover:bg-red-800"
            disabled={!sniValid || run.isPending}
            onClick={() => run.mutate(sni.trim())}
          >
            {run.isPending ? <RefreshCw className="mr-1 h-4 w-4 animate-spin" /> : <Play className="mr-1 h-4 w-4" />}
            Run
          </Button>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[11px] text-zinc-400">try:</span>
          {SNI_PRESETS.map((p) => (
            <button
              key={p}
              type="button"
              onClick={() => setSni(p)}
              className="rounded-full border border-zinc-200 px-2 py-0.5 font-mono text-[10px] text-zinc-500 transition-colors hover:bg-zinc-500/10 hover:text-zinc-600 dark:border-zinc-800 dark:text-zinc-400 dark:hover:text-zinc-300"
            >
              {p}
            </button>
          ))}
        </div>

        {result && (
          <div className="rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
            <div className="flex flex-wrap items-center gap-3">
              <DecisionBadge decision={result.decision} big />
              <span className="font-mono text-xs text-zinc-500">reason: {result.reason}</span>
              {result.matchedRule && (
                <span className="font-mono text-xs text-zinc-500 dark:text-zinc-400">rule: {result.matchedRule}</span>
              )}
              <span className="ml-auto text-[11px] text-zinc-400">
                {result.policyName ? `policy: ${result.policyName}` : "no active policy"}
              </span>
            </div>
            <div className="mt-3 grid grid-cols-2 gap-2 text-xs sm:grid-cols-3">
              <div className="rounded-md bg-zinc-50 px-2 py-1.5 dark:bg-zinc-800/60">
                <p className="text-[10px] uppercase tracking-wide text-zinc-400">TLS</p>
                <p className="font-mono text-zinc-700 dark:text-zinc-200">TLS {result.tlsVersion}</p>
              </div>
              <div className="rounded-md bg-zinc-50 px-2 py-1.5 dark:bg-zinc-800/60">
                <p className="text-[10px] uppercase tracking-wide text-zinc-400">Cipher</p>
                <p className="truncate font-mono text-zinc-700 dark:text-zinc-200" title={result.cipher}>
                  {result.cipher}
                </p>
              </div>
              <div className="rounded-md bg-zinc-50 px-2 py-1.5 dark:bg-zinc-800/60">
                <p className="text-[10px] uppercase tracking-wide text-zinc-400">SNI</p>
                <p className="truncate font-mono text-zinc-700 dark:text-zinc-200" title={result.sni}>
                  {result.sni}
                </p>
              </div>
            </div>
          </div>
        )}

        {recent.length > 0 && (
          <div className="rounded-lg border border-zinc-200 dark:border-zinc-800">
            <p className="border-b border-zinc-200 px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wide text-zinc-500 dark:border-zinc-800">
              Recent tests
            </p>
            <ul className="max-h-44 divide-y divide-zinc-100 overflow-y-auto dark:divide-zinc-800/60 [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-zinc-300 dark:[&::-webkit-scrollbar-thumb]:bg-zinc-700">
              {recent.map((r, i) => (
                <li key={`${r.logId}-${i}`} className="flex items-center gap-2 px-3 py-1.5 text-xs">
                  <DecisionBadge decision={r.decision} />
                  <span className="min-w-0 flex-1 truncate font-mono text-zinc-600 dark:text-zinc-300">{r.sni}</span>
                  <span className="shrink-0 font-mono text-[10px] text-zinc-400">{r.reason}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ── main view ───────────────────────────────────────────────────────────────

export function SslInspectionView() {
  const queryClient = useQueryClient();
  const policiesQuery = useQuery({ queryKey: [...SSL_KEY, "policies"], queryFn: sslInspectionApi.listPolicies });
  const rulesQuery = useQuery({ queryKey: [...SSL_KEY, "bypass-rules"], queryFn: () => sslInspectionApi.listBypassRules() });
  const statsQuery = useQuery({ queryKey: [...SSL_KEY, "stats"], queryFn: sslInspectionApi.getStats });
  const [decisionFilter, setDecisionFilter] = useState<"all" | SslDecision>("all");
  const logsQuery = useQuery({
    queryKey: [...SSL_KEY, "logs", decisionFilter],
    queryFn: () => sslInspectionApi.listLogs(qs({ limit: 50, decision: decisionFilter === "all" ? undefined : decisionFilter })),
  });

  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<SslPolicyDTO | null>(null);
  const [deletingPolicy, setDeletingPolicy] = useState<SslPolicyDTO | null>(null);
  const [bypassOpen, setBypassOpen] = useState(false);
  const [deletingRule, setDeletingRule] = useState<SslBypassRuleDTO | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);

  const policies = policiesQuery.data ?? [];
  const rules = rulesQuery.data ?? [];
  const selected = policies.find((p) => p.id === selectedId) ?? policies[0] ?? null;
  const policyRules = selected ? rules.filter((r) => r.policyId === selected.id) : [];
  const logs = logsQuery.data ?? [];

  const refreshAll = () => void queryClient.invalidateQueries({ queryKey: SSL_KEY });

  const togglePolicy = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => sslInspectionApi.updatePolicy(id, { enabled }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: SSL_KEY }),
    onError: (e) => toastErr(e, "Toggle failed"),
  });

  const delPolicy = useMutation({
    mutationFn: (id: number) => sslInspectionApi.deletePolicy(id),
    onSuccess: () => {
      toastOk("Policy deleted (bypass rules removed with it)");
      setDeletingPolicy(null);
      setSelectedId(null);
      void queryClient.invalidateQueries({ queryKey: SSL_KEY });
    },
    onError: (e) => toastErr(e, "Delete failed"),
  });

  const toggleRule = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => sslInspectionApi.updateBypassRule(id, { enabled }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: [...SSL_KEY, "bypass-rules"] }),
    onError: (e) => toastErr(e, "Toggle failed"),
  });

  const delRule = useMutation({
    mutationFn: (id: number) => sslInspectionApi.deleteBypassRule(id),
    onSuccess: () => {
      toastOk("Bypass rule deleted");
      setDeletingRule(null);
      void queryClient.invalidateQueries({ queryKey: SSL_KEY });
    },
    onError: (e) => toastErr(e, "Delete failed"),
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <p className="mr-auto text-xs text-zinc-500">
          TLS inspection (MITM) policy, bypass rules and simulated connection decisions. The appliance terminates TLS for
          real — the sandbox replays the same decision engine against your configuration.
        </p>
        <Button
          size="sm"
          className="bg-red-700 text-white hover:bg-red-800"
          onClick={() => {
            setEditing(null);
            setEditorOpen(true);
          }}
        >
          <Plus className="mr-1 h-4 w-4" /> Add policy
        </Button>
      </div>

      <StatsStrip stats={statsQuery.data} />

      {policiesQuery.isError ? (
        <QueryError error={policiesQuery.error} onRetry={() => void policiesQuery.refetch()} />
      ) : policiesQuery.isLoading ? (
        <Skeleton className="h-64 rounded-xl" />
      ) : (
        <Card className="p-0">
          <CardHeader className="flex-row items-center justify-between space-y-0 border-b border-zinc-100 p-4 dark:border-zinc-800">
            <CardTitle className="flex items-center gap-2 text-sm font-medium">
              <LockKeyhole className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
              Inspection policies
            </CardTitle>
            <Button
              size="sm"
              variant="outline"
              className="h-8 gap-1 text-xs"
              onClick={() => {
                setEditing(null);
                setEditorOpen(true);
              }}
            >
              <Plus className="h-3.5 w-3.5" /> Add policy
            </Button>
          </CardHeader>
          <CardContent className="space-y-4 p-4">
            {policies.length === 0 ? (
              <EmptyBlock
                icon={<LockKeyhole className="h-6 w-6" />}
                title="No inspection policies"
                description="Create a policy (selective MITM with a signing CA is the usual starting point) to start inspecting TLS."
                action={
                  <Button
                    className="bg-red-700 text-white hover:bg-red-800"
                    onClick={() => {
                      setEditing(null);
                      setEditorOpen(true);
                    }}
                  >
                    <Plus className="mr-1 h-4 w-4" /> Add policy
                  </Button>
                }
              />
            ) : (
              <div className="grid gap-4 lg:grid-cols-[240px_1fr]">
                {/* master list */}
                <div
                  className="max-h-72 space-y-1 overflow-y-auto rounded-lg border border-zinc-200 p-1.5 dark:border-zinc-800 [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-zinc-300 dark:[&::-webkit-scrollbar-thumb]:bg-zinc-700"
                  role="listbox"
                  aria-label="Inspection policies"
                >
                  {policies.map((p) => (
                    <button
                      key={p.id}
                      type="button"
                      role="option"
                      aria-selected={selected?.id === p.id}
                      onClick={() => setSelectedId(p.id)}
                      className={cn(
                        "flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-left text-xs transition-colors",
                        selected?.id === p.id
                          ? "bg-zinc-500/10 font-medium text-zinc-600 dark:text-zinc-300"
                          : "hover:bg-zinc-100 dark:hover:bg-zinc-800",
                      )}
                    >
                      <span className={cn("h-1.5 w-1.5 shrink-0 rounded-full", p.enabled ? "bg-zinc-500" : "bg-zinc-300 dark:bg-zinc-600")} />
                      <span className="min-w-0 flex-1 truncate">{p.name}</span>
                      <ModeBadge mode={p.mode} />
                    </button>
                  ))}
                </div>

                {/* detail */}
                {selected && (
                  <div className="min-w-0 space-y-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-sm font-semibold">{selected.name}</h3>
                      <ModeBadge mode={selected.mode} />
                      <Badge
                        variant="outline"
                        className="border-zinc-300 bg-zinc-100 font-mono text-[10px] uppercase text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
                      >
                        TLS ≥ {selected.minTlsVersion}
                      </Badge>
                      <div className="ml-auto flex items-center gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8"
                          aria-label={`Edit policy ${selected.name}`}
                          onClick={() => {
                            setEditing(selected);
                            setEditorOpen(true);
                          }}
                        >
                          <Pencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8 text-rose-500 hover:text-rose-600"
                          aria-label={`Delete policy ${selected.name}`}
                          onClick={() => setDeletingPolicy(selected)}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </div>

                    <div className="grid gap-4 md:grid-cols-2">
                      <div className="rounded-lg border border-zinc-200 px-3 py-1 dark:border-zinc-800">
                        <DetailRow label="Signing CA">
                          {selected.signingCaName ? (
                            <TooltipProvider delayDuration={100}>
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <Badge variant="outline" className="gap-1 border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300">
                                    <KeyRound className="h-3 w-3" />
                                    {selected.signingCaName}
                                  </Badge>
                                </TooltipTrigger>
                                <TooltipContent className="text-xs">
                                  {selected.signingCaExpiresAt
                                    ? `Expires ${new Date(selected.signingCaExpiresAt).toLocaleDateString()}`
                                    : "No expiry recorded"}
                                </TooltipContent>
                              </Tooltip>
                            </TooltipProvider>
                          ) : (
                            <span className="text-zinc-400">—</span>
                          )}
                        </DetailRow>
                        <DetailRow label="HSTS handling">
                          <span className="font-mono text-[11px]">{selected.hstsHandling}</span>
                        </DetailRow>
                        <DetailRow label="Cert pinning">
                          <span className="font-mono text-[11px]">{selected.certPinningAction}</span>
                        </DetailRow>
                      </div>
                      <div className="rounded-lg border border-zinc-200 px-3 py-1 dark:border-zinc-800">
                        <DetailRow label="Invalid certificate">
                          <span className="font-mono text-[11px]">{selected.invalidCertAction}</span>
                        </DetailRow>
                        <DetailRow label="Bypass rules">
                          <span className="tabular-nums">{selected.bypassRuleCount}</span>
                        </DetailRow>
                        <DetailRow label="Enabled">
                          <Switch
                            checked={selected.enabled}
                            onCheckedChange={(enabled) => togglePolicy.mutate({ id: selected.id, enabled })}
                            aria-label={`Toggle policy ${selected.name}`}
                          />
                        </DetailRow>
                      </div>
                    </div>

                    {/* bypass rules for the selected policy */}
                    <div>
                      <div className="mb-2 flex flex-wrap items-center gap-2">
                        <h4 className="text-xs font-semibold uppercase tracking-wide text-zinc-500">
                          Bypass rules — {selected.name}
                        </h4>
                        <Badge variant="outline" className="border-zinc-300 px-1.5 text-[10px] text-zinc-500 dark:border-zinc-700">
                          {policyRules.length}
                        </Badge>
                        <Button size="sm" variant="outline" className="ml-auto h-7 gap-1 px-2 text-xs" onClick={() => setBypassOpen(true)}>
                          <Plus className="h-3.5 w-3.5" /> Add bypass
                        </Button>
                      </div>
                      {policyRules.length === 0 ? (
                        <p className="rounded-lg border border-dashed border-zinc-200 px-3 py-4 text-center text-xs text-zinc-400 dark:border-zinc-800">
                          No bypass rules — all connections follow the policy decision path.
                        </p>
                      ) : (
                        <div className="max-h-60 overflow-y-auto rounded-lg border border-zinc-200 dark:border-zinc-800 [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-zinc-300 dark:[&::-webkit-scrollbar-thumb]:bg-zinc-700">
                          <Table>
                            <TableHeader>
                              <TableRow>
                                <TableHead className="h-9 text-xs">Type</TableHead>
                                <TableHead className="h-9 text-xs">Value</TableHead>
                                <TableHead className="h-9 text-xs">Reason</TableHead>
                                <TableHead className="h-9 text-right text-xs">Enabled</TableHead>
                                <TableHead className="h-9 w-10" />
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {policyRules.map((r) => (
                                <TableRow key={r.id}>
                                  <TableCell className="py-2">
                                    <MatchTypeBadge type={r.matchType} />
                                  </TableCell>
                                  <TableCell className="py-2 font-mono text-xs">{r.matchValue}</TableCell>
                                  <TableCell className="py-2 text-xs text-zinc-500">{r.reason ?? "—"}</TableCell>
                                  <TableCell className="py-2 text-right">
                                    <Switch
                                      checked={r.enabled}
                                      onCheckedChange={(enabled) => toggleRule.mutate({ id: r.id, enabled })}
                                      aria-label={`Toggle bypass rule ${r.matchValue}`}
                                    />
                                  </TableCell>
                                  <TableCell className="py-2">
                                    <Button
                                      variant="ghost"
                                      size="icon"
                                      className="h-7 w-7 text-rose-500 hover:text-rose-600"
                                      aria-label={`Delete bypass rule ${r.matchValue}`}
                                      onClick={() => setDeletingRule(r)}
                                    >
                                      <Trash2 className="h-3.5 w-3.5" />
                                    </Button>
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      <TestConnectionCard policyId={selected?.id ?? null} policyName={selected?.name ?? null} />

      {/* recent inspection logs */}
      <Card className="p-0">
        <CardHeader className="flex-row items-center justify-between space-y-0 border-b border-zinc-100 p-4 dark:border-zinc-800">
          <div>
            <CardTitle className="flex items-center gap-2 text-sm font-medium">
              <Globe className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
              Recent inspection log
            </CardTitle>
            <CardDescription className="text-xs">Latest simulated decisions — persisted as inspection logs.</CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Select value={decisionFilter} onValueChange={(v) => setDecisionFilter(v as "all" | SslDecision)}>
              <SelectTrigger className="h-8 w-36 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All decisions</SelectItem>
                <SelectItem value="inspected">inspected</SelectItem>
                <SelectItem value="bypassed">bypassed</SelectItem>
                <SelectItem value="blocked">blocked</SelectItem>
              </SelectContent>
            </Select>
            <Button size="sm" variant="outline" className="h-8 gap-1 text-xs" onClick={refreshAll}>
              <RefreshCw className={cn("h-3.5 w-3.5", (logsQuery.isFetching || statsQuery.isFetching) && "animate-spin")} />
              Refresh
            </Button>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {logsQuery.isError ? (
            <div className="p-4">
              <QueryError error={logsQuery.error} onRetry={() => void logsQuery.refetch()} />
            </div>
          ) : logsQuery.isLoading ? (
            <div className="p-4">
              <Skeleton className="h-48 rounded-lg" />
            </div>
          ) : logs.length === 0 ? (
            <EmptyBlock
              icon={<Globe className="h-6 w-6" />}
              title="No inspection activity yet"
              description="Run a connection test above — every decision is persisted here."
            />
          ) : (
            <div className="max-h-96 overflow-y-auto [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-zinc-300 dark:[&::-webkit-scrollbar-thumb]:bg-zinc-700">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="h-9 text-xs">Decision</TableHead>
                    <TableHead className="h-9 text-xs">Reason</TableHead>
                    <TableHead className="h-9 text-xs">SNI</TableHead>
                    <TableHead className="h-9 text-xs">Client IP</TableHead>
                    <TableHead className="h-9 text-xs">TLS</TableHead>
                    <TableHead className="h-9 text-right text-xs">When</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {logs.map((l) => (
                    <TableRow key={l.id}>
                      <TableCell className="py-2">
                        <DecisionBadge decision={l.decision} />
                      </TableCell>
                      <TableCell className="py-2 font-mono text-[11px] text-zinc-500">{l.reason}</TableCell>
                      <TableCell className="max-w-56 truncate py-2 font-mono text-xs" title={l.sni}>
                        {l.sni}
                      </TableCell>
                      <TableCell className="py-2 font-mono text-xs text-zinc-500">{l.clientIp}</TableCell>
                      <TableCell className="py-2 font-mono text-xs text-zinc-500">
                        {l.tlsVersion ? `TLS ${l.tlsVersion}` : "—"}
                      </TableCell>
                      <TableCell className="py-2 text-right text-xs text-zinc-500">{fmtRelative(l.createdAt)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {editorOpen && <PolicyEditor key={editing?.id ?? "new"} initial={editing} onClose={() => setEditorOpen(false)} />}
      {bypassOpen && (
        <BypassEditor key="bypass" policies={policies} defaultPolicyId={selected?.id ?? null} onClose={() => setBypassOpen(false)} />
      )}
      <ConfirmDialog
        open={deletingPolicy !== null}
        onOpenChange={(open) => !open && setDeletingPolicy(null)}
        title={`Delete policy "${deletingPolicy?.name ?? ""}"?`}
        description="The policy and all of its bypass rules are removed. Inspection falls back to no policy (bypass everything)."
        loading={delPolicy.isPending}
        onConfirm={() => deletingPolicy && delPolicy.mutate(deletingPolicy.id)}
      />
      <ConfirmDialog
        open={deletingRule !== null}
        onOpenChange={(open) => !open && setDeletingRule(null)}
        title={`Delete bypass rule "${deletingRule?.matchValue ?? ""}"?`}
        description="Connections matching this rule will follow the normal policy decision path again."
        loading={delRule.isPending}
        onConfirm={() => deletingRule && delRule.mutate(deletingRule.id)}
      />
    </div>
  );
}
