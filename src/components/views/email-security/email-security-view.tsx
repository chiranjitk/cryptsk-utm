"use client";

/**
 * #/email/security — Email Security (M22, spec 2.8). Console layout: 24h stats
 * strip (processed / delivered / quarantined / rejected + avg spam score with
 * top reason chips) above five tabs — Gateways (SMTP proxy/relay listener
 * table + CRUD dialogs), Policy (singleton editor: spam threshold slider,
 * SPF/DKIM/DMARC handling, blocked extensions), Routing Rules (ordered
 * match→action table), Mail Logs (paged verdict-filtered table with
 * quarantine release) and Test (simulated Rspamd+ClamAV scan with an
 * attachment type selector). Stats + logs poll every 10 s via TanStack Query.
 * Theme: white + enterprise red-700; blue/zinc/amber/rose badges only
 * (delivered=blue clean, quarantined/spam=amber, phishing/malware=rose).
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  COMMON_EXTENSIONS,
  DMARC_POLICIES,
  GATEWAY_MODES,
  ROUTING_ACTIONS,
  SPAM_SCORE_MAX,
  TLS_MODES,
  VERDICTS,
  emailSecurityApi,
  fmtRelative,
  qs,
  type AuthResult,
  type DmarcPolicy,
  type EmailGatewayDTO,
  type EmailPolicyDTO,
  type EmailRoutingRuleDTO,
  type EmailVerdict,
  type GatewayMode,
  type RoutingAction,
  type TlsMode,
} from "./email-security-api";
import { ConfirmDialog, EmptyBlock, FieldLabel, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";
import { cn } from "@/lib/utils";
import { useRealtime } from "@/lib/realtime";

/** Stats + mail log poll cadence (spec: no socket events for this view). */
const POLL_MS = 10_000;

/** Mail log page size (client-side paging over the API's 100-row window). */
const LOG_PAGE_SIZE = 10;
/** The logs endpoint is paged-lite (limit 1–100, newest first). */
const LOG_FETCH_WINDOW = 100;

function invalidateAll(queryClient: ReturnType<typeof useQueryClient>) {
  void queryClient.invalidateQueries({ queryKey: ["email-security"] });
}

/** Realtime config channel — refetch everything when this section changes. */
function useEmailSecurityInvalidation(): void {
  const queryClient = useQueryClient();
  useRealtime(["config"], {
    onConfigUpdated: (c) => {
      if (c.section === "email_security") void queryClient.invalidateQueries({ queryKey: ["email-security"] });
    },
  });
}

// ── badge recipes ───────────────────────────────────────────────────────────

const VERDICT_CLS: Record<EmailVerdict, string> = {
  delivered: "border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300",
  quarantined: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  rejected: "border-transparent bg-rose-600 text-white",
};

const VERDICT_ICON: Record<EmailVerdict, React.ComponentType<{ className?: string }>> = {
  delivered: Icons.MailCheck,
  quarantined: Icons.Archive,
  rejected: Icons.Ban,
};

function VerdictBadge({ verdict }: { verdict: EmailVerdict }) {
  const Icon = VERDICT_ICON[verdict] ?? Icons.Mail;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium", VERDICT_CLS[verdict] ?? "")}>
      <Icon className="h-3 w-3" />
      {verdict}
    </Badge>
  );
}

function ModeBadge({ mode }: { mode: GatewayMode }) {
  return (
    <Badge
      variant="outline"
      className={
        mode === "proxy"
          ? "border-zinc-500/30 bg-zinc-500/10 font-medium text-zinc-600 dark:text-zinc-300"
          : "border-zinc-300 bg-zinc-100 font-medium text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
      }
    >
      {mode}
    </Badge>
  );
}

function TlsChip({ tlsMode }: { tlsMode: TlsMode }) {
  return (
    <Badge
      variant="outline"
      className="gap-1 border-zinc-300 bg-zinc-100 font-mono text-[10px] text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
    >
      <Icons.Lock className="h-2.5 w-2.5" />
      {tlsMode}
    </Badge>
  );
}

const ACTION_CLS: Record<RoutingAction, string> = {
  deliver: "border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300",
  relay: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
  reject: "border-transparent bg-rose-600 text-white",
  quarantine: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
};

const ACTION_ICON: Record<RoutingAction, React.ComponentType<{ className?: string }>> = {
  deliver: Icons.MailCheck,
  relay: Icons.ArrowRight,
  reject: Icons.Ban,
  quarantine: Icons.Archive,
};

function ActionBadge({ action }: { action: RoutingAction }) {
  const Icon = ACTION_ICON[action] ?? Icons.ArrowRight;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium", ACTION_CLS[action] ?? "")}>
      <Icon className="h-3 w-3" />
      {action}
    </Badge>
  );
}

function AuthChip({ label, result }: { label: string; result: AuthResult | null }) {
  const cls =
    result === "pass"
      ? "border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300"
      : result === "fail"
        ? "border-rose-600/60 bg-rose-600/5 text-rose-500"
        : result === "softfail"
          ? "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400"
          : "border-zinc-300 bg-zinc-100 text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-400";
  return (
    <Badge variant="outline" className={cn("gap-1 font-mono text-[10px] uppercase", cls)}>
      {result === "pass" ? (
        <Icons.Check className="h-2.5 w-2.5" />
      ) : result === "fail" ? (
        <Icons.X className="h-2.5 w-2.5" />
      ) : (
        <Icons.CircleMinus className="h-2.5 w-2.5" />
      )}
      {label}: {result ?? "n/a"}
    </Badge>
  );
}

/** Phishing / malware / extension / size reasons are hard blocks → rose;
 *  spam_score and dmarc policy outcomes → amber; releases → blue. */
const HARD_REASONS = new Set(["malware", "phishing", "blocked_extension", "size", "dmarc_fail"]);

function ReasonChip({ reason }: { reason: string }) {
  const cls = reason.startsWith("released:")
    ? "border-zinc-500/30 bg-zinc-500/10 font-mono text-[10px] text-zinc-600 dark:text-zinc-300"
    : HARD_REASONS.has(reason)
      ? "border-rose-600/40 bg-rose-600/5 font-mono text-[10px] text-rose-500"
      : "border-amber-500/40 bg-amber-500/5 font-mono text-[10px] text-amber-600 dark:text-amber-400";
  return (
    <Badge variant="outline" className={cls}>
      {reason}
    </Badge>
  );
}

// ── stats strip (10s polling) ───────────────────────────────────────────────

function StatCard(props: { label: string; value: number | string; icon: React.ReactNode; tone: string; sub?: React.ReactNode }) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs font-medium text-zinc-500">{props.label}</span>
          <span className={props.tone}>{props.icon}</span>
        </div>
        <p className="mt-1 text-2xl font-semibold tabular-nums">{props.value}</p>
        {props.sub ? <div className="mt-1">{props.sub}</div> : null}
      </CardContent>
    </Card>
  );
}

function StatsStrip() {
  const statsQuery = useQuery({
    queryKey: ["email-security", "stats"],
    queryFn: emailSecurityApi.getStats,
    refetchInterval: POLL_MS,
  });
  const stats = statsQuery.data;
  const processed = stats ? stats.delivered24h + stats.quarantined24h + stats.rejected24h : null;

  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
      <StatCard
        label="Processed (24h)"
        value={processed ?? "—"}
        tone="text-zinc-500 dark:text-zinc-400"
        icon={<Icons.Mail className="h-4 w-4" />}
        sub={<p className="text-[11px] text-zinc-400">all verdicts, last 24 hours</p>}
      />
      <StatCard
        label="Delivered (24h)"
        value={stats?.delivered24h ?? "—"}
        tone="text-zinc-500 dark:text-zinc-400"
        icon={<Icons.MailCheck className="h-4 w-4" />}
      />
      <StatCard
        label="Quarantined (24h)"
        value={stats?.quarantined24h ?? "—"}
        tone="text-amber-500"
        icon={<Icons.Archive className="h-4 w-4" />}
        sub={
          stats ? (
            <p className="text-[11px] text-zinc-400">retention {stats.quarantineRetentionDays} days</p>
          ) : undefined
        }
      />
      <StatCard
        label="Rejected (24h)"
        value={stats?.rejected24h ?? "—"}
        tone="text-rose-500"
        icon={<Icons.Ban className="h-4 w-4" />}
      />
      <Card>
        <CardContent className="p-4">
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-medium text-zinc-500">Avg spam score (24h)</span>
            <Icons.Gauge className="h-4 w-4 text-zinc-700 dark:text-zinc-500" />
          </div>
          <p className="mt-1 text-2xl font-semibold tabular-nums">
            {stats ? stats.avgSpamScore.toFixed(1) : "—"}
            <span className="ml-1 text-xs font-normal text-zinc-400">/ {SPAM_SCORE_MAX}</span>
          </p>
          {stats && stats.topReasons.length > 0 ? (
            <div className="mt-2 flex flex-wrap gap-1">
              {stats.topReasons.map((t) => (
                <ReasonChip key={t.reason} reason={`${t.reason} ×${t.count}`} />
              ))}
            </div>
          ) : (
            <p className="mt-2 text-xs text-zinc-400">No scan reasons in the last 24h</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ── gateways tab (SMTP proxy/relay listener table) ──────────────────────────

function GatewayEditor(props: { gateway: EmailGatewayDTO | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = props.gateway !== null;
  const [name, setName] = useState(props.gateway?.name ?? "");
  const [mode, setMode] = useState<GatewayMode>(props.gateway?.mode ?? "proxy");
  const [listenPort, setListenPort] = useState(String(props.gateway?.listenPort ?? 25));
  const [relayDomains, setRelayDomains] = useState((props.gateway?.relayDomains ?? []).join(", "));
  const [upstreamHost, setUpstreamHost] = useState(props.gateway?.upstreamHost ?? "");
  const [tlsMode, setTlsMode] = useState<TlsMode>(props.gateway?.tlsMode ?? "starttls");
  const [enabled, setEnabled] = useState(props.gateway?.enabled ?? true);
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => {
      const id = props.gateway?.id;
      if (isEdit && id !== undefined) return emailSecurityApi.updateGateway(id, body);
      return emailSecurityApi.createGateway(body);
    },
    onSuccess: (g) => {
      toastOk(isEdit ? "Gateway updated" : "Gateway created", g.name);
      invalidateAll(queryClient);
      props.onClose();
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Save failed"),
  });

  const submit = () => {
    const port = Number(listenPort);
    if (!name.trim()) {
      setErr("Name is required");
      return;
    }
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      setErr("Listen port must be an integer between 1 and 65535");
      return;
    }
    if (mode === "relay" && !upstreamHost.trim()) {
      setErr("Upstream host is required when mode is relay");
      return;
    }
    const domains = relayDomains
      .split(/[,\s]+/)
      .map((d) => d.trim().toLowerCase())
      .filter((d) => d.length > 0);
    setErr(null);
    save.mutate({
      name: name.trim(),
      mode,
      listenPort: port,
      relayDomains: [...new Set(domains)],
      upstreamHost: upstreamHost.trim() || null,
      tlsMode,
      enabled,
    });
  };

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-base">{isEdit ? "Edit gateway" : "New email gateway"}</DialogTitle>
          <DialogDescription>
            Relay mode forwards to an upstream SMTP host; proxy mode filters inline on the listener port.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div>
            <FieldLabel>Name</FieldLabel>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="mx01" className="font-mono text-xs" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel>Mode</FieldLabel>
              <Select value={mode} onValueChange={(v) => setMode(v as GatewayMode)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {GATEWAY_MODES.map((m) => (
                    <SelectItem key={m} value={m}>
                      {m}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel hint="1–65535">Listen port</FieldLabel>
              <Input
                type="number"
                min={1}
                max={65535}
                value={listenPort}
                onChange={(e) => setListenPort(e.target.value)}
                className="font-mono text-xs"
              />
            </div>
          </div>
          <div>
            <FieldLabel hint={mode === "relay" ? "required for relay" : "optional"}>Upstream host</FieldLabel>
            <Input
              value={upstreamHost}
              onChange={(e) => setUpstreamHost(e.target.value)}
              placeholder="smtp.outbound.example"
              className="font-mono text-xs"
            />
          </div>
          <div>
            <FieldLabel hint="comma-separated domains">Relay domains</FieldLabel>
            <Input
              value={relayDomains}
              onChange={(e) => setRelayDomains(e.target.value)}
              placeholder="corp.example, partner.com"
              className="font-mono text-xs"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel hint="wrapper = implicit SMTPS">TLS mode</FieldLabel>
              <Select value={tlsMode} onValueChange={(v) => setTlsMode(v as TlsMode)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {TLS_MODES.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-end justify-between gap-3 rounded-lg border border-zinc-200 px-3 py-2 dark:border-zinc-800">
              <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Enabled</span>
              <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="Gateway enabled" />
            </div>
          </div>
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button className="bg-amber-700 text-white hover:bg-amber-800" disabled={save.isPending || !name.trim()} onClick={submit}>
            {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create gateway"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function GatewaysCard() {
  const queryClient = useQueryClient();
  const gatewaysQuery = useQuery({ queryKey: ["email-security", "gateways"], queryFn: emailSecurityApi.listGateways });
  const gateways = gatewaysQuery.data ?? [];

  const [addOpen, setAddOpen] = useState(false);
  const [editing, setEditing] = useState<EmailGatewayDTO | null>(null);
  const [deleting, setDeleting] = useState<EmailGatewayDTO | null>(null);

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => emailSecurityApi.updateGateway(id, { enabled }),
    onSuccess: () => invalidateAll(queryClient),
    onError: (e) => toastErr(e, "Toggle failed"),
  });

  const del = useMutation({
    mutationFn: (id: number) => emailSecurityApi.deleteGateway(id),
    onSuccess: () => {
      toastOk("Gateway deleted");
      setDeleting(null);
      invalidateAll(queryClient);
    },
    onError: (e) => toastErr(e, "Delete failed"),
  });

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.Server className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
          Gateways
          <span className="text-xs font-normal text-zinc-400">
            {gateways.length} listener{gateways.length === 1 ? "" : "s"}
          </span>
        </CardTitle>
        <Button size="sm" className="h-8 bg-zinc-700 text-white hover:bg-zinc-800" onClick={() => setAddOpen(true)}>
          <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add
        </Button>
      </CardHeader>
      <CardContent className="p-0">
        {gatewaysQuery.isError ? (
          <div className="p-4">
            <QueryError error={gatewaysQuery.error} onRetry={() => void gatewaysQuery.refetch()} />
          </div>
        ) : gatewaysQuery.isLoading ? (
          <TableSkeleton rows={3} cols={7} />
        ) : gateways.length === 0 ? (
          <EmptyBlock
            icon={<Icons.Server className="h-6 w-6" />}
            title="No gateways yet"
            description="Add a proxy or relay listener to accept and scan SMTP traffic."
            action={
              <Button size="sm" className="bg-zinc-700 text-white hover:bg-zinc-800" onClick={() => setAddOpen(true)}>
                <Icons.Plus className="mr-1 h-3.5 w-3.5" /> New gateway
              </Button>
            }
          />
        ) : (
          <div className="max-h-96 overflow-y-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Listener</TableHead>
                  <TableHead className="w-16">Port</TableHead>
                  <TableHead className="w-28">TLS</TableHead>
                  <TableHead className="max-w-44">Relay domains</TableHead>
                  <TableHead className="max-w-44">Upstream</TableHead>
                  <TableHead className="w-20">Enabled</TableHead>
                  <TableHead className="w-20 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {gateways.map((g) => (
                  <TableRow key={g.id} className={g.enabled ? undefined : "opacity-70"}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium">{g.name}</span>
                        <ModeBadge mode={g.mode} />
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-xs tabular-nums text-zinc-500">:{g.listenPort}</TableCell>
                    <TableCell>
                      <TlsChip tlsMode={g.tlsMode} />
                    </TableCell>
                    <TableCell className="max-w-44">
                      {g.relayDomains.length > 0 ? (
                        <span className="block truncate font-mono text-xs" title={g.relayDomains.join(", ")}>
                          {g.relayDomains.join(", ")}
                        </span>
                      ) : (
                        <span className="text-[11px] text-zinc-400">any</span>
                      )}
                    </TableCell>
                    <TableCell className="max-w-44">
                      <span className="block truncate font-mono text-xs text-zinc-500" title={g.upstreamHost ?? undefined}>
                        {g.upstreamHost ?? "—"}
                      </span>
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={g.enabled}
                        disabled={toggle.isPending && toggle.variables?.id === g.id}
                        onCheckedChange={(enabled) => toggle.mutate({ id: g.id, enabled })}
                        aria-label={`Toggle ${g.name}`}
                      />
                    </TableCell>
                    <TableCell>
                      <div className="flex justify-end gap-0.5">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-zinc-400 hover:text-zinc-600"
                          aria-label={`Edit ${g.name}`}
                          onClick={() => setEditing(g)}
                        >
                          <Icons.Pencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-zinc-400 hover:text-rose-600"
                          aria-label={`Delete ${g.name}`}
                          onClick={() => setDeleting(g)}
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
        {gateways.length > 0 && (
          <p className="border-t border-zinc-200 px-4 py-2 text-[11px] text-zinc-400 dark:border-zinc-800">
            Relay mode requires an upstream host · wrapper TLS enforces implicit SMTPS
          </p>
        )}
      </CardContent>

      {addOpen && <GatewayEditor gateway={null} onClose={() => setAddOpen(false)} />}
      {editing && <GatewayEditor gateway={editing} onClose={() => setEditing(null)} />}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete gateway “${deleting?.name ?? ""}”?`}
        description="The listener stops accepting mail immediately. Log rows are kept."
        loading={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting.id)}
      />
    </Card>
  );
}

// ── policy tab (singleton editor) ───────────────────────────────────────────

interface PolicyForm {
  spamThreshold: number;
  blockPhishing: boolean;
  blockMalware: boolean;
  scanArchives: boolean;
  maxMessageSizeMb: number;
  blockedExtensions: string[];
  spfVerify: boolean;
  dkimVerify: boolean;
  dmarcPolicy: DmarcPolicy;
  quarantineRetentionDays: number;
  enabled: boolean;
}

function toForm(p: EmailPolicyDTO): PolicyForm {
  return {
    spamThreshold: p.spamThreshold,
    blockPhishing: p.blockPhishing,
    blockMalware: p.blockMalware,
    scanArchives: p.scanArchives,
    maxMessageSizeMb: p.maxMessageSizeMb,
    blockedExtensions: p.blockedExtensions,
    spfVerify: p.spfVerify,
    dkimVerify: p.dkimVerify,
    dmarcPolicy: p.dmarcPolicy,
    quarantineRetentionDays: p.quarantineRetentionDays,
    enabled: p.enabled,
  };
}

/** Policy draft editor — PolicyCard mounts it with key={policy.id} so the draft
 *  initializes from the singleton without a state-reset effect. */
function PolicyFormBody({ policy }: { policy: EmailPolicyDTO }) {
  const queryClient = useQueryClient();

  const [form, setForm] = useState<PolicyForm>(() => toForm(policy));
  const [extInput, setExtInput] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const patch = (p: Partial<PolicyForm>) => setForm((f) => ({ ...f, ...p }));

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => emailSecurityApi.updatePolicy(body),
    onSuccess: (p) => {
      toastOk("Email policy saved", p.name);
      setErr(null);
      invalidateAll(queryClient);
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Save failed"),
  });

  const addExtension = (raw: string) => {
    if (!form) return;
    const ext = raw.trim().toLowerCase();
    if (!/^[a-z0-9]{1,10}$/.test(ext)) {
      setErr("Extensions must be 1–10 lowercase letters/digits, e.g. exe");
      return;
    }
    if (!form.blockedExtensions.includes(ext)) {
      patch({ blockedExtensions: [...form.blockedExtensions, ext] });
    }
    setExtInput("");
    setErr(null);
  };

  const submit = () => {
    if (form.maxMessageSizeMb < 1 || form.maxMessageSizeMb > 1024) {
      setErr("Max message size must be between 1 and 1024 MB");
      return;
    }
    if (form.quarantineRetentionDays < 1 || form.quarantineRetentionDays > 90) {
      setErr("Quarantine retention must be between 1 and 90 days");
      return;
    }
    setErr(null);
    save.mutate({ ...form });
  };

  const toggles: Array<[string, boolean, (v: boolean) => void]> = [
    ["Block phishing senders", form.blockPhishing, (v) => patch({ blockPhishing: v })],
    ["Block malware (ClamAV)", form.blockMalware, (v) => patch({ blockMalware: v })],
    ["Scan archives", form.scanArchives, (v) => patch({ scanArchives: v })],
    ["Verify SPF", form.spfVerify, (v) => patch({ spfVerify: v })],
    ["Verify DKIM", form.dkimVerify, (v) => patch({ dkimVerify: v })],
    ["Policy enabled", form.enabled, (v) => patch({ enabled: v })],
  ];

  return (
    <div className="grid gap-4">
      <div>
        <FieldLabel hint={`${form.spamThreshold.toFixed(1)} — over threshold is spam`}>
          Spam threshold (Rspamd score)
        </FieldLabel>
        <div className="flex items-center gap-3">
          <Slider
            min={0}
            max={20}
            step={0.5}
            value={[form.spamThreshold]}
            onValueChange={(vals) => {
              const v = vals[0];
              if (v !== undefined) patch({ spamThreshold: v });
            }}
            aria-label="Spam threshold"
            className="flex-1"
          />
          <span className="w-10 shrink-0 rounded-md border border-zinc-200 py-0.5 text-center font-mono text-xs tabular-nums dark:border-zinc-800">
            {form.spamThreshold.toFixed(1)}
          </span>
        </div>
      </div>

      <div className="grid gap-3 rounded-lg border border-zinc-200 p-4 dark:border-zinc-800 sm:grid-cols-2">
        {toggles.map(([label, value, set]) => (
          <div key={label} className="flex items-center justify-between gap-4">
            <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">{label}</span>
            <Switch checked={value} onCheckedChange={set} aria-label={label} />
          </div>
        ))}
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <div>
          <FieldLabel hint="none / quarantine / reject">DMARC policy</FieldLabel>
          <Select value={form.dmarcPolicy} onValueChange={(v) => patch({ dmarcPolicy: v as DmarcPolicy })}>
            <SelectTrigger aria-label="DMARC policy">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {DMARC_POLICIES.map((p) => (
                <SelectItem key={p} value={p}>
                  {p}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div>
          <FieldLabel hint="MB">Max message size</FieldLabel>
          <Input
            type="number"
            min={1}
            max={1024}
            value={form.maxMessageSizeMb}
            onChange={(e) => patch({ maxMessageSizeMb: Number(e.target.value) })}
            className="font-mono text-xs"
          />
        </div>
        <div>
          <FieldLabel hint="1–90 days">Quarantine retention</FieldLabel>
          <Input
            type="number"
            min={1}
            max={90}
            value={form.quarantineRetentionDays}
            onChange={(e) => patch({ quarantineRetentionDays: Number(e.target.value) })}
            className="font-mono text-xs"
          />
        </div>
      </div>

      <div>
        <FieldLabel hint="toggle presets or add your own, max 20">Blocked extensions</FieldLabel>
        <div className="flex flex-wrap items-center gap-1.5">
          {COMMON_EXTENSIONS.map((ext) => {
            const active = form.blockedExtensions.includes(ext);
            return (
              <button
                key={ext}
                type="button"
                aria-pressed={active}
                onClick={() =>
                  patch({
                    blockedExtensions: active
                      ? form.blockedExtensions.filter((e) => e !== ext)
                      : [...form.blockedExtensions, ext],
                  })
                }
                className={cn(
                  "rounded-full border px-2.5 py-1 font-mono text-xs transition-colors",
                  active
                    ? "border-rose-600/40 bg-rose-600/10 font-medium text-rose-500"
                    : "border-zinc-200 text-zinc-500 hover:bg-zinc-100 dark:border-zinc-800 dark:hover:bg-zinc-800",
                )}
              >
                .{ext}
              </button>
            );
          })}
          {form.blockedExtensions
            .filter((e) => !COMMON_EXTENSIONS.includes(e))
            .map((ext) => (
              <Badge
                key={ext}
                variant="outline"
                className="gap-1 border-rose-600/40 bg-rose-600/10 font-mono text-[10px] text-rose-500"
              >
                .{ext}
                <button
                  type="button"
                  aria-label={`Remove ${ext}`}
                  className="rounded-sm p-0.5 hover:bg-rose-600/20"
                  onClick={() => patch({ blockedExtensions: form.blockedExtensions.filter((e) => e !== ext) })}
                >
                  <Icons.X className="h-2.5 w-2.5" />
                </button>
              </Badge>
            ))}
        </div>
        <div className="mt-2 flex gap-2">
          <Input
            value={extInput}
            onChange={(e) => setExtInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                addExtension(extInput);
              }
            }}
            placeholder="Add extension, e.g. dll"
            className="h-8 max-w-48 font-mono text-xs"
            aria-label="New blocked extension"
          />
          <Button type="button" variant="outline" size="sm" className="h-8 gap-1 text-xs" onClick={() => addExtension(extInput)}>
            <Icons.Plus className="h-3.5 w-3.5" /> Add
          </Button>
        </div>
      </div>

      {err && <p className="text-xs text-rose-600">{err}</p>}

      <div className="flex justify-end">
        <Button className="bg-amber-700 text-white hover:bg-amber-800" disabled={save.isPending} onClick={submit}>
          {save.isPending ? "Saving…" : "Save policy"}
        </Button>
      </div>
    </div>
  );
}

function PolicyCard() {
  const policyQuery = useQuery({ queryKey: ["email-security", "policy"], queryFn: emailSecurityApi.getPolicy });
  const policy = policyQuery.data ?? null;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.Shield className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
          Content policy
          {policy && <span className="text-xs font-normal text-zinc-400">{policy.name}</span>}
        </CardTitle>
      </CardHeader>
      <CardContent className="p-4 pt-0">
        {policyQuery.isError ? (
          <QueryError error={policyQuery.error} onRetry={() => void policyQuery.refetch()} />
        ) : policyQuery.isLoading || !policy ? (
          <div className="space-y-3">
            <div className="h-10 animate-pulse rounded-lg bg-zinc-100 dark:bg-zinc-800" />
            <div className="h-24 animate-pulse rounded-lg bg-zinc-100 dark:bg-zinc-800" />
          </div>
        ) : (
          <PolicyFormBody key={policy.id} policy={policy} />
        )}
      </CardContent>
    </Card>
  );
}

// ── routing rules tab ───────────────────────────────────────────────────────

function RuleEditor(props: { rule: EmailRoutingRuleDTO | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = props.rule !== null;
  const [name, setName] = useState(props.rule?.name ?? "");
  const [matchDomain, setMatchDomain] = useState(props.rule?.matchDomain ?? "");
  const [action, setAction] = useState<RoutingAction>(props.rule?.action ?? "relay");
  const [targetHost, setTargetHost] = useState(props.rule?.targetHost ?? "");
  const [priority, setPriority] = useState(String(props.rule?.priority ?? 10));
  const [enabled, setEnabled] = useState(props.rule?.enabled ?? true);
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => {
      const id = props.rule?.id;
      if (isEdit && id !== undefined) return emailSecurityApi.updateRoutingRule(id, body);
      return emailSecurityApi.createRoutingRule(body);
    },
    onSuccess: (r) => {
      toastOk(isEdit ? "Routing rule updated" : "Routing rule created", r.name);
      invalidateAll(queryClient);
      props.onClose();
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Save failed"),
  });

  const submit = () => {
    const prio = Number(priority);
    if (!name.trim()) {
      setErr("Name is required");
      return;
    }
    if (!matchDomain.trim()) {
      setErr("Match domain is required (domain or @domain)");
      return;
    }
    if (!Number.isInteger(prio) || prio < 1 || prio > 100) {
      setErr("Priority must be an integer between 1 and 100");
      return;
    }
    if (action === "relay" && !targetHost.trim()) {
      setErr("Target host is required when action is relay");
      return;
    }
    setErr(null);
    save.mutate({
      name: name.trim(),
      matchDomain: matchDomain.trim().toLowerCase(),
      action,
      targetHost: targetHost.trim() || null,
      priority: prio,
      enabled,
    });
  };

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-base">{isEdit ? "Edit routing rule" : "New routing rule"}</DialogTitle>
          <DialogDescription>
            Lower priority numbers are evaluated first; priorities must be unique per tenant.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div className="grid grid-cols-[1fr_88px] gap-4">
            <div>
              <FieldLabel>Name</FieldLabel>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="partner-mail" className="font-mono text-xs" />
            </div>
            <div>
              <FieldLabel hint="1–100">Priority</FieldLabel>
              <Input
                type="number"
                min={1}
                max={100}
                value={priority}
                onChange={(e) => setPriority(e.target.value)}
                className="font-mono text-xs"
              />
            </div>
          </div>
          <div>
            <FieldLabel hint="domain or @domain (e.g. @zip)">Match domain</FieldLabel>
            <Input
              value={matchDomain}
              onChange={(e) => setMatchDomain(e.target.value)}
              placeholder="partner.com"
              className="font-mono text-xs"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel>Action</FieldLabel>
              <Select value={action} onValueChange={(v) => setAction(v as RoutingAction)}>
                <SelectTrigger aria-label="Routing action">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ROUTING_ACTIONS.map((a) => (
                    <SelectItem key={a} value={a}>
                      {a}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel hint={action === "relay" ? "required for relay" : "optional"}>Target host</FieldLabel>
              <Input
                value={targetHost}
                onChange={(e) => setTargetHost(e.target.value)}
                placeholder="10.30.0.50"
                className="font-mono text-xs"
              />
            </div>
          </div>
          <div className="flex items-center justify-between gap-4 rounded-lg border border-zinc-200 px-3 py-2 dark:border-zinc-800">
            <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Enabled</span>
            <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="Rule enabled" />
          </div>
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button className="bg-amber-700 text-white hover:bg-amber-800" disabled={save.isPending || !name.trim()} onClick={submit}>
            {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create rule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function RoutingRulesCard() {
  const queryClient = useQueryClient();
  const rulesQuery = useQuery({ queryKey: ["email-security", "routing-rules"], queryFn: emailSecurityApi.listRoutingRules });
  const rules = rulesQuery.data ?? [];

  const [addOpen, setAddOpen] = useState(false);
  const [editing, setEditing] = useState<EmailRoutingRuleDTO | null>(null);
  const [deleting, setDeleting] = useState<EmailRoutingRuleDTO | null>(null);

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => emailSecurityApi.updateRoutingRule(id, { enabled }),
    onSuccess: () => invalidateAll(queryClient),
    onError: (e) => toastErr(e, "Toggle failed"),
  });

  const del = useMutation({
    mutationFn: (id: number) => emailSecurityApi.deleteRoutingRule(id),
    onSuccess: () => {
      toastOk("Routing rule deleted");
      setDeleting(null);
      invalidateAll(queryClient);
    },
    onError: (e) => toastErr(e, "Delete failed"),
  });

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.Route className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
          Routing rules
          <span className="text-xs font-normal text-zinc-400">
            {rules.length} rule{rules.length === 1 ? "" : "s"}
          </span>
        </CardTitle>
        <Button size="sm" className="h-8 bg-zinc-700 text-white hover:bg-zinc-800" onClick={() => setAddOpen(true)}>
          <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add
        </Button>
      </CardHeader>
      <CardContent className="p-0">
        {rulesQuery.isError ? (
          <div className="p-4">
            <QueryError error={rulesQuery.error} onRetry={() => void rulesQuery.refetch()} />
          </div>
        ) : rulesQuery.isLoading ? (
          <TableSkeleton rows={3} cols={6} />
        ) : rules.length === 0 ? (
          <EmptyBlock
            icon={<Icons.Route className="h-6 w-6" />}
            title="No routing rules"
            description="Route matching domains to a relay host, quarantine or reject before the content scan."
          />
        ) : (
          <div className="max-h-96 overflow-y-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-16">Prio</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Match domain</TableHead>
                  <TableHead className="w-28">Action</TableHead>
                  <TableHead>Target host</TableHead>
                  <TableHead className="w-20">Enabled</TableHead>
                  <TableHead className="w-20 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rules.map((rule) => (
                  <TableRow key={rule.id} className={rule.enabled ? undefined : "opacity-70"}>
                    <TableCell className="font-mono text-xs tabular-nums text-zinc-500">{rule.priority}</TableCell>
                    <TableCell className="text-sm font-medium">{rule.name}</TableCell>
                    <TableCell>
                      <span className="block truncate font-mono text-xs" title={rule.matchDomain}>
                        {rule.matchDomain}
                      </span>
                    </TableCell>
                    <TableCell>
                      <ActionBadge action={rule.action} />
                    </TableCell>
                    <TableCell>
                      <span className="block truncate font-mono text-xs text-zinc-500" title={rule.targetHost ?? undefined}>
                        {rule.targetHost ?? "—"}
                      </span>
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={rule.enabled}
                        disabled={toggle.isPending && toggle.variables?.id === rule.id}
                        onCheckedChange={(enabled) => toggle.mutate({ id: rule.id, enabled })}
                        aria-label={`Toggle ${rule.name}`}
                      />
                    </TableCell>
                    <TableCell>
                      <div className="flex justify-end gap-0.5">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-zinc-400 hover:text-zinc-600"
                          aria-label={`Edit ${rule.name}`}
                          onClick={() => setEditing(rule)}
                        >
                          <Icons.Pencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-zinc-400 hover:text-rose-600"
                          aria-label={`Delete ${rule.name}`}
                          onClick={() => setDeleting(rule)}
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

      {addOpen && <RuleEditor rule={null} onClose={() => setAddOpen(false)} />}
      {editing && <RuleEditor rule={editing} onClose={() => setEditing(null)} />}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete rule “${deleting?.name ?? ""}”?`}
        description="Matching domains fall through to the default delivery path immediately."
        loading={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting.id)}
      />
    </Card>
  );
}

// ── test tab (simulated Rspamd + ClamAV scan) ───────────────────────────────

/** Attachment presets for the simulated scan (exe/scr hit ClamAV sim, js hits
 *  the blocked-extensions policy, docm/zip/pdf exercise archive + pass paths). */
const ATTACHMENT_TYPES: Array<{ value: string; label: string }> = [
  { value: "none", label: "No attachment" },
  { value: "report.pdf", label: "report.pdf — PDF document" },
  { value: "invoice.docm", label: "invoice.docm — macro document" },
  { value: "archive.zip", label: "archive.zip — archive" },
  { value: "installer.exe", label: "installer.exe — executable" },
  { value: "photo.scr", label: "photo.scr — screensaver" },
  { value: "script.js", label: "script.js — script" },
];

function TestMessageCard() {
  const queryClient = useQueryClient();
  const policyQuery = useQuery({ queryKey: ["email-security", "policy"], queryFn: emailSecurityApi.getPolicy });
  const threshold = policyQuery.data?.spamThreshold ?? 6.0;

  const [from, setFrom] = useState("ceo@corp.example");
  const [to, setTo] = useState("ops@corp.example");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [attachment, setAttachment] = useState("none");
  const [sizeKb, setSizeKb] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const run = useMutation({
    mutationFn: () =>
      emailSecurityApi.testMessage({
        from: from.trim(),
        to: to.trim(),
        ...(subject.trim() ? { subject: subject.trim() } : {}),
        ...(body ? { body } : {}),
        attachments: attachment === "none" ? [] : [attachment],
        ...(sizeKb.trim() && Number.isFinite(Number(sizeKb)) ? { sizeKb: Number(sizeKb) } : {}),
      }),
    onSuccess: () => {
      setErr(null);
      invalidateAll(queryClient); // test persists a log row + shifts stats
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Test failed"),
  });

  const result = run.data;
  const meterPct = result ? Math.min(100, (result.spamScore / SPAM_SCORE_MAX) * 100) : 0;
  const meterColor = !result
    ? ""
    : result.verdict === "rejected"
      ? "bg-rose-600"
      : result.verdict === "quarantined"
        ? "bg-amber-500"
        : result.spamScore > threshold
          ? "bg-amber-500"
          : "bg-zinc-500";

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.FlaskConical className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
          Test message
          <span className="text-xs font-normal text-zinc-400">simulated Rspamd + ClamAV scan</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 p-4 pt-0">
        <div className="grid gap-3 md:grid-cols-2">
          <div>
            <FieldLabel>From</FieldLabel>
            <Input value={from} onChange={(e) => setFrom(e.target.value)} placeholder="sender@corp.example" className="font-mono text-xs" aria-label="From address" />
          </div>
          <div>
            <FieldLabel>To</FieldLabel>
            <Input value={to} onChange={(e) => setTo(e.target.value)} placeholder="recipient@corp.example" className="font-mono text-xs" aria-label="To address" />
          </div>
          <div className="md:col-span-2">
            <FieldLabel hint="optional">Subject</FieldLabel>
            <Input value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="Your account needs attention" aria-label="Subject" />
          </div>
          <div className="md:col-span-2">
            <FieldLabel hint="optional">Body</FieldLabel>
            <Textarea rows={3} value={body} onChange={(e) => setBody(e.target.value)} placeholder="Paste the message body…" aria-label="Body" />
          </div>
          <div>
            <FieldLabel hint="simulated ClamAV + extension policy">Attachment type</FieldLabel>
            <Select value={attachment} onValueChange={setAttachment}>
              <SelectTrigger aria-label="Attachment type">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {ATTACHMENT_TYPES.map((t) => (
                  <SelectItem key={t.value} value={t.value}>
                    {t.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <FieldLabel hint="optional, KB">Message size</FieldLabel>
            <Input type="number" min={0} value={sizeKb} onChange={(e) => setSizeKb(e.target.value)} placeholder="e.g. 30720" className="font-mono text-xs" aria-label="Message size in KB" />
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button
            className="h-9 bg-zinc-700 px-5 text-white hover:bg-zinc-800"
            disabled={run.isPending || !from.trim() || !to.trim()}
            onClick={() => run.mutate()}
          >
            {run.isPending ? <Icons.Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" /> : <Icons.Play className="mr-1 h-3.5 w-3.5" />}
            Run
          </Button>
          <p className="text-[11px] text-zinc-400">
            Try security@paypa1-security.example, promo@throwaway.mx, “free money winner crypto” or installer.exe.
          </p>
        </div>

        {err && <p className="text-xs text-rose-600">{err}</p>}

        {result && (
          <div className="space-y-3 rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
            <div className="flex flex-wrap items-center gap-2">
              <VerdictBadge verdict={result.verdict} />
              <span className="font-mono text-xs tabular-nums text-zinc-500">
                score {result.spamScore.toFixed(1)} / {SPAM_SCORE_MAX} (threshold {threshold.toFixed(1)})
              </span>
              <span className="text-[11px] text-zinc-400">
                {result.attachmentsScanned} attachment{result.attachmentsScanned === 1 ? "" : "s"} scanned
              </span>
            </div>

            <div className="relative">
              <div className="h-2 w-full overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800">
                <div className={cn("h-full rounded-full transition-all", meterColor)} style={{ width: `${meterPct}%` }} />
              </div>
              <div
                className="absolute top-[-3px] h-3.5 w-0.5 bg-zinc-400"
                style={{ left: `${Math.min(100, (threshold / SPAM_SCORE_MAX) * 100)}%` }}
                aria-hidden="true"
              />
            </div>

            <div className="flex flex-wrap items-center gap-1.5">
              <AuthChip label="spf" result={result.spfResult} />
              <AuthChip label="dkim" result={result.dkimResult} />
              <AuthChip label="dmarc" result={result.dmarcResult} />
            </div>

            {result.reasons.length > 0 ? (
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-[11px] uppercase tracking-wide text-zinc-400">reasons</span>
                {result.reasons.map((r) => (
                  <ReasonChip key={r} reason={r} />
                ))}
              </div>
            ) : (
              <p className="text-xs text-zinc-400">No scan reasons — message would be delivered as-is.</p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ── mail log tab (paged, 10s polling) ───────────────────────────────────────

function MailLogCard() {
  const queryClient = useQueryClient();
  const [verdict, setVerdict] = useState<"all" | EmailVerdict>("all");
  const [q, setQ] = useState("");
  // Page state carries the filter key it was computed under — changing the
  // verdict filter or search resets to page 1 without a state-reset effect.
  const [pageState, setPageState] = useState<{ key: string; n: number }>({ key: "", n: 1 });

  const params = useMemo(
    () => qs({ limit: LOG_FETCH_WINDOW, verdict: verdict === "all" ? undefined : verdict, q: q.trim() || undefined }),
    [verdict, q],
  );
  const logsQuery = useQuery({
    queryKey: ["email-security", "logs", params],
    queryFn: () => emailSecurityApi.listLogs(params),
    refetchInterval: POLL_MS,
  });
  const rows = logsQuery.data?.data ?? [];
  const meta = logsQuery.data?.meta;

  const filterKey = `${verdict}|${q.trim()}`;
  const pageCount = Math.max(1, Math.ceil(rows.length / LOG_PAGE_SIZE));
  const page = pageState.key === filterKey ? pageState.n : 1;
  const safePage = Math.min(page, pageCount);
  const paged = rows.slice((safePage - 1) * LOG_PAGE_SIZE, safePage * LOG_PAGE_SIZE);
  const setPage = (next: number) => setPageState({ key: filterKey, n: Math.min(Math.max(1, next), pageCount) });

  const release = useMutation({
    mutationFn: (id: number) => emailSecurityApi.releaseLog(id),
    onSuccess: (row) => {
      toastOk("Message released", `#${row.id} delivered to ${row.toAddr}`);
      invalidateAll(queryClient);
    },
    onError: (e) => toastErr(e, "Release failed"),
  });

  const rangeStart = rows.length === 0 ? 0 : (safePage - 1) * LOG_PAGE_SIZE + 1;
  const rangeEnd = (safePage - 1) * LOG_PAGE_SIZE + paged.length;

  return (
    <Card>
      <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2 space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.ScrollText className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
          Mail log
        </CardTitle>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Icons.Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-400" />
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search from/to/subject…"
              className="h-8 w-44 pl-8 text-xs"
              aria-label="Search mail log"
            />
          </div>
          <Select
            value={verdict}
            onValueChange={(v) => {
              setVerdict(v as "all" | EmailVerdict);
              void queryClient.invalidateQueries({ queryKey: ["email-security", "logs"] });
            }}
          >
            <SelectTrigger className="h-8 w-36" aria-label="Verdict filter">
              <SelectValue placeholder="All verdicts" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All verdicts</SelectItem>
              {VERDICTS.map((v) => (
                <SelectItem key={v} value={v}>
                  {v}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button variant="ghost" size="icon" className="h-8 w-8" aria-label="Refresh mail log" onClick={() => void logsQuery.refetch()}>
            <Icons.RefreshCw className={cn("h-3.5 w-3.5", logsQuery.isFetching ? "animate-spin" : "")} />
          </Button>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        {logsQuery.isError ? (
          <div className="p-4">
            <QueryError error={logsQuery.error} onRetry={() => void logsQuery.refetch()} />
          </div>
        ) : logsQuery.isLoading ? (
          <TableSkeleton rows={6} cols={8} />
        ) : rows.length === 0 ? (
          <EmptyBlock
            icon={<Icons.ScrollText className="h-6 w-6" />}
            title="No mail log entries"
            description="Run a test message or let the appliance process traffic to populate the log."
          />
        ) : (
          <div className="max-h-96 overflow-y-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-28">Verdict</TableHead>
                  <TableHead>From → To</TableHead>
                  <TableHead className="max-w-48">Subject</TableHead>
                  <TableHead className="w-16 text-right">Score</TableHead>
                  <TableHead>Reasons</TableHead>
                  <TableHead className="w-16 text-right">Size</TableHead>
                  <TableHead className="w-20 text-right">Time</TableHead>
                  <TableHead className="w-20 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {paged.map((log) => (
                  <TableRow key={log.id}>
                    <TableCell>
                      <VerdictBadge verdict={log.verdict} />
                    </TableCell>
                    <TableCell className="max-w-56">
                      <span className="block truncate font-mono text-xs" title={`${log.fromAddr} → ${log.toAddr}`}>
                        {log.fromAddr}
                        <Icons.ArrowRight className="mx-1 inline h-3 w-3 text-zinc-400" />
                        {log.toAddr}
                      </span>
                    </TableCell>
                    <TableCell className="max-w-48">
                      <span className="block truncate text-xs" title={log.subject ?? undefined}>
                        {log.subject ?? "—"}
                      </span>
                    </TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums text-zinc-500">
                      {log.spamScore.toFixed(1)}
                    </TableCell>
                    <TableCell>
                      <div className="flex max-w-56 flex-wrap gap-1">
                        {log.reasons.length > 0 ? (
                          log.reasons.map((r) => <ReasonChip key={r} reason={r} />)
                        ) : (
                          <span className="text-[11px] text-zinc-400">clean</span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums text-zinc-500">
                      {log.sizeKb > 0 ? `${(log.sizeKb / 1024).toFixed(1)}M` : `${log.sizeKb}K`}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-right text-xs text-zinc-500">
                      {fmtRelative(log.createdAt)}
                    </TableCell>
                    <TableCell className="text-right">
                      {log.verdict === "quarantined" ? (
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-7 gap-1 px-2 text-xs"
                          disabled={release.isPending && release.variables === log.id}
                          onClick={() => release.mutate(log.id)}
                          aria-label={`Release message ${log.id}`}
                        >
                          {release.isPending && release.variables === log.id ? (
                            <Icons.Loader2 className="h-3 w-3 animate-spin" />
                          ) : (
                            <Icons.MailCheck className="h-3 w-3" />
                          )}
                          Release
                        </Button>
                      ) : (
                        <span className="text-[11px] text-zinc-300 dark:text-zinc-600">—</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
        {meta && meta.total > 0 && (
          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-zinc-200 px-4 py-2 dark:border-zinc-800">
            <p className="text-[11px] text-zinc-400">
              {rangeStart}–{rangeEnd} of {meta.total > rows.length ? `first ${rows.length} (matched ${meta.total})` : meta.total}
              {" · "}
              newest first
            </p>
            <div className="flex items-center gap-1">
              <Button
                variant="outline"
                size="sm"
                className="h-8 gap-1 px-3 text-xs"
                disabled={safePage <= 1}
                onClick={() => setPage(safePage - 1)}
                aria-label="Previous page"
              >
                <Icons.ChevronLeft className="h-3.5 w-3.5" /> Prev
              </Button>
              <span className="px-2 text-[11px] tabular-nums text-zinc-500">
                Page {safePage} / {pageCount}
              </span>
              <Button
                variant="outline"
                size="sm"
                className="h-8 gap-1 px-3 text-xs"
                disabled={safePage >= pageCount}
                onClick={() => setPage(safePage + 1)}
                aria-label="Next page"
              >
                Next <Icons.ChevronRight className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ── main view ───────────────────────────────────────────────────────────────

export function EmailSecurityView() {
  useEmailSecurityInvalidation();
  return (
    <div className="space-y-4">
      <StatsStrip />
      <Tabs defaultValue="gateways">
        <TabsList className="h-auto flex-wrap">
          <TabsTrigger value="gateways" className="gap-1.5">
            <Icons.Server className="h-3.5 w-3.5" /> Gateways
          </TabsTrigger>
          <TabsTrigger value="policy" className="gap-1.5">
            <Icons.Shield className="h-3.5 w-3.5" /> Policy
          </TabsTrigger>
          <TabsTrigger value="rules" className="gap-1.5">
            <Icons.Route className="h-3.5 w-3.5" /> Routing Rules
          </TabsTrigger>
          <TabsTrigger value="logs" className="gap-1.5">
            <Icons.ScrollText className="h-3.5 w-3.5" /> Mail Logs
          </TabsTrigger>
          <TabsTrigger value="test" className="gap-1.5">
            <Icons.FlaskConical className="h-3.5 w-3.5" /> Test
          </TabsTrigger>
        </TabsList>
        <TabsContent value="gateways" className="mt-4">
          <GatewaysCard />
        </TabsContent>
        <TabsContent value="policy" className="mt-4">
          <PolicyCard />
        </TabsContent>
        <TabsContent value="rules" className="mt-4">
          <RoutingRulesCard />
        </TabsContent>
        <TabsContent value="logs" className="mt-4">
          <MailLogCard />
        </TabsContent>
        <TabsContent value="test" className="mt-4">
          <TestMessageCard />
        </TabsContent>
      </Tabs>
    </div>
  );
}
