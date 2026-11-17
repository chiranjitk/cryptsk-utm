"use client";

/**
 * #/dlp — Data Loss Prevention console (Phase 3 §3.3). Tabs: Patterns
 * (regex/keyword store CRUD), Policies (protocol scope + pattern multi-select
 * + file type control + action), Incidents (alert → review → resolve
 * workflow with engine-redacted excerpts), Test Scan (manual scan card).
 * Style mirrors the M13 threat-intel views; severity palette per
 * UI_DESIGN_SYSTEM §2 (low = zinc, medium = amber, high = orange, critical =
 * rose; emerald only for the resolved status badge).
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import {
  ACTIONS,
  CATEGORIES,
  KINDS,
  PROTOCOLS,
  SEVERITIES,
  STATUSES,
  dlpApi,
  fmtDateTime,
  qs,
  type DlpAction,
  type DlpCategory,
  type DlpIncidentDTO,
  type DlpIncidentStatus,
  type DlpKind,
  type DlpPatternDTO,
  type DlpPolicyDTO,
  type DlpScanResult,
  type DlpSeverity,
  type DlpStats,
} from "./dlp-api";
import { ConfirmDialog, EmptyBlock, FieldLabel, MultiChips, PopoverMulti, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";

const DLP_KEY = ["dlp"] as const;

// ── local badges (DLP scale — mirrors ti-ui recipes) ────────────────────────

const SEVERITY_CLS: Record<DlpSeverity, string> = {
  low: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
  medium: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  high: "border-orange-500/40 bg-orange-500/10 text-orange-500",
  critical: "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium capitalize", SEVERITY_CLS[severity as DlpSeverity] ?? SEVERITY_CLS.low)}>
      {severity}
    </Badge>
  );
}

const ACTION_CLS: Record<DlpAction, string> = {
  alert: "border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300",
  block: "border-rose-500/50 bg-transparent text-rose-500",
  quarantine: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
};

function ActionBadge({ action }: { action?: string }) {
  if (!action) return <span className="text-xs text-zinc-400">—</span>;
  const Icon = action === "block" ? Icons.Ban : action === "quarantine" ? Icons.ShieldAlert : Icons.BellRing;
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium", ACTION_CLS[action as DlpAction] ?? ACTION_CLS.alert)}>
      <Icon className="h-3 w-3" />
      {action}
    </Badge>
  );
}

const STATUS_CLS: Record<DlpIncidentStatus, string> = {
  new: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  reviewing: "border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300",
  resolved: "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
  false_positive: "border-zinc-300 bg-zinc-100 text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-400",
};

function StatusBadge({ status }: { status: string }) {
  return (
    <Badge variant="outline" className={cn("font-medium", STATUS_CLS[status as DlpIncidentStatus] ?? STATUS_CLS.reviewing)}>
      {status === "false_positive" ? "false positive" : status}
    </Badge>
  );
}

function KindBadge({ kind }: { kind: string }) {
  return (
    <Badge
      variant="outline"
      className="border-zinc-300 bg-zinc-100 font-mono text-[10px] uppercase text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
    >
      {kind}
    </Badge>
  );
}

function CategoryChip({ category }: { category: string }) {
  return (
    <Badge variant="outline" className="border-zinc-500/30 bg-zinc-500/5 text-xs font-normal capitalize text-zinc-600 dark:text-zinc-300">
      {category}
    </Badge>
  );
}

function MonoChip({ children }: { children: React.ReactNode }) {
  return (
    <Badge
      variant="outline"
      className="border-zinc-300 bg-zinc-100 font-mono text-[10px] text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
    >
      {children}
    </Badge>
  );
}

/** Status/severity filter pill row (incidents tab). */
function FilterPills({
  options,
  value,
  onChange,
  label,
}: {
  options: string[];
  value: string;
  onChange: (v: string) => void;
  label: string;
}) {
  return (
    <div className="flex items-center gap-1.5" role="group" aria-label={`${label} filter`}>
      {["all", ...options].map((opt) => {
        const active = value === opt;
        return (
          <button
            key={opt}
            type="button"
            onClick={() => onChange(opt)}
            aria-pressed={active}
            className={cn(
              "rounded-full border px-2.5 py-1 text-xs capitalize transition-colors",
              active
                ? "border-zinc-500/30 bg-zinc-500/10 font-medium text-zinc-600 dark:text-zinc-300"
                : "border-zinc-200 text-zinc-500 hover:bg-zinc-100 dark:border-zinc-800 dark:text-zinc-400 dark:hover:bg-zinc-800",
            )}
          >
            {opt === "all" ? `All ${label.toLowerCase()}` : opt === "false_positive" ? "false positive" : opt}
          </button>
        );
      })}
    </div>
  );
}

// ── stats strip + 7d trend ──────────────────────────────────────────────────

function StatsStrip({ stats }: { stats: DlpStats | undefined }) {
  const maxTrend = Math.max(1, ...(stats?.trend7d ?? []).map((d) => d.count));
  const items: Array<{ label: string; value: number; icon: React.ReactNode }> = [
    { label: "Total incidents", value: stats?.totalIncidents ?? 0, icon: <Icons.FileWarning className="h-4 w-4 text-zinc-700 dark:text-zinc-500" /> },
    { label: "Open (new + reviewing)", value: stats?.openIncidents ?? 0, icon: <Icons.Inbox className="h-4 w-4 text-zinc-700 dark:text-zinc-500" /> },
    { label: "Critical incidents", value: stats?.bySeverity.critical ?? 0, icon: <Icons.Siren className="h-4 w-4 text-rose-500" /> },
    { label: "Enabled policies", value: stats?.enabledPolicies ?? 0, icon: <Icons.ShieldCheck className="h-4 w-4 text-zinc-500 dark:text-zinc-400" /> },
  ];
  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
      {items.map((it) => (
        <Card key={it.label} className="p-4">
          <CardContent className="flex items-center gap-3 p-0">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-zinc-500/10">{it.icon}</div>
            <div className="min-w-0">
              <p className="text-xl font-semibold tabular-nums">{it.value.toLocaleString()}</p>
              <p className="truncate text-[11px] text-zinc-500">{it.label}</p>
            </div>
          </CardContent>
        </Card>
      ))}
      <Card className="p-4">
        <CardContent className="p-0">
          <p className="mb-2 text-[11px] text-zinc-500">Incidents — 7 days</p>
          <div className="flex h-9 items-end gap-1" aria-label="Incident trend, last 7 days">
            {(stats?.trend7d ?? []).map((d) => (
              <div key={d.date} className="flex min-w-0 flex-1 flex-col items-center gap-0.5" title={`${d.date}: ${d.count}`}>
                <div
                  className={cn("w-full rounded-sm", d.count > 0 ? "bg-zinc-500/60" : "bg-zinc-200 dark:bg-zinc-700/60")}
                  style={{ height: `${Math.max(2, (d.count / maxTrend) * 28)}px` }}
                />
                <span className="text-[9px] text-zinc-400">{d.date.slice(5)}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ── pattern editor dialog ───────────────────────────────────────────────────

function PatternEditor(props: { initial: DlpPatternDTO | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = props.initial !== null;
  const [name, setName] = useState(props.initial?.name ?? "");
  const [kind, setKind] = useState<DlpKind>(props.initial?.kind ?? "regex");
  const [value, setValue] = useState(props.initial?.value ?? "");
  const [severity, setSeverity] = useState<DlpSeverity>(props.initial?.severity ?? "medium");
  const [category, setCategory] = useState<DlpCategory>(props.initial?.category ?? "pii");
  const [enabled, setEnabled] = useState(props.initial?.enabled ?? true);
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      isEdit ? dlpApi.updatePattern(props.initial!.id, body) : dlpApi.createPattern(body),
    onSuccess: (saved) => {
      toastOk(isEdit ? "Pattern updated" : "Pattern created", saved.name);
      void queryClient.invalidateQueries({ queryKey: DLP_KEY });
      props.onClose();
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Save failed"),
  });

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-base">{isEdit ? `Edit pattern: ${props.initial?.name}` : "Add pattern"}</DialogTitle>
          <DialogDescription>
            Regex patterns use JavaScript regex sources; keyword patterns hold a comma-separated keyword list (SPEC §3.3).
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div className="grid grid-cols-[1fr_130px] gap-4">
            <div>
              <FieldLabel>Name</FieldLabel>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="ssn-us" className="text-xs" />
            </div>
            <div>
              <FieldLabel>Kind</FieldLabel>
              <Select
                value={kind}
                onValueChange={(v) => {
                  setKind(v as DlpKind);
                  setValue("");
                }}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {KINDS.map((k) => (
                    <SelectItem key={k} value={k}>
                      {k}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div>
            <FieldLabel hint={kind === "keyword" ? "comma-separated keywords" : "regex source"}>
              {kind === "keyword" ? "Keywords" : "Pattern"}
            </FieldLabel>
            <Textarea
              value={value}
              onChange={(e) => setValue(e.target.value)}
              rows={2}
              placeholder={kind === "keyword" ? "confidential, internal use only, trade secret" : "\\b\\d{3}-\\d{2}-\\d{4}\\b"}
              className="font-mono text-xs"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel>Severity</FieldLabel>
              <Select value={severity} onValueChange={(v) => setSeverity(v as DlpSeverity)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SEVERITIES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {s}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel>Category</FieldLabel>
              <Select value={category} onValueChange={(v) => setCategory(v as DlpCategory)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CATEGORIES.map((c) => (
                    <SelectItem key={c} value={c}>
                      {c}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="flex items-center justify-between rounded-lg border border-zinc-200 px-3 py-2.5 dark:border-zinc-800">
            <div>
              <p className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Enabled</p>
              <p className="text-[11px] text-zinc-500">Disabled patterns never match in scans</p>
            </div>
            <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="Toggle pattern enabled" />
          </div>
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button
            className="bg-zinc-700 text-white hover:bg-zinc-800"
            disabled={save.isPending || !name.trim() || !value.trim()}
            onClick={() => save.mutate({ name: name.trim(), kind, value: value.trim(), severity, category, enabled })}
          >
            {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Add pattern"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── policy editor dialog ────────────────────────────────────────────────────

function PolicyEditor(props: { initial: DlpPolicyDTO | null; patterns: DlpPatternDTO[]; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = props.initial !== null;
  const [name, setName] = useState(props.initial?.name ?? "");
  const [protocols, setProtocols] = useState<string[]>(props.initial?.protocols ?? ["http", "https", "smtp", "ftp"]);
  const [patternIds, setPatternIds] = useState<number[]>(props.initial?.patternIds ?? []);
  const [fileTypesText, setFileTypesText] = useState((props.initial?.fileTypes ?? []).join(", "));
  const [action, setAction] = useState<DlpAction>(props.initial?.action ?? "alert");
  const [notifyUser, setNotifyUser] = useState(props.initial?.notifyUser ?? false);
  const [enabled, setEnabled] = useState(props.initial?.enabled ?? true);
  const [err, setErr] = useState<string | null>(null);

  const fileTypes = useMemo(
    () =>
      fileTypesText
        .split(",")
        .map((f) => f.trim().replace(/^\./, "").toLowerCase())
        .filter((f) => f.length > 0),
    [fileTypesText],
  );

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      isEdit ? dlpApi.updatePolicy(props.initial!.id, body) : dlpApi.createPolicy(body),
    onSuccess: (saved) => {
      toastOk(isEdit ? "Policy updated" : "Policy created", saved.name);
      void queryClient.invalidateQueries({ queryKey: DLP_KEY });
      props.onClose();
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Save failed"),
  });

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle className="text-base">{isEdit ? `Edit policy: ${props.initial?.name}` : "Add policy"}</DialogTitle>
          <DialogDescription>
            Scope the policy to protocols, attach patterns and optional blocked file extensions, then choose the action.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div>
            <FieldLabel>Name</FieldLabel>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="egress-dlp" className="text-xs" />
          </div>
          <div>
            <FieldLabel hint="scanned protocols">Protocols</FieldLabel>
            <PopoverMulti
              options={PROTOCOLS.map((p) => ({ id: p, label: p }))}
              selected={protocols}
              onChange={setProtocols}
              placeholder="Filter protocols…"
              triggerLabel="Protocols"
              icon={<Icons.Network className="h-4 w-4 text-zinc-500" />}
            />
          </div>
          <div>
            <FieldLabel hint={props.patterns.length === 0 ? "create patterns first" : undefined}>Patterns</FieldLabel>
            <MultiChips
              options={props.patterns.map((p) => ({ id: p.id, label: p.name }))}
              selected={patternIds}
              onToggle={(id) => setPatternIds((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]))}
              emptyLabel="no patterns attached"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel hint="comma-separated">Blocked file types</FieldLabel>
              <Input
                value={fileTypesText}
                onChange={(e) => setFileTypesText(e.target.value)}
                placeholder="pdf, docx, xlsx"
                className="text-xs"
              />
            </div>
            <div>
              <FieldLabel>Action</FieldLabel>
              <Select value={action} onValueChange={(v) => setAction(v as DlpAction)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ACTIONS.map((a) => (
                    <SelectItem key={a} value={a}>
                      {a}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid gap-3">
            <div className="flex items-center justify-between rounded-lg border border-zinc-200 px-3 py-2.5 dark:border-zinc-800">
              <div>
                <p className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Notify user</p>
                <p className="text-[11px] text-zinc-500">Block/quarantine decisions raise a user notification (SPEC §3.3)</p>
              </div>
              <Switch checked={notifyUser} onCheckedChange={setNotifyUser} aria-label="Toggle notify user" />
            </div>
            <div className="flex items-center justify-between rounded-lg border border-zinc-200 px-3 py-2.5 dark:border-zinc-800">
              <div>
                <p className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Enabled</p>
                <p className="text-[11px] text-zinc-500">Disabled policies never participate in scans</p>
              </div>
              <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="Toggle policy enabled" />
            </div>
          </div>
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button
            className="bg-zinc-700 text-white hover:bg-zinc-800"
            disabled={save.isPending || !name.trim() || protocols.length === 0}
            onClick={() =>
              save.mutate({ name: name.trim(), protocols, patternIds, fileTypes, action, notifyUser, enabled })
            }
          >
            {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Add policy"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── test scan card ──────────────────────────────────────────────────────────

function TestScanCard() {
  const queryClient = useQueryClient();
  const [text, setText] = useState("");
  const [protocol, setProtocol] = useState<string>("http");
  const [sourceIp, setSourceIp] = useState("10.0.20.15");
  const [userName, setUserName] = useState("");
  const [fileExtension, setFileExtension] = useState("");
  const [result, setResult] = useState<DlpScanResult | null>(null);

  const scan = useMutation({
    mutationFn: () =>
      dlpApi.scan({
        protocol,
        sourceIp: sourceIp.trim() || "0.0.0.0",
        userName: userName.trim() || undefined,
        text,
        fileExtension: fileExtension.trim().replace(/^\./, "") || undefined,
      }),
    onSuccess: (r) => {
      setResult(r);
      if (r.incidents > 0) {
        toastOk(`Scan created ${r.incidents} incident${r.incidents === 1 ? "" : "s"}`, `Decided severity: ${r.severity ?? "none"}`);
        void queryClient.invalidateQueries({ queryKey: DLP_KEY });
      }
    },
    onError: (e) => toastErr(e, "Scan failed"),
  });

  return (
    <Card>
      <CardContent className="p-4">
        <div className="mb-3 flex items-center gap-2">
          <Icons.FlaskConical className="h-4 w-4 text-zinc-500" />
          <h3 className="text-sm font-semibold">Test scan</h3>
          <p className="text-[11px] text-zinc-500">Runs the enabled policies for the chosen protocol against the pasted payload</p>
        </div>
        <div className="grid gap-3 lg:grid-cols-[1fr_260px]">
          <div>
            <FieldLabel hint="≤ 1 MB">Payload text</FieldLabel>
            <Textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              rows={6}
              placeholder="Paste the payload to inspect — e.g. an HTTP body or SMTP message…"
              className="font-mono text-xs"
              aria-label="Payload text"
            />
          </div>
          <div className="grid content-start gap-3">
            <div>
              <FieldLabel>Protocol</FieldLabel>
              <Select value={protocol} onValueChange={setProtocol}>
                <SelectTrigger aria-label="Scan protocol">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PROTOCOLS.map((p) => (
                    <SelectItem key={p} value={p}>
                      {p}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel>Source IP</FieldLabel>
              <Input value={sourceIp} onChange={(e) => setSourceIp(e.target.value)} className="font-mono text-xs" />
            </div>
            <div>
              <FieldLabel hint="optional">User</FieldLabel>
              <Input value={userName} onChange={(e) => setUserName(e.target.value)} className="text-xs" />
            </div>
            <div>
              <FieldLabel hint="optional">File extension</FieldLabel>
              <Input value={fileExtension} onChange={(e) => setFileExtension(e.target.value)} placeholder="pdf" className="text-xs" />
            </div>
            <Button
              className="bg-zinc-700 text-white hover:bg-zinc-800"
              disabled={scan.isPending || !text.trim()}
              onClick={() => scan.mutate()}
            >
              {scan.isPending ? <Icons.Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" aria-hidden /> : <Icons.Play className="mr-1 h-3.5 w-3.5" />}
              Run scan
            </Button>
          </div>
        </div>

        {result && (
          <div className="mt-4 rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
            <div className="mb-2 flex flex-wrap items-center gap-2 text-xs">
              <span className="font-medium text-zinc-600 dark:text-zinc-300">
                {result.incidents} incident{result.incidents === 1 ? "" : "s"} created
              </span>
              {result.severity && <SeverityBadge severity={result.severity} />}
              {result.matches.length === 0 && result.incidents === 0 && <span className="text-zinc-500">no matches</span>}
              {result.warnings.map((w) => (
                <span key={w} className="text-amber-600 dark:text-amber-400">
                  {w}
                </span>
              ))}
            </div>
            {result.matches.length > 0 && (
              <ul className="divide-y divide-zinc-100 text-xs dark:divide-zinc-800">
                {result.matches.map((m, i) => (
                  <li key={`${m.patternId}-${m.index}-${i}`} className="flex flex-wrap items-center gap-2 py-1.5">
                    <SeverityBadge severity={m.severity} />
                    <span className="font-medium">{m.policyName}</span>
                    <span className="text-zinc-400">/</span>
                    <span className="font-mono text-[11px] text-zinc-500">pattern #{m.patternId}</span>
                    <ActionBadge action={m.action} />
                    <span className="font-mono text-[11px] text-zinc-500">{m.excerpt}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ── patterns tab ────────────────────────────────────────────────────────────

function PatternsTab() {
  const queryClient = useQueryClient();
  const patternsQuery = useQuery({ queryKey: [...DLP_KEY, "patterns"], queryFn: dlpApi.listPatterns });
  const patterns = patternsQuery.data ?? [];

  const [qInput, setQInput] = useState("");
  const [q, setQ] = useState("");
  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<DlpPatternDTO | null>(null);
  const [deleting, setDeleting] = useState<DlpPatternDTO | null>(null);

  useEffect(() => {
    const t = setTimeout(() => setQ(qInput.trim().toLowerCase()), 300);
    return () => clearTimeout(t);
  }, [qInput]);

  const rows = useMemo(
    () =>
      patterns.filter(
        (p) => q === "" || p.name.toLowerCase().includes(q) || p.value.toLowerCase().includes(q),
      ),
    [patterns, q],
  );

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => dlpApi.updatePattern(id, { enabled }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: DLP_KEY }),
    onError: (e) => toastErr(e, "Toggle failed"),
  });

  const del = useMutation({
    mutationFn: (id: number) => dlpApi.deletePattern(id),
    onSuccess: () => {
      toastOk("Pattern deleted", "Referencing policies were scrubbed");
      setDeleting(null);
      void queryClient.invalidateQueries({ queryKey: DLP_KEY });
    },
    onError: (e) => toastErr(e, "Delete failed"),
  });

  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="flex flex-wrap items-center gap-2 p-4">
          <div className="relative">
            <Icons.Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-400" />
            <Input
              value={qInput}
              onChange={(e) => setQInput(e.target.value)}
              placeholder="Search name / value…"
              className="h-8 w-56 pl-8 text-xs"
              aria-label="Search patterns"
            />
          </div>
          <div className="ml-auto">
            <Button
              size="sm"
              className="h-8 bg-zinc-700 text-white hover:bg-zinc-800"
              onClick={() => {
                setEditing(null);
                setEditorOpen(true);
              }}
            >
              <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add pattern
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="p-0">
          {patternsQuery.isError ? (
            <div className="p-4">
              <QueryError error={patternsQuery.error} onRetry={() => void patternsQuery.refetch()} />
            </div>
          ) : patternsQuery.isLoading ? (
            <TableSkeleton rows={6} cols={8} />
          ) : rows.length === 0 ? (
            <EmptyBlock
              icon={<Icons.FileSearch className="h-6 w-6" />}
              title={q ? "No patterns match the search" : "No patterns yet"}
              description={
                q
                  ? "Clear the search or add a regex / keyword pattern."
                  : "Add regex patterns (SSN, credit card, IBAN…) or comma-separated keyword lists to start detecting."
              }
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead className="w-20">Kind</TableHead>
                  <TableHead>Value</TableHead>
                  <TableHead className="w-24">Severity</TableHead>
                  <TableHead className="w-28">Category</TableHead>
                  <TableHead className="w-20">Enabled</TableHead>
                  <TableHead className="w-32">Created</TableHead>
                  <TableHead className="w-20 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((p) => (
                  <TableRow key={p.id} className={p.enabled ? undefined : "opacity-60"}>
                    <TableCell className="max-w-40 truncate font-medium" title={p.name}>
                      {p.name}
                    </TableCell>
                    <TableCell>
                      <KindBadge kind={p.kind} />
                    </TableCell>
                    <TableCell className="max-w-72">
                      <span className="block truncate font-mono text-xs" title={p.value}>
                        {p.value}
                      </span>
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={p.severity} />
                    </TableCell>
                    <TableCell>
                      <CategoryChip category={p.category} />
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={p.enabled}
                        onCheckedChange={(enabled) => toggle.mutate({ id: p.id, enabled })}
                        aria-label={`Toggle pattern ${p.name}`}
                      />
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs text-zinc-500">{fmtDateTime(p.createdAt)}</TableCell>
                    <TableCell>
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-300"
                          aria-label={`Edit pattern ${p.name}`}
                          onClick={() => {
                            setEditing(p);
                            setEditorOpen(true);
                          }}
                        >
                          <Icons.Pencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-rose-500 hover:text-rose-600"
                          aria-label={`Delete pattern ${p.name}`}
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
          )}
        </CardContent>
      </Card>

      {editorOpen && <PatternEditor initial={editing} onClose={() => setEditorOpen(false)} />}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete pattern ${deleting?.name ?? ""}?`}
        description="The pattern stops matching in scans. Policies referencing it are scrubbed of the id."
        loading={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting.id)}
      />
    </div>
  );
}

// ── policies tab ────────────────────────────────────────────────────────────

function PoliciesTab() {
  const queryClient = useQueryClient();
  const policiesQuery = useQuery({ queryKey: [...DLP_KEY, "policies"], queryFn: dlpApi.listPolicies });
  const patternsQuery = useQuery({ queryKey: [...DLP_KEY, "patterns"], queryFn: dlpApi.listPatterns });
  const policies = policiesQuery.data ?? [];
  const patterns = patternsQuery.data ?? [];

  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<DlpPolicyDTO | null>(null);
  const [deleting, setDeleting] = useState<DlpPolicyDTO | null>(null);

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => dlpApi.updatePolicy(id, { enabled }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: DLP_KEY }),
    onError: (e) => toastErr(e, "Toggle failed"),
  });

  const del = useMutation({
    mutationFn: (id: number) => dlpApi.deletePolicy(id),
    onSuccess: () => {
      toastOk("Policy deleted", "Past incidents are kept as history");
      setDeleting(null);
      void queryClient.invalidateQueries({ queryKey: DLP_KEY });
    },
    onError: (e) => toastErr(e, "Delete failed"),
  });

  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="flex flex-wrap items-center gap-2 p-4">
          <p className="text-xs text-zinc-500">
            {patterns.length} pattern{patterns.length === 1 ? "" : "s"} available for attachment
          </p>
          <div className="ml-auto">
            <Button
              size="sm"
              className="h-8 bg-zinc-700 text-white hover:bg-zinc-800"
              onClick={() => {
                setEditing(null);
                setEditorOpen(true);
              }}
            >
              <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add policy
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="p-0">
          {policiesQuery.isError ? (
            <div className="p-4">
              <QueryError error={policiesQuery.error} onRetry={() => void policiesQuery.refetch()} />
            </div>
          ) : policiesQuery.isLoading ? (
            <TableSkeleton rows={4} cols={7} />
          ) : policies.length === 0 ? (
            <EmptyBlock
              icon={<Icons.ShieldAlert className="h-6 w-6" />}
              title="No policies yet"
              description="Create a policy to scope patterns to protocols, block file types and set the action."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Protocols</TableHead>
                  <TableHead>Patterns</TableHead>
                  <TableHead>File types</TableHead>
                  <TableHead className="w-28">Action</TableHead>
                  <TableHead className="w-14">Notify</TableHead>
                  <TableHead className="w-20">Enabled</TableHead>
                  <TableHead className="w-20 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {policies.map((p) => (
                  <TableRow key={p.id} className={p.enabled ? undefined : "opacity-60"}>
                    <TableCell className="max-w-40 truncate font-medium" title={p.name}>
                      {p.name}
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {p.protocols.length === 0 ? <span className="text-xs text-zinc-400">—</span> : p.protocols.map((pr) => <MonoChip key={pr}>{pr}</MonoChip>)}
                      </div>
                    </TableCell>
                    <TableCell className="max-w-56">
                      {p.patternIds.length === 0 ? (
                        <span className="text-xs text-zinc-400">none</span>
                      ) : (
                        <div className="flex flex-wrap gap-1" title={p.patternIds.map((id) => p.patternNames[id] ?? `#${id}`).join(", ")}>
                          {p.patternIds.slice(0, 3).map((id) => (
                            <MonoChip key={id}>{p.patternNames[id] ?? `#${id}`}</MonoChip>
                          ))}
                          {p.patternIds.length > 3 && <MonoChip>+{p.patternIds.length - 3}</MonoChip>}
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="max-w-40">
                      {p.fileTypes.length === 0 ? (
                        <span className="text-xs text-zinc-400">—</span>
                      ) : (
                        <div className="flex flex-wrap gap-1">
                          {p.fileTypes.slice(0, 4).map((f) => (
                            <MonoChip key={f}>.{f}</MonoChip>
                          ))}
                          {p.fileTypes.length > 4 && <MonoChip>+{p.fileTypes.length - 4}</MonoChip>}
                        </div>
                      )}
                    </TableCell>
                    <TableCell>
                      <ActionBadge action={p.action} />
                    </TableCell>
                    <TableCell>
                      {p.notifyUser ? (
                        <Icons.BellRing className="h-3.5 w-3.5 text-zinc-500" aria-label="User notification on" />
                      ) : (
                        <Icons.BellOff className="h-3.5 w-3.5 text-zinc-300 dark:text-zinc-600" aria-label="User notification off" />
                      )}
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={p.enabled}
                        onCheckedChange={(enabled) => toggle.mutate({ id: p.id, enabled })}
                        aria-label={`Toggle policy ${p.name}`}
                      />
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-300"
                          aria-label={`Edit policy ${p.name}`}
                          onClick={() => {
                            setEditing(p);
                            setEditorOpen(true);
                          }}
                        >
                          <Icons.Pencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-rose-500 hover:text-rose-600"
                          aria-label={`Delete policy ${p.name}`}
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
          )}
        </CardContent>
      </Card>

      {editorOpen && <PolicyEditor initial={editing} patterns={patterns} onClose={() => setEditorOpen(false)} />}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete policy ${deleting?.name ?? ""}?`}
        description="Scans stop applying this policy. Historical incidents are preserved."
        loading={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting.id)}
      />
    </div>
  );
}

// ── incidents tab ───────────────────────────────────────────────────────────

function IncidentsTab() {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<string>("all");
  const [severity, setSeverity] = useState<string>("all");
  const [qInput, setQInput] = useState("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);

  useEffect(() => {
    const t = setTimeout(() => {
      setQ(qInput.trim());
      setPage(1);
    }, 350);
    return () => clearTimeout(t);
  }, [qInput]);

  const params = useMemo(
    () =>
      qs({
        status: status === "all" ? undefined : status,
        severity: severity === "all" ? undefined : severity,
        q,
        page,
        limit: 25,
      }),
    [status, severity, q, page],
  );

  const incidentsQuery = useQuery({
    queryKey: [...DLP_KEY, "incidents", params],
    queryFn: () => dlpApi.listIncidents(params),
  });
  const meta = incidentsQuery.data?.meta;
  const rows = incidentsQuery.data?.data ?? [];
  const hasFilters = status !== "all" || severity !== "all" || q !== "";

  const setStatusMut = useMutation({
    mutationFn: ({ id, next }: { id: number; next: DlpIncidentStatus }) => dlpApi.setIncidentStatus(id, next),
    onSuccess: (updated) => {
      toastOk(`Incident #${updated.id} → ${updated.status === "false_positive" ? "false positive" : updated.status}`);
      void queryClient.invalidateQueries({ queryKey: DLP_KEY });
    },
    onError: (e) => toastErr(e, "Status update failed"),
  });

  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="flex flex-wrap items-center gap-3 p-4">
          <FilterPills
            label="status"
            options={STATUSES}
            value={status}
            onChange={(v) => {
              setPage(1);
              setStatus(v);
            }}
          />
          <FilterPills
            label="severities"
            options={SEVERITIES}
            value={severity}
            onChange={(v) => {
              setPage(1);
              setSeverity(v);
            }}
          />
          <div className="relative">
            <Icons.Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-400" />
            <Input
              value={qInput}
              onChange={(e) => setQInput(e.target.value)}
              placeholder="Search source IP / user / excerpt…"
              className="h-8 w-64 pl-8 text-xs"
              aria-label="Search incidents"
            />
          </div>
          {hasFilters && (
            <Button
              variant="ghost"
              size="sm"
              className="h-8 gap-1 text-xs"
              onClick={() => {
                setStatus("all");
                setSeverity("all");
                setQInput("");
                setPage(1);
              }}
            >
              <Icons.X className="h-3.5 w-3.5" /> Clear
            </Button>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardContent className="p-0">
          {incidentsQuery.isError ? (
            <div className="p-4">
              <QueryError error={incidentsQuery.error} onRetry={() => void incidentsQuery.refetch()} />
            </div>
          ) : incidentsQuery.isLoading ? (
            <TableSkeleton rows={8} cols={9} />
          ) : rows.length === 0 ? (
            <EmptyBlock
              icon={<Icons.ShieldCheck className="h-6 w-6" />}
              title={hasFilters ? "No incidents match the current filters" : "No incidents yet"}
              description={
                hasFilters
                  ? "Clear filters or run a test scan to generate incidents."
                  : "Run a scan (policy engine or the Test Scan tab) to detect sensitive data leaving the network."
              }
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-32">Time</TableHead>
                  <TableHead className="w-24">Severity</TableHead>
                  <TableHead>Pattern</TableHead>
                  <TableHead className="w-20">Proto</TableHead>
                  <TableHead className="w-28">Action</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead className="max-w-56">Excerpt (redacted)</TableHead>
                  <TableHead className="w-36">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((inc: DlpIncidentDTO) => (
                  <TableRow key={inc.id}>
                    <TableCell className="whitespace-nowrap text-xs text-zinc-500">{fmtDateTime(inc.createdAt)}</TableCell>
                    <TableCell>
                      <SeverityBadge severity={inc.severity} />
                    </TableCell>
                    <TableCell className="max-w-40">
                      <span className="block truncate text-xs font-medium" title={inc.patternName ?? `#${inc.patternId}`}>
                        {inc.patternName ?? `#${inc.patternId}`}
                      </span>
                    </TableCell>
                    <TableCell>
                      <MonoChip>{inc.protocol}</MonoChip>
                    </TableCell>
                    <TableCell>
                      <ActionBadge action={inc.detail.action} />
                      {inc.detail.fileTypeBlocked && (
                        <span className="ml-1 text-[10px] text-zinc-400" title="File extension matched the policy block list">
                          file type
                        </span>
                      )}
                    </TableCell>
                    <TableCell>
                      <span className="block font-mono text-xs" title={inc.sourceIp}>
                        {inc.sourceIp}
                      </span>
                      {inc.userName && <span className="text-[10px] text-zinc-400">{inc.userName}</span>}
                    </TableCell>
                    <TableCell className="max-w-56">
                      <span className="block truncate font-mono text-[11px] text-zinc-500" title={inc.excerpt}>
                        {inc.excerpt || "—"}
                      </span>
                    </TableCell>
                    <TableCell>
                      <Select
                        value={inc.status}
                        onValueChange={(next) => setStatusMut.mutate({ id: inc.id, next: next as DlpIncidentStatus })}
                      >
                        <SelectTrigger className="h-7 w-32 text-xs" aria-label={`Status of incident ${inc.id}`}>
                          <StatusBadge status={inc.status} />
                        </SelectTrigger>
                        <SelectContent>
                          {STATUSES.map((s) => (
                            <SelectItem key={s} value={s}>
                              {s === "false_positive" ? "false positive" : s}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}

          {meta && meta.total > 0 && (
            <div className="flex flex-wrap items-center justify-between gap-2 border-t border-zinc-200 px-4 py-2.5 text-xs text-zinc-500 dark:border-zinc-800">
              <span>
                page {meta.page} of {meta.totalPages} · {meta.total} incident{meta.total === 1 ? "" : "s"}
              </span>
              <div className="flex items-center gap-1.5">
                <Button variant="outline" size="sm" className="h-7" disabled={meta.page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>
                  <Icons.ChevronLeft className="h-3.5 w-3.5" /> Prev
                </Button>
                <Button variant="outline" size="sm" className="h-7" disabled={meta.page >= meta.totalPages} onClick={() => setPage((p) => p + 1)}>
                  Next <Icons.ChevronRight className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ── main view ───────────────────────────────────────────────────────────────

export function DlpView() {
  const statsQuery = useQuery({ queryKey: [...DLP_KEY, "stats"], queryFn: dlpApi.getStats });

  return (
    <div className="space-y-4">
      <StatsStrip stats={statsQuery.data} />

      <Tabs defaultValue="patterns" className="gap-4">
        <TabsList className="bg-zinc-100 dark:bg-zinc-800/60">
          <TabsTrigger value="patterns" className="gap-1.5">
            <Icons.FileSearch className="h-3.5 w-3.5" /> Patterns
          </TabsTrigger>
          <TabsTrigger value="policies" className="gap-1.5">
            <Icons.ShieldAlert className="h-3.5 w-3.5" /> Policies
          </TabsTrigger>
          <TabsTrigger value="incidents" className="gap-1.5">
            <Icons.FileWarning className="h-3.5 w-3.5" /> Incidents
          </TabsTrigger>
          <TabsTrigger value="scan" className="gap-1.5">
            <Icons.FlaskConical className="h-3.5 w-3.5" /> Test Scan
          </TabsTrigger>
        </TabsList>
        <TabsContent value="patterns">
          <PatternsTab />
        </TabsContent>
        <TabsContent value="policies">
          <PoliciesTab />
        </TabsContent>
        <TabsContent value="incidents">
          <IncidentsTab />
        </TabsContent>
        <TabsContent value="scan">
          <TestScanCard />
        </TabsContent>
      </Tabs>
    </div>
  );
}
