"use client";

/**
 * Compliance & Reporting view (M12 spec 2.13) — hash #/logs/compliance.
 * Top: 5 framework cards (PCI/HIPAA/GDPR/ISO27001/SOC2) with CSS
 * conic-gradient pass-rate rings (blue palette) fed by the latest compliance
 * run per framework. Middle: compliance templates table (Run now, edit,
 * delete) and report runs table (source/status badges, view → rendered
 * contentHtml dialog, delete) + "New report" dialog. Bottom: anonymization
 * rules card with add/edit dialog and a before/after preview.
 * Theme per ADR-019: white & enterprise blue.
 */

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  ConfirmDialog,
  EmptyBlock,
  FieldLabel,
  MultiChips,
  QueryError,
  TableSkeleton,
  toastErr,
  toastOk,
} from "../firewall/fw-ui";
import { cn } from "@/lib/utils";
import {
  fieldErrorsOf,
  qs,
  searchApi,
  type AnonymizationRuleDTO,
  type AnonPreview,
  type ComplianceTemplateDTO,
  type ReportRunListItem,
} from "./search-api";

// ── constants ───────────────────────────────────────────────────────────────

const FRAMEWORKS = ["PCI", "HIPAA", "GDPR", "ISO27001", "SOC2"] as const;
type Framework = (typeof FRAMEWORKS)[number];

const RANGES = ["daily", "weekly", "monthly", "quarterly"] as const;
const SECTION_OPTIONS = [
  { id: 1, label: "traffic" },
  { id: 2, label: "threats" },
  { id: 3, label: "audit" },
];
const SECTION_BY_ID: Record<number, "traffic" | "threats" | "audit"> = { 1: "traffic", 2: "threats", 3: "audit" };
const ID_BY_SECTION: Record<string, number> = { traffic: 1, threats: 2, audit: 3 };

const SOURCE_BADGE: Record<string, string> = {
  "ad-hoc": "border-zinc-300 text-zinc-500 dark:border-zinc-700",
  schedule: "border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400",
  compliance: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
};

const STATUS_BADGE: Record<string, string> = {
  done: "border-transparent bg-blue-600 text-white",
  failed: "border-transparent bg-rose-600 text-white",
  pending: "border-zinc-300 text-zinc-500 dark:border-zinc-700",
  running: "border-zinc-300 text-zinc-500 dark:border-zinc-700",
};

const STRATEGY_BADGE: Record<string, string> = {
  hash: "border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400",
  mask: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  pseudonymize: "border-zinc-300 text-zinc-600 dark:border-zinc-700 dark:text-zinc-300",
};

const FRAMEWORK_HINT: Record<Framework, string> = {
  PCI: "Cardholder-data environment logging",
  HIPAA: "PHI access auditing",
  GDPR: "Personal-data minimization",
  ISO27001: "ISMS event logging",
  SOC2: "Trust-services audit trail",
};

const ANON_DATASETS = ["firewall", "ips", "audit", "dns", "email", "waf"] as const;
const ANON_FIELDS = ["source_ip", "user_name", "url", "email"] as const;

const PREVIEW_COLUMNS: Record<string, string[]> = {
  firewall: ["id", "ts", "srcIp", "dstIp", "protocol", "action", "userName"],
  ips: ["id", "ts", "srcIp", "dstIp", "severity", "category"],
  audit: ["id", "ts", "username", "sourceIp", "action", "objectType"],
};

function fmtTs(ts: string | null): string {
  if (!ts) return "—";
  return new Date(ts).toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** Simple CSS conic-gradient ring (no chart lib needed) — pct -1 = no data. */
function PassRing({ pct }: { pct: number }) {
  const noData = pct < 0;
  return (
    <div className="relative h-16 w-16 shrink-0" role="img" aria-label={noData ? "No runs yet" : `${pct}% pass rate`}>
      <div
        className="h-full w-full rounded-full"
        style={{ background: noData ? "#e4e4e7" : `conic-gradient(#2563eb ${pct}%, #e4e4e7 0)` }}
      />
      <div className="absolute inset-[6px] flex items-center justify-center rounded-full bg-white dark:bg-zinc-950">
        <span className={cn("text-xs font-semibold", noData ? "text-zinc-400" : "text-blue-600 dark:text-blue-400")}>
          {noData ? "n/a" : `${pct}%`}
        </span>
      </div>
    </div>
  );
}

function StringChips({
  options,
  selected,
  onToggle,
}: {
  options: readonly string[];
  selected: string[];
  onToggle: (v: string) => void;
}) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {options.map((o) => {
        const active = selected.includes(o);
        return (
          <button
            key={o}
            type="button"
            aria-pressed={active}
            onClick={() => onToggle(o)}
            className={cn(
              "rounded-full border px-2.5 py-1 text-xs transition-colors",
              active
                ? "border-blue-500/40 bg-blue-500/10 font-medium text-blue-600 dark:text-blue-400"
                : "border-zinc-200 text-zinc-500 hover:bg-zinc-100 dark:border-zinc-800 dark:text-zinc-400 dark:hover:bg-zinc-800",
            )}
          >
            {o}
          </button>
        );
      })}
    </div>
  );
}

// ── view ────────────────────────────────────────────────────────────────────

export function ComplianceView() {
  const queryClient = useQueryClient();
  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ["m12"] });

  const templatesQuery = useQuery({ queryKey: ["m12", "templates"], queryFn: searchApi.listTemplates });
  const runsQuery = useQuery({
    queryKey: ["m12", "runs", ""],
    queryFn: () => searchApi.listRuns(qs({ limit: 100 })),
  });
  const rulesQuery = useQuery({ queryKey: ["m12", "anon"], queryFn: searchApi.listAnonRules });

  const templates = templatesQuery.data ?? [];
  const runs = runsQuery.data?.data ?? [];
  const rules = rulesQuery.data ?? [];

  const complianceRuns = useMemo(() => runs.filter((r) => r.source === "compliance"), [runs]);
  const fwStats = useMemo(() => {
    const m = new Map<Framework, { passRate: number; runs: number }>();
    for (const fw of FRAMEWORKS) {
      const list = complianceRuns.filter((r) => r.summary?.framework === fw);
      m.set(fw, { passRate: list.length > 0 ? (list[0]?.summary?.passRate ?? -1) : -1, runs: list.length });
    }
    return m;
  }, [complianceRuns]);

  // ── run compliance from a template ──
  const runTemplateMut = useMutation({
    mutationFn: (templateId: number) => searchApi.runCompliance(templateId),
    onSuccess: (run) => {
      toastOk("Compliance check complete", `${run.name} — pass rate ${run.summary?.passRate ?? 0}%`);
      invalidate();
    },
    onError: (err) => toastErr(err, "Compliance run failed"),
  });

  const runFramework = (fw: Framework) => {
    const tpl = templates.find((t) => t.framework === fw && t.enabled) ?? templates.find((t) => t.framework === fw);
    if (tpl) runTemplateMut.mutate(tpl.id);
  };

  // ── template editor ──
  const [tplOpen, setTplOpen] = useState(false);
  const [editingTpl, setEditingTpl] = useState<ComplianceTemplateDTO | null>(null);
  const [tplForm, setTplForm] = useState({ name: "", framework: "PCI", range: "monthly", sections: ["traffic", "threats", "audit"] as string[], enabled: true });
  const [tplErr, setTplErr] = useState<Record<string, string[]>>({});
  const openTplEditor = (t: ComplianceTemplateDTO | null) => {
    setEditingTpl(t);
    setTplErr({});
    setTplForm(
      t
        ? { name: t.name, framework: t.framework, range: t.range, sections: t.sections, enabled: t.enabled }
        : { name: "", framework: "PCI", range: "monthly", sections: ["traffic", "threats", "audit"], enabled: true },
    );
    setTplOpen(true);
  };
  const saveTplMut = useMutation({
    mutationFn: () => {
      const body = { ...tplForm, name: tplForm.name.trim() };
      return editingTpl ? searchApi.updateTemplate(editingTpl.id, body) : searchApi.createTemplate(body);
    },
    onSuccess: (t) => {
      toastOk(editingTpl ? "Template updated" : "Template created", t.name);
      setTplOpen(false);
      invalidate();
    },
    onError: (err) => {
      const fe = fieldErrorsOf(err);
      setTplErr(fe);
      if (!Object.keys(fe).length) toastErr(err, "Save failed");
    },
  });
  const toggleTplMut = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => searchApi.updateTemplate(id, { enabled }),
    onSuccess: invalidate,
    onError: (err) => toastErr(err, "Update failed"),
  });
  const [deletingTpl, setDeletingTpl] = useState<ComplianceTemplateDTO | null>(null);
  const delTplMut = useMutation({
    mutationFn: (id: number) => searchApi.deleteTemplate(id),
    onSuccess: () => {
      toastOk("Template deleted");
      setDeletingTpl(null);
      invalidate();
    },
    onError: (err) => toastErr(err, "Delete failed"),
  });

  // ── new (ad-hoc) report dialog ──
  const [newOpen, setNewOpen] = useState(false);
  const [newForm, setNewForm] = useState({ name: "", range: "daily", sections: ["traffic", "threats"] as string[], format: "pdf" });
  const [newErr, setNewErr] = useState<Record<string, string[]>>({});
  const newRunMut = useMutation({
    mutationFn: () => {
      const body = { ...newForm, name: newForm.name.trim(), sections: newForm.sections };
      return searchApi.createRun(body);
    },
    onSuccess: (run) => {
      toastOk("Report generated", `${run.name} (${run.format.toUpperCase()}) is ready — open it from the runs table`);
      setNewOpen(false);
      setNewForm({ name: "", range: "daily", sections: ["traffic", "threats"], format: "pdf" });
      setNewErr({});
      invalidate();
    },
    onError: (err) => {
      const fe = fieldErrorsOf(err);
      setNewErr(fe);
      if (!Object.keys(fe).length) toastErr(err, "Report generation failed");
    },
  });

  // ── view run dialog (contentHtml) ──
  const [viewingId, setViewingId] = useState<number | null>(null);
  const runDetail = useQuery({
    queryKey: ["m12", "run", viewingId],
    queryFn: () => searchApi.getRun(viewingId as number),
    enabled: viewingId != null,
  });
  const viewing = runDetail.data;
  const pdfHint = viewing?.format === "pdf" || (viewing?.summary?.meta?.pdfViaPrint ?? false);

  const [deletingRun, setDeletingRun] = useState<ReportRunListItem | null>(null);
  const delRunMut = useMutation({
    mutationFn: (id: number) => searchApi.deleteRun(id),
    onSuccess: () => {
      toastOk("Report run deleted");
      setDeletingRun(null);
      invalidate();
    },
    onError: (err) => toastErr(err, "Delete failed"),
  });

  // ── anonymization rules ──
  const [ruleOpen, setRuleOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<AnonymizationRuleDTO | null>(null);
  const [ruleForm, setRuleForm] = useState({ name: "", dataset: "firewall", field: "source_ip", strategy: "mask", enabled: true });
  const [ruleErr, setRuleErr] = useState<Record<string, string[]>>({});
  const openRuleEditor = (r: AnonymizationRuleDTO | null) => {
    setEditingRule(r);
    setRuleErr({});
    setRuleForm(
      r
        ? { name: r.name, dataset: r.dataset, field: r.field, strategy: r.strategy, enabled: r.enabled }
        : { name: "", dataset: "firewall", field: "source_ip", strategy: "mask", enabled: true },
    );
    setRuleOpen(true);
  };
  const saveRuleMut = useMutation({
    mutationFn: () => {
      const body = { ...ruleForm, name: ruleForm.name.trim() };
      return editingRule ? searchApi.updateAnonRule(editingRule.id, body) : searchApi.createAnonRule(body);
    },
    onSuccess: (r) => {
      toastOk(editingRule ? "Rule updated" : "Rule created", r.name);
      setRuleOpen(false);
      invalidate();
    },
    onError: (err) => {
      const fe = fieldErrorsOf(err);
      setRuleErr(fe);
      if (!Object.keys(fe).length) toastErr(err, "Save failed");
    },
  });
  const toggleRuleMut = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => searchApi.updateAnonRule(id, { enabled }),
    onSuccess: invalidate,
    onError: (err) => toastErr(err, "Update failed"),
  });
  const [deletingRule, setDeletingRule] = useState<AnonymizationRuleDTO | null>(null);
  const delRuleMut = useMutation({
    mutationFn: (id: number) => searchApi.deleteAnonRule(id),
    onSuccess: () => {
      toastOk("Rule deleted");
      setDeletingRule(null);
      invalidate();
    },
    onError: (err) => toastErr(err, "Delete failed"),
  });

  // ── anonymization preview dialog ──
  const [previewOpen, setPreviewOpen] = useState(false);
  const [previewDataset, setPreviewDataset] = useState("firewall");
  const previewQuery = useQuery({
    queryKey: ["m12", "anon-preview", previewDataset],
    queryFn: () => searchApi.anonPreview(previewDataset),
    enabled: previewOpen,
  });
  const preview: AnonPreview | null = previewQuery.data ?? null;

  return (
    <div className="space-y-4">
      <p className="text-xs text-zinc-500">
        Compliance templates render point-in-time reports with per-framework control checklists computed from live log data; ad-hoc reports roll up traffic, threats and audit sections. Anonymization rules shape what leaves the building.
      </p>

      {/* ── framework cards ── */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-5">
        {FRAMEWORKS.map((fw) => {
          const stat = fwStats.get(fw) ?? { passRate: -1, runs: 0 };
          return (
            <Card key={fw} className="gap-0 py-0">
              <CardContent className="flex items-center gap-3 p-4">
                <PassRing pct={stat.passRate} />
                <div className="min-w-0">
                  <p className="text-sm font-semibold">{fw}</p>
                  <p className="truncate text-[11px] text-zinc-500">{FRAMEWORK_HINT[fw]}</p>
                  <p className="mt-0.5 text-[11px] text-zinc-400">
                    {stat.runs} run{stat.runs === 1 ? "" : "s"}
                  </p>
                  <Button
                    variant="outline"
                    size="sm"
                    className="mt-1.5 h-7 gap-1 px-2 text-[11px]"
                    disabled={runTemplateMut.isPending || templates.length === 0}
                    onClick={() => runFramework(fw)}
                  >
                    <Icons.Play className="h-3 w-3" />
                    Run check
                  </Button>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* ── templates table ── */}
      <Card>
        <CardHeader className="flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="flex items-center gap-1.5 text-sm">
            <Icons.FileCheck className="h-4 w-4 text-blue-600 dark:text-blue-400" />
            Compliance templates
          </CardTitle>
          <Button size="sm" variant="outline" className="h-8 gap-1.5" onClick={() => openTplEditor(null)}>
            <Icons.Plus className="h-3.5 w-3.5" />
            New template
          </Button>
        </CardHeader>
        <CardContent className="p-0">
          {templatesQuery.isLoading ? (
            <TableSkeleton rows={4} cols={7} />
          ) : templatesQuery.isError ? (
            <QueryError error={templatesQuery.error} onRetry={() => void templatesQuery.refetch()} />
          ) : templates.length === 0 ? (
            <EmptyBlock icon={<Icons.FileCheck className="h-6 w-6" />} title="No templates" description="Create a template to run framework checklists on a schedule-like cadence." />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Framework</TableHead>
                  <TableHead>Range</TableHead>
                  <TableHead>Sections</TableHead>
                  <TableHead>Enabled</TableHead>
                  <TableHead>Last run</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {templates.map((t) => (
                  <TableRow key={t.id}>
                    <TableCell className="max-w-48 truncate text-xs font-medium">{t.name}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="border-blue-500/40 bg-blue-500/10 font-semibold text-blue-600 dark:text-blue-400">
                        {t.framework}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs capitalize">{t.range}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {t.sections.map((s) => (
                          <Badge key={s} variant="outline" className="border-zinc-300 px-1.5 text-[10px] text-zinc-500 dark:border-zinc-700">
                            {s}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={t.enabled}
                        onCheckedChange={(enabled) => toggleTplMut.mutate({ id: t.id, enabled })}
                        aria-label={`Toggle ${t.name}`}
                      />
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs text-zinc-500">{fmtTs(t.lastRunAt)}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-0.5">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8 text-blue-600 dark:text-blue-400"
                          aria-label={`Run ${t.name}`}
                          disabled={runTemplateMut.isPending}
                          onClick={() => runTemplateMut.mutate(t.id)}
                        >
                          {runTemplateMut.isPending ? <Icons.Loader2 className="h-4 w-4 animate-spin" /> : <Icons.Play className="h-4 w-4" />}
                        </Button>
                        <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={`Edit ${t.name}`} onClick={() => openTplEditor(t)}>
                          <Icons.Pencil className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8 text-zinc-400 hover:text-rose-600"
                          aria-label={`Delete ${t.name}`}
                          onClick={() => setDeletingTpl(t)}
                        >
                          <Icons.Trash2 className="h-4 w-4" />
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

      {/* ── runs table ── */}
      <Card>
        <CardHeader className="flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="flex items-center gap-1.5 text-sm">
            <Icons.FileBarChart className="h-4 w-4 text-blue-600 dark:text-blue-400" />
            Report runs
            <Badge variant="outline" className="ml-1 border-blue-500/40 bg-blue-500/10 px-1.5 text-[10px] text-blue-600 dark:text-blue-400">
              {runs.length}
            </Badge>
          </CardTitle>
          <Button
            size="sm"
            className="h-8 gap-1.5 bg-blue-600 text-white hover:bg-blue-700"
            onClick={() => {
              setNewErr({});
              setNewOpen(true);
            }}
          >
            <Icons.Plus className="h-3.5 w-3.5" />
            New report
          </Button>
        </CardHeader>
        <CardContent className="p-0">
          {runsQuery.isLoading ? (
            <TableSkeleton rows={5} cols={6} />
          ) : runsQuery.isError ? (
            <QueryError error={runsQuery.error} onRetry={() => void runsQuery.refetch()} />
          ) : runs.length === 0 ? (
            <EmptyBlock
              icon={<Icons.FileBarChart className="h-6 w-6" />}
              title="No report runs yet"
              description="Run a compliance template or create an ad-hoc report — the rendered document opens right here."
              action={
                <Button size="sm" className="bg-blue-600 text-white hover:bg-blue-700" onClick={() => setNewOpen(true)}>
                  New report
                </Button>
              }
            />
          ) : (
            <div className="max-h-96 overflow-y-auto">
              <Table>
                <TableHeader className="sticky top-0 bg-card">
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="hidden md:table-cell">Range</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {runs.map((r) => (
                    <TableRow key={r.id}>
                      <TableCell className="max-w-56 truncate text-xs font-medium">{r.name}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className={cn("font-medium", SOURCE_BADGE[r.source] ?? SOURCE_BADGE["ad-hoc"])}>
                          {r.source}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={cn("font-medium capitalize", STATUS_BADGE[r.status] ?? STATUS_BADGE.pending)}>
                          {r.status}
                        </Badge>
                        {r.summary?.passRate !== undefined ? (
                          <span className="ml-1.5 text-[10px] text-zinc-400">{r.summary.passRate}%</span>
                        ) : null}
                      </TableCell>
                      <TableCell className="hidden text-xs capitalize text-zinc-500 md:table-cell">{r.range}</TableCell>
                      <TableCell className="whitespace-nowrap text-xs text-zinc-500">{fmtTs(r.createdAt)}</TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-0.5">
                          <Button variant="ghost" size="icon" className="h-8 w-8 text-blue-600 dark:text-blue-400" aria-label={`View ${r.name}`} onClick={() => setViewingId(r.id)}>
                            <Icons.Eye className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8 text-zinc-400 hover:text-rose-600"
                            aria-label={`Delete ${r.name}`}
                            onClick={() => setDeletingRun(r)}
                          >
                            <Icons.Trash2 className="h-4 w-4" />
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
      </Card>

      {/* ── anonymization card ── */}
      <Card>
        <CardHeader className="flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="flex items-center gap-1.5 text-sm">
            <Icons.EyeOff className="h-4 w-4 text-blue-600 dark:text-blue-400" />
            Anonymization rules
          </CardTitle>
          <div className="flex gap-1.5">
            <Button
              size="sm"
              variant="outline"
              className="h-8 gap-1.5"
              onClick={() => {
                setPreviewDataset("firewall");
                setPreviewOpen(true);
              }}
            >
              <Icons.Search className="h-3.5 w-3.5" />
              Preview
            </Button>
            <Button size="sm" className="h-8 gap-1.5 bg-blue-600 text-white hover:bg-blue-700" onClick={() => openRuleEditor(null)}>
              <Icons.Plus className="h-3.5 w-3.5" />
              Add rule
            </Button>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {rulesQuery.isLoading ? (
            <TableSkeleton rows={3} cols={6} />
          ) : rulesQuery.isError ? (
            <QueryError error={rulesQuery.error} onRetry={() => void rulesQuery.refetch()} />
          ) : rules.length === 0 ? (
            <EmptyBlock icon={<Icons.EyeOff className="h-6 w-6" />} title="No anonymization rules" description="Hash, mask or pseudonymize sensitive fields before exports leave the console." />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Dataset</TableHead>
                  <TableHead>Field</TableHead>
                  <TableHead>Strategy</TableHead>
                  <TableHead>Enabled</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rules.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell className="max-w-48 truncate text-xs font-medium">{r.name}</TableCell>
                    <TableCell className="text-xs capitalize">{r.dataset}</TableCell>
                    <TableCell className="font-mono text-xs text-zinc-500">{r.field}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className={cn("font-medium", STRATEGY_BADGE[r.strategy] ?? STRATEGY_BADGE.hash)}>
                        {r.strategy}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={r.enabled}
                        onCheckedChange={(enabled) => toggleRuleMut.mutate({ id: r.id, enabled })}
                        aria-label={`Toggle ${r.name}`}
                      />
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-0.5">
                        <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={`Edit ${r.name}`} onClick={() => openRuleEditor(r)}>
                          <Icons.Pencil className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8 text-zinc-400 hover:text-rose-600"
                          aria-label={`Delete ${r.name}`}
                          onClick={() => setDeletingRule(r)}
                        >
                          <Icons.Trash2 className="h-4 w-4" />
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

      {/* ── template editor dialog ── */}
      <Dialog open={tplOpen} onOpenChange={setTplOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{editingTpl ? "Edit template" : "New compliance template"}</DialogTitle>
            <DialogDescription>Templates bundle a framework checklist with the report sections to roll up.</DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <FieldLabel hint="required · unique">Name</FieldLabel>
              <Input value={tplForm.name} onChange={(e) => setTplForm({ ...tplForm, name: e.target.value })} placeholder="e.g. PCI-DSS v4 monthly review" />
              {tplErr.name?.[0] ? <p className="mt-1 text-xs text-rose-600">{tplErr.name[0]}</p> : null}
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <FieldLabel>Framework</FieldLabel>
                <Select value={tplForm.framework} onValueChange={(framework) => setTplForm({ ...tplForm, framework })}>
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {FRAMEWORKS.map((f) => (
                      <SelectItem key={f} value={f}>
                        {f}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <FieldLabel>Range</FieldLabel>
                <Select value={tplForm.range} onValueChange={(range) => setTplForm({ ...tplForm, range })}>
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {RANGES.map((r) => (
                      <SelectItem key={r} value={r} className="capitalize">
                        {r}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div>
              <FieldLabel hint="at least one">Sections</FieldLabel>
              <StringChips
                options={["traffic", "threats", "audit"] as const}
                selected={tplForm.sections}
                onToggle={(s) =>
                  setTplForm({
                    ...tplForm,
                    sections: tplForm.sections.includes(s) ? tplForm.sections.filter((x) => x !== s) : [...tplForm.sections, s],
                  })
                }
              />
            </div>
            <div className="flex items-center justify-between rounded-md border border-zinc-200 px-3 py-2 dark:border-zinc-800">
              <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Enabled</span>
              <Switch checked={tplForm.enabled} onCheckedChange={(enabled) => setTplForm({ ...tplForm, enabled })} aria-label="Enabled" />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setTplOpen(false)}>
              Cancel
            </Button>
            <Button
              className="bg-blue-600 text-white hover:bg-blue-700"
              disabled={saveTplMut.isPending || tplForm.name.trim().length === 0 || tplForm.sections.length === 0}
              onClick={() => saveTplMut.mutate()}
            >
              {saveTplMut.isPending ? <Icons.Loader2 className="mr-1 h-4 w-4 animate-spin" /> : null}
              {editingTpl ? "Save changes" : "Create template"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── new report dialog ── */}
      <Dialog open={newOpen} onOpenChange={setNewOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>New report</DialogTitle>
            <DialogDescription>
              Renders immediately from real log data — format “pdf” produces the identical document plus a print dialog hint.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <FieldLabel hint="required">Name</FieldLabel>
              <Input value={newForm.name} onChange={(e) => setNewForm({ ...newForm, name: e.target.value })} placeholder="e.g. Weekly ops summary" />
              {newErr.name?.[0] ? <p className="mt-1 text-xs text-rose-600">{newErr.name[0]}</p> : null}
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <FieldLabel>Range</FieldLabel>
                <Select value={newForm.range} onValueChange={(range) => setNewForm({ ...newForm, range })}>
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {RANGES.map((r) => (
                      <SelectItem key={r} value={r} className="capitalize">
                        {r}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <FieldLabel>Format</FieldLabel>
                <Select value={newForm.format} onValueChange={(format) => setNewForm({ ...newForm, format })}>
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="pdf">pdf (via print)</SelectItem>
                    <SelectItem value="html">html</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div>
              <FieldLabel hint="at least one">Sections</FieldLabel>
              <MultiChips
                options={SECTION_OPTIONS}
                selected={newForm.sections.map((s) => ID_BY_SECTION[s]).filter(Boolean)}
                onToggle={(id) => {
                  const s = SECTION_BY_ID[id];
                  setNewForm({
                    ...newForm,
                    sections: newForm.sections.includes(s) ? newForm.sections.filter((x) => x !== s) : [...newForm.sections, s],
                  });
                }}
                emptyLabel="any"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setNewOpen(false)}>
              Cancel
            </Button>
            <Button
              className="bg-blue-600 text-white hover:bg-blue-700"
              disabled={newRunMut.isPending || newForm.name.trim().length === 0 || newForm.sections.length === 0}
              onClick={() => newRunMut.mutate()}
            >
              {newRunMut.isPending ? <Icons.Loader2 className="mr-1 h-4 w-4 animate-spin" /> : <Icons.FileBarChart className="mr-1 h-4 w-4" />}
              Generate
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── view rendered report ── */}
      <Dialog open={viewingId != null} onOpenChange={(open) => !open && setViewingId(null)}>
        <DialogContent className="max-h-[85vh] sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle className="truncate pr-6">{viewing?.name ?? "Report"}</DialogTitle>
            <DialogDescription>
              {viewing
                ? `${viewing.source} · ${viewing.range} · generated ${fmtTs(viewing.createdAt)}${viewing.summary?.framework ? ` · ${viewing.summary.framework}` : ""}`
                : "Loading…"}
            </DialogDescription>
          </DialogHeader>
          {runDetail.isLoading ? (
            <div className="flex items-center justify-center py-10">
              <Icons.Loader2 className="h-6 w-6 animate-spin text-blue-600" />
            </div>
          ) : runDetail.isError ? (
            <QueryError error={runDetail.error} onRetry={() => void runDetail.refetch()} />
          ) : (
            <>
              {pdfHint && (
                <div className="flex items-center justify-between gap-2 rounded-md border border-blue-500/30 bg-blue-500/5 px-3 py-2">
                  <p className="text-xs text-zinc-600 dark:text-zinc-400">
                    PDF-format report — use your browser’s print dialog to save it as a PDF file.
                  </p>
                  <Button size="sm" className="h-8 shrink-0 gap-1.5 bg-blue-600 text-white hover:bg-blue-700" onClick={() => window.print()}>
                    <Icons.Printer className="h-3.5 w-3.5" />
                    Print
                  </Button>
                </div>
              )}
              <div
                className="max-h-[70vh] overflow-y-auto rounded-md border border-zinc-200 bg-white p-4 dark:border-zinc-800"
                // rendered server-side by our own report engine (escaped tables, fixed inline CSS)
                dangerouslySetInnerHTML={{ __html: viewing?.contentHtml ?? "<p>No content stored for this run.</p>" }}
              />
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* ── anonymization rule editor ── */}
      <Dialog open={ruleOpen} onOpenChange={setRuleOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{editingRule ? "Edit anonymization rule" : "New anonymization rule"}</DialogTitle>
            <DialogDescription>
              Rules rewrite matching fields at export/preview time — the underlying logs are never modified.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <FieldLabel hint="required · unique">Name</FieldLabel>
              <Input value={ruleForm.name} onChange={(e) => setRuleForm({ ...ruleForm, name: e.target.value })} placeholder="e.g. Mask internal source IPs" />
              {ruleErr.name?.[0] ? <p className="mt-1 text-xs text-rose-600">{ruleErr.name[0]}</p> : null}
            </div>
            <div className="grid grid-cols-3 gap-2">
              <div>
                <FieldLabel>Dataset</FieldLabel>
                <Select
                  value={ruleForm.dataset}
                  onValueChange={(dataset) => setRuleForm({ ...ruleForm, dataset, field: dataset === "audit" ? "user_name" : "source_ip" })}
                >
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {ANON_DATASETS.map((d) => (
                      <SelectItem key={d} value={d} className="capitalize">
                        {d}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <FieldLabel>Field</FieldLabel>
                <Select value={ruleForm.field} onValueChange={(field) => setRuleForm({ ...ruleForm, field })}>
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {ANON_FIELDS.map((f) => (
                      <SelectItem key={f} value={f} className="font-mono text-xs">
                        {f}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <FieldLabel>Strategy</FieldLabel>
                <Select value={ruleForm.strategy} onValueChange={(strategy) => setRuleForm({ ...ruleForm, strategy })}>
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="hash">hash</SelectItem>
                    <SelectItem value="mask">mask</SelectItem>
                    <SelectItem value="pseudonymize">pseudonymize</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="flex items-center justify-between rounded-md border border-zinc-200 px-3 py-2 dark:border-zinc-800">
              <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Enabled</span>
              <Switch checked={ruleForm.enabled} onCheckedChange={(enabled) => setRuleForm({ ...ruleForm, enabled })} aria-label="Enabled" />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRuleOpen(false)}>
              Cancel
            </Button>
            <Button
              className="bg-blue-600 text-white hover:bg-blue-700"
              disabled={saveRuleMut.isPending || ruleForm.name.trim().length === 0}
              onClick={() => saveRuleMut.mutate()}
            >
              {saveRuleMut.isPending ? <Icons.Loader2 className="mr-1 h-4 w-4 animate-spin" /> : null}
              {editingRule ? "Save changes" : "Create rule"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── anonymization preview ── */}
      <Dialog open={previewOpen} onOpenChange={setPreviewOpen}>
        <DialogContent className="max-h-[85vh] sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle>Anonymization preview</DialogTitle>
            <DialogDescription>
              Last 5 rows of the dataset with enabled rules applied — blue cells were rewritten.
            </DialogDescription>
          </DialogHeader>
          <div className="flex items-center gap-2">
            <span className="text-xs font-medium text-zinc-500">Dataset</span>
            <Select value={previewDataset} onValueChange={setPreviewDataset}>
              <SelectTrigger className="h-8 w-40 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {ANON_DATASETS.filter((d) => PREVIEW_COLUMNS[d]).map((d) => (
                  <SelectItem key={d} value={d} className="capitalize">
                    {d}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {previewQuery.isFetching && <Icons.Loader2 className="h-4 w-4 animate-spin text-blue-600" />}
          </div>
          {previewQuery.isLoading ? (
            <div className="flex items-center justify-center py-10">
              <Icons.Loader2 className="h-6 w-6 animate-spin text-blue-600" />
            </div>
          ) : previewQuery.isError ? (
            <QueryError error={previewQuery.error} onRetry={() => void previewQuery.refetch()} />
          ) : !preview || preview.before.length === 0 ? (
            <EmptyBlock icon={<Icons.SearchX className="h-6 w-6" />} title="No rows to preview" description="This dataset has no log rows yet." />
          ) : (
            <div className="grid max-h-[60vh] gap-3 overflow-y-auto lg:grid-cols-2">
              {(
                [
                  { label: "Before", rows: preview.before, compare: null },
                  { label: "After", rows: preview.after, compare: preview.before },
                ] as const
              ).map((side) => (
                <div key={side.label} className="rounded-md border border-zinc-200 dark:border-zinc-800">
                  <p className="border-b border-zinc-200 px-2.5 py-1.5 text-[11px] font-semibold uppercase tracking-wide text-zinc-500 dark:border-zinc-800">
                    {side.label}
                  </p>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        {(PREVIEW_COLUMNS[previewDataset] ?? Object.keys(side.rows[0] ?? {})).map((c) => (
                          <TableHead key={c} className="px-2 py-1.5 text-[10px]">
                            {c}
                          </TableHead>
                        ))}
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {side.rows.map((row, i) => (
                        <TableRow key={i}>
                          {(PREVIEW_COLUMNS[previewDataset] ?? Object.keys(row)).map((c) => {
                            const val = row[c] ?? "—";
                            const changed =
                              side.compare != null && side.compare[i] != null && String(side.compare[i][c] ?? "") !== String(val);
                            return (
                              <TableCell
                                key={c}
                                className={cn(
                                  "max-w-32 truncate px-2 py-1.5 font-mono text-[11px]",
                                  changed && "font-medium text-blue-600 dark:text-blue-400",
                                )}
                              >
                                {String(val)}
                              </TableCell>
                            );
                          })}
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              ))}
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* ── delete confirms ── */}
      <ConfirmDialog
        open={deletingTpl != null}
        onOpenChange={(open) => !open && setDeletingTpl(null)}
        title={`Delete template "${deletingTpl?.name ?? ""}"?`}
        description="Past report runs are kept. This cannot be undone."
        confirmLabel="Delete template"
        loading={delTplMut.isPending}
        onConfirm={() => deletingTpl && delTplMut.mutate(deletingTpl.id)}
      />
      <ConfirmDialog
        open={deletingRun != null}
        onOpenChange={(open) => !open && setDeletingRun(null)}
        title={`Delete report "${deletingRun?.name ?? ""}"?`}
        description="The rendered document and its summary are removed. This cannot be undone."
        confirmLabel="Delete report"
        loading={delRunMut.isPending}
        onConfirm={() => deletingRun && delRunMut.mutate(deletingRun.id)}
      />
      <ConfirmDialog
        open={deletingRule != null}
        onOpenChange={(open) => !open && setDeletingRule(null)}
        title={`Delete rule "${deletingRule?.name ?? ""}"?`}
        description="Matching fields will no longer be anonymized in previews/exports. This cannot be undone."
        confirmLabel="Delete rule"
        loading={delRuleMut.isPending}
        onConfirm={() => deletingRule && delRuleMut.mutate(deletingRule.id)}
      />
    </div>
  );
}
