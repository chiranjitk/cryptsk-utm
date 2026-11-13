"use client";

/**
 * #/ips/policies — IPS policy list + editor (M04 §4). Mode radio cards with
 * explanation, ET category matrix, custom suricata rules (loose validation),
 * exceptions (sid 0 = any-SID bypass per ADR-017), thresholds, preprocessors,
 * TI blocklist; Apply-preset dialog (DATA_PLANE §3.1); Rule Updates card
 * backed by the ips/auto_update SystemSetting.
 */

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { ScrollArea } from "@/components/ui/scroll-area";
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
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import { ipsApi, customRuleLineErrors, fmtDateTime, fmtRelative, type CategoryDefDto, type ExceptionRow, type IpsMode, type IpsPolicyDto, type IpsPreset, type ThresholdRow, type UpdateSettingsDto } from "./ips-api";
import { ModeBadge, SeverityBadge, modeHint, useIpsConfigInvalidation } from "./ips-ui";
import { IpsOsSync } from "./os-sync";
import { ConfirmDialog, EditorSection, EmptyBlock, FieldLabel, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";

const POLICIES_KEY = ["ips", "policies"] as const;
const CATEGORIES_KEY = ["ips", "rule-categories"] as const;
const SETTINGS_KEY = ["ips", "update-settings"] as const;

const MODES: IpsMode[] = ["inline_drop", "inline_tap", "passive"];

// ── editor form state ───────────────────────────────────────────────────────

interface EditorForm {
  name: string;
  mode: IpsMode;
  enabled: boolean;
  categories: Record<string, boolean>;
  customRulesRaw: string;
  exceptions: ExceptionRow[];
  thresholds: ThresholdRow[];
  preprocessors: { stream: boolean; http: boolean; tls: boolean; ssh: boolean };
  tiBlocklist: boolean;
}

function formFromPolicy(p: IpsPolicyDto | null): EditorForm {
  if (!p) {
    return {
      name: "",
      mode: "inline_drop",
      enabled: true,
      categories: {},
      customRulesRaw: "",
      exceptions: [],
      thresholds: [],
      preprocessors: { stream: true, http: true, tls: true, ssh: true },
      tiBlocklist: false,
    };
  }
  return {
    name: p.name,
    mode: p.mode,
    enabled: p.enabled,
    categories: { ...p.ruleCategories },
    customRulesRaw: p.customRules.join("\n"),
    exceptions: p.exceptions.map((e) => ({ ...e })),
    thresholds: p.thresholds.map((t) => ({ ...t })),
    preprocessors: {
      stream: p.preprocessors.stream !== false,
      http: p.preprocessors.http !== false,
      tls: p.preprocessors.tls !== false,
      ssh: p.preprocessors.ssh !== false,
    },
    tiBlocklist: p.tiBlocklist,
  };
}

/** Client-side loose check mirroring the server's customRulesSchema. */
function validateCustomRules(raw: string): Array<{ line: number; message: string }> {
  const errors: Array<{ line: number; message: string }> = [];
  raw.split("\n").forEach((line, i) => {
    const t = line.trim();
    if (!t) return;
    if (!/^(alert|drop|pass|reject)\b/.test(t)) {
      errors.push({ line: i + 1, message: "must start with an action keyword (alert|drop|pass|reject)" });
    } else if (!/\bsid:\s*\d+\s*;/.test(t)) {
      errors.push({ line: i + 1, message: 'missing `sid:<number>;`' });
    }
  });
  return errors;
}

// ── main view ───────────────────────────────────────────────────────────────

export function PoliciesView() {
  useIpsConfigInvalidation();
  const queryClient = useQueryClient();

  const policiesQuery = useQuery({ queryKey: POLICIES_KEY, queryFn: ipsApi.listPolicies });
  const categoriesQuery = useQuery({ queryKey: CATEGORIES_KEY, queryFn: ipsApi.listCategories, staleTime: 5 * 60_000 });
  const settingsQuery = useQuery({ queryKey: SETTINGS_KEY, queryFn: ipsApi.getUpdateSettings });

  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<IpsPolicyDto | null>(null);
  const [duplicateSource, setDuplicateSource] = useState<IpsPolicyDto | null>(null);
  const [presetKey, setPresetKey] = useState<IpsPreset | null>(null);
  const [deleting, setDeleting] = useState<IpsPolicyDto | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);
  /** openedAt for the stale-data banner (config:updated races) */
  const [editorOpenedAt, setEditorOpenedAt] = useState(0);

  const policies = useMemo(() => policiesQuery.data ?? [], [policiesQuery.data]);
  const categories = useMemo(() => categoriesQuery.data?.categories ?? [], [categoriesQuery.data]);

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: POLICIES_KEY });
    void queryClient.invalidateQueries({ queryKey: SETTINGS_KEY });
  };

  const openCreate = () => {
    setEditing(null);
    setDuplicateSource(null);
    setEditorOpenedAt(Date.now());
    setEditorOpen(true);
  };
  const openEdit = (p: IpsPolicyDto) => {
    setEditing(p);
    setDuplicateSource(null);
    setEditorOpenedAt(Date.now());
    setEditorOpen(true);
  };
  const openDuplicate = (p: IpsPolicyDto) => {
    setEditing(null);
    setDuplicateSource(p);
    setEditorOpenedAt(Date.now());
    setEditorOpen(true);
  };

  const toggleMut = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => ipsApi.updatePolicy(id, { enabled }),
    onSuccess: (_d, vars) => {
      toastOk(vars.enabled ? "Policy enabled" : "Policy disabled", "Generator picks up the change on the next tick");
      invalidate();
    },
    onError: (err) => toastErr(err, "Toggle failed"),
  });

  const duplicateMut = useMutation({
    mutationFn: async (p: IpsPolicyDto) => {
      let name = `${p.name}-copy`;
      if (policies.some((x) => x.name === name)) name = `${p.name}-copy-${Date.now().toString(36).slice(-4)}`;
      return ipsApi.createPolicy({
        name,
        mode: p.mode,
        enabled: false,
        ruleCategories: p.ruleCategories,
        customRules: p.customRules,
        exceptions: p.exceptions,
        thresholds: p.thresholds,
        preprocessors: p.preprocessors,
        tiBlocklist: p.tiBlocklist,
      });
    },
    onSuccess: (created) => {
      toastOk("Policy duplicated", `${created.name} created disabled — edit and enable when ready`);
      invalidate();
    },
    onError: (err) => toastErr(err, "Duplicate failed"),
  });

  const deleteMut = useMutation({
    mutationFn: (id: number) => ipsApi.deletePolicy(id),
    onSuccess: () => {
      toastOk("Policy deleted", "Events survive policy deletion by design");
      setDeleting(null);
      invalidate();
    },
    onError: (err) => {
      setDeleting(null);
      toastErr(err, "Delete failed");
    },
  });

  const deletingConflicts = deleting ? deleting.attachedRuleNames : [];
  const staleEditor = editorOpen && editing != null && policiesQuery.dataUpdatedAt > editorOpenedAt;

  return (
    <div className="space-y-4">
      {/* header row */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <p className="text-sm text-zinc-500">
            Policies decide how traffic is inspected and which ET categories are enabled.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" className="gap-1.5">
                <Icons.Wand2 className="h-4 w-4 text-zinc-700 dark:text-zinc-500" />
                Apply preset
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-52">
              <DropdownMenuLabel className="text-xs">Profile bundles (DATA_PLANE §3.1)</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => setPresetKey("conservative")}>
                <Icons.ShieldMinus className="mr-2 h-4 w-4 text-emerald-500" /> Conservative
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => setPresetKey("balanced")}>
                <Icons.Scale className="mr-2 h-4 w-4 text-zinc-700 dark:text-zinc-500" /> Balanced
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => setPresetKey("aggressive")}>
                <Icons.ShieldAlert className="mr-2 h-4 w-4 text-rose-500" /> Aggressive
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
          <Button onClick={openCreate} className="gap-1.5">
            <Icons.Plus className="h-4 w-4" /> New policy
          </Button>
        </div>
      </div>

      {/* GUI↔OS integration — real Suricata facts, plan, apply/rollback */}
      <IpsOsSync />

      {policiesQuery.isError ? (
        <QueryError error={policiesQuery.error} onRetry={() => void policiesQuery.refetch()} />
      ) : policiesQuery.isLoading ? (
        <Card>
          <CardContent className="pt-6">
            <TableSkeleton rows={3} cols={7} />
          </CardContent>
        </Card>
      ) : policies.length === 0 ? (
        <Card>
          <CardContent className="p-0">
            <EmptyBlock
              icon={<Icons.Radar className="h-6 w-6" />}
              title="No IPS policies yet"
              description="Create a policy or apply a preset bundle to start inspecting traffic."
              action={
                <Button onClick={openCreate} size="sm" className="gap-1.5">
                  <Icons.Plus className="h-4 w-4" /> New policy
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
                  <TableHead>Policy</TableHead>
                  <TableHead>Mode</TableHead>
                  <TableHead>Enabled</TableHead>
                  <TableHead>Categories</TableHead>
                  <TableHead>Custom rules</TableHead>
                  <TableHead>Attached rules</TableHead>
                  <TableHead className="w-10" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {policies.map((p) => (
                  <TableRow key={p.id} className={cn(!p.enabled && "opacity-60")}>
                    <TableCell>
                      <p className="font-medium">{p.name}</p>
                      <p className="text-[11px] text-zinc-400">
                        {p.tiBlocklist ? "TI blocklist on · " : ""}
                        {p.thresholds.length} threshold{p.thresholds.length === 1 ? "" : "s"} ·{" "}
                        {p.exceptions.length} exception{p.exceptions.length === 1 ? "" : "s"}
                      </p>
                    </TableCell>
                    <TableCell>
                      <ModeBadge mode={p.mode} />
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={p.enabled}
                        disabled={toggleMut.isPending}
                        aria-label={`Toggle policy ${p.name}`}
                        onCheckedChange={(enabled) => toggleMut.mutate({ id: p.id, enabled })}
                      />
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-xs tabular-nums">
                        {Object.values(p.ruleCategories).filter(Boolean).length}
                        <span className="text-zinc-400">/{categories.length || p.ruleCategories.length}</span>
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-xs tabular-nums">{p.customRules.length}</span>
                    </TableCell>
                    <TableCell>
                      {p.attachedRuleCount > 0 ? (
                        <a
                          href={`#/firewall/rules?search=${encodeURIComponent(p.name)}`}
                          className="inline-flex items-center gap-1 text-xs font-medium text-zinc-700 hover:underline dark:text-zinc-500"
                        >
                          <Icons.ShieldCheck className="h-3.5 w-3.5" />
                          {p.attachedRuleCount} rule{p.attachedRuleCount === 1 ? "" : "s"}
                        </a>
                      ) : (
                        <span className="text-xs text-zinc-400">none</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={`Actions for ${p.name}`}>
                            <Icons.MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onClick={() => openEdit(p)}>
                            <Icons.Pencil className="mr-2 h-4 w-4" /> Edit
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => openDuplicate(p)}>
                            <Icons.Copy className="mr-2 h-4 w-4" /> Duplicate
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem onClick={() => setDeleting(p)} className="text-rose-600 focus:text-rose-600 dark:text-rose-400">
                            <Icons.Trash2 className="mr-2 h-4 w-4" /> Delete
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* Rule Updates card */}
      <RuleUpdatesCard settings={settingsQuery.data ?? null} loading={settingsQuery.isLoading} onChanged={invalidate} />

      {/* editor */}
      <PolicyEditor
        open={editorOpen}
        onOpenChange={(open) => {
          setEditorOpen(open);
          if (!open) {
            setEditing(null);
            setDuplicateSource(null);
          }
        }}
        editing={editing}
        duplicateSource={duplicateSource}
        categories={categories}
        stale={staleEditor}
        onSaved={() => {
          setEditorOpen(false);
          setEditing(null);
          setDuplicateSource(null);
          invalidate();
        }}
      />

      {/* preset dialog */}
      {presetKey && (
        <PresetDialog
          presetKey={presetKey}
          policies={policies}
          categories={categories}
          onClose={() => setPresetKey(null)}
          onApplied={() => {
            setPresetKey(null);
            invalidate();
          }}
        />
      )}

      {/* delete confirm — mirrors fw-ui ConflictDialog with RESTRICT detail */}
      <ConfirmDialog
        open={deleting != null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete policy ${deleting?.name ?? ""}?`}
        description={
          deletingConflicts.length > 0
            ? `${deleting?.name} is attached to ${deletingConflicts.length} firewall rule${deletingConflicts.length === 1 ? "" : "s"} (${deletingConflicts.join(", ")}). The server will reject with 409 until detached.`
            : "The policy will be removed. Historical ips_events are kept (no FK, ER_DIAGRAM §2)."
        }
        confirmLabel="Delete"
        loading={deleteMut.isPending}
        onConfirm={() => deleting && deleteMut.mutate(deleting.id)}
      />
    </div>
  );
}

// ── policy editor dialog ────────────────────────────────────────────────────

function PolicyEditor(props: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editing: IpsPolicyDto | null;
  duplicateSource: IpsPolicyDto | null;
  categories: CategoryDefDto[];
  stale: boolean;
  onSaved: () => void;
}) {
  const { open, editing, duplicateSource } = props;
  const base = editing ?? duplicateSource;
  const [form, setForm] = useState<EditorForm>(() => {
    const f = formFromPolicy(base);
    if (!editing && duplicateSource) f.name = `${duplicateSource.name}-copy`;
    return f;
  });
  const [serverLineErrors, setServerLineErrors] = useState<Array<{ line: number; message: string }>>([]);
  const [nameError, setNameError] = useState<string | null>(null);

  // re-seed the form when a different policy is loaded into the dialog
  const baseId = base?.id ?? null;
  const baseKey = `${baseId ?? "new"}:${editing ? "edit" : "dup"}:${base?.name ?? ""}`;
  const [lastKey, setLastKey] = useState(baseKey);
  if (baseKey !== lastKey) {
    setLastKey(baseKey);
    setServerLineErrors([]);
    const f = formFromPolicy(base);
    if (!editing && duplicateSource) f.name = `${duplicateSource.name}-copy`;
    setForm(f);
  }

  const set = <K extends keyof EditorForm>(key: K, value: EditorForm[K]) => setForm((prev) => ({ ...prev, [key]: value }));

  const customRuleErrors = useMemo(() => validateCustomRules(form.customRulesRaw), [form.customRulesRaw]);
  const lineErrors = serverLineErrors.length > 0 ? serverLineErrors : customRuleErrors;

  const categoriesOn = useMemo(() => Object.values(form.categories).filter(Boolean).length, [form.categories]);

  const exceptionProblems = useMemo(
    () =>
      form.exceptions
        .map((e, i) => (!Number.isInteger(e.sid) || e.sid < 0 ? i : -1))
        .filter((i) => i >= 0),
    [form.exceptions],
  );
  const thresholdProblems = useMemo(
    () =>
      form.thresholds
        .map((t, i) => (!Number.isInteger(t.sid) || t.sid < 1 || t.count < 1 || t.seconds < 1 ? i : -1))
        .filter((i) => i >= 0),
    [form.thresholds],
  );

  const saveMut = useMutation({
    mutationFn: async () => {
      const body = {
        name: form.name.trim(),
        mode: form.mode,
        enabled: form.enabled,
        ruleCategories: form.categories,
        customRules: form.customRulesRaw.split("\n").map((l) => l.trim()).filter(Boolean),
        exceptions: form.exceptions,
        thresholds: form.thresholds,
        preprocessors: form.preprocessors,
        tiBlocklist: form.tiBlocklist,
      };
      if (editing) return ipsApi.updatePolicy(editing.id, body);
      return ipsApi.createPolicy(body);
    },
    onSuccess: (saved) => {
      toastOk(editing ? "Policy updated" : "Policy created", `${saved.name} saved`);
      props.onSaved();
    },
    onError: (err) => {
      const lineErrs = customRuleLineErrors(err);
      if (lineErrs.length > 0) setServerLineErrors(lineErrs);
      else if (err instanceof Error && /already exists/i.test(err.message)) setNameError(err.message);
      toastErr(err, editing ? "Update failed" : "Create failed");
    },
  });

  const submit = () => {
    setNameError(null);
    setServerLineErrors([]);
    if (!form.name.trim()) {
      setNameError("Name is required");
      return;
    }
    if (customRuleErrors.length > 0) return;
    if (exceptionProblems.length > 0 || thresholdProblems.length > 0) return;
    saveMut.mutate();
  };

  return (
    <Dialog open={open} onOpenChange={props.onOpenChange}>
      <DialogContent className="max-h-[92vh] w-[calc(100vw-1rem)] max-w-4xl overflow-y-auto sm:max-w-4xl">
        <DialogHeader>
          <DialogTitle>
            {editing ? `Edit policy — ${editing.name}` : duplicateSource ? `Duplicate policy — ${duplicateSource.name}-copy` : "New IPS policy"}
          </DialogTitle>
          <DialogDescription>
            Suricata-style inspection policy: mode, category matrix, custom rules, exceptions and thresholds.
          </DialogDescription>
        </DialogHeader>

        {props.stale && (
          <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-400">
            <Icons.TriangleAlert className="mt-0.5 h-4 w-4 shrink-0" />
            <span>The policy list changed while this editor was open (config:updated ips). Review your changes before saving — saving now overwrites the newer state.</span>
          </div>
        )}

        <div className="space-y-4">
          <EditorSection title="General">
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <FieldLabel>Name</FieldLabel>
                <Input value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="e.g. DMZ-AGGRESSIVE" aria-invalid={Boolean(nameError)} />
                {nameError ? <p className="mt-1 text-xs text-rose-600 dark:text-rose-400">{nameError}</p> : null}
              </div>
              <div className="flex items-end justify-between gap-4">
                <div className="flex flex-col gap-1.5">
                  <Label className="text-xs font-medium text-zinc-700 dark:text-zinc-300" htmlFor="ips-enabled">Policy enabled</Label>
                  <Switch id="ips-enabled" checked={form.enabled} onCheckedChange={(v) => set("enabled", v)} />
                </div>
                <div className="flex items-center gap-2 text-xs text-zinc-500">
                  <Icons.CircleCheck className="h-3.5 w-3.5 text-emerald-500" />
                  {categoriesOn} of {props.categories.length || "?"} categories on
                </div>
              </div>
            </div>
          </EditorSection>

          <EditorSection title="Inspection mode">
            <RadioGroup value={form.mode} onValueChange={(v) => set("mode", v as IpsMode)} className="grid gap-2 sm:grid-cols-3">
              {MODES.map((m) => (
                <Label
                  key={m}
                  htmlFor={`mode-${m}`}
                  className={cn(
                    "flex cursor-pointer items-start gap-2.5 rounded-lg border p-3 transition-colors",
                    form.mode === m ? "border-zinc-600/60 bg-zinc-600/5" : "hover:bg-zinc-50 dark:hover:bg-zinc-800/50",
                  )}
                >
                  <RadioGroupItem id={`mode-${m}`} value={m} className="mt-0.5" />
                  <span className="space-y-1">
                    <ModeBadge mode={m} />
                    <span className="block text-[11px] leading-snug text-zinc-500">{modeHint(m)}</span>
                  </span>
                </Label>
              ))}
            </RadioGroup>
            <p className="flex items-start gap-1.5 rounded-md bg-zinc-50 px-2.5 py-2 text-[11px] text-zinc-500 dark:bg-zinc-800/60">
              <Icons.Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              Only <span className="font-medium text-zinc-700 dark:text-zinc-200">inline drop</span> blocks traffic — inline tap and passive are detect-only. Suricata runs inline via nftables NFQUEUE (queue num 1–4 fanout); passive runs on a mirror/SPAN tap via af-packet.
            </p>
          </EditorSection>

          <EditorSection title={`ET category matrix (${props.categories.length})`}>
            {props.categories.length === 0 ? (
              <p className="text-xs text-zinc-400">Loading categories…</p>
            ) : (
              <>
                <div className="mb-2 flex items-center justify-between">
                  <p className="text-[11px] text-zinc-400">Enabled categories receive signatures; the rest are skipped by the engine.</p>
                  <div className="flex items-center gap-2">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="h-7 px-2 text-[11px]"
                      onClick={() => set("categories", Object.fromEntries(props.categories.map((c) => [c.name, true])))}
                    >
                      All on
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="h-7 px-2 text-[11px]"
                      onClick={() => set("categories", Object.fromEntries(props.categories.map((c) => [c.name, false])))}
                    >
                      All off
                    </Button>
                  </div>
                </div>
                <ScrollArea className="max-h-64">
                  <div className="grid gap-1.5 pr-3 sm:grid-cols-2">
                    {props.categories.map((c) => {
                      const on = form.categories[c.name] === true;
                      const familyOff = c.family !== "generic" && form.preprocessors[c.family] === false;
                      return (
                        <div
                          key={c.name}
                          className={cn(
                            "flex items-center justify-between gap-2 rounded-md border px-2.5 py-1.5",
                            on ? "border-zinc-600/30 bg-zinc-600/5" : "border-zinc-200 dark:border-zinc-800",
                          )}
                        >
                          <div className="min-w-0">
                            <p className="flex items-center gap-1.5 text-xs font-medium">
                              {c.label}
                              <SeverityBadge severity={c.baseSeverity} className="px-1 py-0 text-[9px]" />
                            </p>
                            <p className="truncate text-[10px] text-zinc-400">
                              {c.family === "generic" ? "any inspector" : `${c.family} inspector`}
                              {familyOff ? " · inspector off — family will not fire" : ""} · sid {c.sidRange}
                            </p>
                          </div>
                          <Switch
                            checked={on}
                            aria-label={`Toggle category ${c.name}`}
                            onCheckedChange={(v) => set("categories", { ...form.categories, [c.name]: v })}
                          />
                        </div>
                      );
                    })}
                  </div>
                </ScrollArea>
              </>
            )}
          </EditorSection>

          <EditorSection title="Custom rules">
            <FieldLabel hint="one raw suricata rule per line — loosely validated, signature logic simulated">
              Suricata rule strings
            </FieldLabel>
            <Textarea
              value={form.customRulesRaw}
              onChange={(e) => {
                set("customRulesRaw", e.target.value);
                setServerLineErrors([]);
              }}
              rows={4}
              className="font-mono text-xs"
              placeholder={"alert http $EXTERNAL_NET any -> $HOME_NET 80 (msg:\"ET exploit attempt\"; content:\"/etc/passwd\"; sid:20200001; rev:1;)"}
            />
            {lineErrors.length > 0 && (
              <ul className="space-y-0.5 rounded-md border border-rose-500/40 bg-rose-500/5 px-2.5 py-2 text-[11px] text-rose-600 dark:text-rose-400">
                {lineErrors.map((e) => (
                  <li key={`${e.line}-${e.message}`}>line {e.line}: {e.message}</li>
                ))}
              </ul>
            )}
          </EditorSection>

          <div className="grid gap-4 lg:grid-cols-2">
            <EditorSection title={`Exceptions (${form.exceptions.length})`}>
              <p className="text-[11px] text-zinc-400">
                sid <span className="font-mono">0</span> = any-SID capture-level bypass (ADR-017); optional source/dest (ip or cidr) narrows the match.
              </p>
              <div className="space-y-1.5">
                {form.exceptions.map((ex, i) => (
                  <div key={i} className="grid grid-cols-[70px_1fr_1fr_28px] items-center gap-1.5">
                    <Input
                      value={ex.sid === 0 && ex.source === undefined && ex.dest === undefined && !ex.comment ? "" : String(ex.sid ?? "")}
                      onChange={(e) => {
                        const next = [...form.exceptions];
                        next[i] = { ...ex, sid: e.target.value === "" ? (Number.NaN as number) : Number(e.target.value) };
                        set("exceptions", next);
                      }}
                      placeholder="sid"
                      className="h-7 font-mono text-xs"
                      aria-label="Exception sid"
                    />
                    <Input
                      value={ex.source ?? ""}
                      onChange={(e) => {
                        const next = [...form.exceptions];
                        next[i] = { ...ex, source: e.target.value || null };
                        set("exceptions", next);
                      }}
                      placeholder="source (optional)"
                      className="h-7 font-mono text-xs"
                      aria-label="Exception source"
                    />
                    <Input
                      value={ex.comment ?? ""}
                      onChange={(e) => {
                        const next = [...form.exceptions];
                        next[i] = { ...ex, comment: e.target.value || null };
                        set("exceptions", next);
                      }}
                      placeholder="comment"
                      className="h-7 text-xs"
                      aria-label="Exception comment"
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7"
                      aria-label={`Remove exception ${i + 1}`}
                      onClick={() => set("exceptions", form.exceptions.filter((_, j) => j !== i))}
                    >
                      <Icons.X className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                ))}
              </div>
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="mt-1.5 h-7 gap-1 text-xs"
                onClick={() => set("exceptions", [...form.exceptions, { sid: 0, source: null, dest: null, comment: null }])}
              >
                <Icons.Plus className="h-3.5 w-3.5" /> Add exception
              </Button>
              {exceptionProblems.length > 0 && (
                <p className="mt-1 text-[11px] text-rose-600 dark:text-rose-400">
                  {exceptionProblems.length} exception row{exceptionProblems.length === 1 ? "" : "s"} need a valid sid (integer ≥ 0).
                </p>
              )}
            </EditorSection>

            <EditorSection title={`Thresholds (${form.thresholds.length})`}>
              <p className="text-[11px] text-zinc-400">
                Alert at most <span className="font-mono">count</span> events per <span className="font-mono">seconds</span> per tracked host — further hits are recorded as <span className="font-mono">suppressed</span>.
              </p>
              <div className="space-y-1.5">
                {form.thresholds.map((th, i) => (
                  <div key={i} className="grid grid-cols-[70px_84px_58px_58px_28px] items-center gap-1.5">
                    <Input
                      value={String(th.sid ?? "")}
                      onChange={(e) => {
                        const next = [...form.thresholds];
                        next[i] = { ...th, sid: e.target.value === "" ? (Number.NaN as number) : Number(e.target.value) };
                        set("thresholds", next);
                      }}
                      placeholder="sid"
                      className="h-7 font-mono text-xs"
                      aria-label="Threshold sid"
                    />
                    <Select
                      value={th.track}
                      onValueChange={(v) => {
                        const next = [...form.thresholds];
                        next[i] = { ...th, track: v as ThresholdRow["track"] };
                        set("thresholds", next);
                      }}
                    >
                      <SelectTrigger className="h-7 px-2 text-xs" aria-label="Track by">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="by_src">by_src</SelectItem>
                        <SelectItem value="by_dst">by_dst</SelectItem>
                      </SelectContent>
                    </Select>
                    <Input
                      value={String(th.count ?? "")}
                      onChange={(e) => {
                        const next = [...form.thresholds];
                        next[i] = { ...th, count: e.target.value === "" ? (Number.NaN as number) : Number(e.target.value) };
                        set("thresholds", next);
                      }}
                      placeholder="count"
                      className="h-7 font-mono text-xs"
                      aria-label="Threshold count"
                    />
                    <Input
                      value={String(th.seconds ?? "")}
                      onChange={(e) => {
                        const next = [...form.thresholds];
                        next[i] = { ...th, seconds: e.target.value === "" ? (Number.NaN as number) : Number(e.target.value) };
                        set("thresholds", next);
                      }}
                      placeholder="secs"
                      className="h-7 font-mono text-xs"
                      aria-label="Threshold seconds"
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7"
                      aria-label={`Remove threshold ${i + 1}`}
                      onClick={() => set("thresholds", form.thresholds.filter((_, j) => j !== i))}
                    >
                      <Icons.X className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                ))}
              </div>
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="mt-1.5 h-7 gap-1 text-xs"
                onClick={() => set("thresholds", [...form.thresholds, { sid: 1, track: "by_src", count: 10, seconds: 60 }])}
              >
                <Icons.Plus className="h-3.5 w-3.5" /> Add threshold
              </Button>
              {thresholdProblems.length > 0 && (
                <p className="mt-1 text-[11px] text-rose-600 dark:text-rose-400">
                  {thresholdProblems.length} threshold row{thresholdProblems.length === 1 ? "" : "s"} need sid ≥ 1, count ≥ 1, seconds ≥ 1.
                </p>
              )}
            </EditorSection>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <EditorSection title="Anomaly detection (preprocessors)">
              <div className="space-y-2">
                {(
                  [
                    ["stream", "Stream reassembly"],
                    ["http", "HTTP inspector"],
                    ["tls", "TLS inspector"],
                    ["ssh", "SSH inspector"],
                  ] as const
                ).map(([key, label]) => (
                  <div key={key} className="flex items-center justify-between rounded-md border border-zinc-200 px-2.5 py-1.5 dark:border-zinc-800">
                    <div>
                      <p className="text-xs font-medium">{label}</p>
                      <p className="font-mono text-[10px] text-zinc-400">{key}</p>
                    </div>
                    <Switch
                      checked={form.preprocessors[key]}
                      aria-label={`Toggle preprocessor ${key}`}
                      onCheckedChange={(v) => set("preprocessors", { ...form.preprocessors, [key]: v })}
                    />
                  </div>
                ))}
              </div>
              <p className="mt-2 text-[11px] text-zinc-400">
                Suricata anomaly-detection engines applied for this policy; deep stream/decoding tuning is a Phase-2 item. Disabling an inspector suppresses its event families.
              </p>
            </EditorSection>

            <EditorSection title="Threat intelligence">
              <div className="flex items-center justify-between rounded-md border border-zinc-200 px-2.5 py-2.5 dark:border-zinc-800">
                <div className="pr-3">
                  <p className="text-xs font-medium">TI blocklist</p>
                  <p className="mt-0.5 text-[11px] leading-snug text-zinc-500">
                    Drop traffic to/from known-bad feed IPs (ET-compatible free feeds). The generator emits <span className="font-mono">c2</span>/<span className="font-mono">malware</span> drop events for feed sources.
                  </p>
                </div>
                <Switch checked={form.tiBlocklist} aria-label="Toggle TI blocklist" onCheckedChange={(v) => set("tiBlocklist", v)} />
              </div>
            </EditorSection>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => props.onOpenChange(false)} disabled={saveMut.isPending}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={saveMut.isPending || customRuleErrors.length > 0 || exceptionProblems.length > 0 || thresholdProblems.length > 0}>
            {saveMut.isPending ? "Saving…" : editing ? "Save changes" : "Create policy"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── preset dialog ───────────────────────────────────────────────────────────

const PRESET_META: Record<IpsPreset, { label: string; icon: React.ReactNode; blurb: string }> = {
  conservative: {
    label: "Conservative",
    icon: <Icons.ShieldMinus className="h-4 w-4 text-emerald-500" />,
    blurb: "High-confidence categories only; alert-heavy, drops rarely. First weeks after deployment.",
  },
  balanced: {
    label: "Balanced",
    icon: <Icons.Scale className="h-4 w-4 text-zinc-700 dark:text-zinc-500" />,
    blurb: "Most ET categories on, noisy policy categories off, inline drop. Standard small enterprise.",
  },
  aggressive: {
    label: "Aggressive",
    icon: <Icons.ShieldAlert className="h-4 w-4 text-rose-500" />,
    blurb: "All categories on including policy/scan, drop-enabled. DMZ servers, incident response.",
  },
};

function PresetDialog(props: {
  presetKey: IpsPreset;
  policies: IpsPolicyDto[];
  categories: CategoryDefDto[];
  onClose: () => void;
  onApplied: () => void;
}) {
  const { presetKey } = props;
  const meta = PRESET_META[presetKey];
  const [mode, setMode] = useState<"create" | "replace">("create");
  const [name, setName] = useState(presetKey.toUpperCase());
  const [replaceId, setReplaceId] = useState<string>("");

  const applyMut = useMutation({
    mutationFn: () =>
      ipsApi.applyPreset(
        presetKey,
        mode === "create" ? name.trim() || presetKey.toUpperCase() : undefined,
        mode === "replace" ? Number(replaceId) : undefined,
      ),
    onSuccess: (policy) => {
      toastOk("Preset applied", `${policy.name} now carries the ${presetKey} bundle (${mode === "replace" ? "replaced" : "created"})`);
      props.onApplied();
    },
    onError: (err) => toastErr(err, "Preset failed"),
  });

  // preview bundle: mirror of PRESETS from the server catalog — we show the
  // category chips per DATA_PLANE §3.1 (conservative/balanced/aggressive)
  const previewOn: string[] =
    presetKey === "conservative"
      ? ["trojan", "worm", "botnet", "exploit", "malware", "c2"]
      : presetKey === "balanced"
        ? props.categories.filter((c) => !["dos", "policy", "info_leak"].includes(c.name)).map((c) => c.name)
        : props.categories.map((c) => c.name);
  const previewMode: IpsMode = presetKey === "conservative" ? "inline_tap" : "inline_drop";

  return (
    <Dialog open onOpenChange={(open) => !open && props.onClose()}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            {meta.icon} Apply preset — {meta.label}
          </DialogTitle>
          <DialogDescription>{meta.blurb}</DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          <div className="rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
            <p className="mb-1.5 text-xs font-medium">Bundle preview</p>
            <div className="mb-2 flex items-center gap-2">
              <ModeBadge mode={previewMode} />
              <span className="text-[11px] text-zinc-400">{previewOn.length} of {props.categories.length} categories on</span>
            </div>
            <div className="flex flex-wrap gap-1">
              {props.categories.map((c) => {
                const on = previewOn.includes(c.name);
                return (
                  <Badge
                    key={c.name}
                    variant="outline"
                    className={cn(
                      "px-1.5 py-0 font-mono text-[10px]",
                      on
                        ? "border-zinc-600/40 bg-zinc-600/10 text-zinc-700 dark:text-zinc-500"
                        : "border-zinc-200 text-zinc-400 line-through dark:border-zinc-800",
                    )}
                  >
                    {c.name}
                  </Badge>
                );
              })}
            </div>
          </div>

          <RadioGroup value={mode} onValueChange={(v) => setMode(v as "create" | "replace")} className="grid grid-cols-2 gap-2">
            <Label htmlFor="preset-create" className={cn("flex cursor-pointer items-center gap-2 rounded-lg border p-2.5", mode === "create" && "border-zinc-600/60 bg-zinc-600/5")}>
              <RadioGroupItem id="preset-create" value="create" />
              <span className="text-xs font-medium">Create new policy</span>
            </Label>
            <Label htmlFor="preset-replace" className={cn("flex cursor-pointer items-center gap-2 rounded-lg border p-2.5", mode === "replace" && "border-zinc-600/60 bg-zinc-600/5")}>
              <RadioGroupItem id="preset-replace" value="replace" />
              <span className="text-xs font-medium">Replace existing</span>
            </Label>
          </RadioGroup>

          {mode === "create" ? (
            <div>
              <FieldLabel hint="default: preset name">Policy name</FieldLabel>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder={presetKey.toUpperCase()} />
            </div>
          ) : (
            <div>
              <FieldLabel hint="category map + mode are overwritten">Target policy</FieldLabel>
              <Select value={replaceId} onValueChange={setReplaceId}>
                <SelectTrigger aria-label="Target policy">
                  <SelectValue placeholder="Select a policy…" />
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
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={props.onClose} disabled={applyMut.isPending}>
            Cancel
          </Button>
          <Button
            onClick={() => applyMut.mutate()}
            disabled={applyMut.isPending || (mode === "create" && !name.trim()) || (mode === "replace" && !replaceId)}
          >
            {applyMut.isPending ? "Applying…" : "Apply preset"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── Rule Updates card (auto-update scheduler) ───────────────────────────────

function RuleUpdatesCard(props: { settings: UpdateSettingsDto | null; loading: boolean; onChanged: () => void }) {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [interval, setInterval] = useState<"daily" | "weekly" | null>(null);
  const [time, setTime] = useState<string | null>(null);
  const [engineNote, setEngineNote] = useState<string | null>(null);

  const s = props.settings;
  const effEnabled = enabled ?? s?.enabled ?? true;
  const effInterval = interval ?? s?.interval ?? "daily";
  const effTime = time ?? s?.time ?? "03:00";
  const dirty = enabled != null || interval != null || time != null;

  const saveMut = useMutation({
    mutationFn: () => ipsApi.saveUpdateSettings({ enabled: effEnabled, interval: effInterval, time: effTime }),
    onSuccess: (next) => {
      toastOk("Update schedule saved", next.enabled ? `Next ET refresh ${fmtRelative(next.nextUpdateAt)}` : "Auto-update disabled");
      setEnabled(null);
      setInterval(null);
      setTime(null);
      props.onChanged();
    },
    onError: (err) => toastErr(err, "Save failed"),
  });

  const runMut = useMutation({
    mutationFn: () => ipsApi.runUpdateNow(),
    onSuccess: (next) => {
      const engine = next.engine;
      if (engine?.ranOnOs) {
        toastOk(engine.reloaded ? "ET ruleset refreshed on host" : "ET ruleset refreshed", engine.note);
      } else if (engine) {
        toastErr(new Error(engine.note), "Engine refresh not run — schedule updated");
      } else {
        toastOk("ET rules updated", "Emerging Threats feed refreshed (simulated)");
      }
      setEngineNote(engine?.note ?? null);
      props.onChanged();
    },
    onError: (err) => toastErr(err, "Update failed"),
  });

  if (props.loading || !s) {
    return (
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm">
            <Icons.RefreshCw className="h-4 w-4 text-zinc-400" /> Rule Updates
          </CardTitle>
          <CardDescription>Loading scheduler…</CardDescription>
        </CardHeader>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.RefreshCw className="h-4 w-4 text-zinc-700 dark:text-zinc-500" /> Rule Updates
          <Badge variant="outline" className="ml-1 border-zinc-300 font-mono text-[10px] text-zinc-500 dark:border-zinc-700">
            {s.source}
          </Badge>
        </CardTitle>
        <CardDescription>Suricata-update scheduling — "Run update now" attempts a real host refresh when suricata-update + the OS gate allow it.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid gap-3 md:grid-cols-3">
          <div className="flex items-center justify-between rounded-md border border-zinc-200 px-3 py-2 dark:border-zinc-800">
            <span className="text-xs font-medium">Auto-update</span>
            <Switch
              checked={effEnabled}
              aria-label="Toggle auto update"
              onCheckedChange={(v) => setEnabled(v)}
            />
          </div>
          <div>
            <FieldLabel>Interval</FieldLabel>
            <RadioGroup value={effInterval} onValueChange={(v) => setInterval(v as "daily" | "weekly")} className="flex gap-4">
              <Label htmlFor="upd-daily" className="flex cursor-pointer items-center gap-1.5 text-xs">
                <RadioGroupItem id="upd-daily" value="daily" /> daily
              </Label>
              <Label htmlFor="upd-weekly" className="flex cursor-pointer items-center gap-1.5 text-xs">
                <RadioGroupItem id="upd-weekly" value="weekly" /> weekly
              </Label>
            </RadioGroup>
          </div>
          <div>
            <FieldLabel hint="HH:MM">Time</FieldLabel>
            <Input value={effTime} onChange={(e) => setTime(e.target.value)} placeholder="03:00" className="h-8 w-28 font-mono text-xs" />
          </div>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-zinc-200 pt-3 dark:border-zinc-800">
          <div className="flex flex-wrap gap-x-6 gap-y-1 text-xs text-zinc-500">
            <span>
              Last update: <span className="font-mono text-zinc-700 dark:text-zinc-300">{fmtDateTime(s.lastUpdateAt)}</span>
            </span>
            <span>
              Next update:{" "}
              <span className="font-mono text-zinc-700 dark:text-zinc-300">
                {s.enabled ? `${fmtDateTime(s.nextUpdateAt)} (${fmtRelative(s.nextUpdateAt)})` : "—"}
              </span>
            </span>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => runMut.mutate()} disabled={runMut.isPending} className="gap-1.5">
              <Icons.Play className="h-3.5 w-3.5" /> {runMut.isPending ? "Updating…" : "Run update now"}
            </Button>
            <Button size="sm" onClick={() => saveMut.mutate()} disabled={saveMut.isPending || !dirty} className="gap-1.5">
              <Icons.Save className="h-3.5 w-3.5" /> {saveMut.isPending ? "Saving…" : "Save schedule"}
            </Button>
          </div>
        </div>
        {engineNote ? (
          <p className="text-xs text-zinc-500">
            <span className="font-medium text-zinc-700 dark:text-zinc-300">Engine:</span> {engineNote}
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}
