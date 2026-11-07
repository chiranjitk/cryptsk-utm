"use client";

/**
 * #/web/url-filter — URL Filtering (M16, spec 2.3). Master-detail layout:
 * policy cards (left) with defaults + toggles, per-policy Categories (13-row
 * replace-all table) and Custom lists (block/allow, paste import) tabs, a
 * simulated "Test URL" decision card and a 24h stats strip + recent log table.
 * Theme: allow = blue, block = rose, warn = amber (blue-600 enterprise).
 */

import { useEffect, useMemo, useState } from "react";
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
  LIST_TYPES,
  LOG_ACTIONS,
  MATCH_TYPES,
  RULE_ACTIONS,
  categoryLabel,
  fmtRelative,
  qs,
  urlFilterApi,
  type CategoryRuleDTO,
  type CustomListDTO,
  type ListType,
  type MatchType,
  type PolicyAction,
  type RuleAction,
  type UrlLogAction,
  type UrlPolicyDTO,
} from "./url-filter-api";
import { ConfirmDialog, EmptyBlock, FieldLabel, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";

const POLICIES_KEY = ["url-filter", "policies"] as const;

function invalidateAll(queryClient: ReturnType<typeof useQueryClient>) {
  void queryClient.invalidateQueries({ queryKey: ["url-filter"] });
}

// ── badge recipes (UI_DESIGN_SYSTEM: allow=blue soft, block=rose, warn=amber) ──

const DECISION_CLS: Record<UrlLogAction, string> = {
  allowed: "border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400",
  blocked: "border-transparent bg-rose-600 text-white",
  warned: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
};

const DECISION_ICON: Record<UrlLogAction, React.ComponentType<{ className?: string }>> = {
  allowed: Icons.ShieldCheck,
  blocked: Icons.Ban,
  warned: Icons.TriangleAlert,
};

function DecisionBadge({ decision }: { decision: UrlLogAction }) {
  const Icon = DECISION_ICON[decision] ?? Icons.Globe;
  return (
    <Badge variant="outline" className={`gap-1 font-medium ${DECISION_CLS[decision] ?? ""}`}>
      <Icon className="h-3 w-3" />
      {decision}
    </Badge>
  );
}

function DefaultActionBadge({ action }: { action: PolicyAction }) {
  return (
    <Badge
      variant="outline"
      className={
        action === "block"
          ? "gap-1 border-transparent bg-rose-600 font-medium text-white"
          : "gap-1 border-blue-500/40 bg-blue-500/10 font-medium text-blue-600 dark:text-blue-400"
      }
    >
      {action === "block" ? <Icons.Ban className="h-3 w-3" /> : <Icons.ShieldCheck className="h-3 w-3" />}
      default {action}
    </Badge>
  );
}

function ListTypeBadge({ type }: { type: ListType }) {
  return (
    <Badge
      variant="outline"
      className={
        type === "block"
          ? "border-rose-600/60 bg-transparent text-rose-500"
          : "border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400"
      }
    >
      {type}
    </Badge>
  );
}

function CategoryChip({ category }: { category: string }) {
  return (
    <Badge
      variant="outline"
      className="border-zinc-300 bg-zinc-100 capitalize text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
    >
      {categoryLabel(category)}
    </Badge>
  );
}

// ── policy editor dialog (create + edit) ────────────────────────────────────

function PolicyEditor(props: { policy: UrlPolicyDTO | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = props.policy !== null;
  const [name, setName] = useState(props.policy?.name ?? "");
  const [defaultAction, setDefaultAction] = useState<PolicyAction>(props.policy?.defaultAction ?? "allow");
  const [safeSearchEnforce, setSafeSearch] = useState(props.policy?.safeSearchEnforce ?? true);
  const [httpsInspection, setHttpsInspection] = useState(props.policy?.httpsInspection ?? false);
  const [transparentProxy, setTransparentProxy] = useState(props.policy?.transparentProxy ?? true);
  const [enabled, setEnabled] = useState(props.policy?.enabled ?? true);
  const [fileTypes, setFileTypes] = useState((props.policy?.fileTypesBlocked ?? []).join(", "));
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => {
      const id = props.policy?.id;
      if (isEdit && id !== undefined) return urlFilterApi.updatePolicy(id, body);
      return urlFilterApi.createPolicy(body);
    },
    onSuccess: (p) => {
      toastOk(isEdit ? "Policy updated" : "Policy created", p.name);
      invalidateAll(queryClient);
      props.onClose();
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Save failed"),
  });

  const submit = () => {
    const tokens = fileTypes
      .split(/[,\s]+/)
      .map((t) => t.trim().toLowerCase())
      .filter((t) => t.length > 0);
    const bad = tokens.find((t) => !/^[a-z0-9]{1,10}$/.test(t));
    if (!name.trim()) {
      setErr("Name is required");
      return;
    }
    if (bad) {
      setErr(`Invalid file type "${bad}" — use short lowercase extensions like exe`);
      return;
    }
    if (tokens.length > 20) {
      setErr("At most 20 file types");
      return;
    }
    setErr(null);
    save.mutate({
      name: name.trim(),
      defaultAction,
      safeSearchEnforce,
      httpsInspection,
      transparentProxy,
      enabled,
      fileTypesBlocked: [...new Set(tokens)],
    });
  };

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-base">{isEdit ? "Edit policy" : "New URL filter policy"}</DialogTitle>
          <DialogDescription>
            Default action applies when no category rule, custom list or file-type rule matches.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div>
            <FieldLabel>Name</FieldLabel>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Corporate Web Filter" />
          </div>
          <div>
            <FieldLabel hint="used when nothing else matches">Default action</FieldLabel>
            <Select value={defaultAction} onValueChange={(v) => setDefaultAction(v as PolicyAction)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="allow">allow</SelectItem>
                <SelectItem value="block">block</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <FieldLabel hint="comma-separated, max 20">Blocked file types</FieldLabel>
            <Input
              value={fileTypes}
              onChange={(e) => setFileTypes(e.target.value)}
              placeholder="exe, bat, scr, js"
              className="font-mono text-xs"
            />
          </div>
          <div className="grid gap-3 rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
            {(
              [
                ["Enforce SafeSearch", safeSearchEnforce, setSafeSearch],
                ["HTTPS inspection", httpsInspection, setHttpsInspection],
                ["Transparent proxy", transparentProxy, setTransparentProxy],
                ["Policy enabled", enabled, setEnabled],
              ] as Array<[string, boolean, (v: boolean) => void]>
            ).map(([label, value, set]) => (
              <div key={label} className="flex items-center justify-between gap-4">
                <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">{label}</span>
                <Switch checked={value} onCheckedChange={set} aria-label={label} />
              </div>
            ))}
          </div>
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button
            className="bg-blue-600 text-white hover:bg-blue-700"
            disabled={save.isPending || !name.trim()}
            onClick={submit}
          >
            {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create policy"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── categories tab (13 rows, replace-all on change) ─────────────────────────

function CategoriesTab({ policyId }: { policyId: number }) {
  const queryClient = useQueryClient();
  const rulesQuery = useQuery({
    queryKey: ["url-filter", "rules", policyId],
    queryFn: () => urlFilterApi.listCategoryRules(policyId),
  });

  // local draft for snappy inline edits; keyed by server rows so new data resets it
  const [draftState, setDraftState] = useState<{ key: unknown; draft: CategoryRuleDTO[] | null }>({
    key: null,
    draft: null,
  });
  const draft = draftState.key === rulesQuery.data ? draftState.draft : null;
  const rules = draft ?? rulesQuery.data ?? [];
  const setDraft = (d: CategoryRuleDTO[] | null) => setDraftState({ key: rulesQuery.data, draft: d });

  const save = useMutation({
    mutationFn: (next: CategoryRuleDTO[]) =>
      urlFilterApi.replaceCategoryRules(
        policyId,
        next.map((r) => ({ category: r.category, action: r.action, listSource: r.listSource, enabled: r.enabled })),
      ),
    onMutate: (next) => setDraft(next),
    onSuccess: (server) => {
      setDraft(server);
      invalidateAll(queryClient);
    },
    onError: (e) => {
      setDraft(null);
      toastErr(e, "Saving category rules failed");
    },
  });

  const update = (category: string, patch: Partial<CategoryRuleDTO>) => {
    const next = rules.map((r) => (r.category === category ? { ...r, ...patch } : r));
    if (next.length > 0) save.mutate(next);
  };

  return (
    <div className="max-h-96 overflow-y-auto">
      {rulesQuery.isError ? (
        <div className="p-4">
          <QueryError error={rulesQuery.error} onRetry={() => void rulesQuery.refetch()} />
        </div>
      ) : rulesQuery.isLoading ? (
        <TableSkeleton rows={6} cols={4} />
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Category</TableHead>
              <TableHead className="w-32">Action</TableHead>
              <TableHead className="w-20">Enabled</TableHead>
              <TableHead className="w-28 text-right">Source</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rules.map((rule) => (
              <TableRow key={rule.category} className={rule.enabled ? undefined : "opacity-70"}>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <span className="text-sm capitalize">{categoryLabel(rule.category)}</span>
                    {!rule.configured && (
                      <span className="text-[10px] uppercase text-zinc-400">not configured</span>
                    )}
                  </div>
                </TableCell>
                <TableCell>
                  <Select
                    value={rule.action}
                    onValueChange={(v) => update(rule.category, { action: v as RuleAction })}
                  >
                    <SelectTrigger className="h-8 w-28" aria-label={`Action for ${rule.category}`}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {RULE_ACTIONS.map((a) => (
                        <SelectItem key={a} value={a}>
                          {a}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </TableCell>
                <TableCell>
                  <Switch
                    checked={rule.enabled}
                    onCheckedChange={(enabled) => update(rule.category, { enabled })}
                    aria-label={`Toggle ${rule.category}`}
                  />
                </TableCell>
                <TableCell className="text-right">
                  <span className="text-[11px] uppercase text-zinc-400">{rule.listSource}</span>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      {save.isPending && (
        <p className="border-t border-zinc-200 px-4 py-2 text-[11px] text-zinc-400 dark:border-zinc-800">
          Saving rule set…
        </p>
      )}
    </div>
  );
}

// ── custom lists tab ────────────────────────────────────────────────────────

function AddListEntryDialog(props: { policyId: number; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [listType, setListType] = useState<ListType>("block");
  const [matchType, setMatchType] = useState<MatchType>("domain");
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: () =>
      urlFilterApi.createCustomList({ policyId: props.policyId, listType, matchType, value: value.trim(), note: note.trim() || null }),
    onSuccess: (created) => {
      toastOk("Entry added", created.value);
      invalidateAll(queryClient);
      props.onClose();
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Save failed"),
  });

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-base">Add list entry</DialogTitle>
          <DialogDescription>Domain, wildcard (*.example.com) or absolute http(s) URL.</DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel>List</FieldLabel>
              <Select value={listType} onValueChange={(v) => setListType(v as ListType)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {LIST_TYPES.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel>Match type</FieldLabel>
              <Select value={matchType} onValueChange={(v) => setMatchType(v as MatchType)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {MATCH_TYPES.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div>
            <FieldLabel>Value</FieldLabel>
            <Input
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder={matchType === "url" ? "https://bad.example/path" : matchType === "wildcard" ? "*.gambling-cdn.example" : "badsite.example"}
              className="font-mono text-xs"
            />
          </div>
          <div>
            <FieldLabel hint="optional">Note</FieldLabel>
            <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Why this entry exists…" />
          </div>
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button
            className="bg-blue-600 text-white hover:bg-blue-700"
            disabled={save.isPending || !value.trim()}
            onClick={() => save.mutate()}
          >
            {save.isPending ? "Saving…" : "Add entry"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ImportListDialog(props: { policyId: number; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [listType, setListType] = useState<ListType>("block");
  const [text, setText] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const run = useMutation({
    mutationFn: () => urlFilterApi.importCustomLists({ policyId: props.policyId, listType, text }),
    onSuccess: (r) => {
      toastOk(`Imported ${r.created} entr${r.created === 1 ? "y" : "ies"}`, `${r.skipped} skipped (blank, invalid or duplicate)`);
      invalidateAll(queryClient);
      props.onClose();
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Import failed"),
  });

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-base">Import list</DialogTitle>
          <DialogDescription>
            One value per line — blanks, #comments, invalid and duplicate rows are skipped (max 500 per import).
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div>
            <FieldLabel>Target list</FieldLabel>
            <Select value={listType} onValueChange={(v) => setListType(v as ListType)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {LIST_TYPES.map((t) => (
                  <SelectItem key={t} value={t}>
                    {t}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <FieldLabel hint="newline-separated">Values</FieldLabel>
            <Textarea
              rows={8}
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder={"badsite.example\n*.trackers.example\nhttps://phish.example/login"}
              className="font-mono text-xs"
            />
          </div>
          {err && <p className="text-xs text-rose-600">{err}</p>}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={props.onClose}>
            Cancel
          </Button>
          <Button
            className="bg-blue-600 text-white hover:bg-blue-700"
            disabled={run.isPending || !text.trim()}
            onClick={() => run.mutate()}
          >
            {run.isPending ? "Importing…" : <><Icons.Upload className="mr-1 h-3.5 w-3.5" /> Import</>}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function CustomListsTab({ policyId }: { policyId: number }) {
  const queryClient = useQueryClient();
  const [listType, setListType] = useState<"all" | ListType>("all");
  const [addOpen, setAddOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [deleting, setDeleting] = useState<CustomListDTO | null>(null);

  const params = useMemo(() => qs({ policyId, listType: listType === "all" ? undefined : listType }), [policyId, listType]);
  const listsQuery = useQuery({
    queryKey: ["url-filter", "lists", params],
    queryFn: () => urlFilterApi.listCustomLists(params),
  });
  const rows = listsQuery.data ?? [];

  const del = useMutation({
    mutationFn: (id: number) => urlFilterApi.deleteCustomList(id),
    onSuccess: () => {
      toastOk("Entry deleted");
      setDeleting(null);
      invalidateAll(queryClient);
    },
    onError: (e) => toastErr(e, "Delete failed"),
  });

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 border-b border-zinc-200 p-4 dark:border-zinc-800">
        <Select value={listType} onValueChange={(v) => setListType(v as "all" | ListType)}>
          <SelectTrigger className="h-8 w-36" aria-label="List type filter">
            <SelectValue placeholder="All lists" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All lists</SelectItem>
            {LIST_TYPES.map((t) => (
              <SelectItem key={t} value={t}>
                {t} only
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <span className="text-xs text-zinc-400">{rows.length} entries</span>
        <div className="ml-auto flex items-center gap-2">
          <Button variant="outline" size="sm" className="h-8 gap-1 text-xs" onClick={() => setImportOpen(true)}>
            <Icons.Upload className="h-3.5 w-3.5" /> Import list
          </Button>
          <Button size="sm" className="h-8 bg-blue-600 text-white hover:bg-blue-700" onClick={() => setAddOpen(true)}>
            <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add
          </Button>
        </div>
      </div>

      {listsQuery.isError ? (
        <div className="p-4">
          <QueryError error={listsQuery.error} onRetry={() => void listsQuery.refetch()} />
        </div>
      ) : listsQuery.isLoading ? (
        <TableSkeleton rows={4} cols={6} />
      ) : rows.length === 0 ? (
        <EmptyBlock
          icon={<Icons.ListFilter className="h-6 w-6" />}
          title="No custom list entries"
          description="Add entries one by one or paste a list to tune this policy beyond the category feeds."
        />
      ) : (
        <div className="max-h-96 overflow-y-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Value</TableHead>
                <TableHead className="w-24">Match</TableHead>
                <TableHead className="w-20">List</TableHead>
                <TableHead className="max-w-40">Note</TableHead>
                <TableHead className="w-24">Added</TableHead>
                <TableHead className="w-16 text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((entry) => (
                <TableRow key={entry.id}>
                  <TableCell className="max-w-72">
                    <span className="block truncate font-mono text-xs" title={entry.value}>
                      {entry.value}
                    </span>
                  </TableCell>
                  <TableCell className="text-xs text-zinc-500">{entry.matchType}</TableCell>
                  <TableCell>
                    <ListTypeBadge type={entry.listType} />
                  </TableCell>
                  <TableCell className="max-w-40">
                    <span className="block truncate text-xs text-zinc-500" title={entry.note ?? undefined}>
                      {entry.note ?? "—"}
                    </span>
                  </TableCell>
                  <TableCell className="whitespace-nowrap text-xs text-zinc-500">{fmtRelative(entry.createdAt)}</TableCell>
                  <TableCell>
                    <div className="flex justify-end">
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7 text-rose-500 hover:text-rose-600"
                        aria-label={`Delete ${entry.value}`}
                        onClick={() => setDeleting(entry)}
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

      {addOpen && <AddListEntryDialog policyId={policyId} onClose={() => setAddOpen(false)} />}
      {importOpen && <ImportListDialog policyId={policyId} onClose={() => setImportOpen(false)} />}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete ${deleting?.value ?? ""}?`}
        description="The entry is removed from this policy's matching immediately."
        loading={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting.id)}
      />
    </div>
  );
}

// ── test URL card ───────────────────────────────────────────────────────────

function TestUrlCard({ policy }: { policy: UrlPolicyDTO }) {
  const queryClient = useQueryClient();
  const [url, setUrl] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const run = useMutation({
    mutationFn: () => urlFilterApi.testUrl(policy.id, url.trim()),
    onSuccess: (r) => {
      setErr(null);
      invalidateAll(queryClient); // test persists a log row + shifts stats
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Test failed"),
  });

  const result = run.data;

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.Globe className="h-4 w-4 text-blue-600 dark:text-blue-400" />
          Test URL
          <span className="text-xs font-normal text-zinc-400">simulated decision for “{policy.name}”</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 p-4 pt-0">
        <div className="flex flex-col gap-2 sm:flex-row">
          <div className="relative flex-1">
            <Icons.Link2 className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-400" />
            <Input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && url.trim()) run.mutate();
              }}
              placeholder="https://gamble-site.net/play"
              className="pl-8 font-mono text-xs"
              aria-label="URL to test"
            />
          </div>
          <Button
            className="h-9 bg-blue-600 px-5 text-white hover:bg-blue-700"
            disabled={run.isPending || !url.trim()}
            onClick={() => run.mutate()}
          >
            {run.isPending ? <Icons.Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" /> : <Icons.Play className="mr-1 h-3.5 w-3.5" />}
            Run
          </Button>
        </div>

        {err && <p className="text-xs text-rose-600">{err}</p>}

        {result && (
          <div className="flex flex-wrap items-center gap-2 rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
            <DecisionBadge decision={result.decision} />
            <Badge variant="outline" className="border-zinc-300 font-mono text-[11px] text-zinc-600 dark:border-zinc-700 dark:text-zinc-300">
              reason: {result.reason}
            </Badge>
            {result.category && <CategoryChip category={result.category} />}
            <span className="text-[11px] text-zinc-400">logged to URL filter logs</span>
          </div>
        )}

        {!result && !err && (
          <p className="text-xs text-zinc-400">
            Try gamble-site.net, phishing-login.example, malware-cdn.xyz, a search with ?q=… or an .exe download.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

// ── stats strip + logs ──────────────────────────────────────────────────────

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
  const statsQuery = useQuery({ queryKey: ["url-filter", "stats"], queryFn: urlFilterApi.getStats });
  const stats = statsQuery.data;

  return (
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <StatCard
        label="Allowed (24h)"
        value={stats?.allowed24h ?? "—"}
        tone="text-blue-600 dark:text-blue-400"
        icon={<Icons.ShieldCheck className="h-4 w-4" />}
      />
      <StatCard
        label="Blocked (24h)"
        value={stats?.blocked24h ?? "—"}
        tone="text-rose-500"
        icon={<Icons.Ban className="h-4 w-4" />}
      />
      <StatCard
        label="Warned (24h)"
        value={stats?.warned24h ?? "—"}
        tone="text-amber-500"
        icon={<Icons.TriangleAlert className="h-4 w-4" />}
      />
      <Card>
        <CardContent className="p-4">
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-medium text-zinc-500">Top blocked (24h)</span>
            <Icons.TrendingDown className="h-4 w-4 text-rose-500" />
          </div>
          {stats && stats.topBlocked.length > 0 ? (
            <ul className="mt-2 space-y-1">
              {stats.topBlocked.map((t) => (
                <li key={t.domain} className="flex items-center justify-between gap-2 text-xs">
                  <span className="truncate font-mono text-zinc-600 dark:text-zinc-300" title={t.domain}>
                    {t.domain}
                  </span>
                  <span className="shrink-0 font-semibold tabular-nums text-rose-500">{t.count}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-2 text-xs text-zinc-400">No blocked domains in the last 24h</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function LogsCard() {
  const queryClient = useQueryClient();
  const [action, setAction] = useState<"all" | UrlLogAction>("all");

  const params = useMemo(() => qs({ limit: 25, action: action === "all" ? undefined : action }), [action]);
  const logsQuery = useQuery({
    queryKey: ["url-filter", "logs", params],
    queryFn: () => urlFilterApi.listLogs(params),
    refetchInterval: 15_000,
  });
  const rows = logsQuery.data?.data ?? [];
  const meta = logsQuery.data?.meta;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icons.ScrollText className="h-4 w-4 text-blue-600 dark:text-blue-400" />
          Recent URL filter activity
        </CardTitle>
        <div className="flex items-center gap-2">
          <Select
            value={action}
            onValueChange={(v) => {
              setAction(v as "all" | UrlLogAction);
              void queryClient.invalidateQueries({ queryKey: ["url-filter", "logs"] });
            }}
          >
            <SelectTrigger className="h-8 w-32" aria-label="Action filter">
              <SelectValue placeholder="All actions" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All actions</SelectItem>
              {LOG_ACTIONS.map((a) => (
                <SelectItem key={a} value={a}>
                  {a}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button variant="ghost" size="icon" className="h-8 w-8" aria-label="Refresh logs" onClick={() => void logsQuery.refetch()}>
            <Icons.RefreshCw className={`h-3.5 w-3.5 ${logsQuery.isFetching ? "animate-spin" : ""}`} />
          </Button>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        {logsQuery.isError ? (
          <div className="p-4">
            <QueryError error={logsQuery.error} onRetry={() => void logsQuery.refetch()} />
          </div>
        ) : logsQuery.isLoading ? (
          <TableSkeleton rows={5} cols={6} />
        ) : rows.length === 0 ? (
          <EmptyBlock
            icon={<Icons.ScrollText className="h-6 w-6" />}
            title="No log entries"
            description="Run a URL test or wait for appliance traffic to populate the log."
          />
        ) : (
          <div className="max-h-96 overflow-y-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-24">Action</TableHead>
                  <TableHead>URL / domain</TableHead>
                  <TableHead className="w-28">Category</TableHead>
                  <TableHead className="w-28">Reason</TableHead>
                  <TableHead className="w-32">Client IP</TableHead>
                  <TableHead className="w-24 text-right">Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((log) => (
                  <TableRow key={log.id}>
                    <TableCell>
                      <DecisionBadge decision={log.action} />
                    </TableCell>
                    <TableCell className="max-w-80">
                      <span className="block truncate font-mono text-xs" title={log.url}>
                        {log.domain}
                      </span>
                      <span className="block truncate text-[10px] text-zinc-400" title={log.url}>
                        {log.method} {log.url}
                      </span>
                    </TableCell>
                    <TableCell>
                      <CategoryChip category={log.category} />
                    </TableCell>
                    <TableCell className="font-mono text-xs text-zinc-500">{log.reason}</TableCell>
                    <TableCell className="font-mono text-xs text-zinc-500">{log.clientIp}</TableCell>
                    <TableCell className="whitespace-nowrap text-right text-xs text-zinc-500">
                      {fmtRelative(log.createdAt)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
        {meta && meta.total > 0 && (
          <p className="border-t border-zinc-200 px-4 py-2 text-[11px] text-zinc-400 dark:border-zinc-800">
            {rows.length} of {meta.total} log entries (newest first)
          </p>
        )}
      </CardContent>
    </Card>
  );
}

// ── policy master list (left column) ────────────────────────────────────────

function PolicyCard(props: {
  policy: UrlPolicyDTO;
  selected: boolean;
  onSelect: () => void;
  onEdit: () => void;
  onDelete: () => void;
  onToggle: (enabled: boolean) => void;
  toggling: boolean;
}) {
  const { policy } = props;
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={props.onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          props.onSelect();
        }
      }}
      aria-pressed={props.selected}
      className={`w-full cursor-pointer rounded-xl border p-4 text-left transition-colors ${
        props.selected
          ? "border-blue-500/50 bg-blue-500/5 ring-1 ring-blue-500/30"
          : "border-zinc-200 hover:bg-zinc-50 dark:border-zinc-800 dark:hover:bg-zinc-800/50"
      }`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="truncate text-sm font-semibold">{policy.name}</p>
          <div className="mt-1.5">
            <DefaultActionBadge action={policy.defaultAction} />
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-1">
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 text-zinc-400 hover:text-blue-600"
            aria-label={`Edit ${policy.name}`}
            onClick={(e) => {
              e.stopPropagation();
              props.onEdit();
            }}
          >
            <Icons.Pencil className="h-3.5 w-3.5" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 text-zinc-400 hover:text-rose-600"
            aria-label={`Delete ${policy.name}`}
            onClick={(e) => {
              e.stopPropagation();
              props.onDelete();
            }}
          >
            <Icons.Trash2 className="h-3.5 w-3.5" />
          </Button>
          <span onClick={(e) => e.stopPropagation()} className="pl-0.5">
            <Switch
              checked={policy.enabled}
              disabled={props.toggling}
              onCheckedChange={props.onToggle}
              aria-label={`Toggle ${policy.name}`}
            />
          </span>
        </div>
      </div>

      <div className="mt-3 flex flex-wrap gap-1.5">
        {policy.safeSearchEnforce && (
          <Badge variant="outline" className="border-blue-500/40 bg-blue-500/10 text-[10px] text-blue-600 dark:text-blue-400">
            safe-search
          </Badge>
        )}
        {policy.httpsInspection && (
          <Badge variant="outline" className="border-blue-500/40 bg-blue-500/10 text-[10px] text-blue-600 dark:text-blue-400">
            https-inspect
          </Badge>
        )}
        {policy.transparentProxy && (
          <Badge variant="outline" className="border-zinc-300 text-[10px] text-zinc-500 dark:border-zinc-700 dark:text-zinc-400">
            transparent
          </Badge>
        )}
        {policy.fileTypesBlocked.map((ext) => (
          <Badge key={ext} variant="outline" className="border-rose-600/40 bg-transparent font-mono text-[10px] text-rose-500">
            .{ext}
          </Badge>
        ))}
      </div>

      <p className="mt-2 text-[11px] text-zinc-400">
        {policy.ruleCount} category rules · {policy.customListCount} custom entries
      </p>
    </div>
  );
}

// ── main view ───────────────────────────────────────────────────────────────

export function UrlFilterView() {
  const queryClient = useQueryClient();
  const policiesQuery = useQuery({ queryKey: POLICIES_KEY, queryFn: urlFilterApi.listPolicies });
  const policies = policiesQuery.data ?? [];

  const [selectedId, setSelectedId] = useState<number | null>(null);
  const selected = policies.find((p) => p.id === selectedId) ?? policies[0] ?? null;

  const [addOpen, setAddOpen] = useState(false);
  const [editing, setEditing] = useState<UrlPolicyDTO | null>(null);
  const [deleting, setDeleting] = useState<UrlPolicyDTO | null>(null);

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => urlFilterApi.updatePolicy(id, { enabled }),
    onSuccess: () => invalidateAll(queryClient),
    onError: (e) => toastErr(e, "Toggle failed"),
  });

  const del = useMutation({
    mutationFn: (id: number) => urlFilterApi.deletePolicy(id),
    onSuccess: () => {
      toastOk("Policy deleted");
      setDeleting(null);
      setSelectedId(null);
      invalidateAll(queryClient);
    },
    onError: (e) => toastErr(e, "Delete failed"),
  });

  return (
    <div className="space-y-4">
      <StatsStrip />

      <div className="grid items-start gap-4 lg:grid-cols-[340px_1fr]">
        {/* master list */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm">Policies</CardTitle>
            <Button
              size="sm"
              className="h-8 bg-blue-600 text-white hover:bg-blue-700"
              onClick={() => setAddOpen(true)}
            >
              <Icons.Plus className="mr-1 h-3.5 w-3.5" /> Add
            </Button>
          </CardHeader>
          <CardContent className="p-4 pt-0">
            {policiesQuery.isError ? (
              <QueryError error={policiesQuery.error} onRetry={() => void policiesQuery.refetch()} />
            ) : policiesQuery.isLoading ? (
              <div className="space-y-3">
                {Array.from({ length: 2 }).map((_, i) => (
                  <div key={i} className="h-28 animate-pulse rounded-xl bg-zinc-100 dark:bg-zinc-800" />
                ))}
              </div>
            ) : policies.length === 0 ? (
              <EmptyBlock
                icon={<Icons.Shield className="h-6 w-6" />}
                title="No policies yet"
                description="Create a URL filter policy to control web access rules."
                action={
                  <Button size="sm" className="bg-blue-600 text-white hover:bg-blue-700" onClick={() => setAddOpen(true)}>
                    <Icons.Plus className="mr-1 h-3.5 w-3.5" /> New policy
                  </Button>
                }
              />
            ) : (
              <div className="max-h-96 space-y-3 overflow-y-auto pr-1">
                {policies.map((policy) => (
                  <PolicyCard
                    key={policy.id}
                    policy={policy}
                    selected={selected?.id === policy.id}
                    onSelect={() => setSelectedId(policy.id)}
                    onEdit={() => {
                      setSelectedId(policy.id);
                      setEditing(policy);
                    }}
                    onDelete={() => setDeleting(policy)}
                    onToggle={(enabled) => toggle.mutate({ id: policy.id, enabled })}
                    toggling={toggle.isPending && toggle.variables?.id === policy.id}
                  />
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* detail */}
        <div className="space-y-4">
          {selected ? (
            <>
              <Card>
                <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2 space-y-0 pb-2">
                  <CardTitle className="flex items-center gap-2 text-sm">
                    <Icons.Shield className="h-4 w-4 text-blue-600 dark:text-blue-400" />
                    {selected.name}
                    {!selected.enabled && (
                      <Badge variant="outline" className="border-zinc-300 text-[10px] uppercase text-zinc-400 dark:border-zinc-700">
                        disabled
                      </Badge>
                    )}
                  </CardTitle>
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-8 gap-1 text-xs"
                    onClick={() => setEditing(selected)}
                  >
                    <Icons.Pencil className="h-3.5 w-3.5" /> Edit
                  </Button>
                </CardHeader>
                <CardContent className="p-0">
                  <Tabs defaultValue="categories">
                    <TabsList className="mx-4 mt-1">
                      <TabsTrigger value="categories">Categories</TabsTrigger>
                      <TabsTrigger value="lists">Custom lists</TabsTrigger>
                    </TabsList>
                    <TabsContent value="categories" className="mt-0">
                      <CategoriesTab key={`rules-${selected.id}`} policyId={selected.id} />
                    </TabsContent>
                    <TabsContent value="lists" className="mt-0">
                      <CustomListsTab key={`lists-${selected.id}`} policyId={selected.id} />
                    </TabsContent>
                  </Tabs>
                </CardContent>
              </Card>

              <TestUrlCard key={`test-${selected.id}`} policy={selected} />
            </>
          ) : (
            !policiesQuery.isLoading &&
            !policiesQuery.isError && (
              <Card>
                <CardContent className="p-0">
                  <EmptyBlock
                    icon={<Icons.Shield className="h-6 w-6" />}
                    title="No policy selected"
                    description="Select or create a policy to manage its category rules and custom lists."
                  />
                </CardContent>
              </Card>
            )
          )}
        </div>
      </div>

      <LogsCard />

      {addOpen && <PolicyEditor policy={null} onClose={() => setAddOpen(false)} />}
      {editing && <PolicyEditor policy={editing} onClose={() => setEditing(null)} />}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete policy “${deleting?.name ?? ""}”?`}
        description="Its category rules and custom lists are removed too. Existing log rows are kept."
        loading={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting.id)}
      />
    </div>
  );
}
