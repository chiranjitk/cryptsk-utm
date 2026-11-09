"use client";

/**
 * #/threat-intel/feeds — threat feed subscriptions (M13 §2.11 tab 1).
 * Card grid per feed: provider/format/category/interval, enabled switch
 * (PUT), simulated "Sync now" ingestion (POST /sync → corpus replay),
 * last-sync status pill (ok = blue, error = red, never = zinc) and a
 * stats strip (total IOCs / critical / hits 24h) from /stats.
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { ConfirmDialog, EmptyBlock, FieldLabel, QueryError, toastErr, toastOk } from "../firewall/fw-ui";
import {
  CATEGORIES,
  FORMATS,
  PROVIDERS,
  fmtRelative,
  threatIntelApi,
  type FeedDTO,
  type FeedFormat,
  type FeedProvider,
  type ThreatCategory,
  type ThreatStats,
} from "./threat-intel-api";
import { CategoryChip } from "./ti-ui";

const TI_KEY = ["threat-intel"] as const;
const FEEDS_KEY = ["threat-intel", "feeds"] as const;

const PROVIDER_LABEL: Record<FeedProvider, string> = {
  abusech: "Abuse.ch",
  otx: "AlienVault OTX",
  spamhaus: "Spamhaus",
  custom: "Custom",
};

/** ok = blue, error = red, never = zinc (module rule — no emerald). */
function SyncStatusPill({ status, at }: { status: string; at: string | null }) {
  const cls =
    status === "ok"
      ? "border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-300"
      : status === "error"
        ? "border-zinc-500/40 bg-zinc-500/10 text-zinc-600 dark:text-zinc-400"
        : "border-zinc-300 bg-zinc-100 text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800";
  const label = status === "ok" ? "ok" : status === "error" ? "error" : "never synced";
  return (
    <TooltipProvider delayDuration={100}>
      <Tooltip>
        <TooltipTrigger asChild>
          <Badge variant="outline" className={cn("gap-1 font-medium", cls)}>
            {status === "ok" ? (
              <Icons.CheckCircle2 className="h-3 w-3" />
            ) : status === "error" ? (
              <Icons.CircleX className="h-3 w-3" />
            ) : (
              <Icons.Clock className="h-3 w-3" />
            )}
            {label}
          </Badge>
        </TooltipTrigger>
        <TooltipContent className="text-xs">
          {at ? `Last sync ${fmtRelative(at)}` : "Feed has not been synced yet"}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

// ── feed editor (create + edit) ─────────────────────────────────────────────

function FeedEditor(props: { initial: FeedDTO | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = props.initial !== null;
  const [name, setName] = useState(props.initial?.name ?? "");
  const [provider, setProvider] = useState<FeedProvider>(props.initial?.provider ?? "abusech");
  const [url, setUrl] = useState(props.initial?.url ?? "");
  const [format, setFormat] = useState<FeedFormat>(props.initial?.format ?? "csv");
  const [category, setCategory] = useState<ThreatCategory>((props.initial?.category as ThreatCategory) ?? "botnet");
  const [interval, setIntervalMinutes] = useState(String(props.initial?.intervalMinutes ?? 60));
  const [autoBlock, setAutoBlock] = useState(props.initial?.autoBlock ?? false);
  const [enabled, setEnabled] = useState(props.initial?.enabled ?? true);
  const [err, setErr] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      isEdit ? threatIntelApi.updateFeed(props.initial!.id, body) : threatIntelApi.createFeed(body),
    onSuccess: (saved) => {
      toastOk(`${isEdit ? "Updated" : "Created"} feed "${saved.name}"`);
      void queryClient.invalidateQueries({ queryKey: TI_KEY });
      props.onClose();
    },
    onError: (e) => setErr(e instanceof Error ? e.message : "Save failed"),
  });

  const intervalNum = Number(interval);

  return (
    <Dialog open onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-base">{isEdit ? "Edit feed" : "Add threat feed"}</DialogTitle>
          <DialogDescription>
            Sandbox note — sync replays a built-in sample corpus per provider; the appliance performs the real fetch.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div>
            <FieldLabel>Name</FieldLabel>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Abuse.ch URLhaus" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel>Provider</FieldLabel>
              <Select value={provider} onValueChange={(v) => setProvider(v as FeedProvider)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PROVIDERS.map((p) => (
                    <SelectItem key={p} value={p}>
                      {PROVIDER_LABEL[p]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel>Format</FieldLabel>
              <Select value={format} onValueChange={(v) => setFormat(v as FeedFormat)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {FORMATS.map((f) => (
                    <SelectItem key={f} value={f}>
                      {f.toUpperCase()}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div>
            <FieldLabel hint="https:// or http://">Feed URL</FieldLabel>
            <Input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://urlhaus.abuse.ch/downloads/csv_recent/"
              className="font-mono text-xs"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <FieldLabel>Category</FieldLabel>
              <Select value={category} onValueChange={(v) => setCategory(v as ThreatCategory)}>
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
            <div>
              <FieldLabel hint="5–1440 min">Interval (minutes)</FieldLabel>
              <Input
                type="number"
                min={5}
                max={1440}
                value={interval}
                onChange={(e) => setIntervalMinutes(e.target.value)}
              />
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
            <div className="flex items-center gap-2">
              <Switch id="feed-autoblock" checked={autoBlock} onCheckedChange={setAutoBlock} />
              <Label htmlFor="feed-autoblock" className="text-xs">
                Auto-block new critical IOCs
              </Label>
            </div>
            <div className="flex items-center gap-2">
              <Switch id="feed-enabled" checked={enabled} onCheckedChange={setEnabled} />
              <Label htmlFor="feed-enabled" className="text-xs">
                Enabled
              </Label>
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
            disabled={save.isPending || !name.trim() || !url.trim() || !Number.isFinite(intervalNum) || intervalNum < 5 || intervalNum > 1440}
            onClick={() =>
              save.mutate({
                name: name.trim(),
                provider,
                url: url.trim(),
                format,
                category,
                intervalMinutes: intervalNum,
                autoBlock,
                enabled,
              })
            }
          >
            {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create feed"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── stats strip ─────────────────────────────────────────────────────────────

function StatsStrip({ stats }: { stats: ThreatStats | undefined }) {
  const items: Array<{ label: string; value: number; icon: React.ReactNode; tone?: "red" }> = [
    { label: "Total IOCs", value: stats?.totalIocs ?? 0, icon: <Icons.Database className="h-4 w-4 text-zinc-700 dark:text-zinc-500" /> },
    { label: "Critical", value: stats?.bySeverity.critical ?? 0, icon: <Icons.Siren className="h-4 w-4 text-rose-500" />, tone: "red" },
    { label: "Hits (24h)", value: stats?.hits24h ?? 0, icon: <Icons.Activity className="h-4 w-4 text-zinc-700 dark:text-zinc-500" /> },
    { label: "Active feeds", value: stats?.activeFeeds ?? 0, icon: <Icons.Rss className="h-4 w-4 text-zinc-500 dark:text-zinc-400" /> },
  ];
  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      {items.map((it) => (
        <Card key={it.label} className="p-4">
          <CardContent className="flex items-center gap-3 p-0">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-zinc-500/10">{it.icon}</div>
            <div className="min-w-0">
              <p className={cn("text-xl font-semibold tabular-nums", it.tone === "red" && (it.value ?? 0) > 0 ? "text-zinc-600 dark:text-zinc-400" : undefined)}>
                {it.value.toLocaleString()}
              </p>
              <p className="truncate text-[11px] text-zinc-500">{it.label}</p>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ── main view ───────────────────────────────────────────────────────────────

export function FeedsView() {
  const queryClient = useQueryClient();
  const feedsQuery = useQuery({ queryKey: FEEDS_KEY, queryFn: threatIntelApi.listFeeds });
  const statsQuery = useQuery({ queryKey: ["threat-intel", "stats"], queryFn: threatIntelApi.getStats });

  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<FeedDTO | null>(null);
  const [deleting, setDeleting] = useState<FeedDTO | null>(null);
  const [syncingId, setSyncingId] = useState<number | null>(null);

  const feeds = feedsQuery.data ?? [];

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => threatIntelApi.updateFeed(id, { enabled }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: FEEDS_KEY }),
    onError: (e) => toastErr(e, "Toggle failed"),
  });

  const sync = useMutation({
    mutationFn: (id: number) => {
      setSyncingId(id);
      return threatIntelApi.syncFeed(id);
    },
    onSuccess: (r) => {
      toastOk(
        `${r.entriesApplied} IOCs ingested`,
        `${r.feedName}: ${r.newIocs} new, ${r.updatedIocs} updated` +
          (r.autoBlockCreated > 0 ? `, ${r.autoBlockCreated} auto-block rule(s) created` : ""),
      );
      void queryClient.invalidateQueries({ queryKey: TI_KEY });
    },
    onError: (e) => toastErr(e, "Sync failed"),
    onSettled: () => setSyncingId(null),
  });

  const del = useMutation({
    mutationFn: (id: number) => threatIntelApi.deleteFeed(id),
    onSuccess: () => {
      toastOk("Feed deleted");
      setDeleting(null);
      void queryClient.invalidateQueries({ queryKey: TI_KEY });
    },
    onError: (e) => toastErr(e, "Delete failed"),
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <p className="mr-auto text-xs text-zinc-500">
          Subscriptions to external threat-intel providers. In the sandbox, &quot;Sync now&quot; replays a sample corpus per
          provider — feeds with auto-block create drop rules for new critical IOCs.
        </p>
        <Button
          size="sm"
          className="bg-zinc-700 text-white hover:bg-zinc-800"
          onClick={() => {
            setEditing(null);
            setEditorOpen(true);
          }}
        >
          <Icons.Plus className="mr-1 h-4 w-4" /> Add feed
        </Button>
      </div>

      {feedsQuery.isError ? (
        <QueryError error={feedsQuery.error} onRetry={() => void feedsQuery.refetch()} />
      ) : feedsQuery.isLoading ? (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-52 rounded-xl" />
          ))}
        </div>
      ) : feeds.length === 0 ? (
        <Card className="p-0">
          <CardContent className="p-0">
            <EmptyBlock
              icon={<Icons.Rss className="h-6 w-6" />}
              title="No threat feeds configured"
              description="Add a provider feed (Abuse.ch, OTX, Spamhaus or custom) to start ingesting indicators of compromise."
              action={
                <Button
                  className="bg-zinc-700 text-white hover:bg-zinc-800"
                  onClick={() => {
                    setEditing(null);
                    setEditorOpen(true);
                  }}
                >
                  <Icons.Plus className="mr-1 h-4 w-4" /> Add feed
                </Button>
              }
            />
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {feeds.map((feed) => (
            <Card key={feed.id} className="flex flex-col p-4">
              <CardHeader className="flex-row items-start justify-between space-y-0 p-0 pb-3">
                <div className="min-w-0">
                  <CardTitle className="truncate text-sm font-medium">{feed.name}</CardTitle>
                  <div className="mt-1 flex flex-wrap items-center gap-1.5">
                    <Badge variant="outline" className="border-zinc-500/30 bg-zinc-500/10 text-[10px] font-semibold text-zinc-600 dark:text-zinc-300">
                      {PROVIDER_LABEL[feed.provider] ?? feed.provider}
                    </Badge>
                    <Badge variant="outline" className="border-zinc-300 bg-zinc-100 font-mono text-[10px] uppercase text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
                      {feed.format}
                    </Badge>
                    <CategoryChip category={feed.category} />
                  </div>
                </div>
                <Switch
                  checked={feed.enabled}
                  onCheckedChange={(enabled) => toggle.mutate({ id: feed.id, enabled })}
                  aria-label={`Toggle feed ${feed.name}`}
                />
              </CardHeader>

              <CardContent className="flex flex-1 flex-col gap-3 p-0">
                <p className="truncate font-mono text-[11px] text-zinc-500" title={feed.url}>
                  {feed.url}
                </p>
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-zinc-500">
                  <span className="inline-flex items-center gap-1">
                    <Icons.Timer className="h-3 w-3" /> every {feed.intervalMinutes}m
                  </span>
                  {feed.autoBlock && (
                    <span className="inline-flex items-center gap-1 font-medium text-zinc-700 dark:text-zinc-500">
                      <Icons.ShieldCheck className="h-3 w-3" /> auto-block
                    </span>
                  )}
                </div>

                <div className="mt-auto flex flex-wrap items-center gap-2 border-t border-zinc-200 pt-3 dark:border-zinc-800">
                  <SyncStatusPill status={feed.lastStatus} at={feed.lastSyncAt} />
                  <span className="text-[11px] text-zinc-500">
                    {feed.lastStatus === "never" ? "—" : `${fmtRelative(feed.lastSyncAt)} · ${feed.lastCount} IOCs`}
                  </span>
                  <div className="ml-auto flex items-center gap-1">
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7 gap-1 px-2 text-xs"
                      disabled={sync.isPending}
                      onClick={() => sync.mutate(feed.id)}
                    >
                      <Icons.RefreshCw className={cn("h-3.5 w-3.5", syncingId === feed.id && "animate-spin")} />
                      Sync now
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7"
                      aria-label={`Edit feed ${feed.name}`}
                      onClick={() => {
                        setEditing(feed);
                        setEditorOpen(true);
                      }}
                    >
                      <Icons.Pencil className="h-3.5 w-3.5" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 text-rose-500 hover:text-rose-600"
                      aria-label={`Delete feed ${feed.name}`}
                      onClick={() => setDeleting(feed)}
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

      <StatsStrip stats={statsQuery.data} />

      {editorOpen && <FeedEditor key={editing?.id ?? "new"} initial={editing} onClose={() => setEditorOpen(false)} />}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete feed "${deleting?.name ?? ""}"?`}
        description="The feed subscription is removed. Already-ingested IOCs keep their provenance and hit history."
        loading={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting.id)}
      />
    </div>
  );
}
