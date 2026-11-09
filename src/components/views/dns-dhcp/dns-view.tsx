"use client";

/**
 * DNS Security view (M06 §4) — hash #/dns-dhcp/dns, 4 tabs:
 * Resolver Settings | Policies | Records | Query Log.
 * Deep links via ?tab=… in the hash. Query Log polls every 10 s (no socket
 * event exists for query rows — M06 §6); everything else invalidates on
 * config:updated {section:"dns"}.
 */

import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent } from "@/components/ui/card";
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
import { Textarea } from "@/components/ui/textarea";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Label } from "@/components/ui/label";
import { ConfirmDialog, EditorSection, EmptyBlock, FieldLabel, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";
import {
  dnsApi,
  fieldErrorsOf,
  fmtDateTime,
  humanizeSeconds,
  type DnsPolicyDTO,
  type DnsRecordDTO,
  type ResolverSettingsDTO,
} from "./dns-dhcp-api";
import {
  BlockedBadge,
  CategoryChips,
  InfoNote,
  IpListEditor,
  RecordTypeChip,
  ResultBadge,
  useDnsConfigInvalidation,
} from "./dns-dhcp-ui";
import { cn } from "@/lib/utils";

type TabKey = "settings" | "policies" | "records" | "querylog";

const TABS: Array<{ key: TabKey; label: string }> = [
  { key: "settings", label: "Resolver Settings" },
  { key: "policies", label: "Policies" },
  { key: "records", label: "Records" },
  { key: "querylog", label: "Query Log" },
];

const BLOCK_CATEGORIES = ["ads", "malware", "phishing", "adult", "social", "gambling"] as const;
const RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "PTR"] as const;

function tabFromHash(): TabKey {
  const qs = window.location.hash.split("?")[1];
  const v = new URLSearchParams(qs ?? "").get("tab");
  return TABS.some((t) => t.key === v) ? (v as TabKey) : "settings";
}

export function DnsView() {
  useDnsConfigInvalidation();
  const [tab, setTab] = useState<TabKey>(() => tabFromHash());
  useEffect(() => {
    // keep the tab deep-linkable without retriggering hashchange
    history.replaceState(null, "", `#/dns-dhcp/dns?tab=${tab}`);
  }, [tab]);

  return (
    <Tabs value={tab} onValueChange={(v) => setTab(v as TabKey)}>
      <TabsList className="flex w-full flex-wrap justify-start gap-1 sm:w-auto">
        {TABS.map((t) => (
          <TabsTrigger key={t.key} value={t.key} className="text-xs sm:text-sm">
            {t.label}
          </TabsTrigger>
        ))}
      </TabsList>
      <TabsContent value="settings" className="mt-3 space-y-3">
        <ResolverSettingsTab />
      </TabsContent>
      <TabsContent value="policies" className="mt-3 space-y-3">
        <PoliciesTab />
      </TabsContent>
      <TabsContent value="records" className="mt-3 space-y-3">
        <RecordsTab />
      </TabsContent>
      <TabsContent value="querylog" className="mt-3 space-y-3">
        <QueryLogTab />
      </TabsContent>
    </Tabs>
  );
}

// ── Resolver Settings ───────────────────────────────────────────────────────

type ForwardZoneRow = { domain: string; server: string; port: string };

function ResolverSettingsTab() {
  const q = useQuery({ queryKey: ["dns", "settings"], queryFn: dnsApi.getSettings });

  if (q.isLoading) {
    return (
      <Card>
        <CardContent className="space-y-3 pt-6">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-9 w-full animate-pulse rounded-md bg-zinc-100 dark:bg-zinc-800" />
          ))}
        </CardContent>
      </Card>
    );
  }
  if (q.isError) return <QueryError error={q.error} onRetry={() => void q.refetch()} />;
  if (!q.data) return null;
  return <ResolverForm key={q.dataUpdatedAt} initial={q.data} />;
}

function ResolverForm({ initial }: { initial: ResolverSettingsDTO }) {
  const queryClient = useQueryClient();
  const [forwarders, setForwarders] = useState<string[]>(initial.forwarders);
  const [cacheSizeMb, setCacheSizeMb] = useState(String(initial.cacheSizeMb));
  const [rrl, setRrl] = useState(initial.rrl);
  const [dot, setDot] = useState(initial.dot);
  const [zones, setZones] = useState<ForwardZoneRow[]>(
    initial.forwardZones.map((z) => ({ domain: z.domain, server: z.server, port: z.port ? String(z.port) : "" })),
  );
  const [dohEnabled, setDohEnabled] = useState(initial.doh.enabled);
  const [dohPort, setDohPort] = useState(String(initial.doh.port));
  const [serverErrors, setServerErrors] = useState<Record<string, string[]>>({});

  const save = useMutation({
    mutationFn: () =>
      dnsApi.putSettings({
        forwarders,
        cacheSizeMb: Number(cacheSizeMb) || 0,
        rrl,
        dot,
        forwardZones: zones
          .filter((z) => z.domain.trim() && z.server.trim())
          .map((z) => ({ domain: z.domain.trim(), server: z.server.trim(), ...(z.port ? { port: Number(z.port) } : {}) })),
        doh: { enabled: dohEnabled, port: Number(dohPort) || 443 },
      }),
    onSuccess: () => {
      setServerErrors({});
      toastOk("Resolver settings applied", "DNS configuration saved");
      void queryClient.invalidateQueries({ queryKey: ["dns"] });
    },
    onError: (err) => {
      setServerErrors(fieldErrorsOf(err));
      toastErr(err, "Save failed");
    },
  });

  const err = (path: string) => serverErrors[path]?.join("; ");

  return (
    <Card>
      <CardContent className="space-y-5 pt-6">
        <EditorSection title="Default forwarders">
          <IpListEditor values={forwarders} onChange={setForwarders} placeholder="e.g. 9.9.9.9" addLabel="Add forwarder" />
          {err("forwarders") && <p className="text-[11px] text-rose-500">{err("forwarders")}</p>}
        </EditorSection>

        <div className="grid gap-5 lg:grid-cols-2">
          <EditorSection title="Cache">
            <FieldLabel hint="16–4096 MB">Cache size (MB)</FieldLabel>
            <Input
              type="number"
              className="h-9 w-32 font-mono text-xs"
              value={cacheSizeMb}
              onChange={(e) => setCacheSizeMb(e.currentTarget.value)}
              aria-label="Cache size in MB"
            />
            {err("cacheSizeMb") && <p className="text-[11px] text-rose-500">{err("cacheSizeMb")}</p>}
          </EditorSection>
          <EditorSection title="Protection toggles">
            <label className="flex items-center justify-between gap-3">
              <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Response rate limiting (RRL)</span>
              <Switch checked={rrl} onCheckedChange={setRrl} aria-label="Toggle RRL" />
            </label>
            <label className="flex items-center justify-between gap-3">
              <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">DNS over TLS (DoT)</span>
              <Switch checked={dot} onCheckedChange={setDot} aria-label="Toggle DoT" />
            </label>
            <InfoNote>
              Display-only in sandbox; Unbound DoT termination (tls-port 853) and the dnsproxy DoH sidecar run on the appliance.
            </InfoNote>
          </EditorSection>
        </div>

        <EditorSection title="Forward zones (per-domain conditional forwarding)">
          {zones.length === 0 && <p className="text-[11px] text-zinc-400">No forward zones — queries go to the default forwarders.</p>}
          <div className="space-y-1.5">
            {zones.map((row, i) => (
              <div key={i} className="flex flex-wrap items-center gap-1.5">
                <Input
                  className="h-8 min-w-36 flex-1 font-mono text-xs"
                  placeholder="corp.local"
                  defaultValue={row.domain}
                  aria-label="Forward zone domain"
                  onBlur={(e) => setZones(zones.map((z, idx) => (idx === i ? { ...z, domain: e.currentTarget.value } : z)))}
                />
                <Input
                  className="h-8 w-40 font-mono text-xs"
                  placeholder="192.168.10.254"
                  defaultValue={row.server}
                  aria-label="Forward zone server"
                  onBlur={(e) => setZones(zones.map((z, idx) => (idx === i ? { ...z, server: e.currentTarget.value } : z)))}
                />
                <Input
                  className="h-8 w-20 font-mono text-xs"
                  placeholder="port"
                  defaultValue={row.port}
                  aria-label="Forward zone port (optional)"
                  onBlur={(e) => setZones(zones.map((z, idx) => (idx === i ? { ...z, port: e.currentTarget.value } : z)))}
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8 text-zinc-400 hover:text-rose-500"
                  aria-label={`Remove forward zone ${row.domain}`}
                  onClick={() => setZones(zones.filter((_, idx) => idx !== i))}
                >
                  <Icons.Trash2 className="h-3.5 w-3.5" />
                </Button>
              </div>
            ))}
          </div>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="h-7 text-[11px]"
            onClick={() => setZones([...zones, { domain: "", server: "", port: "" }])}
          >
            <Icons.Plus className="mr-1 h-3 w-3" /> Add zone
          </Button>
          {err("forwardZones") && <p className="text-[11px] text-rose-500">{err("forwardZones")}</p>}
        </EditorSection>

        <EditorSection title="DNS over HTTPS (DoH) server">
          <label className="flex items-center justify-between gap-3">
            <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Serve DoH on this appliance</span>
            <Switch checked={dohEnabled} onCheckedChange={setDohEnabled} aria-label="Toggle DoH server" />
          </label>
          {dohEnabled && (
            <div>
              <FieldLabel hint="1–65535">DoH port</FieldLabel>
              <Input
                type="number"
                className="h-9 w-32 font-mono text-xs"
                value={dohPort}
                onChange={(e) => setDohPort(e.currentTarget.value)}
                aria-label="DoH port"
              />
            </div>
          )}
          <InfoNote>Display-only in sandbox — the dnsproxy DoH sidecar runs on the appliance.</InfoNote>
        </EditorSection>

        <div className="flex justify-end">
          <Button onClick={() => save.mutate()} disabled={save.isPending} className="bg-red-700 text-white hover:bg-red-800">
            {save.isPending ? "Saving…" : "Save resolver settings"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ── Policies ────────────────────────────────────────────────────────────────

function PoliciesTab() {
  const queryClient = useQueryClient();
  const q = useQuery({ queryKey: ["dns", "policies"], queryFn: dnsApi.listPolicies });
  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<DnsPolicyDTO | null>(null);
  const [deleting, setDeleting] = useState<DnsPolicyDTO | null>(null);

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ["dns", "policies"] });

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => dnsApi.updatePolicy(id, { enabled }),
    onSuccess: () => invalidate(),
    onError: (err) => toastErr(err, "Toggle failed"),
  });

  const del = useMutation({
    mutationFn: (id: number) => dnsApi.deletePolicy(id),
    onSuccess: () => {
      toastOk("Policy deleted");
      setDeleting(null);
      invalidate();
    },
    onError: (err) => toastErr(err, "Delete failed"),
  });

  const enabledCount = (q.data ?? []).filter((p) => p.enabled).length;
  const lastEnabledWarning =
    deleting?.enabled && enabledCount <= 1
      ? " This is the last enabled policy — DNS filtering becomes inactive after deletion."
      : "";

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs text-zinc-500">
          {(q.data ?? []).length} polic{(q.data ?? []).length === 1 ? "y" : "ies"} · first-match wins (ordered by id)
        </p>
        <Button
          size="sm"
          className="bg-red-700 text-white hover:bg-red-800"
          onClick={() => {
            setEditing(null);
            setEditorOpen(true);
          }}
        >
          <Icons.Plus className="mr-1 h-4 w-4" /> Add Policy
        </Button>
      </div>

      {q.isLoading ? (
        <Card>
          <CardContent className="pt-6">
            <TableSkeleton rows={3} cols={5} />
          </CardContent>
        </Card>
      ) : q.isError ? (
        <QueryError error={q.error} onRetry={() => void q.refetch()} />
      ) : (q.data ?? []).length === 0 ? (
        <Card>
          <CardContent className="p-0">
            <EmptyBlock
              icon={<Icons.ShieldBan className="h-6 w-6" />}
              title="No DNS policies"
              description="Create a filtering policy to start blocking categories or custom domains."
              action={
                <Button
                  size="sm"
                  className="bg-red-700 text-white hover:bg-red-800"
                  onClick={() => {
                    setEditing(null);
                    setEditorOpen(true);
                  }}
                >
                  Add Policy
                </Button>
              }
            />
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-3 lg:grid-cols-2">
          {(q.data ?? []).map((p) => (
            <Card key={p.id} className={cn(!p.enabled && "opacity-60")}>
              <CardContent className="space-y-2.5 pt-5">
                <div className="flex items-center justify-between gap-2">
                  <p className="flex items-center gap-2 text-sm font-medium">
                    {p.name}
                    <Badge
                      variant="outline"
                      className={cn(
                        "px-1.5 py-0 text-[10px]",
                        p.action === "sinkhole"
                          ? "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400"
                          : "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400",
                      )}
                    >
                      {p.action}
                    </Badge>
                  </p>
                  <Switch
                    checked={p.enabled}
                    onCheckedChange={(v) => toggle.mutate({ id: p.id, enabled: v })}
                    aria-label={`Toggle policy ${p.name}`}
                  />
                </div>
                <CategoryChips categories={p.blockCategories} />
                <p className="text-[11px] text-zinc-500">
                  block list: <span className="font-mono">{p.customBlock.length}</span> · allow list:{" "}
                  <span className="font-mono">{p.customAllow.length}</span>
                  {p.action === "sinkhole" && (
                    <>
                      {" "}
                      · sinkhole <span className="font-mono">{p.sinkholeIp}</span>
                    </>
                  )}
                </p>
                <div className="flex items-center justify-end gap-1.5 border-t border-zinc-100 pt-2 dark:border-zinc-800">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 text-xs"
                    onClick={() => {
                      setEditing(p);
                      setEditorOpen(true);
                    }}
                  >
                    <Icons.Pencil className="mr-1 h-3.5 w-3.5" /> Edit
                  </Button>
                  <Button variant="ghost" size="sm" className="h-7 text-xs text-rose-600 hover:text-rose-600 dark:text-rose-400" onClick={() => setDeleting(p)}>
                    <Icons.Trash2 className="mr-1 h-3.5 w-3.5" /> Delete
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <PolicyEditor
        open={editorOpen}
        onOpenChange={setEditorOpen}
        editing={editing}
        onSaved={() => {
          setEditorOpen(false);
          invalidate();
        }}
      />

      <ConfirmDialog
        open={deleting != null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete policy "${deleting?.name ?? ""}"?`}
        description={"Blocked categories and custom lists stop applying immediately." + lastEnabledWarning}
        confirmLabel="Delete"
        loading={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting.id)}
      />
    </div>
  );
}

function PolicyEditor({
  open,
  onOpenChange,
  editing,
  onSaved,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editing: DnsPolicyDTO | null;
  onSaved: () => void;
}) {
  const [form, setForm] = useState(() => formFrom(editing));
  const [blockRaw, setBlockRaw] = useState(() => (editing?.customBlock ?? []).join("\n"));
  const [allowRaw, setAllowRaw] = useState(() => (editing?.customAllow ?? []).join("\n"));
  const [serverErrors, setServerErrors] = useState<Record<string, string[]>>({});

  const seedKey = editing?.id ?? "new";
  const [lastKey, setLastKey] = useState(seedKey);
  if (seedKey !== lastKey) {
    setLastKey(seedKey);
    setServerErrors({});
    setForm(formFrom(editing));
    setBlockRaw((editing?.customBlock ?? []).join("\n"));
    setAllowRaw((editing?.customAllow ?? []).join("\n"));
  }

  const parseList = (raw: string): { ok: string[]; bad: string[] } => {
    const seen = new Set<string>();
    const ok: string[] = [];
    const bad: string[] = [];
    for (const line of raw.split("\n")) {
      const v = line.trim().toLowerCase();
      if (!v) continue;
      if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/.test(v)) {
        bad.push(line.trim());
        continue;
      }
      if (!seen.has(v)) {
        seen.add(v);
        ok.push(v);
      }
    }
    return { ok, bad };
  };

  const blockParsed = useMemo(() => parseList(blockRaw), [blockRaw]);
  const allowParsed = useMemo(() => parseList(allowRaw), [allowRaw]);

  const save = useMutation({
    mutationFn: () => {
      const body = {
        name: form.name.trim(),
        enabled: form.enabled,
        blockCategories: form.categories,
        customBlock: blockParsed.ok,
        customAllow: allowParsed.ok,
        action: form.action,
        ...(form.action === "sinkhole" ? { sinkholeIp: form.sinkholeIp.trim() || "0.0.0.0" } : {}),
      };
      return editing ? dnsApi.updatePolicy(editing.id, body) : dnsApi.createPolicy(body);
    },
    onSuccess: () => {
      toastOk(editing ? "Policy updated" : "Policy created");
      onSaved();
    },
    onError: (err) => {
      setServerErrors(fieldErrorsOf(err));
      toastErr(err, "Save failed");
    },
  });

  const err = (path: string) => serverErrors[path]?.join("; ");
  const set = <K extends keyof PolicyForm>(k: K, v: PolicyForm[K]) => setForm((f) => ({ ...f, [k]: v }));

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
      <DialogHeader>
        <DialogTitle>{editing ? `Edit policy — ${editing.name}` : "Add DNS policy"}</DialogTitle>
        <DialogDescription>Categories + custom lists, evaluated top-down (first match wins).</DialogDescription>
      </DialogHeader>
      <div className="space-y-4">
        <EditorSection title="Identity">
          <FieldLabel>Policy name</FieldLabel>
          <Input className="h-9 text-sm" value={form.name} onChange={(e) => set("name", e.currentTarget.value)} aria-label="Policy name" />
          {err("name") && <p className="text-[11px] text-rose-500">{err("name")}</p>}
          <label className="flex items-center justify-between gap-3 pt-1">
            <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Enabled</span>
            <Switch checked={form.enabled} onCheckedChange={(v) => set("enabled", v)} aria-label="Toggle policy enabled" />
          </label>
        </EditorSection>

        <EditorSection title="Block categories">
          <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-3">
            {BLOCK_CATEGORIES.map((c) => {
              const on = form.categories.includes(c);
              return (
                <button
                  key={c}
                  type="button"
                  aria-pressed={on}
                  onClick={() =>
                    set("categories", on ? form.categories.filter((x) => x !== c) : [...form.categories, c])
                  }
                  className={cn(
                    "flex items-center justify-between rounded-md border px-2.5 py-1.5 text-xs font-medium capitalize transition-colors",
                    on ? "border-red-600/40 bg-red-600/5 text-red-700 dark:text-red-500" : "border-zinc-200 text-zinc-600 dark:border-zinc-800 dark:text-zinc-300",
                  )}
                >
                  {c}
                  {on && <Icons.Check className="h-3.5 w-3.5" />}
                </button>
              );
            })}
          </div>
        </EditorSection>

        <EditorSection title="Custom block list">
          <FieldLabel hint="one domain per line, bulk paste OK">Domains</FieldLabel>
          <Textarea className="font-mono text-xs" rows={4} value={blockRaw} onChange={(e) => setBlockRaw(e.currentTarget.value)} placeholder={"ads.example.com\ntracker.example.net"} aria-label="Custom block list" />
          <p className={cn("text-[11px]", blockParsed.bad.length ? "text-amber-600 dark:text-amber-400" : "text-zinc-400")}>
            {blockParsed.ok.length} domain(s) parsed{blockParsed.bad.length ? ` · ${blockParsed.bad.length} invalid line(s) ignored` : ""} · duplicates removed
          </p>
        </EditorSection>

        <EditorSection title="Custom allow list (wins over block categories)">
          <FieldLabel hint="one domain per line">Domains</FieldLabel>
          <Textarea className="font-mono text-xs" rows={3} value={allowRaw} onChange={(e) => setAllowRaw(e.currentTarget.value)} placeholder="cdn.corp.local" aria-label="Custom allow list" />
          <p className={cn("text-[11px]", allowParsed.bad.length ? "text-amber-600 dark:text-amber-400" : "text-zinc-400")}>
            {allowParsed.ok.length} domain(s) parsed{allowParsed.bad.length ? ` · ${allowParsed.bad.length} invalid line(s) ignored` : ""}
          </p>
        </EditorSection>

        <EditorSection title="Action">
          <Select value={form.action} onValueChange={(v) => set("action", v as "sinkhole" | "nxdomain")}>
            <SelectTrigger className="h-9 w-44 text-sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="sinkhole">sinkhole — answer with sinkhole IP</SelectItem>
              <SelectItem value="nxdomain">nxdomain — domain does not exist</SelectItem>
            </SelectContent>
          </Select>
          {form.action === "sinkhole" && (
            <div>
              <FieldLabel hint="answers point here">Sinkhole IP</FieldLabel>
              <Input className="h-9 w-44 font-mono text-xs" value={form.sinkholeIp} onChange={(e) => set("sinkholeIp", e.currentTarget.value)} aria-label="Sinkhole IP" />
              {err("sinkholeIp") && <p className="text-[11px] text-rose-500">{err("sinkholeIp")}</p>}
            </div>
          )}
        </EditorSection>
      </div>
      <DialogFooter>
        <Button variant="outline" onClick={() => onOpenChange(false)}>
          Cancel
        </Button>
        <Button onClick={() => save.mutate()} disabled={save.isPending} className="bg-red-700 text-white hover:bg-red-800">
          {save.isPending ? "Saving…" : editing ? "Save changes" : "Create policy"}
        </Button>
      </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

type PolicyForm = {
  name: string;
  enabled: boolean;
  categories: string[];
  action: "sinkhole" | "nxdomain";
  sinkholeIp: string;
};

function formFrom(p: DnsPolicyDTO | null): PolicyForm {
  return {
    name: p?.name ?? "",
    enabled: p?.enabled ?? true,
    categories: p?.blockCategories ?? [],
    action: (p?.action as PolicyForm["action"]) ?? "sinkhole",
    sinkholeIp: p?.sinkholeIp ?? "0.0.0.0",
  };
}

// ── Records ─────────────────────────────────────────────────────────────────

function RecordsTab() {
  const queryClient = useQueryClient();
  const [qInput, setQInput] = useState("");
  const [q, setQ] = useState("");
  const [zone, setZone] = useState("all");
  const [type, setType] = useState("all");
  const [page, setPage] = useState(1);
  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<DnsRecordDTO | null>(null);
  const [deleting, setDeleting] = useState<DnsRecordDTO | null>(null);

  useEffect(() => {
    const t = setTimeout(() => {
      setQ(qInput);
      setPage(1);
    }, 350);
    return () => clearTimeout(t);
  }, [qInput]);

  const params = useMemo(() => {
    const sp = new URLSearchParams({ page: String(page), limit: "50" });
    if (q) sp.set("q", q);
    if (zone !== "all") sp.set("zone", zone);
    if (type !== "all") sp.set("type", type);
    return sp.toString();
  }, [q, zone, type, page]);

  const list = useQuery({ queryKey: ["dns", "records", params], queryFn: () => dnsApi.listRecords(params) });
  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ["dns", "records"] });

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => dnsApi.updateRecord(id, { enabled }),
    onSuccess: () => invalidate(),
    onError: (err) => toastErr(err, "Toggle failed"),
  });
  const del = useMutation({
    mutationFn: (id: number) => dnsApi.deleteRecord(id),
    onSuccess: () => {
      toastOk("Record deleted");
      setDeleting(null);
      invalidate();
    },
    onError: (err) => toastErr(err, "Delete failed"),
  });

  const rows = list.data?.data ?? [];
  const meta = list.data?.meta;
  const zones = Array.from(new Set(["corp.local", ...rows.map((r) => r.zone)]));

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative">
          <Icons.Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-400" />
          <Input className="h-9 w-52 pl-8 text-sm" placeholder="Search name / value…" value={qInput} onChange={(e) => setQInput(e.currentTarget.value)} aria-label="Search records" />
        </div>
        <Select value={zone} onValueChange={(v) => { setZone(v); setPage(1); }}>
          <SelectTrigger className="h-9 w-44 text-sm"><SelectValue /></SelectTrigger>
          <SelectContent>
            {zones.map((z) => (
              <SelectItem key={z} value={z}>{z}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={type} onValueChange={(v) => { setType(v); setPage(1); }}>
          <SelectTrigger className="h-9 w-32 text-sm"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All types</SelectItem>
            {RECORD_TYPES.map((t) => (
              <SelectItem key={t} value={t}>{t}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button
          size="sm"
          className="ml-auto bg-red-700 text-white hover:bg-red-800"
          onClick={() => {
            setEditing(null);
            setEditorOpen(true);
          }}
        >
          <Icons.Plus className="mr-1 h-4 w-4" /> Add Record
        </Button>
      </div>

      <Card>
        <CardContent className="p-0">
          {list.isLoading ? (
            <div className="pt-6">
              <TableSkeleton rows={6} cols={7} />
            </div>
          ) : list.isError ? (
            <div className="p-4">
              <QueryError error={list.error} onRetry={() => void list.refetch()} />
            </div>
          ) : rows.length === 0 ? (
            <EmptyBlock
              icon={<Icons.BookMarked className="h-6 w-6" />}
              title="No DNS records"
              description="Local A/AAAA/CNAME/MX/TXT/SRV/PTR records answered by the resolver."
              action={
                <Button size="sm" className="bg-red-700 text-white hover:bg-red-800" onClick={() => { setEditing(null); setEditorOpen(true); }}>
                  Add Record
                </Button>
              }
            />
          ) : (
            <div className="max-h-[480px] overflow-auto [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-zinc-300 dark:[&::-webkit-scrollbar-thumb]:bg-zinc-700">
              <table className="w-full text-sm">
                <thead className="sticky top-0 border-b border-zinc-200 bg-zinc-50 text-left text-[11px] uppercase tracking-wide text-zinc-500 dark:border-zinc-800 dark:bg-zinc-900">
                  <tr>
                    <th className="px-4 py-2.5 font-medium">Zone / Name</th>
                    <th className="px-4 py-2.5 font-medium">Type</th>
                    <th className="px-4 py-2.5 font-medium">Value</th>
                    <th className="px-4 py-2.5 font-medium">TTL</th>
                    <th className="px-4 py-2.5 font-medium">Prio</th>
                    <th className="px-4 py-2.5 font-medium">Enabled</th>
                    <th className="w-10 px-4 py-2.5" />
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.id} className={cn("border-b border-zinc-100 last:border-0 hover:bg-zinc-50 dark:border-zinc-800/60 dark:hover:bg-zinc-800/40", !r.enabled && "opacity-60")}>
                      <td className="px-4 py-2.5">
                        <p className="font-medium">{r.name}</p>
                        <p className="text-[11px] text-zinc-400">{r.zone}</p>
                      </td>
                      <td className="px-4 py-2.5"><RecordTypeChip type={r.type} /></td>
                      <td className="max-w-64 truncate px-4 py-2.5 font-mono text-xs" title={r.value}>{r.value}</td>
                      <td className="px-4 py-2.5 font-mono text-xs tabular-nums">{humanizeSeconds(r.ttl)}</td>
                      <td className="px-4 py-2.5 font-mono text-xs tabular-nums">{r.priority ?? <span className="text-zinc-400">—</span>}</td>
                      <td className="px-4 py-2.5">
                        <Switch checked={r.enabled} onCheckedChange={(v) => toggle.mutate({ id: r.id, enabled: v })} aria-label={`Toggle record ${r.name}`} />
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={`Edit record ${r.name}`} onClick={() => { setEditing(r); setEditorOpen(true); }}>
                            <Icons.Pencil className="h-3.5 w-3.5" />
                          </Button>
                          <Button variant="ghost" size="icon" className="h-8 w-8 text-rose-500 hover:text-rose-600" aria-label={`Delete record ${r.name}`} onClick={() => setDeleting(r)}>
                            <Icons.Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {meta && meta.totalPages > 1 && (
        <div className="flex items-center justify-end gap-2 text-xs text-zinc-500">
          <Button variant="outline" size="sm" className="h-7" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
            <Icons.ChevronLeft className="mr-1 h-3.5 w-3.5" /> Prev
          </Button>
          <span className="tabular-nums">{meta.page} / {meta.totalPages}</span>
          <Button variant="outline" size="sm" className="h-7" disabled={page >= meta.totalPages} onClick={() => setPage((p) => p + 1)}>
            Next <Icons.ChevronRight className="ml-1 h-3.5 w-3.5" />
          </Button>
        </div>
      )}

      <RecordEditor open={editorOpen} onOpenChange={setEditorOpen} editing={editing} zones={zones} onSaved={() => { setEditorOpen(false); invalidate(); }} />

      <ConfirmDialog
        open={deleting != null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete record ${deleting?.name ?? ""}?`}
        description={`Type ${deleting?.type ?? ""} in zone ${deleting?.zone ?? ""} — the resolver stops answering it.`}
        confirmLabel="Delete"
        loading={del.isPending}
        onConfirm={() => deleting && del.mutate(deleting.id)}
      />
    </div>
  );
}

function RecordEditor({
  open,
  onOpenChange,
  editing,
  zones,
  onSaved,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editing: DnsRecordDTO | null;
  zones: string[];
  onSaved: () => void;
}) {
  const [form, setForm] = useState(() => recordFormFrom(editing));
  const [serverErrors, setServerErrors] = useState<Record<string, string[]>>({});

  const seedKey = `${editing?.id ?? "new"}`;
  const [lastKey, setLastKey] = useState(seedKey);
  if (seedKey !== lastKey) {
    setLastKey(seedKey);
    setServerErrors({});
    setForm(recordFormFrom(editing));
  }

  const needsPriority = form.type === "MX" || form.type === "SRV";

  const save = useMutation({
    mutationFn: () => {
      const body: Record<string, unknown> = {
        zone: form.zone.trim(),
        name: form.name.trim(),
        type: form.type,
        value: form.value.trim(),
        ttl: Number(form.ttl) || 3600,
        enabled: form.enabled,
        ...(needsPriority ? { priority: form.priority === "" ? null : Number(form.priority) } : { priority: null }),
      };
      return editing ? dnsApi.updateRecord(editing.id, body) : dnsApi.createRecord(body);
    },
    onSuccess: () => {
      toastOk(editing ? "Record updated" : "Record created");
      onSaved();
    },
    onError: (err) => {
      setServerErrors(fieldErrorsOf(err));
      toastErr(err, "Save failed");
    },
  });

  const err = (path: string) => serverErrors[path]?.join("; ");
  const set = <K extends keyof RecordForm>(k: K, v: RecordForm[K]) => setForm((f) => ({ ...f, [k]: v }));

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-xl">
      <DialogHeader>
        <DialogTitle>{editing ? "Edit record" : "Add DNS record"}</DialogTitle>
        <DialogDescription>Local records answered by the simulated resolver.</DialogDescription>
      </DialogHeader>
      <div className="space-y-4">
        <EditorSection title="Record">
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <FieldLabel>Zone</FieldLabel>
              <Input className="h-9 font-mono text-xs" list="dns-zone-list" value={form.zone} onChange={(e) => set("zone", e.currentTarget.value)} aria-label="Zone" />
              <datalist id="dns-zone-list">
                {zones.map((z) => (
                  <option key={z} value={z} />
                ))}
              </datalist>
              {err("zone") && <p className="text-[11px] text-rose-500">{err("zone")}</p>}
            </div>
            <div>
              <FieldLabel hint="@ for the zone apex">Name</FieldLabel>
              <Input className="h-9 font-mono text-xs" value={form.name} onChange={(e) => set("name", e.currentTarget.value)} aria-label="Record name" />
              {err("name") && <p className="text-[11px] text-rose-500">{err("name")}</p>}
            </div>
            <div>
              <FieldLabel>Type</FieldLabel>
              <Select value={form.type} onValueChange={(v) => set("type", v)}>
                <SelectTrigger className="h-9 text-sm"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {RECORD_TYPES.map((t) => (
                    <SelectItem key={t} value={t}>{t}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <FieldLabel hint="seconds, 60–604800">TTL</FieldLabel>
              <Input type="number" className="h-9 font-mono text-xs" value={form.ttl} onChange={(e) => set("ttl", e.currentTarget.value)} aria-label="TTL seconds" />
              {err("ttl") && <p className="text-[11px] text-rose-500">{err("ttl")}</p>}
            </div>
          </div>
          <div>
            <FieldLabel hint={typeHint(form.type)}>Value</FieldLabel>
            <Input className="h-9 font-mono text-xs" value={form.value} onChange={(e) => set("value", e.currentTarget.value)} aria-label="Record value" />
            {err("value") && <p className="text-[11px] text-rose-500">{err("value")}</p>}
          </div>
          {needsPriority && (
            <div>
              <FieldLabel hint="10–65535, required for MX/SRV">Priority</FieldLabel>
              <Input type="number" className="h-9 w-32 font-mono text-xs" value={form.priority} onChange={(e) => set("priority", e.currentTarget.value)} aria-label="Priority" />
              {err("priority") && <p className="text-[11px] text-rose-500">{err("priority")}</p>}
            </div>
          )}
          <label className="flex items-center justify-between gap-3 pt-1">
            <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Enabled</span>
            <Switch checked={form.enabled} onCheckedChange={(v) => set("enabled", v)} aria-label="Toggle record enabled" />
          </label>
        </EditorSection>
      </div>
      <DialogFooter>
        <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
        <Button onClick={() => save.mutate()} disabled={save.isPending} className="bg-red-700 text-white hover:bg-red-800">
          {save.isPending ? "Saving…" : editing ? "Save changes" : "Create record"}
        </Button>
      </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

type RecordForm = { zone: string; name: string; type: string; value: string; ttl: string; priority: string; enabled: boolean };

function recordFormFrom(r: DnsRecordDTO | null): RecordForm {
  return {
    zone: r?.zone ?? "corp.local",
    name: r?.name ?? "",
    type: r?.type ?? "A",
    value: r?.value ?? "",
    ttl: String(r?.ttl ?? 3600),
    priority: r?.priority != null ? String(r.priority) : "",
    enabled: r?.enabled ?? true,
  };
}

function typeHint(type: string): string {
  switch (type) {
    case "A": return "IPv4 address";
    case "AAAA": return "IPv6 address";
    case "CNAME": return "target hostname";
    case "MX": return "mail hostname";
    case "TXT": return "free text ≤ 255 chars";
    case "SRV": return "weight port target";
    case "PTR": return "…in-addr.arpa";
    default: return "";
  }
}

// ── Query Log ───────────────────────────────────────────────────────────────

function QueryLogTab() {
  const [qInput, setQInput] = useState("");
  const [q, setQ] = useState("");
  const [blocked, setBlocked] = useState<"all" | "true" | "false">("all");
  const [page, setPage] = useState(1);

  useEffect(() => {
    const t = setTimeout(() => {
      setQ(qInput);
      setPage(1);
    }, 350);
    return () => clearTimeout(t);
  }, [qInput]);

  const params = useMemo(() => {
    const sp = new URLSearchParams({ page: String(page), limit: "50" });
    if (q) sp.set("q", q);
    if (blocked !== "all") sp.set("blocked", blocked);
    return sp.toString();
  }, [q, blocked, page]);

  // 10 s poll while the tab is mounted (no socket event for query rows — M06 §6)
  const list = useQuery({
    queryKey: ["dns", "query-logs", params],
    queryFn: () => dnsApi.listQueryLogs(params),
    refetchInterval: 10_000,
  });

  const rows = list.data?.data ?? [];
  const meta = list.data?.meta;
  const blockedCount = rows.filter((r) => r.blocked).length;

  return (
    <div className="space-y-3">
      <Alert className="border-red-600/40 bg-red-600/10 text-red-800 dark:text-red-300">
        <Icons.Info className="h-4 w-4" />
        <AlertTitle>Derived view</AlertTitle>
        <AlertDescription>
          Generated by the simulated DNS query generator — not persisted; rows survive neither a restart nor --reset (SIMULATION_LAYER §6).
        </AlertDescription>
      </Alert>

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative">
          <Icons.Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-400" />
          <Input className="h-9 w-56 pl-8 text-sm" placeholder="Domain or client IP…" value={qInput} onChange={(e) => setQInput(e.currentTarget.value)} aria-label="Filter query log" />
        </div>
        <Select value={blocked} onValueChange={(v) => { setBlocked(v as "all" | "true" | "false"); setPage(1); }}>
          <SelectTrigger className="h-9 w-40 text-sm"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All results</SelectItem>
            <SelectItem value="true">Blocked only</SelectItem>
            <SelectItem value="false">Allowed only</SelectItem>
          </SelectContent>
        </Select>
        <span className="ml-auto flex items-center gap-1.5 text-[11px] text-zinc-400">
          <Icons.Radio className="h-3.5 w-3.5 text-emerald-500" /> auto-refresh 10 s · {blockedCount}/{rows.length} blocked on page
        </span>
      </div>

      <Card>
        <CardContent className="p-0">
          {list.isLoading ? (
            <div className="pt-6">
              <TableSkeleton rows={8} cols={5} />
            </div>
          ) : list.isError ? (
            <div className="p-4">
              <QueryError error={list.error} onRetry={() => void list.refetch()} />
            </div>
          ) : rows.length === 0 ? (
            <EmptyBlock icon={<Icons.Globe2 className="h-6 w-6" />} title="No queries match" description="Adjust the filters, or wait for the next simulated tick (2 s)." />
          ) : (
            <ul className="max-h-[480px] divide-y divide-zinc-100 overflow-auto dark:divide-zinc-800/60 [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-zinc-300 dark:[&::-webkit-scrollbar-thumb]:bg-zinc-700">
              {rows.map((r) => (
                <li key={`${r.seq}-${r.ts}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 text-xs hover:bg-zinc-50 dark:hover:bg-zinc-800/40">
                  <span className="w-32 shrink-0 font-mono text-[11px] tabular-nums text-zinc-400">{fmtDateTime(r.ts)}</span>
                  <span className="w-28 shrink-0 font-mono text-[11px] text-zinc-500">{r.clientIp}</span>
                  <span className="min-w-0 flex-1 truncate font-mono text-xs text-zinc-800 dark:text-zinc-200" title={r.domain}>{r.domain}</span>
                  <Badge variant="outline" className="border-zinc-300 bg-zinc-50 px-1.5 py-0 font-mono text-[10px] text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800/60">
                    {r.qtype}
                  </Badge>
                  <ResultBadge action={r.action} />
                  {r.blocked && <BlockedBadge />}
                  {r.category && (
                    <Badge variant="outline" className="border-zinc-200 px-1.5 py-0 text-[10px] text-zinc-400 dark:border-zinc-800">
                      {r.category}
                    </Badge>
                  )}
                  <span className="w-14 shrink-0 text-right font-mono text-[11px] tabular-nums text-zinc-400">{r.latencyMs} ms</span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      {meta && meta.totalPages > 1 && (
        <div className="flex items-center justify-end gap-2 text-xs text-zinc-500">
          <Button variant="outline" size="sm" className="h-7" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
            <Icons.ChevronLeft className="mr-1 h-3.5 w-3.5" /> Prev
          </Button>
          <span className="tabular-nums">{meta.page} / {meta.totalPages}</span>
          <Button variant="outline" size="sm" className="h-7" disabled={page >= meta.totalPages} onClick={() => setPage((p) => p + 1)}>
            Next <Icons.ChevronRight className="ml-1 h-3.5 w-3.5" />
          </Button>
        </div>
      )}
    </div>
  );
}
