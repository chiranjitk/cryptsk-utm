"use client";

/**
 * API Platform view (M10 §4 `#/system/api-keys`) — 2 tabs: API Keys | Webhooks.
 * Behavior owned by M11 (key lifecycle §5.1, webhooks §5.6):
 *   Keys:    table (prefix/scope badges/lastUsedAt/expiresAt/revoked) → create
 *            dialog with the three LOCKED scope arrays → show-secret-once
 *            dialog gated behind "I have saved it" → destructive revoke.
 *   Webhooks: CRUD + events multi-select (5 locked values) + enabled switch +
 *            "Send test" simulated delivery (M11 §5.6 — no real HTTP egress).
 * Theme per ADR-019: blue-600 primary; scope badges read=zinc, write=amber,
 * admin=rose; emerald only for a genuinely-ok lastStatus.
 */

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { toast as showToast } from "@/hooks/use-toast";
import { ConfirmDialog, EmptyBlock, FieldLabel, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";
import {
  apiKeysApi,
  copyText,
  fieldErrorsOf,
  fmtDateTime,
  fmtRelative,
  type ApiKeyCreatedDTO,
  type ApiKeyDTO,
  type WebhookDTO,
} from "./api-keys-api";
import { cn } from "@/lib/utils";

// ── constants (LOCKED values — M11 §3.1/§5.6, PROJECT_MEMORY §6) ───────────

type TabKey = "keys" | "webhooks";

const TABS: Array<{ key: TabKey; label: string }> = [
  { key: "keys", label: "API Keys" },
  { key: "webhooks", label: "Webhooks" },
];

const SCOPE_OPTIONS: Array<{ scopes: string[]; label: string; capability: string }> = [
  { scopes: ["read"], label: "Read-only", capability: "All GET endpoints — lists, details, stats, logs." },
  {
    scopes: ["read", "write"],
    label: "Read + Write",
    capability: "Read plus config/operational mutations (rules, DNS/DHCP, VPN, WAN…).",
  },
  {
    scopes: ["read", "write", "admin"],
    label: "Read + Write + Admin",
    capability: "Write plus identity/system mutations (users, auth settings, backups, HA).",
  },
];

const WEBHOOK_EVENTS = ["alerts.new", "config.updated", "wan.status", "vpn.status", "sessions.update"] as const;

const EVENT_HINTS: Record<string, string> = {
  "alerts.new": "Fires with new alerts",
  "config.updated": "Fires on config-section changes",
  "wan.status": "WAN up/degraded/down transitions",
  "vpn.status": "VPN up/down/error transitions",
  "sessions.update": "Session connect/disconnect updates",
};

// ── atoms ───────────────────────────────────────────────────────────────────

const SCOPE_BADGE_CLS: Record<string, string> = {
  read: "border-zinc-300 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
  write: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  admin: "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400",
};

function ScopeBadges({ scopes }: { scopes: string[] }) {
  return (
    <div className="flex flex-wrap gap-1">
      {scopes.map((s) => (
        <Badge key={s} variant="outline" className={cn("font-medium", SCOPE_BADGE_CLS[s] ?? SCOPE_BADGE_CLS.read)}>
          {s}
        </Badge>
      ))}
    </div>
  );
}

function StatusChip({ status }: { status: string | null }) {
  if (!status) return <span className="text-xs text-zinc-400">—</span>;
  const ok = status === "200";
  return (
    <Badge
      variant="outline"
      className={cn(
        "font-mono text-[10px]",
        ok
          ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
          : "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400",
      )}
    >
      {status}
    </Badge>
  );
}

function tabFromHash(): TabKey {
  const qs = window.location.hash.split("?")[1];
  const v = new URLSearchParams(qs ?? "").get("tab");
  return TABS.some((t) => t.key === v) ? (v as TabKey) : "keys";
}

function FieldError({ errors }: { errors?: string[] }) {
  if (!errors || errors.length === 0) return null;
  return <p className="mt-1 text-[11px] text-rose-600 dark:text-rose-400">{errors.join(" · ")}</p>;
}

// ── Tab 1 — API keys ────────────────────────────────────────────────────────

function KeysTab() {
  const qc = useQueryClient();
  const query = useQuery({ queryKey: ["api-keys"], queryFn: apiKeysApi.listKeys });

  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState<{ name: string; scopesIdx: number; expires: string }>({ name: "", scopesIdx: 0, expires: "" });
  const [fe, setFe] = useState<Record<string, string[]>>({});
  const [reveal, setReveal] = useState<{ created: ApiKeyCreatedDTO; saved: boolean } | null>(null);
  const [copied, setCopied] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<ApiKeyDTO | null>(null);

  const createMut = useMutation({
    mutationFn: () => {
      const opt = SCOPE_OPTIONS[form.scopesIdx];
      return apiKeysApi.createKey({
        name: form.name,
        scopes: opt.scopes,
        ...(form.expires ? { expiresAt: new Date(form.expires).toISOString() } : {}),
      });
    },
    onSuccess: (created) => {
      setCreateOpen(false);
      setFe({});
      setCopied(false);
      setReveal({ created, saved: false }); // full key exists ONLY in this response
      setForm({ name: "", scopesIdx: 0, expires: "" });
      void qc.invalidateQueries({ queryKey: ["api-keys"] });
    },
    onError: (err) => {
      const fieldErrors = fieldErrorsOf(err);
      if (Object.keys(fieldErrors).length > 0) setFe(fieldErrors);
      else toastErr(err, "Could not create the API key");
    },
  });

  const revokeMut = useMutation({
    mutationFn: (id: number) => apiKeysApi.revokeKey(id),
    onSuccess: () => {
      setRevokeTarget(null);
      toastOk("API key revoked", "Clients using it receive 401 immediately; the row stays for audit history.");
      void qc.invalidateQueries({ queryKey: ["api-keys"] });
    },
    onError: (err) => toastErr(err, "Could not revoke the API key"),
  });

  const keys = query.data ?? [];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs text-zinc-500">
          Machine clients authenticate with <code className="rounded bg-zinc-100 px-1 font-mono text-[11px] dark:bg-zinc-800">Authorization: Bearer ck_…</code>{" "}
          — only the prefix is ever stored retrievable.
        </p>
        <Button size="sm" className="gap-1.5" onClick={() => setCreateOpen(true)}>
          <Icons.KeyRound className="h-4 w-4" />
          New API key
        </Button>
      </div>

      {query.isLoading ? (
        <TableSkeleton rows={4} cols={7} />
      ) : query.isError ? (
        <QueryError error={query.error} onRetry={() => void query.refetch()} />
      ) : keys.length === 0 ? (
        <EmptyBlock
          icon={<Icons.KeyRound className="h-6 w-6" />}
          title="No API keys yet"
          description="API keys authenticate machine integrations (convention: prefix them with bot-). The full secret is shown exactly once at creation — store it in your secret manager; only a SHA-256 hash is kept."
          action={
            <Button size="sm" variant="outline" onClick={() => setCreateOpen(true)}>
              <Icons.Plus className="mr-1 h-4 w-4" /> New API key
            </Button>
          }
        />
      ) : (
        <div className="rounded-lg border border-zinc-200 dark:border-zinc-800">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Prefix</TableHead>
                <TableHead>Scopes</TableHead>
                <TableHead>Last used</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {keys.map((k) => (
                <TableRow key={k.id}>
                  <TableCell>
                    <span className="flex items-center gap-1.5 font-medium">
                      {k.name}
                      {k.revoked ? (
                        <Badge variant="outline" className="border-rose-500/40 bg-rose-500/10 text-[10px] text-rose-600 dark:text-rose-400">
                          revoked
                        </Badge>
                      ) : null}
                    </span>
                  </TableCell>
                  <TableCell>
                    <code className="rounded bg-zinc-100 px-1.5 py-0.5 font-mono text-xs dark:bg-zinc-800">{k.prefix}</code>
                  </TableCell>
                  <TableCell>
                    <ScopeBadges scopes={k.scopes} />
                  </TableCell>
                  <TableCell className="text-xs text-zinc-500">{fmtRelative(k.lastUsedAt)}</TableCell>
                  <TableCell className="text-xs text-zinc-500">{k.expiresAt ? fmtDateTime(k.expiresAt) : "never"}</TableCell>
                  <TableCell className="text-xs text-zinc-500">{fmtDateTime(k.createdAt)}</TableCell>
                  <TableCell>
                    {!k.revoked ? (
                      <Button
                        size="sm"
                        variant="ghost"
                        className="h-7 gap-1 px-2 text-rose-600 hover:bg-rose-500/10 hover:text-rose-700 dark:text-rose-400"
                        onClick={() => setRevokeTarget(k)}
                      >
                        <Icons.Ban className="h-3.5 w-3.5" />
                        Revoke
                      </Button>
                    ) : null}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {/* create dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>New API key</DialogTitle>
            <DialogDescription>
              Scopes cannot be changed after creation — create a new key instead. The full secret is shown once.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <FieldLabel hint="1–64 chars">Name</FieldLabel>
              <Input
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="bot-grafana-readonly"
                autoFocus
              />
              <FieldError errors={fe.name} />
            </div>
            <div>
              <FieldLabel hint="locked arrays">Scopes</FieldLabel>
              <RadioGroup
                value={String(form.scopesIdx)}
                onValueChange={(v) => setForm((f) => ({ ...f, scopesIdx: Number(v) }))}
                className="gap-2"
              >
                {SCOPE_OPTIONS.map((opt, i) => (
                  <Label
                    key={opt.label}
                    className={cn(
                      "flex cursor-pointer items-start gap-2.5 rounded-md border p-3 transition-colors",
                      form.scopesIdx === i
                        ? "border-blue-500/40 bg-blue-500/10 dark:border-blue-500/40"
                        : "border-zinc-200 hover:bg-zinc-50 dark:border-zinc-800 dark:hover:bg-zinc-900",
                    )}
                  >
                    <RadioGroupItem value={String(i)} className="mt-0.5" />
                    <span className="space-y-0.5">
                      <span className="block text-sm font-medium leading-none">{opt.label}</span>
                      <span className="block text-[11px] leading-snug text-zinc-500">{opt.capability}</span>
                    </span>
                  </Label>
                ))}
              </RadioGroup>
              <FieldError errors={fe.scopes} />
            </div>
            <div>
              <FieldLabel hint="optional — expired keys authenticate as 401">Expiry</FieldLabel>
              <Input
                type="datetime-local"
                value={form.expires}
                onChange={(e) => setForm((f) => ({ ...f, expires: e.target.value }))}
              />
              <FieldError errors={fe.expiresAt} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)} disabled={createMut.isPending}>
              Cancel
            </Button>
            <Button className="bg-blue-600 text-white hover:bg-blue-700" onClick={() => createMut.mutate()} disabled={createMut.isPending || !form.name.trim()}>
              {createMut.isPending ? "Creating…" : "Create key"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* show-secret-once dialog — close is gated behind the "I saved it" checkbox */}
      <Dialog
        open={reveal !== null}
        onOpenChange={(o) => {
          if (!o && !reveal?.saved) return; // block esc/overlay close until saved
          setReveal(null);
        }}
      >
        <DialogContent className="sm:max-w-lg" onInteractOutside={(e) => e.preventDefault()}>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Icons.ShieldCheck className="h-4 w-4 text-blue-600 dark:text-blue-400" />
              Save your API key now
            </DialogTitle>
            <DialogDescription>
              {reveal ? <>Key “{reveal.created.name}” · prefix <code className="font-mono">{reveal.created.prefix}</code></> : null}
            </DialogDescription>
          </DialogHeader>
          {reveal ? (
            <div className="space-y-3">
              <div className="flex items-start gap-2">
                <code className="min-w-0 flex-1 break-all rounded-md border border-zinc-200 bg-zinc-50 p-3 font-mono text-xs leading-relaxed dark:border-zinc-800 dark:bg-zinc-900">
                  {reveal.created.key}
                </code>
                <Button
                  size="sm"
                  variant="outline"
                  className="shrink-0 gap-1.5"
                  onClick={async () => {
                    const ok = await copyText(reveal.created.key);
                    setCopied(ok);
                    if (ok) toastOk("Copied to clipboard");
                    else toastErr(new Error("Clipboard unavailable — select and copy manually"), "Copy failed");
                  }}
                >
                  {copied ? <Icons.Check className="h-4 w-4" /> : <Icons.Copy className="h-4 w-4" />}
                  {copied ? "Copied" : "Copy"}
                </Button>
              </div>
              <p className="flex items-start gap-1.5 text-xs text-amber-600 dark:text-amber-400">
                <Icons.TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                This secret is shown once and cannot be recovered. Cryptsk stores only its SHA-256 hash.
              </p>
              <Label className="flex cursor-pointer items-center gap-2 rounded-md border border-zinc-200 p-3 text-sm dark:border-zinc-800">
                <Checkbox
                  checked={reveal.saved}
                  onCheckedChange={(v) => setReveal({ ...reveal, saved: v === true })}
                />
                I have saved this key
              </Label>
            </div>
          ) : null}
          <DialogFooter>
            <Button
              className="bg-blue-600 text-white hover:bg-blue-700"
              disabled={!reveal?.saved}
              onClick={() => setReveal(null)}
            >
              Done
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* revoke confirm */}
      <ConfirmDialog
        open={revokeTarget !== null}
        onOpenChange={(o) => (o ? null : setRevokeTarget(null))}
        title={`Revoke API key “${revokeTarget?.name ?? ""}”?`}
        description="Clients using this key immediately receive 401. The row stays in the list with a revoked badge for audit history."
        confirmLabel="Revoke"
        loading={revokeMut.isPending}
        onConfirm={() => revokeTarget && revokeMut.mutate(revokeTarget.id)}
      />
    </div>
  );
}

// ── Tab 2 — Webhooks ────────────────────────────────────────────────────────

function WebhooksTab() {
  const qc = useQueryClient();
  const query = useQuery({ queryKey: ["webhooks"], queryFn: apiKeysApi.listWebhooks });

  const [editor, setEditor] = useState<{ open: boolean; editing: WebhookDTO | null }>({ open: false, editing: null });
  const [form, setForm] = useState<{ name: string; url: string; events: string[]; secret: string }>({ name: "", url: "", events: [], secret: "" });
  const [fe, setFe] = useState<Record<string, string[]>>({});
  const [deleteTarget, setDeleteTarget] = useState<WebhookDTO | null>(null);

  const openCreate = () => {
    setForm({ name: "", url: "", events: [], secret: "" });
    setFe({});
    setEditor({ open: true, editing: null });
  };
  const openEdit = (wh: WebhookDTO) => {
    setForm({ name: wh.name, url: wh.url, events: [...wh.events], secret: "" });
    setFe({});
    setEditor({ open: true, editing: wh });
  };

  const saveMut = useMutation({
    mutationFn: () => {
      const body: Record<string, unknown> = {
        name: form.name,
        url: form.url,
        events: form.events,
        ...(form.secret ? { secret: form.secret } : {}), // omitted on edit → keep stored value
      };
      return editor.editing ? apiKeysApi.updateWebhook(editor.editing.id, body) : apiKeysApi.createWebhook(body);
    },
    onSuccess: (saved) => {
      setEditor({ open: false, editing: null });
      setFe({});
      toastOk(editor.editing ? "Webhook updated" : "Webhook registered", saved.url);
      void qc.invalidateQueries({ queryKey: ["webhooks"] });
    },
    onError: (err) => {
      const fieldErrors = fieldErrorsOf(err);
      if (Object.keys(fieldErrors).length > 0) setFe(fieldErrors);
      else toastErr(err, editor.editing ? "Could not update the webhook" : "Could not register the webhook");
    },
  });

  const toggleMut = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => apiKeysApi.updateWebhook(id, { enabled }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["webhooks"] }),
    onError: (err) => toastErr(err, "Could not update the webhook"),
  });

  const deleteMut = useMutation({
    mutationFn: (id: number) => apiKeysApi.deleteWebhook(id),
    onSuccess: () => {
      setDeleteTarget(null);
      toastOk("Webhook deleted");
      void qc.invalidateQueries({ queryKey: ["webhooks"] });
    },
    onError: (err) => toastErr(err, "Could not delete the webhook"),
  });

  const [deliveriesFor, setDeliveriesFor] = useState<number | null>(null);
  const deliveriesQuery = useQuery({
    queryKey: ["webhooks", "deliveries", deliveriesFor],
    queryFn: () => apiKeysApi.listWebhookDeliveries(deliveriesFor!),
    enabled: deliveriesFor !== null,
  });

  const testMut = useMutation({
    mutationFn: (id: number) => apiKeysApi.testWebhook(id),
    onSuccess: (result, id) => {
      // REAL delivery result — M11 §5.6 (divergence closed): signed HTTPS POST + retries
      showToast({
        title: result.ok ? "Delivered" : "Delivery failed",
        description: result.ok
          ? `HTTP ${result.statusCode} · ${result.attempts} attempt(s) · ${result.durationMs} ms · sig ${result.signaturePrefix ?? "none"}…`
          : `${result.error ?? "unknown error"} · ${result.attempts} attempt(s)`,
        variant: result.ok ? "default" : "destructive",
      });
      void qc.invalidateQueries({ queryKey: ["webhooks"] });
      setDeliveriesFor(id); // open ledger so the user sees the attempt
    },
    onError: (err) => toastErr(err, "Test delivery failed"),
  });

  const toggleEvent = (ev: string) =>
    setForm((f) => ({
      ...f,
      events: f.events.includes(ev) ? f.events.filter((e) => e !== ev) : [...f.events, ev],
    }));

  const webhooks = query.data ?? [];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs text-zinc-500">
          Machine-facing change notifications — deliveries are <span className="font-medium">real HTTPS POSTs</span> signed with your HMAC secret (X-Cryptsk-Signature), with bounded retries and a per-webhook delivery ledger.
        </p>
        <Button size="sm" className="gap-1.5" onClick={openCreate}>
          <Icons.Webhook className="h-4 w-4" />
          Add webhook
        </Button>
      </div>

      {query.isLoading ? (
        <TableSkeleton rows={3} cols={7} />
      ) : query.isError ? (
        <QueryError error={query.error} onRetry={() => void query.refetch()} />
      ) : webhooks.length === 0 ? (
        <EmptyBlock
          icon={<Icons.Webhook className="h-6 w-6" />}
          title="No webhooks — register a callback endpoint"
          description="HTTPS-only URLs; events are limited to the five locked values (logs.tail is deliberately excluded). Secrets are write-only and never returned by the API."
          action={
            <Button size="sm" variant="outline" onClick={openCreate}>
              <Icons.Plus className="mr-1 h-4 w-4" /> Add webhook
            </Button>
          }
        />
      ) : (
        <div className="rounded-lg border border-zinc-200 dark:border-zinc-800">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>URL</TableHead>
                <TableHead>Events</TableHead>
                <TableHead>Enabled</TableHead>
                <TableHead>Last delivery</TableHead>
                <TableHead>Failures</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {webhooks.map((wh) => (
                <TableRow key={wh.id}>
                  <TableCell className="font-medium">{wh.name}</TableCell>
                  <TableCell>
                    <code className="block max-w-52 truncate font-mono text-xs text-zinc-600 dark:text-zinc-300" title={wh.url}>
                      {wh.url}
                    </code>
                  </TableCell>
                  <TableCell>
                    <div className="flex max-w-48 flex-wrap gap-1">
                      {wh.events.map((ev) => (
                        <Badge
                          key={ev}
                          variant="outline"
                          className="border-blue-500/40 bg-blue-500/10 font-mono text-[10px] text-blue-600 dark:text-blue-400"
                        >
                          {ev}
                        </Badge>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Switch
                      checked={wh.enabled}
                      disabled={toggleMut.isPending}
                      onCheckedChange={(enabled) => toggleMut.mutate({ id: wh.id, enabled })}
                      aria-label={`Enable ${wh.name}`}
                    />
                  </TableCell>
                  <TableCell>
                    <span className="flex items-center gap-1.5 text-xs text-zinc-500">
                      {fmtRelative(wh.lastDeliveryAt)}
                      <StatusChip status={wh.lastStatus} />
                    </span>
                  </TableCell>
                  <TableCell>
                    {wh.failureCount > 0 ? (
                      <Badge variant="outline" className="border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400">
                        {wh.failureCount}
                      </Badge>
                    ) : (
                      <span className="text-xs text-zinc-400">0</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center justify-end gap-0.5">
                      <Button size="icon" variant="ghost" className="h-7 w-7" aria-label={`Edit ${wh.name}`} onClick={() => openEdit(wh)}>
                        <Icons.Pencil className="h-3.5 w-3.5" />
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="h-7 gap-1 px-2 text-blue-600 hover:bg-blue-500/10 dark:text-blue-400"
                        disabled={testMut.isPending}
                        onClick={() => testMut.mutate(wh.id)}
                      >
                        <Icons.SendHorizontal className="h-3.5 w-3.5" />
                        {testMut.isPending && testMut.variables === wh.id ? "Testing…" : "Send test"}
                      </Button>
                      <Button
                        size="icon"
                        variant="ghost"
                        className="h-7 w-7"
                        aria-label={`Delivery history for ${wh.name}`}
                        onClick={() => setDeliveriesFor(wh.id)}
                      >
                        <Icons.History className="h-3.5 w-3.5" />
                      </Button>
                      <Button
                        size="icon"
                        variant="ghost"
                        className="h-7 w-7 text-rose-600 hover:bg-rose-500/10 hover:text-rose-700 dark:text-rose-400"
                        aria-label={`Delete ${wh.name}`}
                        onClick={() => setDeleteTarget(wh)}
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

      {/* create/edit dialog */}
      <Dialog open={editor.open} onOpenChange={(o) => setEditor((e) => ({ ...e, open: o }))}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{editor.editing ? "Edit webhook" : "Add webhook"}</DialogTitle>
            <DialogDescription>
              {editor.editing
                ? "Leave the secret empty to keep the stored value — it is never returned by the API."
                : "Register an HTTPS callback endpoint; the appliance delivers HMAC-SHA256-signed payloads."}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <FieldLabel hint="1–64 chars">Name</FieldLabel>
              <Input value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} placeholder="soc-alerts" autoFocus />
              <FieldError errors={fe.name} />
            </div>
            <div>
              <FieldLabel hint="https only">URL</FieldLabel>
              <Input
                type="url"
                value={form.url}
                onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))}
                placeholder="https://ops.example.com/hooks/cryptsk"
              />
              <FieldError errors={fe.url} />
            </div>
            <div>
              <FieldLabel hint="locked events">Events</FieldLabel>
              <div className="grid gap-1.5 sm:grid-cols-2">
                {WEBHOOK_EVENTS.map((ev) => {
                  const active = form.events.includes(ev);
                  return (
                    <label
                      key={ev}
                      className={cn(
                        "flex cursor-pointer items-start gap-2 rounded-md border p-2 text-xs transition-colors",
                        active
                          ? "border-blue-500/40 bg-blue-500/10 dark:border-blue-500/40"
                          : "border-zinc-200 hover:bg-zinc-50 dark:border-zinc-800 dark:hover:bg-zinc-900",
                      )}
                    >
                      <Checkbox className="mt-0.5" checked={active} onCheckedChange={() => toggleEvent(ev)} />
                      <span>
                        <span className="block font-mono font-medium">{ev}</span>
                        <span className="block text-[10px] text-zinc-400">{EVENT_HINTS[ev]}</span>
                      </span>
                    </label>
                  );
                })}
              </div>
              <FieldError errors={fe.events} />
            </div>
            <div>
              <FieldLabel hint={editor.editing ? "omit to keep" : "optional · 16–128 chars"}>HMAC secret</FieldLabel>
              <Input
                type="password"
                value={form.secret}
                onChange={(e) => setForm((f) => ({ ...f, secret: e.target.value }))}
                placeholder={editor.editing ? "•••••••• (keep stored secret)" : "Shared secret for payload signing"}
                autoComplete="new-password"
              />
              <FieldError errors={fe.secret} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditor({ open: false, editing: null })} disabled={saveMut.isPending}>
              Cancel
            </Button>
            <Button
              className="bg-blue-600 text-white hover:bg-blue-700"
              onClick={() => saveMut.mutate()}
              disabled={saveMut.isPending || !form.name.trim() || !form.url.trim() || form.events.length === 0}
            >
              {saveMut.isPending ? "Saving…" : editor.editing ? "Save changes" : "Register webhook"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* delete confirm */}
      <ConfirmDialog
        open={deleteTarget !== null}
        onOpenChange={(o) => (o ? null : setDeleteTarget(null))}
        title={`Delete webhook “${deleteTarget?.name ?? ""}”?`}
        description="The registration is removed immediately; its delivery ledger is discarded."
        confirmLabel="Delete"
        loading={deleteMut.isPending}
        onConfirm={() => deleteTarget && deleteMut.mutate(deleteTarget.id)}
      />

      {/* delivery ledger (real HTTPS attempts) */}
      <Dialog open={deliveriesFor !== null} onOpenChange={(o) => (o ? null : setDeliveriesFor(null))}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="text-base">Delivery ledger</DialogTitle>
            <DialogDescription>
              Last 50 real HTTPS attempts — signed with X-Cryptsk-Signature, bounded retries.
            </DialogDescription>
          </DialogHeader>
          <div className="max-h-96 overflow-y-auto">
            {deliveriesQuery.isLoading ? (
              <p className="py-6 text-center text-xs text-zinc-500">Loading…</p>
            ) : (deliveriesQuery.data ?? []).length === 0 ? (
              <p className="py-6 text-center text-xs text-zinc-500">No deliveries yet — use “Send test”.</p>
            ) : (
              <ul className="space-y-1.5">
                {(deliveriesQuery.data ?? []).map((d) => (
                  <li key={d.id} className="flex items-center gap-2 rounded-md border border-zinc-200 px-2.5 py-1.5 text-xs dark:border-zinc-800">
                    <span
                      className={
                        d.ok
                          ? "inline-block h-2 w-2 shrink-0 rounded-full bg-blue-600"
                          : "inline-block h-2 w-2 shrink-0 rounded-full bg-rose-500"
                      }
                      aria-hidden
                    />
                    <span className="font-mono">{d.event}</span>
                    <span className="text-zinc-500">
                      {d.ok ? `HTTP ${d.statusCode}` : (d.error ?? "failed")} · {d.attempts} attempt(s)
                      {d.durationMs !== null ? ` · ${d.durationMs} ms` : ""}
                    </span>
                    <span className="ml-auto shrink-0 text-zinc-400">
                      {new Date(d.createdAt).toLocaleTimeString()}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ── view shell ──────────────────────────────────────────────────────────────

export function ApiKeysView() {
  const [tab, setTab] = useState<TabKey>(() => tabFromHash());
  useEffect(() => {
    // keep the tab deep-linkable without retriggering hashchange
    history.replaceState(null, "", `#/system/api-keys?tab=${tab}`);
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
      <TabsContent value="keys" className="mt-3">
        <KeysTab />
      </TabsContent>
      <TabsContent value="webhooks" className="mt-3">
        <WebhooksTab />
      </TabsContent>
    </Tabs>
  );
}
