"use client";

/**
 * Captive Portal view (M07 §4) — hash #/identity/portal.
 * Stacked cards: (1) portal settings form — enabled, mode with per-mode
 * captions, interface, session timeout, bandwidth cap, redirect URL, voucher
 * TTL; (2) guest vouchers — generation dialog (N codes, one-time full reveal,
 * Copy all + CSV), masked list with state badges + revoke. Vouchers are
 * volatile in sandbox (MockEngine in-memory, SCHEMA.md §6) — labeled.
 */

import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
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
import { ConfirmDialog, EmptyBlock, FieldLabel, QueryError, TableSkeleton, toastErr, toastOk } from "@/components/views/firewall/fw-ui";
import { fieldErrorsOf, fmtDateTime, portalApi, type CaptivePortalDTO } from "./identity-api";
import { InfoNote, VoucherStateBadge } from "./identity-ui";
import { cn } from "@/lib/utils";

const MODE_CAPTIONS: Record<string, string> = {
  clickthrough: "Guests accept an AUP banner — no credentials.",
  credentials: "Guests sign in with a username/password (simulated self-registration).",
  voucher: "Guests redeem a time-limited voucher code (generated below).",
};

type VoucherStateFilter = "all" | "unused" | "used" | "expired";

export function PortalView() {
  const q = useQuery({ queryKey: ["portal", "profile"], queryFn: portalApi.get });

  if (q.isLoading) {
    return (
      <Card>
        <CardContent className="space-y-3 pt-6">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-9 w-full animate-pulse rounded-md bg-zinc-100 dark:bg-zinc-800" />
          ))}
        </CardContent>
      </Card>
    );
  }
  if (q.isError) return <QueryError error={q.error} onRetry={() => void q.refetch()} />;
  if (!q.data) return null;

  return (
    <div className="space-y-4">
      {!q.data.enabled && (
        <Alert className="border-amber-500/40 bg-amber-500/5">
          <Icons.PauseCircle className="h-4 w-4 text-amber-500" />
          <AlertTitle>Captive portal is disabled</AlertTitle>
          <AlertDescription>Guest networks pass through without interception. Enable it in Portal Settings.</AlertDescription>
        </Alert>
      )}
      <PortalForm initial={q.data} />
      <VouchersCard mode={q.data.mode} voucherTtlHours={q.data.voucherTtlHours} />
    </div>
  );
}

// ── portal settings ─────────────────────────────────────────────────────────

function PortalForm({ initial }: { initial: CaptivePortalDTO }) {
  const queryClient = useQueryClient();
  const [form, setForm] = useState({
    name: initial.name,
    enabled: initial.enabled,
    mode: initial.mode,
    interfaceName: initial.interfaceName,
    sessionTimeoutMin: String(initial.sessionTimeoutMin),
    bandwidthKbps: initial.bandwidthKbps ? String(initial.bandwidthKbps) : "",
    redirectUrl: initial.redirectUrl ?? "",
    voucherTtlHours: String(initial.voucherTtlHours),
  });
  const [errs, setErrs] = useState<Record<string, string[]>>({});

  const ifacesQ = useQuery({
    queryKey: ["portal", "interfaces"],
    queryFn: () => fetch("/api/v1/interfaces?limit=100", { credentials: "same-origin" }).then((r) => r.json()) as Promise<{ data?: Array<{ name: string; role: string; enabled: boolean }> }>,
  });

  const save = useMutation({
    mutationFn: () =>
      portalApi.put({
        name: form.name,
        enabled: form.enabled,
        mode: form.mode,
        interfaceName: form.interfaceName,
        sessionTimeoutMin: Number(form.sessionTimeoutMin),
        bandwidthKbps: form.bandwidthKbps ? Number(form.bandwidthKbps) : null,
        redirectUrl: form.redirectUrl,
        voucherTtlHours: Number(form.voucherTtlHours),
      }),
    onSuccess: () => {
      toastOk("Portal settings saved");
      void queryClient.invalidateQueries({ queryKey: ["portal"] });
    },
    onError: (e) => {
      setErrs(fieldErrorsOf(e));
      toastErr(e, "Save failed");
    },
  });

  return (
    <Card className="gap-4">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Icons.Wifi className="h-4 w-4 text-blue-600 dark:text-blue-400" />
          Portal Settings
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <div>
            <FieldLabel>Profile name</FieldLabel>
            <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.currentTarget.value })} className={cn(errs.name && "border-rose-500")} />
          </div>
          <div className="flex items-end justify-between gap-3 pb-1">
            <div>
              <p className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Enabled</p>
              <p className="text-[11px] text-zinc-400">Intercept guest traffic on the portal interface</p>
            </div>
            <Switch checked={form.enabled} onCheckedChange={(v) => setForm({ ...form, enabled: v })} aria-label="Portal enabled" />
          </div>
        </div>

        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <div>
            <FieldLabel>Mode</FieldLabel>
            <Select value={form.mode} onValueChange={(v) => setForm({ ...form, mode: v })}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="clickthrough">clickthrough</SelectItem>
                <SelectItem value="credentials">credentials</SelectItem>
                <SelectItem value="voucher">voucher</SelectItem>
              </SelectContent>
            </Select>
            <p className="mt-1 text-[11px] text-zinc-400">{MODE_CAPTIONS[form.mode]}</p>
          </div>
          <div>
            <FieldLabel>Interface</FieldLabel>
            <Select value={form.interfaceName} onValueChange={(v) => setForm({ ...form, interfaceName: v })}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(ifacesQ.data?.data ?? []).map((i) => (
                  <SelectItem key={i.name} value={i.name}>
                    {i.name}
                    <span className="ml-1 text-[10px] text-zinc-400">{i.role}</span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <div>
            <FieldLabel hint="5–1440">Session timeout (min)</FieldLabel>
            <Input
              type="number"
              value={form.sessionTimeoutMin}
              onChange={(e) => setForm({ ...form, sessionTimeoutMin: e.currentTarget.value })}
              className={cn(errs.sessionTimeoutMin && "border-rose-500")}
            />
          </div>
          <div>
            <FieldLabel hint="optional · per-guest QoS cap">Bandwidth (kbps)</FieldLabel>
            <Input
              type="number"
              value={form.bandwidthKbps}
              onChange={(e) => setForm({ ...form, bandwidthKbps: e.currentTarget.value })}
              placeholder="e.g. 5120"
              className={cn(errs.bandwidthKbps && "border-rose-500")}
            />
          </div>
          <div>
            <FieldLabel hint="1–720">Voucher TTL (hours)</FieldLabel>
            <Input
              type="number"
              value={form.voucherTtlHours}
              onChange={(e) => setForm({ ...form, voucherTtlHours: e.currentTarget.value })}
              className={cn(errs.voucherTtlHours && "border-rose-500")}
            />
          </div>
        </div>

        <div>
          <FieldLabel hint="optional">Redirect URL after sign-in</FieldLabel>
          <Input
            value={form.redirectUrl}
            onChange={(e) => setForm({ ...form, redirectUrl: e.currentTarget.value })}
            placeholder="https://intranet.local/welcome"
            className={cn(errs.redirectUrl && "border-rose-500")}
          />
          {errs.redirectUrl?.map((m) => (
            <p key={m} className="mt-1 text-[11px] text-rose-500">{m}</p>
          ))}
        </div>

        <div className="flex items-center justify-between gap-3">
          <InfoNote>In credentials mode the MockEngine occasionally self-registers a guest (display-only behavior).</InfoNote>
          <Button onClick={() => void save.mutateAsync()} disabled={save.isPending}>
            {save.isPending ? "Saving…" : "Save portal settings"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ── vouchers ────────────────────────────────────────────────────────────────

function VouchersCard({ mode, voucherTtlHours }: { mode: string; voucherTtlHours: number }) {
  const queryClient = useQueryClient();
  const [genOpen, setGenOpen] = useState(false);
  const [reveal, setReveal] = useState<Array<{ id: number; code: string; expiresAt: string }> | null>(null);
  const [revoke, setRevoke] = useState<{ id: number } | null>(null);
  const [stateFilter, setStateFilter] = useState<VoucherStateFilter>("all");

  const listQ = useQuery({
    queryKey: ["portal", "vouchers"],
    queryFn: portalApi.listVouchers,
    refetchInterval: 20_000,
  });

  const delMut = useMutation({
    mutationFn: (id: number) => portalApi.revokeVoucher(id),
    onSuccess: () => {
      toastOk("Voucher revoked");
      void queryClient.invalidateQueries({ queryKey: ["portal", "vouchers"] });
      setRevoke(null);
    },
    onError: (e) => toastErr(e, "Revoke failed"),
  });

  const rows = useMemo(() => {
    const all = listQ.data ?? [];
    return stateFilter === "all" ? all : all.filter((v) => v.state === stateFilter);
  }, [listQ.data, stateFilter]);

  const downloadMaskedCsv = () => {
    const header = "code,createdAt,expiresAt,usedAt,state";
    const lines = rows.map((v) => [v.codeMasked, v.createdAt, v.expiresAt, v.usedAt ?? "", v.state].join(","));
    const blob = new Blob([`${header}\n${lines.join("\n")}`], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "vouchers-masked.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Card className="gap-4">
      <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2 space-y-0">
        <CardTitle className="flex items-center gap-2 text-base">
          <Icons.Ticket className="h-4 w-4 text-blue-600 dark:text-blue-400" />
          Guest Vouchers
          <Badge variant="outline" className="border-amber-500/40 bg-amber-500/10 px-1.5 py-0 text-[10px] text-amber-600 dark:text-amber-400">
            volatile in sandbox
          </Badge>
        </CardTitle>
        <Button size="sm" className="h-9" disabled={mode !== "voucher"} onClick={() => setGenOpen(true)}>
          <Icons.TicketPlus className="mr-1 h-3.5 w-3.5" /> Generate vouchers
        </Button>
      </CardHeader>
      <CardContent className="px-0">
        {mode !== "voucher" && (
          <div className="px-6 pb-2">
            <InfoNote>Generation is disabled — switch the portal mode to &ldquo;voucher&rdquo; first.</InfoNote>
          </div>
        )}
        {listQ.isLoading ? (
          <div className="px-6">
            <TableSkeleton rows={4} cols={6} />
          </div>
        ) : listQ.isError ? (
          <QueryError error={listQ.error} onRetry={() => void listQ.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyBlock
            icon={<Icons.Ticket className="h-6 w-6" />}
            title="No vouchers yet"
            description={mode === "voucher" ? "Generate a batch of time-limited guest codes." : "Switch the portal mode to voucher to enable generation."}
            action={
              mode === "voucher" ? (
                <Button size="sm" variant="outline" onClick={() => setGenOpen(true)}>
                  <Icons.TicketPlus className="mr-1 h-3.5 w-3.5" /> Generate vouchers
                </Button>
              ) : undefined
            }
          />
        ) : (
          <>
            <div className="mb-2 flex flex-wrap items-center gap-1.5 px-6">
              {(["all", "unused", "used", "expired"] as VoucherStateFilter[]).map((f) => (
                <button
                  key={f}
                  type="button"
                  onClick={() => setStateFilter(f)}
                  aria-pressed={stateFilter === f}
                  className={cn(
                    "rounded-full border px-2.5 py-1 text-xs transition-colors",
                    stateFilter === f
                      ? "border-blue-500/40 bg-blue-500/10 font-medium text-blue-600 dark:text-blue-400"
                      : "border-zinc-200 text-zinc-500 hover:bg-zinc-100 dark:border-zinc-800 dark:text-zinc-400 dark:hover:bg-zinc-800",
                  )}
                >
                  {f}
                </button>
              ))}
              <Button variant="outline" size="sm" className="ml-auto h-7 text-[11px]" onClick={downloadMaskedCsv}>
                <Icons.Download className="mr-1 h-3 w-3" /> CSV (masked)
              </Button>
            </div>
            <div className="max-h-96 overflow-x-auto overflow-y-auto">
              <Table>
                <TableHeader className="sticky top-0 bg-card">
                  <TableRow>
                    <TableHead>Code</TableHead>
                    <TableHead>State</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead>Expires</TableHead>
                    <TableHead>Used</TableHead>
                    <TableHead className="w-10" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((v) => (
                    <TableRow key={v.id}>
                      <TableCell>
                        <code className="font-mono text-xs tracking-wide">{v.codeMasked}</code>
                        {v.bandwidthKbps ? (
                          <Badge variant="outline" className="ml-2 border-zinc-300 bg-zinc-50 px-1 py-0 text-[9px] text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800/60">
                            {v.bandwidthKbps} kbps
                          </Badge>
                        ) : null}
                      </TableCell>
                      <TableCell>
                        <VoucherStateBadge state={v.state} />
                      </TableCell>
                      <TableCell className="text-xs text-zinc-500">{fmtDateTime(v.createdAt)}</TableCell>
                      <TableCell className="text-xs text-zinc-500">{fmtDateTime(v.expiresAt)}</TableCell>
                      <TableCell className="text-xs text-zinc-500">{v.usedAt ? fmtDateTime(v.usedAt) : "—"}</TableCell>
                      <TableCell>
                        {v.state === "unused" && (
                          <>
                            <ConfirmDialog
                              open={revoke?.id === v.id}
                              onOpenChange={(o) => !o && setRevoke(null)}
                              title="Revoke this voucher?"
                              description="The code stops working immediately. This cannot be undone."
                              loading={delMut.isPending}
                              onConfirm={() => void delMut.mutateAsync(v.id)}
                            />
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-8 w-8 text-zinc-400 hover:text-rose-500"
                              aria-label={`Revoke voucher ${v.codeMasked}`}
                              onClick={() => setRevoke({ id: v.id })}
                            >
                              <Icons.Ban className="h-4 w-4" />
                            </Button>
                          </>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </>
        )}
      </CardContent>

      <GenerateDialog
        open={genOpen}
        voucherTtlHours={voucherTtlHours}
        onClose={() => setGenOpen(false)}
        onGenerated={(codes) => {
          setGenOpen(false);
          setReveal(codes);
          void queryClient.invalidateQueries({ queryKey: ["portal", "vouchers"] });
        }}
      />

      {/* one-time reveal — full codes are never shown again after closing */}
      <Dialog open={reveal !== null} onOpenChange={(o) => !o && setReveal(null)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Icons.Ticket className="h-5 w-5 text-emerald-600" />
              {reveal?.length ?? 0} voucher codes generated
            </DialogTitle>
            <DialogDescription>
              Shown <strong>only once</strong> — copy or download now. The list shows masked codes afterwards.
            </DialogDescription>
          </DialogHeader>
          <div className="max-h-64 overflow-y-auto rounded-md border border-zinc-200 bg-zinc-50 p-3 dark:border-zinc-800 dark:bg-zinc-900">
            <ul className="space-y-1 font-mono text-xs">
              {(reveal ?? []).map((v) => (
                <li key={v.id} className="flex items-center justify-between gap-2">
                  <span className="tracking-widest">{v.code}</span>
                  <span className="text-[10px] text-zinc-400">exp {fmtDateTime(v.expiresAt)}</span>
                </li>
              ))}
            </ul>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                if (!reveal) return;
                void navigator.clipboard.writeText(reveal.map((v) => v.code).join("\n"));
                toastOk("Copied", `${reveal.length} codes on the clipboard`);
              }}
            >
              <Icons.Copy className="mr-1 h-3.5 w-3.5" /> Copy all
            </Button>
            <Button
              onClick={() => {
                if (!reveal) return;
                const header = "code,expiresAt";
                const lines = reveal.map((v) => `${v.code},${v.expiresAt}`).join("\n");
                const blob = new Blob([`${header}\n${lines}`], { type: "text/csv" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = "vouchers-full.csv";
                a.click();
                URL.revokeObjectURL(url);
              }}
            >
              <Icons.Download className="mr-1 h-3.5 w-3.5" /> Download CSV
            </Button>
            <Button variant="ghost" onClick={() => setReveal(null)}>
              Done
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

function GenerateDialog(props: {
  open: boolean;
  voucherTtlHours: number;
  onClose: () => void;
  onGenerated: (codes: Array<{ id: number; code: string; expiresAt: string }>) => void;
}) {
  // Radix unmounts content when closed — the form remounts fresh per open.
  return (
    <Dialog open={props.open} onOpenChange={(o) => !o && props.onClose()}>
      <DialogContent className="sm:max-w-sm">
        <GenerateForm voucherTtlHours={props.voucherTtlHours} onClose={props.onClose} onGenerated={props.onGenerated} />
      </DialogContent>
    </Dialog>
  );
}

function GenerateForm(props: {
  voucherTtlHours: number;
  onClose: () => void;
  onGenerated: (codes: Array<{ id: number; code: string; expiresAt: string }>) => void;
}) {
  const [count, setCount] = useState("10");
  const [ttlHours, setTtlHours] = useState(() => String(props.voucherTtlHours));
  const [bandwidthKbps, setBandwidthKbps] = useState("");
  const [errs, setErrs] = useState<Record<string, string[]>>({});

  const gen = useMutation({
    mutationFn: () =>
      portalApi.generateVouchers({
        count: Number(count),
        ttlHours: Number(ttlHours),
        ...(bandwidthKbps ? { bandwidthKbps: Number(bandwidthKbps) } : {}),
      }),
    onSuccess: (codes) => props.onGenerated(codes),
    onError: (e) => {
      setErrs(fieldErrorsOf(e));
      toastErr(e, "Generation failed");
    },
  });

  const n = Number(count);
  return (
    <>
      <DialogHeader>
        <DialogTitle>Generate vouchers</DialogTitle>
        <DialogDescription>Codes are Crockford base32, unique among live vouchers, and revealed once.</DialogDescription>
      </DialogHeader>
        <div className="space-y-3">
          <div>
            <FieldLabel hint="1–500">Count</FieldLabel>
            <Input type="number" value={count} onChange={(e) => setCount(e.currentTarget.value)} className={cn(errs.count && "border-rose-500")} />
            {errs.count?.map((m) => (
              <p key={m} className="mt-1 text-[11px] text-rose-500">{m}</p>
            ))}
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <div>
              <FieldLabel hint="defaults to profile">TTL (hours)</FieldLabel>
              <Input type="number" value={ttlHours} onChange={(e) => setTtlHours(e.currentTarget.value)} className={cn(errs.ttlHours && "border-rose-500")} />
            </div>
            <div>
              <FieldLabel hint="optional">Bandwidth (kbps)</FieldLabel>
              <Input type="number" value={bandwidthKbps} onChange={(e) => setBandwidthKbps(e.currentTarget.value)} placeholder="profile default" className={cn(errs.bandwidthKbps && "border-rose-500")} />
            </div>
          </div>
        </div>
      <DialogFooter>
        <Button variant="outline" onClick={props.onClose}>Cancel</Button>
        <Button onClick={() => void gen.mutateAsync()} disabled={gen.isPending || !n || n < 1 || n > 500}>
          {gen.isPending ? "Generating…" : `Generate ${Number.isNaN(n) ? "" : n}`}
        </Button>
      </DialogFooter>
    </>
  );
}
