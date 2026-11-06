"use client";

/**
 * Identity Sessions view (M07 §4) — hash #/identity/sessions.
 * Live ip→user map from local/RADIUS/captive-portal/VPN auth. Read-only live
 * table: method filter chips, ticking lastSeen, force-expire row action.
 * `sessions:update {kind:"identity"}` diffs patch rows in place without a
 * full refetch (merged within one tick).
 */

import { useEffect, useMemo, useState, useSyncExternalStore } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { ConfirmDialog, EmptyBlock, QueryError, TableSkeleton, toastErr, toastOk } from "@/components/views/firewall/fw-ui";
import { fmtAgo, sessionsApi, type IdentitySessionDTO } from "./identity-api";
import { MethodBadge } from "./identity-ui";
import { getSocket, useRealtime } from "@/lib/realtime";
import { cn } from "@/lib/utils";

type MethodFilter = "all" | "local" | "radius" | "captive_portal" | "vpn";

const METHOD_FILTERS: Array<{ key: MethodFilter; label: string }> = [
  { key: "all", label: "All" },
  { key: "local", label: "local" },
  { key: "radius", label: "radius" },
  { key: "captive_portal", label: "captive_portal" },
  { key: "vpn", label: "vpn" },
];

export function IdentitySessionsView() {
  const queryClient = useQueryClient();
  const [method, setMethod] = useState<MethodFilter>("all");
  const [q, setQ] = useState("");
  const [expire, setExpire] = useState<IdentitySessionDTO | null>(null);
  const [, setClock] = useState(0); // re-render for the ticking lastSeen labels

  // socket connection status as an external store — no setState-in-effect
  const socketConnected = useSyncExternalStore(
    (cb) => {
      const s = getSocket();
      s.on("connect", cb);
      s.on("disconnect", cb);
      return () => {
        s.off("connect", cb);
        s.off("disconnect", cb);
      };
    },
    () => getSocket().connected,
    () => true,
  );
  const livePaused = !socketConnected;

  useEffect(() => {
    const t = window.setInterval(() => setClock((c) => c + 1), 5000);
    return () => window.clearInterval(t);
  }, []);

  const state = "active";
  const params = useMemo(() => {
    const p = new URLSearchParams({ state });
    if (method !== "all") p.set("method", method);
    if (q) p.set("q", q);
    return p.toString();
  }, [method, q]);

  const listQ = useQuery({
    queryKey: ["identity", "sessions", params],
    queryFn: () => sessionsApi.list(params),
    refetchInterval: 15_000,
  });

  // realtime: merge identity diffs in place; flip the live banner on disconnect
  useRealtime(["sessions"], {
    onSessionsUpdate: (u) => {
      if (u.kind !== "identity") return;
      queryClient.setQueryData<{ data: IdentitySessionDTO[] }>(["identity", "sessions", params], (prev) => {
        if (!prev) return prev;
        let rows = prev.data;
        for (const d of u.diff) {
          const idx = rows.findIndex((r) => r.id === d.id);
          if (d.status === "expired") {
            if (state === "active") {
              rows = idx >= 0 ? rows.filter((r) => r.id !== d.id) : rows;
            } else if (idx >= 0) {
              rows = rows.map((r) => (r.id === d.id ? { ...r, state: "expired" } : r));
            }
          } else if (idx >= 0) {
            rows = rows.map((r) =>
              r.id === d.id
                ? { ...r, userName: d.userName ?? r.userName, state: d.status ?? r.state, lastSeen: d.lastActivity ?? r.lastSeen }
                : r,
            );
          } else {
            // new login we don't have yet — a refetch picks up full row data
            void queryClient.invalidateQueries({ queryKey: ["identity", "sessions"] });
          }
        }
        return { ...prev, data: rows };
      });
    },
  });

  const expireMut = useMutation({
    mutationFn: (id: number) => sessionsApi.expire(id),
    onSuccess: () => {
      toastOk("Session expired", "The row flipped to expired without a reload.");
      void queryClient.invalidateQueries({ queryKey: ["identity", "sessions"] });
      setExpire(null);
    },
    onError: (e) => toastErr(e, "Expire failed"),
  });

  const rows = listQ.data?.data ?? [];

  return (
    <div className="space-y-3">
      {livePaused && (
        <Alert className="border-amber-500/40 bg-amber-500/5">
          <Icons.WifiOff className="h-4 w-4 text-amber-500" />
          <AlertTitle>Live updates paused</AlertTitle>
          <AlertDescription>Socket disconnected — rows refresh on reconnect or manual reload.</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardContent className="pt-6">
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <div className="flex flex-wrap gap-1.5">
              {METHOD_FILTERS.map((f) => (
                <button
                  key={f.key}
                  type="button"
                  onClick={() => setMethod(f.key)}
                  aria-pressed={method === f.key}
                  className={cn(
                    "rounded-full border px-2.5 py-1 text-xs transition-colors",
                    method === f.key
                      ? "border-blue-500/40 bg-blue-500/10 font-medium text-blue-600 dark:text-blue-400"
                      : "border-zinc-200 text-zinc-500 hover:bg-zinc-100 dark:border-zinc-800 dark:text-zinc-400 dark:hover:bg-zinc-800",
                  )}
                >
                  {f.label}
                </button>
              ))}
            </div>
            <div className="ml-auto flex items-center gap-2">
              <Badge variant="outline" className="gap-1 border-emerald-500/40 bg-emerald-500/10 px-1.5 py-0 text-[10px] text-emerald-600 dark:text-emerald-400">
                <span className="relative flex h-1.5 w-1.5">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-500 opacity-60" />
                  <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-500" />
                </span>
                live
              </Badge>
              <Input
                value={q}
                onChange={(e) => setQ(e.currentTarget.value)}
                placeholder="Search ip / user / mac…"
                aria-label="Search identity sessions"
                className="h-9 w-40 text-xs sm:w-56"
              />
            </div>
          </div>

          {listQ.isLoading ? (
            <TableSkeleton rows={8} cols={6} />
          ) : listQ.isError ? (
            <QueryError error={listQ.error} onRetry={() => void listQ.refetch()} />
          ) : rows.length === 0 ? (
            <EmptyBlock
              icon={<Icons.Fingerprint className="h-6 w-6" />}
              title="No active identity sessions"
              description="Users appear here after a local, RADIUS, captive-portal or VPN login."
            />
          ) : (
            <div className="max-h-96 overflow-x-auto overflow-y-auto">
              <Table>
                <TableHeader className="sticky top-0 bg-card">
                  <TableRow>
                    <TableHead>Source IP</TableHead>
                    <TableHead>User</TableHead>
                    <TableHead>Method</TableHead>
                    <TableHead>Device MAC</TableHead>
                    <TableHead>Started</TableHead>
                    <TableHead>Last seen</TableHead>
                    <TableHead className="w-10" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((s) => (
                    <TableRow key={s.id}>
                      <TableCell className="font-mono text-xs">{s.sourceIp}</TableCell>
                      <TableCell className="font-medium">{s.userName}</TableCell>
                      <TableCell>
                        <MethodBadge method={s.method} />
                      </TableCell>
                      <TableCell className="font-mono text-[11px] text-zinc-500">{s.deviceMac ?? "—"}</TableCell>
                      <TableCell className="text-xs text-zinc-500">{fmtAgo(s.startedAt)}</TableCell>
                      <TableCell className="text-xs text-zinc-500">{fmtAgo(s.lastSeen)}</TableCell>
                      <TableCell>
                        <ConfirmDialog
                          open={expire?.id === s.id}
                          onOpenChange={(o) => !o && setExpire(null)}
                          title={`Expire session for "${s.userName}"?`}
                          description={`${s.sourceIp} loses its identity mapping immediately — user-based rules will treat this IP as unknown.`}
                          confirmLabel="Expire session"
                          loading={expireMut.isPending}
                          onConfirm={() => void expireMut.mutateAsync(s.id)}
                        />
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8 text-zinc-400 hover:text-rose-500"
                          aria-label={`Expire session for ${s.userName}`}
                          onClick={() => setExpire(s)}
                        >
                          <Icons.TimerOff className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
