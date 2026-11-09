"use client";

/**
 * #/vpn/sessions — live VPN session table (M05 §4). Filter bar (per-config
 * select, status chips, user/IP search), server-paginated rows and realtime
 * byte/status patching via `sessions:update {kind:"vpn"}` — rows update in
 * place without a refetch flash; status transitions under an active status
 * filter trigger a throttled refetch. Disconnect confirms first (M05 §5).
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useRealtime } from "@/lib/realtime";
import { cn } from "@/lib/utils";
import { fmtBytes, fmtDateTime, fmtRelative, vpnApi, type VpnSessionDto, type VpnSessionStatus } from "./vpn-api";
import { SessionStatusBadge, useVpnConfigInvalidation } from "./vpn-ui";
import { ConfirmDialog, EmptyBlock, QueryError, TableSkeleton, toastErr, toastOk } from "../firewall/fw-ui";

const SESSIONS_KEY = ["vpn", "sessions"] as const;
const CONFIGS_KEY = ["vpn", "configs"] as const;

interface SessionsPage {
  data: VpnSessionDto[];
  meta: { page: number; limit: number; total: number; totalPages: number };
}

export function SessionsView() {
  useVpnConfigInvalidation();
  const queryClient = useQueryClient();

  const [vpnId, setVpnId] = useState("all");
  const [status, setStatus] = useState<"all" | VpnSessionStatus>("all");
  const [qInput, setQInput] = useState("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const [kicking, setKicking] = useState<VpnSessionDto | null>(null);

  const configsQuery = useQuery({ queryKey: CONFIGS_KEY, queryFn: vpnApi.listConfigs });
  const configs = useMemo(() => configsQuery.data ?? [], [configsQuery.data]);

  // debounce free-text search
  useEffect(() => {
    const t = setTimeout(() => {
      setQ(qInput.trim());
      setPage(1);
    }, 350);
    return () => clearTimeout(t);
  }, [qInput]);

  const params = useMemo(() => {
    const sp = new URLSearchParams();
    if (vpnId !== "all") sp.set("vpnId", vpnId);
    if (status !== "all") sp.set("status", status);
    if (q) sp.set("q", q);
    sp.set("page", String(page));
    sp.set("limit", "25");
    return sp.toString();
  }, [vpnId, status, q, page]);

  const sessionsQuery = useQuery<SessionsPage>({
    queryKey: [...SESSIONS_KEY, params],
    queryFn: () => vpnApi.listSessions(params),
    refetchInterval: 15_000, // slow safety net; realtime does the fast path
  });

  // ── realtime patching (sessions:update {kind:"vpn", diff}) ─────────────────
  const filterRef = useRef({ vpnId, status });
  useEffect(() => {
    filterRef.current = { vpnId, status };
  }, [vpnId, status]);

  useRealtime(["sessions"], {
    onSessionsUpdate: (u) => {
      if (u.kind !== "vpn") return;
      const f = filterRef.current;
      let needsRefetch = false;
      queryClient.setQueriesData<SessionsPage>({ queryKey: [...SESSIONS_KEY] }, (prev) => {
        if (!prev) return prev;
        let rows = prev.data;
        for (const d of u.diff) {
          rows = rows.map((s) => {
            if (s.id !== d.id) return s;
            const next: VpnSessionDto = {
              ...s,
              bytesIn: d.bytesIn != null ? s.bytesIn + d.bytesIn : s.bytesIn,
              bytesOut: d.bytesOut != null ? s.bytesOut + d.bytesOut : s.bytesOut,
              lastActivity: d.lastActivity ?? s.lastActivity,
              status: (d.status as VpnSessionStatus) ?? s.status,
            };
            if (f.status !== "all" && next.status !== f.status) needsRefetch = true;
            return next;
          });
        }
        return { ...prev, data: rows };
      });
      if (needsRefetch) void queryClient.invalidateQueries({ queryKey: SESSIONS_KEY });
      // keep the configs-view session counts honest on connect/disconnect churn
      void queryClient.invalidateQueries({ queryKey: CONFIGS_KEY });
    },
  });

  const kickMut = useMutation({
    mutationFn: (id: number) => vpnApi.disconnectSession(id),
    onSuccess: () => {
      toastOk("Session disconnected", "The client will need to reconnect; the engine will not respawn it immediately.");
      setKicking(null);
      void queryClient.invalidateQueries({ queryKey: SESSIONS_KEY });
      void queryClient.invalidateQueries({ queryKey: CONFIGS_KEY });
    },
    onError: (err) => {
      setKicking(null);
      toastErr(err, "Disconnect failed");
    },
  });

  const rows = sessionsQuery.data?.data ?? [];
  const meta = sessionsQuery.data?.meta;
  const hasFilters = vpnId !== "all" || status !== "all" || q;
  const configName = (id: number) => configs.find((c) => c.id === id)?.name ?? `#${id}`;

  return (
    <div className="space-y-4">
      {/* filter bar */}
      <div className="flex flex-wrap items-center gap-2">
        <Select value={vpnId} onValueChange={(v) => { setVpnId(v); setPage(1); }}>
          <SelectTrigger className="w-52">
            <SelectValue placeholder="All tunnels" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All tunnels</SelectItem>
            {configs.map((c) => (
              <SelectItem key={c.id} value={String(c.id)}>
                {c.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select value={status} onValueChange={(v) => { setStatus(v as typeof status); setPage(1); }}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Any status</SelectItem>
            <SelectItem value="active">Active</SelectItem>
            <SelectItem value="idle">Idle</SelectItem>
            <SelectItem value="disconnected">Disconnected</SelectItem>
          </SelectContent>
        </Select>

        <div className="relative min-w-56 flex-1">
          <Icons.Search className="absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-400" />
          <Input
            value={qInput}
            onChange={(e) => setQInput(e.target.value)}
            placeholder="Search user or IP…"
            className="pl-8"
            aria-label="Search sessions"
          />
        </div>

        <div className="flex items-center gap-1.5 text-xs text-zinc-400">
          <Icons.Radio className="h-4 w-4 text-emerald-500" />
          live via sessions:update
        </div>
      </div>

      {sessionsQuery.isError ? (
        <QueryError error={sessionsQuery.error} onRetry={() => void sessionsQuery.refetch()} />
      ) : sessionsQuery.isLoading ? (
        <Card>
          <CardContent className="pt-6">
            <TableSkeleton rows={8} cols={8} />
          </CardContent>
        </Card>
      ) : rows.length === 0 ? (
        <Card>
          <CardContent className="p-0">
            <EmptyBlock
              icon={<Icons.Users className="h-6 w-6" />}
              title={hasFilters ? "No sessions match the filters" : "No VPN sessions"}
              description={
                hasFilters
                  ? "Loosen the filters or clear the search to see more rows."
                  : "Remote-access sessions appear here when clients connect (WireGuard, IPSec EAP or OpenVPN)."
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
                  <TableHead>User</TableHead>
                  <TableHead>Tunnel</TableHead>
                  <TableHead>Source IP</TableHead>
                  <TableHead>Assigned IP</TableHead>
                  <TableHead>Bytes in / out</TableHead>
                  <TableHead>Connected</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="w-10" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((s) => (
                  <TableRow key={s.id} className={cn(s.status === "disconnected" && "opacity-60")}>
                    <TableCell>
                      <div className="flex items-center gap-1.5">
                        <p className="font-medium">{s.userName ?? <span className="text-zinc-400">site-to-site</span>}</p>
                        {s.groupName ? (
                          <Badge variant="outline" className="border-zinc-500/40 bg-zinc-500/10 text-[10px] text-zinc-600 dark:text-zinc-400">
                            {s.groupName}
                          </Badge>
                        ) : null}
                      </div>
                      <p className="text-[11px] text-zinc-400">activity {fmtRelative(s.lastActivity)}</p>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs font-medium">{configName(s.vpnId)}</span>
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-xs">{s.sourceIp}</span>
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-xs">{s.assignedIp ?? "—"}</span>
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-xs tabular-nums">
                        ↓ {fmtBytes(s.bytesIn)} · ↑ {fmtBytes(s.bytesOut)}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs text-zinc-500">{fmtDateTime(s.connectedAt)}</span>
                    </TableCell>
                    <TableCell>
                      <SessionStatusBadge status={s.status} />
                    </TableCell>
                    <TableCell>
                      {s.status !== "disconnected" ? (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 gap-1 px-2 text-xs text-rose-600 hover:text-rose-600 dark:text-rose-400"
                          onClick={() => setKicking(s)}
                        >
                          <Icons.Unplug className="h-3.5 w-3.5" /> Disconnect
                        </Button>
                      ) : null}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* pagination */}
      {meta && meta.totalPages > 1 ? (
        <div className="flex items-center justify-between text-xs text-zinc-500">
          <span>
            Page {meta.page} of {meta.totalPages} · {meta.total} sessions
          </span>
          <div className="flex gap-1.5">
            <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>
              <Icons.ChevronLeft className="h-4 w-4" /> Prev
            </Button>
            <Button variant="outline" size="sm" disabled={page >= meta.totalPages} onClick={() => setPage((p) => p + 1)}>
              Next <Icons.ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      ) : null}

      <ConfirmDialog
        open={kicking != null}
        onOpenChange={(open) => !open && setKicking(null)}
        title={`Disconnect ${kicking?.userName ?? "session"}?`}
        description={
          kicking
            ? `${kicking.userName ?? "This peer"} (assigned ${kicking.assignedIp ?? "n/a"}) will be disconnected immediately. The engine will not respawn this session in the same window.`
            : ""
        }
        confirmLabel="Disconnect"
        loading={kickMut.isPending}
        onConfirm={() => kicking && kickMut.mutate(kicking.id)}
      />
    </div>
  );
}
