"use client";

/**
 * M19 RIB tab — live simulated FRR routing table. Refresh (POST) regenerates
 * rows from BGP/OSPF/static config; protocol filter + free-text search are
 * server-side (?protocol/?q).
 */

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
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
import { EmptyBlock, QueryError, TableSkeleton, toastErr, toastOk } from "@/components/views/firewall/fw-ui";
import { drApi, type RibProtocol } from "./dynamic-routing-api";
import { RibProtocolBadge } from "./dr-ui";

const RIB_KEY = ["dynamic-routing", "rib"] as const;

const PROTOCOLS: Array<RibProtocol | "all"> = ["all", "bgp", "ospf", "static", "connected"];

export function RibTab() {
  const qc = useQueryClient();
  const [protocol, setProtocol] = useState<RibProtocol | "all">("all");
  const [q, setQ] = useState("");

  const search = useMemo(() => q.trim(), [q]);
  const ribQ = useQuery({
    queryKey: [...RIB_KEY, protocol, search],
    queryFn: () => drApi.listRib(protocol === "all" ? undefined : protocol, search || undefined),
  });

  const refreshMut = useMutation({
    mutationFn: drApi.refreshRib,
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: ["dynamic-routing"] });
      toastOk(
        "RIB refreshed",
        `+${r.added} added · ${r.updated} updated · ${r.removed} removed — ${r.total} routes (bgp ${r.byProtocol.bgp}, ospf ${r.byProtocol.ospf}, static ${r.byProtocol.static}, connected ${r.byProtocol.connected})`,
      );
    },
    onError: (err) => toastErr(err, "RIB refresh failed"),
  });

  const rows = ribQ.data ?? [];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm text-zinc-500">
          Simulated FRR view — refresh syncs established BGP sessions, OSPF interfaces and static routes.
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <Select value={protocol} onValueChange={(v) => setProtocol(v as RibProtocol | "all")}>
            <SelectTrigger className="w-36" aria-label="Filter by protocol">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {PROTOCOLS.map((p) => (
                <SelectItem key={p} value={p}>
                  {p === "all" ? "all protocols" : p}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search prefix / next-hop…"
            className="w-56"
            aria-label="Search routes"
          />
          <Button
            className="gap-1.5 bg-blue-600 text-white hover:bg-blue-700"
            disabled={refreshMut.isPending}
            onClick={() => refreshMut.mutate()}
          >
            <Icons.RefreshCw className={refreshMut.isPending ? "h-4 w-4 animate-spin" : "h-4 w-4"} />
            Refresh RIB
          </Button>
        </div>
      </div>

      {ribQ.isLoading ? (
        <TableSkeleton rows={6} cols={7} />
      ) : ribQ.isError ? (
        <QueryError error={ribQ.error} onRetry={() => void ribQ.refetch()} />
      ) : rows.length === 0 ? (
        <EmptyBlock
          icon={<Icons.Route className="h-6 w-6" />}
          title="No routes"
          description={search || protocol !== "all" ? "No routes match the current filter." : "Refresh the RIB to sync from routing config."}
          action={
            <Button size="sm" variant="outline" className="gap-1" disabled={refreshMut.isPending} onClick={() => refreshMut.mutate()}>
              <Icons.RefreshCw className="h-3.5 w-3.5" />
              Refresh
            </Button>
          }
        />
      ) : (
        <div className="max-h-96 overflow-y-auto rounded-lg border border-zinc-200 dark:border-zinc-800 [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-zinc-300 dark:[&::-webkit-scrollbar-thumb]:bg-zinc-700">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-28">Protocol</TableHead>
                <TableHead>Prefix</TableHead>
                <TableHead>Next hop</TableHead>
                <TableHead>Interface</TableHead>
                <TableHead>Metric</TableHead>
                <TableHead>Local pref</TableHead>
                <TableHead>AS path</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((r) => (
                <TableRow key={r.id}>
                  <TableCell>
                    <RibProtocolBadge protocol={r.protocol} />
                  </TableCell>
                  <TableCell className="font-mono text-xs font-medium">{r.prefix}</TableCell>
                  <TableCell className="font-mono text-xs">{r.nextHop}</TableCell>
                  <TableCell className="font-mono text-xs">{r.interfaceName}</TableCell>
                  <TableCell className="font-mono text-xs">{r.metric}</TableCell>
                  <TableCell className="font-mono text-xs">{r.localPref === null ? "—" : r.localPref}</TableCell>
                  <TableCell className="max-w-56 truncate font-mono text-xs text-zinc-500">{r.asPath ?? "—"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
