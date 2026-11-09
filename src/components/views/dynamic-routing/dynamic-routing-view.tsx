"use client";

/**
 * #/routing/dynamic — M19 Dynamic Routing view (spec 2.6). Four tabs (BGP,
 * OSPF, Policy Objects, RIB) under an aggregate overview strip fed by
 * /api/v1/dynamic-routing/overview. config:updated (section=dynamic_routing)
 * invalidates the whole ["dynamic-routing"] query family.
 */

import { useQuery, useQueryClient } from "@tanstack/react-query";
import * as Icons from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useRealtime } from "@/lib/realtime";
import { drApi } from "./dynamic-routing-api";
import { BgpTab } from "./bgp-tab";
import { OspfTab } from "./ospf-tab";
import { PolicyObjectsTab } from "./policy-tab";
import { RibTab } from "./rib-tab";

const OVERVIEW_KEY = ["dynamic-routing", "overview"] as const;

function OverviewStrip() {
  const q = useQuery({ queryKey: OVERVIEW_KEY, queryFn: drApi.getOverview });

  const cards = [
    {
      icon: Icons.Network,
      label: "BGP sessions",
      value: q.isLoading ? null : `${q.data?.bgp.established ?? 0}/${q.data?.bgp.total ?? 0}`,
      sub: "established / configured",
    },
    {
      icon: Icons.Share2,
      label: "OSPF adjacencies",
      value: q.isLoading ? null : String(q.data?.ospf.fullAdjacencies ?? 0),
      sub: q.isLoading ? "" : q.data?.ospf.enabled ? "full · process enabled" : "full · process disabled",
    },
    {
      icon: Icons.Route,
      label: "RIB routes",
      value: q.isLoading
        ? null
        : String(
            (q.data?.rib.bgp ?? 0) + (q.data?.rib.ospf ?? 0) + (q.data?.rib.static ?? 0) + (q.data?.rib.connected ?? 0),
          ),
      sub: q.isLoading
        ? ""
        : `bgp ${q.data?.rib.bgp ?? 0} · ospf ${q.data?.rib.ospf ?? 0} · static ${q.data?.rib.static ?? 0} · conn ${q.data?.rib.connected ?? 0}`,
    },
    {
      icon: Icons.Activity,
      label: "BFD profiles",
      value: q.isLoading ? null : String(q.data?.bfd.profiles ?? 0),
      sub: q.isLoading ? "" : `${q.data?.bfd.neighborsUsing ?? 0} neighbors attached`,
    },
  ];

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
      {cards.map((c) => {
        const Icon = c.icon;
        return (
          <Card key={c.label}>
            <CardContent className="flex items-center gap-4 p-4">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-red-600/10 text-red-700 dark:text-red-500">
                <Icon className="h-5 w-5" />
              </div>
              <div className="min-w-0">
                <p className="text-xs font-medium text-zinc-500">{c.label}</p>
                {c.value === null ? (
                  <Skeleton className="mt-1 h-6 w-16" />
                ) : (
                  <p className="truncate text-xl font-semibold leading-tight">{c.value}</p>
                )}
                {c.sub ? <p className="truncate text-[11px] text-zinc-400">{c.sub}</p> : null}
              </div>
            </CardContent>
          </Card>
        );
      })}
      {!q.isError ? null : (
        <Badge variant="outline" className="col-span-full border-rose-500/40 bg-rose-500/5 text-rose-600 dark:text-rose-400">
          overview unavailable — {q.error instanceof Error ? q.error.message : "request failed"}
        </Badge>
      )}
    </div>
  );
}

export function DynamicRoutingView() {
  const qc = useQueryClient();
  useRealtime(["config"], {
    onConfigUpdated: (c) => {
      if (c.section === "dynamic_routing") {
        void qc.invalidateQueries({ queryKey: ["dynamic-routing"] });
      }
    },
  });

  return (
    <div className="flex flex-col gap-6">
      <header className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">BGP &amp; OSPF</h1>
          <p className="text-sm text-zinc-500">
            Dynamic routing control plane — peering sessions, OSPF process, policy objects and the simulated FRR RIB.
          </p>
        </div>
        <Badge variant="outline" className="border-red-600/40 bg-red-600/10 font-mono text-red-700 dark:text-red-500">
          spec 2.6
        </Badge>
      </header>

      <OverviewStrip />

      <Tabs defaultValue="bgp" className="gap-6">
        <TabsList className="h-auto w-full flex-wrap justify-start sm:w-auto">
          <TabsTrigger value="bgp" className="gap-1.5">
            <Icons.Network className="h-4 w-4" />
            BGP
          </TabsTrigger>
          <TabsTrigger value="ospf" className="gap-1.5">
            <Icons.Share2 className="h-4 w-4" />
            OSPF
          </TabsTrigger>
          <TabsTrigger value="policy" className="gap-1.5">
            <Icons.ListFilter className="h-4 w-4" />
            Policy Objects
          </TabsTrigger>
          <TabsTrigger value="rib" className="gap-1.5">
            <Icons.Route className="h-4 w-4" />
            RIB
          </TabsTrigger>
        </TabsList>

        <TabsContent value="bgp">
          <BgpTab />
        </TabsContent>
        <TabsContent value="ospf">
          <OspfTab />
        </TabsContent>
        <TabsContent value="policy">
          <PolicyObjectsTab />
        </TabsContent>
        <TabsContent value="rib">
          <RibTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
