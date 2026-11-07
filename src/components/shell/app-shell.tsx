"use client";

/**
 * AppShell — the single-route SPA shell (ADR-006).
 * Auth gate → sidebar + topbar + hash-routed view area. Deep links, back/forward
 * and refresh all work via hash. No other Next.js routes exist.
 */

import { useCallback, useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useTheme } from "next-themes";
import * as Icons from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Sheet, SheetContent, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { ScrollArea } from "@/components/ui/scroll-area";
import { NAV_GROUPS, VIEWS, viewFor, type ViewDef } from "./nav-config";
import { LoginView } from "@/components/views/login/login-view";
import { DashboardView } from "@/components/views/dashboard/dashboard-view";
import { PlaceholderView } from "@/components/views/placeholder/placeholder-view";
import { RulesView } from "@/components/views/firewall/rules-view";
import { NatView } from "@/components/views/firewall/nat-view";
import { ObjectsView } from "@/components/views/firewall/objects-view";
import { ZonesView } from "@/components/views/firewall/zones-view";
import { InterfacesView } from "@/components/views/network/interfaces-view";
import { RoutingView } from "@/components/views/network/routing-view";
import { WanView } from "@/components/views/network/wan-view";
import { PoliciesView } from "@/components/views/ips/policies-view";
import { EventsView } from "@/components/views/ips/events-view";
import { ConfigsView } from "@/components/views/vpn/configs-view";
import { SessionsView } from "@/components/views/vpn/sessions-view";
import { DnsView } from "@/components/views/dns-dhcp/dns-view";
import { DhcpView } from "@/components/views/dns-dhcp/dhcp-view";
import { UsersView } from "@/components/views/identity/users-view";
import { IdentitySessionsView } from "@/components/views/identity/sessions-view";
import { PortalView } from "@/components/views/identity/portal-view";
import { QosView } from "@/components/views/qos/qos-view";
import { FirewallLogsView } from "@/components/views/logs/firewall-logs-view";
import { IpsLogsView } from "@/components/views/logs/ips-logs-view";
import { AuditView } from "@/components/views/logs/audit-view";
import { LiveTailView } from "@/components/views/logs/live-tail-view";
import { ReportsView } from "@/components/views/logs/reports-view";
import { ApiKeysView } from "@/components/views/system/api-keys-view";
// Phase 2 views (M12–M14 batch 1)
import { SearchView } from "@/components/views/logs/search-view";
import { ComplianceView } from "@/components/views/logs/compliance-view";
import { FeedsView } from "@/components/views/threat-intel/feeds-view";
import { IocsView } from "@/components/views/threat-intel/iocs-view";
import { AutoBlockView } from "@/components/views/threat-intel/auto-block-view";
import { AuthoritiesView } from "@/components/views/pki/authorities-view";
import { CertificatesView } from "@/components/views/pki/certificates-view";
import { HaView } from "@/components/views/ha/ha-view";
import { SystemView } from "@/components/views/system/system-view";
import { BackupsView } from "@/components/views/system/backups-view";
import { NotificationCenter } from "@/components/views/system/notification-center";
import { SetupWizard, useSetupCompleted } from "@/components/views/setup/setup-wizard";
import { fetchApi, useRealtime } from "@/lib/realtime";
import { cn } from "@/lib/utils";

type Me = {
  kind: "user" | "key";
  username: string;
  role?: string;
  tenantId: number;
  permissions: { read: string[]; write: string[]; admin: string[] };
};

function useHashRoute(): string {
  const [hash, setHash] = useState("");
  useEffect(() => {
    const apply = () => setHash(window.location.hash || "#/dashboard");
    apply();
    window.addEventListener("hashchange", apply);
    return () => window.removeEventListener("hashchange", apply);
  }, []);
  return hash;
}

function Icon({ name, className }: { name: string; className?: string }) {
  const C = (Icons as unknown as Record<string, React.ComponentType<{ className?: string }>>)[name] ?? Icons.Circle;
  return <C className={className} />;
}

function SidebarNav({ current, onNavigate }: { current: string; onNavigate?: () => void }) {
  return (
    <nav aria-label="Console navigation" className="flex flex-col gap-4 px-3 py-4">
      {NAV_GROUPS.map((group) => (
        <div key={group.label}>
          <p className="px-2 pb-1 text-[11px] font-semibold uppercase tracking-wider text-zinc-500">{group.label}</p>
          <ul className="space-y-0.5">
            {group.paths.map((p) => {
              const view = viewFor(p)!;
              const active = current === p;
              return (
                <li key={p}>
                  <a
                    href={`#${p}`}
                    onClick={onNavigate}
                    aria-current={active ? "page" : undefined}
                    className={cn(
                      "flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm transition-colors",
                      active
                        ? "bg-blue-500/10 font-medium text-blue-600 dark:text-blue-400"
                        : "text-zinc-700 hover:bg-zinc-100 dark:text-zinc-300 dark:hover:bg-zinc-800/60",
                    )}
                  >
                    <Icon name={view.icon} className="h-4 w-4 shrink-0" />
                    <span className="truncate">{view.title}</span>
                  </a>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );
}

export function AppShell() {
  const hash = useHashRoute();
  const routePath = (hash.startsWith("#") ? hash.slice(1) : hash).split("?")[0] || "/dashboard";
  const queryClient = useQueryClient();
  const { resolvedTheme, setTheme } = useTheme();
  const [mobileOpen, setMobileOpen] = useState(false);
  const setupGate = useSetupCompleted();

  const meQuery = useQuery<Me>({
    queryKey: ["auth", "me"],
    queryFn: () => fetchApi<Me>("/api/v1/auth/me"),
    retry: false,
  });

  // config:updated → invalidate everything (section-aware refinement lands with M03+)
  useRealtime(["metrics", "alerts", "config"], {
    onConfigUpdated: () => void queryClient.invalidateQueries(),
  });

  const logout = useCallback(async () => {
    await fetch("/api/v1/auth/logout", { method: "POST", credentials: "same-origin" });
    queryClient.clear();
    window.location.hash = "#/dashboard";
    window.location.reload();
  }, [queryClient]);

  if (meQuery.isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="flex flex-col items-center gap-3">
          <Icons.ShieldCheck className="h-10 w-10 animate-pulse text-blue-600" />
          <p className="text-sm text-zinc-500">Loading console…</p>
        </div>
      </div>
    );
  }

  if (meQuery.isError || !meQuery.data) {
    return <LoginView onLoggedIn={() => void meQuery.refetch()} />;
  }

  // first-time-setup gate (view 29): renders instead of the shell while setup
  // is incomplete — same gate pattern as AuthGate (M10 §4)
  if (!setupGate.isLoading && !setupGate.completed) {
    return <SetupWizard onFinished={() => void queryClient.invalidateQueries()} />;
  }

  const me = meQuery.data;
  const view: ViewDef = viewFor(routePath) ?? VIEWS[0];

  const sidebar = (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 border-b border-zinc-200 px-4 py-4 dark:border-zinc-800">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600 text-white">
          <Icons.ShieldCheck className="h-5 w-5" />
        </div>
        <div>
          <p className="text-sm font-semibold leading-tight">Cryptsk</p>
          <p className="text-[11px] leading-tight text-zinc-500">UTM / NGFW Console</p>
        </div>
      </div>
      <ScrollArea className="min-h-0 flex-1">
        <SidebarNav current={routePath} onNavigate={() => setMobileOpen(false)} />
      </ScrollArea>
      <div className="border-t border-zinc-200 px-4 py-3 text-[11px] text-zinc-500 dark:border-zinc-800">
        Tenant #{me.tenantId} · simulated appliance
      </div>
    </div>
  );

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <div className="flex flex-1">
        {/* desktop sidebar */}
        <aside className="sticky top-0 hidden h-screen w-60 shrink-0 border-r border-zinc-200 dark:border-zinc-800 lg:block">
          {sidebar}
        </aside>

        <div className="flex min-w-0 flex-1 flex-col">
          {/* topbar */}
          <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-zinc-200 bg-background/95 px-4 backdrop-blur dark:border-zinc-800">
            {/* mobile menu */}
            <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
              <SheetTrigger asChild>
                <Button variant="ghost" size="icon" className="lg:hidden" aria-label="Open navigation">
                  <Icons.Menu className="h-5 w-5" />
                </Button>
              </SheetTrigger>
              <SheetContent side="left" className="w-64 p-0">
                <SheetTitle className="sr-only">Navigation</SheetTitle>
                {sidebar}
              </SheetContent>
            </Sheet>

            <h1 className="truncate text-sm font-semibold">{view.title}</h1>
            <Badge variant="outline" className="hidden border-blue-500/40 bg-blue-500/10 text-blue-600 sm:inline-flex dark:text-blue-400">
              Simulated
            </Badge>

            <div className="ml-auto flex items-center gap-1.5">
              <Button
                variant="ghost"
                size="icon"
                aria-label="Toggle dark mode"
                onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
              >
                {resolvedTheme === "dark" ? <Icons.Sun className="h-4.5 w-4.5" /> : <Icons.Moon className="h-4.5 w-4.5" />}
              </Button>
              <NotificationCenter />
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" className="gap-2 px-2">
                    <span className="flex h-7 w-7 items-center justify-center rounded-full bg-violet-500/15 text-xs font-semibold text-violet-600 dark:text-violet-400">
                      {me.username.slice(0, 2).toUpperCase()}
                    </span>
                    <span className="hidden text-sm md:inline">{me.username}</span>
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-52">
                  <DropdownMenuLabel>
                    <p className="text-sm font-medium">{me.username}</p>
                    <p className="text-xs text-zinc-500">{me.role ?? "api key"}</p>
                  </DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={logout} className="text-rose-600 focus:text-rose-600 dark:text-rose-400">
                    <Icons.LogOut className="mr-2 h-4 w-4" /> Sign out
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </header>

          {/* view area */}
          <main className="flex-1 p-4 md:p-6">
            {view.path === "/dashboard" ? (
              <DashboardView />
            ) : view.path === "/firewall/rules" ? (
              <RulesView />
            ) : view.path === "/firewall/nat" ? (
              <NatView />
            ) : view.path === "/firewall/objects" ? (
              <ObjectsView />
            ) : view.path === "/firewall/zones" ? (
              <ZonesView />
            ) : view.path === "/network/interfaces" ? (
              <InterfacesView />
            ) : view.path === "/network/routing" ? (
              <RoutingView />
            ) : view.path === "/network/wan" ? (
              <WanView />
            ) : view.path === "/ips/policies" ? (
              <PoliciesView />
            ) : view.path === "/ips/events" ? (
              <EventsView />
            ) : view.path === "/vpn/configs" ? (
              <ConfigsView />
            ) : view.path === "/vpn/sessions" ? (
              <SessionsView />
            ) : view.path === "/dns-dhcp/dns" ? (
              <DnsView />
            ) : view.path === "/dns-dhcp/dhcp" ? (
              <DhcpView />
            ) : view.path === "/identity/users" ? (
              <UsersView />
            ) : view.path === "/identity/sessions" ? (
              <IdentitySessionsView />
            ) : view.path === "/identity/portal" ? (
              <PortalView />
            ) : view.path === "/qos/policies" ? (
              <QosView />
            ) : view.path === "/logs/firewall" ? (
              <FirewallLogsView />
            ) : view.path === "/logs/ips" ? (
              <IpsLogsView />
            ) : view.path === "/logs/audit" ? (
              <AuditView />
            ) : view.path === "/logs/live" ? (
              <LiveTailView />
            ) : view.path === "/logs/reports" ? (
              <ReportsView />
            ) : view.path === "/system/api-keys" ? (
              <ApiKeysView />
            ) : view.path === "/logs/search" ? (
              <SearchView />
            ) : view.path === "/logs/compliance" ? (
              <ComplianceView />
            ) : view.path === "/threat-intel/feeds" ? (
              <FeedsView />
            ) : view.path === "/threat-intel/iocs" ? (
              <IocsView />
            ) : view.path === "/threat-intel/auto-block" ? (
              <AutoBlockView />
            ) : view.path === "/pki/authorities" ? (
              <AuthoritiesView />
            ) : view.path === "/pki/certificates" ? (
              <CertificatesView />
            ) : view.path === "/ha" ? (
              <HaView />
            ) : view.path === "/system/settings" ? (
              <SystemView />
            ) : view.path === "/system/backups" ? (
              <BackupsView />
            ) : (
              <PlaceholderView view={view} />
            )}
          </main>

          {/* sticky footer — pushes down naturally on overflow (min-h-screen + mt-auto) */}
          <footer className="mt-auto border-t border-zinc-200 px-4 py-3 text-xs text-zinc-500 dark:border-zinc-800">
            <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-1 sm:flex-row">
              <p>Cryptsk UTM/NGFW — Phase 1 console (simulation mode)</p>
              <p>docs first · code second · v0.1.0-m0</p>
            </div>
          </footer>
        </div>
      </div>
    </div>
  );
}
