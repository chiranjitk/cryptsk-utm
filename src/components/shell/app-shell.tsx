"use client";

/**
 * AppShell — the single-route SPA shell (ADR-006).
 * Auth gate → window-chrome topbar + hash-routed view area + floating frosted
 * glass dock (T17 "Cerulean Dock" skin — navigation lives at the bottom, not
 * in a sidebar). Deep links, back/forward and refresh all work via hash. No
 * other Next.js routes exist.
 */

import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
import { CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList, CommandSeparator } from "@/components/ui/command";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useTheme } from "next-themes";
import { motion, useReducedMotion } from "framer-motion";
import * as Icons from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Sheet, SheetContent, SheetTitle } from "@/components/ui/sheet";
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
// Phase 2 views (M15–M17 batch 2)
import { SslInspectionView } from "@/components/views/ssl-inspection/ssl-inspection-view";
import { UrlFilterView } from "@/components/views/url-filter/url-filter-view";
import { WafView } from "@/components/views/waf/waf-view";
// Phase 2 views (M18–M20 batch 3)
import { AppControlView } from "@/components/views/app-control/app-control-view";
import { DynamicRoutingView } from "@/components/views/dynamic-routing/dynamic-routing-view";
import { SdwanView } from "@/components/views/sdwan/sdwan-view";
// Phase 2 views (M21–M23 batch 4)
import { Ipv6View } from "@/components/views/ipv6/ipv6-view";
import { EmailSecurityView } from "@/components/views/email-security/email-security-view";
import { IdentityAdvancedView } from "@/components/views/identity-advanced/identity-advanced-view";
import { HaView } from "@/components/views/ha/ha-view";
import { SystemView } from "@/components/views/system/system-view";
import { BackupsView } from "@/components/views/system/backups-view";
import { NotificationCenter } from "@/components/views/system/notification-center";
import { SetupWizard, useSetupCompleted } from "@/components/views/setup/setup-wizard";
import { BrandLogo } from "@/components/shell/brand-logo";
import { fetchApi, useRealtime, useRealtimeStatus, type RealtimeStatus } from "@/lib/realtime";
import { cn } from "@/lib/utils";

type Me = {
  kind: "user" | "key";
  username: string;
  role?: string;
  tenantId: number;
  permissions: { read: string[]; write: string[]; admin: string[] };
  dataPlane?: "host" | "simulated";
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

// topbar realtime dot — emerald = connected (true health semantics), amber =
// connecting/reconnecting, rose = offline (initial connect failed). UI_DESIGN_SYSTEM §5.12.
const RT_DOT: Record<RealtimeStatus, { dot: string; label: string; pulse?: boolean }> = {
  connected: { dot: "bg-emerald-500", label: "Realtime stream connected" },
  connecting: { dot: "bg-amber-500", label: "Realtime stream connecting" },
  reconnecting: { dot: "bg-amber-500", label: "Realtime stream reconnecting", pulse: true },
  offline: { dot: "bg-rose-500", label: "Realtime stream offline" },
};

// platform hint for the ⌘/Ctrl+K badge — external-store pattern keeps hydration safe
// (server snapshot "Ctrl+K", client re-renders to ⌘K after hydration; no state, no effect)
const emptySubscribe = () => () => {};
const getIsApple = () => /Mac|iPhone|iPad|iPod/.test(navigator.platform);
const getIsAppleServer = () => false;

function SidebarNav({ current, onNavigate }: { current: string; onNavigate?: () => void }) {
  return (
    <nav aria-label="Console navigation" className="flex flex-col gap-4 px-3 py-4">
      {NAV_GROUPS.map((group) => (
        <div key={group.label}>
          <p className="px-2 pb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">{group.label}</p>
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
                      "flex min-h-11 items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500/60",
                      active
                        ? "bg-sky-500/10 font-medium text-sky-700 dark:bg-sky-400/10 dark:text-sky-300"
                        : "text-slate-600 hover:bg-sky-500/8 hover:text-sky-700 dark:text-slate-300 dark:hover:bg-sky-400/10 dark:hover:text-sky-300",
                    )}
                  >
                    <Icon name={view.icon} className={cn("h-4 w-4 shrink-0", active ? "text-sky-600 dark:text-sky-400" : "text-slate-400 dark:text-slate-500")} />
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

/**
 * DockItem — one frosted-dock tile (T17 dk-di). 44px touch target, cerulean
 * gradient + dot indicator when active, native title tooltip + aria-label.
 */
function DockItem({ href, label, icon, active }: { href: string; label: string; icon: string; active: boolean }) {
  return (
    <a
      href={href}
      aria-label={label}
      aria-current={active ? "page" : undefined}
      title={label}
      className={cn(
        "relative grid h-11 w-11 shrink-0 place-items-center rounded-2xl transition-all duration-150",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500/60",
        active
          ? "bg-gradient-to-br from-sky-500 to-sky-700 text-white shadow-[0_10px_20px_rgba(2,132,199,0.42)]"
          : "bg-sky-500/8 text-slate-500 hover:bg-sky-500/15 hover:text-sky-700 dark:bg-sky-400/10 dark:text-slate-300 dark:hover:bg-sky-400/20 dark:hover:text-sky-300",
      )}
    >
      <Icon name={icon} className="h-[18px] w-[18px]" />
      {active && (
        <span aria-hidden="true" className="absolute -bottom-1.5 left-1/2 h-1 w-1 -translate-x-1/2 rounded-full bg-sky-600 dark:bg-sky-400" />
      )}
    </a>
  );
}

/**
 * Dock — floating frosted-glass bottom navigation (T17 "Cerulean Dock").
 * Grid button opens the full grouped nav sheet; then Dashboard + one tile per
 * nav group (tile targets the group's first view; every view stays reachable
 * via the sheet and the ⌘K palette). Horizontally scrollable on narrow
 * screens; fixed above the footer, which clears it via mb-20.
 */
function Dock({ current, allNavOpen, onAllNavOpenChange, onNavigate }: { current: string; allNavOpen: boolean; onAllNavOpenChange: (open: boolean) => void; onNavigate: () => void }) {
  return (
    <>
      <div className="pointer-events-none fixed inset-x-0 bottom-3 z-40 flex justify-center px-3">
        <nav
          aria-label="Console dock"
          className="dock-glass no-scrollbar pointer-events-auto flex max-w-full items-center gap-1 overflow-x-auto rounded-3xl px-2.5 py-2.5 shadow-[0_22px_44px_rgba(16,50,80,0.18)] dark:shadow-[0_22px_44px_rgba(0,0,0,0.5)]"
        >
          <button
            type="button"
            aria-label="All views"
            title="All views"
            onClick={() => onAllNavOpenChange(true)}
            className="grid h-11 w-11 shrink-0 place-items-center rounded-2xl bg-sky-500/8 text-slate-500 transition-all duration-150 hover:bg-sky-500/15 hover:text-sky-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500/60 dark:bg-sky-400/10 dark:text-slate-300 dark:hover:bg-sky-400/20 dark:hover:text-sky-300"
          >
            <Icons.LayoutGrid className="h-[18px] w-[18px]" />
          </button>
          <span aria-hidden="true" className="mx-1 h-6 w-px shrink-0 bg-border" />
          <DockItem href="#/dashboard" label="Dashboard" icon={VIEWS[0]!.icon} active={current === "/dashboard"} />
          {NAV_GROUPS.slice(1).map((group) => {
            const first = viewFor(group.paths[0]!)!;
            const active = group.paths.includes(current);
            return <DockItem key={group.label} href={`#${group.paths[0]}`} label={group.label} icon={first.icon} active={active} />;
          })}
        </nav>
      </div>

      {/* full grouped navigation — every view reachable from the dock's grid button */}
      <Sheet open={allNavOpen} onOpenChange={onAllNavOpenChange}>
        <SheetContent side="left" className="w-72 p-0">
          <SheetTitle className="sr-only">All views</SheetTitle>
          <div className="flex h-full flex-col">
            <div className="flex items-center gap-2.5 border-b px-4 py-4">
              <BrandLogo className="h-8 w-8 shrink-0" />
              <div>
                <p className="text-sm font-semibold leading-tight">Cryptsk</p>
                <p className="text-[11px] leading-tight text-slate-500">UTM / NGFW Console</p>
              </div>
            </div>
            <ScrollArea className="min-h-0 flex-1">
              <SidebarNav current={current} onNavigate={onNavigate} />
            </ScrollArea>
          </div>
        </SheetContent>
      </Sheet>
    </>
  );
}

export function AppShell() {
  const hash = useHashRoute();
  const routePath = (hash.startsWith("#") ? hash.slice(1) : hash).split("?")[0] || "/dashboard";
  const queryClient = useQueryClient();
  const { resolvedTheme, setTheme } = useTheme();
  const [allNavOpen, setAllNavOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const shortcutHint = useSyncExternalStore(emptySubscribe, getIsApple, getIsAppleServer) ? "\u2318K" : "Ctrl+K";
  const setupGate = useSetupCompleted();
  const reduceMotion = useReducedMotion();
  const rtStatus = useRealtimeStatus();

  const navigateTo = useCallback(
    (path: string) => {
      setPaletteOpen(false);
      setAllNavOpen(false);
      if (window.location.hash !== `#${path}`) window.location.hash = path;
    },
    [setPaletteOpen, setAllNavOpen],
  );

  const skipToContent = useCallback(() => {
    document.getElementById("main-content")?.focus();
  }, []);

  const meQuery = useQuery<Me>({
    queryKey: ["auth", "me"],
    queryFn: () => fetchApi<Me>("/api/v1/auth/me"),
    retry: false,
  });

  // ⌘/Ctrl+K opens the command palette — bound only while the shell (not login/setup) is mounted.
  const shellMounted = !!meQuery.data && !meQuery.isError && !meQuery.isLoading && (setupGate.isLoading || setupGate.completed);
  useEffect(() => {
    if (!shellMounted) return;
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((open) => !open);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [shellMounted]);

  // config:updated → invalidate everything (section-aware refinement lands with M03+)
  useRealtime(["metrics", "alerts", "config"], {
    onConfigUpdated: () => void queryClient.invalidateQueries(),
  });

  const logout = useCallback(async () => {
    await fetch("/api/v1/auth/logout", { method: "POST", credentials: "same-origin" });
    queryClient.clear();
    // drop any hash deep-link without a history entry — after the reload the
    // auth gate renders the login view, and a fresh login lands on #/dashboard
    window.history.replaceState(null, "", window.location.pathname);
    window.location.reload();
  }, [queryClient]);

  if (meQuery.isLoading) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-6 bg-background">
        {/* branded boot spinner — ping halo + orbit ring around the mark */}
        <div className="relative flex h-20 w-20 items-center justify-center">
          <span className="absolute inset-0 animate-ping rounded-full bg-sky-600/15" aria-hidden="true" />
          <span
            className="absolute inset-0 animate-spin rounded-full border-2 border-sky-600/20 border-t-sky-600 [animation-duration:1.1s]"
            aria-hidden="true"
          />
          <BrandLogo className="relative h-9 w-9 drop-shadow-md" />
        </div>
        <div className="flex flex-col items-center gap-1">
          <p className="text-sm font-medium text-slate-700 dark:text-slate-300">Loading console…</p>
          <p className="animate-pulse text-xs text-slate-400 dark:text-slate-500">
            establishing secure session · real telemetry
          </p>
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
  const sectionLabel = NAV_GROUPS.find((g) => g.paths.includes(routePath))?.label;

  return (
    <div className="cerulean-stage flex min-h-screen flex-col bg-background">
      {/* skip-to-content — button (not hash anchor) so routing hash stays intact */}
      <button
        type="button"
        onClick={skipToContent}
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-background focus:px-3 focus:py-2 focus:text-sm focus:font-medium focus:shadow-md focus:outline-none focus:ring-2 focus:ring-ring"
      >
        Skip to main content
      </button>
      <div className="flex flex-1 flex-col">
        {/* window-chrome topbar — traffic dots, brand, breadcrumb, status, actions (T17 dk-bar) */}
        <header className="glass-bar sticky top-0 z-30 flex h-14 items-center gap-3 border-b px-4">
          <span aria-hidden="true" className="hidden shrink-0 items-center gap-1.5 sm:flex">
            <i className="h-2.5 w-2.5 rounded-full bg-slate-200 dark:bg-slate-600" />
            <i className="h-2.5 w-2.5 rounded-full bg-slate-200 dark:bg-slate-600" />
            <i className="h-2.5 w-2.5 rounded-full bg-slate-200 dark:bg-slate-600" />
          </span>
          <BrandLogo className="h-7 w-7 shrink-0" />
          <h1 className="flex min-w-0 items-baseline gap-2 text-sm font-semibold">
            <span className="hidden shrink-0 font-display text-[13px] font-bold tracking-tight sm:inline">Cryptsk</span>
            <span aria-hidden="true" className="hidden shrink-0 text-slate-300 dark:text-slate-600 sm:inline">/</span>
            {sectionLabel ? (
              <>
                <span className="hidden shrink-0 text-[11px] font-medium uppercase tracking-wider text-slate-400 dark:text-slate-500 md:inline">
                  {sectionLabel}
                </span>
                <span aria-hidden="true" className="hidden shrink-0 text-slate-300 dark:text-slate-600 md:inline">/</span>
              </>
            ) : null}
            <span className="truncate">{view.title}</span>
          </h1>
          <Badge
            variant="outline"
            className={cn(
              "hidden shrink-0 sm:inline-flex",
              me.dataPlane === "simulated"
                ? "border-slate-500/30 bg-slate-500/10 text-slate-600 dark:text-slate-300"
                : "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:border-sky-400/40 dark:bg-sky-400/10 dark:text-sky-300",
            )}
          >
            {me.dataPlane === "simulated" ? "Simulated" : "Live"}
          </Badge>
          {/* realtime transport indicator — reuses the singleton socket via useRealtimeStatus (no new connection) */}
          <span role="status" aria-label={RT_DOT[rtStatus].label} title={RT_DOT[rtStatus].label} className="flex shrink-0 items-center px-0.5">
            <span
              aria-hidden="true"
              className={cn("h-2 w-2 rounded-full", RT_DOT[rtStatus].dot, RT_DOT[rtStatus].pulse && "animate-pulse")}
            />
          </span>

          <div className="ml-auto flex items-center gap-1.5">
            {/* command-palette trigger — keyboard parity via the global ⌘/Ctrl+K listener */}
            <Button
              variant="outline"
              className="h-11 gap-2 rounded-xl bg-white/70 px-3 text-xs text-slate-500 hover:bg-white lg:h-9 dark:bg-white/5 dark:hover:bg-white/10"
              aria-label="Open command palette"
              onClick={() => setPaletteOpen(true)}
            >
              <Icons.Search className="h-4 w-4" />
              <span className="hidden sm:inline">Search…</span>
              <kbd className="hidden h-5 items-center rounded border border-slate-200 bg-slate-100 px-1.5 font-mono text-[10px] font-medium text-slate-500 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400 md:inline-flex">
                {shortcutHint}
              </kbd>
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="size-11 lg:size-9"
              aria-label="Toggle dark mode"
              onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
            >
              {resolvedTheme === "dark" ? <Icons.Sun className="h-4.5 w-4.5" /> : <Icons.Moon className="h-4.5 w-4.5" />}
            </Button>
            <NotificationCenter />
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" className="h-11 gap-2 px-2 lg:h-9">
                  <span className="flex h-7 w-7 items-center justify-center rounded-full bg-sky-500/15 text-xs font-semibold text-sky-700 dark:bg-sky-400/15 dark:text-sky-300">
                    {me.username.slice(0, 2).toUpperCase()}
                  </span>
                  <span className="hidden text-sm md:inline">{me.username}</span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-52">
                <DropdownMenuLabel>
                  <p className="text-sm font-medium">{me.username}</p>
                  <p className="text-xs text-slate-500">{me.role ?? "api key"}</p>
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
        <main id="main-content" tabIndex={-1} className="flex-1 p-4 pb-6 focus:outline-none md:p-6">
          {/* subtle 180ms fade/rise on hash change; opacity-only for reduced motion (UI_DESIGN_SYSTEM §7) */}
          <motion.div
            key={routePath}
            initial={reduceMotion ? { opacity: 0 } : { opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.18, ease: "easeOut" }}
          >
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
            ) : view.path === "/web/ssl-inspection" ? (
              <SslInspectionView />
            ) : view.path === "/web/url-filter" ? (
              <UrlFilterView />
            ) : view.path === "/web/waf" ? (
              <WafView />
            ) : view.path === "/web/app-control" ? (
              <AppControlView />
            ) : view.path === "/routing/dynamic" ? (
              <DynamicRoutingView />
            ) : view.path === "/routing/sdwan" ? (
              <SdwanView />
            ) : view.path === "/network/ipv6" ? (
              <Ipv6View />
            ) : view.path === "/email/security" ? (
              <EmailSecurityView />
            ) : view.path === "/identity/federation" || view.path === "/identity/nac" ? (
              <IdentityAdvancedView />
            ) : view.path === "/ha" ? (
              <HaView />
            ) : view.path === "/system/settings" ? (
              <SystemView />
            ) : view.path === "/system/backups" ? (
              <BackupsView />
            ) : (
              <PlaceholderView view={view} />
            )}
          </motion.div>
        </main>

        {/* global command palette — ⌘/Ctrl+K, Esc closes, Enter navigates, arrows move (cmdk) */}
        <CommandDialog open={paletteOpen} onOpenChange={setPaletteOpen}>
          <CommandInput placeholder="Search views and commands…" />
          <CommandList>
            <CommandEmpty>No matching view or command.</CommandEmpty>
            {NAV_GROUPS.map((group) => (
              <CommandGroup key={group.label} heading={group.label}>
                {group.paths.map((p) => {
                  const paletteView = viewFor(p)!;
                  return (
                    <CommandItem key={p} value={`${paletteView.title} ${p}`} onSelect={() => navigateTo(p)}>
                      <Icon name={paletteView.icon} className="h-4 w-4 shrink-0" />
                      <span className="truncate">{paletteView.title}</span>
                    </CommandItem>
                  );
                })}
              </CommandGroup>
            ))}
            <CommandSeparator />
            <CommandGroup heading="Preferences">
              <CommandItem
                value="Toggle dark mode theme"
                onSelect={() => {
                  setTheme(resolvedTheme === "dark" ? "light" : "dark");
                  setPaletteOpen(false);
                }}
              >
                {resolvedTheme === "dark" ? <Icons.Sun className="h-4 w-4 shrink-0" /> : <Icons.Moon className="h-4 w-4 shrink-0" />}
                <span>Toggle dark mode</span>
              </CommandItem>
            </CommandGroup>
          </CommandList>
        </CommandDialog>

        {/* sticky footer — pushes down naturally on overflow; mb-20 clears the fixed dock */}
        <footer className="mb-20 mt-auto border-t px-4 py-3 text-xs text-slate-500 dark:text-slate-400">
          <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-1 sm:flex-row">
            <p>Cryptsk UTM/NGFW — {me.dataPlane === "simulated" ? "demo console (simulation mode)" : "real data plane (ADR-021)"}</p>
            <p>docs first · code second · v0.24.0-m24</p>
          </div>
        </footer>
      </div>

      {/* floating glass dock — the sidebar's replacement (T17 Cerulean Dock) */}
      <Dock current={routePath} allNavOpen={allNavOpen} onAllNavOpenChange={setAllNavOpen} onNavigate={() => setAllNavOpen(false)} />
    </div>
  );
}
