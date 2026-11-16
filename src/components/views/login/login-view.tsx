"use client";

/**
 * Login view — AUTH_AND_RBAC §2 (username + password → JWT httpOnly cookie).
 * Rendered in place of the shell when unauthenticated (single-route rule).
 */

import { useState } from "react";
import { ChevronsUpDown, KeyRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { BrandLogo } from "@/components/shell/brand-logo";

/** Seeded demo accounts (prisma/seed.ts §Users) — Fill buttons populate the form, never auto-submit. */
const DEMO_ACCOUNTS = [
  { username: "admin", password: "admin123", role: "super_admin" },
  { username: "socuser", password: "socuser123", role: "soc_analyst" },
  { username: "netops", password: "netops123", role: "network_admin" },
  { username: "viewer", password: "viewer123", role: "auditor" },
] as const;

export function LoginView({ onLoggedIn }: { onLoggedIn: () => void }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/v1/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ username, password }),
      });
      const json = (await res.json()) as { error?: { message: string; code: string } };
      if (!res.ok) {
        setError(json.error?.message ?? "Login failed");
        return;
      }
      onLoggedIn();
    } catch {
      setError("Network error — is the console server running?");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="cerulean-stage flex min-h-screen flex-col items-center justify-center bg-background p-4">
      <div className="mb-6 flex flex-col items-center gap-2">
        <BrandLogo className="h-12 w-12 drop-shadow-lg" />
        <h1 className="font-display text-xl font-bold tracking-tight">Cryptsk Console</h1>
        <p className="text-sm text-slate-500 dark:text-slate-400">UTM / NGFW management — real-host telemetry</p>
      </div>

      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle className="text-base">Sign in</CardTitle>
          <CardDescription>Use your console account — or expand the demo credentials below</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                minLength={1}
                aria-describedby={error ? "login-error" : undefined}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={1}
                aria-describedby={error ? "login-error" : undefined}
              />
            </div>
            {error ? (
              <p id="login-error" role="alert" className="rounded-md bg-rose-500/10 px-3 py-2 text-sm text-rose-600 dark:text-rose-400">
                {error}
              </p>
            ) : null}
            <Button type="submit" className="w-full" disabled={busy}>
              {busy ? "Signing in…" : "Sign in"}
            </Button>
          </form>

          {/* demo-credentials helper — fills the fields only; submit stays a deliberate action */}
          <Collapsible className="pt-1">
            <CollapsibleTrigger className="group flex min-h-11 w-full items-center justify-between rounded-md px-1 py-2 text-xs text-zinc-500 transition-colors hover:text-zinc-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/60 dark:hover:text-zinc-300 sm:min-h-0">
              <span className="flex items-center gap-1.5">
                <KeyRound className="h-3.5 w-3.5" aria-hidden="true" />
                Demo credentials
              </span>
              <ChevronsUpDown className="h-3.5 w-3.5 transition-transform group-data-[state=open]:rotate-180" aria-hidden="true" />
            </CollapsibleTrigger>
            <CollapsibleContent className="space-y-1.5 pt-1">
              {DEMO_ACCOUNTS.map((a) => (
                <div
                  key={a.username}
                  className="flex items-center justify-between gap-2 rounded-md border border-zinc-200 px-2.5 py-1.5 dark:border-zinc-800"
                >
                  <div className="min-w-0">
                    <p className="truncate font-mono text-xs">
                      {a.username} / {a.password}
                    </p>
                    <p className="text-[10px] text-zinc-400">{a.role}</p>
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="h-8 shrink-0 text-xs"
                    aria-label={`Fill credentials for ${a.username} (${a.role})`}
                    onClick={() => {
                      setUsername(a.username);
                      setPassword(a.password);
                      setError(null);
                    }}
                  >
                    Fill
                  </Button>
                </div>
              ))}
              <p className="px-1 text-[10px] text-zinc-400">Fill only populates the fields — review and press Sign in.</p>
            </CollapsibleContent>
          </Collapsible>
        </CardContent>
      </Card>

      <p className="mt-6 max-w-sm text-center text-xs text-zinc-500">
        8 roles enforced server-side (super_admin → api_service). Failed logins are rate-limited to 5/min and audited.
      </p>
    </div>
  );
}
