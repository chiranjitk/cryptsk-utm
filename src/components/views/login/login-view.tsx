"use client";

/**
 * Login view — AUTH_AND_RBAC §2 (username + password → JWT httpOnly cookie).
 * Rendered in place of the shell when unauthenticated (single-route rule).
 */

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ShieldCheck } from "lucide-react";

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
    <div className="flex min-h-screen flex-col items-center justify-center bg-zinc-50 p-4 dark:bg-zinc-950">
      <div className="mb-6 flex flex-col items-center gap-2">
        <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-emerald-500 text-white shadow-lg shadow-emerald-500/20">
          <ShieldCheck className="h-7 w-7" />
        </div>
        <h1 className="text-xl font-semibold">Cryptsk Console</h1>
        <p className="text-sm text-zinc-500">UTM / NGFW management — simulated appliance</p>
      </div>

      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle className="text-base">Sign in</CardTitle>
          <CardDescription>Use your console account (seed: admin / admin123)</CardDescription>
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
              />
            </div>
            {error ? (
              <p role="alert" className="rounded-md bg-rose-500/10 px-3 py-2 text-sm text-rose-600 dark:text-rose-400">
                {error}
              </p>
            ) : null}
            <Button type="submit" className="w-full bg-emerald-600 hover:bg-emerald-700" disabled={busy}>
              {busy ? "Signing in…" : "Sign in"}
            </Button>
          </form>
        </CardContent>
      </Card>

      <p className="mt-6 max-w-sm text-center text-xs text-zinc-500">
        8 roles enforced server-side (super_admin → api_service). Failed logins are rate-limited to 5/min and audited.
      </p>
    </div>
  );
}
