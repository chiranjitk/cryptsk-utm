/**
 * GET /api/v1/interfaces/os-state — live host OS state (via /sys/class/net)
 * diffed against the console DB (desired state). Read-only, no side effects.
 *
 * Response rows:
 *   managed   — DB interfaces with per-field drift vs the OS
 *   unmanaged — OS interfaces the console has no row for
 *   applyEnabled — whether OS apply is gated ON (CONSOLE_OS_APPLY=1)
 */

import { route } from "@/lib/api/handler";
import { db } from "@/lib/db";
import { readInterfaces } from "@/lib/host/proc";
import { diffIfaceOs } from "@/lib/network/iface-os";
import type { IfaceRuleView } from "@/lib/network/iface-rules";

export const dynamic = "force-dynamic";

function toRuleView(row: {
  name: string;
  type: string;
  mode: string;
  role: string;
  mtu: number;
  mssClamp: number | null;
  enabled: boolean;
  parentName: string | null;
  vlanId: number | null;
  config: string;
}): IfaceRuleView {
  let cfg: Record<string, unknown> = {};
  try {
    const parsed = JSON.parse(row.config) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) cfg = parsed as Record<string, unknown>;
  } catch {
    // tolerate garbage JSON (ADR-005)
  }
  return {
    name: row.name,
    type: row.type,
    mode: row.mode,
    role: row.role,
    mtu: row.mtu,
    mssClamp: row.mssClamp,
    enabled: row.enabled,
    parentName: row.parentName ?? (typeof cfg.parent === "string" ? cfg.parent : null),
    vlanId: row.vlanId,
    config: cfg,
  };
}

export const GET = route({ area: "network" }, async ({ auth }) => {
  const [rows, osIfaces] = await Promise.all([
    db.networkInterface.findMany({ where: { tenantId: auth.tenantId }, orderBy: { id: "asc" } }),
    readInterfaces(),
  ]);

  const osByName = new Map(osIfaces.map((i) => [i.name, i]));
  const dbNames = new Set(rows.map((r) => r.name));

  const managed = rows.map((r) => {
    const view = toRuleView(r);
    const os = osByName.get(r.name) ?? null;
    const diff = diffIfaceOs(view, os ?? undefined);
    const ip = typeof view.config["ip"] === "string" ? (view.config["ip"] as string) : null;
    const prefix = typeof view.config["cidrPrefix"] === "number" ? (view.config["cidrPrefix"] as number) : null;
    return {
      name: r.name,
      type: r.type,
      role: r.role,
      enabled: r.enabled,
      mode: r.mode,
      db: {
        mtu: r.mtu,
        ip: ip && prefix != null && r.mode === "l3" ? `${ip}/${prefix}` : null,
        adminState: r.enabled ? "enabled" : "disabled",
      },
      os: os
        ? {
            operState: os.operState,
            carrier: os.carrier,
            mtu: os.mtu,
            ipv4: os.ipv4,
            mac: os.mac,
            isDefaultRoute: os.isDefaultRoute,
          }
        : null,
      inSync: diff.inSync,
      drift: diff.drift,
    };
  });

  const unmanaged = osIfaces
    .filter((i) => !dbNames.has(i.name))
    .map((i) => ({ name: i.name, operState: i.operState, mtu: i.mtu, ipv4: i.ipv4, mac: i.mac }));

  return {
    data: {
      applyEnabled: process.env.CONSOLE_OS_APPLY === "1",
      capturedAt: new Date().toISOString(),
      managed,
      unmanaged,
    },
  };
});
