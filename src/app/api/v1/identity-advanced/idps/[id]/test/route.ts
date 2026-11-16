/**
 * Federated IdP test (M23, spec 2.9) — simulated SSO handshake. Deterministic
 * FNV-1a latency (same seed → same result, mirrors the profiling rescan
 * simulation), with the same documentation-target heuristic the M07 tests use
 * (localhost / example.* / TEST-NET hosts are "dead" in the sandbox). The
 * result PERSISTS as the IdP row status ("ok" | "error") so the federation
 * view badge reflects the last handshake.
 */

import { route, numericId } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { fnv1a, type IdpStatus } from "@/app/api/v1/identity-advanced/_lib/server";

export const dynamic = "force-dynamic";

/** Documentation-target hosts — "dead" in the sandbox (M07 isDeadIp spirit). */
function isDeadHost(host: string): boolean {
  const h = host.trim().toLowerCase().replace(/\.$/, "");
  if (!h) return true;
  if (h === "localhost" || h === "::1" || /^127(\.\d{1,3}){3}$/.test(h)) return true;
  if (/^(example\.(com|org|net)|.*\.example|.*\.invalid)$/.test(h)) return true;
  if (/^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/.test(h)) return true;
  return false;
}

/** Hostname of an sso/metadata URL, or null when unparseable/absent. */
function hostOf(url: string | null): string | null {
  if (!url) return null;
  try {
    return new URL(url).hostname || null;
  } catch {
    return null;
  }
}

export const POST = route({ area: "federation", section: "identity" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const row = await db.federatedIdp.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!row) throw ApiError.notFound("IdP not found");

  const endpoint = row.ssoUrl ?? row.metadataUrl ?? row.entityId;
  const host = hostOf(row.ssoUrl) ?? hostOf(row.metadataUrl);
  const latencyMs = 5 + (fnv1a(`idp:${id}:${endpoint ?? row.name}`) % 41);

  let ok: boolean;
  let error: string | undefined;
  if (!row.enabled) {
    ok = false;
    error = "provider is disabled — handshake refused";
  } else if (!endpoint) {
    ok = false;
    error = "no ssoUrl/metadataUrl configured — nothing to handshake with";
  } else if (host && isDeadHost(host)) {
    ok = false;
    error = `No route to ${host} (handshake timed out after ${row.redirectUri ? "3" : "2"}s)`;
  } else {
    ok = true;
  }

  const status: IdpStatus = ok ? "ok" : "error";
  await db.federatedIdp.update({ where: { id: row.id }, data: { status } });

  return {
    data: { ok, latencyMs, ssoUrl: row.ssoUrl ?? undefined, error, status },
    audit: {
      action: "idp.test",
      objectType: "federated_idp",
      objectId: id,
      objectName: row.name,
      before: { status: row.status },
      after: { ok, latencyMs, status },
    },
  };
});
