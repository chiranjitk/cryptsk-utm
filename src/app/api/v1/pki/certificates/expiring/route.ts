/**
 * GET /api/v1/pki/certificates/expiring?days=30 (M14) — expiry-monitoring
 * feed for the dashboard chip: non-revoked certificates whose notAfter falls
 * inside the window (including already-expired rows), soonest first.
 * NOTE: static route wins over /certificates/[id] in the App Router.
 */

import { route } from "@/lib/api/handler";
import { db } from "@/lib/db";
import { expiringQuerySchema } from "@/lib/validators/pki";
import { sanitizeCert } from "@/app/api/v1/pki/shared";

export const dynamic = "force-dynamic";

export const GET = route({ area: "pki", querySchema: expiringQuerySchema }, async ({ auth, query }) => {
  const horizon = new Date(Date.now() + query.days * 86_400_000);
  const [rows, cas] = await Promise.all([
    db.certificate.findMany({
      where: { tenantId: auth.tenantId, status: { not: "revoked" }, notAfter: { lte: horizon } },
      orderBy: { notAfter: "asc" },
    }),
    db.certificateAuthority.findMany({ where: { tenantId: auth.tenantId }, select: { id: true, name: true } }),
  ]);
  const caNames = new Map(cas.map((c) => [c.id, c.name]));
  return { data: rows.map((r) => sanitizeCert(r, caNames.get(r.caId) ?? null)) };
});
