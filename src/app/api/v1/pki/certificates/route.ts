/**
 * Certificates (M14 §2.12) — GET list (server-side filters: caId, type,
 * status, issuedFor, q) + POST issue. POST runs REAL X.509 issuance under the
 * selected ACTIVE CA via lib/pki/x509; SANs are normalized to DNS:/IP: form
 * and validated. List responses NEVER contain keyPem (keyFingerprint + hasKey).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { issueCertificate } from "@/lib/pki/x509";
import { certCreateSchema, certListQuerySchema } from "@/lib/validators/pki";
import { normalizeSans, sanitizeCert } from "@/app/api/v1/pki/shared";

export const dynamic = "force-dynamic";

export const GET = route({ area: "pki", querySchema: certListQuerySchema }, async ({ auth, query }) => {
  const [rows, cas] = await Promise.all([
    db.certificate.findMany({
      where: {
        tenantId: auth.tenantId,
        ...(query.caId !== undefined ? { caId: query.caId } : {}),
        ...(query.type ? { type: query.type } : {}),
        ...(query.issuedFor ? { issuedFor: query.issuedFor } : {}),
      },
      orderBy: { createdAt: "desc" },
    }),
    db.certificateAuthority.findMany({ where: { tenantId: auth.tenantId }, select: { id: true, name: true } }),
  ]);
  const caNames = new Map(cas.map((c) => [c.id, c.name]));

  let items = rows.map((row) => sanitizeCert(row, caNames.get(row.caId) ?? null));
  if (query.status) {
    // status is computed on read (revocation + expiry), so filter post-shape
    items = items.filter((c) => c.status === query.status);
  }
  if (query.q) {
    const q = query.q.toLowerCase();
    items = items.filter(
      (c) => c.name.toLowerCase().includes(q) || c.commonName.toLowerCase().includes(q) || c.serial.toLowerCase().includes(q),
    );
  }
  return { data: items };
});

export const POST = route(
  { area: "pki", bodySchema: certCreateSchema, section: "pki" },
  async ({ auth, body }) => {
    const ca = await db.certificateAuthority.findFirst({
      where: { id: body.caId, tenantId: auth.tenantId },
    });
    if (!ca) throw ApiError.notFound("CA not found");
    if (ca.status !== "active") throw ApiError.conflict("CA is not active — certificates can only be issued by active CAs");
    if (!ca.keyPem) throw ApiError.conflict("CA has no signing key material");

    let material;
    try {
      material = await issueCertificate({
        ca: { certPem: ca.certPem, keyPem: ca.keyPem },
        commonName: body.commonName,
        sans: normalizeSans(body.sans),
        keyType: body.keyType,
        validityDays: body.validityDays,
        type: body.type,
        crlUrl: ca.crlUrl,
      });
    } catch (err) {
      throw ApiError.validation(err instanceof Error ? err.message : "Certificate issuance failed");
    }

    const created = await db.certificate.create({
      data: {
        tenantId: auth.tenantId,
        caId: ca.id,
        name: body.name,
        commonName: body.commonName,
        sans: JSON.stringify(normalizeSans(body.sans)),
        type: body.type,
        issuedFor: body.issuedFor,
        keyType: body.keyType,
        validityDays: body.validityDays,
        serial: material.serial,
        certPem: material.certPem,
        keyPem: material.keyPem,
        status: "active",
        autoRenew: true,
        notBefore: material.notBefore,
        notAfter: material.notAfter,
      },
    });

    return {
      data: sanitizeCert(created, ca.name),
      audit: {
        action: "pki_certificate.issue",
        objectType: "pki_certificate",
        objectId: created.id,
        objectName: created.name,
        after: sanitizeCert(created, ca.name),
      },
    };
  },
);
