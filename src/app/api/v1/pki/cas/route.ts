/**
 * Certificate Authorities (M14 §2.12) — GET list + POST create.
 * POST runs REAL X.509 generation via lib/pki/x509 (node-forge). Rows are
 * returned sanitized: no keyPem ever — keyFingerprint + hasKey instead.
 * Mutations audit `pki_ca.*` and snapshot section `pki`.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { generateCa } from "@/lib/pki/x509";
import { caCreateSchema } from "@/lib/validators/pki";
import { sanitizeCa } from "@/app/api/v1/pki/shared";

export const dynamic = "force-dynamic";

export const GET = route({ area: "pki" }, async ({ auth }) => {
  const [cas, certs, parents] = await Promise.all([
    db.certificateAuthority.findMany({
      where: { tenantId: auth.tenantId },
      orderBy: [{ type: "asc" }, { id: "asc" }],
    }),
    db.certificate.groupBy({ by: ["caId"], where: { tenantId: auth.tenantId }, _count: { _all: true } }),
    db.certificateAuthority.findMany({
      where: { tenantId: auth.tenantId },
      select: { id: true, name: true },
    }),
  ]);
  const counts = new Map(certs.map((c) => [c.caId, c._count._all]));
  const names = new Map(parents.map((p) => [p.id, p.name]));
  return {
    data: cas.map((ca) => sanitizeCa(ca, counts.get(ca.id) ?? 0, ca.parentCaId ? (names.get(ca.parentCaId) ?? null) : null)),
  };
});

export const POST = route(
  { area: "pki", bodySchema: caCreateSchema, section: "pki" },
  async ({ auth, body }) => {
    // Multiple roots are allowed (spec: "allow multiple"); subordinates must
    // point at an ACTIVE CA of the same tenant.
    let parent: { certPem: string; keyPem: string; notAfter: Date | null } | undefined;
    if (body.type === "subordinate") {
      const parentCa = await db.certificateAuthority.findFirst({
        where: { id: body.parentCaId!, tenantId: auth.tenantId },
      });
      if (!parentCa) throw ApiError.notFound("Parent CA not found");
      if (parentCa.status !== "active") throw ApiError.conflict("Parent CA is not active");
      if (!parentCa.keyPem) throw ApiError.conflict("Parent CA has no signing key material");
      parent = { certPem: parentCa.certPem, keyPem: parentCa.keyPem, notAfter: parentCa.notAfter };
    }

    let material;
    try {
      material = await generateCa({
        commonName: body.commonName,
        org: body.org ?? undefined,
        keyType: body.keyType,
        validityDays: body.validityDays,
        isRoot: body.type === "root",
        parent,
        crlUrl: body.crlUrl ?? undefined,
        ocspUrl: body.ocspUrl ?? undefined,
      });
    } catch (err) {
      throw ApiError.validation(
        err instanceof Error ? err.message : "CA generation failed",
      );
    }

    const created = await db.certificateAuthority.create({
      data: {
        tenantId: auth.tenantId,
        name: body.name,
        type: body.type,
        commonName: body.commonName,
        org: body.org ?? null,
        keyType: body.keyType,
        validityDays: body.validityDays,
        parentCaId: body.type === "subordinate" ? body.parentCaId! : null,
        serial: material.serial,
        certPem: material.certPem,
        keyPem: material.keyPem,
        status: "active",
        crlUrl: body.crlUrl ?? null,
        ocspUrl: body.ocspUrl ?? null,
        autoRenew: body.autoRenew,
        notBefore: material.notBefore,
        notAfter: material.notAfter,
      },
    });

    return {
      // sanitized — audit snapshot must never contain key material
      data: sanitizeCa(created),
      audit: { action: "pki_ca.create", objectType: "pki_ca", objectId: created.id, objectName: created.name, after: sanitizeCa(created) },
    };
  },
);
