/**
 * M14 seed — PKI (spec 2.12). Idempotent: upserts by (tenantId, name).
 * Generates REAL X.509 material via src/lib/pki/x509 (node-forge): root CA
 * (RSA-4096, 10y), issuing subordinate (RSA-2048, 5y) and three end-entity
 * certificates. NEVER logs key material — summaries only.
 *
 * Run via: bun prisma/seed-phase2.ts (orchestrator tolerates missing modules).
 */

import type { PrismaClient } from "@prisma/client";
// relative import: seed runs under bun, where "@/..." path aliases are not
// guaranteed — this module resolves directly (see orchestrator note).
import { generateCa, issueCertificate } from "../../src/lib/pki/x509";

const TENANT = 1;

export default async function seed(prisma: PrismaClient): Promise<string> {
  // ── root CA — "Cryptsk Root CA", RSA-4096, 10 years ────────────────────────
  let root = await prisma.certificateAuthority.findUnique({
    where: { tenantId_name: { tenantId: TENANT, name: "Cryptsk Root CA" } },
  });
  if (!root) {
    const material = await generateCa({
      commonName: "Cryptsk Root CA",
      org: "Cryptsk",
      keyType: "rsa4096",
      validityDays: 3650,
      isRoot: true,
      crlUrl: "http://pki.cryptsk.local/crl/root.crl",
    });
    root = await prisma.certificateAuthority.create({
      data: {
        tenantId: TENANT,
        name: "Cryptsk Root CA",
        type: "root",
        commonName: "Cryptsk Root CA",
        org: "Cryptsk",
        keyType: "rsa4096",
        validityDays: 3650,
        serial: material.serial,
        certPem: material.certPem,
        keyPem: material.keyPem,
        status: "active",
        crlUrl: "http://pki.cryptsk.local/crl/root.crl",
        notBefore: material.notBefore,
        notAfter: material.notAfter,
      },
    });
  }

  // ── issuing subordinate — "Cryptsk Issuing CA", RSA-2048, 5 years ─────────
  let issuing = await prisma.certificateAuthority.findUnique({
    where: { tenantId_name: { tenantId: TENANT, name: "Cryptsk Issuing CA" } },
  });
  if (!issuing) {
    const material = await generateCa({
      commonName: "Cryptsk Issuing CA",
      org: "Cryptsk",
      keyType: "rsa2048",
      validityDays: 1825,
      isRoot: false,
      parent: { certPem: root.certPem, keyPem: root.keyPem },
      crlUrl: "http://pki.cryptsk.local/crl/issuing.crl",
    });
    issuing = await prisma.certificateAuthority.create({
      data: {
        tenantId: TENANT,
        name: "Cryptsk Issuing CA",
        type: "subordinate",
        commonName: "Cryptsk Issuing CA",
        org: "Cryptsk",
        keyType: "rsa2048",
        validityDays: 1825,
        parentCaId: root.id,
        serial: material.serial,
        certPem: material.certPem,
        keyPem: material.keyPem,
        status: "active",
        crlUrl: "http://pki.cryptsk.local/crl/issuing.crl",
        notBefore: material.notBefore,
        notAfter: material.notAfter,
      },
    });
  }

  // ── end-entity certificates (all under the issuing CA, active) ────────────
  const certs = [
    {
      name: "ssl-inspect-signing",
      commonName: "ssl-inspect.cryptsk.local",
      sans: ["DNS:*.cryptsk.local"],
      type: "server" as const,
      issuedFor: "ssl_inspect",
    },
    {
      name: "waf-vhost-demo",
      commonName: "app.corp.example",
      sans: ["DNS:app.corp.example"],
      type: "server" as const,
      issuedFor: "waf",
    },
    {
      name: "radius-client-01",
      commonName: "radius-client-01",
      sans: [],
      type: "client" as const,
      issuedFor: "general",
    },
  ];

  let issued = 0;
  for (const spec of certs) {
    const existing = await prisma.certificate.findUnique({
      where: { tenantId_name: { tenantId: TENANT, name: spec.name } },
    });
    if (existing) continue;
    const material = await issueCertificate({
      ca: { certPem: issuing.certPem, keyPem: issuing.keyPem },
      commonName: spec.commonName,
      sans: spec.sans,
      keyType: "rsa2048",
      validityDays: 730,
      type: spec.type,
      crlUrl: issuing.crlUrl,
    });
    await prisma.certificate.create({
      data: {
        tenantId: TENANT,
        caId: issuing.id,
        name: spec.name,
        commonName: spec.commonName,
        sans: JSON.stringify(spec.sans),
        type: spec.type,
        issuedFor: spec.issuedFor,
        keyType: "rsa2048",
        validityDays: 730,
        serial: material.serial,
        certPem: material.certPem,
        keyPem: material.keyPem,
        status: "active",
        autoRenew: true,
        notBefore: material.notBefore,
        notAfter: material.notAfter,
      },
    });
    issued += 1;
  }

  return `M14: 2 CAs, 3 certificates (real X.509 via node-forge)${issued < 3 ? ` — ${3 - issued} already seeded` : ""}`;
}
