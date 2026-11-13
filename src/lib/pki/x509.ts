/**
 * PKI crypto core (M14 §2.12) — REAL X.509 generation via node-forge 1.4.3.
 * Server-only: every CA/certificate in the sandbox is genuine RSA key material
 * with real self- or parent-signed certificates (SHA-256), not simulated PEM.
 *
 * CRL support: node-forge 1.4.3 has NO CRL creation API (`forge.pki.crl` does
 * not exist), so buildCrl() constructs a standards-shaped RFC 5280
 * CertificateList by hand with forge.asn1 and signs the TBSCertList with the
 * CA key via forge.pki.rsa.sign — that is real DER + real RSA signature, not
 * a text mock.
 *
 * Key-type note: forge 1.4.3 cannot GENERATE ECDSA keypairs (its only
 * non-RSA primitive is Ed25519/EdDSA), so keyType is restricted to
 * rsa2048 | rsa4096 here; ec256/ec384 are rejected with a descriptive error.
 */

import * as forge from "node-forge";
import { createHash } from "node:crypto";

export type PkiKeyType = "rsa2048" | "rsa4096";
export type PkiStatus = "active" | "revoked" | "expired";

export interface PkiMaterial {
  certPem: string;
  keyPem: string;
  serial: string;
  notBefore: Date;
  notAfter: Date;
}

export interface GenerateCaOptions {
  commonName: string;
  org?: string | null;
  keyType: string;
  validityDays: number;
  isRoot: boolean;
  /** Required when isRoot=false — subordinate is signed by this parent. */
  parent?: { certPem: string; keyPem: string };
  /** Embedded as a real cRLDistributionPoints URI extension when set. */
  crlUrl?: string | null;
  /** Stored column only (forge has no AIA creation) — kept for OCSP display. */
  ocspUrl?: string | null;
}

export interface IssueCertificateOptions {
  ca: { certPem: string; keyPem: string };
  commonName: string;
  /** Entries: "DNS:x", "IP:y", or a bare hostname (treated as DNS). */
  sans: string[];
  keyType: string;
  validityDays: number;
  type: "server" | "client" | "device" | "user";
  crlUrl?: string | null;
}

// ── helpers ─────────────────────────────────────────────────────────────────

function assertRsaKeyType(keyType: string): asserts keyType is PkiKeyType {
  if (keyType !== "rsa2048" && keyType !== "rsa4096") {
    throw new Error(
      `Unsupported keyType '${keyType}': node-forge 1.4.3 cannot generate EC keypairs — use rsa2048 or rsa4096`,
    );
  }
}

async function generateRsaKeyPair(bits: 2048 | 4096): Promise<forge.pki.rsa.KeyPair> {
  // Native crypto path (Node/Bun) inside forge → non-blocking; pure-JS fallback
  // uses forge's stepwise generator. Both deliver genuine RSA keys.
  return new Promise((resolve, reject) => {
    forge.pki.rsa.generateKeyPair({ bits, workers: 2 }, (err, keypair) => {
      if (err) reject(err instanceof Error ? err : new Error(String(err)));
      else resolve(keypair);
    });
  });
}

/** 128-bit random serial, hex uppercase (RFC 5280: ≥64 bits of entropy). */
function newSerial(): string {
  return forge.util.bytesToHex(forge.random.getBytesSync(16)).toUpperCase();
}

/**
 * forge.pem output uses CRLF line endings; OpenSSL's CRL loader (and several
 * consumers) only accept LF — normalize every PEM we emit to "\n".
 */
function pemNormalize(pem: string): string {
  return pem.replace(/\r\n/g, "\n");
}

function subjectAttrs(commonName: string, org?: string | null): forge.pki.CertificateField[] {
  const attrs: forge.pki.CertificateField[] = [{ name: "commonName", value: commonName }];
  if (org) attrs.push({ name: "organizationName", value: org });
  return attrs;
}

/** GeneralName from a SAN entry — bare hostnames default to DNS. */
function altNameFromSan(san: string): { type: number; value?: string; ip?: string } {
  const entry = san.trim();
  if (/^IP:/i.test(entry)) return { type: 7, ip: entry.slice(3).trim() };
  const dns = /^DNS:/i.test(entry) ? entry.slice(4).trim() : entry;
  return { type: 2, value: dns };
}

interface CertValidity {
  notBefore: Date;
  notAfter: Date;
}

function validityWindow(validityDays: number, maxNotAfter?: Date | null): CertValidity {
  const notBefore = new Date(Date.now() - 60 * 60 * 1000); // 1h clock-skew backstop
  let notAfter = new Date(Date.now() + validityDays * 86_400_000);
  if (maxNotAfter && notAfter > maxNotAfter) notAfter = maxNotAfter; // cannot outlive the issuing CA
  return { notBefore, notAfter };
}

// ── CA generation ───────────────────────────────────────────────────────────

export async function generateCa(opts: GenerateCaOptions): Promise<PkiMaterial> {
  assertRsaKeyType(opts.keyType);
  const bits = opts.keyType === "rsa4096" ? 4096 : 2048;

  let issuerCert: forge.pki.Certificate | null = null;
  let issuerKey: forge.pki.PrivateKey | null = null;
  let maxNotAfter: Date | null = null;
  if (!opts.isRoot) {
    if (!opts.parent) throw new Error("Subordinate CAs require a parent { certPem, keyPem }");
    issuerCert = forge.pki.certificateFromPem(opts.parent.certPem);
    issuerKey = forge.pki.privateKeyFromPem(opts.parent.keyPem);
    maxNotAfter = issuerCert.validity.notAfter;
  }

  const keypair = await generateRsaKeyPair(bits);
  const serial = newSerial();
  const { notBefore, notAfter } = validityWindow(opts.validityDays, maxNotAfter);

  const cert = forge.pki.createCertificate();
  cert.publicKey = keypair.publicKey;
  cert.serialNumber = serial;
  cert.validity.notBefore = notBefore;
  cert.validity.notAfter = notAfter;

  const attrs = subjectAttrs(opts.commonName, opts.org);
  cert.setSubject(attrs);
  // Self-signed root: issuer == subject; subordinate: issuer = parent subject.
  cert.setIssuer(issuerCert ? issuerCert.subject.attributes : attrs);

  const extensions: object[] = [
    { name: "basicConstraints", cA: true, pathLenConstraint: opts.isRoot ? 1 : 0, critical: true },
    { name: "keyUsage", keyCertSign: true, cRLSign: true, critical: true },
    { name: "subjectKeyIdentifier" },
  ];
  // AKI must point at the ISSUER's SKI — forge's `keyIdentifier: true` uses the
  // cert being signed, so pass the parent's SKI bytes explicitly when chained.
  if (issuerCert) {
    extensions.push({ name: "authorityKeyIdentifier", keyIdentifier: issuerCert.generateSubjectKeyIdentifier().getBytes() });
  } else {
    extensions.push({ name: "authorityKeyIdentifier", keyIdentifier: true });
  }
  if (opts.crlUrl) {
    extensions.push({ name: "cRLDistributionPoints", altNames: [{ type: 6, value: opts.crlUrl }] });
  }
  (cert as unknown as { setExtensions: (e: object[]) => void }).setExtensions(extensions);

  cert.sign(issuerKey ?? keypair.privateKey, forge.md.sha256.create());

  return {
    certPem: pemNormalize(forge.pki.certificateToPem(cert)),
    keyPem: pemNormalize(forge.pki.privateKeyToPem(keypair.privateKey)),
    serial,
    notBefore,
    notAfter,
  };
}

// ── end-entity certificate issuance ─────────────────────────────────────────

export async function issueCertificate(opts: IssueCertificateOptions): Promise<PkiMaterial> {
  assertRsaKeyType(opts.keyType);
  const bits = opts.keyType === "rsa4096" ? 4096 : 2048;
  const caCert = forge.pki.certificateFromPem(opts.ca.certPem);
  const caKey = forge.pki.privateKeyFromPem(opts.ca.keyPem);

  const keypair = await generateRsaKeyPair(bits);
  const serial = newSerial();
  const { notBefore, notAfter } = validityWindow(opts.validityDays, caCert.validity.notAfter);

  const cert = forge.pki.createCertificate();
  cert.publicKey = keypair.publicKey;
  cert.serialNumber = serial;
  cert.validity.notBefore = notBefore;
  cert.validity.notAfter = notAfter;
  cert.setSubject(subjectAttrs(opts.commonName));
  cert.setIssuer(caCert.subject.attributes);

  const extensions: object[] = [
    { name: "basicConstraints", cA: false, critical: true },
    { name: "keyUsage", digitalSignature: true, keyEncipherment: true, critical: true },
    {
      name: "extKeyUsage",
      serverAuth: true,
      // client/device/user certs also authenticate the holder (mTLS, VPN, RADIUS).
      clientAuth: opts.type !== "server",
    },
    { name: "subjectKeyIdentifier" },
    { name: "authorityKeyIdentifier", keyIdentifier: caCert.generateSubjectKeyIdentifier().getBytes() },
  ];
  if (opts.sans.length > 0) {
    extensions.push({ name: "subjectAltName", altNames: opts.sans.map(altNameFromSan) });
  }
  if (opts.crlUrl) {
    extensions.push({ name: "cRLDistributionPoints", altNames: [{ type: 6, value: opts.crlUrl }] });
  }
  (cert as unknown as { setExtensions: (e: object[]) => void }).setExtensions(extensions);

  cert.sign(caKey, forge.md.sha256.create());

  return {
    certPem: pemNormalize(forge.pki.certificateToPem(cert)),
    keyPem: pemNormalize(forge.pki.privateKeyToPem(keypair.privateKey)),
    serial,
    notBefore,
    notAfter,
  };
}

// ── fingerprints / expiry helpers ───────────────────────────────────────────

/**
 * SHA-256 over the DER (base64-decoded PEM body) — first 16 hex chars.
 * Works for certificate PEM and private-key PEM alike (used as keyFingerprint).
 */
export function fingerprint(pem: string): string {
  const match = /-----BEGIN [^-]+-----([A-Za-z0-9+/=\s]+)-----END/.exec(pem);
  const body = (match ? match[1] : pem).replace(/\s+/g, "");
  return createHash("sha256").update(Buffer.from(body, "base64")).digest("hex").slice(0, 16);
}

export function daysUntil(notAfter: Date | null): number | null {
  if (!notAfter) return null;
  return Math.ceil((notAfter.getTime() - Date.now()) / 86_400_000);
}

export function statusOf(notAfter: Date | null, revoked: boolean): PkiStatus {
  if (revoked) return "revoked";
  if (notAfter && notAfter.getTime() < Date.now()) return "expired";
  return "active";
}

// ── CRL (RFC 5280 CertificateList built by hand, signed for real) ───────────

/** RFC 5280 §5.3.1 CRLReason code for a revocation reason name. */
export function crlReasonCode(reason: string): number {
  const map: Record<string, number> = {
    unspecified: 0,
    keyCompromise: 1,
    caCompromise: 2,
    affiliationChanged: 3,
    superseded: 4,
    cessationOfOperation: 5,
    certificateHold: 6,
    privilegeWithdrawn: 9,
    aACompromise: 10,
  };
  return map[reason] ?? 0;
}

/** CRL entry info — serial + revocation date + mapped reason code. */
export function revokeCertInfo(serial: string, date: Date, reason?: string) {
  return { serial, date, reasonCode: reason ? crlReasonCode(reason) : undefined };
}

function timeAsn1(d: Date): forge.asn1.Asn1 {
  // RFC 5280: UTCTime for dates before 2050, GeneralizedTime afterwards.
  const type = d.getUTCFullYear() < 2050 ? forge.asn1.Type.UTCTIME : forge.asn1.Type.GENERALIZEDTIME;
  return forge.asn1.create(forge.asn1.Class.UNIVERSAL, type, false, forge.asn1.dateToUtcTime(d));
}

function serialToIntegerBytes(serialHex: string): string {
  const clean = serialHex.replace(/[^0-9a-fA-F]/g, "");
  const padded = clean.length % 2 ? `0${clean}` : clean;
  let bytes = forge.util.hexToBytes(padded);
  if (bytes.length === 0 || bytes.charCodeAt(0) >= 0x80) bytes = `\x00${bytes}`; // keep INTEGER positive
  return bytes;
}

function oidAsn1(oid: string): forge.asn1.Asn1 {
  return forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer(oid).getBytes());
}

function extnValueAsn1(inner: forge.asn1.Asn1): forge.asn1.Asn1 {
  return forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.OCTETSTRING,
    false,
    forge.asn1.toDer(inner).getBytes(),
  );
}

export interface CrlRevokedEntry {
  serial: string;
  date: Date;
  reasonCode?: number;
}

/**
 * Build a signed X.509 CRL (PEM). TBSCertList is assembled per RFC 5280 with
 * forge.asn1 and signed with the CA private key (SHA-256 + RSA) — the output
 * is a genuine, verifiable CertificateList, not a placeholder.
 */
export function buildCrl(
  ca: { certPem: string; keyPem: string },
  revoked: CrlRevokedEntry[],
  nextUpdateDays = 30,
  crlNumber = 1,
): string {
  const caCert = forge.pki.certificateFromPem(ca.certPem);
  const caKey = forge.pki.privateKeyFromPem(ca.keyPem);

  // AlgorithmIdentifier: sha256WithRSAEncryption (NULL params).
  const sigAlg = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    oidAsn1(forge.pki.oids.sha256WithRSAEncryption),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, ""),
  ]);

  const now = new Date();
  const nextUpdate = new Date(now.getTime() + nextUpdateDays * 86_400_000);

  const tbsValue: forge.asn1.Asn1[] = [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false, "\x01"), // version v2
    sigAlg,
    forge.pki.distinguishedNameToAsn1(caCert.subject),
    timeAsn1(now),
    timeAsn1(nextUpdate),
  ];

  if (revoked.length > 0) {
    const entries = revoked.map((r) => {
      const fields: forge.asn1.Asn1[] = [
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false, serialToIntegerBytes(r.serial)),
        timeAsn1(r.date),
      ];
      if (r.reasonCode !== undefined) {
        fields.push(
          forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [
            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
              oidAsn1("2.5.29.21"), // id-ce-cRLReasons
              extnValueAsn1(
                forge.asn1.create(
                  forge.asn1.Class.UNIVERSAL,
                  forge.asn1.Type.ENUMERATED,
                  false,
                  String.fromCharCode(r.reasonCode),
                ),
              ),
            ]),
          ]),
        );
      }
      return forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, fields);
    });
    tbsValue.push(forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, entries));
  }

  // crlExtensions [0] — cRLNumber (id-ce-cRLNumber 2.5.29.20), proper v2 CRLs.
  tbsValue.push(
    forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        oidAsn1("2.5.29.20"),
        extnValueAsn1(
          forge.asn1.create(
            forge.asn1.Class.UNIVERSAL,
            forge.asn1.Type.INTEGER,
            false,
            forge.asn1.integerToDer(crlNumber).getBytes(),
          ),
        ),
      ]),
    ]),
  );

  const tbs = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, tbsValue);

  const md = forge.md.sha256.create();
  md.update(forge.asn1.toDer(tbs).getBytes(), "raw");
  // forge.pki.rsa exposes no public sign(); the PKCS#1 private key object does.
  const signature = caKey.sign(md);

  const certificateList = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    tbs,
    sigAlg,
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.BITSTRING, false, `\x00${signature}`),
  ]);

  const der = forge.asn1.toDer(certificateList).getBytes();
  return pemNormalize(forge.pem.encode({ type: "X509 CRL", body: forge.util.encode64(der) }));
}
