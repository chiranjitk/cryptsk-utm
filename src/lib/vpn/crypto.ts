/**
 * VPN real cryptography (enterprise gap fix — replaces the SIMULATION §9
 * placeholder key helpers). WireGuard keys are genuine Curve25519 (X25519)
 * pairs: the hub public key is DERIVED from the stored private key so GUI
 * bundles carry key material that actually works against a real `wg`
 * interface. IPSec PSKs / OpenVPN tls-crypt are CSPRNG bytes.
 *
 * X25519 raw encoding: Node exposes the 32-byte raw private key as the tail
 * of a fixed PKCS#8 DER wrapper and the raw public key as the tail of a
 * fixed SPKI DER wrapper. Both prefixes are constant (RFC 8410).
 */

import { createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes } from "crypto";

// RFC 8410 prefixes: PKCS#8 private = 302e020100300506032b656e04220420 | raw32
//                    SPKI   public  = 302a300506032b656e032100 | raw32
const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");

export interface WgKeypair {
  privateKey: string;
  publicKey: string;
}

function b64(buf: Buffer): string {
  return buf.toString("base64");
}

function rawPrivateToPkcs8(raw: Buffer): Buffer {
  return Buffer.concat([X25519_PKCS8_PREFIX, raw]);
}

/** 32-byte raw public key from a 32-byte raw private key (true scalarmult). */
export function publicKeyFromPrivateRaw(rawPrivate: Buffer): Buffer {
  const priv = createPrivateKey({ key: rawPrivateToPkcs8(rawPrivate), format: "der", type: "pkcs8" });
  const pub = createPublicKey(priv);
  const spki = pub.export({ format: "der", type: "spki" }) as Buffer;
  return spki.subarray(spki.length - 32);
}

/** Generate a fresh WireGuard keypair (base64, 44 chars — the wg format). */
export function generateWgKeypair(): WgKeypair {
  const { privateKey, publicKey } = generateKeyPairSync("x25519");
  const privRaw = (privateKey.export({ format: "der", type: "pkcs8" }) as Buffer).subarray(16);
  const pubRaw = (publicKey.export({ format: "der", type: "spki" }) as Buffer).subarray(12);
  return { privateKey: b64(privRaw), publicKey: b64(pubRaw) };
}

/** Derive the WireGuard public key for an existing base64 private key. */
export function wgPublicKeyFromPrivate(privateKeyB64: string): string | null {
  try {
    const raw = Buffer.from(privateKeyB64, "base64");
    if (raw.length !== 32) return null;
    return b64(publicKeyFromPrivateRaw(raw));
  } catch {
    return null;
  }
}

/** CSPRNG IPSec pre-shared key (256-bit, base64) — swanctl secrets safe. */
export function generatePsk(): string {
  return randomBytes(32).toString("base64");
}

/** CSPRNG OpenVPN tls-crypt/auth material helper (for future client bundles). */
export function randomHex(bytes: number): string {
  return randomBytes(bytes).toString("hex");
}
