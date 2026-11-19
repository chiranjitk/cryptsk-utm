/**
 * /api/v1/vpn/keygen — REAL key material for the tunnel editor (replaces the
 * client-side placeholder generator of the simulation era):
 *   • wgPrivateKey / wgPublicKey — fresh X25519 pair (44-char base64, wg fmt)
 *   • psk — CSPRNG 256-bit IPSec pre-shared key
 * Secrets travel over the authenticated console session only and are never
 * persisted here — the editor decides what to keep.
 */

import { route } from "@/lib/api/handler";
import { can } from "@/lib/auth/rbac";
import { ApiError } from "@/lib/api/errors";
import { generatePsk, generateWgKeypair } from "@/lib/vpn/crypto";

export const dynamic = "force-dynamic";

export const GET = route({ area: "vpn_config" }, async ({ auth }) => {
  // audit fix L13 — minting key material is an editor capability: only roles
  // that hold vpn_config:write (super_admin/tenant_admin/network_admin) may
  // call it; read-only principals must not be able to draw fresh secrets.
  if (!can(auth, "vpn_config", "write")) {
    throw ApiError.forbidden("Key generation requires VPN configuration write access");
  }
  const kp = generateWgKeypair();
  return { data: { wgPrivateKey: kp.privateKey, wgPublicKey: kp.publicKey, psk: generatePsk() } };
});
