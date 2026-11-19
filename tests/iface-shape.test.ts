/**
 * Interface shaping regression tests (audit F-a fix 2): the PPPoE password is
 * WRITE-ONLY — shapeIface (the single shaping path behind GET /interfaces,
 * GET /interfaces/{id} and the PUT audit before/after snapshots) must never
 * emit the stored plaintext; responses carry the "********" mask literal.
 */

import { describe, expect, test } from "vitest";
import { PPPOE_PASSWORD_MASK, shapeIface, type IfaceRow } from "@/lib/network/iface-service";

function row(config: Record<string, unknown>): IfaceRow {
  return {
    id: 1,
    tenantId: 1,
    name: "wan0",
    type: "physical",
    mode: "l3",
    role: "wan",
    parentName: null,
    vlanId: null,
    mtu: 1500,
    mssClamp: null,
    enabled: true,
    config: JSON.stringify(config),
    description: null,
    zoneId: null,
  };
}

describe("shapeIface pppoe password redaction", () => {
  test("pppoe.password is replaced with the mask literal (rest of pppoe kept)", () => {
    const shaped = shapeIface(
      row({ wanType: "pppoe", pppoe: { user: "corp@sso", password: "hunter2", service: "iptv" } }),
      null,
      undefined,
    );
    const pppoe = shaped.config.pppoe as { user: string; password: string; service?: string };
    expect(pppoe.user).toBe("corp@sso");
    expect(pppoe.password).toBe(PPPOE_PASSWORD_MASK);
    expect(pppoe.service).toBe("iptv");
    // the plaintext must not leak anywhere in the serialized payload
    expect(JSON.stringify(shaped)).not.toContain("hunter2");
  });

  test("non-pppoe config keys pass through untouched", () => {
    const shaped = shapeIface(row({ wanType: "static", ip: "10.1.1.5", cidrPrefix: 24 }), null, undefined);
    expect(shaped.config.wanType).toBe("static");
    expect(shaped.config.ip).toBe("10.1.1.5");
    expect(shaped.config).not.toHaveProperty("pppoe");
  });

  test("link state derivation is unaffected by redaction", () => {
    const shaped = shapeIface(row({ wanType: "pppoe", pppoe: { user: "u", password: "p" } }), null, undefined);
    expect(shaped.linkUp).toBe(true);
    expect(shaped.degraded).toBe(false);
  });
});
