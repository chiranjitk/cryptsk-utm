/**
 * SD-WAN OS integration — unit tests for the pure renderer (lib/sdwan/os.ts),
 * the exec whitelist + confirm step-guard, and the validation-only apply
 * pipeline (lib/sdwan/os-service.ts) with mocked exec and tmp state dirs.
 * The route layer is asserted at source level (wiring guard, the established
 * pattern in app-control-os.test.ts).
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from "vitest";
import { createHash } from "crypto";
import fs from "fs";
import path from "path";
import { readFileSync, existsSync } from "fs";
import {
  GENERATED_ON_APPLY,
  IFNAMSIZ,
  PRIVATE_KEY_PLACEHOLDER,
  SDWAN_IFACE_PREFIX,
  SDWAN_WG_DIR,
  buildSdwanRollbackScript,
  deriveOverlaySubnet,
  deriveSiteAddress,
  deriveSiteNet,
  generateSdwanWgConfigs,
  octetOf,
  parseWgShow,
  sdwanApplyMode,
  sdwanApplyTs,
  sdwanIface,
  sdwanIfacesFromWgShow,
  sdwanListenPort,
  sdwanSlug,
  sdwanStepGuarded,
  wgPubKeyLooksReal,
  type SdwanOverlayShape,
} from "@/lib/sdwan/os";

// ── isolated tmp state/config dirs + mocked exec ────────────────────────────

const h = vi.hoisted(() => ({
  execCalls: [] as string[],
  stripOk: true,
  wgDir: "",
  sdwanDir: "",
}));

vi.mock("@/lib/sdwan/os", async (importOriginal) => {
  const fsp = await import("node:fs");
  const osp = await import("node:os");
  const psp = await import("node:path");
  h.wgDir = fsp.mkdtempSync(psp.join(osp.tmpdir(), "sdwan-test-wg-"));
  h.sdwanDir = fsp.mkdtempSync(psp.join(osp.tmpdir(), "sdwan-test-state-"));
  process.env.CONSOLE_WG_DIR = h.wgDir;
  process.env.CONSOLE_SDWAN_DIR = h.sdwanDir;
  const actual = await importOriginal<typeof import("@/lib/sdwan/os")>();
  return { ...actual, SDWAN_WG_DIR: h.wgDir };
});

vi.mock("@/lib/host/tools", () => ({
  hasTool: async (bin: string) => bin === "wg" || bin === "wg-quick",
  runTool: async (cmd: string) => {
    h.execCalls.push(cmd);
    if (cmd.startsWith("wg-quick strip")) {
      return h.stripOk
        ? { ok: true, stdout: "", stderr: "" }
        : { ok: false, stdout: "", stderr: "wg-quick: config parse error", error: "exit 1" };
    }
    return { ok: true, stdout: "", stderr: "" };
  },
  readNftRuleset: async () => ({ available: false, ruleset: "", permissionDenied: false }),
}));

// ── fixtures ────────────────────────────────────────────────────────────────

const PUB_HUB = `${"A".repeat(43)}=`;
const PUB_B = `${"B".repeat(43)}=`;

const overlayShape = (over: Partial<SdwanOverlayShape> = {}): SdwanOverlayShape => ({
  id: 1,
  name: "HQ Mesh",
  topology: "hub_spoke",
  encryption: "wireguard",
  enabled: true,
  sites: [
    { id: 10, name: "dc-hub", role: "hub", publicIp: "203.0.113.1", wgPubKey: PUB_HUB, enabled: true },
    { id: 11, name: "branch-a", role: "spoke", publicIp: "198.51.100.10", wgPubKey: null, enabled: true },
    { id: 12, name: "branch-b", role: "spoke", publicIp: "198.51.100.11", wgPubKey: PUB_B, enabled: true },
    { id: 13, name: "branch-off", role: "spoke", publicIp: "198.51.100.12", wgPubKey: null, enabled: false },
  ],
  ...over,
});

const fullShape = (): SdwanOverlayShape[] => [
  overlayShape(),
  overlayShape({
    id: 2,
    name: "legacy-ipsec",
    topology: "full_mesh",
    encryption: "ipsec",
    sites: [{ id: 20, name: "legacy", role: "hub", publicIp: "203.0.113.9", wgPubKey: null, enabled: true }],
  }),
  overlayShape({ id: 3, name: "Disabled Overlay", enabled: false }),
];

const gen = (overlays: SdwanOverlayShape[], generatedAt?: Date) =>
  generateSdwanWgConfigs({ overlays, keepaliveSec: 25, generatedAt: generatedAt ?? new Date("2026-01-01T00:00:00Z") });

const plan = gen(fullShape());
const file1 = plan.files.find((f) => f.overlayId === 1)!;

// ── renderer: structure + determinism + hashes ──────────────────────────────

describe("generateSdwanWgConfigs — structure", () => {
  it("renders one wg-quick file per enabled WireGuard overlay with the mission naming", () => {
    expect(plan.files).toHaveLength(1);
    expect(file1.iface).toBe("utm-sdwan-hq-mesh-1");
    expect(file1.fileName).toBe(`${SDWAN_WG_DIR}/utm-sdwan-hq-mesh-1.conf`);
    expect(sdwanSlug("HQ Mesh", 1)).toBe("hq-mesh-1");
    expect(sdwanIface("HQ Mesh", 1)).toBe("utm-sdwan-hq-mesh-1");
    expect(plan.counts).toEqual({ overlays: 2, rendered: 1, skipped: 1, peers: 2 });
    expect(plan.skippedOverlays).toEqual([
      { id: 2, name: "legacy-ipsec", reason: expect.stringContaining("ipsec") },
    ]);
  });

  it("renders [Interface] with derived ListenPort, redacted PrivateKey and local Address", () => {
    expect(file1.listenPort).toBe(51820);
    expect(file1.conf).toContain("[Interface]");
    expect(file1.conf).toContain(`ListenPort = ${sdwanListenPort(1)}`);
    expect(file1.conf).toContain(`PrivateKey = ${PRIVATE_KEY_PLACEHOLDER}`);
    // local anchor = the hub site (id 10) → derived tunnel address
    expect(file1.address).toBe(deriveSiteAddress(1, 10));
    expect(file1.conf).toContain(`Address = ${deriveSiteAddress(1, 10)}`);
    expect(file1.overlaySubnet).toBe(deriveOverlaySubnet(1));
  });

  it("renders one [Peer] per enabled remote site with AllowedIPs, Endpoint and keepalive", () => {
    const peers = file1.peers;
    expect(peers.map((p) => p.siteName)).toEqual(["branch-a", "branch-b"]); // disabled site + local hub excluded
    expect(file1.conf).toContain("AllowedIPs = " + deriveSiteNet(1, 11));
    expect(file1.conf).toContain("AllowedIPs = " + deriveSiteNet(1, 12));
    expect(file1.conf).toContain("Endpoint = 198.51.100.10:51820");
    expect(file1.conf).toContain("Endpoint = 198.51.100.11:51820");
    expect(file1.conf).toContain("PersistentKeepalive = 25");
    expect(file1.conf.match(/\[Peer\]/g)).toHaveLength(2);
  });

  it("keeps the derived addressing deterministic (octetOf, site /24, overlay /16)", () => {
    expect(octetOf(1)).toBe(1);
    expect(octetOf(254)).toBe(254);
    expect(octetOf(255)).toBe(1);
    expect(deriveSiteNet(1, 11)).toBe("10.1.11.0/24");
    expect(deriveOverlaySubnet(2)).toBe("10.2.0.0/16");
    expect(sdwanListenPort(1)).toBe(51820);
    expect(sdwanListenPort(3)).toBe(51822);
  });
});

describe("generateSdwanWgConfigs — determinism + hashes", () => {
  it("is byte-identical for the same input + generatedAt", () => {
    const a = gen(fullShape());
    const b = gen(fullShape());
    expect(a.files[0].conf).toBe(b.files[0].conf);
    expect(a.files.map((f) => f.confHash)).toEqual(b.files.map((f) => f.confHash));
    expect(a.combinedHash).toBe(b.combinedHash);
  });

  it("per-file confHash is the sha256 of the config; combinedHash is order-independent", () => {
    expect(file1.confHash).toBe(createHash("sha256").update(file1.conf, "utf8").digest("hex"));
    const expectedCombined = createHash("sha256")
      .update(
        [...plan.files]
          .sort((x, y) => (x.iface < y.iface ? -1 : 1))
          .map((f) => `${f.iface}:${f.confHash}`)
          .join("\n"),
        "utf8",
      )
      .digest("hex");
    expect(plan.combinedHash).toBe(expectedCombined);

    // shuffled input order → identical output
    const shuffled = gen([...fullShape()].reverse());
    expect(shuffled.combinedHash).toBe(plan.combinedHash);
    const shuffledSites = gen([
      overlayShape({
        sites: [...overlayShape().sites].reverse(),
      }),
      fullShape()[1],
      fullShape()[2],
    ]);
    expect(shuffledSites.files[0].conf).toBe(file1.conf);
    expect(shuffledSites.combinedHash).toBe(
      gen([overlayShape(), fullShape()[1], fullShape()[2]]).combinedHash,
    );
  });

  it("changing one overlay changes its file hash and the combined hash", () => {
    const modified = gen([
      overlayShape({ id: 1, sites: overlayShape().sites.map((s) => (s.id === 12 ? { ...s, publicIp: "198.51.100.99" } : s)) }),
      fullShape()[1],
      fullShape()[2],
    ]);
    const m1 = modified.files.find((f) => f.overlayId === 1)!;
    expect(m1.confHash).not.toBe(file1.confHash);
    expect(modified.combinedHash).not.toBe(plan.combinedHash);
    expect(m1.conf).toContain("Endpoint = 198.51.100.99:51820");
  });
});

// ── redaction of key material ───────────────────────────────────────────────

describe("plan redaction — keys never leak into plans", () => {
  it("PrivateKey is exactly the placeholder in every rendered file", () => {
    for (const f of plan.files) {
      const m = /^PrivateKey = (.*)$/m.exec(f.conf);
      expect(m?.[1]).toBe(PRIVATE_KEY_PLACEHOLDER);
    }
    expect(plan.files.every((f) => f.conf.includes(PRIVATE_KEY_PLACEHOLDER))).toBe(true);
  });

  it("records the site public key verbatim (public material) and [GENERATED-ON-APPLY] for missing keys", () => {
    expect(file1.conf).toContain(`PublicKey = ${PUB_B}`);
    expect(file1.conf).toContain(`PublicKey = ${GENERATED_ON_APPLY}`);
    const w = file1.warnings.find((x) => x.code === "generated-on-apply");
    expect(w?.siteId).toBe(11);
    expect(w?.message).toContain("branch-a");
    expect(w?.message).toContain(GENERATED_ON_APPLY);
  });

  it("wgPubKeyLooksReal accepts only 44-char base64 key strings", () => {
    expect(wgPubKeyLooksReal(PUB_HUB)).toBe(true);
    expect(wgPubKeyLooksReal(null)).toBe(false);
    expect(wgPubKeyLooksReal("short")).toBe(false);
    expect(wgPubKeyLooksReal(`${"A".repeat(42)}==`)).toBe(false);
  });
});

// ── plan honesty warnings ───────────────────────────────────────────────────

describe("plan warnings — mandated honesty", () => {
  it("always carries the probe-simulated and traffic-affecting warnings", () => {
    const codes = plan.warnings.map((w) => w.code);
    expect(codes).toContain("probe-simulated");
    expect(codes).toContain("traffic-affecting");
    expect(plan.warnings.find((w) => w.code === "probe-simulated")!.message).toContain("probes are simulated");
    expect(plan.warnings.find((w) => w.code === "traffic-affecting")!.message).toContain("bringUp confirmation");
  });

  it("skips ipsec overlays loudly and warns on derived port collisions + IFNAMSIZ", () => {
    const codes = plan.warnings.map((w) => w.code);
    expect(codes).toContain("ipsec-not-rendered");
    // per-file warnings: derived port collision + IFNAMSIZ overflow
    expect(file1.warnings.map((w) => w.code)).toContain("listen-port-collision-risk");
    // utm-sdwan-hq-mesh-1 = 19 chars > IFNAMSIZ
    expect(file1.iface.length).toBeGreaterThan(IFNAMSIZ);
    expect(file1.warnings.map((w) => w.code)).toContain("iface-name-too-long");
    // a short name produces NO IFNAMSIZ warning
    const short = gen([overlayShape({ id: 1, name: "o" })]);
    expect(short.files[0].iface).toBe("utm-sdwan-o-1");
    expect(short.files[0].warnings.some((w) => w.code === "iface-name-too-long")).toBe(false);
  });

  it("warns when an overlay has no hub site and anchors to the first enabled site", () => {
    const noHub = gen([overlayShape({ sites: overlayShape().sites.map((s) => ({ ...s, role: "spoke" as const })) })]);
    expect(noHub.files[0].localSite?.name).toBe("dc-hub"); // lowest id enabled site
    expect(noHub.files[0].warnings.some((w) => w.code === "no-hub")).toBe(true);
  });

  it("omits PersistentKeepalive for invalid settings and emits keepalive-invalid", () => {
    const bad = generateSdwanWgConfigs({ overlays: fullShape(), keepaliveSec: 9999 });
    expect(bad.files[0].conf).not.toContain("PersistentKeepalive");
    expect(bad.warnings.some((w) => w.code === "keepalive-invalid")).toBe(true);
    const zero = generateSdwanWgConfigs({ overlays: fullShape(), keepaliveSec: 0 });
    expect(zero.files[0].conf).not.toContain("PersistentKeepalive");
    expect(zero.warnings.some((w) => w.code === "keepalive-invalid")).toBe(false);
  });
});

// ── wg show parser (pure) ───────────────────────────────────────────────────

describe("parseWgShow — live interface state", () => {
  const dump = [
    "interface: utm-sdwan-hq-mesh-1",
    "  public key: AbCdEf1234=",
    "  private key: (hidden)",
    "  listening port: 51820",
    "",
    "peer: XyZwAbCdEf1234=",
    "  endpoint: 198.51.100.10:51820",
    "  allowed ips: 10.1.11.0/24",
    "  latest handshake: 12 seconds ago",
    "",
    "peer: QrsTABCD1234=",
    "  allowed ips: 10.1.12.0/24",
    "",
    "interface: utm-vpn-tun",
    "  public key: VpnKey1234=",
    "  listening port: 51821",
    "peer: Zz1234=",
  ].join("\n");

  it("parses interfaces with listen port and peer counts", () => {
    const ifaces = parseWgShow(dump);
    expect(ifaces).toHaveLength(2);
    expect(ifaces[0]).toEqual({ iface: "utm-sdwan-hq-mesh-1", listenPort: 51820, peers: 2, publicKey: "AbCdEf1234=" });
    expect(ifaces[1]).toEqual({ iface: "utm-vpn-tun", listenPort: 51821, peers: 1, publicKey: "VpnKey1234=" });
    expect(parseWgShow("")).toEqual([]);
  });

  it("filters the managed utm-sdwan-* namespace only", () => {
    const managed = sdwanIfacesFromWgShow(parseWgShow(dump));
    expect(managed.map((i) => i.iface)).toEqual(["utm-sdwan-hq-mesh-1"]);
  });
});

// ── exec whitelist + confirm step-guard (pure) ──────────────────────────────

describe("sdwanStepGuarded — anchored whitelist", () => {
  it("accepts exactly the managed-namespace commands", () => {
    expect(sdwanStepGuarded(`wg-quick strip utm-sdwan-hq-mesh-1`)).toBe(true);
    expect(sdwanStepGuarded(`wg-quick up utm-sdwan-hq-mesh-1`)).toBe(true);
    expect(sdwanStepGuarded(`wg-quick down utm-sdwan-o-1`)).toBe(true);
    expect(sdwanStepGuarded("wg show")).toBe(true);
    expect(sdwanStepGuarded("wg show all dump")).toBe(true);
    expect(sdwanStepGuarded("wg --version")).toBe(true);
    expect(
      sdwanStepGuarded(`nohup /bin/sh "${h.sdwanDir}/rollback-2026-01-01T00-00-00-000Z.sh" >/dev/null 2>&1 &`),
    ).toBe(true);
  });

  it("rejects foreign interfaces, other tools and injection attempts", () => {
    expect(sdwanStepGuarded("wg-quick up wg0")).toBe(false);
    expect(sdwanStepGuarded("wg-quick up utm-vpn-tun")).toBe(false);
    expect(sdwanStepGuarded("wg-quick strip utm-sdwan-hq-mesh-1; rm -rf /")).toBe(false);
    expect(sdwanStepGuarded("nft -f /etc/nftables.conf")).toBe(false);
    expect(sdwanStepGuarded("rm -rf /")).toBe(false);
    expect(sdwanStepGuarded("ip rule add pref 5010")).toBe(false);
    expect(sdwanStepGuarded("wg set utm-sdwan-x peer AAA allowed-ips 0.0.0.0/0")).toBe(false);
    expect(sdwanStepGuarded("")).toBe(false);
    expect(sdwanStepGuarded("wg-quick down ens32")).toBe(false);
  });
});

describe("sdwanApplyMode — confirm step-guard", () => {
  it("returns step-guard when confirmSec is missing (nothing executes)", () => {
    expect(sdwanApplyMode({})).toBe("step-guard");
    expect(sdwanApplyMode({ ts: undefined, confirmSec: undefined })).toBe("step-guard");
  });

  it("executes only with an explicit confirmSec window", () => {
    expect(sdwanApplyMode({ confirmSec: 60 })).toBe("execute");
    expect(sdwanApplyMode({ confirmSec: 15 })).toBe("execute");
  });

  it("treats a ts as an explicit confirm of the armed window", () => {
    expect(sdwanApplyMode({ ts: "2026-01-01T00-00-00-000Z" })).toBe("confirm");
    expect(sdwanApplyMode({ ts: "x", confirmSec: 60 })).toBe("confirm");
  });

  it("produces filesystem-safe timestamps", () => {
    expect(sdwanApplyTs(new Date("2026-01-01T00:00:00.000Z"))).toBe("2026-01-01T00-00-00-000Z");
    expect(sdwanApplyTs()).not.toMatch(/[:.]/);
  });
});

describe("buildSdwanRollbackScript — snapshot restore timer", () => {
  const script = buildSdwanRollbackScript({
    ts: "2026-01-01T00-00-00-000Z",
    confirmSec: 60,
    confirmFile: `${h.sdwanDir}/confirm-ts`,
    backupDir: `${h.sdwanDir}/backup-ts`,
    stateFile: `${h.sdwanDir}/state.json`,
    scriptFile: `${h.sdwanDir}/rollback-ts.sh`,
    wgDir: h.wgDir,
    updated: ["utm-sdwan-a-1"],
    created: ["utm-sdwan-b-2"],
  });

  it("sleeps, honors the confirm flag, restores updated files and removes created files", () => {
    expect(script).toContain("#!/bin/sh");
    expect(script).toContain("sleep 60");
    expect(script).toContain(`if [ -f "${h.sdwanDir}/confirm-ts" ]; then exit 0; fi`);
    expect(script).toContain(`cp -f "${h.sdwanDir}/backup-ts/utm-sdwan-a-1.conf" "${h.wgDir}/utm-sdwan-a-1.conf"`);
    expect(script).toContain(`rm -f "${h.wgDir}/utm-sdwan-b-2.conf"`);
    expect(script).toContain(`rm -f "${h.sdwanDir}/rollback-ts.sh"`);
    expect(script).toContain(`grep -qF "\\"ts\\": \\"2026-01-01T00-00-00-000Z\\""` );
  });

  it("never tears down running tunnels and never flushes the ruleset", () => {
    expect(script).not.toContain("wg-quick");
    expect(script).not.toContain("flush ruleset");
    expect(script).toContain("NOT torn down");
  });
});

// ── route wiring (source-level guard, app-control-os.test.ts pattern) ───────

describe("POST /api/v1/sdwan/os route wiring", () => {
  const routePath = path.join(process.cwd(), "src/app/api/v1/sdwan/os/route.ts");

  it("exists with the 5-action enum, step-guard, gate and bringUp guard", () => {
    expect(existsSync(routePath)).toBe(true);
    const src = readFileSync(routePath, "utf8");
    expect(src).toContain('z.enum(["plan", "apply", "rollback", "up", "down"])');
    expect(src).toContain("sdwanApplyMode");
    expect(src).toContain("confirmed: false");
    expect(src).toContain("bringUp !== true");
    expect(src).toContain("ApiError.validation");
    expect(src).toContain('area: "sdwan"');
    expect(src).toContain("confirmSec: z.number().int().min(15).max(600).optional()");
    expect(src).toContain("readSdwanStatus");
    expect(src).toContain("sdwan.os-apply.confirm-required");
    expect(src).toContain("sdwan.os-up.exec");
  });

  it("gate is read from CONSOLE_OS_APPLY + host data plane in the service", () => {
    const svcSrc = readFileSync(path.join(process.cwd(), "src/lib/sdwan/os-service.ts"), "utf8");
    expect(svcSrc).toContain('process.env.CONSOLE_OS_APPLY === "1"');
    expect(svcSrc).toContain("getDataPlaneMode");
    expect(svcSrc).toContain('!== "host"');
  });
});

// ── os-service: gate-off preview + validation-only apply (mocked exec) ──────

let svc: typeof import("@/lib/sdwan/os-service");

beforeAll(async () => {
  svc = await import("@/lib/sdwan/os-service");
});

const cleanDirs = () => {
  for (const dir of [h.wgDir, h.sdwanDir]) {
    for (const f of fs.readdirSync(dir)) {
      fs.rmSync(path.join(dir, f), { recursive: true, force: true });
    }
  }
};

beforeEach(() => {
  cleanDirs();
  h.execCalls.length = 0;
  h.stripOk = true;
  delete process.env.CONSOLE_OS_APPLY;
  delete process.env.CONSOLE_SDWAN_WG_PRIVATE_KEY;
  delete process.env.CONSOLE_SDWAN_KEY_DIR;
});

afterEach(() => {
  delete process.env.CONSOLE_OS_APPLY;
  delete process.env.CONSOLE_SDWAN_WG_PRIVATE_KEY;
  delete process.env.CONSOLE_SDWAN_KEY_DIR;
});

afterAll(() => {
  for (const dir of [h.wgDir, h.sdwanDir]) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe("applySdwanPlan — gate-off plan preview", () => {
  it("does not exec, does not write, and reports gate off honestly", async () => {
    const outcome = await svc.applySdwanPlan(plan, { confirmSec: 60 });
    expect(outcome.gate).toBe("off");
    expect(outcome.applied).toBe(false);
    expect(outcome.results[0]?.step).toBe("gate");
    expect(outcome.results[0]?.detail).toContain("preview");
    expect(h.execCalls).toHaveLength(0);
    expect(fs.readdirSync(h.wgDir)).toHaveLength(0);
    // the plan itself is still a full preview (gate-independent renderer)
    expect(outcome.counts).toEqual(plan.counts);
    expect(outcome.warnings.map((w) => w.code)).toContain("probe-simulated");
  });
});

describe("applySdwanPlan — validation-only pipeline (mocked exec)", () => {
  it("snapshots, writes, validates with wg-quick strip and arms the timer — never up", async () => {
    process.env.CONSOLE_OS_APPLY = "1";
    // pre-existing file for the snapshot path
    fs.writeFileSync(path.join(h.wgDir, "utm-sdwan-hq-mesh-1.conf"), "# previous config\n", "utf8");

    const outcome = await svc.applySdwanPlan(plan, { confirmSec: 60 });

    expect(outcome.gate).toBe("on");
    expect(outcome.applied).toBe(true);
    expect(outcome.rolledBack).toBe(false);
    expect(outcome.confirmDeadlineAt).not.toBeNull();
    expect(outcome.files).toHaveLength(1);
    expect(outcome.files[0]?.action).toBe("updated");
    expect(outcome.files[0]?.validated).toBe(true);

    // exec set: validation + rollback timer only — NO wg-quick up, all whitelisted
    expect(h.execCalls.length).toBeGreaterThanOrEqual(2);
    expect(h.execCalls.every((c) => sdwanStepGuarded(c))).toBe(true);
    expect(h.execCalls.some((c) => c.startsWith("wg-quick strip utm-sdwan-hq-mesh-1"))).toBe(true);
    expect(h.execCalls.some((c) => c.includes("wg-quick up"))).toBe(false);
    expect(h.execCalls.some((c) => c.startsWith("nohup /bin/sh"))).toBe(true);

    // file written (keySource absent → GENERATED-ON-APPLY marker, never a fake key)
    const written = fs.readFileSync(path.join(h.wgDir, "utm-sdwan-hq-mesh-1.conf"), "utf8");
    expect(written).toContain(`PrivateKey = ${GENERATED_ON_APPLY}`);
    expect(outcome.keySource).toBe("absent");
    expect(outcome.files[0]?.confHash).toBe(
      createHash("sha256").update(written, "utf8").digest("hex"),
    );
    expect(outcome.files[0]?.confHash).not.toBe(file1.confHash);

    // snapshot of the previous file + manifest recorded
    const backupDir = path.join(h.sdwanDir, `backup-${outcome.ts}`);
    expect(fs.readFileSync(path.join(backupDir, "utm-sdwan-hq-mesh-1.conf"), "utf8")).toBe("# previous config\n");
    const manifest = JSON.parse(fs.readFileSync(path.join(backupDir, "manifest.json"), "utf8")) as { updated: string[]; created: string[] };
    expect(manifest.updated).toEqual(["utm-sdwan-hq-mesh-1"]);
    expect(manifest.created).toEqual([]);

    // state.json carries the written hashes + pending window
    const state = JSON.parse(fs.readFileSync(svc.SDWAN_STATE_FILE, "utf8")) as { ts: string; confHashes: Record<string, string> };
    expect(state.ts).toBe(outcome.ts);
    expect(state.confHashes[path.join(h.wgDir, "utm-sdwan-hq-mesh-1.conf")]).toBe(outcome.files[0]?.confHash);
    expect(await svc.readApplyState()).not.toBeNull();
  });

  it("substitutes the private key server-side from the env secret source without logging it", async () => {
    process.env.CONSOLE_OS_APPLY = "1";
    process.env.CONSOLE_SDWAN_WG_PRIVATE_KEY = "SDWANTESTKEYmaterial0123456789abcdefg=";
    const outcome = await svc.applySdwanPlan(plan, { confirmSec: 30 });
    expect(outcome.applied).toBe(true);
    expect(outcome.keySource).toBe("env");
    const written = fs.readFileSync(path.join(h.wgDir, "utm-sdwan-hq-mesh-1.conf"), "utf8");
    expect(written).toContain("PrivateKey = SDWANTESTKEYmaterial0123456789abcdefg=");
    expect(written).not.toContain(PRIVATE_KEY_PLACEHOLDER);
    // the key never leaks into the outcome / results text
    expect(JSON.stringify(outcome)).not.toContain("SDWANTESTKEYmaterial0123456789abcdefg=");
  });

  it("auto-restores the snapshot when wg-quick strip validation fails", async () => {
    process.env.CONSOLE_OS_APPLY = "1";
    fs.writeFileSync(path.join(h.wgDir, "utm-sdwan-hq-mesh-1.conf"), "# previous config\n", "utf8");
    h.stripOk = false;

    const outcome = await svc.applySdwanPlan(plan, { confirmSec: 60 });

    expect(outcome.applied).toBe(false);
    expect(outcome.rolledBack).toBe(true);
    expect(outcome.rollbackReason).toContain("wg-quick strip");
    expect(outcome.results.some((r) => r.step === "auto-restore" && r.ok)).toBe(true);
    // the pre-apply content was restored, no pending window remains
    expect(fs.readFileSync(path.join(h.wgDir, "utm-sdwan-hq-mesh-1.conf"), "utf8")).toBe("# previous config\n");
    expect(await svc.readApplyState()).toBeNull();
  });
});

describe("confirm + rollback (mocked exec)", () => {
  it("confirms only the armed window; rollback restores from the newest snapshot", async () => {
    process.env.CONSOLE_OS_APPLY = "1";
    fs.writeFileSync(path.join(h.wgDir, "utm-sdwan-hq-mesh-1.conf"), "# previous config\n", "utf8");
    const outcome = await svc.applySdwanPlan(plan, { confirmSec: 60 });
    expect(outcome.applied).toBe(true);

    // wrong ts → honest refusal
    expect(await svc.confirmSdwanApply("other-ts")).toEqual({ confirmed: false, ts: "other-ts" });
    // right ts → confirmed, window closed
    expect(await svc.confirmSdwanApply(outcome.ts)).toEqual({ confirmed: true, ts: outcome.ts });
    expect(await svc.readApplyState()).toBeNull();

    // simulate drift then rollback to the snapshot
    fs.writeFileSync(path.join(h.wgDir, "utm-sdwan-hq-mesh-1.conf"), "# drifted by hand\n", "utf8");
    const rb = await svc.rollbackSdwan();
    expect(rb.rolledBack).toBe(true);
    expect(rb.restoredCount).toBe(1);
    expect(fs.readFileSync(path.join(h.wgDir, "utm-sdwan-hq-mesh-1.conf"), "utf8")).toBe("# previous config\n");
    expect(rb.detail).toContain("not torn down");
  });
});
