/**
 * RADIUS OS layer tests (IMPL-8) — clients.conf renderer determinism, secret
 * rendering, slug sanitization/collisions, empty-state (header-only + stop),
 * config-injection refusals, command whitelist (NO radtest by construction),
 * plan ordering (snapshot → stage → install → validate → restart|stop →
 * verify → state LAST), drift, ss parse, and the three wired test routes.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "fs";
import path from "path";
import {
  RADIUS_AUTH_PORT,
  RADIUS_HEADER_MARKER,
  RADIUS_MANAGED_FILE,
  RADIUS_STAGE_FILE,
  buildRadiusApplyPlan,
  computeRadiusDrift,
  hardRadiusRefusal,
  isUnsafeRadiusToken,
  parseSsForAuthPort,
  profileSlug,
  radiusConfHash,
  radiusStepGuarded,
  renderClientBlock,
  renderRadiusClientsConf,
  uniqueSlugs,
  type RadiusProfileShape,
} from "@/lib/identity/os";

const profile = (over: Partial<RadiusProfileShape> = {}): RadiusProfileShape => ({
  id: 1,
  name: "corp-nas",
  serverIp: "192.0.2.5",
  authPort: 1812,
  sharedSecret: "s3cret-P@ss",
  timeoutSec: 3,
  retries: 2,
  enabled: true,
  ...over,
});

// ── slug sanitization ──────────────────────────────────────────────────────

describe("profileSlug / uniqueSlugs", () => {
  it("folds names to lowercase [a-z0-9-] slugs", () => {
    expect(profileSlug("Corp DC!")).toBe("corp-dc");
    expect(profileSlug("  Branch___Office 42 ")).toBe("branch-office-42");
    expect(profileSlug("Ünïcødé & Co")).toMatch(/^[a-z0-9-]+$/); // unicode folds into the same charset
    expect(profileSlug("---")).toBe("nas"); // never bare
    expect(profileSlug("")).toBe("nas");
  });
  it("caps the slug length and re-trims trailing dashes", () => {
    const slug = profileSlug("x".repeat(80) + "!");
    expect(slug.length).toBeLessThanOrEqual(48);
    expect(slug.endsWith("-")).toBe(false);
  });
  it("disambiguates slug collisions with the profile id", () => {
    const slugs = uniqueSlugs([profile({ id: 1, name: "Corp DC" }), profile({ id: 2, name: "Corp DC" })]);
    expect(slugs.get(1)).toBe("corp-dc");
    expect(slugs.get(2)).toBe("corp-dc-2");
  });
  it("keeps distinct names untouched and is deterministic per id order", () => {
    const slugs = uniqueSlugs([profile({ id: 2, name: "b" }), profile({ id: 1, name: "a" })]);
    expect(slugs.get(1)).toBe("a");
    expect(slugs.get(2)).toBe("b");
  });
});

// ── renderer ───────────────────────────────────────────────────────────────

describe("renderRadiusClientsConf", () => {
  const profiles = [
    profile({ id: 2, name: "branch", serverIp: "192.0.2.20", sharedSecret: "br@nch-secret" }),
    profile({ id: 1, name: "Corp DC!", serverIp: "192.0.2.5", sharedSecret: "s3cret-P@ss" }),
    profile({ id: 3, name: "off", serverIp: "192.0.2.30", enabled: false }),
  ];

  it("is deterministic (byte-identical renders, hash-stable, sha256-16)", () => {
    const a = renderRadiusClientsConf(profiles);
    const b = renderRadiusClientsConf(profiles);
    expect(a.content).toBe(b.content);
    expect(radiusConfHash(a.content)).toBe(radiusConfHash(b.content));
    expect(radiusConfHash(a.content)).toHaveLength(16);
  });

  it("renders the console header and one client block per enabled profile", () => {
    const { content, profiles: rendered } = renderRadiusClientsConf(profiles);
    expect(content.startsWith(RADIUS_HEADER_MARKER)).toBe(true);
    expect(rendered).toHaveLength(2); // disabled id 3 skipped
    expect(rendered.map((p) => p.id)).toEqual([1, 2]); // SORTED by id, not input order
    expect(content).toContain("client corp-dc {");
    expect(content).toContain("client branch {");
    expect(content).not.toContain("client off {");
    expect(content).not.toContain("192.0.2.30");
    expect(content).not.toContain("client localhost {"); // stock client is NOT invented back
    expect(content).not.toContain("client localhost_ipv6 {");
  });

  it("renders secrets VERBATIM (ipaddr/secret tokens), never the profile name as secret", () => {
    const { content } = renderRadiusClientsConf([profile({ sharedSecret: "s3cret-P@ss" })]);
    expect(content).toContain("\tipaddr = 192.0.2.5");
    expect(content).toContain("\tsecret = s3cret-P@ss");
  });

  it("carries slug + per-block renderHash identity per profile", () => {
    const { profiles: rendered } = renderRadiusClientsConf(profiles);
    const first = rendered[0];
    expect(first.slug).toBe("corp-dc");
    expect(first.renderHash).toHaveLength(16);
    expect(first.renderHash).toBe(renderClientBlock(profile({ id: 1, name: "Corp DC!" }), "corp-dc").rendered.renderHash);
    expect(first.secretRendered).toBe(true);
    expect(JSON.stringify(rendered)).not.toContain("s3cret"); // status identity never leaks secrets
  });

  it("renders the header-only empty state when no profile is enabled", () => {
    const { content, profiles: rendered, warnings } = renderRadiusClientsConf([profile({ enabled: false })]);
    expect(rendered).toHaveLength(0);
    expect(content.startsWith(RADIUS_HEADER_MARKER)).toBe(true);
    expect(content).toContain("No console-managed NAS clients — freeradius is stopped (console-off)");
    expect(content).not.toMatch(/^client \S+ \{/m); // zero client blocks
    expect(warnings.some((w) => w.includes("stopped"))).toBe(true);
  });

  it("warns on disabled profiles without failing", () => {
    const { warnings } = renderRadiusClientsConf([profile({ enabled: false, name: "off" })]);
    expect(warnings.some((w) => w.includes("off") && w.includes("disabled"))).toBe(true);
  });
});

// ── refusals (config injection) ────────────────────────────────────────────

describe("hardRadiusRefusal / isUnsafeRadiusToken", () => {
  it("flags whitespace, quotes, backslash and block/comment metacharacters", () => {
    for (const evil of ["two words", 'quo"te', "back\\slash", "#comment", "block{", "block}", "dollar$x", "back`tick", "semi;colon"]) {
      expect(isUnsafeRadiusToken(evil)).toBe(true);
    }
    expect(isUnsafeRadiusToken("s3cret-P@ss!~")).toBe(false); // punctuation without metachars is fine
  });
  it("hard-refuses enabled profiles with injectable secrets or serverIp", () => {
    const ref = hardRadiusRefusal([profile({ sharedSecret: 'evil" secret' })]);
    expect(ref).toContain("shared secret");
    expect(ref).toContain("refused");
    expect(hardRadiusRefusal([profile({ serverIp: "1.2.3.4 # comment" })])).toContain("serverIp");
    expect(hardRadiusRefusal([profile({ serverIp: "192.0.2.5" })])).toBeNull();
  });
  it("ignores disabled profiles (nothing is rendered for them)", () => {
    expect(hardRadiusRefusal([profile({ sharedSecret: "bad secret", enabled: false })])).toBeNull();
  });
  it("does NOT refuse loopback serverIp — a NAS on localhost is legitimate", () => {
    expect(hardRadiusRefusal([profile({ serverIp: "127.0.0.1" })])).toBeNull();
  });
});

// ── command whitelist ──────────────────────────────────────────────────────

describe("radiusStepGuarded", () => {
  it("allows exactly the freeradius/systemctl/ss/cp/install/rm plan forms", () => {
    expect(radiusStepGuarded("freeradius -CX")).toBe(true);
    expect(radiusStepGuarded("systemctl restart freeradius")).toBe(true);
    expect(radiusStepGuarded("systemctl stop freeradius")).toBe(true);
    expect(radiusStepGuarded("systemctl is-active freeradius")).toBe(true);
    expect(radiusStepGuarded("ss -lun '( sport = :1812 )'")).toBe(true);
    expect(radiusStepGuarded("cp /etc/freeradius/3.0/clients.conf /var/lib/console/identity/backup-2025-01-01T00-00-00-000Z/clients.conf")).toBe(true);
    expect(radiusStepGuarded(`install -m 0640 -o root -g freerad ${RADIUS_STAGE_FILE} ${RADIUS_MANAGED_FILE}`)).toBe(true);
    expect(radiusStepGuarded("install -m 0640 -o root -g freerad /var/lib/console/identity/backup-t/clients.conf /etc/freeradius/3.0/clients.conf")).toBe(true);
    expect(radiusStepGuarded("rm -f /var/lib/console/identity/stage-clients.conf")).toBe(true);
  });
  it("rejects everything else — radtest NEVER, chaining, other units, traversal, state file", () => {
    for (const evil of [
      "",
      "radtest user s3cret 192.0.2.5 1812 s3cret",
      "radtest user pass 127.0.0.1 0 secret",
      "freeradius -CX -d /etc/shadow",
      "freeradius -CX; rm -rf /",
      "freeradius -CX && reboot",
      "systemctl restart freeradiusd",
      "systemctl enable freeradius",
      "systemctl restart cron",
      "systemctl stop freeradius --now",
      "ss -lun", // unquoted / no filter
      "ss -lun '( sport = :22 )'",
      "install -m 0640 /etc/shadow /etc/freeradius/3.0/clients.conf",
      "install -m 0640 -o root -g freerad /var/lib/console/identity/../../etc/shadow /etc/freeradius/3.0/clients.conf",
      "cp /etc/shadow /var/lib/console/identity/backup-x/shadow",
      "rm -f /var/lib/console/identity/state.json", // state is fs-managed, not whitelisted
      "rm -rf /etc/freeradius",
      "sh -c evil",
      "reboot",
    ]) {
      expect(radiusStepGuarded(evil)).toBe(false);
    }
  });
});

// ── apply plan ─────────────────────────────────────────────────────────────

describe("buildRadiusApplyPlan", () => {
  const profiles = [profile({ id: 1, name: "Corp DC!" }), profile({ id: 2, name: "branch", serverIp: "192.0.2.20", sharedSecret: "br@nch" })];

  it("orders: snapshot → stage → install → validate → cleanup → restart → verify → writefile (LAST)", () => {
    const plan = buildRadiusApplyPlan({ profiles, managedFileExists: true, mode: "exec", ts: "t" });
    const kinds = plan.steps.map((s) => s.kind as string);
    expect(kinds[0]).toBe("snapshot");
    const idx = (k: string) => kinds.indexOf(k);
    expect(idx("stage")).toBeGreaterThan(idx("snapshot"));
    expect(idx("install")).toBeGreaterThan(idx("stage"));
    expect(idx("validate")).toBeGreaterThan(idx("install")); // freeradius -CX validates the whole dir → after install
    expect(idx("restart")).toBeGreaterThan(idx("validate"));
    expect(idx("verify")).toBeGreaterThan(idx("restart"));
    expect(kinds[kinds.length - 1]).toBe("writefile"); // state.json is written only after every verify
    expect(idx("stop")).toBe(-1); // non-empty plan never stops the unit

    // exact commands for the critical steps
    expect(plan.steps.find((s) => s.kind === "snapshot")?.cmd).toBe(
      `cp ${RADIUS_MANAGED_FILE} /var/lib/console/identity/backup-t/clients.conf`,
    );
    expect(plan.steps.find((s) => s.kind === "stage")?.cmd).toBe("");
    expect(plan.steps.find((s) => s.kind === "install")?.cmd).toBe(
      `install -m 0640 -o root -g freerad ${RADIUS_STAGE_FILE} ${RADIUS_MANAGED_FILE}`,
    );
    expect(plan.steps.filter((s) => s.cmd === "freeradius -CX")).toHaveLength(2); // validate + re-validate verify
    expect(plan.steps.find((s) => s.kind === "restart")?.cmd).toBe("systemctl restart freeradius");
    const verifies = plan.steps.filter((s) => s.kind === "verify" && s.cmd !== "").map((s) => s.cmd);
    expect(verifies).toEqual(["systemctl is-active freeradius", `ss -lun '( sport = :${RADIUS_AUTH_PORT} )'`, "freeradius -CX"]);
    expect(plan.confHash).toHaveLength(16);
  });

  it("empty state: header-only file + systemctl stop (unit left disabled) instead of restart", () => {
    const plan = buildRadiusApplyPlan({ profiles: [profile({ enabled: false })], managedFileExists: true, mode: "plan", ts: "t" });
    expect(plan.empty).toBe(true);
    expect(plan.profiles).toHaveLength(0);
    expect(plan.content).toContain("No console-managed NAS clients");
    const stop = plan.steps.find((s) => s.kind === "stop");
    expect(stop?.cmd).toBe("systemctl stop freeradius");
    expect(plan.steps.some((s) => s.kind === "restart")).toBe(false);
    expect(plan.steps[plan.steps.length - 1].kind).toBe("writefile");
    const state = JSON.parse(plan.stateContent) as { empty: boolean; profileIds: number[]; confHash: string; note?: string };
    expect(state.empty).toBe(true);
    expect(state.profileIds).toEqual([]);
    expect(state.confHash).toBe(plan.confHash);
    expect(state.note).toContain("stopped");
  });

  it("skips the snapshot step when no managed file exists (first apply)", () => {
    const plan = buildRadiusApplyPlan({ profiles, managedFileExists: false, mode: "exec", ts: "t" });
    expect(plan.steps.some((s) => s.kind === "snapshot")).toBe(false);
    expect(plan.steps[plan.steps.length - 1].kind).toBe("writefile");
  });

  it("state content carries confHash + appliedAt + rendered profileIds", () => {
    const plan = buildRadiusApplyPlan({ profiles: [...profiles, profile({ id: 3, enabled: false })], managedFileExists: true, mode: "exec", ts: "t" });
    const state = JSON.parse(plan.stateContent) as { confHash: string; appliedAt: string; profileIds: number[]; empty: boolean };
    expect(state.confHash).toBe(plan.confHash);
    expect(typeof state.appliedAt).toBe("string");
    expect(state.profileIds).toEqual([1, 2]); // disabled id 3 excluded
    expect(state.empty).toBe(false);
  });

  it("every step cmd passes the whitelist (plan is executable as written)", () => {
    const plan = buildRadiusApplyPlan({ profiles, managedFileExists: true, mode: "exec", ts: "t" });
    for (const s of plan.steps) {
      if (s.cmd !== "") expect(radiusStepGuarded(s.cmd)).toBe(true);
    }
  });

  it("drops refused profiles from the render and warns (refusal surfaces separately)", () => {
    const plan = buildRadiusApplyPlan({
      profiles: [profile({ id: 1, name: "evil", sharedSecret: "two words" }), profile({ id: 2, name: "ok" })],
      managedFileExists: false,
      mode: "plan",
      ts: "t",
    });
    expect(plan.content).not.toContain("two words");
    expect(plan.content).toContain("client ok {");
    expect(plan.warnings.some((w) => w.includes("evil") && w.includes("refused"))).toBe(true);
  });
});

// ── drift + ss parse ───────────────────────────────────────────────────────

describe("computeRadiusDrift", () => {
  const rendered = renderRadiusClientsConf([profile()]);

  it("in-sync when hash matches AND unit active (profiles defined)", () => {
    const ok = computeRadiusDrift({
      renderedContent: rendered.content,
      liveFileHash: radiusConfHash(rendered.content),
      unitActive: true,
      hasEnabledProfiles: true,
    });
    expect(ok.inSync).toBe(true);
    expect(ok.driftReasons).toEqual([]);
  });
  it("flags missing/changed file and inactive unit", () => {
    const missing = computeRadiusDrift({ renderedContent: rendered.content, liveFileHash: null, unitActive: true, hasEnabledProfiles: true });
    expect(missing.driftReasons[0]).toContain("managed file is missing");

    const changed = computeRadiusDrift({
      renderedContent: rendered.content,
      liveFileHash: "deadbeefdeadbeef",
      unitActive: true,
      hasEnabledProfiles: true,
    });
    expect(changed.driftReasons.some((r) => r.includes("deadbeefdeadbeef"))).toBe(true);

    const down = computeRadiusDrift({
      renderedContent: rendered.content,
      liveFileHash: radiusConfHash(rendered.content),
      unitActive: false,
      hasEnabledProfiles: true,
    });
    expect(down.inSync).toBe(false);
    expect(down.driftReasons.some((r) => r.includes("not active"))).toBe(true);
  });
  it("empty state: unit must be STOPPED to be in sync (console-off)", () => {
    const empty = renderRadiusClientsConf([]).content;
    const stopped = computeRadiusDrift({ renderedContent: empty, liveFileHash: radiusConfHash(empty), unitActive: false, hasEnabledProfiles: false });
    expect(stopped.inSync).toBe(true);
    const running = computeRadiusDrift({ renderedContent: empty, liveFileHash: radiusConfHash(empty), unitActive: true, hasEnabledProfiles: false });
    expect(running.inSync).toBe(false);
    expect(running.driftReasons.some((r) => r.includes("stopped"))).toBe(true);
  });
});

describe("parseSsForAuthPort", () => {
  const SS = `State  Recv-Q Send-Q Local Address:Port  Peer Address:Port
UNCONN 0      0      0.0.0.0:1812         0.0.0.0:*
UNCONN 0      0      [::]:1812            [::]:*
UNCONN 0      0      0.0.0.0:5353         0.0.0.0:*`;
  it("true when udp/1812 is bound (v4 or v6); exact port match only", () => {
    expect(parseSsForAuthPort(SS)).toBe(true);
    expect(parseSsForAuthPort("UNCONN 0 0 0.0.0.0:1812 0.0.0.0:*")).toBe(true);
    expect(parseSsForAuthPort("UNCONN 0 0 [::]:1812 [::]:*")).toBe(true);
    expect(parseSsForAuthPort("UNCONN 0 0 10.9.9.9:18120 0.0.0.0:*")).toBe(false); // :18120 ≠ :1812 (sport filter is exact)
  });
  it("false when the port is unbound — an empty probe is definitive for LISTEN", () => {
    expect(parseSsForAuthPort("UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*")).toBe(false);
    expect(parseSsForAuthPort("")).toBe(false);
    expect(parseSsForAuthPort("\n")).toBe(false);
  });
});

// ── route wiring (existence + handler shape) ───────────────────────────────

describe("test routes are wired (GUI 404 bugs fixed)", () => {
  const srcRoot = path.join(process.cwd(), "src/app/api/v1");

  it("radius-profiles/[id]/test wires the existing testRadiusProfile service", () => {
    const p = path.join(srcRoot, "radius-profiles/[id]/test/route.ts");
    expect(existsSync(p)).toBe(true);
    const s = readFileSync(p, "utf8");
    expect(s).toContain('testRadiusProfile } from "@/lib/identity/service"');
    expect(s).toContain("testRadiusProfile(auth.tenantId, id)");
    expect(s).toContain('numericId(params, "id")');
    expect(s).toContain('area: "identity"');
    expect(s).toContain('action: "radius_profile.test"');
    expect(s).toContain('objectType: "radius_profile"');
  });

  it("directory-sources/[id]/test wires the existing testDirectorySource service", () => {
    const p = path.join(srcRoot, "directory-sources/[id]/test/route.ts");
    expect(existsSync(p)).toBe(true);
    const s = readFileSync(p, "utf8");
    expect(s).toContain('testDirectorySource } from "@/lib/identity/service"');
    expect(s).toContain("testDirectorySource(auth.tenantId, id)");
    expect(s).toContain('numericId(params, "id")');
    expect(s).toContain('area: "identity"');
    expect(s).toContain('action: "directory_source.test"');
    expect(s).toContain('objectType: "directory_source"');
  });

  it("identity-advanced/idps/[id]/test implements the deterministic simulated handshake + status persist", () => {
    const p = path.join(srcRoot, "identity-advanced/idps/[id]/test/route.ts");
    expect(existsSync(p)).toBe(true);
    const s = readFileSync(p, "utf8");
    expect(s).toContain('area: "federation"');
    expect(s).toContain('section: "identity"');
    expect(s).toContain('numericId(params, "id")');
    expect(s).toContain("fnv1a"); // deterministic simulation hash (M23 convention)
    expect(s).toContain('action: "idp.test"');
    expect(s).toContain('objectType: "federated_idp"');
    expect(s).toContain("db.federatedIdp.update"); // result persists as the row status
    expect(s).toContain("status");
  });

  it("identity/os route exposes GET status + POST {action: apply|rollback} with the audit family", () => {
    const p = path.join(srcRoot, "identity/os/route.ts");
    expect(existsSync(p)).toBe(true);
    const s = readFileSync(p, "utf8");
    expect(s).toContain("export const GET");
    expect(s).toContain("export const POST");
    expect(s).toContain('readRadiusOsStatus, rollbackRadiusToOs } from "@/lib/identity/os-service"');
    expect(s).toContain("applyRadiusToOs");
    expect(s).toContain('action: z.enum(["apply", "rollback"])');
    expect(s).toContain('area: "identity"');
    expect(s).toContain('section: "identity"');
    expect(s).toContain('"radius.os-apply.exec"');
    expect(s).toContain('"radius.os-apply.plan"');
    expect(s).toContain('"radius.os-apply.failed"');
    expect(s).toContain('"radius.os-rollback"');
    expect(s).toContain('objectType: "radius_profile"');
  });

  it("panel is mounted in the RADIUS Profiles tab (users-view) and identity-api carries the OS client", () => {
    const view = readFileSync(path.join(process.cwd(), "src/components/views/identity/users-view.tsx"), "utf8");
    expect(view).toContain('from "./os-apply"');
    expect(view).toContain("<IdentityOsPanel");
    const api = readFileSync(path.join(process.cwd(), "src/components/views/identity/identity-api.ts"), "utf8");
    expect(api).toContain("getOsStatus");
    expect(api).toContain("applyToOs");
    expect(api).toContain('"/api/v1/identity/os"');
  });
});
