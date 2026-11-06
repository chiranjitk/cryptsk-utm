/**
 * OpenAPI 3.1 artifact generator (M11 §4.2, restored REVIEW-4A).
 *
 * Source of truth = the LOCKED §7.2 route table in PROJECT_MEMORY (paths are
 * LOCKED — expand, never rename). ROUTE_MANIFEST below enumerates that table
 * verbatim (method + summary + tag); the spec object is built ONCE at module
 * load and served cached by GET /api/v1/openapi.json. This is generation, not
 * a hand-written parallel spec: the manifest IS the generator input, and the
 * builder throws on duplicate method+path entries (§7.2 drift guard).
 *
 * Machine-readable docs = this artifact; human docs = ENDPOINTS.md; no
 * swagger UI bundle ships in Phase 1 (M11 §4.1).
 */

import { z } from "zod";
import { apiKeyCreateSchema, webhookCreateSchema, webhookUpdateSchema } from "@/lib/validators/api-keys";

type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

/** [method, path (relative to /api/v1), summary, tag, isPublic?] */
type RouteDef = readonly [Method, string, string, string, true?];

/**
 * ROUTE_MANIFEST — the LOCKED API_SURFACE catalog (PROJECT_MEMORY §7.2).
 * Copy-verbatim enumeration; expand-only per the §7.2 rule.
 */
export const ROUTE_MANIFEST: readonly RouteDef[] = [
  // ── AUTH ────────────────────────────────────────────────────────────────
  ["POST", "/auth/login", "Login (sets the cryptsk_token session cookie; totpCode only when enrolled)", "Auth", true],
  ["POST", "/auth/logout", "Logout (clears the session cookie)", "Auth"],
  ["GET", "/auth/me", "Current user + permissions", "Auth"],

  // ── DASHBOARD ───────────────────────────────────────────────────────────
  ["GET", "/dashboard/summary", "Health, throughput, sessions, alerts24h, topApps, topTalkers, wanStatus, vpnStatus", "Dashboard"],

  // ── NETWORK ─────────────────────────────────────────────────────────────
  ["GET", "/interfaces", "List interfaces (with live stats)", "Network"],
  ["POST", "/interfaces", "Create logical interface (vlan/bridge/bond/gre)", "Network"],
  ["GET", "/interfaces/{id}", "Interface detail", "Network"],
  ["PUT", "/interfaces/{id}", "Update interface (ip config, mtu, role, zone…)", "Network"],
  ["DELETE", "/interfaces/{id}", "Delete interface (non-physical only)", "Network"],
  ["GET", "/interfaces/{id}/stats", "Per-interface counters", "Network"],
  ["GET", "/routes", "Static routes list", "Network"],
  ["POST", "/routes", "Create static route", "Network"],
  ["PUT", "/routes/{id}", "Update static route", "Network"],
  ["DELETE", "/routes/{id}", "Delete static route", "Network"],
  ["GET", "/wan-policies", "Multi-WAN policies + probe states", "Network"],
  ["POST", "/wan-policies", "Create WAN policy", "Network"],
  ["PUT", "/wan-policies/{id}", "Update WAN policy", "Network"],
  ["DELETE", "/wan-policies/{id}", "Delete WAN policy", "Network"],
  ["POST", "/wan-policies/{id}/probe", "Force WAN probe now", "Network"],

  // ── OBJECTS ─────────────────────────────────────────────────────────────
  ["GET", "/zones", "List security zones", "Objects"],
  ["POST", "/zones", "Create zone", "Objects"],
  ["PUT", "/zones/{id}", "Update zone", "Objects"],
  ["DELETE", "/zones/{id}", "Delete zone", "Objects"],
  ["GET", "/address-objects", "List address objects", "Objects"],
  ["POST", "/address-objects", "Create address object", "Objects"],
  ["PUT", "/address-objects/{id}", "Update address object", "Objects"],
  ["DELETE", "/address-objects/{id}", "Delete address object", "Objects"],
  ["GET", "/address-groups", "List address groups", "Objects"],
  ["POST", "/address-groups", "Create address group", "Objects"],
  ["PUT", "/address-groups/{id}", "Update address group", "Objects"],
  ["DELETE", "/address-groups/{id}", "Delete address group", "Objects"],
  ["GET", "/service-objects", "List service objects", "Objects"],
  ["POST", "/service-objects", "Create service object", "Objects"],
  ["PUT", "/service-objects/{id}", "Update service object", "Objects"],
  ["DELETE", "/service-objects/{id}", "Delete service object", "Objects"],
  ["GET", "/service-groups", "List service groups", "Objects"],
  ["POST", "/service-groups", "Create service group", "Objects"],
  ["PUT", "/service-groups/{id}", "Update service group", "Objects"],
  ["DELETE", "/service-groups/{id}", "Delete service group", "Objects"],
  ["GET", "/schedule-objects", "List schedule objects", "Objects"],
  ["POST", "/schedule-objects", "Create schedule object", "Objects"],
  ["PUT", "/schedule-objects/{id}", "Update schedule object", "Objects"],
  ["DELETE", "/schedule-objects/{id}", "Delete schedule object", "Objects"],

  // ── FIREWALL ────────────────────────────────────────────────────────────
  ["GET", "/firewall-rules", "Ordered firewall rules list (?zone=&search=)", "Firewall"],
  ["POST", "/firewall-rules", "Create firewall rule", "Firewall"],
  ["GET", "/firewall-rules/{id}", "Firewall rule detail", "Firewall"],
  ["PUT", "/firewall-rules/{id}", "Update firewall rule", "Firewall"],
  ["DELETE", "/firewall-rules/{id}", "Delete firewall rule", "Firewall"],
  ["PATCH", "/firewall-rules/{id}/toggle", "Enable/disable rule {enabled}", "Firewall"],
  ["POST", "/firewall-rules/reorder", "Reorder rules {orderedIds}", "Firewall"],
  ["GET", "/firewall-rules/{id}/hits", "Per-rule hit counters", "Firewall"],
  ["POST", "/firewall-rules/{id}/hits/reset", "Reset per-rule counters (audited)", "Firewall"],
  ["POST", "/firewall-rules/validate", "Shadow/conflict check (no persist)", "Firewall"],
  ["POST", "/firewall-rules/import", "Batch import {format: json|csv, payload}", "Firewall"],
  ["GET", "/firewall-rules/export", "Export rules CSV (current filter)", "Firewall"],
  ["GET", "/nat-rules", "List NAT rules", "Firewall"],
  ["POST", "/nat-rules", "Create NAT rule", "Firewall"],
  ["PUT", "/nat-rules/{id}", "Update NAT rule", "Firewall"],
  ["DELETE", "/nat-rules/{id}", "Delete NAT rule", "Firewall"],
  ["PATCH", "/nat-rules/{id}/toggle", "Enable/disable NAT rule {enabled}", "Firewall"],
  ["POST", "/nat-rules/reorder", "Reorder NAT rules {orderedIds}", "Firewall"],

  // ── IPS ─────────────────────────────────────────────────────────────────
  ["GET", "/ips/policies", "List IPS policies", "IPS"],
  ["POST", "/ips/policies", "Create IPS policy", "IPS"],
  ["PUT", "/ips/policies/{id}", "Update IPS policy", "IPS"],
  ["DELETE", "/ips/policies/{id}", "Delete IPS policy", "IPS"],
  ["POST", "/ips/policies/apply-preset", "Apply preset {preset: conservative|balanced|aggressive}", "IPS"],
  ["GET", "/ips/rule-categories", "ET rule category list + enabled state", "IPS"],
  ["GET", "/ips/update-settings", "Auto-update scheduler config", "IPS"],
  ["PUT", "/ips/update-settings", "Update auto-update scheduler config", "IPS"],
  ["GET", "/ips/events", "IPS events (?severity=&sid=&q=&since=&until=&category=&page=)", "IPS"],
  ["POST", "/ips/events/{id}/suppress", "Suppress event {duration}", "IPS"],

  // ── VPN ─────────────────────────────────────────────────────────────────
  ["GET", "/vpn/configs", "List VPN configs", "VPN"],
  ["POST", "/vpn/configs", "Create VPN config", "VPN"],
  ["PUT", "/vpn/configs/{id}", "Update VPN config", "VPN"],
  ["DELETE", "/vpn/configs/{id}", "Delete VPN config", "VPN"],
  ["GET", "/vpn/configs/{id}/status", "Tunnel state, DPD, handshakes", "VPN"],
  ["POST", "/vpn/configs/{id}/client-bundle", "Client bundle download (wg .conf / .ovpn payload)", "VPN"],
  ["GET", "/vpn/sessions", "Active VPN sessions", "VPN"],
  ["POST", "/vpn/sessions/{id}/disconnect", "Disconnect a VPN session", "VPN"],
  ["GET", "/vpn/user-groups", "List VPN user groups", "VPN"],
  ["POST", "/vpn/user-groups", "Create VPN user group", "VPN"],
  ["PUT", "/vpn/user-groups/{id}", "Update VPN user group", "VPN"],
  ["DELETE", "/vpn/user-groups/{id}", "Delete VPN user group", "VPN"],

  // ── DNS & DHCP ──────────────────────────────────────────────────────────
  ["GET", "/dns/settings", "Resolver config", "DNS & DHCP"],
  ["PUT", "/dns/settings", "Update resolver config", "DNS & DHCP"],
  ["GET", "/dns/policies", "List DNS policies", "DNS & DHCP"],
  ["POST", "/dns/policies", "Create DNS policy", "DNS & DHCP"],
  ["PUT", "/dns/policies/{id}", "Update DNS policy", "DNS & DHCP"],
  ["DELETE", "/dns/policies/{id}", "Delete DNS policy", "DNS & DHCP"],
  ["GET", "/dns/records", "List DNS records", "DNS & DHCP"],
  ["POST", "/dns/records", "Create DNS record", "DNS & DHCP"],
  ["PUT", "/dns/records/{id}", "Update DNS record", "DNS & DHCP"],
  ["DELETE", "/dns/records/{id}", "Delete DNS record", "DNS & DHCP"],
  ["GET", "/dns/query-logs", "DNS query logs (?q=&blocked=)", "DNS & DHCP"],
  ["GET", "/dhcp/subnets", "List DHCP subnets", "DNS & DHCP"],
  ["POST", "/dhcp/subnets", "Create DHCP subnet", "DNS & DHCP"],
  ["PUT", "/dhcp/subnets/{id}", "Update DHCP subnet", "DNS & DHCP"],
  ["DELETE", "/dhcp/subnets/{id}", "Delete DHCP subnet (cascades reservations + leases)", "DNS & DHCP"],
  ["GET", "/dhcp/reservations", "List DHCP reservations", "DNS & DHCP"],
  ["POST", "/dhcp/reservations", "Create DHCP reservation", "DNS & DHCP"],
  ["PUT", "/dhcp/reservations/{id}", "Update DHCP reservation", "DNS & DHCP"],
  ["DELETE", "/dhcp/reservations/{id}", "Delete DHCP reservation", "DNS & DHCP"],
  ["GET", "/dhcp/leases", "DHCP leases (?state=active|expired)", "DNS & DHCP"],
  ["POST", "/dhcp/leases/{id}/release", "Force-release a lease", "DNS & DHCP"],
  ["GET", "/dhcp/relay", "DHCP relay (ip-helper) config", "DNS & DHCP"],
  ["PUT", "/dhcp/relay", "Update DHCP relay config", "DNS & DHCP"],

  // ── IDENTITY ────────────────────────────────────────────────────────────
  ["GET", "/users", "List local users", "Identity"],
  ["POST", "/users", "Create local user", "Identity"],
  ["PUT", "/users/{id}", "Update local user", "Identity"],
  ["DELETE", "/users/{id}", "Delete local user", "Identity"],
  ["GET", "/user-groups", "List user groups", "Identity"],
  ["POST", "/user-groups", "Create user group", "Identity"],
  ["PUT", "/user-groups/{id}", "Update user group", "Identity"],
  ["DELETE", "/user-groups/{id}", "Delete user group", "Identity"],
  ["GET", "/auth-settings", "Password policy, lockout, TOTP settings", "Identity"],
  ["PUT", "/auth-settings", "Update auth settings", "Identity"],
  ["GET", "/radius-profiles", "List RADIUS profiles", "Identity"],
  ["POST", "/radius-profiles", "Create RADIUS profile", "Identity"],
  ["PUT", "/radius-profiles/{id}", "Update RADIUS profile", "Identity"],
  ["DELETE", "/radius-profiles/{id}", "Delete RADIUS profile", "Identity"],
  ["POST", "/radius-profiles/{id}/test", "Simulated connectivity test → {ok, latencyMs}", "Identity"],
  ["POST", "/radius-profiles/{id}/reveal", "Reveal sharedSecret (audited, one-time)", "Identity"],
  ["GET", "/captive-portal", "Captive portal profile", "Identity"],
  ["PUT", "/captive-portal", "Update captive portal profile", "Identity"],
  ["GET", "/captive-portal/vouchers", "List vouchers (simulated, in-memory)", "Identity"],
  ["POST", "/captive-portal/vouchers", "Batch-generate vouchers {count, ttlHours?, bandwidthKbps?}", "Identity"],
  ["DELETE", "/captive-portal/vouchers/{id}", "Revoke one voucher", "Identity"],
  ["GET", "/identity/sessions", "Live ip→user sessions map", "Identity"],
  ["POST", "/identity/sessions/{id}/expire", "Force-expire a session (audited)", "Identity"],
  ["GET", "/directory-sources", "List directory sources (LDAP/AD)", "Identity"],
  ["POST", "/directory-sources", "Create directory source", "Identity"],
  ["PUT", "/directory-sources/{id}", "Update directory source", "Identity"],
  ["DELETE", "/directory-sources/{id}", "Delete directory source", "Identity"],
  ["POST", "/directory-sources/{id}/test", "Simulated LDAP/AD connectivity test", "Identity"],

  // ── QOS ─────────────────────────────────────────────────────────────────
  ["GET", "/qos/policies", "List QoS policies", "QoS"],
  ["POST", "/qos/policies", "Create QoS policy", "QoS"],
  ["PUT", "/qos/policies/{id}", "Update QoS policy", "QoS"],
  ["DELETE", "/qos/policies/{id}", "Delete QoS policy", "QoS"],
  ["GET", "/qos/rules", "List QoS rules (scoped by ?policyId=)", "QoS"],

  // ── LOGS ────────────────────────────────────────────────────────────────
  ["GET", "/logs/firewall", "Firewall logs (?q=&action=&src=&dst=&since=&until=&page=)", "Logs"],
  ["GET", "/logs/firewall/export", "CSV export of current filter (same params, no page)", "Logs"],
  ["GET", "/logs/ips", "IPS logs (?severity=&category=&page=)", "Logs"],
  ["GET", "/logs/audit", "Audit log (?user=&objectType=&page=)", "Logs"],
  ["GET", "/logs/stats", "Chart aggregates (?range=1h|24h|7d)", "Logs"],
  ["GET", "/logs/syslog-targets", "List syslog targets", "Logs"],
  ["POST", "/logs/syslog-targets", "Create syslog target", "Logs"],
  ["PUT", "/logs/syslog-targets/{id}", "Update syslog target", "Logs"],
  ["DELETE", "/logs/syslog-targets/{id}", "Delete syslog target", "Logs"],
  ["GET", "/logs/netflow-targets", "List NetFlow targets", "Logs"],
  ["POST", "/logs/netflow-targets", "Create NetFlow target", "Logs"],
  ["PUT", "/logs/netflow-targets/{id}", "Update NetFlow target", "Logs"],
  ["DELETE", "/logs/netflow-targets/{id}", "Delete NetFlow target", "Logs"],
  ["GET", "/logs/report-schedules", "List report schedules", "Logs"],
  ["POST", "/logs/report-schedules", "Create report schedule", "Logs"],
  ["PUT", "/logs/report-schedules/{id}", "Update report schedule", "Logs"],
  ["DELETE", "/logs/report-schedules/{id}", "Delete report schedule", "Logs"],
  ["POST", "/logs/report-schedules/{id}/run", "Generate the report now (simulated)", "Logs"],
  ["GET", "/logs/reports/export", "Report export (?range=1h|24h|7d&format=csv|json)", "Logs"],

  // ── HA ──────────────────────────────────────────────────────────────────
  ["GET", "/ha/status", "Local + peer HA state (simulated)", "HA"],
  ["GET", "/ha/config", "HA pair configuration", "HA"],
  ["PUT", "/ha/config", "Update HA pair configuration", "HA"],

  // ── SYSTEM ──────────────────────────────────────────────────────────────
  ["GET", "/system/status", "cpu/ram/disk/temp/uptime/services", "System"],
  ["GET", "/system/settings", "System settings (NTP, SNMP, hardening, thresholds)", "System"],
  ["PUT", "/system/settings", "Update system settings", "System"],
  ["POST", "/system/services/{name}/restart", "Restart a running service (audited, simulated)", "System"],
  ["GET", "/system/firmware", "Firmware current/channel/history", "System"],
  ["POST", "/system/firmware/check", "Simulated update check (sets available)", "System"],
  ["POST", "/system/firmware/upgrade", "Staged upgrade — safety backup first (simulated)", "System"],
  ["POST", "/system/firmware/rollback", "Roll back to the previous version (simulated)", "System"],
  ["GET", "/system/policy-templates", "Per-vertical starter policy templates", "System"],
  ["POST", "/system/policy-templates/{id}/apply", "Apply a template's starter config (audited)", "System"],
  ["GET", "/system/ssh-keys", "List SSH management keys (public material only)", "System"],
  ["POST", "/system/ssh-keys", "Add SSH public key (fingerprint derived server-side)", "System"],
  ["DELETE", "/system/ssh-keys/{id}", "Remove SSH key", "System"],
  ["POST", "/system/setup/complete", "Mark the first-time-setup wizard done", "System"],
  ["GET", "/system/backups", "List backups", "System"],
  ["POST", "/system/backups", "Create backup (simulated)", "System"],
  ["POST", "/system/backups/{id}/restore", "Restore backup (typed confirmation, simulated)", "System"],
  ["GET", "/system/backups/{id}/download", "JSON backup download", "System"],
  ["GET", "/notifications", "Notifications (?unread=true)", "System"],
  ["POST", "/notifications/{id}/read", "Mark one notification read", "System"],
  ["POST", "/notifications/read-all", "Mark all notifications read (audited)", "System"],
  ["GET", "/config-versions", "Config version list (?page=)", "System"],
  ["GET", "/config-versions/{id}", "One version + full snapshot", "System"],

  // ── API PLATFORM (M11) ──────────────────────────────────────────────────
  ["GET", "/api-keys", "List API keys (prefix + metadata only, never the secret)", "API Platform"],
  ["POST", "/api-keys", "Create API key — the response carries the full key exactly once", "API Platform"],
  ["DELETE", "/api-keys/{id}", "Revoke API key (soft: revoked = true)", "API Platform"],
  ["GET", "/webhooks", "List webhook registrations (secret masked, never returned)", "API Platform"],
  ["POST", "/webhooks", "Register webhook {name, url, events, secret?}", "API Platform"],
  ["PUT", "/webhooks/{id}", "Update webhook (omit secret to keep stored value)", "API Platform"],
  ["DELETE", "/webhooks/{id}", "Delete webhook registration", "API Platform"],
  ["POST", "/webhooks/{id}/test", "Simulated delivery → {ok, status, latencyMs}", "API Platform"],
  ["GET", "/openapi.json", "This OpenAPI 3.1 artifact (generated from the §7.2 route table)", "API Platform"],
] as const;

const TAG_DESCRIPTIONS: Record<string, string> = {
  Auth: "Session lifecycle (JWT cookie, 8 h — ADR-007)",
  Dashboard: "Console dashboard aggregates",
  Network: "Interfaces, static routes, multi-WAN",
  Objects: "Zones, address/service/schedule objects and groups",
  Firewall: "Firewall + NAT rules",
  IPS: "Intrusion prevention policies, categories, events",
  VPN: "VPN configs, sessions, user groups",
  "DNS & DHCP": "Resolver, DNS policies/records, DHCP subnets/reservations/leases/relay",
  Identity: "Users, groups, auth settings, RADIUS, captive portal, directory sources, sessions",
  QoS: "QoS policies and rules",
  Logs: "Firewall/IPS/audit logs, targets, reports",
  HA: "High-availability pair (simulated)",
  System: "Appliance system services, backups, notifications, config versions",
  "API Platform": "API-key lifecycle, webhook registrations, OpenAPI artifact (M11)",
};

/** requestBody schemas generated from the M11 zod validators (zod 4 → JSON Schema). */
const REQUEST_BODY_SCHEMAS: Record<string, z.ZodType> = {
  "POST /api-keys": apiKeyCreateSchema,
  "POST /webhooks": webhookCreateSchema,
  "PUT /webhooks/{id}": webhookUpdateSchema,
};

function jsonSchemaOf(schema: z.ZodType): Record<string, unknown> {
  try {
    // io "input" = the wire format (pre-*.default / pre-refine); refinements
    // (future-datetime, exact scope arrays) are enforced server-side.
    return z.toJSONSchema(schema, { io: "input", unrepresentable: "any" }) as Record<string, unknown>;
  } catch {
    return { type: "object", additionalProperties: true };
  }
}

function pathParamsOf(path: string): Array<Record<string, unknown>> {
  const params: Array<Record<string, unknown>> = [];
  for (const seg of path.split("/")) {
    const m = seg.match(/^\{(.+)\}$/);
    if (!m) continue;
    params.push({
      name: m[1],
      in: "path",
      required: true,
      schema: m[1] === "id" ? { type: "integer", minimum: 1 } : { type: "string" },
    });
  }
  return params;
}

function buildOpenApi(): Record<string, unknown> {
  const paths: Record<string, Record<string, unknown>> = {};
  const seen = new Set<string>();

  for (const [method, path, summary, tag, isPublic] of ROUTE_MANIFEST) {
    const key = `${method} ${path}`;
    if (seen.has(key)) throw new Error(`[openapi] duplicate manifest entry: ${key} (§7.2 is LOCKED)`);
    seen.add(key);

    const item = (paths[path] ??= {});
    const op: Record<string, unknown> = {
      tags: [tag],
      summary,
      responses: {
        "200": {
          description: "Success envelope { data, meta? }",
          content: { "application/json": { schema: { $ref: "#/components/schemas/SuccessEnvelope" } } },
        },
        ...(!isPublic
          ? {
              "401": { description: "UNAUTHORIZED — missing/invalid/expired/revoked credential" },
              "403": { description: "FORBIDDEN — insufficient scope/role" },
            }
          : {}),
      },
    };
    if (!isPublic) op.security = [{ bearerAuth: [] }, { cookieAuth: [] }];
    const params = pathParamsOf(path);
    if (params.length > 0) op.parameters = params;

    const bodySchema = REQUEST_BODY_SCHEMAS[key];
    if (bodySchema) {
      op.requestBody = {
        required: true,
        content: { "application/json": { schema: jsonSchemaOf(bodySchema) } },
      };
    }
    item[method.toLowerCase()] = op;
  }

  const usedTags = new Set(ROUTE_MANIFEST.map(([, , , tag]) => tag));
  const tags = Object.keys(TAG_DESCRIPTIONS)
    .filter((t) => usedTags.has(t))
    .map((t) => ({ name: t, description: TAG_DESCRIPTIONS[t] }));

  return {
    openapi: "3.1.0",
    info: {
      title: "Cryptsk Console API",
      version: "1.0.0",
      description:
        "Machine-facing REST API of the Cryptsk UTM/NGFW console (Phase 1). " +
        "Paths are the LOCKED §7.2 catalog of docs/00-PROJECT-MEMORY/PROJECT_MEMORY.md; " +
        "this artifact is generated from that route manifest (expand, never rename). " +
        "Human-readable documentation: docs/04-API/ENDPOINTS.md. Envelope: success " +
        "{ data, meta? }, error { error: { code, message, details? } }. Auth: session " +
        "cookie (cryptsk_token) or API key `Authorization: Bearer ck_…` (scopes read/write/admin).",
    },
    servers: [{ url: "/api/v1", description: "Console API v1 (path-segment versioning, LOCKED)" }],
    tags,
    paths,
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          description: "API key: `Authorization: Bearer ck_<prefix8>_<secret32>` (M11 §5.1)",
        },
        cookieAuth: {
          type: "apiKey",
          in: "cookie",
          name: "cryptsk_token",
          description: "Interactive session cookie (JWT, 8 h — ADR-007)",
        },
      },
      schemas: {
        SuccessEnvelope: {
          type: "object",
          properties: {
            data: {}, // resource-shaped; see ENDPOINTS.md per endpoint
            meta: {
              type: "object",
              properties: {
                page: { type: "integer" },
                limit: { type: "integer" },
                total: { type: "integer" },
                totalPages: { type: "integer" },
              },
            },
          },
          required: ["data"],
        },
        ErrorEnvelope: {
          type: "object",
          properties: {
            error: {
              type: "object",
              properties: {
                code: {
                  type: "string",
                  enum: ["VALIDATION_ERROR", "UNAUTHORIZED", "FORBIDDEN", "NOT_FOUND", "CONFLICT", "RATE_LIMITED", "INTERNAL"],
                },
                message: { type: "string" },
                details: {},
                requestId: { type: "string" },
              },
              required: ["code", "message"],
            },
          },
          required: ["error"],
        },
      },
    },
  };
}

/** Built once at module load; served cached by GET /api/v1/openapi.json. */
export const openApiSpec: Record<string, unknown> = buildOpenApi();
