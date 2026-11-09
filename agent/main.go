package main

// cryptsk-agent — the appliance/sensor data-plane agent (ADR-004, checklist
// deploy/AGENT_ADAPTER_CHECKLIST.md §Transport, LOCKED).
//
//   • listens on ${AGENT_LISTEN} (default :8080), POST-only JSON API
//   • auth: X-Agent-Auth must equal AGENT_SHARED_SECRET (constant-time compare;
//     the agent REFUSES to start without a secret — no unauthenticated plane)
//   • idempotency: X-Request-Id (ULID/UUID from the console) is logged, one
//     execution per request (all reads; probes are safe to repeat)
//   • envelope: { data } on success, { error:{ code, message } } on failure
//
// Endpoints (Phase-1 rows 1–2 + WAN probe of the rollout order):
//   POST /v1/engine/snapshot    { sinceLogSeq, sinceDnsSeq } → Snapshot
//   POST /v1/dashboard/summary  { tenantId }                 → host-plane subset
//   POST /v1/wan/probe          { iface }                    → { state }
//   GET  /healthz (unauthenticated liveness for pm2/systemd)
//
// NO FABRICATION POLICY (ADR-021): every value is measured on this host
// (/proc, sysfs, statfs, gateway TCP probes, Suricata eve.json, journald,
// unbound log). Sources that are absent yield honest emptiness — never zeros
// dressed up as data, never random fill.

import (
        "context"
        "crypto/subtle"
        "encoding/json"
        "fmt"
        "log"
        "net/http"
        "os"
        "path/filepath"
        "strings"
        "time"
)

// execTimeout — context with a deadline for outbound command execs.
func execTimeout(d time.Duration) (context.Context, context.CancelFunc) {
        return context.WithTimeout(context.Background(), d)
}

func envStr(key, def string) string {
        if v := strings.TrimSpace(os.Getenv(key)); v != "" {
                return v
        }
        return def
}

// extraWanIfaces — AGENT_WAN_IFACES=eth1,eth2 (policy-routing multi-WAN boxes
// whose WAN interfaces hold no 0.0.0.0/0 route in the main table).
func extraWanIfaces() []string {
        raw := strings.TrimSpace(os.Getenv("AGENT_WAN_IFACES"))
        if raw == "" {
                return nil
        }
        out := []string{}
        for _, f := range strings.Split(raw, ",") {
                if f = strings.TrimSpace(f); f != "" {
                        out = append(out, f)
                }
        }
        return out
}

// loadDotEnv — parse KEY=VALUE lines from <root>/.env without overriding
// variables that are already set in the environment (real env wins).
func loadDotEnv(root string) {
        f, err := os.Open(filepath.Join(root, ".env"))
        if err != nil {
                return
        }
        defer f.Close()
        sc := jsonDecoderlessScanner(f)
        for _, line := range sc {
                line = strings.TrimSpace(line)
                if line == "" || strings.HasPrefix(line, "#") {
                        continue
                }
                idx := strings.Index(line, "=")
                if idx <= 0 {
                        continue
                }
                key := strings.TrimSpace(line[:idx])
                val := strings.TrimSpace(line[idx+1:])
                val = strings.Trim(val, `"'`)
                if os.Getenv(key) == "" && key != "" {
                        os.Setenv(key, val)
                }
        }
}

func jsonDecoderlessScanner(f *os.File) []string {
        var lines []string
        buf := make([]byte, 0, 64*1024)
        tmp := make([]byte, 4096)
        for {
                n, err := f.Read(tmp)
                buf = append(buf, tmp[:n]...)
                if err != nil {
                        break
                }
        }
        for _, line := range strings.Split(string(buf), "\n") {
                lines = append(lines, line)
        }
        return lines
}

// authGuard — constant-time X-Agent-Auth check against AGENT_SHARED_SECRET.
func authGuard(secret string, next http.HandlerFunc) http.HandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) {
                got := r.Header.Get("X-Agent-Auth")
                if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(secret)) != 1 {
                        writeJSON(w, http.StatusUnauthorized, errEnvelope("UNAUTHORIZED", "missing or invalid X-Agent-Auth header"))
                        return
                }
                reqID := r.Header.Get("X-Request-Id")
                if reqID != "" {
                        log.Printf("%s %s request-id=%s", r.Method, r.URL.Path, reqID)
                }
                next(w, r)
        }
}

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(status)
        enc := json.NewEncoder(w)
        enc.SetEscapeHTML(false)
        _ = enc.Encode(body)
}

func readBody(r *http.Request, v interface{}) error {
        defer r.Body.Close()
        dec := json.NewDecoder(r.Body)
        return dec.Decode(v)
}

func main() {
        root, err := os.Getwd()
        if err != nil {
                root = "."
        }
        loadDotEnv(root)

        listen := envStr("AGENT_LISTEN", ":8080")
        secret := strings.TrimSpace(os.Getenv("AGENT_SHARED_SECRET"))
        if secret == "" {
                log.Fatalf("[agent] FATAL: AGENT_SHARED_SECRET is not set — refusing to serve an unauthenticated data plane")
        }

        c := NewCollector(root)
        stopCh := make(chan struct{})
        go c.Run(stopCh)

        mux := http.NewServeMux()

        mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
                writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "tick": c.tickNo})
        })

        mux.HandleFunc("/v1/engine/snapshot", authGuard(secret, func(w http.ResponseWriter, r *http.Request) {
                if r.Method != http.MethodPost {
                        writeJSON(w, http.StatusMethodNotAllowed, errEnvelope("METHOD_NOT_ALLOWED", "POST only"))
                        return
                }
                var req SnapshotRequest
                if err := readBody(r, &req); err != nil {
                        writeJSON(w, http.StatusBadRequest, errEnvelope("BAD_REQUEST", "invalid JSON body: "+err.Error()))
                        return
                }
                writeJSON(w, http.StatusOK, okEnvelope(c.Snapshot(req.SinceLogSeq, req.SinceDnsSeq)))
        }))

        mux.HandleFunc("/v1/dashboard/summary", authGuard(secret, func(w http.ResponseWriter, r *http.Request) {
                if r.Method != http.MethodPost {
                        writeJSON(w, http.StatusMethodNotAllowed, errEnvelope("METHOD_NOT_ALLOWED", "POST only"))
                        return
                }
                var req struct {
                        TenantID int `json:"tenantId"`
                }
                _ = readBody(r, &req) // tenantId accepted but the agent is tenant-blind
                writeJSON(w, http.StatusOK, okEnvelope(c.Dashboard()))
        }))

        mux.HandleFunc("/v1/wan/probe", authGuard(secret, func(w http.ResponseWriter, r *http.Request) {
                if r.Method != http.MethodPost {
                        writeJSON(w, http.StatusMethodNotAllowed, errEnvelope("METHOD_NOT_ALLOWED", "POST only"))
                        return
                }
                var req ProbeRequest
                if err := readBody(r, &req); err != nil || strings.TrimSpace(req.Iface) == "" {
                        writeJSON(w, http.StatusBadRequest, errEnvelope("VALIDATION_ERROR", "body must be {\"iface\":\"<name>\"}"))
                        return
                }
                iface := filepath.Base(strings.TrimSpace(req.Iface)) // path-traversal safe
                writeJSON(w, http.StatusOK, okEnvelope(ProbeResponse{State: c.ForceProbe(iface)}))
        }))

        srv := &http.Server{
                Addr:              listen,
                Handler:           mux,
                ReadHeaderTimeout: 5 * time.Second,
                ReadTimeout:       35 * time.Second, // > 30 s mutation window
                WriteTimeout:      35 * time.Second,
        }

        fmt.Printf("[agent] real data plane starting on %s (tick 2s) — point the console at it: AGENT_BASE_URL=http://<this-host>%s\n", listen, listen)
        if err := srv.ListenAndServe(); err != nil {
                log.Fatalf("[agent] server error: %v", err)
        }
}
