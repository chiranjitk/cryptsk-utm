package main

// Real log-source tailers (ADR-021) — same sources and parse rules as
// src/lib/engine/host-collector.ts:
//   • Suricata eve.json        → IpsEventEntry   (kind "ips")
//   • nftables kernel logs     → FirewallLogEntry (kind "firewall") via journalctl -k
//   • unbound query log        → DnsQueryLogEntry
// Every source degrades to honest emptiness when the file/binary is missing.
// Sequence numbers are agent-side monotonic counters (the console tracks its
// own cursors sinceLogSeq / sinceDnsSeq and only persists what it has not seen).

import (
        "bufio"
        "encoding/json"
        "os"
        "os/exec"
        "regexp"
        "strconv"
        "strings"
        "time"
)

// ── Suricata eve.json ────────────────────────────────────────────────────────

type eveAlert struct {
        Timestamp string `json:"timestamp"`
        EventType string `json:"event_type"`
        SrcIP     string `json:"src_ip"`
        SrcPort   int    `json:"src_port"`
        DstIP     string `json:"dest_ip"`
        DstPort   int    `json:"dest_port"`
        Proto     string `json:"proto"`
        Alert     *struct {
                Severity   int    `json:"severity"`
                SignatureID int   `json:"signature_id"`
                Category   string `json:"category"`
                Signature  string `json:"signature"`
                Action     string `json:"action"`
        } `json:"alert"`
}

// tailEve reads new bytes of eve.json past *offset (rotation-aware) and
// returns parsed IPS entries. Never fabricates: bad lines are skipped.
func tailEve(path string, offset *int64) []IpsEventEntry {
        st, err := os.Stat(path)
        if err != nil {
                *offset = 0
                return nil
        }
        size := st.Size()
        if size < *offset { // log rotated / truncated
                *offset = 0
        }
        if size == *offset {
                return nil
        }
        f, err := os.Open(path)
        if err != nil {
                return nil
        }
        defer f.Close()

        readLen := size - *offset
        const maxRead = int64(4 * 1024 * 1024)
        if readLen > maxRead {
                *offset = size - maxRead
                readLen = maxRead
        }
        buf := make([]byte, readLen)
        if _, err := f.ReadAt(buf, *offset); err != nil {
                return nil
        }
        *offset = size

        out := []IpsEventEntry{}
        for _, line := range strings.Split(string(buf), "\n") {
                if strings.TrimSpace(line) == "" {
                        continue
                }
                if e := parseEveAlert(line); e != nil {
                        out = append(out, *e)
                }
        }
        return out
}

func parseEveAlert(line string) *IpsEventEntry {
        var j eveAlert
        if err := json.Unmarshal([]byte(line), &j); err != nil {
                return nil
        }
        if j.EventType != "alert" || j.Alert == nil {
                return nil
        }
        sev := j.Alert.Severity
        if sev == 0 {
                sev = 8
        }
        severity := "info"
        switch {
        case sev <= 2:
                severity = "critical"
        case sev <= 4:
                severity = "high"
        case sev <= 6:
                severity = "medium"
        case sev <= 8:
                severity = "low"
        }
        action := "allowed"
        if j.Alert.Action == "blocked" {
                action = "blocked"
        }
        ts := j.Timestamp
        if ts == "" {
                ts = isoNow()
        }
        e := &IpsEventEntry{TS: ts, Action: action, Severity: severity}
        if j.SrcIP != "" {
                e.SrcIP = strPtr(j.SrcIP)
        }
        if j.DstIP != "" {
                e.DstIP = strPtr(j.DstIP)
        }
        if j.SrcPort > 0 {
                e.SrcPort = intPtr(j.SrcPort)
        }
        if j.DstPort > 0 {
                e.DstPort = intPtr(j.DstPort)
        }
        if j.Alert.SignatureID != 0 {
                e.SID = strPtr(strconv.Itoa(j.Alert.SignatureID))
        }
        if j.Alert.Category != "" {
                e.Category = strPtr(j.Alert.Category)
        }
        if j.Alert.Signature != "" {
                e.Message = strPtr(j.Alert.Signature)
        }
        return e
}

// ── nftables kernel logs (journalctl) ────────────────────────────────────────

var (
        fwKeyRe   = regexp.MustCompile(`(?:^|\s)(SRC|DST|PROTO|SPT|DPT)=([^\s]+)`)
        fwRuleRe  = regexp.MustCompile(`([A-Za-z0-9_-]+)\[([A-Za-z0-9_-]+)\]`)
)

// journalKernelLogs runs `journalctl -k -o cat --since <since>` and returns
// parsed nftables log lines. Empty (not fabricated) when journalctl is absent.
func journalKernelLogs(since time.Time) []string {
        if _, err := exec.LookPath("journalctl"); err != nil {
                return nil
        }
        formatted := since.UTC().Format("2006-01-02 15:04:05")
        ctx, cancel := execTimeout(8 * time.Second)
        defer cancel()
        cmd := exec.CommandContext(ctx, "sh", "-c",
                `journalctl -k -o cat --since "`+formatted+`" 2>/dev/null | head -400`)
        out, err := cmd.Output()
        if err != nil {
                return nil
        }
        lines := []string{}
        sc := bufio.NewScanner(strings.NewReader(string(out)))
        sc.Buffer(make([]byte, 64*1024), 1024*1024)
        for sc.Scan() {
                line := sc.Text()
                if strings.Contains(line, "IN=") || strings.Contains(line, "OUT=") {
                        lines = append(lines, line)
                }
        }
        return lines
}

// parseKernelFwLine — mirrors host-collector.parseKernelFwLine.
func parseKernelFwLine(line string) *FirewallLogEntry {
        get := func(key string) string {
                for _, m := range fwKeyRe.FindAllStringSubmatch(line, -1) {
                        if m[1] == key {
                                return m[2]
                        }
                }
                return ""
        }
        srcIP, dstIP := get("SRC"), get("DST")
        if srcIP == "" || dstIP == "" {
                return nil
        }
        protoRaw := strings.ToUpper(get("PROTO"))
        if protoRaw == "" {
                protoRaw = "UDP"
        }
        protocol := strings.ToLower(protoRaw)
        switch protocol {
        case "tcp", "udp", "icmp":
        default:
                protocol = strings.ToLower(protoRaw)
        }

        prefix := ""
        if idx := strings.Index(line, " IN="); idx >= 0 {
                prefix = strings.TrimSpace(line[:idx])
        }
        var ruleName *string
        actionStr := "deny"
        if m := fwRuleRe.FindStringSubmatch(prefix); m != nil {
                r := m[1]
                ruleName = &r
                actionStr = strings.ToLower(m[2])
        }

        e := &FirewallLogEntry{
                TS:       isoNow(),
                SrcIP:    srcIP,
                DstIP:    dstIP,
                Protocol: protocol,
                Action:   actionStr,
                RuleName: ruleName,
                Bytes:    0,
                Packets:  1,
        }
        if p := parseI64(get("SPT")); p > 0 && p < 65536 {
                e.SrcPort = int(p)
        }
        if p := parseI64(get("DPT")); p > 0 && p < 65536 {
                e.DstPort = int(p)
        }
        return e
}

// ── unbound query log ────────────────────────────────────────────────────────

var unboundRe = regexp.MustCompile(`info:\s+(\d+\.\d+\.\d+\.\d+)\s+query\s+(\S+)\s+(\S+?\.?)\s+IN`)

// tailUnbound reads new bytes of the unbound query log past *offset and
// returns parsed DnsQueryLogEntry rows (agent-side monotonic seq).
func tailUnbound(path string, offset *int64, nextSeq func() int64) []DnsQueryLogEntry {
        st, err := os.Stat(path)
        if err != nil {
                *offset = 0
                return nil
        }
        size := st.Size()
        if size < *offset {
                *offset = 0
        }
        if size == *offset {
                return nil
        }
        f, err := os.Open(path)
        if err != nil {
                return nil
        }
        defer f.Close()

        readLen := size - *offset
        const maxRead = int64(2 * 1024 * 1024)
        if readLen > maxRead {
                *offset = size - maxRead
                readLen = maxRead
        }
        buf := make([]byte, readLen)
        if _, err := f.ReadAt(buf, *offset); err != nil {
                return nil
        }
        *offset = size

        out := []DnsQueryLogEntry{}
        for _, line := range strings.Split(string(buf), "\n") {
                m := unboundRe.FindStringSubmatch(line)
                if m == nil {
                        continue
                }
                domain := strings.TrimSuffix(m[3], ".")
                out = append(out, DnsQueryLogEntry{
                        Seq:       nextSeq(),
                        TS:        isoNow(),
                        ClientIP:  m[1],
                        Domain:    domain,
                        QType:     m[2],
                        Action:    "allowed",
                        Blocked:   false,
                        Category:  nil,
                        LatencyMs: 0,
                })
        }
        return out
}

// ── small helpers ────────────────────────────────────────────────────────────

func strPtr(s string) *string    { return &s }
func intPtr(i int) *int          { return &i }
