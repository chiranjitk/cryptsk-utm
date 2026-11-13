package main

// procfs/sysfs readers — REAL host data, no simulation (ADR-021).
// Mirrors src/lib/host/proc.ts exactly: same files, same fields, same
// honest-degradation semantics (missing file → zero value, never fabricated).

import (
        "math"
        "os"
        "path/filepath"
        "sort"
        "strconv"
        "strings"
        "syscall"
)

// NetDevSample — one /proc/net/dev line.
type NetDevSample struct {
        Name      string
        RxBytes   uint64
        RxPackets uint64
        RxErrors  uint64
        RxDrops   uint64
        TxBytes   uint64
        TxPackets uint64
        TxErrors  uint64
        TxDrops   uint64
}

func readNetDev() []NetDevSample {
        raw, err := os.ReadFile("/proc/net/dev")
        if err != nil {
                return nil
        }
        out := []NetDevSample{}
        lines := strings.Split(string(raw), "\n")
        for i, line := range lines {
                if i < 2 { // two header lines
                        continue
                }
                idx := strings.Index(line, ":")
                if idx < 0 {
                        continue
                }
                name := strings.TrimSpace(line[:idx])
                if name == "" {
                        continue
                }
                fields := strings.Fields(line[idx+1:])
                if len(fields) < 12 {
                        continue
                }
                // rx: bytes packets errs drop fifo frame compressed multicast
                // tx: bytes packets errs drop fifo colls carrier compressed
                out = append(out, NetDevSample{
                        Name:      name,
                        RxBytes:   parseU64(fields[0]),
                        RxPackets: parseU64(fields[1]),
                        RxErrors:  parseU64(fields[2]),
                        RxDrops:   parseU64(fields[3]),
                        TxBytes:   parseU64(fields[8]),
                        TxPackets: parseU64(fields[9]),
                        TxErrors:  parseU64(fields[10]),
                        TxDrops:   parseU64(fields[11]),
                })
        }
        return out
}

// CpuTimes — cumulative jiffies from /proc/stat "cpu " aggregate line.
type CpuTimes struct {
        Idle  uint64
        Total uint64
}

func readCpuTimes() (CpuTimes, bool) {
        raw, err := os.ReadFile("/proc/stat")
        if err != nil {
                return CpuTimes{}, false
        }
        for _, line := range strings.Split(string(raw), "\n") {
                if !strings.HasPrefix(line, "cpu ") {
                        continue
                }
                fields := strings.Fields(line)[1:]
                vals := make([]uint64, 0, len(fields))
                var total uint64
                for _, f := range fields {
                        v := parseU64(f)
                        vals = append(vals, v)
                        total += v
                }
                if len(vals) < 5 {
                        return CpuTimes{}, false
                }
                // user nice system idle iowait … → idle = idle + iowait
                return CpuTimes{Idle: vals[3] + vals[4], Total: total}, true
        }
        return CpuTimes{}, false
}

// MemInfo — /proc/meminfo total/available in bytes.
type MemInfo struct {
        TotalBytes     uint64
        AvailableBytes uint64
}

func readMemInfo() (MemInfo, bool) {
        raw, err := os.ReadFile("/proc/meminfo")
        if err != nil {
                return MemInfo{}, false
        }
        get := func(key string) uint64 {
                for _, line := range strings.Split(string(raw), "\n") {
                        if strings.HasPrefix(line, key+":") {
                                fields := strings.Fields(strings.TrimPrefix(line, key+":"))
                                if len(fields) >= 1 {
                                        return parseU64(fields[0]) * 1024
                                }
                        }
                }
                return 0
        }
        total := get("MemTotal")
        if total == 0 {
                return MemInfo{}, false
        }
        avail := get("MemAvailable")
        if avail == 0 {
                avail = get("MemFree")
        }
        return MemInfo{TotalBytes: total, AvailableBytes: avail}, true
}

// readDiskPct — statfs on the console data dir (mirrors readDiskUsage).
func readDiskPct(path string) float64 {
        var st syscall.Statfs_t
        if err := syscall.Statfs(path, &st); err != nil {
                return 0
        }
        total := st.Blocks * uint64(st.Bsize)
        free := st.Bavail * uint64(st.Bsize)
        if total == 0 {
                return 0
        }
        return round1((1 - float64(free)/float64(total)) * 100)
}

// readThermalC — first readable thermal zone (milli°C → °C); 0 when absent.
func readThermalC() float64 {
        entries, err := os.ReadDir("/sys/class/thermal")
        if err != nil {
                return 0
        }
        names := []string{}
        for _, e := range entries {
                if strings.HasPrefix(e.Name(), "thermal_zone") {
                        names = append(names, e.Name())
                }
        }
        sort.Strings(names)
        for _, z := range names {
                raw, err := os.ReadFile(filepath.Join("/sys/class/thermal", z, "temp"))
                if err != nil {
                        continue
                }
                milli := parseI64(strings.TrimSpace(string(raw)))
                if milli > 0 {
                        return round1(float64(milli) / 1000)
                }
        }
        return 0
}

// readConntrackCount — real nf_conntrack count; 0 when the entry is absent.
func readConntrackCount() int {
        raw, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_count")
        if err != nil {
                return 0
        }
        v := parseI64(strings.TrimSpace(string(raw)))
        if v > 0 {
                return int(v)
        }
        return 0
}

const tcpEstablished = 0x01

// readTcpSessions — /proc/net/tcp + tcp6 table counts.
func readTcpSessions() (total int, established int) {
        for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
                raw, err := os.ReadFile(f)
                if err != nil {
                        continue
                }
                lines := strings.Split(string(raw), "\n")
                for i, line := range lines {
                        if i == 0 {
                                continue // header
                        }
                        fields := strings.Fields(line)
                        if len(fields) < 4 {
                                continue
                        }
                        total++
                        if st, err := strconv.ParseUint(fields[3], 16, 32); err == nil && int(st) == tcpEstablished {
                                established++
                        }
                }
        }
        return total, established
}

// readUdpEndpoints — /proc/net/udp + udp6.
func readUdpEndpoints() int {
        total := 0
        for _, f := range []string{"/proc/net/udp", "/proc/net/udp6"} {
                raw, err := os.ReadFile(f)
                if err != nil {
                        continue
                }
                if n := len(strings.Split(string(raw), "\n")); n > 1 {
                        total += n - 1
                }
        }
        return total
}

// readUptimeSec — /proc/uptime (real host uptime, not process uptime).
func readUptimeSec() int64 {
        raw, err := os.ReadFile("/proc/uptime")
        if err != nil {
                return 0
        }
        fields := strings.Fields(string(raw))
        if len(fields) == 0 {
                return 0
        }
        f, err := strconv.ParseFloat(fields[0], 64)
        if err != nil {
                return 0
        }
        return int64(f)
}

// defaultRouteIfaces — every interface holding a 0.0.0.0/0 route (v4).
// These are the WAN candidates the agent probes honestly.
func defaultRouteIfaces() []string {
        raw, err := os.ReadFile("/proc/net/route")
        if err != nil {
                return nil
        }
        seen := map[string]bool{}
        out := []string{}
        lines := strings.Split(string(raw), "\n")
        for i, line := range lines {
                if i == 0 {
                        continue
                }
                fields := strings.Fields(line)
                if len(fields) >= 8 && fields[1] == "00000000" && !seen[fields[0]] {
                        seen[fields[0]] = true
                        out = append(out, fields[0])
                }
        }
        return out
}

// gatewayFor — default gateway of one interface, decoded from /proc/net/route
// (gateway hex is little-endian: "0100A8C0" → 192.168.0.1). Empty when none.
func gatewayFor(iface string) string {
        raw, err := os.ReadFile("/proc/net/route")
        if err != nil {
                return ""
        }
        lines := strings.Split(string(raw), "\n")
        for i, line := range lines {
                if i == 0 {
                        continue
                }
                fields := strings.Fields(line)
                if len(fields) >= 3 && fields[0] == iface && fields[1] == "00000000" {
                        return decodeHexIP(fields[2])
                }
        }
        return ""
}

func decodeHexIP(hex string) string {
        if len(hex) != 8 {
                return ""
        }
        b := make([]byte, 4)
        for i := 0; i < 4; i++ {
                v, err := strconv.ParseUint(hex[i*2:i*2+2], 16, 8)
                if err != nil {
                        return ""
                }
                b[i] = byte(v)
        }
        // little-endian → reverse bytes
        return strconv.Itoa(int(b[3])) + "." + strconv.Itoa(int(b[2])) + "." + strconv.Itoa(int(b[1])) + "." + strconv.Itoa(int(b[0]))
}

// readFirstLine — first line of a small sysfs file, trimmed.
func readFirstLine(path string) (string, error) {
        raw, err := os.ReadFile(path)
        if err != nil {
                return "", err
        }
        return strings.TrimSpace(strings.SplitN(string(raw), "\n", 2)[0]), nil
}

// ── number helpers ───────────────────────────────────────────────────────────

func parseU64(s string) uint64 {
        v, err := strconv.ParseUint(s, 10, 64)
        if err != nil {
                return 0
        }
        return v
}

func parseI64(s string) int64 {
        v, err := strconv.ParseInt(s, 10, 64)
        if err != nil {
                return 0
        }
        return v
}

func round1(f float64) float64 {
        return math.Round(f*10) / 10 // same semantics as JS Math.round(x*10)/10
}
