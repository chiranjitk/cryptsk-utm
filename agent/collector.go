package main

// Collector — the agent-side data plane. One goroutine ticks every 2 s
// (LOCKED cadence) and samples REAL host telemetry:
//   • every tick    : netdev deltas + CPU jiffies + meminfo + conntrack/tcp/udp
//   • every 5 ticks : WAN gateway probes + source tails (eve / journal / unbound)
//   • every 30 ticks: disk + thermal
// Rings mirror the console (metrics 500, logs 2000, dns 2000). Nothing is ever
// invented — sources that are missing simply produce nothing (ADR-021).

import (
        "net"
        "sync"
        "time"
)

const (
        tickMs        = 2000
        metricsCap    = 500
        logsCap       = 2000
        dnsCap        = 2000
        wanEvery      = 5
        sourcesEvery  = 5
        slowEvery     = 30
        probeTimeout  = 2500 * time.Millisecond
        probeUpMs     = 250 // < 250 ms → up, ≤ timeout → degraded (host tools.ts)
)

type Collector struct {
        mu sync.Mutex

        tickNo    int64
        logSeq    int64
        dnsSeq    int64
        startedAt time.Time

        metricsRing []MetricsTick
        logsRing    []LogRingEntry
        dnsRing     []DnsQueryLogEntry

        lastNetDev []NetDevSample
        lastCpu    CpuTimes
        hasCpu     bool

        diskPct float64
        tempC   float64

        tcpTotal      int
        tcpEstablished int
        udpEndpoints  int

        wanStates map[string]string // iface → up|degraded|down|unknown

        // tail offsets / source state
        evePath     string
        eveOffset   int64
        unboundPath string
        unboundOff  int64
        journalSince time.Time
        agentRoot   string
}

func NewCollector(agentRoot string) *Collector {
        c := &Collector{
                metricsRing:  []MetricsTick{},
                logsRing:     []LogRingEntry{},
                dnsRing:      []DnsQueryLogEntry{},
                wanStates:    map[string]string{},
                journalSince: time.Now().Add(-15 * time.Second),
                agentRoot:    agentRoot,
                startedAt:    time.Now(),
        }
        if p := envStr("SURICATA_EVE_PATH", "/var/log/suricata/eve.json"); p != "" {
                c.evePath = p
        }
        if p := envStr("UNBOUND_LOG_PATH", "/var/log/unbound/unbound.log"); p != "" {
                c.unboundPath = p
        }
        // seed sampler baselines so the first deltas are sane
        c.lastNetDev = readNetDev()
        c.lastCpu, c.hasCpu = readCpuTimes()
        c.diskPct = readDiskPct(c.agentRoot)
        c.tempC = readThermalC()
        return c
}

// Run drives the tick loop until stopCh closes.
func (c *Collector) Run(stopCh <-chan struct{}) {
        ticker := time.NewTicker(tickMs * time.Millisecond)
        defer ticker.Stop()
        c.sampleMetrics() // immediate first sample
        for {
                select {
                case <-stopCh:
                        return
                case <-ticker.C:
                        c.tickNo++
                        c.sampleMetrics()
                        if c.tickNo%wanEvery == 0 {
                                c.wanProbeStep()
                        }
                        if c.tickNo%sourcesEvery == 0 {
                                c.sourcesStep()
                        }
                        if c.tickNo%slowEvery == 0 {
                                c.slowStep()
                        }
                }
        }
}

func (c *Collector) sampleMetrics() {
        now := readNetDev()
        prev := map[string]NetDevSample{}
        for _, s := range c.lastNetDev {
                prev[s.Name] = s
        }
        dtSec := float64(tickMs) / 1000

        ifaces := []IfaceTick{}
        for _, s := range now {
                if s.Name == "lo" {
                        continue
                }
                var rxBps, txBps float64
                if p, ok := prev[s.Name]; ok {
                        if s.RxBytes >= p.RxBytes {
                                rxBps = float64(s.RxBytes-p.RxBytes) / dtSec
                        }
                        if s.TxBytes >= p.TxBytes {
                                txBps = float64(s.TxBytes-p.TxBytes) / dtSec
                        }
                }
                ifaces = append(ifaces, IfaceTick{
                        Name:   s.Name,
                        RxKbps: round1(rxBps * 8 / 100),
                        TxKbps: round1(txBps * 8 / 100),
                })
        }
        c.lastNetDev = now

        cpuPct := 0.0
        cpu, ok := readCpuTimes()
        if ok && c.hasCpu && cpu.Total > c.lastCpu.Total {
                idleDelta := float64(cpu.Idle) - float64(c.lastCpu.Idle)
                totalDelta := float64(cpu.Total) - float64(c.lastCpu.Total)
                if totalDelta > 0 {
                        cpuPct = round1((1 - idleDelta/totalDelta) * 100)
                }
        }
        c.lastCpu, c.hasCpu = cpu, ok

        memPct := 0.0
        if mem, ok := readMemInfo(); ok && mem.TotalBytes > 0 {
                memPct = round1((1 - float64(mem.AvailableBytes)/float64(mem.TotalBytes)) * 100)
        }

        conntrack := readConntrackCount()
        c.tcpTotal, c.tcpEstablished = readTcpSessions()
        c.udpEndpoints = readUdpEndpoints()
        if conntrack == 0 {
                conntrack = c.tcpEstablished // real fallback (host-collector semantics)
        }

        tick := MetricsTick{
                TS:            isoNow(),
                Ifaces:        ifaces,
                CPUPct:        cpuPct,
                MemPct:        memPct,
                ConntrackCnt:  conntrack,
        }
        if tick.Ifaces == nil {
                tick.Ifaces = []IfaceTick{}
        }

        c.mu.Lock()
        c.metricsRing = append(c.metricsRing, tick)
        if len(c.metricsRing) > metricsCap {
                c.metricsRing = c.metricsRing[len(c.metricsRing)-metricsCap:]
        }
        c.mu.Unlock()
}

// wanProbeStep — REAL gateway TCP :53 probes (carrier → gateway → connect).
func (c *Collector) wanProbeStep() {
        tracked := map[string]bool{}
        for _, iface := range defaultRouteIfaces() {
                tracked[iface] = true
        }
        for _, iface := range extraWanIfaces() {
                tracked[iface] = true
        }
        for iface := range tracked {
                state := probeGateway(iface)
                c.mu.Lock()
                c.wanStates[iface] = state
                c.mu.Unlock()
        }
}

// probeGateway mirrors src/lib/host/tools.ts probeGateway exactly.
func probeGateway(iface string) string {
        // carrier check
        if raw, err := readFirstLine("/sys/class/net/" + iface + "/carrier"); err == nil && raw == "0" {
                return "down" // carrier lost (link down)
        }
        gw := gatewayFor(iface)
        if gw == "" {
                return "down" // no default gateway on interface
        }
        started := time.Now()
        conn, err := net.DialTimeout("tcp", net.JoinHostPort(gw, "53"), probeTimeout)
        latency := time.Since(started).Milliseconds()
        if err != nil {
                // connection refused/timeout → degraded when the probe window elapsed,
                // down for immediate errors (mirrors the socket error semantics)
                if latency >= probeTimeout.Milliseconds()-50 {
                        return "degraded"
                }
                return "down"
        }
        conn.Close()
        if latency < probeUpMs {
                return "up"
        }
        return "degraded"
}

func (c *Collector) sourcesStep() {
        // Suricata eve.json
        if c.evePath != "" {
                if events := tailEve(c.evePath, &c.eveOffset); len(events) > 0 {
                        c.mu.Lock()
                        for _, e := range events {
                                c.logSeq++
                                c.logsRing = append(c.logsRing, LogRingEntry{Kind: "ips", Entry: e, Seq: c.logSeq})
                        }
                        if len(c.logsRing) > logsCap {
                                c.logsRing = c.logsRing[len(c.logsRing)-logsCap:]
                        }
                        c.mu.Unlock()
                }
        }
        // unbound query log
        if c.unboundPath != "" {
                if queries := tailUnbound(c.unboundPath, &c.unboundOff, c.nextDnsSeq); len(queries) > 0 {
                        c.mu.Lock()
                        c.dnsRing = append(c.dnsRing, queries...)
                        if len(c.dnsRing) > dnsCap {
                                c.dnsRing = c.dnsRing[len(c.dnsRing)-dnsCap:]
                        }
                        c.mu.Unlock()
                }
        }
        // nftables kernel logs via journalctl
        for _, line := range journalKernelLogs(c.journalSince) {
                if e := parseKernelFwLine(line); e != nil {
                        c.mu.Lock()
                        c.logSeq++
                        c.logsRing = append(c.logsRing, LogRingEntry{Kind: "firewall", Entry: *e, Seq: c.logSeq})
                        if len(c.logsRing) > logsCap {
                                c.logsRing = c.logsRing[len(c.logsRing)-logsCap:]
                        }
                        c.mu.Unlock()
                }
        }
        c.journalSince = time.Now().Add(-12 * time.Second)
}

func (c *Collector) slowStep() {
        c.diskPct = readDiskPct(c.agentRoot)
        c.tempC = readThermalC()
}

func (c *Collector) nextDnsSeq() int64 {
        c.mu.Lock()
        defer c.mu.Unlock()
        c.dnsSeq++
        return c.dnsSeq
}

// Snapshot builds the delta snapshot for the console's cursors.
func (c *Collector) Snapshot(sinceLogSeq, sinceDnsSeq int64) Snapshot {
        c.mu.Lock()
        defer c.mu.Unlock()

        s := Snapshot{
                TickNumber: int(c.tickNo),
                UptimeSec:  readUptimeSec(),
                Vitals: Vitals{
                        CPUPct:  c.latestCPU(),
                        MemPct:  c.latestMem(),
                        DiskPct: c.diskPct,
                        TempC:   c.tempC,
                },
        }
        if len(c.metricsRing) > 0 {
                latest := c.metricsRing[len(c.metricsRing)-1]
                s.MetricsTick = &latest
                hist := c.metricsRing
                if len(hist) > 70 {
                        hist = hist[len(hist)-70:]
                }
                s.MetricsHistory = append([]MetricsTick{}, hist...)
        }
        logs := []LogRingEntry{}
        for _, e := range c.logsRing {
                if e.Seq > sinceLogSeq {
                        logs = append(logs, e)
                }
        }
        if len(logs) > 0 {
                s.LogsTail = logs
        }
        dns := []DnsQueryLogEntry{}
        for _, q := range c.dnsRing {
                if q.Seq > sinceDnsSeq {
                        dns = append(dns, q)
                }
        }
        if len(dns) > 0 {
                s.DnsTail = dns
        }
        wans := []WanState{}
        for iface, state := range c.wanStates {
                wans = append(wans, WanState{Iface: iface, State: state})
        }
        if len(wans) > 0 {
                s.WanStates = wans
        }
        return s
}

// Dashboard — host-plane subset for the console merge (adapters/agent.ts).
func (c *Collector) Dashboard() DashboardSummary {
        c.mu.Lock()
        defer c.mu.Unlock()

        var d DashboardSummary
        d.Health.CPUPct = c.latestCPU()
        d.Health.MemPct = c.latestMem()
        d.Health.DiskPct = c.diskPct
        d.Health.TempC = c.tempC
        d.Health.UptimeSec = readUptimeSec()

        if len(c.metricsRing) > 0 {
                latest := c.metricsRing[len(c.metricsRing)-1]
                d.Throughput = &latest
                hist := c.metricsRing
                if len(hist) > 70 {
                        hist = hist[len(hist)-70:]
                }
                d.ThroughputHistory = append([]MetricsTick{}, hist...)
        } else {
                d.ThroughputHistory = []MetricsTick{}
        }
        d.Sessions.Active = c.tcpEstablished + c.udpEndpoints
        d.Sessions.ConntrackCount = 0
        if d.Throughput != nil {
                d.Sessions.ConntrackCount = d.Throughput.ConntrackCnt
        }
        d.WanStates = []WanState{}
        for iface, state := range c.wanStates {
                d.WanStates = append(d.WanStates, WanState{Iface: iface, State: state})
        }
        return d
}

// latestCPU / latestMem — vitals from the newest metrics tick (0 until first).
func (c *Collector) latestCPU() float64 {
        if len(c.metricsRing) == 0 {
                return 0
        }
        return c.metricsRing[len(c.metricsRing)-1].CPUPct
}

func (c *Collector) latestMem() float64 {
        if len(c.metricsRing) == 0 {
                return 0
        }
        return c.metricsRing[len(c.metricsRing)-1].MemPct
}

func (c *Collector) ForceProbe(iface string) string {
        state := probeGateway(iface)
        c.mu.Lock()
        c.wanStates[iface] = state
        c.mu.Unlock()
        return state
}
