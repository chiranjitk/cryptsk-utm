package main

// Wire types — MUST match the console contracts byte-for-byte in JSON shape:
//   • snapshot:  src/lib/engine/agent-engine.ts  (AgentSnapshot)
//   • dashboard: src/lib/adapters/agent.ts       (host-plane subset)
//   • metrics:   src/lib/engine/events.ts        (MetricsTick)
//   • log rows:  src/lib/engine/events.ts        (FirewallLogEntry / IpsEventEntry)
//   • dns rows:  src/lib/engine/generators/dns-queries.ts (DnsQueryLogEntry)
// Field names are LOCKED (deploy/AGENT_ADAPTER_CHECKLIST.md §Transport).

import "time"

// MetricsTick — one 2 s sample (events.ts MetricsTick).
type MetricsTick struct {
	TS            string      `json:"ts"`
	Ifaces        []IfaceTick `json:"ifaces"`
	CPUPct        float64     `json:"cpuPct"`
	MemPct        float64     `json:"memPct"`
	ConntrackCnt  int         `json:"conntrackCount"`
}

type IfaceTick struct {
	Name  string  `json:"name"`
	RxKbps float64 `json:"rxKbps"`
	TxKbps float64 `json:"txKbps"`
}

// Vitals — system health numbers (agent-engine.ts AgentVitals).
type Vitals struct {
	CPUPct  float64 `json:"cpuPct"`
	MemPct  float64 `json:"memPct"`
	DiskPct float64 `json:"diskPct"`
	TempC   float64 `json:"tempC"`
}

// WanState — probe state for one tracked interface.
type WanState struct {
	Iface string `json:"iface"`
	State string `json:"state"` // up | degraded | down | unknown
}

// FirewallLogEntry — events.ts FirewallLogEntry (nullable strings for rule/app/user).
type FirewallLogEntry struct {
	TS       string  `json:"ts"`
	SrcIP    string  `json:"srcIp"`
	DstIP    string  `json:"dstIp"`
	SrcPort  int     `json:"srcPort"`
	DstPort  int     `json:"dstPort"`
	Protocol string  `json:"protocol"`
	Action   string  `json:"action"`
	RuleName *string `json:"ruleName"`
	AppName  *string `json:"appName"`
	Bytes    int64   `json:"bytes"`
	Packets  int64   `json:"packets"`
	UserName *string `json:"userName"`
}

// IpsEventEntry — events.ts IpsEventEntry.
type IpsEventEntry struct {
	TS       string  `json:"ts"`
	SrcIP    *string `json:"srcIp"`
	SrcPort  *int    `json:"srcPort"`
	DstIP    *string `json:"dstIp"`
	DstPort  *int    `json:"dstPort"`
	Action   string  `json:"action"`
	SID      *string `json:"sid"`
	Severity string  `json:"severity"`
	Category *string `json:"category"`
	Message  *string `json:"message"`
}

// DnsQueryLogEntry — dns-queries.ts DnsQueryLogEntry.
type DnsQueryLogEntry struct {
	Seq       int64   `json:"seq"`
	TS        string  `json:"ts"`
	ClientIP  string  `json:"clientIp"`
	Domain    string  `json:"domain"`
	QType     string  `json:"qtype"`
	Action    string  `json:"action"` // allowed | sinkhole | nxdomain
	Blocked   bool    `json:"blocked"`
	Category  *string `json:"category"`
	LatencyMs int     `json:"latencyMs"`
}

// LogRingEntry — mock-engine.ts LogRingEntry { kind, entry, seq }.
// Entry is either FirewallLogEntry or IpsEventEntry (kind discriminates).
type LogRingEntry struct {
	Kind  string      `json:"kind"` // firewall | ips
	Entry interface{} `json:"entry"`
	Seq   int64       `json:"seq"`
}

// Snapshot — POST /v1/engine/snapshot response (agent-engine.ts AgentSnapshot).
type Snapshot struct {
	TickNumber     int              `json:"tickNumber"`
	UptimeSec      int64            `json:"uptimeSec"`
	Vitals         Vitals           `json:"vitals"`
	MetricsTick    *MetricsTick     `json:"metricsTick,omitempty"`
	MetricsHistory []MetricsTick    `json:"metricsHistory,omitempty"`
	LogsTail       []LogRingEntry   `json:"logsTail,omitempty"`
	DnsTail        []DnsQueryLogEntry `json:"dnsTail,omitempty"`
	WanStates      []WanState       `json:"wanStates,omitempty"`
}

// DashboardSummary — POST /v1/dashboard/summary HOST-PLANE SUBSET only.
// The console merges its own DB aggregates (alerts24h, topApps, topTalkers,
// vpnStatus, recentThreats, wanPolicies) — the agent is stateless by design.
type DashboardSummary struct {
	Health struct {
		CPUPct    float64 `json:"cpuPct"`
		MemPct    float64 `json:"memPct"`
		DiskPct   float64 `json:"diskPct"`
		TempC     float64 `json:"tempC"`
		UptimeSec int64   `json:"uptimeSec"`
	} `json:"health"`
	Throughput       *MetricsTick `json:"throughput"`
	ThroughputHistory []MetricsTick `json:"throughputHistory"`
	Sessions         struct {
		Active         int `json:"active"`
		ConntrackCount int `json:"conntrackCount"`
	} `json:"sessions"`
	WanStates []WanState `json:"wanStates"`
}

// ProbeRequest / ProbeResponse — POST /v1/wan/probe.
type ProbeRequest struct {
	Iface string `json:"iface"`
}
type ProbeResponse struct {
	State string `json:"state"` // up | degraded | down | unknown | "" (untracked)
}

// SnapshotRequest — console cursor state for delta tails.
type SnapshotRequest struct {
	SinceLogSeq int64 `json:"sinceLogSeq"`
	SinceDnsSeq int64 `json:"sinceDnsSeq"`
}

// envelope helpers (console contract: { data } / { error:{code,message} })
func okEnvelope(v interface{}) map[string]interface{} {
	return map[string]interface{}{"data": v}
}

func errEnvelope(code, message string) map[string]interface{} {
	return map[string]interface{}{"error": map[string]string{"code": code, "message": message}}
}

func isoNow() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00")
}
