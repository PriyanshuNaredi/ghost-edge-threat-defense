package main

import (
	"math"
	"net/url"
	"strings"
)

// ThreatType enumerates the classes of threats the rule engine can detect.
type ThreatType string

const (
	ThreatNone      ThreatType = "NONE"
	ThreatSQLi      ThreatType = "SQL_INJECTION"
	ThreatXSS       ThreatType = "XSS"
	ThreatTraversal ThreatType = "PATH_TRAVERSAL"
	ThreatRate      ThreatType = "RATE_LIMIT"
	ThreatAnomaly   ThreatType = "ANOMALY"
)

// Action enumerates the enforcement decisions the gateway can take.
type Action string

const (
	ActionAllow     Action = "ALLOW"
	ActionBlock     Action = "BLOCK"
	ActionThrottle  Action = "THROTTLE"
	ActionBlacklist Action = "BLACKLIST"
)

// Rule is a single signature: a lowercase substring matcher with a severity weight.
// Weights are tuned so a single "severe" signature crosses the block threshold,
// while "moderate" signatures require corroboration (multiple matches or entropy).
type Rule struct {
	Pattern string
	Threat  ThreatType
	Weight  float64
}

var sqliRules = []Rule{
	{"' or 1=1", ThreatSQLi, 78},
	{"' or '1'='1", ThreatSQLi, 78},
	{"or 1=1--", ThreatSQLi, 75},
	{"union select", ThreatSQLi, 76},
	{"union all select", ThreatSQLi, 76},
	{"drop table", ThreatSQLi, 78},
	{"insert into", ThreatSQLi, 55},
	{"delete from", ThreatSQLi, 55},
	{"xp_cmdshell", ThreatSQLi, 80},
	{"waitfor delay", ThreatSQLi, 70},
	{"sleep(", ThreatSQLi, 68},
	{"benchmark(", ThreatSQLi, 68},
	{"information_schema", ThreatSQLi, 62},
	{"group_concat(", ThreatSQLi, 55},
	{"select * from", ThreatSQLi, 45},
	{"admin'--", ThreatSQLi, 70},
	{"' or ''='", ThreatSQLi, 72},
	{";--", ThreatSQLi, 38},
	{"concat(", ThreatSQLi, 32},
	{"update set", ThreatSQLi, 34},
}

var xssRules = []Rule{
	{"<script", ThreatXSS, 74},
	{"</script", ThreatXSS, 70},
	{"javascript:", ThreatXSS, 72},
	{"onerror=", ThreatXSS, 70},
	{"onload=", ThreatXSS, 68},
	{"onclick=", ThreatXSS, 55},
	{"onmouseover=", ThreatXSS, 55},
	{"<svg", ThreatXSS, 60},
	{"<iframe", ThreatXSS, 62},
	{"<img src=x", ThreatXSS, 64},
	{"document.cookie", ThreatXSS, 66},
	{"eval(", ThreatXSS, 48},
	{"expression(", ThreatXSS, 52},
	{"vbscript:", ThreatXSS, 60},
	{"srcdoc=", ThreatXSS, 45},
	{"alert(", ThreatXSS, 34},
}

var traversalRules = []Rule{
	{"../", ThreatTraversal, 70},
	{"..\\", ThreatTraversal, 70},
	{"..%2f", ThreatTraversal, 68},
	{"%2e%2e", ThreatTraversal, 66},
	{"..%252f", ThreatTraversal, 70},
	{"....//", ThreatTraversal, 68},
	{"/etc/passwd", ThreatTraversal, 78},
	{"/etc/shadow", ThreatTraversal, 78},
	{"c:\\windows", ThreatTraversal, 70},
	{"c:/windows", ThreatTraversal, 70},
	{"win.ini", ThreatTraversal, 62},
	{"boot.ini", ThreatTraversal, 62},
	{"/proc/self", ThreatTraversal, 66},
	{"system32", ThreatTraversal, 48},
}

// Verdict is the outcome of heuristic inspection for a single request.
type Verdict struct {
	Threat     ThreatType
	Score      float64
	Payload    string
	Confidence float64
	Matched    []string
}

func allRules() []Rule {
	out := make([]Rule, 0, len(sqliRules)+len(xssRules)+len(traversalRules))
	out = append(out, sqliRules...)
	out = append(out, xssRules...)
	out = append(out, traversalRules...)
	return out
}

// buildSurface assembles the full inspection surface from path, query and body.
func buildSurface(path, rawQuery, body string) string {
	var sb strings.Builder
	sb.WriteString(path)
	if rawQuery != "" {
		sb.WriteByte('?')
		if dec, err := url.QueryUnescape(rawQuery); err == nil {
			sb.WriteString(dec)
		} else {
			sb.WriteString(rawQuery)
		}
	}
	if body != "" {
		sb.WriteByte('\n')
		sb.WriteString(body)
	}
	return sb.String()
}

// shannonEntropy returns bits-per-character entropy of the input. High entropy
// often indicates obfuscated/encoded payloads (base64 blobs, hex, random tokens).
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}
	var ent float64
	n := float64(len(s))
	for _, c := range freq {
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	return ent
}

// extractContext returns a snippet of the surface surrounding the matched pattern,
// used by the dashboard's Intercept Inspector to highlight the flagged payload.
func extractContext(surface, pattern string) string {
	idx := strings.Index(strings.ToLower(surface), pattern)
	if idx < 0 {
		return pattern
	}
	start := idx - 24
	if start < 0 {
		start = 0
	}
	end := idx + len(pattern) + 24
	if end > len(surface) {
		end = len(surface)
	}
	return surface[start:end]
}

// Inspect runs the signature engine plus entropy heuristic over the request surface
// and returns a Verdict with a cumulative anomaly score in [0, 100].
func Inspect(method, path, rawQuery, body string) Verdict {
	surface := buildSurface(path, rawQuery, body)
	lower := strings.ToLower(surface)
	decoded := lower
	if dec, err := url.QueryUnescape(lower); err == nil {
		decoded = dec
	}

	v := Verdict{Threat: ThreatNone}
	var total float64
	var bestWeight float64

	for _, rule := range allRules() {
		if strings.Contains(decoded, rule.Pattern) || strings.Contains(lower, rule.Pattern) {
			total += rule.Weight
			v.Matched = append(v.Matched, rule.Pattern)
			if rule.Weight >= bestWeight {
				bestWeight = rule.Weight
				v.Threat = rule.Threat
				v.Payload = extractContext(surface, rule.Pattern)
			}
		}
	}

	// Entropy heuristic: normal prose/URLs sit around 3.5-4.5 bits/char.
	// Obfuscated payloads push higher; add a scaled bonus above 4.5.
	if ent := shannonEntropy(surface); ent > 4.5 {
		total += (ent - 4.5) * 8
	}

	if total > 100 {
		total = 100
	}
	v.Score = total
	if len(v.Matched) > 0 {
		v.Confidence = math.Min(0.99, 0.35+total/120.0)
	}
	return v
}
