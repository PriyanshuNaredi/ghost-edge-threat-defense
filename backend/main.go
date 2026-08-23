package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// Stats are the live counters exposed on /ghost/stats.
type Stats struct {
	Total     int64 `json:"total_requests"`
	Allowed   int64 `json:"allowed"`
	Blocked   int64 `json:"blocked"`
	Throttled int64 `json:"throttled"`
	Blacklist int64 `json:"blacklisted"`
}

var (
	stats       Stats
	startTime   = time.Now()
	hub         = NewHub()
	limiter     = NewRateLimiter(12, 4, 3, 45*time.Second) // 12 burst, 4/s refill, 3 strikes -> 45s blacklist
	blockThresh = 60.0
	warnThresh  = 35.0
)

// clientIP extracts the originating IP, honoring X-Forwarded-For so the simulator's
// distributed botnet IPs are respected by the rate limiter.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	if xri := r.Header.Get("X-Real-Ip"); xri != "" {
		return strings.TrimSpace(xri)
	}
	host := r.RemoteAddr
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		return host[:idx]
	}
	return host
}

// emit builds and broadcasts a structured security event.
func emit(ip, route string, threat ThreatType, score float64, action Action, payload string, conf float64, r *http.Request) {
	ev := SecurityEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		ClientIP:  ip,
		Route:     route,
		Threat:    threat,
		Score:     score,
		Action:    action,
		Payload:   payload,
		Conf:      conf,
	}
	if r != nil && action != ActionAllow {
		for k, v := range r.Header {
			if len(v) > 0 {
				ev.Headers = append(ev.Headers, [2]string{k, v[0]})
			}
			if len(ev.Headers) >= 12 {
				break
			}
		}
	}
	hub.Broadcast(ev)
}

// deny writes a JSON block response and records the event.
func deny(w http.ResponseWriter, r *http.Request, ip string, code int, threat ThreatType, score float64, action Action, payload string, conf float64) {
	atomic.AddInt64(&stats.Blocked, 1)
	if action == ActionBlacklist {
		atomic.AddInt64(&stats.Blacklist, 1)
	}
	emit(ip, r.URL.Path, threat, score, action, payload, conf, r)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Ghost-Action", string(action))
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{
		"status":      "blocked",
		"threat_type": threat,
		"score":       score,
		"action":      action,
		"payload":     payload,
		"confidence":  conf,
		"timestamp":   time.Now().UTC().Format(time.RFC3339Nano),
	})
}

// gateway is the WAF middleware in front of the upstream handler.
func gateway(upstream http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Control plane: stats + websocket endpoint bypass inspection.
		switch {
		case r.URL.Path == "/ghost/stats":
			writeStats(w)
			return
		case r.URL.Path == "/ws":
			hub.ServeWS(w, r)
			return
		case r.URL.Path == "/ghost/ping":
			w.Write([]byte("pong"))
			return
		}

		atomic.AddInt64(&stats.Total, 1)
		ip := clientIP(r)

		// 1. Blacklist gate.
		if limiter.IsBlacklisted(ip) {
			deny(w, r, ip, http.StatusForbidden, ThreatRate, 100, ActionBlacklist, "ip on temporary blacklist", 1.0)
			return
		}

		// 2. Leaky token bucket.
		allowed, nowBlacklisted := limiter.Allow(ip)
		if !allowed {
			if nowBlacklisted {
				deny(w, r, ip, http.StatusForbidden, ThreatRate, 100, ActionBlacklist, "rate limit strikes exhausted", 1.0)
			} else {
				atomic.AddInt64(&stats.Throttled, 1)
				emit(ip, r.URL.Path, ThreatRate, 88, ActionThrottle, "token bucket exhausted", 0.95, r)
				w.Header().Set("Retry-After", "1")
				w.Header().Set("X-Ghost-Action", "THROTTLE")
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(map[string]any{"status": "throttled", "action": "THROTTLE"})
			}
			return
		}

		// 3. Heuristic inspection (path + query + body).
		var body string
		if r.Body != nil && r.ContentLength > 0 && r.ContentLength < 1<<20 {
			raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err == nil {
				body = string(raw)
				r.Body = io.NopCloser(strings.NewReader(body)) // restore for upstream
			}
		}
		verdict := Inspect(r.Method, r.URL.Path, r.URL.RawQuery, body)

		// 4. Anomaly score: signature score + frequency factor.
		freq := limiter.RecentRate(ip)
		anomaly := verdict.Score + freq*1.5
		if anomaly > 100 {
			anomaly = 100
		}

		switch {
		case verdict.Score >= blockThresh || anomaly >= blockThresh+15:
			// Severe signature or compounding anomaly: drop and blacklist.
			limiter.Blacklist(ip)
			deny(w, r, ip, http.StatusForbidden, verdict.Threat, anomaly, ActionBlock, verdict.Payload, verdict.Confidence)
			return
		case verdict.Score >= warnThresh:
			// Suspicious but not conclusive: log loudly, still forward.
			emit(ip, r.URL.Path, verdict.Threat, anomaly, ActionAllow, verdict.Payload, verdict.Confidence, r)
		default:
			emit(ip, r.URL.Path, ThreatNone, anomaly, ActionAllow, "", 0, nil)
		}

		upstream.ServeHTTP(w, r)
	})
}

func writeStats(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"total_requests": atomic.LoadInt64(&stats.Total),
		"allowed":        atomic.LoadInt64(&stats.Allowed),
		"blocked":        atomic.LoadInt64(&stats.Blocked),
		"throttled":      atomic.LoadInt64(&stats.Throttled),
		"blacklisted":    atomic.LoadInt64(&stats.Blacklist),
		"uptime_seconds": int(time.Since(startTime).Seconds()),
		"ws_clients":     hub.Clients(),
	})
}

// upstreamEcho is the built-in "clean" upstream service the proxy forwards to.
func upstreamEcho() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&stats.Allowed, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream", "ghost-echo")
		json.NewEncoder(w).Encode(map[string]any{
			"service": "ghost-upstream-echo",
			"path":    r.URL.Path,
			"query":   r.URL.RawQuery,
			"method":  r.Method,
			"ip":      clientIP(r),
			"note":    "clean traffic forwarded by ghost gateway",
		})
	})
}

func main() {
	listen := flag.String("listen", ":8090", "gateway listen address")
	upstreamURL := flag.String("upstream", "", "upstream URL to proxy to (empty = built-in echo service)")
	noSim := flag.Bool("no-sim", false, "disable the built-in attack simulator")
	flag.Parse()

	var upstream http.Handler
	if *upstreamURL != "" {
		u, err := url.Parse(*upstreamURL)
		if err != nil {
			log.Fatalf("invalid upstream URL: %v", err)
		}
		upstream = httputil.NewSingleHostReverseProxy(u)
		log.Printf("[ghost] proxying clean traffic -> %s", u)
	} else {
		upstream = upstreamEcho()
		log.Printf("[ghost] no upstream configured: using built-in echo service")
	}

	if !*noSim {
		sim := NewSimulator("http://127.0.0.1" + portOf(*listen))
		go sim.Run()
		log.Printf("[ghost] attack simulator daemon: ACTIVE")
	} else {
		log.Printf("[ghost] attack simulator daemon: disabled")
	}

	go hub.keepalive()

	srv := &http.Server{
		Addr:         *listen,
		Handler:      gateway(upstream),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	log.Printf("[ghost] edge threat defense gateway listening on %s", *listen)
	log.Printf("[ghost] websocket telemetry: ws://localhost%s/ws", portOf(*listen))
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func portOf(listen string) string {
	if idx := strings.LastIndex(listen, ":"); idx >= 0 {
		return listen[idx:]
	}
	return ":8080"
}
