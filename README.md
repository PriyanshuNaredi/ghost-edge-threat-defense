# GHOST — Edge Threat Defense & WAF Interceptor

An intelligent API gateway and Web Application Firewall that intercepts live
(simulated) cyber attacks, applies per-IP token-bucket rate limiting with
dynamic blacklisting, scores request anomalies via signature matching and
Shannon entropy, and streams every decision to a real-time cyber command deck.

```
┌──────────────┐     ┌─────────────────────────────────────────┐     ┌──────────────┐
│   Simulated  │     │              GHOST GATEWAY              │     │   Upstream   │
│ botnet/attack│────▶│  ┌───────────┐  ┌────────────────────┐  │────▶│  echo service│
│   clients    │     │  │ blacklist │─▶│ rule engine (WAF)  │  │     │  (or your own│
└──────────────┘     │  │  gate     │  │ SQLi/XSS/traversal │  │     │  -upstream)  │
                     │  └───────────┘  └─────────┬──────────┘  │     └──────────────┘
┌──────────────┐     │  ┌────────────────────┐   │ anomaly score│
│  React HUD   │◀────│─▶│ leaky token bucket │◀──┘ + entropy    │
│ (Threat Map) │ ws  │  └────────────────────┘                │
└──────────────┘     └─────────────────────────────────────────┘
```

---

## Phase 1 — Go Reverse Proxy & Threat Detection Engine

**Zero external dependencies** — pure Go standard library, including a
hand-crafted RFC 6455 WebSocket server. Builds fully offline.

| File | Responsibility |
|---|---|
| `backend/main.go` | Gateway middleware chain (blacklist → rate limit → inspect → score → proxy/block), control plane, built-in upstream echo |
| `backend/rules.go` | Signature engine (SQLi/XSS/path traversal), Shannon entropy heuristic, anomaly scoring, verdicts |
| `backend/ratelimit.go` | Leaky token bucket per IP, strike system, dynamic blacklisting with expiry, janitor loop |
| `backend/simulator.go` | Background attack daemon: benign baseline, injection probes, distributed botnet spikes |
| `backend/ws.go` | RFC 6455 WebSocket hub broadcasting structured security events |

### Inspection pipeline (per request)

1. **Blacklist gate** — IPs on the temporary blacklist are dropped instantly (403).
2. **Leaky token bucket** — burst 12 tokens, 4 tokens/s refill. Exhaustion →
   429 THROTTLE; 3 strikes → 45 s dynamic blacklist (403 BLACKLIST).
3. **Signature inspection** — 50+ weighted signatures across SQLi, XSS, and
   path traversal (URL-decoded surface: path + query + body).
4. **Anomaly scoring** — `score = Σ signature weights + (entropy − 4.5) × 8 + rps × 1.5`
   (clamped 0–100). Score ≥ 60 → BLOCK (+ blacklist); ≥ 35 → flagged but forwarded.
5. **Forward** — clean traffic is proxied upstream (built-in echo, or `-upstream`).

### Security event wire format

Broadcast over WebSocket as JSON (`[timestamp, client_ip, route, threat_type, score, action_taken]`):

```json
{
  "timestamp": "2026-08-21T20:04:21.9004827Z",
  "client_ip": "203.0.113.7",
  "route": "/api/login",
  "threat_type": "SQL_INJECTION",
  "score": 100,
  "action_taken": "BLOCK",
  "payload": "/api/login?user=admin' OR 1=1--",
  "confidence": 0.99,
  "headers": [["User-Agent", "curl/8.9.0"], ["X-Forwarded-For", "203.0.113.7"]]
}
```

### Setup

```bash
cd backend
go build -o ghost.exe .        # or: ./scripts/run.sh
./ghost.exe                    # listens on :8090, simulator ON
```

Flags: `-listen :8090` · `-upstream http://my-service:3000` · `-no-sim`

### Verification (curl)

```bash
# 1. Clean traffic → forwarded to upstream echo (200)
curl -s -H "X-Forwarded-For: 10.0.1.50" http://127.0.0.1:8090/api/products

# 2. SQL injection → 403 BLOCK, SQL_INJECTION
curl -s -H "X-Forwarded-For: 203.0.113.7" \
  "http://127.0.0.1:8090/api/login?user=admin%27%20OR%201%3D1--&pass=x"

# 3. XSS → 403 BLOCK, XSS
curl -s -H "X-Forwarded-For: 198.51.100.9" \
  "http://127.0.0.1:8090/api/comments?body=%3Cscript%3Ealert(document.cookie)%3C/script%3E"

# 4. Path traversal → 403 BLOCK, PATH_TRAVERSAL
curl -s -H "X-Forwarded-For: 192.0.2.44" --path-as-is \
  "http://127.0.0.1:8090/static/../../../../etc/passwd"

# 5. Flood one IP → 429 THROTTLE ×3 → 403 BLACKLIST
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code} " \
    -H "X-Forwarded-For: 172.16.99.99" http://127.0.0.1:8090/api/feed
done   # → 200 ×17, 429 ×2, 403

# 6. Live telemetry stream
curl -s http://127.0.0.1:8090/ghost/stats
```

Or run everything at once: `bash backend/scripts/verify.sh`

---

## Phase 2 — React Cyber Threat Map & Live Intercept HUD

Minimalist radar command deck: deep slate `#0a0e17`, cyan data streams,
amber warnings, red block notifications.

| Component | Role |
|---|---|
| `ThreatGauge.tsx` | Glowing 270° SVG threat gauge (cyan→amber→red) + canvas particle burst on every dropped request |
| `TrafficGrid.tsx` | Real-time request distribution heat-grid per route |
| `EventFeed.tsx` | Live intercept feed with framer-motion slide-in rows |
| `InspectorModal.tsx` | Glassmorphic inspector: raw headers, flagged payload, confidence, anomaly score |
| `Sparkline.tsx` | Canvas throughput + intercepts sparklines |

Stack: React 18 + TypeScript + Tailwind CSS v4 + framer-motion + Canvas/SVG.

### Setup

```bash
cd frontend
npm install
npm run dev          # → http://localhost:5173 (proxies /ws + /ghost to :8090)
```

> **Windows note:** this project folder contains `&` in its name, which breaks
> `npm run` under cmd.exe. If `npm run dev|build` fails with
> `'WAF' is not recognized`, invoke the tools directly:
>
> ```bash
> node node_modules/vite/bin/vite.js          # dev
> node node_modules/typescript/bin/tsc -b && node node_modules/vite/bin/vite.js build
> ```
>
> The provided scripts (`frontend/scripts/…`) already do this.

The HUD auto-reconnects to the gateway WebSocket and derives its threat level
from the live event stream — point it at any running gateway.

---

## Running the full stack

```bash
# terminal 1 — gateway + attack simulator
cd backend && ./ghost.exe -listen :8090

# terminal 2 — control deck
cd frontend && node node_modules/vite/bin/vite.js --port 5273
# open http://localhost:5273
```

Default ports: gateway `:8090`, HUD `:5173` (change with `--port`; the Vite
proxy and gateway flags are independent).
