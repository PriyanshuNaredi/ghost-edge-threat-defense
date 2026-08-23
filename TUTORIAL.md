# GHOST — The Complete Tutorial

*A guided tour of the Edge Threat Defense & WAF Interceptor: how every piece
works, why it was built that way, and every problem we hit while building it —
with root causes and fixes.*

---

## Table of Contents

1. [The Big Picture — what is this thing?](#1-the-big-picture)
2. [The Life of a Request](#2-the-life-of-a-request)
3. [Phase 1 Deep Dive — the Go Gateway](#3-phase-1-deep-dive--the-go-gateway)
   - 3.1 [`main.go` — the middleware chain](#31-maingo--the-middleware-chain)
   - 3.2 [`rules.go` — signatures, entropy, scoring](#32-rulesgo--signatures-entropy-scoring)
   - 3.3 [`ratelimit.go` — the leaky token bucket](#33-ratelimitgo--the-leaky-token-bucket)
   - 3.4 [`simulator.go` — the attack daemon](#34-simulatorgo--the-attack-daemon)
   - 3.5 [`ws.go` — WebSocket from scratch (RFC 6455)](#35-wsgo--websocket-from-scratch-rfc-6455)
4. [Phase 2 Deep Dive — the React Control Deck](#4-phase-2-deep-dive--the-react-control-deck)
   - 4.1 [`useGhost.ts` — the telemetry hook](#41-useghostts--the-telemetry-hook)
   - 4.2 [`ThreatGauge.tsx` — gauge + particle physics](#42-threatgaugetsx--gauge--particle-physics)
   - 4.3 [`Sparkline.tsx` — canvas throughput charts](#43-sparkinlinetsx--canvas-throughput-charts)
   - 4.4 [The supporting cast](#44-the-supporting-cast)
5. [Problems We Hit — and How They Were Fixed](#5-problems-we-hit--and-how-they-were-fixed)
6. [Running & Verifying Yourself](#6-running--verifying-yourself)
7. [Where to Take It Next](#7-where-to-take-it-next)

---

## 1. The Big Picture

Ghost is three programs pretending to be the internet:

```
┌──────────────┐     ┌─────────────────────────────────────────┐     ┌──────────────┐
│   Simulated  │     │              GHOST GATEWAY              │     │   Upstream   │
│ botnet/attack│────▶│  blacklist gate → rate limiter → WAF   │────▶│ echo service │
│   clients    │     │              ↓ anomaly score            │     │ (or any URL) │
└──────────────┘     │        allow / throttle / block         │     └──────────────┘
                     └──────────────┬──────────────────────────┘
┌──────────────┐                    │ WebSocket event stream
│  React HUD   │◀───────────────────┘
│ (this tab)   │   {timestamp, client_ip, route, threat_type, score, action_taken}
└──────────────┘
```

Three concepts you need before reading any code:

**Reverse proxy** — a server that sits in front of your real application.
Clients talk to the proxy; the proxy decides whether to forward the request
to the upstream app or kill it. Ghost is a reverse proxy with opinions.

**WAF (Web Application Firewall)** — a proxy that inspects request *content*
for known attack shapes: SQL injection (`' OR 1=1`), cross-site scripting
(`<script>alert(1)</script>`), path traversal (`../../etc/passwd`).

**Rate limiting** — content-agnostic abuse control: no matter *what* you send,
you may not send too much of it, too fast. Ghost uses a **leaky token bucket**
per client IP with strike-based **dynamic blacklisting**.

Everything else in this project is those three ideas plus telemetry.

---

## 2. The Life of a Request

Every request hitting the gateway walks this exact path (in `main.go` →
`gateway()`):

```
request arrives
   │
   ├─ path is /ghost/stats or /ws?  ──▶ control plane, bypass inspection
   │
   ├─ ① IsBlacklisted(ip)?         ──▶ yes: 403 BLACKLIST, event, done
   │
   ├─ ② limiter.Allow(ip)          ──▶ bucket empty? 429 THROTTLE
   │       3 strikes?               ──▶ 45s blacklist: 403 BLACKLIST
   │
   ├─ ③ Inspect(path, query, body) ──▶ 50+ signatures + Shannon entropy
   │
   ├─ ④ anomaly = signatures + entropy + request-rate
   │       score ≥ 60               ──▶ 403 BLOCK (+ blacklist the IP)
   │       score ≥ 35               ──▶ flagged, but forwarded
   │
   └─ ⑤ forward to upstream        ──▶ 200, echo JSON, ALLOW event
```

Every branch emits a **SecurityEvent** that is broadcast to all connected
dashboards over WebSocket. The gateway never blocks on a slow dashboard —
events are dropped for slow consumers rather than stalling the proxy path
(that's the `default:` branch in `Hub.Broadcast`).

---

## 3. Phase 1 Deep Dive — the Go Gateway

### 3.1 `main.go` — the middleware chain

The heart is ~60 lines of `gateway()`. Design decisions worth understanding:

**Client IP resolution.** The simulator spoofs distributed botnets, so the
gateway honors `X-Forwarded-For` (first hop) before falling back to
`r.RemoteAddr`. In production you'd only trust that header from your own load
balancer — trusting it from arbitrary clients lets attackers dodge per-IP
buckets by rotating a fake header (a real, famous WAF bypass).

**Body reading with restoration.** To inspect a request body we must consume
`r.Body` — but the reverse proxy needs it afterward. So we read up to 1 MiB
and *restore* it:

```go
raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
r.Body = io.NopCloser(strings.NewReader(body)) // rewind for the proxy
```

**The built-in upstream.** If you don't pass `-upstream`, requests are served
by `upstreamEcho()` — an in-process handler returning JSON. This makes the
whole demo self-contained: no second service to install.

**Why not gorilla/websocket?** The whole backend is stdlib-only — including
the WebSocket server — so `go build` works with zero network access. §3.5
shows how little code that actually takes.

### 3.2 `rules.go` — signatures, entropy, scoring

**Signature tables.** Three slices of `Rule{Pattern, Threat, Weight}`. Patterns
are lowercase substrings matched against a lowercased, URL-decoded
"inspection surface" (path + query + body concatenated). Weights are tuned so:

- one *severe* signature (`union select` = 76, `/etc/passwd` = 78) crosses the
  block threshold (60) alone;
- *moderate* ones (`alert(` = 34, `concat(` = 32) need corroboration — another
  match, high entropy, or high request rate.

This two-tier design is the difference between a WAF and a naive blocklist:
`?price=34.5` contains no signature; `?price=<34.5 AND sleep(5)` gets caught
by the combination.

**Shannon entropy.** For each character frequency `p`, entropy is
`H = −Σ p·log₂p` (bits/char). Normal English/URLs sit around 3.5–4.5; base64
blobs, hex dumps, and obfuscated payloads push 5.5+. Ghost adds
`(H − 4.5) × 8` points — so a random-looking payload is suspicious even with
zero signature hits. Classic example it catches: `?token=kJ8f$2mZ9xQ...`.

**The verdict.** `Inspect()` returns the dominant threat, cumulative score
(clamped 0–100), a *context snippet* around the matched pattern (what the HUD
highlights in the inspector), and a confidence value.

### 3.3 `ratelimit.go` — the leaky token bucket

Per-IP state is tiny:

```go
type bucket struct {
    tokens  float64    // current capacity
    last    time.Time  // for refill math
    hits    []time.Time // last 2s of requests (frequency factor)
    strikes int         // exhausted-bucket violations
}
```

The **leak**: on every arrival, `tokens += elapsedSeconds × refillRate`,
capped at capacity (12). Each request consumes 1. Sustained safe rate is
therefore the refill rate (4/s); bursts up to 12 are tolerated.

**Escalation**: exhaustion → strike. Three strikes inside the window →
45-second blacklist. Critical blocks (score ≥ 60) also blacklist immediately —
that's the "instant dynamic blacklisting" requirement: a confirmed SQLi attacker
doesn't get a second shot.

**The janitor**: a goroutine ticks every 30 s and evicts buckets idle for 5
minutes and expired blacklist entries — otherwise the maps would grow forever
under spoofed-IP floods (a slow memory leak, a classic production bug).

One subtlety you can see in the verify output: a flood shows `200 200 ... 429
200 429 403` — the lone 200 between 429s is the bucket *refilling* in the
gap between two HTTP round-trips. That's correct leaky-bucket behavior, not a
bug.

### 3.4 `simulator.go` — the attack daemon

A single goroutine loop that cycles through realistic attack phases:

- **Baseline** — 2–4 "human" clients from a stable `10.0.x.x` pool hitting
  normal routes.
- **Probes** (~55% of cycles) — one injection attempt from a random public IP,
  rotating through SQLi/XSS/traversal payload pools.
- **Botnet spikes** (~12% of cycles) — a swarm of 6–16 IPs firing 25–60
  requests at one route. This is what makes the HUD's threat gauge spike and
  the particle bursts fire.

Every simulated request sets `X-Forwarded-For: <fake IP>` so the rate limiter
treats the swarm as distributed, not as one localhost client.

### 3.5 `ws.go` — WebSocket from scratch (RFC 6455)

What `gorilla/websocket` does for you, in ~200 lines:

**The handshake.** HTTP `Upgrade: websocket` → server hijacks the TCP
connection and replies `101 Switching Protocols` with
`Sec-WebSocket-Accept = base64(SHA1(clientKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`.
That magic GUID is straight from the RFC.

**Framing.** After hijack, it's no longer HTTP — data flows in binary frames:

```
┌───────┬───────┬─────────────┬────────────┬─────────┐
│ FIN + │ mask  │ payload len │ mask key   │ payload │
│ opcode│ bit=0 │ 7/16/64-bit │ (4 bytes)  │ (XOR'd) │
└───────┴───────┴─────────────┴────────────┴─────────┘
```

Client→server frames are always masked (XOR with a 4-byte key); server→client
frames never are. Lengths ≥126 switch to 16-bit, ≥65536 to 64-bit extended
length. `writeFrame`/`readFrame` implement exactly this.

**The hub.** `Hub` keeps a `map[*wsClient]struct{}`; `Broadcast` marshals the
event once and pushes to each client's buffered channel — with a `default:`
drop for slow clients, so a paused browser tab can never back-pressure the
proxy. A keepalive goroutine pings every 20 s so proxies don't reap idle
sockets.

---

## 4. Phase 2 Deep Dive — the React Control Deck

### 4.1 `useGhost.ts` — the telemetry hook

One hook owns all live state: WebSocket events, `/ghost/stats` polling,
throughput series, threat level.

**Reconnect with exponential backoff** — on close, retry at
`min(1s × 2^n, 15s)`. Kill the gateway and watch the HUD badge flip to
OFFLINE, then reconnect automatically when it returns.

**Throughput sampling.** Messages increment a *ref* counter; a 500 ms interval
folds it into a `series` array. This is the standard trick for high-frequency
streams: never `setState` per message (a botnet spike is 60+ messages/sec —
per-message renders would melt the UI), batch instead.

**Threat level** is a smoothed EMA: `level = 0.6·prev + 0.4·(0.6·blockDensity
+ 0.4·maxScore)` — responsive to spikes without flickering.

### 4.2 `ThreatGauge.tsx` — gauge + particle physics

The gauge is SVG: a background track circle and a value circle, both using
`strokeDasharray` on a 270° arc (`dash = level/100 × 0.75 × circumference`,
rotated 135°). Framer-motion animates between dash values; a Gaussian-blur SVG
filter makes the arc glow.

The **particle burst** is a `<canvas>` layered under the SVG. Each dropped
request increments `blockPulse`, which spawns 26 particles at the rim with
random angle/velocity; a `requestAnimationFrame` loop moves them outward and
fades `life -= 0.022`. Canvas for hundreds of moving dots, SVG for crisp arcs,
DOM for text — each layer doing what it's best at.

### 4.3 `Sparkline.tsx` — canvas throughput charts

A DPR-aware canvas (multiply dimensions by `devicePixelRatio`, scale the
context) drawing a gradient-filled polyline per 500 ms sample: cyan for total
requests, red overlay for intercepts. Redraws are driven by React state
changes on the `series` prop — no animation loop needed.

### 4.4 The supporting cast

- **`TrafficGrid.tsx`** — buckets the last 200 events per route; cell
  background alpha scales with volume, border color with the worst threat seen
  (`#f43f5e` traversal, `#fb923c` XSS, `#fbbf24` traversal-lite…).
- **`EventFeed.tsx`** — last 40 events, newest first, `AnimatePresence`
  slide-in; blocked rows carry a rose left border; every row opens the
  inspector.
- **`InspectorModal.tsx`** — the glassmorphic modal: `.glass` =
  `backdrop-filter: blur(14px)` + translucent panel + cyan hairline border.
  Shows score/confidence/action cards, the flagged payload in a red mono box,
  and the raw request headers captured by the gateway for non-ALLOW actions.
- **`App.tsx`** — 12-column grid: traffic grid + sparklines (3), gauge (5),
  feed (4); a fixed-position alert stack (top-right) where every dropped
  request springs in for ~4 s.

---

## 5. Problems We Hit — and How They Were Fixed

These are real issues from the build, in the order they happened. Each one is
a lesson that transfers to any project.

### 5.1 The gateway wouldn't start: `bind: address already in use`

**Symptom.** `ghost.exe` exited immediately; the log ended with
`listen tcp :8080: bind: Only one usage of each socket address...`.

**Diagnosis.** `netstat -ano | findstr :8080` showed PID 38792 (not ours)
already listening on 8080.

**Fix.** Never kill a process you don't own. Run Ghost on a free port
(`-listen :8090`) — and since it happened *twice* (5173 was also taken later),
the default port became `:8090` in `main.go` and every script/README uses it.

**Lesson.** Ports are machine-global mutable state. Make the port a flag from
day one; before debugging "my server is broken", check whether the port is
even yours.

### 5.2 curl attacks returned `404 page not found`

**Symptom.** While Ghost had failed to bind (§5.1), our verification curls
against `:8080` got `404 page not found` — an HTTP response! From whom?

**Diagnosis.** The squatter on 8080 was a real web server answering our attack
routes with 404s. A 404 is *not* "connection refused" — something spoke HTTP
back.

**Fix.** Once we targeted the correct port, responses were ours. The traversal
probe needed one extra flag (§5.3).

**Lesson.** A plausible HTTP error can come from a completely different
process. When responses look absurd, verify *who* is answering.

### 5.3 Path traversal attack returned a redirect, not a block

**Symptom.** `curl .../static/../../../../etc/passwd` came back
`Temporary Redirect → /etc/passwd` instead of `403 BLOCK`.

**Diagnosis.** **curl normalizes dot-segments in URLs by default** — it
rewrote `/static/../../../..` before even sending. The gateway never saw the
traversal; the echo upstream just bounced the cleaned path.

**Fix.** `curl --path-as-is` disables client-side normalization. After that:
`403 PATH_TRAVERSAL score 100`.

**Lesson.** Your attack tools can quietly defuse your attack tests. For
security testing, know your client's default behavior (`--path-as-is`,
`--data-urlencode`, etc.).

### 5.4 `npm run build` exploded: `'WAF' is not recognized…`

**Symptom.** Inside `frontend/`, `npm run build` printed
`'WAF' is not recognized as an internal or external command` and node failed
to find `...\Downloads\typescript\bin\tsc`.

**Diagnosis.** The project folder is named
`Ghost - Edge Threat Defense & WAF Interceptor` — it contains an **`&`**. npm
on Windows runs scripts through `cmd.exe`, where `&` is a command separator:
the command line got chopped at the ampersand, `WAF Interceptor\...` became a
new "command", and the resolved path collapsed to `Downloads\typescript\...`.

**Fix.** Bypass npm's script layer and invoke the binaries through node
directly:

```bash
node node_modules/typescript/bin/tsc -b
node node_modules/vite/bin/vite.js build
```

That's exactly what `frontend/scripts/*.sh|bat` do, so the workaround is
built in. (The cleanest permanent fix is renaming the folder to drop the `&`.)

**Lesson.** Special characters in paths (`&`, spaces, non-ASCII) are landmines
for every tool that shells out to `cmd.exe`. Avoid them in project paths when
you can; know the direct-invocation escape hatch when you can't.

### 5.5 Vite dev server "up" but curl got connection refused

**Symptom.** Vite's log said `ready … Local: http://localhost:5273/`, yet
`curl http://127.0.0.1:5273/` failed with exit code 7 (connection refused).

**Diagnosis.** Vite binds to `localhost`, which modern Windows resolves to
IPv6 `::1` first. Vite was listening on `[::1]:5273`; curl was knocking on the
IPv4 door `127.0.0.1`.

**Fix.** `curl http://localhost:5273/` (let curl resolve the same way) —
200 OK. Browsers were never affected; they try both stacks.

**Lesson.** "localhost" is not one address. When something is listening but
unreachable, check *which* stack (v4/v6) each side is using.

### 5.6 Dead code in `main.go` — the in-process transport

**Symptom.** The first draft of `main.go` wrapped the built-in echo handler in
a fake `http.Transport` (`inProcessTransport`) so it could be plugged into
`httputil.ReverseProxy` — including one assignment of `upstream.Transport`
that immediately overwrote another. It compiled, but it was two layers of
indirection for zero benefit.

**Fix.** The gateway function only needs an `http.Handler`. Signature changed
from `gateway(proxy *httputil.ReverseProxy)` to `gateway(upstream http.Handler)`;
with `-upstream` set we pass the real reverse proxy, otherwise the echo
handler directly. ~40 lines deleted, `responseRecorder` deleted.

**Lesson.** If an abstraction exists only to satisfy a type you chose, change
the type. `http.Handler` is the universal socket of Go web code.

### 5.7 Strict TypeScript caught an unused import before it shipped

**Symptom.** While refactoring `useGhost.ts`, a leftover `useCallback` import
would have failed the build.

**Fix (prevention).** `tsconfig.app.json` sets `"noUnusedLocals": true` and
`"noUnusedParameters": true`, so `tsc -b` is a gate, not a formality. The
import was removed before the build ever ran.

**Lesson.** Turn strictness on at project creation. The compiler is the
cheapest reviewer you will ever hire.

### 5.8 The browser test couldn't click the SQLi row — feed eviction

**Symptom.** During E2E verification we fired a guaranteed SQLi attack by
curl, then tried to click its row in the HUD feed. "Not found" — within
seconds.

**Diagnosis.** The feed renders only the **last 40 events**, newest first.
The simulator's botnet spikes push 25–60 events per burst, so the target row
was evicted in the time between the curl and the click.

**Fix (test strategy).** Match by *threat class* (`/SQLi|XSS|TRAVERSAL|RATE/`)
and wait for *any* matching row, rather than chasing one specific event.
Ironically we ended up capturing a live `BLACKLIST` event from a real
rate-limited botnet IP — a better test than the one we planned.

**Lesson.** In live systems, test against stable *categories* of state, not
specific transient instances.

### 5.9 Screenshot bytes came back empty — verify via DOM instead

**Symptom.** One `emitImage(await tab.screenshot())` call returned
"(no output)" instead of a visible image.

**Fix.** Rather than retrying blindly, the inspector's state was verified with
a `domSnapshot()` (text), which proved the modal had opened with score 100,
confidence 100%, action BLACKLIST, flagged payload, and raw headers. The
visual channel was confirmed on the earlier successful capture.

**Lesson.** Have more than one observation channel. When one goes quiet,
switch instruments instead of repeating the failed call.

### 5.10 Design guard: slow dashboards can't stall the proxy

Not a bug that happened — a bug we *prevented*. `Hub.Broadcast` uses
non-blocking sends:

```go
select {
case c.send <- data:
default: // slow client: drop rather than block the pipeline
}
```

Without the `default`, one paused browser tab would eventually back-pressure
the gateway's request loop itself. Security telemetry must never be on the
critical path of the traffic it observes.

---

## 6. Running & Verifying Yourself

```bash
# ── Phase 1: gateway (defaults: :8090, simulator ON) ─────────────
cd backend
go build -o ghost.exe .
./ghost.exe                       # or: bash scripts/run.sh

# verify the whole threat model in one command:
bash scripts/verify.sh            # Windows: scripts\verify.bat

# ── Phase 2: control deck ────────────────────────────────────────
cd frontend
npm install
node node_modules/vite/bin/vite.js     # → http://localhost:5173
                                       # (scripts/dev.sh|.bat wrap this)
```

Expected verify output (abridged):

```
1. Clean traffic  → {"service":"ghost-upstream-echo", …}
2. SQLi           → {"status":"blocked","threat_type":"SQL_INJECTION","score":100,…}
3. XSS            → {"status":"blocked","threat_type":"XSS",…}
4. Traversal      → {"status":"blocked","threat_type":"PATH_TRAVERSAL",…}
5. Flood          → 200 ×17  429 429 → strike, strike
6. Post-blacklist → {"action":"BLACKLIST","threat_type":"RATE_LIMIT",…}
```

Flags: `-listen :8090` · `-upstream http://your-service` · `-no-sim`

---

## 7. Where to Take It Next

- **Real IP trust** — only honor `X-Forwarded-For` from known proxy IPs.
- **Persistence** — ship events to SQLite/ClickHouse instead of the void.
- **Machine-learned scoring** — replace/augment weights with a tiny logistic
  model over entropy + n-gram features.
- **Challenge mode** — return a JS proof-of-work challenge instead of a bare
  429.
- **Multi-gateway federation** — share blacklists between gateway replicas
  via gossip (the bucket state is already per-IP and mergeable).
- **Replay** — record raw request bytes (ethically!) and replay the day's
  traffic against new rule sets as a regression test.
