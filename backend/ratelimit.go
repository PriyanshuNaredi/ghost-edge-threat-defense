package main

import (
	"sync"
	"time"
)

// bucket is a leaky token bucket for a single client IP. Tokens refill at a steady
// rate (the "leak"), each request consumes one token, and repeated exhaustion earns
// strikes that escalate into a temporary blacklist.
type bucket struct {
	tokens  float64
	last    time.Time
	hits    []time.Time
	strikes int
}

// RateLimiter tracks per-IP token buckets and a time-expiring blacklist.
type RateLimiter struct {
	mu           sync.Mutex
	buckets      map[string]*bucket
	blacklist    map[string]time.Time
	capacity     float64
	refillRate   float64 // tokens per second
	strikeLimit  int
	blacklistDur time.Duration
}

// NewRateLimiter constructs a limiter and starts its background janitor.
func NewRateLimiter(capacity, refillRate float64, strikeLimit int, blacklistDur time.Duration) *RateLimiter {
	rl := &RateLimiter{
		buckets:      make(map[string]*bucket),
		blacklist:    make(map[string]time.Time),
		capacity:     capacity,
		refillRate:   refillRate,
		strikeLimit:  strikeLimit,
		blacklistDur: blacklistDur,
	}
	go rl.cleanupLoop()
	return rl
}

// IsBlacklisted reports whether the IP is currently blacklisted, expiring stale entries.
func (rl *RateLimiter) IsBlacklisted(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	exp, ok := rl.blacklist[ip]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(rl.blacklist, ip)
		return false
	}
	return true
}

// Blacklist forcibly blacklists an IP for the configured duration.
func (rl *RateLimiter) Blacklist(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.blacklist[ip] = time.Now().Add(rl.blacklistDur)
}

// Allow consumes a token for the IP. It returns whether the request may proceed and
// whether the IP was (or just became) blacklisted.
func (rl *RateLimiter) Allow(ip string) (allowed bool, blacklisted bool) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()

	if exp, ok := rl.blacklist[ip]; ok {
		if now.Before(exp) {
			return false, true
		}
		delete(rl.blacklist, ip)
	}

	b, ok := rl.buckets[ip]
	if !ok {
		b = &bucket{tokens: rl.capacity, last: now}
		rl.buckets[ip] = b
	}

	// Refill (leak) tokens based on elapsed time, capped at capacity.
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * rl.refillRate
	if b.tokens > rl.capacity {
		b.tokens = rl.capacity
	}
	b.last = now

	// Record the hit and keep only the last 2s of history for frequency scoring.
	b.hits = append(b.hits, now)
	cutoff := now.Add(-2 * time.Second)
	keep := b.hits[:0]
	for _, t := range b.hits {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	b.hits = keep

	if b.tokens >= 1 {
		b.tokens--
		return true, false
	}

	// Exhausted: strike the IP. Enough strikes escalate to a blacklist.
	b.strikes++
	if b.strikes >= rl.strikeLimit {
		rl.blacklist[ip] = now.Add(rl.blacklistDur)
		return false, true
	}
	return false, false
}

// RecentRate returns the number of requests the IP made in the last second, used as
// a frequency factor in anomaly scoring.
func (rl *RateLimiter) RecentRate(ip string) float64 {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b, ok := rl.buckets[ip]
	if !ok {
		return 0
	}
	now := time.Now()
	count := 0
	for _, t := range b.hits {
		if now.Sub(t) <= time.Second {
			count++
		}
	}
	return float64(count)
}

// cleanupLoop periodically evicts idle buckets and expired blacklist entries.
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, b := range rl.buckets {
			if len(b.hits) == 0 || now.Sub(b.last) > 5*time.Minute {
				delete(rl.buckets, ip)
			}
		}
		for ip, exp := range rl.blacklist {
			if now.After(exp) {
				delete(rl.blacklist, ip)
			}
		}
		rl.mu.Unlock()
	}
}
