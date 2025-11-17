package tcpguard

import (
	"sync"
	"time"
)

// RequestProfiler keeps short-lived per-IP request fingerprints so we can
// derive lightweight diversity metrics without hitting persistent storage.
type RequestProfiler struct {
	mu         sync.Mutex
	window     time.Duration
	maxEntries int
	data       map[string]*ipProfile
}

type ipProfile struct {
	events []profileEvent
}

type profileEvent struct {
	timestamp time.Time
	path      string
	userAgent string
}

// ProfileSnapshot represents a summarized view of the recent request history
// for a given IP.
type ProfileSnapshot struct {
	Requests           int
	UniquePaths        int
	UniqueUserAgents   int
	PathDiversityScore float64
}

// NewRequestProfiler creates a profiler with the provided sliding window and
// per-IP retention size.
func NewRequestProfiler(window time.Duration, maxEntries int) *RequestProfiler {
	if window <= 0 {
		window = time.Minute
	}
	if maxEntries <= 0 {
		maxEntries = 256
	}
	return &RequestProfiler{
		window:     window,
		maxEntries: maxEntries,
		data:       make(map[string]*ipProfile),
	}
}

// Track stores a single request observation for the given IP.
func (p *RequestProfiler) Track(ip, path, userAgent string, now time.Time) {
	if ip == "" {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	prof := p.ensureProfile(ip)
	prof.events = append(prof.events, profileEvent{timestamp: now, path: path, userAgent: userAgent})

	// Trim very old events beyond the sliding window.
	cutoff := now.Add(-p.window)
	prof.events = trimProfileEvents(prof.events, cutoff)

	// Enforce max entries to keep memory bounded.
	if len(prof.events) > p.maxEntries {
		prof.events = prof.events[len(prof.events)-p.maxEntries:]
	}
}

// Snapshot returns an aggregated view of the recent request history for the
// provided IP.
func (p *RequestProfiler) Snapshot(ip string, now time.Time) ProfileSnapshot {
	if ip == "" {
		return ProfileSnapshot{}
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	prof, ok := p.data[ip]
	if !ok {
		return ProfileSnapshot{}
	}

	cutoff := now.Add(-p.window)
	prof.events = trimProfileEvents(prof.events, cutoff)

	if len(prof.events) == 0 {
		return ProfileSnapshot{}
	}

	pathSet := make(map[string]struct{})
	uaSet := make(map[string]struct{})
	for _, ev := range prof.events {
		if ev.path != "" {
			pathSet[ev.path] = struct{}{}
		}
		if ev.userAgent != "" {
			uaSet[ev.userAgent] = struct{}{}
		}
	}

	requests := len(prof.events)
	diversity := 0.0
	if requests > 0 {
		diversity = float64(len(pathSet)) / float64(requests)
	}

	return ProfileSnapshot{
		Requests:           requests,
		UniquePaths:        len(pathSet),
		UniqueUserAgents:   len(uaSet),
		PathDiversityScore: diversity,
	}
}

func (p *RequestProfiler) ensureProfile(ip string) *ipProfile {
	prof, ok := p.data[ip]
	if !ok {
		prof = &ipProfile{}
		p.data[ip] = prof
	}
	return prof
}

func trimProfileEvents(events []profileEvent, cutoff time.Time) []profileEvent {
	idx := 0
	for idx < len(events) && events[idx].timestamp.Before(cutoff) {
		idx++
	}
	if idx > 0 {
		return events[idx:]
	}
	return events
}
