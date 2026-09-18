// Package session provides fail-closed checks for runtime evidence. It does
// not create or refresh device credentials; it only prevents an analysis
// session from silently mixing stale values with a new capture.
package session

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"iosruntimeassistant/core/event"
)

var (
	ErrRejected       = errors.New("event rejected by session guard")
	ErrMissingSession = errors.New("sessionId is required")
	ErrInactive       = errors.New("session is not active")
	ErrStaleEvidence  = errors.New("evidence is stale or expired")
	ErrFutureEvent    = errors.New("event timestamp is too far in the future")
)

// Policy is intentionally conservative but opt-in. A host that only reviews
// historical JSONL may leave RequireActiveSession false, while a live device
// adapter should enable it before accepting bridge tokens or cookies.
type Policy struct {
	RequireSessionID     bool
	RequireActiveSession bool
	RequireFreshEvidence bool
	AllowUnknownEvidence bool
	MaxAge               time.Duration
	MaxFutureSkew        time.Duration
}

type Decision struct {
	Allowed   bool          `json:"allowed"`
	SessionID string        `json:"sessionId,omitempty"`
	Age       time.Duration `json:"age"`
	Reasons   []string      `json:"reasons"`
}

type Guard struct {
	mu      sync.RWMutex
	policy  Policy
	active  map[string]time.Time
	current string
}

func NewGuard(policy Policy) *Guard {
	if policy.MaxFutureSkew <= 0 {
		policy.MaxFutureSkew = 30 * time.Second
	}
	return &Guard{policy: policy, active: make(map[string]time.Time)}
}

func (g *Guard) Start(sessionID string, at time.Time) error {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return ErrMissingSession
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	g.mu.Lock()
	g.active[sessionID] = at
	g.current = sessionID
	g.mu.Unlock()
	return nil
}

func (g *Guard) End(sessionID string) {
	sessionID = strings.TrimSpace(sessionID)
	g.mu.Lock()
	delete(g.active, sessionID)
	if g.current == sessionID {
		g.current = ""
	}
	g.mu.Unlock()
}

func (g *Guard) Current() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.current
}

func (g *Guard) Active(sessionID string) bool {
	g.mu.RLock()
	_, ok := g.active[strings.TrimSpace(sessionID)]
	g.mu.RUnlock()
	return ok
}

func (g *Guard) Policy() Policy {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.policy
}

// Check evaluates an event without mutating guard state. Reasons are stable
// strings so the MCP layer can explain a rejection without exposing payloads.
func (g *Guard) Check(e event.Event, now time.Time) Decision {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	policy := g.Policy()
	decision := Decision{Allowed: true, SessionID: strings.TrimSpace(e.SessionID)}
	if e.Timestamp.IsZero() {
		decision.Allowed = false
		decision.Reasons = append(decision.Reasons, "timestamp is missing")
		return decision
	}
	decision.Age = now.Sub(e.Timestamp)
	if decision.Age < -policy.MaxFutureSkew {
		decision.Allowed = false
		decision.Reasons = append(decision.Reasons, ErrFutureEvent.Error())
	}
	if policy.MaxAge > 0 && decision.Age > policy.MaxAge {
		decision.Allowed = false
		decision.Reasons = append(decision.Reasons, "event exceeds max age")
	}
	if policy.RequireSessionID && decision.SessionID == "" {
		decision.Allowed = false
		decision.Reasons = append(decision.Reasons, ErrMissingSession.Error())
	}
	if policy.RequireActiveSession && decision.SessionID != "" && !g.Active(decision.SessionID) {
		decision.Allowed = false
		decision.Reasons = append(decision.Reasons, ErrInactive.Error())
	}
	if policy.RequireFreshEvidence {
		freshness := ""
		ttl := 0
		if e.Evidence != nil {
			freshness = strings.ToLower(strings.TrimSpace(e.Evidence.Freshness))
			ttl = e.Evidence.TTLSeconds
		}
		switch freshness {
		case "fresh", "live", "current":
			// accepted below
		case "stale", "expired":
			decision.Allowed = false
			decision.Reasons = append(decision.Reasons, ErrStaleEvidence.Error())
		case "":
			if !policy.AllowUnknownEvidence {
				decision.Allowed = false
				decision.Reasons = append(decision.Reasons, "evidence freshness is unknown")
			}
		default:
			if !policy.AllowUnknownEvidence {
				decision.Allowed = false
				decision.Reasons = append(decision.Reasons, "unsupported evidence freshness")
			}
		}
		if ttl > 0 && decision.Age > time.Duration(ttl)*time.Second {
			decision.Allowed = false
			decision.Reasons = append(decision.Reasons, "evidence TTL has elapsed")
		}
	}
	return decision
}

func (g *Guard) Accept(e event.Event, now time.Time) error {
	decision := g.Check(e, now)
	if decision.Allowed {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrRejected, strings.Join(decision.Reasons, "; "))
}
