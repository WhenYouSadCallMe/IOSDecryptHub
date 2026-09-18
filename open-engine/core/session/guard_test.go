package session

import (
	"errors"
	"testing"
	"time"

	"iosruntimeassistant/core/event"
)

func TestGuardAcceptsFreshActiveEvent(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	g := NewGuard(Policy{
		RequireSessionID:     true,
		RequireActiveSession: true,
		RequireFreshEvidence: true,
		MaxAge:               10 * time.Second,
	})
	if err := g.Start("session-a", now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	e, err := event.New(event.TypeNetwork, "request.resume", event.Target{PID: 1})
	if err != nil {
		t.Fatal(err)
	}
	e.SessionID = "session-a"
	e.Timestamp = now.Add(-time.Second)
	e.Evidence = &event.Evidence{Source: "device", Freshness: "fresh", TTLSeconds: 30}
	if err := g.Accept(e, now); err != nil {
		t.Fatal(err)
	}
}

func TestGuardRejectsStaleAndInactiveEvidence(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	g := NewGuard(Policy{
		RequireSessionID:     true,
		RequireActiveSession: true,
		RequireFreshEvidence: true,
	})
	e, err := event.New(event.TypeNetwork, "request.resume", event.Target{PID: 1})
	if err != nil {
		t.Fatal(err)
	}
	e.SessionID = "session-old"
	e.Timestamp = now
	e.Evidence = &event.Evidence{Freshness: "stale"}
	if err := g.Accept(e, now); !errors.Is(err, ErrRejected) {
		t.Fatalf("expected rejection, got %v", err)
	}
	decision := g.Check(e, now)
	if decision.Allowed || len(decision.Reasons) < 2 {
		t.Fatalf("expected stale and inactive reasons: %+v", decision)
	}
}

func TestGuardRejectsUnknownFreshnessByDefault(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	g := NewGuard(Policy{RequireFreshEvidence: true})
	e, err := event.New(event.TypeBridge, "bridge.return", event.Target{PID: 1})
	if err != nil {
		t.Fatal(err)
	}
	e.Timestamp = now
	if decision := g.Check(e, now); decision.Allowed {
		t.Fatalf("unknown evidence unexpectedly accepted: %+v", decision)
	}
}
