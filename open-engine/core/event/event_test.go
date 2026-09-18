package event

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewEventIsValidAndSerializable(t *testing.T) {
	e, err := New(TypeNetwork, "request.resume", Target{BundleID: "example.app", PID: 42})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.MarshalJSON(); err != nil {
		t.Fatal(err)
	}
}

func TestEventCarriesSessionEvidenceAndRejectsInvalidConfidence(t *testing.T) {
	e, err := New(TypeCrypto, "CCCrypt", Target{PID: 42})
	if err != nil {
		t.Fatal(err)
	}
	e.SessionID = "session-1"
	e.ASLRSlide = "0x100000000"
	e.Layer = "native"
	e.Confidence = 0.97
	e.Evidence = &Evidence{Source: "device-runtime", Freshness: "current", TTLSeconds: 120}
	if _, err := e.MarshalJSON(); err != nil {
		t.Fatal(err)
	}
	e.Confidence = 1.1
	if err := e.Validate(); err == nil {
		t.Fatal("expected invalid confidence error")
	}
}

func TestBusPublishesAndBackpressures(t *testing.T) {
	b := NewBus()
	sub, err := b.Subscribe(1)
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Cancel()
	e, err := New(TypeCrypto, "CCCrypt", Target{PID: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Publish(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if got := <-sub.C; got.EventID != e.EventID {
		t.Fatalf("event id mismatch: got %q want %q", got.EventID, e.EventID)
	}

	if err := b.Publish(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := b.Publish(ctx, e); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline, got %v", err)
	}
	if b.Stats().Dropped != 1 {
		t.Fatalf("expected one dropped event, stats=%+v", b.Stats())
	}
}

func TestBusClose(t *testing.T) {
	b := NewBus()
	sub, err := b.Subscribe(1)
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(TypeSystem, "process.exit", Target{PID: 1})
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
	if _, ok := <-sub.C; ok {
		t.Fatal("subscription channel should be closed")
	}
	if err := b.Publish(context.Background(), e); !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}
