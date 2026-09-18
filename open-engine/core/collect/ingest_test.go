package collect

import (
	"context"
	"testing"
	"time"

	"iosruntimeassistant/core/analysis"
	"iosruntimeassistant/core/event"
)

func TestIngestorCorrelatesAndDeduplicates(t *testing.T) {
	index := NewEventIndex(10)
	ingestor := NewIngestor(
		index,
		analysis.NewFlowCorrelator(analysis.CorrelatorConfig{Window: time.Minute}),
		analysis.NewDeduplicator(time.Minute, 10),
		nil,
	)
	e, err := event.New(event.TypeNetwork, "request.resume", event.Target{PID: 1})
	if err != nil {
		t.Fatal(err)
	}
	e.SessionID = "session-a"
	e.Timestamp = time.Now().UTC()
	e.RequestID = "request-1"
	e.Arguments = map[string]any{"url": "https://example.test/order"}
	first, err := ingestor.Ingest(context.Background(), e)
	if err != nil || !first.Emitted || first.Event.FlowID == "" {
		t.Fatalf("first ingest: %+v %v", first, err)
	}
	secondEvent := e
	secondEvent.EventID = "second-event"
	second, err := ingestor.Ingest(context.Background(), secondEvent)
	if err != nil || second.Emitted || second.Repeat != 2 {
		t.Fatalf("duplicate ingest: %+v %v", second, err)
	}
	if index.Len() != 1 {
		t.Fatalf("duplicate should not grow index: %d", index.Len())
	}
}
