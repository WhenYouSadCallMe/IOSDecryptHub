package collect

import (
	"testing"
	"time"

	"iosruntimeassistant/core/event"
)

func TestEventIndexFiltersPaginatesAndProjects(t *testing.T) {
	index := NewEventIndex(4)
	for n, operation := range []string{"bridge.return", "CCCrypt", "request.resume"} {
		e, err := event.New(event.TypeNetwork, operation, event.Target{PID: 9})
		if err != nil {
			t.Fatal(err)
		}
		e.SessionID = "s1"
		e.FlowID = "f1"
		e.RequestID = "r1"
		e.Timestamp = time.Unix(int64(n+1), 0).UTC()
		e.Arguments = map[string]any{"cookie": "sid=secret", "n": n}
		if err := index.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	result, err := index.Query(EventQuery{FlowID: "f1", Cursor: 0, Limit: 2, Projection: "crypto"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Matched != 3 || len(result.Events) != 2 || !result.Truncated || result.NextCursor != 2 {
		t.Fatalf("unexpected query result: %+v", result)
	}
	if result.Events[0]["arguments"].(map[string]any)["cookie"] == "sid=secret" {
		t.Fatal("secret cookie was exposed in crypto projection")
	}
}
