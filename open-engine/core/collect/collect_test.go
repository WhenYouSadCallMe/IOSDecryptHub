package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"iosruntimeassistant/core/event"
)

func TestJSONLSinkRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	sink := NewJSONLSink(&buf)
	e, err := event.New(event.TypeNetwork, "request.resume", event.Target{PID: 7})
	if err != nil {
		t.Fatal(err)
	}
	e.Arguments = map[string]any{"url": "https://example.test"}
	if err := sink.Write(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := ParseLines(strings.NewReader(buf.String()), func(got event.Event) error {
		count++
		if got.EventID != e.EventID {
			t.Fatalf("id mismatch: %q != %q", got.EventID, e.EventID)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 1 || sink.Stats().Written != 1 {
		t.Fatalf("unexpected count/stats: %d %+v", count, sink.Stats())
	}
}

func TestRedactorMasksNestedCredentialKeys(t *testing.T) {
	r := NewRedactor(nil)
	got := r.Value(map[string]any{
		"authorization": "Bearer abc",
		"nested":        map[string]any{"cookie": "sid=secret", "count": 2},
		"items":         []any{map[string]any{"token": "xyz"}},
	})
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if strings.Contains(text, "Bearer abc") || strings.Contains(text, "sid=secret") || strings.Contains(text, "xyz") {
		t.Fatalf("secret leaked: %s", text)
	}
	if !strings.Contains(text, "redacted") {
		t.Fatalf("redaction marker missing: %s", text)
	}
}
