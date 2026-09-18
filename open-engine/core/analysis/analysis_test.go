package analysis

import (
	"testing"
	"time"

	"iosruntimeassistant/core/event"
)

func TestProfileBytesDetectsGzipAndEntropy(t *testing.T) {
	profile := ProfileBytes([]byte{0x1f, 0x8b, 0x08, 0x00, 0xff, 0x00})
	if profile.MagicBytes != "gzip" || profile.Encoding != "gzip" {
		t.Fatalf("unexpected profile: %+v", profile)
	}
	if profile.Entropy <= 0 || len(profile.SHA256) != 64 {
		t.Fatalf("missing entropy/hash: %+v", profile)
	}
}

func TestDeduplicatorSuppressesOnlyWithinWindow(t *testing.T) {
	d := NewDeduplicator(time.Second, 8)
	e, err := event.New(event.TypeNetwork, "request.resume", event.Target{PID: 1})
	if err != nil {
		t.Fatal(err)
	}
	e.Timestamp = time.Unix(100, 0).UTC()
	if emit, repeat := d.Observe(e); !emit || repeat != 1 {
		t.Fatalf("first event: %v %d", emit, repeat)
	}
	e.Timestamp = time.Unix(100, int64(500*time.Millisecond)).UTC()
	if emit, repeat := d.Observe(e); emit || repeat != 2 {
		t.Fatalf("duplicate event: %v %d", emit, repeat)
	}
	e.Timestamp = time.Unix(102, 0).UTC()
	if emit, repeat := d.Observe(e); !emit || repeat != 1 {
		t.Fatalf("expired event: %v %d", emit, repeat)
	}
}

func TestProvenanceTraceForwardAndBackward(t *testing.T) {
	g := NewGraph()
	a, err := g.UpsertValue(ValueNode{ID: "a", Name: "bridge.return", Hash: "ha"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := g.UpsertValue(ValueNode{ID: "b", Name: "aes.result", Hash: "hb"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := g.UpsertValue(ValueNode{ID: "c", Name: "header.x-token", Hash: "hc"})
	if err != nil {
		t.Fatal(err)
	}
	for _, edge := range []Edge{{From: a, To: b, Operation: "AES-CBC", EventID: "e2"}, {From: b, To: c, Operation: "header.set", EventID: "e3"}} {
		if err := g.Link(edge); err != nil {
			t.Fatal(err)
		}
	}
	forward, err := g.Trace(a, DirectionForward, 5)
	if err != nil || len(forward) != 3 {
		t.Fatalf("forward trace: %v %+v", err, forward)
	}
	backward, err := g.Trace(c, DirectionBackward, 5)
	if err != nil || len(backward) != 3 {
		t.Fatalf("backward trace: %v %+v", err, backward)
	}
}

func TestResponseClassifierSeparatesRiskAndBusiness(t *testing.T) {
	business := ClassifyResponse(ResponseInput{Body: map[string]any{"resultCode": 999, "msg": "busy", "data": nil}})
	if business.Layer != LayerBusiness || business.RiskPassedByClientRule == nil || !*business.RiskPassedByClientRule {
		t.Fatalf("business classification: %+v", business)
	}
	risk := ClassifyResponse(ResponseInput{Body: map[string]any{"code": -1, "data": map[string]any{"risk": true, "explain": "SCORE_REFUSE"}}})
	if risk.Layer != LayerRisk || risk.RiskPassedByClientRule == nil || *risk.RiskPassedByClientRule {
		t.Fatalf("risk classification: %+v", risk)
	}
}

func TestFlowCorrelatorUsesRequestAndValueEvidence(t *testing.T) {
	c := NewFlowCorrelator(CorrelatorConfig{Window: time.Second})
	first, err := event.New(event.TypeCrypto, "CCCrypt", event.Target{BundleID: "com.example.app", PID: 7})
	if err != nil {
		t.Fatal(err)
	}
	first.SessionID = "session-a"
	first.Timestamp = time.Unix(100, 0).UTC()
	first.ValueRefs = []event.ValueRef{{Hash: "key-hash", Role: "ciphertext"}}
	first, firstCorrelation, err := c.Correlate(first)
	if err != nil {
		t.Fatal(err)
	}
	if !firstCorrelation.Created || first.FlowID == "" {
		t.Fatalf("expected a new flow: %+v", firstCorrelation)
	}

	second, err := event.New(event.TypeNetwork, "request.resume", first.Target)
	if err != nil {
		t.Fatal(err)
	}
	second.SessionID = first.SessionID
	second.Timestamp = time.Unix(100, int64(500*time.Millisecond)).UTC()
	second.RequestID = "request-1"
	second.Arguments = map[string]any{"url": "https://example.test/order?nonce=redacted"}
	second.ValueRefs = []event.ValueRef{{Hash: "key-hash", Role: "body"}}
	second, secondCorrelation, err := c.Correlate(second)
	if err != nil {
		t.Fatal(err)
	}
	if second.FlowID != first.FlowID || secondCorrelation.Created || secondCorrelation.Score < 0.9 {
		t.Fatalf("expected value-based correlation: %+v first=%s second=%s", secondCorrelation, first.FlowID, second.FlowID)
	}

	third, err := event.New(event.TypeNetwork, "request.resume", first.Target)
	if err != nil {
		t.Fatal(err)
	}
	third.SessionID = first.SessionID
	third.Timestamp = time.Unix(101, 0).UTC()
	third.Arguments = map[string]any{"requestId": "request-1", "url": "https://example.test/order"}
	third, thirdCorrelation, err := c.Correlate(third)
	if err != nil {
		t.Fatal(err)
	}
	if third.FlowID != first.FlowID || thirdCorrelation.Score < 0.9 {
		t.Fatalf("expected request-based correlation: %+v", thirdCorrelation)
	}
}

func TestFlowCorrelatorDoesNotReuseExpiredFlow(t *testing.T) {
	c := NewFlowCorrelator(CorrelatorConfig{Window: time.Second})
	first, err := event.New(event.TypeNetwork, "request.resume", event.Target{PID: 9})
	if err != nil {
		t.Fatal(err)
	}
	first.SessionID = "session-a"
	first.Timestamp = time.Unix(100, 0).UTC()
	first.RequestID = "request-1"
	first, _, err = c.Correlate(first)
	if err != nil {
		t.Fatal(err)
	}

	second, err := event.New(event.TypeNetwork, "request.resume", first.Target)
	if err != nil {
		t.Fatal(err)
	}
	second.SessionID = first.SessionID
	second.Timestamp = time.Unix(102, 0).UTC()
	second.RequestID = "request-1"
	second, correlation, err := c.Correlate(second)
	if err != nil {
		t.Fatal(err)
	}
	if second.FlowID == first.FlowID || correlation.Created == false {
		t.Fatalf("expired flow was reused: first=%s second=%s correlation=%+v", first.FlowID, second.FlowID, correlation)
	}
}

func TestAnnotateEventAddsDerivedProfilesWithoutRawPayload(t *testing.T) {
	e, err := event.New(event.TypeCrypto, "encrypt", event.Target{PID: 2})
	if err != nil {
		t.Fatal(err)
	}
	e.Arguments = map[string]any{"body": []byte{0x1f, 0x8b, 0x08, 0x00}}
	e.Result = map[string]any{"cipherText": "0011223344556677"}
	annotated := AnnotateEvent(e)
	if annotated.Analysis == nil || len(annotated.Analysis.Arguments) != 1 || len(annotated.Analysis.Result) != 1 {
		t.Fatalf("missing value analysis: %+v", annotated.Analysis)
	}
	if annotated.Analysis.Arguments[0].MagicBytes != "gzip" || annotated.Analysis.Result[0].Encoding != "hex-text" {
		t.Fatalf("unexpected profiles: %+v", annotated.Analysis)
	}
	if annotated.Analysis.Arguments[0].SHA256 == "" || annotated.Analysis.Arguments[0].Length != 4 {
		t.Fatalf("hash/length missing: %+v", annotated.Analysis.Arguments[0])
	}
}
