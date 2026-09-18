package host

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"iosruntimeassistant/core/analysis"
	"iosruntimeassistant/core/collect"
	"iosruntimeassistant/core/event"
	"iosruntimeassistant/core/session"
)

func TestMCPQueryAndToolsList(t *testing.T) {
	index := collect.NewEventIndex(20)
	e, err := event.New(event.TypeNetwork, "request.resume", event.Target{PID: 12})
	if err != nil {
		t.Fatal(err)
	}
	e.SessionID = "session-a"
	e.FlowID = "flow-a"
	e.Arguments = map[string]any{"url": "https://example.test/order", "authorization": "secret"}
	e.ValueRefs = []event.ValueRef{{Name: "request.signature", Hash: "hash-a", Role: "signature"}}
	if err := index.Add(e); err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{Index: index, Provenance: analysis.NewGraph()})

	toolsResponse := requestRPC(t, server, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": map[string]any{}})
	if toolsResponse.Code != http.StatusOK || !strings.Contains(toolsResponse.Body.String(), "query_events") {
		t.Fatalf("tools/list response: %s", toolsResponse.Body.String())
	}

	queryResponse := requestRPC(t, server, map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]any{"name": "query_events", "arguments": map[string]any{"flowId": "flow-a", "projection": "network"}},
	})
	if queryResponse.Code != http.StatusOK || strings.Contains(queryResponse.Body.String(), "secret") || !strings.Contains(queryResponse.Body.String(), "flow-a") {
		t.Fatalf("query response leaked or missing data: %s", queryResponse.Body.String())
	}

	findResponse := requestRPC(t, server, map[string]any{
		"jsonrpc": "2.0", "id": 3, "method": "tools/call",
		"params": map[string]any{"name": "find_values", "arguments": map[string]any{"role": "signature"}},
	})
	if findResponse.Code != http.StatusOK || !strings.Contains(findResponse.Body.String(), "hash-a") {
		t.Fatalf("find_values response: %s", findResponse.Body.String())
	}
}

func TestMCPClassifiesFlowAndUsesBearerToken(t *testing.T) {
	index := collect.NewEventIndex(20)
	e, err := event.New(event.TypeNetwork, "response", event.Target{PID: 12})
	if err != nil {
		t.Fatal(err)
	}
	e.FlowID = "flow-risk"
	e.Result = map[string]any{"body": map[string]any{"code": -1, "data": map[string]any{"risk": true}}}
	if err := index.Add(e); err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{Index: index, BearerToken: "local-secret"})
	unauthorized := requestRPCWithHeaders(t, server, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "status"}, nil)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected unauthorized status: %d", unauthorized.Code)
	}
	response := requestRPCWithHeaders(t, server, map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "summarize_flow",
		"params": map[string]any{"flowId": "flow-risk"},
	}, map[string]string{"Authorization": "Bearer local-secret"})
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "risk_layer") {
		t.Fatalf("summary did not classify risk: %s", response.Body.String())
	}
}

func TestMCPTraceAndSessionCheck(t *testing.T) {
	graph := analysis.NewGraph()
	if _, err := graph.UpsertValue(analysis.ValueNode{ID: "a", Hash: "ha"}); err != nil {
		t.Fatal(err)
	}
	if _, err := graph.UpsertValue(analysis.ValueNode{ID: "b", Hash: "hb"}); err != nil {
		t.Fatal(err)
	}
	if err := graph.Link(analysis.Edge{From: "a", To: "b", Operation: "encrypt"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	guard := session.NewGuard(session.Policy{RequireSessionID: true, RequireActiveSession: true})
	if err := guard.Start("session-a", now); err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{Provenance: graph, Guard: guard})
	trace := requestRPC(t, server, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "trace_value",
		"params": map[string]any{"start": "a", "direction": "forward"},
	})
	if trace.Code != http.StatusOK || !strings.Contains(trace.Body.String(), "encrypt") {
		t.Fatalf("trace response: %s", trace.Body.String())
	}
	e, err := event.New(event.TypeBridge, "bridge.return", event.Target{PID: 3})
	if err != nil {
		t.Fatal(err)
	}
	e.SessionID = "session-a"
	e.Timestamp = now
	e.Evidence = &event.Evidence{Freshness: "fresh"}
	encoded, _ := json.Marshal(e)
	sessionCheck := requestRPC(t, server, map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "session_check",
		"params": map[string]any{"event": json.RawMessage(encoded)},
	})
	if sessionCheck.Code != http.StatusOK || !strings.Contains(sessionCheck.Body.String(), `"allowed":true`) {
		t.Fatalf("session check response: %s", sessionCheck.Body.String())
	}
}

func TestMCPAnalyzePayloadAndNormalizeStack(t *testing.T) {
	server := NewServer(Config{})
	payload := requestRPC(t, server, map[string]any{
		"jsonrpc": "2.0", "id": 10, "method": "tools/call",
		"params": map[string]any{"name": "analyze_payload", "arguments": map[string]any{"data": `{"code":0}`, "encoding": "utf8"}},
	})
	if payload.Code != http.StatusOK || !strings.Contains(payload.Body.String(), "json") {
		t.Fatalf("analyze_payload response: %s", payload.Body.String())
	}
	stackResponse := requestRPC(t, server, map[string]any{
		"jsonrpc": "2.0", "id": 11, "method": "tools/call",
		"params": map[string]any{"name": "normalize_stack", "arguments": map[string]any{
			"slide":  "0x100000000",
			"frames": []map[string]any{{"address": float64(0x100012340), "image": "App", "symbol": "encrypt"}},
		}},
	})
	if stackResponse.Code != http.StatusOK || !strings.Contains(stackResponse.Body.String(), "0x12340") {
		t.Fatalf("normalize_stack response: %s", stackResponse.Body.String())
	}
}

func TestMCPProbeMutationIsNonExecutable(t *testing.T) {
	server := NewServer(Config{})
	response := requestRPC(t, server, map[string]any{
		"jsonrpc": "2.0", "id": 12, "method": "tools/call",
		"params": map[string]any{"name": "probe_mutation", "arguments": map[string]any{"flowId": "flow-a", "field": "signature", "mutation": "flip-one-byte"}},
	})
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, "record-only-plan") || !strings.Contains(body, "\"executable\":false") {
		t.Fatalf("unexpected mutation plan: %s", body)
	}
}

func requestRPC(t *testing.T, server *Server, value map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	return requestRPCWithHeaders(t, server, value, nil)
}

func requestRPCWithHeaders(t *testing.T, server *Server, value map[string]any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	return response
}
