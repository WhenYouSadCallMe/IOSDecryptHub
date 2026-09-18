// Package host exposes the device-independent analysis layer through a small
// MCP-compatible JSON-RPC handler. The handler is embeddable in an existing
// host process; it does not start a listener or a resident daemon by itself.
package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"iosruntimeassistant/core/analysis"
	"iosruntimeassistant/core/collect"
	"iosruntimeassistant/core/event"
	"iosruntimeassistant/core/session"
)

const (
	DefaultServerName    = "iosruntimeassistant-open-engine"
	DefaultServerVersion = "0.3.0"
	maxRPCBodyBytes      = 2 * 1024 * 1024
)

type Config struct {
	Index       *collect.EventIndex
	Provenance  *analysis.Graph
	Guard       *session.Guard
	BearerToken string
	Name        string
	Version     string
}

type Server struct {
	index       *collect.EventIndex
	provenance  *analysis.Graph
	guard       *session.Guard
	bearerToken string
	name        string
	version     string
}

func NewServer(config Config) *Server {
	name := strings.TrimSpace(config.Name)
	if name == "" {
		name = DefaultServerName
	}
	version := strings.TrimSpace(config.Version)
	if version == "" {
		version = DefaultServerVersion
	}
	index := config.Index
	if index == nil {
		index = collect.NewEventIndex(10000)
	}
	graph := config.Provenance
	if graph == nil {
		graph = analysis.NewGraph()
	}
	return &Server{
		index:       index,
		provenance:  graph,
		guard:       config.Guard,
		bearerToken: strings.TrimSpace(config.BearerToken),
		name:        name,
		version:     version,
	}
}

// Handler returns the same server as an http.Handler for callers that prefer
// http.ServeMux or httptest. The server intentionally binds nowhere on its
// own; deployments should choose a loopback address and, when needed, set a
// bearer token in Config.
func (s *Server) Handler() http.Handler { return s }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"name":    s.name,
			"version": s.version,
			"transport": map[string]any{
				"jsonRpc":  true,
				"listener": "embedded",
			},
		})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.bearerToken != "" && r.Header.Get("Authorization") != "Bearer "+s.bearerToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRPCBodyBytes))
	if err != nil {
		s.writeRPCError(w, nil, -32600, "request body is too large or unreadable", nil)
		return
	}
	var request rpcRequest
	if err := json.Unmarshal(body, &request); err != nil {
		s.writeRPCError(w, nil, -32700, "invalid JSON", nil)
		return
	}
	if request.JSONRPC != "2.0" || strings.TrimSpace(request.Method) == "" {
		s.writeRPCError(w, request.ID, -32600, "invalid JSON-RPC request", nil)
		return
	}
	result, rpcErr := s.dispatch(r.Context(), request.Method, request.Params)
	// JSON-RPC notifications do not require a response. We still process them
	// above so clients can use notifications/initialized normally.
	if len(request.ID) == 0 && strings.HasPrefix(request.Method, "notifications/") {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if rpcErr != nil {
		s.writeRPCError(w, request.ID, rpcErr.Code, rpcErr.Message, rpcErr.Data)
		return
	}
	s.writeRPCResult(w, request.ID, result)
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int
	Message string
	Data    any
}

func (s *Server) dispatch(ctx context.Context, method string, params json.RawMessage) (any, *rpcError) {
	args := map[string]any{}
	if len(params) != 0 && string(params) != "null" {
		if err := json.Unmarshal(params, &args); err != nil {
			return nil, &rpcError{Code: -32602, Message: "params must be an object", Data: err.Error()}
		}
	}
	switch method {
	case "initialize":
		return map[string]any{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": s.name, "version": s.version},
		}, nil
	case "notifications/initialized":
		return nil, nil
	case "tools/list":
		return map[string]any{"tools": toolDefinitions()}, nil
	case "tools/call":
		name, _ := args["name"].(string)
		toolArgs, _ := args["arguments"].(map[string]any)
		value, err := s.callTool(ctx, name, toolArgs)
		if err != nil {
			return nil, &rpcError{Code: -32602, Message: err.Error()}
		}
		return toolSuccess(value), nil
	case "query_events", "trace_value", "classify_response", "summarize_flow", "generate_frida_script", "generate_dylib_hook", "generate_observer_plan", "session_check", "status":
		value, err := s.callTool(ctx, method, args)
		if err != nil {
			return nil, &rpcError{Code: -32602, Message: err.Error()}
		}
		return value, nil
	default:
		return nil, &rpcError{Code: -32601, Message: "method not found", Data: method}
	}
}

func (s *Server) callTool(ctx context.Context, name string, args map[string]any) (any, error) {
	if args == nil {
		args = map[string]any{}
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	switch strings.TrimSpace(name) {
	case "query_events":
		query, err := queryFromArgs(args)
		if err != nil {
			return nil, err
		}
		return s.index.Query(query)
	case "trace_value":
		start := stringArg(args, "start")
		if start == "" {
			start = stringArg(args, "valueId")
		}
		if start == "" {
			return nil, errors.New("start or valueId is required")
		}
		direction := analysis.Direction(strings.ToLower(stringArg(args, "direction")))
		if direction == "" {
			direction = analysis.DirectionForward
		}
		if direction != analysis.DirectionForward && direction != analysis.DirectionBackward {
			return nil, errors.New("direction must be forward or backward")
		}
		return s.provenance.Trace(start, direction, intArg(args, "maxDepth", 32))
	case "classify_response":
		return analysis.ClassifyResponse(analysis.ResponseInput{
			HTTPStatus: intArg(args, "httpStatus", 0),
			Body:       args["body"],
		}), nil
	case "summarize_flow":
		return s.summarizeFlow(args)
	case "generate_frida_script", "generate_dylib_hook", "generate_observer_plan":
		return observerPlan(name, args), nil
	case "session_check":
		if s.guard == nil {
			return map[string]any{"configured": false, "allowed": true, "reasons": []string{"no session guard configured"}}, nil
		}
		encoded, err := json.Marshal(args["event"])
		if err != nil {
			return nil, fmt.Errorf("event must be an object: %w", err)
		}
		var e event.Event
		if err := json.Unmarshal(encoded, &e); err != nil {
			return nil, fmt.Errorf("event is invalid: %w", err)
		}
		decision := s.guard.Check(e, time.Now().UTC())
		return decision, nil
	case "status":
		value := map[string]any{"events": s.index.Len(), "server": s.name, "version": s.version}
		if s.guard != nil {
			value["sessionGuard"] = map[string]any{"configured": true, "current": s.guard.Current()}
		} else {
			value["sessionGuard"] = map[string]any{"configured": false}
		}
		return value, nil
	default:
		return nil, fmt.Errorf("unknown tool %q", name)
	}
}

func (s *Server) summarizeFlow(args map[string]any) (map[string]any, error) {
	flowID := stringArg(args, "flowId")
	if flowID == "" {
		return nil, errors.New("flowId is required")
	}
	result, err := s.index.Query(collect.EventQuery{FlowID: flowID, Limit: intArg(args, "limit", 500), Projection: "full"})
	if err != nil {
		return nil, err
	}
	types := map[string]int{}
	layers := map[string]int{}
	operations := map[string]int{}
	classifications := make([]analysis.Classification, 0)
	for _, item := range result.Events {
		types[fmt.Sprint(item["type"])]++
		layers[fmt.Sprint(item["layer"])]++
		operations[fmt.Sprint(item["operation"])]++
		if body, ok := item["result"]; ok && body != nil {
			if envelope, ok := body.(map[string]any); ok {
				if nested, exists := envelope["body"]; exists {
					body = nested
				}
			}
			classification := analysis.ClassifyResponse(analysis.ResponseInput{Body: body})
			if classification.Layer != analysis.LayerUnknown {
				classifications = append(classifications, classification)
			}
		}
	}
	return map[string]any{
		"flowId":          flowID,
		"matched":         result.Matched,
		"truncated":       result.Truncated,
		"types":           types,
		"layers":          layers,
		"operations":      operations,
		"classifications": classifications,
		"events":          result.Events,
	}, nil
}

func queryFromArgs(args map[string]any) (collect.EventQuery, error) {
	query := collect.EventQuery{
		SessionID:      stringArg(args, "sessionId"),
		FlowID:         stringArg(args, "flowId"),
		RequestID:      stringArg(args, "requestId"),
		Operation:      stringArg(args, "operation"),
		Cursor:         intArg(args, "cursor", 0),
		Limit:          intArg(args, "limit", 100),
		Projection:     stringArg(args, "projection"),
		IncludeDropped: boolArg(args, "includeDropped", false),
	}
	if rawType := stringArg(args, "type"); rawType != "" {
		query.Type = event.Type(rawType)
	}
	for key, destination := range map[string]*time.Time{"since": &query.Since, "until": &query.Until} {
		if raw := stringArg(args, key); raw != "" {
			parsed, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				return collect.EventQuery{}, fmt.Errorf("%s must be RFC3339: %w", key, err)
			}
			*destination = parsed
		}
	}
	return query, nil
}

func observerPlan(kind string, args map[string]any) map[string]any {
	target := map[string]any{}
	for _, key := range []string{"image", "symbol", "class", "selector", "module", "address"} {
		if value := stringArg(args, key); value != "" {
			target[key] = value
		}
	}
	captures := args["capture"]
	if captures == nil {
		captures = []string{"arguments", "result", "nativeStack"}
	}
	return map[string]any{
		"kind":       kind,
		"mode":       "record-only",
		"executable": false,
		"target":     target,
		"capture":    captures,
		"redact":     []string{"authorization", "cookie", "set-cookie", "token", "password"},
		"steps": []string{
			"validate the target against an authorized test app and its loaded images",
			"install the corresponding observer adapter in the signed Agent",
			"emit Event Schema v1 JSONL with flow/request/value references",
			"review the redacted event stream before enabling any extended adapter",
		},
		"reason": "This repository keeps the host plan non-executable: AGENTS.md forbids adding runtime hooks, inline hooks, or a resident daemon.",
	}
}

func toolSuccess(value any) map[string]any {
	encoded, err := json.Marshal(value)
	if err != nil {
		encoded = []byte(`{"error":"result encoding failed"}`)
	}
	return map[string]any{
		"content":           []map[string]any{{"type": "text", "text": string(encoded)}},
		"structuredContent": value,
		"isError":           false,
	}
}

func toolDefinitions() []map[string]any {
	objectSchema := map[string]any{"type": "object", "additionalProperties": true}
	return []map[string]any{
		{"name": "query_events", "description": "Query redacted runtime events by session, flow, request, type or time window.", "inputSchema": objectSchema},
		{"name": "trace_value", "description": "Trace a value forward or backward through the provenance graph.", "inputSchema": objectSchema},
		{"name": "classify_response", "description": "Separate transport, gateway, risk and business response layers.", "inputSchema": objectSchema},
		{"name": "summarize_flow", "description": "Return a compact, token-efficient summary of one flow.", "inputSchema": objectSchema},
		{"name": "generate_frida_script", "description": "Return a non-executable record-only observer plan for an authorized adapter.", "inputSchema": objectSchema},
		{"name": "generate_dylib_hook", "description": "Return a non-executable record-only adapter plan; no hook code is emitted.", "inputSchema": objectSchema},
		{"name": "session_check", "description": "Check whether an event belongs to the active and fresh analysis session.", "inputSchema": objectSchema},
		{"name": "status", "description": "Return host event-index and session-guard status.", "inputSchema": objectSchema},
	}
}

func stringArg(args map[string]any, key string) string {
	value, _ := args[key].(string)
	return strings.TrimSpace(value)
}

func intArg(args map[string]any, key string, fallback int) int {
	value := args[key]
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case int:
		return typed
	case json.Number:
		parsed, err := strconv.Atoi(string(typed))
		if err == nil {
			return parsed
		}
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		if err == nil {
			return parsed
		}
	}
	return fallback
}

func boolArg(args map[string]any, key string, fallback bool) bool {
	value, ok := args[key].(bool)
	if !ok {
		return fallback
	}
	return value
}

func (s *Server) writeRPCResult(w http.ResponseWriter, id json.RawMessage, result any) {
	s.writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": rpcID(id), "result": result})
}

func (s *Server) writeRPCError(w http.ResponseWriter, id json.RawMessage, code int, message string, data any) {
	errValue := map[string]any{"code": code, "message": message}
	if data != nil {
		errValue["data"] = data
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": rpcID(id), "error": errValue})
}

func rpcID(id json.RawMessage) any {
	if len(id) == 0 {
		return nil
	}
	var value any
	if json.Unmarshal(id, &value) == nil {
		return value
	}
	return nil
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
