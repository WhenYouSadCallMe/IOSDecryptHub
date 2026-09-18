// Package host exposes the device-independent analysis layer through a small
// MCP-compatible JSON-RPC handler. The handler is embeddable in an existing
// host process; it does not start a listener or a resident daemon by itself.
package host

import (
	"context"
	"encoding/base64"
	"encoding/hex"
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
	"iosruntimeassistant/core/macho"
	"iosruntimeassistant/core/protocol"
	"iosruntimeassistant/core/session"
	"iosruntimeassistant/core/stack"
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
	case "query_events", "find_values", "trace_value", "classify_response", "summarize_flow", "analyze_payload", "analyze_macho", "normalize_stack", "generate_frida_script", "generate_dylib_hook", "generate_observer_plan", "probe_mutation", "session_check", "status":
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
	case "find_values":
		return s.index.FindValues(valueQueryFromArgs(args))
	case "analyze_payload":
		data, err := payloadBytes(args)
		if err != nil {
			return nil, err
		}
		return protocol.Inspect(data, protocol.Options{MaxBytes: intArg(args, "maxBytes", protocol.DefaultMaxBytes), Depth: intArg(args, "depth", 2)})
	case "analyze_macho":
		path := stringArg(args, "path")
		if path == "" {
			return nil, errors.New("path is required")
		}
		return macho.ParseFile(path)
	case "normalize_stack":
		return normalizeStackArgs(args)
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
	case "probe_mutation":
		return mutationPlan(args), nil
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
		{"name": "find_values", "description": "Find value references and derived byte profiles by hash, role, name, encoding or magic bytes.", "inputSchema": objectSchema},
		{"name": "analyze_payload", "description": "Bounded read-only protocol, compression, encoding, entropy and protobuf/messagepack inspection.", "inputSchema": objectSchema},
		{"name": "analyze_macho", "description": "Read-only Mach-O/FAT metadata, UUID, segments and architecture inspection.", "inputSchema": objectSchema},
		{"name": "normalize_stack", "description": "Convert runtime stack addresses to IDA/Ghidra addresses using an explicit ASLR slide.", "inputSchema": objectSchema},
		{"name": "trace_value", "description": "Trace a value forward or backward through the provenance graph.", "inputSchema": objectSchema},
		{"name": "classify_response", "description": "Separate transport, gateway, risk and business response layers.", "inputSchema": objectSchema},
		{"name": "summarize_flow", "description": "Return a compact, token-efficient summary of one flow.", "inputSchema": objectSchema},
		{"name": "generate_frida_script", "description": "Return a non-executable record-only observer plan for an authorized adapter.", "inputSchema": objectSchema},
		{"name": "generate_dylib_hook", "description": "Return a non-executable record-only adapter plan; no hook code is emitted.", "inputSchema": objectSchema},
		{"name": "probe_mutation", "description": "Create an auditable, non-executable mutation plan for a future authorized lab adapter.", "inputSchema": objectSchema},
		{"name": "session_check", "description": "Check whether an event belongs to the active and fresh analysis session.", "inputSchema": objectSchema},
		{"name": "status", "description": "Return host event-index and session-guard status.", "inputSchema": objectSchema},
	}
}

func mutationPlan(args map[string]any) map[string]any {
	target := map[string]any{}
	for _, key := range []string{"flowId", "requestId", "eventId", "valueHash", "field", "operation"} {
		if value := stringArg(args, key); value != "" {
			target[key] = value
		}
	}
	mutation := stringArg(args, "mutation")
	if mutation == "" {
		mutation = "replace-with-same-length-marker"
	}
	return map[string]any{
		"kind":                         "probe_mutation",
		"mode":                         "record-only-plan",
		"executable":                   false,
		"requiresExplicitConfirmation": true,
		"target":                       target,
		"mutation":                     mutation,
		"capture":                      []string{"beforeHash", "afterHash", "responseClassification", "rollbackStatus"},
		"safety": []string{
			"never mutate a live account or production endpoint",
			"require a fresh session and an isolated authorized test target",
			"reject length-changing mutations unless the adapter explicitly declares framing support",
			"record a rollback token and stop on the first unexpected response",
		},
		"reason": "The host layer only plans mutations. Applying them requires a separately signed lab adapter and is disabled by repository policy.",
	}
}

func payloadBytes(args map[string]any) ([]byte, error) {
	value := args["data"]
	encoding := strings.ToLower(stringArg(args, "encoding"))
	if text, ok := value.(string); ok {
		switch encoding {
		case "hex":
			decoded, err := hex.DecodeString(strings.TrimSpace(text))
			if err != nil {
				return nil, fmt.Errorf("data is not valid hex: %w", err)
			}
			return decoded, nil
		case "base64":
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
			if err != nil {
				return nil, fmt.Errorf("data is not valid base64: %w", err)
			}
			return decoded, nil
		default:
			return []byte(text), nil
		}
	}
	if value == nil {
		return nil, errors.New("data is required")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("data cannot be encoded: %w", err)
	}
	return encoded, nil
}

func normalizeStackArgs(args map[string]any) ([]stack.Frame, error) {
	encoded, err := json.Marshal(args["frames"])
	if err != nil {
		return nil, errors.New("frames must be an array")
	}
	var frames []event.StackFrame
	if err := json.Unmarshal(encoded, &frames); err != nil {
		return nil, fmt.Errorf("frames must be an array of stack frames: %w", err)
	}
	return stack.NormalizeNative(frames, uint64Arg(args, "slide", 0)), nil
}

func valueQueryFromArgs(args map[string]any) collect.ValueQuery {
	return collect.ValueQuery{
		Term:       stringArg(args, "term"),
		Hash:       stringArg(args, "hash"),
		Role:       stringArg(args, "role"),
		DataType:   stringArg(args, "dataType"),
		SessionID:  stringArg(args, "sessionId"),
		FlowID:     stringArg(args, "flowId"),
		Type:       event.Type(stringArg(args, "type")),
		Limit:      intArg(args, "limit", 100),
		Projection: stringArg(args, "projection"),
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

func uint64Arg(args map[string]any, key string, fallback uint64) uint64 {
	value := args[key]
	switch typed := value.(type) {
	case float64:
		if typed >= 0 {
			return uint64(typed)
		}
	case int:
		if typed >= 0 {
			return uint64(typed)
		}
	case string:
		parsed, err := strconv.ParseUint(strings.TrimSpace(typed), 0, 64)
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
