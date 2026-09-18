package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"iosruntimeassistant/core/event"
)

// CorrelatorConfig controls how long a flow remains eligible for implicit
// correlation. Correlation is deliberately evidence-based: an event is only
// attached to an existing flow when it carries a request/parent/value/endpoint
// signal. The correlator never guesses from process timing alone.
type CorrelatorConfig struct {
	Window    time.Duration
	MaxFlows  int
	MaxEvents int
}

// Correlation describes why an event was attached to a flow. Keeping reasons
// in the result makes the relationship explainable to an AI agent and useful
// for audit logs.
type Correlation struct {
	FlowID  string   `json:"flowId"`
	Score   float64  `json:"score"`
	Reasons []string `json:"reasons"`
	Created bool     `json:"created"`
}

// FlowSummary is a compact snapshot suitable for MCP responses.
type FlowSummary struct {
	FlowID     string    `json:"flowId"`
	SessionID  string    `json:"sessionId,omitempty"`
	LastSeen   time.Time `json:"lastSeen"`
	EventCount uint64    `json:"eventCount"`
	RequestIDs []string  `json:"requestIds,omitempty"`
	Endpoints  []string  `json:"endpoints,omitempty"`
}

type flowState struct {
	FlowSummary
	targetKey string
	values    map[string]struct{}
}

// FlowCorrelator links events emitted by different observers without changing
// their payload. Strong identifiers are preferred in this order:
// explicit flowId, requestId, parentEventId, value hash, and endpoint. This is
// enough to join a crypto event to a later NSURLSession event when both expose
// the same value reference, while avoiding the false positives caused by a
// process-wide time-only heuristic.
type FlowCorrelator struct {
	mu       sync.Mutex
	cfg      CorrelatorConfig
	sequence uint64
	flows    map[string]*flowState
	request  map[string]string
	parent   map[string]string
	value    map[string]string
	endpoint map[string]string
}

var (
	ErrCorrelationEvent = errors.New("correlation event is invalid")
)

func NewFlowCorrelator(cfg CorrelatorConfig) *FlowCorrelator {
	if cfg.Window <= 0 {
		cfg.Window = 10 * time.Second
	}
	if cfg.MaxFlows < 1 {
		cfg.MaxFlows = 2048
	}
	if cfg.MaxEvents < 1 {
		cfg.MaxEvents = 100000
	}
	return &FlowCorrelator{
		cfg:      cfg,
		flows:    make(map[string]*flowState),
		request:  make(map[string]string),
		parent:   make(map[string]string),
		value:    make(map[string]string),
		endpoint: make(map[string]string),
	}
}

// Correlate returns a copy of e with FlowID populated when the evidence is
// sufficient. Existing FlowID values are preserved, never replaced.
func (c *FlowCorrelator) Correlate(e event.Event) (event.Event, Correlation, error) {
	if err := e.Validate(); err != nil {
		return event.Event{}, Correlation{}, fmt.Errorf("%w: %v", ErrCorrelationEvent, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	now := e.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}
	c.expire(now)

	hints := extractCorrelationHints(e)
	flowID, reasons, score := c.find(e, hints, now)
	created := false
	if flowID == "" {
		c.sequence++
		flowID = c.newFlowID(e, c.sequence)
		created = true
		reasons = []string{"new flow: no reusable correlation evidence"}
		score = 1
		c.flows[flowID] = &flowState{
			FlowSummary: FlowSummary{FlowID: flowID, SessionID: e.SessionID, LastSeen: now},
			targetKey:   targetKey(e),
			values:      make(map[string]struct{}),
		}
	}
	c.record(flowID, e, hints, now)
	e.FlowID = flowID
	return e, Correlation{FlowID: flowID, Score: score, Reasons: reasons, Created: created}, nil
}

// Attach is a concise alias for integrations that process a stream of events.
func (c *FlowCorrelator) Attach(e event.Event) (event.Event, Correlation, error) {
	return c.Correlate(e)
}

func (c *FlowCorrelator) find(e event.Event, hints correlationHints, now time.Time) (string, []string, float64) {
	if e.FlowID != "" {
		if state, ok := c.flows[e.FlowID]; ok && c.compatible(state, e, now) {
			return e.FlowID, []string{"explicit flowId"}, 1
		}
		// An explicit id is still authoritative even when this process started
		// after the event was emitted. Re-create its state below.
		return e.FlowID, []string{"explicit flowId (state initialized from event)"}, 1
	}
	if hints.requestID != "" {
		if id := c.request[scoped(e.SessionID, hints.requestID)]; id != "" {
			if state, ok := c.flows[id]; ok && c.compatible(state, e, now) {
				return id, []string{"shared requestId"}, 0.99
			}
		}
	}
	if e.ParentEventID != "" {
		if id := c.parent[e.ParentEventID]; id != "" {
			if state, ok := c.flows[id]; ok && c.compatible(state, e, now) {
				return id, []string{"parentEventId points to flow"}, 0.98
			}
		}
	}
	for _, hash := range hints.values {
		if id := c.value[scoped(e.SessionID, hash)]; id != "" {
			if state, ok := c.flows[id]; ok && c.compatible(state, e, now) {
				return id, []string{"shared value hash: " + hash}, 0.95
			}
		}
	}
	if hints.endpoint != "" {
		if id := c.endpoint[scoped(e.SessionID, hints.endpoint)]; id != "" {
			if state, ok := c.flows[id]; ok && c.compatible(state, e, now) {
				return id, []string{"shared endpoint: " + hints.endpoint}, 0.9
			}
		}
	}
	return "", nil, 0
}

func (c *FlowCorrelator) compatible(state *flowState, e event.Event, now time.Time) bool {
	if state == nil || (state.SessionID != "" && e.SessionID != "" && state.SessionID != e.SessionID) {
		return false
	}
	if state.targetKey != "" && targetKey(e) != "" && state.targetKey != targetKey(e) {
		return false
	}
	if !state.LastSeen.IsZero() && now.Before(state.LastSeen.Add(-c.cfg.Window)) {
		return false
	}
	if !state.LastSeen.IsZero() && now.Sub(state.LastSeen) > c.cfg.Window {
		return false
	}
	return true
}

func (c *FlowCorrelator) record(flowID string, e event.Event, hints correlationHints, now time.Time) {
	state, ok := c.flows[flowID]
	if !ok {
		state = &flowState{
			FlowSummary: FlowSummary{FlowID: flowID, SessionID: e.SessionID},
			targetKey:   targetKey(e),
			values:      make(map[string]struct{}),
		}
		c.flows[flowID] = state
	}
	if state.SessionID == "" {
		state.SessionID = e.SessionID
	}
	state.LastSeen = now
	state.EventCount++
	if e.EventID != "" {
		c.parent[e.EventID] = flowID
	}
	if hints.requestID != "" {
		c.request[scoped(e.SessionID, hints.requestID)] = flowID
		state.RequestIDs = appendUnique(state.RequestIDs, hints.requestID)
	}
	if hints.endpoint != "" {
		c.endpoint[scoped(e.SessionID, hints.endpoint)] = flowID
		state.Endpoints = appendUnique(state.Endpoints, hints.endpoint)
	}
	for _, hash := range hints.values {
		c.value[scoped(e.SessionID, hash)] = flowID
		state.values[hash] = struct{}{}
	}
	if len(c.flows) > c.cfg.MaxFlows {
		c.evict()
	}
}

func (c *FlowCorrelator) expire(now time.Time) {
	for id, state := range c.flows {
		if !state.LastSeen.IsZero() && now.Sub(state.LastSeen) > c.cfg.Window {
			delete(c.flows, id)
		}
	}
}

func (c *FlowCorrelator) evict() {
	for len(c.flows) > c.cfg.MaxFlows {
		var oldestID string
		var oldest time.Time
		for id, state := range c.flows {
			if oldestID == "" || state.LastSeen.Before(oldest) {
				oldestID, oldest = id, state.LastSeen
			}
		}
		if oldestID == "" {
			return
		}
		delete(c.flows, oldestID)
	}
}

func (c *FlowCorrelator) newFlowID(e event.Event, sequence uint64) string {
	seed := fmt.Sprintf("%s|%s|%d|%s|%d", e.SessionID, targetKey(e), e.Timestamp.UnixNano(), e.Type, sequence)
	hash := sha256.Sum256([]byte(seed))
	return "flow_" + hex.EncodeToString(hash[:8])
}

// Snapshot returns stable flow summaries sorted by id.
func (c *FlowCorrelator) Snapshot() []FlowSummary {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]FlowSummary, 0, len(c.flows))
	for _, state := range c.flows {
		copyState := state.FlowSummary
		copyState.RequestIDs = append([]string(nil), state.RequestIDs...)
		copyState.Endpoints = append([]string(nil), state.Endpoints...)
		result = append(result, copyState)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].FlowID < result[j].FlowID })
	return result
}

type correlationHints struct {
	requestID string
	endpoint  string
	values    []string
}

func extractCorrelationHints(e event.Event) correlationHints {
	hints := correlationHints{}
	if e.RequestID != "" {
		hints.requestID = strings.TrimSpace(e.RequestID)
	}
	extractHints(e.Arguments, &hints)
	extractHints(e.Result, &hints)
	seen := make(map[string]struct{}, len(e.ValueRefs))
	for _, ref := range e.ValueRefs {
		value := strings.TrimSpace(ref.Hash)
		if value == "" {
			value = strings.TrimSpace(ref.SourceEventID)
		}
		if value != "" {
			if _, ok := seen[value]; !ok {
				seen[value] = struct{}{}
				hints.values = append(hints.values, value)
			}
		}
	}
	return hints
}

func extractHints(value any, hints *correlationHints) {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			lower := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(key), "_", ""), "-", ""))
			text, ok := item.(string)
			if ok {
				text = strings.TrimSpace(text)
				switch lower {
				case "requestid", "reqid":
					if hints.requestID == "" {
						hints.requestID = text
					}
				case "url", "uri", "endpoint", "host":
					if hints.endpoint == "" {
						hints.endpoint = normalizeEndpoint(text)
					}
				}
			}
			extractHints(item, hints)
		}
	case []any:
		for _, item := range typed {
			extractHints(item, hints)
		}
	case []map[string]any:
		for _, item := range typed {
			extractHints(item, hints)
		}
	}
}

func normalizeEndpoint(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if index := strings.IndexByte(value, '?'); index >= 0 {
		value = value[:index]
	}
	if len(value) > 512 {
		value = value[:512]
	}
	return value
}

func targetKey(e event.Event) string {
	return fmt.Sprintf("%s|%d|%s", strings.TrimSpace(e.Target.BundleID), e.Target.PID, strings.TrimSpace(e.Target.Image))
}

func scoped(sessionID, value string) string {
	return strings.TrimSpace(sessionID) + "|" + strings.TrimSpace(value)
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
