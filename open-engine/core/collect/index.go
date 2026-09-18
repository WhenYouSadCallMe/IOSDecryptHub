package collect

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"iosruntimeassistant/core/event"
)

type EventQuery struct {
	SessionID      string
	FlowID         string
	RequestID      string
	Type           event.Type
	Operation      string
	Since          time.Time
	Until          time.Time
	Cursor         int
	Limit          int
	Projection     string
	IncludeDropped bool
}

type ValueQuery struct {
	Term       string
	Hash       string
	Role       string
	DataType   string
	SessionID  string
	FlowID     string
	Type       event.Type
	Limit      int
	Projection string
}

type QueryResult struct {
	Events     []map[string]any `json:"events"`
	NextCursor int              `json:"nextCursor,omitempty"`
	Matched    int              `json:"matched"`
	Truncated  bool             `json:"truncated"`
}

// EventIndex is a bounded in-memory index intended for the MCP/AI host. The
// device Agent can stream events into it through JSONL or a transport adapter.
// It is deliberately bounded so a noisy target cannot exhaust host memory.
type EventIndex struct {
	mu        sync.RWMutex
	maxEvents int
	events    []event.Event
	redactor  *Redactor
}

func NewEventIndex(maxEvents int) *EventIndex {
	if maxEvents < 1 {
		maxEvents = 10000
	}
	return &EventIndex{maxEvents: maxEvents, redactor: NewRedactor(nil)}
}

func (i *EventIndex) Add(e event.Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.events = append(i.events, e)
	if len(i.events) > i.maxEvents {
		i.events = append([]event.Event(nil), i.events[len(i.events)-i.maxEvents:]...)
	}
	return nil
}

func (i *EventIndex) Len() int {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return len(i.events)
}

func (i *EventIndex) Query(q EventQuery) (QueryResult, error) {
	if q.Cursor < 0 {
		return QueryResult{}, fmt.Errorf("cursor must not be negative")
	}
	if q.Limit < 0 {
		return QueryResult{}, fmt.Errorf("limit must not be negative")
	}
	if q.Limit == 0 {
		q.Limit = 100
	}
	projection := strings.ToLower(strings.TrimSpace(q.Projection))
	if projection == "" {
		projection = "summary"
	}
	if projection != "summary" && projection != "stacks" && projection != "crypto" && projection != "network" && projection != "full" {
		return QueryResult{}, fmt.Errorf("unsupported projection %q", q.Projection)
	}

	i.mu.RLock()
	matched := make([]event.Event, 0)
	for _, e := range i.events {
		if !q.IncludeDropped && e.Dropped {
			continue
		}
		if q.SessionID != "" && e.SessionID != q.SessionID {
			continue
		}
		if q.FlowID != "" && e.FlowID != q.FlowID {
			continue
		}
		if q.RequestID != "" && e.RequestID != q.RequestID {
			continue
		}
		if q.Type != "" && e.Type != q.Type {
			continue
		}
		if q.Operation != "" && !strings.Contains(strings.ToLower(e.Operation), strings.ToLower(q.Operation)) {
			continue
		}
		if !q.Since.IsZero() && e.Timestamp.Before(q.Since) {
			continue
		}
		if !q.Until.IsZero() && e.Timestamp.After(q.Until) {
			continue
		}
		matched = append(matched, e)
	}
	i.mu.RUnlock()

	// EventBus order is normally chronological, but sorting here makes a query
	// deterministic after merging streams from multiple processes.
	sort.SliceStable(matched, func(a, b int) bool { return matched[a].Timestamp.Before(matched[b].Timestamp) })
	result := QueryResult{Matched: len(matched)}
	start := q.Cursor
	if start > len(matched) {
		start = len(matched)
	}
	end := start + q.Limit
	if end > len(matched) {
		end = len(matched)
	}
	result.Truncated = end < len(matched)
	if result.Truncated {
		result.NextCursor = end
	}
	for _, e := range matched[start:end] {
		result.Events = append(result.Events, ProjectEvent(e, projection, i.redactor))
	}
	return result, nil
}

// FindValues searches only derived identifiers and value references. It never
// performs a substring search over raw arguments/results, which keeps a
// credential from becoming searchable plaintext in the host index.
func (i *EventIndex) FindValues(q ValueQuery) (QueryResult, error) {
	if q.Limit < 0 {
		return QueryResult{}, fmt.Errorf("limit must not be negative")
	}
	if q.Limit == 0 {
		q.Limit = 100
	}
	projection := strings.ToLower(strings.TrimSpace(q.Projection))
	if projection == "" {
		projection = "full"
	}
	if projection != "summary" && projection != "stacks" && projection != "crypto" && projection != "network" && projection != "full" {
		return QueryResult{}, fmt.Errorf("unsupported projection %q", q.Projection)
	}
	term := strings.ToLower(strings.TrimSpace(q.Term))
	hash := strings.ToLower(strings.TrimSpace(q.Hash))
	role := strings.ToLower(strings.TrimSpace(q.Role))
	dataType := strings.ToLower(strings.TrimSpace(q.DataType))
	i.mu.RLock()
	matched := make([]event.Event, 0)
	for _, e := range i.events {
		if q.SessionID != "" && e.SessionID != q.SessionID {
			continue
		}
		if q.FlowID != "" && e.FlowID != q.FlowID {
			continue
		}
		if q.Type != "" && e.Type != q.Type {
			continue
		}
		if valueMatches(e, term, hash, role, dataType) {
			matched = append(matched, e)
		}
	}
	i.mu.RUnlock()
	sort.SliceStable(matched, func(a, b int) bool { return matched[a].Timestamp.Before(matched[b].Timestamp) })
	result := QueryResult{Matched: len(matched), Truncated: len(matched) > q.Limit}
	if result.Truncated {
		matched = matched[:q.Limit]
		result.NextCursor = q.Limit
	}
	for _, e := range matched {
		result.Events = append(result.Events, ProjectEvent(e, projection, i.redactor))
	}
	return result, nil
}

func valueMatches(e event.Event, term, hash, role, dataType string) bool {
	for _, ref := range e.ValueRefs {
		if hash != "" && !strings.EqualFold(strings.TrimSpace(ref.Hash), hash) {
			continue
		}
		if role != "" && !strings.EqualFold(strings.TrimSpace(ref.Role), role) {
			continue
		}
		if dataType != "" && !strings.EqualFold(strings.TrimSpace(ref.DataType), dataType) {
			continue
		}
		if term != "" && !containsFold(term, ref.Name, ref.Hash, ref.Role, ref.DataType, ref.SourceEventID) {
			continue
		}
		return true
	}
	// Derived profiles have no role or dataType. Do not let them satisfy a
	// constrained reference query merely because their hash also matches.
	if e.Analysis != nil && role == "" && dataType == "" {
		for _, profile := range append(append([]event.ValueAnalysis{}, e.Analysis.Arguments...), e.Analysis.Result...) {
			if hash != "" && !strings.EqualFold(strings.TrimSpace(profile.SHA256), hash) {
				continue
			}
			if term != "" && !containsFold(term, profile.Path, profile.SHA256, profile.Encoding, profile.MagicBytes) {
				continue
			}
			return true
		}
	}
	return false
}

func containsFold(term string, values ...string) bool {
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), term) {
			return true
		}
	}
	return false
}

func ProjectEvent(e event.Event, projection string, redactor *Redactor) map[string]any {
	if redactor == nil {
		redactor = NewRedactor(nil)
	}
	view := map[string]any{
		"eventId":       e.EventID,
		"sessionId":     e.SessionID,
		"timestamp":     e.Timestamp,
		"flowId":        e.FlowID,
		"requestId":     e.RequestID,
		"parentEventId": e.ParentEventID,
		"type":          e.Type,
		"layer":         e.Layer,
		"operation":     e.Operation,
		"target":        e.Target,
		"confidence":    e.Confidence,
		"evidence":      e.Evidence,
		"sensitivity":   e.Sensitivity,
	}
	switch projection {
	case "stacks":
		view["nativeStack"] = e.NativeStack
		view["jsStack"] = e.JSStack
	case "crypto":
		view["arguments"] = redactor.Value(e.Arguments)
		view["result"] = redactor.Value(e.Result)
		view["analysis"] = e.Analysis
		view["valueRefs"] = e.ValueRefs
	case "network":
		view["arguments"] = redactor.Value(e.Arguments)
		view["result"] = redactor.Value(e.Result)
		view["analysis"] = e.Analysis
		view["valueRefs"] = e.ValueRefs
	case "full":
		view["arguments"] = redactor.Value(e.Arguments)
		view["result"] = redactor.Value(e.Result)
		view["analysis"] = e.Analysis
		view["nativeStack"] = e.NativeStack
		view["jsStack"] = e.JSStack
		view["valueRefs"] = e.ValueRefs
		view["tags"] = e.Tags
		view["dropped"] = e.Dropped
	}
	return view
}
