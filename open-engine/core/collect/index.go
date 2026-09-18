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
