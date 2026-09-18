package collect

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"iosruntimeassistant/core/analysis"
	"iosruntimeassistant/core/event"
	"iosruntimeassistant/core/session"
)

// Ingestor is the recommended host-side event path. It applies the session
// guard, flow correlation and bounded deduplication before putting an event in
// the query index. Each stage is optional so historical JSONL imports can use
// the same type without pretending that an active device session exists.
type Ingestor struct {
	Index        *EventIndex
	Correlator   *analysis.FlowCorrelator
	Deduplicator *analysis.Deduplicator
	Guard        *session.Guard
}

type IngestResult struct {
	Event       event.Event          `json:"event"`
	Correlation analysis.Correlation `json:"correlation"`
	Decision    *session.Decision    `json:"decision,omitempty"`
	Emitted     bool                 `json:"emitted"`
	Repeat      uint64               `json:"repeat"`
}

func NewIngestor(index *EventIndex, correlator *analysis.FlowCorrelator, deduplicator *analysis.Deduplicator, guard *session.Guard) *Ingestor {
	if index == nil {
		index = NewEventIndex(10000)
	}
	return &Ingestor{Index: index, Correlator: correlator, Deduplicator: deduplicator, Guard: guard}
}

func (i *Ingestor) Ingest(ctx context.Context, e event.Event) (IngestResult, error) {
	if err := e.Validate(); err != nil {
		return IngestResult{}, err
	}
	select {
	case <-ctx.Done():
		return IngestResult{}, ctx.Err()
	default:
	}
	result := IngestResult{Event: e, Repeat: 1}
	if i.Guard != nil {
		decision := i.Guard.Check(e, time.Now().UTC())
		result.Decision = &decision
		if !decision.Allowed {
			return result, fmt.Errorf("session guard rejected event: %v", decision.Reasons)
		}
	}
	if i.Correlator != nil {
		correlated, correlation, err := i.Correlator.Correlate(e)
		if err != nil {
			return result, err
		}
		e = correlated
		result.Event = e
		result.Correlation = correlation
	}
	e = analysis.AnnotateEvent(e)
	result.Event = e
	if i.Deduplicator != nil {
		emit, repeat := i.Deduplicator.Observe(e)
		result.Emitted = emit
		result.Repeat = repeat
		if !emit {
			return result, nil
		}
		if repeat > 1 {
			e.Tags = append(e.Tags, "repeat:"+strconv.FormatUint(repeat, 10))
			result.Event = e
		}
	}
	if err := i.Index.Add(e); err != nil {
		return result, err
	}
	result.Emitted = true
	return result, nil
}
