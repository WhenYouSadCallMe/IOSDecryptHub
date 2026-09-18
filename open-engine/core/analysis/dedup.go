package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"iosruntimeassistant/core/event"
)

type DedupStats struct {
	Emitted    uint64 `json:"emitted"`
	Suppressed uint64 `json:"suppressed"`
}

type dedupEntry struct {
	last  time.Time
	count uint64
}

// Deduplicator suppresses identical high-frequency events during a bounded
// time window. It preserves the first event and exposes a repeat count to the
// collector, so deduplication never erases the fact that an operation ran.
type Deduplicator struct {
	mu         sync.Mutex
	window     time.Duration
	maxEntries int
	seen       map[string]dedupEntry
	stats      DedupStats
}

func NewDeduplicator(window time.Duration, maxEntries int) *Deduplicator {
	if window <= 0 {
		window = 2 * time.Second
	}
	if maxEntries < 1 {
		maxEntries = 4096
	}
	return &Deduplicator{window: window, maxEntries: maxEntries, seen: make(map[string]dedupEntry)}
}

// Observe returns emit=true for a new event or an event outside the window.
// repeat is the number of occurrences represented by the emitted event.
func (d *Deduplicator) Observe(e event.Event) (emit bool, repeat uint64) {
	now := e.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}
	key := eventFingerprint(e)
	d.mu.Lock()
	defer d.mu.Unlock()
	if previous, ok := d.seen[key]; ok && now.Sub(previous.last) >= 0 && now.Sub(previous.last) < d.window {
		previous.last = now
		previous.count++
		d.seen[key] = previous
		d.stats.Suppressed++
		return false, previous.count
	}
	if len(d.seen) >= d.maxEntries {
		d.evictOldest()
	}
	d.seen[key] = dedupEntry{last: now, count: 1}
	d.stats.Emitted++
	return true, 1
}

func (d *Deduplicator) Stats() DedupStats {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stats
}

func (d *Deduplicator) evictOldest() {
	var oldestKey string
	var oldest time.Time
	for key, entry := range d.seen {
		if oldestKey == "" || entry.last.Before(oldest) {
			oldestKey, oldest = key, entry.last
		}
	}
	if oldestKey != "" {
		delete(d.seen, oldestKey)
	}
}

func eventFingerprint(e event.Event) string {
	// Exclude event identity, timestamp and stacks: those vary per invocation,
	// while operation/value identity is what noise filtering needs.
	payload := struct {
		Target    event.Target     `json:"target"`
		FlowID    string           `json:"flowId,omitempty"`
		RequestID string           `json:"requestId,omitempty"`
		Type      event.Type       `json:"type"`
		Operation string           `json:"operation"`
		Arguments any              `json:"arguments,omitempty"`
		Result    any              `json:"result,omitempty"`
		ValueRefs []event.ValueRef `json:"valueRefs,omitempty"`
	}{e.Target, e.FlowID, e.RequestID, e.Type, e.Operation, e.Arguments, e.Result, e.ValueRefs}
	b, _ := json.Marshal(payload)
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:])
}
