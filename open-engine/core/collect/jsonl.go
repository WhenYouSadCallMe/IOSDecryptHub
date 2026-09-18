// Package collect contains the desktop-side event sinks. JSONL is the first
// durable format because it is streamable, inspectable and does not require a
// native database dependency in the iOS Agent.
package collect

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"iosruntimeassistant/core/event"
)

var ErrClosed = errors.New("jsonl sink is closed")

type Stats struct {
	Written uint64 `json:"written"`
	Bytes   uint64 `json:"bytes"`
	Failed  uint64 `json:"failed"`
}

type JSONLSink struct {
	mu     sync.Mutex
	w      *bufio.Writer
	close  func() error
	closed bool
	stats  Stats
}

func NewJSONLSink(w io.Writer) *JSONLSink {
	return &JSONLSink{w: bufio.NewWriter(w)}
}

// NewJSONLSinkWithCloser is used when the sink owns a file or socket. Close
// flushes buffered bytes before invoking the supplied closer.
func NewJSONLSinkWithCloser(w io.Writer, closeFn func() error) *JSONLSink {
	s := NewJSONLSink(w)
	s.close = closeFn
	return s
}

func (s *JSONLSink) Write(ctx context.Context, e event.Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("encode event: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	n, err := s.w.Write(append(b, '\n'))
	if err != nil {
		s.stats.Failed++
		return fmt.Errorf("write event: %w", err)
	}
	s.stats.Written++
	s.stats.Bytes += uint64(n)
	return nil
}

func (s *JSONLSink) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	return s.w.Flush()
}

func (s *JSONLSink) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

func (s *JSONLSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	flushErr := s.w.Flush()
	if s.close == nil {
		return flushErr
	}
	closeErr := s.close()
	if flushErr != nil {
		return flushErr
	}
	return closeErr
}

// Tee subscribes to a Bus and writes events until ctx is cancelled. It returns
// the first sink error; cancellation is treated as a clean stop.
func Tee(ctx context.Context, sub event.Subscription, sink *JSONLSink) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case e, ok := <-sub.C:
			if !ok {
				return nil
			}
			if err := sink.Write(ctx, e); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return nil
				}
				return err
			}
		}
	}
}

// ParseLines is deliberately small and strict: malformed lines are reported
// with their line number instead of being silently skipped.
func ParseLines(r io.Reader, fn func(event.Event) error) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 4*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		var e event.Event
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			return fmt.Errorf("parse JSONL line %d: %w", line, err)
		}
		if err := e.Validate(); err != nil {
			return fmt.Errorf("validate JSONL line %d: %w", line, err)
		}
		if fn != nil {
			if err := fn(e); err != nil {
				return err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read JSONL: %w", err)
	}
	return nil
}

func NormalizeOperation(operation string) string {
	return strings.TrimSpace(strings.ToLower(operation))
}
