package event

import (
	"context"
	"errors"
	"sync"
)

var (
	ErrClosed       = errors.New("event bus is closed")
	ErrSubscription = errors.New("invalid subscription")
)

type Subscription struct {
	ID uint64
	C  <-chan Event

	cancel func()
}

func (s Subscription) Cancel() {
	if s.cancel != nil {
		s.cancel()
	}
}

type BusStats struct {
	Subscribers uint64
	Published   uint64
	Delivered   uint64
	Dropped     uint64
}

type Bus struct {
	mu          sync.RWMutex
	subscribers map[uint64]*subscriber
	nextID      uint64
	closed      bool
	stats       BusStats
}

type subscriber struct {
	mu     sync.Mutex
	ch     chan Event
	closed bool
}

func (s *subscriber) send(ctx context.Context, e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrSubscription
	}
	select {
	case s.ch <- e:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *subscriber) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.ch)
	}
}

func NewBus() *Bus {
	return &Bus{subscribers: make(map[uint64]*subscriber)}
}

func (b *Bus) Subscribe(buffer int) (Subscription, error) {
	if buffer < 1 {
		buffer = 1
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return Subscription{}, ErrClosed
	}
	b.nextID++
	id := b.nextID
	s := &subscriber{ch: make(chan Event, buffer)}
	b.subscribers[id] = s
	b.stats.Subscribers = uint64(len(b.subscribers))
	return Subscription{
		ID: id,
		C:  s.ch,
		cancel: func() {
			b.unsubscribe(id)
		},
	}, nil
}

func (b *Bus) unsubscribe(id uint64) {
	b.mu.Lock()
	s, ok := b.subscribers[id]
	if !ok {
		b.mu.Unlock()
		return
	}
	delete(b.subscribers, id)
	b.stats.Subscribers = uint64(len(b.subscribers))
	b.mu.Unlock()
	s.close()
}

// Publish applies backpressure using ctx. A subscriber is removed only when
// it explicitly cancels; a slow subscriber therefore makes the publisher
// wait instead of silently losing an event.
func (b *Bus) Publish(ctx context.Context, e Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return ErrClosed
	}
	subscribers := make([]*subscriber, 0, len(b.subscribers))
	for _, s := range b.subscribers {
		subscribers = append(subscribers, s)
	}
	b.mu.RUnlock()

	delivered := 0
	for _, s := range subscribers {
		if err := s.send(ctx, e); err != nil {
			if errors.Is(err, ErrSubscription) {
				continue
			}
			b.mu.Lock()
			b.stats.Dropped++
			b.mu.Unlock()
			return ctx.Err()
		}
		delivered++
	}
	b.mu.Lock()
	b.stats.Published++
	b.stats.Delivered += uint64(delivered)
	b.mu.Unlock()
	return nil
}

func (b *Bus) Stats() BusStats {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.stats
}

func (b *Bus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	subscribers := make([]*subscriber, 0, len(b.subscribers))
	for id, s := range b.subscribers {
		subscribers = append(subscribers, s)
		delete(b.subscribers, id)
	}
	b.stats.Subscribers = 0
	for _, s := range subscribers {
		s.close()
	}
}
