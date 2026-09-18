// Package hook implements the host-side Hook Registry contract. The iOS
// implementation will translate the same IDs into fishhook/ObjC/Swift
// adapters; keeping registration state here makes profiles testable on any OS.
package hook

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"iosruntimeassistant/core/profile"
)

var (
	ErrDuplicate = errors.New("hook already registered")
	ErrNotFound  = errors.New("hook not found")
)

type State string

const (
	StateEnabled  State = "enabled"
	StateDisabled State = "disabled"
)

type Entry struct {
	Spec       profile.HookSpec `json:"spec"`
	State      State            `json:"state"`
	Generation uint64           `json:"generation"`
}

type Registry struct {
	mu         sync.RWMutex
	entries    map[string]Entry
	generation uint64
}

func NewRegistry() *Registry {
	return &Registry{entries: make(map[string]Entry)}
}

func (r *Registry) Register(spec profile.HookSpec) error {
	if strings.TrimSpace(spec.ID) == "" {
		return errors.New("hook id is required")
	}
	if err := (profile.Profile{SchemaVersion: profile.CurrentSchemaVersion, Name: "single", Hooks: []profile.HookSpec{spec}}).Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.entries[spec.ID]; ok {
		return fmt.Errorf("%w: %s", ErrDuplicate, spec.ID)
	}
	r.generation++
	state := StateEnabled
	if spec.Enabled != nil && !*spec.Enabled {
		state = StateDisabled
	}
	r.entries[spec.ID] = Entry{Spec: spec, State: state, Generation: r.generation}
	return nil
}

// RegisterProfile validates the complete profile before modifying the
// registry, so a bad entry cannot leave a partially installed profile.
func (r *Registry) RegisterProfile(p profile.Profile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(p.Hooks))
	for _, spec := range p.Hooks {
		if _, ok := seen[spec.ID]; ok {
			return fmt.Errorf("%w: %s", ErrDuplicate, spec.ID)
		}
		seen[spec.ID] = struct{}{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, spec := range p.Hooks {
		if _, ok := r.entries[spec.ID]; ok {
			return fmt.Errorf("%w: %s", ErrDuplicate, spec.ID)
		}
	}
	for _, spec := range p.Hooks {
		r.generation++
		state := StateEnabled
		if spec.Enabled != nil && !*spec.Enabled {
			state = StateDisabled
		}
		r.entries[spec.ID] = Entry{Spec: spec, State: state, Generation: r.generation}
	}
	return nil
}

func (r *Registry) SetEnabled(id string, enabled bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if enabled {
		entry.State = StateEnabled
	} else {
		entry.State = StateDisabled
	}
	r.generation++
	entry.Generation = r.generation
	r.entries[id] = entry
	return nil
}

func (r *Registry) Unregister(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.entries[id]; !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	delete(r.entries, id)
	r.generation++
	return nil
}

func (r *Registry) Get(id string) (Entry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.entries[id]
	return entry, ok
}

func (r *Registry) Snapshot() []Entry {
	r.mu.RLock()
	entries := make([]Entry, 0, len(r.entries))
	for _, entry := range r.entries {
		entries = append(entries, entry)
	}
	r.mu.RUnlock()
	sort.Slice(entries, func(i, j int) bool { return entries[i].Spec.ID < entries[j].Spec.ID })
	return entries
}
