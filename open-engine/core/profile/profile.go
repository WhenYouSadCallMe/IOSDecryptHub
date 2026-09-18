// Package profile contains the data-driven HookSpec contract. It intentionally
// uses JSON in the first increment so the host has no external dependency;
// YAML support can be added later without changing the in-memory model.
package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

const CurrentSchemaVersion = 1

type HookType string

const (
	HookCImport      HookType = "c-import"
	HookObjectiveC   HookType = "objc"
	HookSwiftSymbol  HookType = "swift-symbol"
	HookJavaScript   HookType = "js"
	HookNotification HookType = "notification"
)

type Target struct {
	Image    string `json:"image,omitempty"`
	Class    string `json:"class,omitempty"`
	Selector string `json:"selector,omitempty"`
	Symbol   string `json:"symbol,omitempty"`
	Script   string `json:"script,omitempty"`
}

type Filter struct {
	Expression string `json:"expression,omitempty"`
}

type HookSpec struct {
	ID         string            `json:"id"`
	Type       HookType          `json:"type"`
	Target     Target            `json:"target"`
	Capture    []string          `json:"capture,omitempty"`
	Filter     *Filter           `json:"filter,omitempty"`
	Redact     []string          `json:"redact,omitempty"`
	SampleRate float64           `json:"sampleRate,omitempty"`
	Enabled    *bool             `json:"enabled,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type Profile struct {
	SchemaVersion int        `json:"schemaVersion"`
	Name          string     `json:"name"`
	Mode          string     `json:"mode,omitempty"`
	Hooks         []HookSpec `json:"hooks"`
}

func Load(data []byte) (Profile, error) {
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return Profile{}, fmt.Errorf("decode profile: %w", err)
	}
	if err := p.Validate(); err != nil {
		return Profile{}, err
	}
	return p, nil
}

func LoadFile(path string) (Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, fmt.Errorf("read profile %q: %w", path, err)
	}
	return Load(data)
}

func (p Profile) Validate() error {
	if p.SchemaVersion != CurrentSchemaVersion {
		return fmt.Errorf("unsupported schemaVersion %d", p.SchemaVersion)
	}
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("profile name is required")
	}
	seen := make(map[string]struct{}, len(p.Hooks))
	for i, h := range p.Hooks {
		if strings.TrimSpace(h.ID) == "" {
			return fmt.Errorf("hooks[%d].id is required", i)
		}
		if _, ok := seen[h.ID]; ok {
			return fmt.Errorf("duplicate hook id %q", h.ID)
		}
		seen[h.ID] = struct{}{}
		if !validType(h.Type) {
			return fmt.Errorf("hooks[%d] has unsupported type %q", i, h.Type)
		}
		if h.SampleRate < 0 || h.SampleRate > 1 {
			return fmt.Errorf("hooks[%d].sampleRate must be between 0 and 1", i)
		}
		if err := validateTarget(h); err != nil {
			return fmt.Errorf("hooks[%d]: %w", i, err)
		}
	}
	return nil
}

func validType(t HookType) bool {
	switch t {
	case HookCImport, HookObjectiveC, HookSwiftSymbol, HookJavaScript, HookNotification:
		return true
	default:
		return false
	}
}

func validateTarget(h HookSpec) error {
	switch h.Type {
	case HookCImport, HookSwiftSymbol:
		if strings.TrimSpace(h.Target.Symbol) == "" {
			return errors.New("target.symbol is required")
		}
	case HookObjectiveC:
		if strings.TrimSpace(h.Target.Class) == "" || strings.TrimSpace(h.Target.Selector) == "" {
			return errors.New("target.class and target.selector are required")
		}
	case HookJavaScript:
		if strings.TrimSpace(h.Target.Script) == "" {
			return errors.New("target.script is required")
		}
	case HookNotification:
		if strings.TrimSpace(h.Target.Image) == "" {
			return errors.New("target.image is required")
		}
	}
	return nil
}
