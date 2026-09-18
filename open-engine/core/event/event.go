// Package event defines the transport-neutral event contract shared by the
// iOS agent, desktop collector and MCP server.
package event

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const CurrentSchemaVersion = 1

type Type string

const (
	TypeCrypto     Type = "crypto"
	TypeNetwork    Type = "network"
	TypeStorage    Type = "storage"
	TypeBridge     Type = "bridge"
	TypeJavaScript Type = "js"
	TypeMemory     Type = "memory"
	TypeSystem     Type = "system"
)

type Sensitivity string

const (
	SensitivityPublic Sensitivity = "public"
	SensitivityMasked Sensitivity = "masked"
	SensitivitySecret Sensitivity = "secret"
)

type Target struct {
	BundleID string `json:"bundleId,omitempty"`
	PID      int    `json:"pid,omitempty"`
	TID      uint64 `json:"tid,omitempty"`
	Image    string `json:"image,omitempty"`
}

type StackFrame struct {
	Address uint64 `json:"address,omitempty"`
	Image   string `json:"image,omitempty"`
	Symbol  string `json:"symbol,omitempty"`
	Offset  uint64 `json:"offset,omitempty"`
	File    string `json:"file,omitempty"`
	Line    int    `json:"line,omitempty"`
}

type ValueRef struct {
	Name          string `json:"name,omitempty"`
	Hash          string `json:"hash,omitempty"`
	Length        int    `json:"length,omitempty"`
	DataType      string `json:"dataType,omitempty"`
	Role          string `json:"role,omitempty"`
	SourceEventID string `json:"sourceEventId,omitempty"`
}

type Evidence struct {
	Source     string `json:"source,omitempty"`
	Freshness  string `json:"freshness,omitempty"`
	TTLSeconds int    `json:"ttlSeconds,omitempty"`
}

// ValueAnalysis contains derived byte metadata only. It intentionally has no
// raw payload field, so adding profiling to an event cannot accidentally turn
// the event stream into a credential dump.
type ValueAnalysis struct {
	Path       string  `json:"path"`
	Role       string  `json:"role,omitempty"`
	Length     int     `json:"length"`
	SHA256     string  `json:"sha256"`
	Entropy    float64 `json:"entropy"`
	MagicBytes string  `json:"magicBytes,omitempty"`
	Encoding   string  `json:"encoding"`
}

type EventAnalysis struct {
	Arguments []ValueAnalysis `json:"arguments,omitempty"`
	Result    []ValueAnalysis `json:"result,omitempty"`
}

// Event is deliberately transport-neutral. Arguments and Result are kept as
// JSON values so that native and JavaScript observers can use the same schema
// without embedding platform-specific types in the collector.
type Event struct {
	SchemaVersion int            `json:"schemaVersion"`
	EventID       string         `json:"eventId"`
	SessionID     string         `json:"sessionId,omitempty"`
	Timestamp     time.Time      `json:"timestamp"`
	Target        Target         `json:"target"`
	ASLRSlide     string         `json:"aslrSlide,omitempty"`
	FlowID        string         `json:"flowId,omitempty"`
	RequestID     string         `json:"requestId,omitempty"`
	ParentEventID string         `json:"parentEventId,omitempty"`
	Layer         string         `json:"layer,omitempty"`
	Type          Type           `json:"type"`
	Operation     string         `json:"operation"`
	Arguments     any            `json:"arguments,omitempty"`
	Result        any            `json:"result,omitempty"`
	NativeStack   []StackFrame   `json:"nativeStack,omitempty"`
	JSStack       []StackFrame   `json:"jsStack,omitempty"`
	ValueRefs     []ValueRef     `json:"valueRefs,omitempty"`
	Tags          []string       `json:"tags,omitempty"`
	Confidence    float64        `json:"confidence,omitempty"`
	Evidence      *Evidence      `json:"evidence,omitempty"`
	Analysis      *EventAnalysis `json:"analysis,omitempty"`
	Sensitivity   Sensitivity    `json:"sensitivity"`
	Dropped       bool           `json:"dropped,omitempty"`
}

func NewID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func New(typ Type, operation string, target Target) (Event, error) {
	id, err := NewID()
	if err != nil {
		return Event{}, err
	}
	return Event{
		SchemaVersion: CurrentSchemaVersion,
		EventID:       id,
		Timestamp:     time.Now().UTC(),
		Target:        target,
		Type:          typ,
		Operation:     operation,
		Sensitivity:   SensitivityMasked,
	}, nil
}

func (e Event) Validate() error {
	if e.SchemaVersion != CurrentSchemaVersion {
		return fmt.Errorf("unsupported schemaVersion %d", e.SchemaVersion)
	}
	if strings.TrimSpace(e.EventID) == "" {
		return errors.New("eventId is required")
	}
	if e.Timestamp.IsZero() {
		return errors.New("timestamp is required")
	}
	if strings.TrimSpace(string(e.Type)) == "" {
		return errors.New("type is required")
	}
	if strings.TrimSpace(e.Operation) == "" {
		return errors.New("operation is required")
	}
	if e.Confidence < 0 || e.Confidence > 1 {
		return errors.New("confidence must be between 0 and 1")
	}
	switch e.Sensitivity {
	case SensitivityPublic, SensitivityMasked, SensitivitySecret:
	default:
		return fmt.Errorf("invalid sensitivity %q", e.Sensitivity)
	}
	return nil
}

func (e Event) MarshalJSON() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	type alias Event
	return json.Marshal(alias(e))
}
