package hook

import (
	"errors"
	"testing"

	"iosruntimeassistant/core/profile"
)

func objcSpec(id string) profile.HookSpec {
	return profile.HookSpec{
		ID:   id,
		Type: profile.HookObjectiveC,
		Target: profile.Target{
			Class:    "NSURLSessionTask",
			Selector: "resume",
		},
		Capture: []string{"arguments", "stack"},
	}
}

func TestRegistryLifecycle(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(objcSpec("network.resume")); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(objcSpec("network.resume")); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("expected duplicate, got %v", err)
	}
	if err := r.SetEnabled("network.resume", false); err != nil {
		t.Fatal(err)
	}
	entry, ok := r.Get("network.resume")
	if !ok || entry.State != StateDisabled {
		t.Fatalf("unexpected entry: %+v %v", entry, ok)
	}
	if err := r.Unregister("network.resume"); err != nil {
		t.Fatal(err)
	}
	if err := r.Unregister("network.resume"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestRegisterProfileIsAtomic(t *testing.T) {
	r := NewRegistry()
	p := profile.Profile{
		SchemaVersion: profile.CurrentSchemaVersion,
		Name:          "atomic",
		Hooks:         []profile.HookSpec{objcSpec("ok"), {ID: "bad", Type: "unknown"}},
	}
	if err := r.RegisterProfile(p); err == nil {
		t.Fatal("expected profile validation error")
	}
	if got := len(r.Snapshot()); got != 0 {
		t.Fatalf("profile was partially installed: %d entries", got)
	}
}
