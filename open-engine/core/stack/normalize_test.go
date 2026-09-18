package stack

import (
	"strings"
	"testing"

	"iosruntimeassistant/core/event"
)

func TestNormalizeNativeFrames(t *testing.T) {
	frames := NormalizeNative([]event.StackFrame{{Address: 0x100012340, Image: "App", Symbol: "encrypt"}, {Address: 1, Image: "App"}}, 0x100000000)
	if len(frames) != 2 || frames[0].IDAAddress != 0x12340 || !strings.Contains(frames[0].Normalized, "encrypt") {
		t.Fatalf("unexpected normalized frames: %+v", frames)
	}
	if !frames[1].Unresolved || frames[1].ConversionErr == "" {
		t.Fatalf("expected unresolved frame: %+v", frames[1])
	}
}
