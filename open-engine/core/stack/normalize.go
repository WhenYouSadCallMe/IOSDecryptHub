// Package stack normalizes runtime frames for offline symbolization tools.
// It never resolves or executes symbols; it only calculates stable addresses
// from the ASLR slide reported by the agent.
package stack

import (
	"fmt"
	"strings"

	"iosruntimeassistant/core/event"
	"iosruntimeassistant/core/macho"
)

type Frame struct {
	Address       uint64 `json:"address"`
	IDAAddress    uint64 `json:"idaAddress,omitempty"`
	Slide         uint64 `json:"slide,omitempty"`
	Image         string `json:"image,omitempty"`
	Symbol        string `json:"symbol,omitempty"`
	Normalized    string `json:"normalized,omitempty"`
	Unresolved    bool   `json:"unresolved,omitempty"`
	ConversionErr string `json:"conversionError,omitempty"`
}

func NormalizeNative(frames []event.StackFrame, slide uint64) []Frame {
	result := make([]Frame, 0, len(frames))
	for _, frame := range frames {
		normalized := Frame{
			Address: frame.Address,
			Slide:   slide,
			Image:   strings.TrimSpace(frame.Image),
			Symbol:  strings.TrimSpace(frame.Symbol),
		}
		if frame.Address >= slide {
			normalized.IDAAddress = frame.Address - slide
			normalized.Normalized = fmt.Sprintf("%s!0x%x", normalized.Image, normalized.IDAAddress)
		} else {
			normalized.Unresolved = true
			normalized.ConversionErr = fmt.Sprintf("runtime address 0x%x is below slide 0x%x", frame.Address, slide)
		}
		if normalized.Symbol != "" {
			normalized.Normalized += " " + normalized.Symbol
		}
		result = append(result, normalized)
	}
	return result
}

func NormalizeASLRAddress(runtimeAddress uint64, slide uint64) (uint64, error) {
	return macho.IDAAddress(runtimeAddress, slide)
}
