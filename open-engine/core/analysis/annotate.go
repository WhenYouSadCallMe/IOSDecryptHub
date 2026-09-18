package analysis

import (
	"sort"
	"strings"

	"iosruntimeassistant/core/event"
)

const defaultAnalysisItems = 64

// AnnotateEvent adds derived byte metadata to an event without copying raw
// values into a new field. It is useful immediately before indexing so an AI
// can distinguish a Base64 payload, a gzip body and a high-entropy binary
// value while the redactor still controls the original arguments/result.
func AnnotateEvent(e event.Event) event.Event {
	return AnnotateEventWithLimit(e, defaultAnalysisItems)
}

func AnnotateEventWithLimit(e event.Event, limit int) event.Event {
	if limit < 1 {
		limit = defaultAnalysisItems
	}
	analysis := &event.EventAnalysis{}
	analysis.Arguments = profileValue(e.Arguments, "arguments", "", limit)
	analysis.Result = profileValue(e.Result, "result", "", limit)
	if len(analysis.Arguments) == 0 && len(analysis.Result) == 0 {
		e.Analysis = nil
	} else {
		e.Analysis = analysis
	}
	return e
}

func profileValue(value any, path, role string, limit int) []event.ValueAnalysis {
	result := make([]event.ValueAnalysis, 0)
	var visit func(any, string, string)
	visit = func(current any, currentPath, currentRole string) {
		if len(result) >= limit {
			return
		}
		switch typed := current.(type) {
		case []byte:
			profile := ProfileBytes(typed)
			profile.Preview = ""
			result = append(result, event.ValueAnalysis{
				Path: currentPath, Role: currentRole, Length: profile.Length,
				SHA256: profile.SHA256, Entropy: profile.Entropy,
				MagicBytes: profile.MagicBytes, Encoding: profile.Encoding,
			})
		case string:
			if !isProfileCandidate(currentPath, typed) {
				return
			}
			profile := ProfileBytes([]byte(typed))
			profile.Preview = ""
			result = append(result, event.ValueAnalysis{
				Path: currentPath, Role: currentRole, Length: profile.Length,
				SHA256: profile.SHA256, Entropy: profile.Entropy,
				MagicBytes: profile.MagicBytes, Encoding: profile.Encoding,
			})
		case map[string]any:
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				nextPath := currentPath + "." + key
				nextRole := key
				visit(typed[key], nextPath, nextRole)
			}
		case []any:
			for index, item := range typed {
				visit(item, currentPath+"["+itoa(index)+"]", currentRole)
			}
		case []map[string]any:
			for index, item := range typed {
				visit(item, currentPath+"["+itoa(index)+"]", currentRole)
			}
		}
	}
	visit(value, path, role)
	return result
}

func isProfileCandidate(path, value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 8 {
		return false
	}
	encoding := GuessEncoding([]byte(value))
	if encoding == "hex-text" || encoding == "base64-text" {
		return true
	}
	path = strings.ToLower(path)
	for _, marker := range []string{"body", "payload", "cipher", "plain", "signature", "digest", "token", "key", "iv", "data"} {
		if strings.Contains(path, marker) {
			return true
		}
	}
	return false
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}
