package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"regexp"
	"strings"
)

type Redactor struct {
	keys    map[string]struct{}
	pattern *regexp.Regexp
}

func NewRedactor(keys []string) *Redactor {
	set := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		key = strings.ToLower(strings.TrimSpace(key))
		if key != "" {
			set[key] = struct{}{}
		}
	}
	// The pattern is intentionally conservative: it catches common credential
	// labels without treating arbitrary business strings as secrets.
	return &Redactor{
		keys:    set,
		pattern: regexp.MustCompile(`(?i)(authorization|cookie|set-cookie|password|passwd|secret|token|api[-_]?key|verify[-_]?code)`),
	}
}

func (r *Redactor) KeyIsSensitive(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	if _, ok := r.keys[key]; ok {
		return true
	}
	return r.pattern != nil && r.pattern.MatchString(key)
}

func (r *Redactor) Value(value any) any {
	return r.value(value, false)
}

func (r *Redactor) value(value any, force bool) any {
	if force {
		return Masked(value)
	}
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = r.value(item, r.KeyIsSensitive(key))
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = r.value(item, false)
		}
		return out
	default:
		return value
	}
}

func Masked(value any) map[string]any {
	text := fmt.Sprint(value)
	hash := sha256.Sum256([]byte(text))
	return map[string]any{
		"redacted": true,
		"length":   len(text),
		"sha256":   hex.EncodeToString(hash[:]),
		"preview":  preview(text, 4),
	}
}

func preview(text string, n int) string {
	runes := []rune(text)
	if len(runes) <= n {
		return "***"
	}
	return string(runes[:n]) + "…"
}

// RedactReflect handles typed maps/slices used by native adapters while
// keeping the public Value API simple. Unsupported values are stringified only
// when they are explicitly marked sensitive.
func (r *Redactor) RedactReflect(value any) any {
	return r.reflectValue(reflect.ValueOf(value), false)
}

func (r *Redactor) reflectValue(v reflect.Value, force bool) any {
	if !v.IsValid() {
		return nil
	}
	if force {
		return Masked(v.Interface())
	}
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer:
		if v.IsNil() {
			return nil
		}
		return r.reflectValue(v.Elem(), false)
	case reflect.Map:
		out := make(map[string]any, v.Len())
		iter := v.MapRange()
		for iter.Next() {
			key := fmt.Sprint(iter.Key().Interface())
			out[key] = r.reflectValue(iter.Value(), r.KeyIsSensitive(key))
		}
		return out
	case reflect.Slice, reflect.Array:
		out := make([]any, v.Len())
		for i := 0; i < v.Len(); i++ {
			out[i] = r.reflectValue(v.Index(i), false)
		}
		return out
	default:
		return v.Interface()
	}
}
