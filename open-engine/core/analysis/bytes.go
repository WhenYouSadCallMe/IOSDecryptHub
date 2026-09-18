// Package analysis contains host-side, evidence-preserving helpers that make
// runtime events easier for an AI agent to search and explain. It does not
// perform code injection or mutate a target process.
package analysis

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"
)

type ByteProfile struct {
	Length     int     `json:"length"`
	SHA256     string  `json:"sha256"`
	Entropy    float64 `json:"entropy"`
	MagicBytes string  `json:"magicBytes,omitempty"`
	Encoding   string  `json:"encoding"`
	Preview    string  `json:"preview,omitempty"`
}

// ProfileBytes returns a compact description that is safe to put in an AI
// context by default. It never returns the complete input.
func ProfileBytes(data []byte) ByteProfile {
	hash := sha256.Sum256(data)
	return ByteProfile{
		Length:     len(data),
		SHA256:     hex.EncodeToString(hash[:]),
		Entropy:    ShannonEntropy(data),
		MagicBytes: MagicBytes(data),
		Encoding:   GuessEncoding(data),
		Preview:    preview(data, 32),
	}
}

func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	result := 0.0
	denom := float64(len(data))
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / denom
		result -= p * math.Log2(p)
	}
	return result
}

func MagicBytes(data []byte) string {
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		return "gzip"
	}
	if len(data) >= 2 && data[0] == 0x78 && (data[1] == 0x01 || data[1] == 0x5e || data[1] == 0x9c || data[1] == 0xda) {
		return "zlib"
	}
	if len(data) >= 4 && string(data[:4]) == "PK\x03\x04" {
		return "zip"
	}
	if len(data) >= 4 && string(data[:4]) == "\x7fELF" {
		return "elf"
	}
	if len(data) >= 4 && (string(data[:4]) == "\xcf\xfa\xed\xfe" || string(data[:4]) == "\xfe\xed\xfa\xcf") {
		return "mach-o"
	}
	if len(data) >= 2 && data[0] == 0x30 && data[1] >= 0x80 {
		return "asn1"
	}
	return ""
}

func GuessEncoding(data []byte) string {
	if len(data) == 0 {
		return "empty"
	}
	if magic := MagicBytes(data); magic != "" {
		return magic
	}
	if utf8.Valid(data) && isMostlyPrintable(data) {
		text := strings.TrimSpace(string(data))
		if text != "" && isHex(text) && len(text)%2 == 0 {
			return "hex-text"
		}
		if _, err := base64.StdEncoding.DecodeString(text); err == nil && len(text) >= 8 {
			return "base64-text"
		}
		return "utf8"
	}
	return "binary"
}

func isMostlyPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printable := 0
	for _, b := range data {
		if b == '\n' || b == '\r' || b == '\t' || (b >= 0x20 && b < 0x7f) {
			printable++
		}
	}
	return float64(printable)/float64(len(data)) >= 0.85
}

func isHex(text string) bool {
	if text == "" {
		return false
	}
	for _, r := range text {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func preview(data []byte, max int) string {
	if len(data) == 0 {
		return ""
	}
	if utf8.Valid(data) && isMostlyPrintable(data) {
		text := string(data)
		if len([]rune(text)) <= max {
			return text
		}
		return string([]rune(text)[:max]) + "…"
	}
	limit := len(data)
	if limit > max {
		limit = max
	}
	if len(data) > limit {
		return fmt.Sprintf("%x…", data[:limit])
	}
	return fmt.Sprintf("%x", data[:limit])
}
