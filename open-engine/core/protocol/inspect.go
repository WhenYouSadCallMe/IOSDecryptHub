// Package protocol provides bounded, read-only payload inspection. It is
// intentionally a recognizer rather than a full protocol implementation: the
// output is metadata and hashes that can be safely handed to an AI agent.
package protocol

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

const (
	DefaultMaxBytes = 1 << 20
	maxDepth        = 2
)

type Kind string

const (
	KindEmpty       Kind = "empty"
	KindText        Kind = "text"
	KindJSON        Kind = "json"
	KindHTTP        Kind = "http1"
	KindBase64      Kind = "base64"
	KindHex         Kind = "hex"
	KindGZIP        Kind = "gzip"
	KindZLIB        Kind = "zlib"
	KindProtobuf    Kind = "protobuf"
	KindMessagePack Kind = "messagepack"
	KindBinary      Kind = "binary"
)

type Options struct {
	MaxBytes int
	Depth    int
}

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Inspection struct {
	Kind          Kind        `json:"kind"`
	Encoding      string      `json:"encoding,omitempty"`
	Length        int         `json:"length"`
	DecodedLength int         `json:"decodedLength,omitempty"`
	SHA256        string      `json:"sha256"`
	Entropy       float64     `json:"entropy"`
	Confidence    float64     `json:"confidence"`
	Preview       string      `json:"preview,omitempty"`
	Headers       []Header    `json:"headers,omitempty"`
	JSONKeys      []string    `json:"jsonKeys,omitempty"`
	Nested        *Inspection `json:"nested,omitempty"`
	Truncated     bool        `json:"truncated,omitempty"`
	MessageFields []FieldHint `json:"messageFields,omitempty"`
}

type FieldHint struct {
	Number int    `json:"number"`
	Wire   string `json:"wire"`
}

var ErrPayloadTooLarge = errors.New("payload exceeds inspection limit")

func Inspect(data []byte, options Options) (Inspection, error) {
	if options.MaxBytes <= 0 {
		options.MaxBytes = DefaultMaxBytes
	}
	if options.Depth <= 0 {
		options.Depth = maxDepth
	}
	if len(data) > options.MaxBytes {
		return Inspection{}, fmt.Errorf("%w: %d > %d", ErrPayloadTooLarge, len(data), options.MaxBytes)
	}
	return inspect(data, options, 0), nil
}

func inspect(data []byte, options Options, depth int) Inspection {
	hash := sha256.Sum256(data)
	result := Inspection{
		Length:     len(data),
		SHA256:     hex.EncodeToString(hash[:]),
		Entropy:    shannonEntropy(data),
		Preview:    preview(data, 48),
		Confidence: 0.55,
	}
	if len(data) == 0 {
		result.Kind = KindEmpty
		result.Encoding = "empty"
		result.Confidence = 1
		return result
	}
	if looksHTTP(data) {
		result.Kind = KindHTTP
		result.Encoding = "http/1.1"
		result.Headers = parseHeaders(data)
		result.Confidence = 0.98
		return result
	}
	if parsed, keys, ok := parseJSON(data); ok {
		_ = parsed
		result.Kind = KindJSON
		result.Encoding = "utf-8"
		result.JSONKeys = keys
		result.Confidence = 0.99
		return result
	}
	if decoded, ok := decodeGZIP(data, options.MaxBytes); ok {
		result.Kind = KindGZIP
		result.Encoding = "gzip"
		result.DecodedLength = len(decoded)
		result.Confidence = 0.99
		if depth < options.Depth {
			nested := inspect(decoded, options, depth+1)
			result.Nested = &nested
		}
		return result
	}
	if decoded, ok := decodeZLIB(data, options.MaxBytes); ok {
		result.Kind = KindZLIB
		result.Encoding = "zlib"
		result.DecodedLength = len(decoded)
		result.Confidence = 0.98
		if depth < options.Depth {
			nested := inspect(decoded, options, depth+1)
			result.Nested = &nested
		}
		return result
	}
	if decoded, ok := decodeHex(data); ok {
		result.Kind = KindHex
		result.Encoding = "hex"
		result.DecodedLength = len(decoded)
		result.Confidence = 0.94
		if depth < options.Depth {
			nested := inspect(decoded, options, depth+1)
			result.Nested = &nested
		}
		return result
	}
	if decoded, ok := decodeBase64(data); ok {
		result.Kind = KindBase64
		result.Encoding = "base64"
		result.DecodedLength = len(decoded)
		result.Confidence = 0.9
		if depth < options.Depth {
			nested := inspect(decoded, options, depth+1)
			result.Nested = &nested
		}
		return result
	}
	if fields, ok := protobufHints(data); ok {
		result.Kind = KindProtobuf
		result.Encoding = "protobuf-wire"
		result.MessageFields = fields
		result.Confidence = 0.65
		return result
	}
	if looksMessagePack(data) {
		result.Kind = KindMessagePack
		result.Encoding = "messagepack"
		result.Confidence = 0.62
		return result
	}
	if isPrintable(data) {
		result.Kind = KindText
		result.Encoding = "utf-8"
		result.Confidence = 0.8
		return result
	}
	result.Kind = KindBinary
	result.Encoding = "binary"
	result.Confidence = 0.7
	return result
}

func parseJSON(data []byte) (any, []string, bool) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return nil, nil, false
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, nil, false
	}
	keys := make([]string, 0)
	if object, ok := value.(map[string]any); ok {
		for key := range object {
			keys = append(keys, key)
		}
		for _, item := range object {
			if nested, ok := item.(map[string]any); ok {
				for key := range nested {
					keys = append(keys, key)
				}
			}
		}
	}
	return value, uniqueSorted(keys), true
}

func decodeGZIP(data []byte, limit int) ([]byte, bool) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, false
	}
	defer reader.Close()
	decoded, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil || len(decoded) > limit {
		return nil, false
	}
	return decoded, true
}

func decodeZLIB(data []byte, limit int) ([]byte, bool) {
	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, false
	}
	defer reader.Close()
	decoded, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil || len(decoded) > limit {
		return nil, false
	}
	return decoded, true
}

func decodeBase64(data []byte) ([]byte, bool) {
	text := strings.TrimSpace(string(data))
	if len(text) < 12 || len(text)%4 != 0 {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(text)
	if err != nil || len(decoded) == 0 || string(decoded) == text {
		return nil, false
	}
	return decoded, true
}

func decodeHex(data []byte) ([]byte, bool) {
	text := strings.TrimSpace(string(data))
	if len(text) < 8 || len(text)%2 != 0 {
		return nil, false
	}
	decoded, err := hex.DecodeString(text)
	if err != nil || len(decoded) == 0 {
		return nil, false
	}
	return decoded, true
}

func looksHTTP(data []byte) bool {
	text := string(data)
	for _, prefix := range []string{"GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HTTP/1."} {
		if strings.HasPrefix(text, prefix) {
			return true
		}
	}
	return false
}

func parseHeaders(data []byte) []Header {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	result := make([]Header, 0)
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		result = append(result, Header{Name: strings.TrimSpace(parts[0]), Value: "<redacted>"})
		if len(result) >= 64 {
			break
		}
	}
	return result
}

func protobufHints(data []byte) ([]FieldHint, bool) {
	if len(data) < 2 {
		return nil, false
	}
	offset := 0
	fields := make([]FieldHint, 0, 8)
	for offset < len(data) && len(fields) < 16 {
		key, next, ok := readVarint(data, offset)
		if !ok || key == 0 {
			return nil, false
		}
		number := int(key >> 3)
		wire := int(key & 7)
		if number < 1 || number > 536870911 || wire == 3 || wire == 4 || wire > 5 {
			return nil, false
		}
		fields = append(fields, FieldHint{Number: number, Wire: wireName(wire)})
		offset = next
		switch wire {
		case 0:
			_, offset, ok = readVarint(data, offset)
		case 1:
			offset += 8
		case 2:
			length, after, valid := readVarint(data, offset)
			if !valid || length > uint64(len(data)-after) {
				return nil, false
			}
			offset = after + int(length)
		case 5:
			offset += 4
		}
		if offset > len(data) {
			return nil, false
		}
	}
	return fields, len(fields) >= 1 && offset == len(data)
}

func readVarint(data []byte, offset int) (uint64, int, bool) {
	var result uint64
	for shift := uint(0); offset < len(data) && shift < 64; shift += 7 {
		byteValue := data[offset]
		offset++
		result |= uint64(byteValue&0x7f) << shift
		if byteValue < 0x80 {
			return result, offset, true
		}
	}
	return 0, offset, false
}

func wireName(wire int) string {
	switch wire {
	case 0:
		return "varint"
	case 1:
		return "fixed64"
	case 2:
		return "length-delimited"
	case 5:
		return "fixed32"
	default:
		return strconv.Itoa(wire)
	}
}

func looksMessagePack(data []byte) bool {
	first := data[0]
	return first >= 0x80 && first <= 0x9f || first >= 0xdc && first <= 0xdf || first >= 0xa0 && first <= 0xbf
}

func isPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	count := 0
	for _, value := range data {
		if value == '\n' || value == '\r' || value == '\t' || value >= 0x20 && value < 0x7f {
			count++
		}
	}
	return float64(count)/float64(len(data)) >= 0.85
}

func preview(data []byte, limit int) string {
	if len(data) > limit {
		data = data[:limit]
	}
	if isPrintable(data) {
		return string(data)
	}
	return hex.EncodeToString(data)
}

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, value := range data {
		counts[value]++
	}
	result := 0.0
	for _, count := range counts {
		if count == 0 {
			continue
		}
		probability := float64(count) / float64(len(data))
		result -= probability * math.Log2(probability)
	}
	return result
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j] < result[i] {
				result[i], result[j] = result[j], result[i]
			}
		}
	}
	return result
}
