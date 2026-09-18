package protocol

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"testing"
)

func TestInspectJSONAndRedactsHTTPHeaders(t *testing.T) {
	jsonBody, _ := json.Marshal(map[string]any{"resultCode": 999, "data": nil, "nested": map[string]any{"token": "secret"}})
	inspection, err := Inspect(jsonBody, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Kind != KindJSON || len(inspection.JSONKeys) == 0 || inspection.SHA256 == "" {
		t.Fatalf("unexpected JSON inspection: %+v", inspection)
	}
	httpInspection, err := Inspect([]byte("HTTP/1.1 200 OK\r\nAuthorization: Bearer secret\r\nContent-Type: application/json\r\n\r\n{}"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if httpInspection.Kind != KindHTTP || len(httpInspection.Headers) != 2 || httpInspection.Headers[0].Value != "<redacted>" {
		t.Fatalf("unexpected HTTP inspection: %+v", httpInspection)
	}
}

func TestInspectGZIPAndNestedJSON(t *testing.T) {
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	_, _ = writer.Write([]byte(`{"ok":true,"code":0}`))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	inspection, err := Inspect(buffer.Bytes(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Kind != KindGZIP || inspection.Nested == nil || inspection.Nested.Kind != KindJSON {
		t.Fatalf("unexpected gzip inspection: %+v", inspection)
	}
}

func TestInspectBase64HexAndProtobufHints(t *testing.T) {
	base64Inspection, err := Inspect([]byte("eyJjb2RlIjowLCJkYXRhIjpudWxsfQ=="), Options{})
	if err != nil || base64Inspection.Kind != KindBase64 || base64Inspection.Nested == nil || base64Inspection.Nested.Kind != KindJSON {
		t.Fatalf("base64 inspection: %+v %v", base64Inspection, err)
	}
	hexInspection, err := Inspect([]byte("7b22636f6465223a307d"), Options{})
	if err != nil || hexInspection.Kind != KindHex || hexInspection.Nested == nil || hexInspection.Nested.Kind != KindJSON {
		t.Fatalf("hex inspection: %+v %v", hexInspection, err)
	}
	protobufInspection, err := Inspect([]byte{0x08, 0x96, 0x01}, Options{})
	if err != nil || protobufInspection.Kind != KindProtobuf || len(protobufInspection.MessageFields) != 1 {
		t.Fatalf("protobuf inspection: %+v %v", protobufInspection, err)
	}
}

func TestInspectRejectsOversizedPayload(t *testing.T) {
	if _, err := Inspect([]byte("123456789"), Options{MaxBytes: 8}); err == nil {
		t.Fatal("expected oversized payload error")
	}
}
