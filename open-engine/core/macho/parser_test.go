package macho

import (
	"encoding/binary"
	"testing"
)

func TestParseThinArm64Image(t *testing.T) {
	data := make([]byte, 32+24+72)
	order := binary.LittleEndian
	order.PutUint32(data[0:4], magic64LE)
	order.PutUint32(data[4:8], 0x0100000c)
	order.PutUint32(data[8:12], 0)
	order.PutUint32(data[12:16], 2)
	order.PutUint32(data[16:20], 2)
	order.PutUint32(data[20:24], 96)
	// LC_UUID
	order.PutUint32(data[32:36], lcUUID)
	order.PutUint32(data[36:40], 24)
	copy(data[40:56], []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	// LC_SEGMENT_64
	segmentOffset := 56
	order.PutUint32(data[segmentOffset:segmentOffset+4], lcSegment64)
	order.PutUint32(data[segmentOffset+4:segmentOffset+8], 72)
	copy(data[segmentOffset+8:segmentOffset+24], []byte("__TEXT"))
	order.PutUint64(data[segmentOffset+24:segmentOffset+32], 0x100000000)
	order.PutUint64(data[segmentOffset+32:segmentOffset+40], 0x4000)
	order.PutUint64(data[segmentOffset+40:segmentOffset+48], 0)
	order.PutUint64(data[segmentOffset+48:segmentOffset+56], 0x4000)
	order.PutUint32(data[segmentOffset+56:segmentOffset+60], 5)
	order.PutUint32(data[segmentOffset+60:segmentOffset+64], 5)

	image, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if image.Architecture != "arm64" || !image.Is64 || image.UUID == "" || len(image.Segments) != 1 {
		t.Fatalf("unexpected image: %+v", image)
	}
	if image.Segments[0].VMAddress != 0x100000000 || image.Segments[0].Name != "__TEXT" {
		t.Fatalf("unexpected segment: %+v", image.Segments[0])
	}
}

func TestAddressSlideConversion(t *testing.T) {
	ida, err := IDAAddress(0x100012340, 0x100000000)
	if err != nil || ida != 0x12340 {
		t.Fatalf("IDA address: 0x%x %v", ida, err)
	}
	runtime, err := RuntimeAddress(ida, 0x100000000)
	if err != nil || runtime != 0x100012340 {
		t.Fatalf("runtime address: 0x%x %v", runtime, err)
	}
	if _, err := IDAAddress(1, 2); err == nil {
		t.Fatal("expected invalid slide conversion")
	}
}
