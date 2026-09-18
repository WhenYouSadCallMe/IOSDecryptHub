// Package macho parses enough Mach-O metadata to make runtime addresses
// comparable with IDA/Ghidra without loading an executable or executing it.
// It is bounded, read-only and supports thin arm64/arm64e plus common FAT
// containers.
package macho

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

const (
	magic32LE  = 0xfeedface
	magic32BE  = 0xcefaedfe
	magic64LE  = 0xfeedfacf
	magic64BE  = 0xcffaedfe
	fatMagicBE = 0xcafebabe
	fatMagicLE = 0xbebafeca

	lcSegment64 = 0x19
	lcUUID      = 0x1b
	maxCommands = 4096
)

type Segment struct {
	Name       string `json:"name"`
	VMAddress  uint64 `json:"vmAddress"`
	VMSize     uint64 `json:"vmSize"`
	FileOffset uint64 `json:"fileOffset"`
	FileSize   uint64 `json:"fileSize"`
	MaxProt    int32  `json:"maxProt"`
	InitProt   int32  `json:"initProt"`
}

type Slice struct {
	Offset       uint64 `json:"offset"`
	Size         uint64 `json:"size"`
	CPUType      int32  `json:"cpuType"`
	CPUSubtype   int32  `json:"cpuSubtype"`
	Architecture string `json:"architecture"`
}

type Image struct {
	Format       string    `json:"format"`
	Architecture string    `json:"architecture"`
	CPUType      int32     `json:"cpuType"`
	CPUSubtype   int32     `json:"cpuSubtype"`
	FileType     uint32    `json:"fileType"`
	Is64         bool      `json:"is64"`
	UUID         string    `json:"uuid,omitempty"`
	Segments     []Segment `json:"segments,omitempty"`
	Slices       []Slice   `json:"slices,omitempty"`
}

var (
	ErrInvalidImage = errors.New("invalid Mach-O image")
	ErrUnsupported  = errors.New("unsupported Mach-O format")
)

func ParseFile(path string) (Image, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Image{}, err
	}
	return Parse(data)
}

func Parse(data []byte) (Image, error) {
	if len(data) < 4 {
		return Image{}, ErrInvalidImage
	}
	magic := binary.BigEndian.Uint32(data[:4])
	switch magic {
	case fatMagicBE, fatMagicLE:
		return parseFat(data, magic == fatMagicLE)
	}
	return parseThin(data, 0)
}

func parseFat(data []byte, little bool) (Image, error) {
	var order binary.ByteOrder = binary.BigEndian
	if little {
		order = binary.LittleEndian
	}
	if len(data) < 8 {
		return Image{}, ErrInvalidImage
	}
	nfat := order.Uint32(data[4:8])
	if nfat == 0 || nfat > 32 || len(data) < 8+int(nfat)*20 {
		return Image{}, ErrInvalidImage
	}
	slices := make([]Slice, 0, nfat)
	var first Image
	for index := uint32(0); index < nfat; index++ {
		base := 8 + int(index)*20
		cpuType := int32(order.Uint32(data[base : base+4]))
		cpuSubtype := int32(order.Uint32(data[base+4 : base+8]))
		offset := uint64(order.Uint32(data[base+8 : base+12]))
		size := uint64(order.Uint32(data[base+12 : base+16]))
		if offset > uint64(len(data)) || size > uint64(len(data))-offset {
			return Image{}, ErrInvalidImage
		}
		slices = append(slices, Slice{Offset: offset, Size: size, CPUType: cpuType, CPUSubtype: cpuSubtype, Architecture: architecture(cpuType, cpuSubtype)})
		if index == 0 {
			parsed, err := parseThin(data[offset:offset+size], offset)
			if err != nil {
				return Image{}, err
			}
			first = parsed
		}
	}
	first.Format = "fat"
	first.Slices = slices
	return first, nil
}

func parseThin(data []byte, baseOffset uint64) (Image, error) {
	if len(data) < 28 {
		return Image{}, ErrInvalidImage
	}
	magic := binary.BigEndian.Uint32(data[:4])
	little := magic == magic32BE || magic == magic64BE
	var order binary.ByteOrder = binary.BigEndian
	if little {
		order = binary.LittleEndian
	}
	is64 := magic == magic64LE || magic == magic64BE
	if !is64 && magic != magic32LE && magic != magic32BE {
		return Image{}, ErrUnsupported
	}
	if is64 && len(data) < 32 {
		return Image{}, ErrInvalidImage
	}
	cpuType := int32(order.Uint32(data[4:8]))
	cpuSubtype := int32(order.Uint32(data[8:12]))
	fileType := order.Uint32(data[12:16])
	ncmds := order.Uint32(data[16:20])
	sizeofcmds := order.Uint32(data[20:24])
	headerSize := 28
	if is64 {
		headerSize = 32
	}
	if ncmds > maxCommands || sizeofcmds > uint32(len(data)-headerSize) {
		return Image{}, ErrInvalidImage
	}
	image := Image{
		Format:       "thin",
		Architecture: architecture(cpuType, cpuSubtype),
		CPUType:      cpuType,
		CPUSubtype:   cpuSubtype,
		FileType:     fileType,
		Is64:         is64,
	}
	commandOffset := headerSize
	commandEnd := commandOffset + int(sizeofcmds)
	for command := uint32(0); command < ncmds; command++ {
		if commandOffset+8 > commandEnd || commandOffset+8 > len(data) {
			return Image{}, ErrInvalidImage
		}
		commandType := order.Uint32(data[commandOffset : commandOffset+4])
		commandSize := order.Uint32(data[commandOffset+4 : commandOffset+8])
		if commandSize < 8 || commandOffset+int(commandSize) > commandEnd || commandOffset+int(commandSize) > len(data) {
			return Image{}, ErrInvalidImage
		}
		switch commandType {
		case lcUUID:
			if commandSize >= 24 {
				image.UUID = formatUUID(data[commandOffset+8 : commandOffset+24])
			}
		case lcSegment64:
			if is64 && commandSize >= 72 {
				segment := Segment{
					Name:       trimName(data[commandOffset+8 : commandOffset+24]),
					VMAddress:  order.Uint64(data[commandOffset+24 : commandOffset+32]),
					VMSize:     order.Uint64(data[commandOffset+32 : commandOffset+40]),
					FileOffset: order.Uint64(data[commandOffset+40 : commandOffset+48]),
					FileSize:   order.Uint64(data[commandOffset+48 : commandOffset+56]),
					MaxProt:    int32(order.Uint32(data[commandOffset+56 : commandOffset+60])),
					InitProt:   int32(order.Uint32(data[commandOffset+60 : commandOffset+64])),
				}
				image.Segments = append(image.Segments, segment)
			}
		}
		commandOffset += int(commandSize)
	}
	_ = baseOffset
	return image, nil
}

func IDAAddress(runtimeAddress, slide uint64) (uint64, error) {
	if runtimeAddress < slide {
		return 0, fmt.Errorf("runtime address 0x%x is below slide 0x%x", runtimeAddress, slide)
	}
	return runtimeAddress - slide, nil
}

func RuntimeAddress(idaAddress, slide uint64) (uint64, error) {
	if ^uint64(0)-idaAddress < slide {
		return 0, errors.New("runtime address overflows uint64")
	}
	return idaAddress + slide, nil
}

func trimName(data []byte) string {
	if index := bytes.IndexByte(data, 0); index >= 0 {
		data = data[:index]
	}
	return string(data)
}

func formatUUID(data []byte) string {
	if len(data) != 16 {
		return ""
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", data[:4], data[4:6], data[6:8], data[8:10], data[10:])
}

func architecture(cpuType int32, cpuSubtype int32) string {
	const (
		cpuARM64  = 0x0100000c
		cpuX8664  = 0x01000007
		cpuARM    = 12
		cpuX86    = 7
		cpuARM64E = 2
	)
	switch uint32(cpuType) {
	case cpuARM64:
		if cpuSubtype&0xff == cpuARM64E {
			return "arm64e"
		}
		return "arm64"
	case cpuX8664:
		return "x86_64"
	case cpuARM:
		return "arm"
	case cpuX86:
		return "x86"
	default:
		return fmt.Sprintf("cpu:%d/sub:%d", cpuType, cpuSubtype)
	}
}
