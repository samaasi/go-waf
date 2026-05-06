package utils

import (
	"encoding/binary"
	"fmt"
	"unicode/utf8"
)

// GrpcFrame represents a single gRPC message frame.
type GrpcFrame struct {
	Compressed bool
	Length     uint32
	Payload    []byte
}

// ParseGrpcFrames extracts individual gRPC messages from a raw stream.
func ParseGrpcFrames(data []byte) ([]*GrpcFrame, error) {
	var frames []*GrpcFrame
	for len(data) >= 5 {
		compressed := data[0] == 1
		length := binary.BigEndian.Uint32(data[1:5])
		
		if uint32(len(data[5:])) < length {
			break // Incomplete frame
		}
		
		frames = append(frames, &GrpcFrame{
			Compressed: compressed,
			Length:     length,
			Payload:    data[5 : 5+length],
		})
		data = data[5+length:]
	}
	return frames, nil
}

// ExtractProtobufStrings attempts to extract human-readable strings from a Protobuf-encoded payload.
// This is used for heuristic inspection when a .proto schema is unavailable.
func ExtractProtobufStrings(payload []byte) []string {
	var result []string
	pos := 0
	for pos < len(payload) {
		tag, n := ReadVarint(payload[pos:])
		if n == 0 {
			break
		}
		pos += n
		wireType := int(tag & 0x7)

		switch wireType {
		case 0: // Varint
			_, n := ReadVarint(payload[pos:])
			if n == 0 {
				break
			}
			pos += n
		case 1: // 64-bit
			pos += 8
		case 2: // Length-delimited (Strings, sub-messages, bytes)
			length, n := ReadVarint(payload[pos:])
			if n == 0 || pos+n+int(length) > len(payload) {
				break
			}
			pos += n
			val := payload[pos : pos+int(length)]
			if utf8.Valid(val) && len(val) > 2 {
				result = append(result, string(val))
			}
			pos += int(length)
		case 5: // 32-bit
			pos += 4
		default:
			return result // Malformed or unknown wire type
		}
	}
	return result
}

// ParseProtobuf maps field numbers to their string values for targeted rules (e.g. ARGS:grpc.field.1).
func ParseProtobuf(data []byte) map[string][]string {
	res := make(map[string][]string)
	pos := 0
	for pos < len(data) {
		tag, n := ReadVarint(data[pos:])
		if n == 0 {
			break
		}
		pos += n
		wireType := int(tag & 0x7)
		fieldNum := int(tag >> 3)

		switch wireType {
		case 0: // Varint
			_, n := ReadVarint(data[pos:])
			pos += n
		case 1: // 64-bit
			pos += 8
		case 2: // Length-delimited
			length, n := ReadVarint(data[pos:])
			pos += n
			if pos+int(length) > len(data) {
				break
			}
			val := data[pos : pos+int(length)]
			if utf8.Valid(val) && len(val) > 1 {
				key := fmt.Sprintf("grpc.field.%d", fieldNum)
				res[key] = append(res[key], string(val))
			}
			pos += int(length)
		case 5: // 32-bit
			pos += 4
		default:
			return res
		}
	}
	return res
}

// ReadVarint reads a Protobuf-style varint from the buffer.
func ReadVarint(buf []byte) (uint64, int) {
	var x uint64
	var s uint
	for i, b := range buf {
		if b < 0x80 {
			if i > 9 || i == 9 && b > 1 {
				return 0, 0
			}
			return x | uint64(b)<<s, i + 1
		}
		x |= uint64(b&0x7f) << s
		s += 7
	}
	return 0, 0
}
