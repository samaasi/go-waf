package utils

import (
	"testing"
)

func TestGrpcParser_ParseFrames(t *testing.T) {
	// 5-byte header + payload
	// 0: non-compressed, [0,0,0,5]: length 5, payload: [1,2,3,4,5]
	data := []byte{0, 0, 0, 0, 5, 1, 2, 3, 4, 5}
	frames, err := ParseGrpcFrames(data)
	if err != nil {
		t.Fatalf("ParseGrpcFrames failed: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}
	if frames[0].Length != 5 {
		t.Errorf("expected length 5, got %d", frames[0].Length)
	}
}

func TestProtobuf_Parse(t *testing.T) {
	// Protobuf message: field 1, wire 2 (string), length 4, value "test"
	// Tag: (1 << 3) | 2 = 10
	data := []byte{10, 4, 't', 'e', 's', 't'}
	fields := ParseProtobuf(data)
	if vals, ok := fields["grpc.field.1"]; ok {
		if vals[0] != "test" {
			t.Errorf("expected 'test', got %s", vals[0])
		}
	} else {
		t.Errorf("field 1 not found")
	}
}
