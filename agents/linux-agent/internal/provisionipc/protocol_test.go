//go:build linux

package provisionipc

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	input := []byte(`{"operation":"DATABASE_USAGE"}`)
	var wire bytes.Buffer
	if err := writeFrame(&wire, input, MaxRequestBytes); err != nil {
		t.Fatal(err)
	}
	got, err := readFrame(&wire, MaxRequestBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, input) {
		t.Fatalf("frame mismatch: got %q want %q", got, input)
	}
}

func TestReadFrameRejectsOversize(t *testing.T) {
	wire := []byte{0, 0, 0, 8, '1', '2', '3', '4', '5', '6', '7', '8'}
	if _, err := readFrame(bytes.NewReader(wire), 7); err == nil {
		t.Fatal("expected oversized frame rejection")
	}
}

func TestReadFrameRejectsTruncatedPayload(t *testing.T) {
	wire := []byte{0, 0, 0, 4, 'a', 'b'}
	if _, err := readFrame(bytes.NewReader(wire), 8); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected unexpected EOF, got %v", err)
	}
}

func TestWriteFrameRejectsEmptyAndOversize(t *testing.T) {
	for _, payload := range [][]byte{nil, []byte("12345")} {
		var wire bytes.Buffer
		if err := writeFrame(&wire, payload, 4); err == nil {
			t.Fatalf("expected rejection for payload length %d", len(payload))
		}
	}
}

func TestCappedBufferEnforcesLimit(t *testing.T) {
	buffer := &cappedBuffer{limit: 4}
	if n, err := buffer.Write([]byte("abc")); n != 3 || err != nil {
		t.Fatalf("first write = %d, %v", n, err)
	}
	if n, err := buffer.Write([]byte("xyz")); n != 1 || err == nil {
		t.Fatalf("overflow write = %d, %v", n, err)
	}
	if string(buffer.data) != "abcx" {
		t.Fatalf("unexpected capped output %q", buffer.data)
	}
}
