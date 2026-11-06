//go:build linux

package provisionipc

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const (
	MaxRequestBytes  = 1 << 20
	MaxResponseBytes = 12 << 20
	frameHeaderBytes = 4
)

type Result struct {
	ExitCode int    `json:"exitCode"`
	Stdout   []byte `json:"stdout"`
	Stderr   []byte `json:"stderr"`
}

func writeFrame(w io.Writer, payload []byte, limit int) error {
	if len(payload) == 0 || len(payload) > limit {
		return fmt.Errorf("frame size %d is outside allowed range", len(payload))
	}
	var header [frameHeaderBytes]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readFrame(r io.Reader, limit int) ([]byte, error) {
	var header [frameHeaderBytes]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || uint64(size) > uint64(limit) {
		return nil, fmt.Errorf("frame size %d is outside allowed range", size)
	}
	payload := make([]byte, int(size))
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func marshalResult(result Result) ([]byte, error) {
	return json.Marshal(result)
}

func unmarshalResult(payload []byte) (Result, error) {
	var result Result
	if err := json.Unmarshal(payload, &result); err != nil {
		return Result{}, err
	}
	return result, nil
}
