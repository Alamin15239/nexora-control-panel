package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestDecodeRequest(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:  "valid request",
			input: `{"operation":"DATABASE_USAGE"}`,
		},
		{
			name:    "empty request",
			input:   "",
			wantErr: true,
		},
		{
			name:    "malformed JSON",
			input:   `{"operation":`,
			wantErr: true,
		},
		{
			name:    "unknown field",
			input:   `{"operation":"DATABASE_USAGE","unexpected":true}`,
			wantErr: true,
		},
		{
			name:    "multiple JSON documents",
			input:   `{"operation":"DATABASE_USAGE"} {"operation":"DATABASE_USAGE"}`,
			wantErr: true,
		},
		{
			name:    "trailing invalid data",
			input:   `{"operation":"DATABASE_USAGE"} trailing`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeRequest(strings.NewReader(tt.input))

			if (err != nil) != tt.wantErr {
				t.Fatalf("decodeRequest() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err == nil && got.Operation != "DATABASE_USAGE" {
				t.Fatalf("unexpected operation: %q", got.Operation)
			}
		})
	}
}

func TestDecodeRequestRejectsOversizedInput(t *testing.T) {
	const maxRequestBytes = 1 << 20

	input := append(
		[]byte(`{"operation":"DATABASE_USAGE","contentBase64":"`),
		bytes.Repeat([]byte("a"), maxRequestBytes)...,
	)
	input = append(input, []byte(`"}`)...)

	if _, err := decodeRequest(bytes.NewReader(input)); err == nil {
		t.Fatal("expected oversized request to be rejected")
	}
}

func TestDecodeRequestAcceptsMaximumSizeBoundary(t *testing.T) {
	const maxRequestBytes = 1 << 20

	paddingSize := maxRequestBytes - len(`{"operation":"DATABASE_USAGE","contentBase64":""}`)
	input := []byte(`{"operation":"DATABASE_USAGE","contentBase64":"` +
		strings.Repeat("a", paddingSize) + `"}`)

	if len(input) != maxRequestBytes {
		t.Fatalf("test input size = %d, expected %d", len(input), maxRequestBytes)
	}

	if _, err := decodeRequest(bytes.NewReader(input)); err != nil {
		t.Fatalf("maximum-size request should be accepted: %v", err)
	}
}
