package middleware

import (
	"bytes"
	"errors"
	"io"
	"net/http"
)

// MaxInspectionSize limits how much of the body we inspect to prevent DoS.
// Attackers rarely hide payloads at the end of a 10MB file.
const MaxInspectionSize = 8 * 1024 // 8KB

// BufferedRequest holds the inspected data and allows the stream to continue.
type BufferedRequest struct {
	OriginalBody io.ReadCloser
	Buffer       []byte
	IsJSON       bool
}

// SmartReadBody reads only the necessary bytes for inspection
// while preserving the stream for the actual handler.
func SmartReadBody(r *http.Request) (*BufferedRequest, error) {
	if r.ContentLength > 0 && r.ContentLength > (10*1024*1024) { // 10MB hard cap
		return nil, errors.New("request body too large")
	}

	buffer := make([]byte, MaxInspectionSize)
	n, err := io.ReadFull(r.Body, buffer)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}

	validBuffer := buffer[:n]

	// Detect suspicious padding used to bypass the 8KB inspection limit
	if n >= 1024 {
		whitespace := 0
		for i := 0; i < 1024; i++ {
			if validBuffer[i] <= 32 {
				whitespace++
			}
		}
		if whitespace > 800 { // >80% whitespace in first 1KB
			return nil, errors.New("suspicious request padding detected")
		}
	}

	r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(validBuffer), r.Body))

	isJSON := false
	contentType := r.Header.Get("Content-Type")
	if contentType == "application/json" || (n > 0 && validBuffer[0] == '{') {
		isJSON = true
	}

	return &BufferedRequest{
		OriginalBody: r.Body,
		Buffer:       validBuffer,
		IsJSON:       isJSON,
	}, nil
}
