package middleware

import (
	"bytes"
	"encoding/json"
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

// ExtractValuesOnly flattens a JSON object and returns ONLY the values.
// This prevents blocking on keys like {"union": "data"} which is safe,
// versus {"data": "UNION SELECT"} which is an attack.
func ExtractValuesOnly(data []byte) []string {
	var values []string

	// Generic decoding to handle any structure
	var f interface{}
	if err := json.Unmarshal(data, &f); err != nil {
		return []string{string(data)}
	}

	// Recursive extractor
	var recurse func(interface{})
	recurse = func(v interface{}) {
		switch vv := v.(type) {
		case string:
			values = append(values, vv)
		case map[string]interface{}:
			for _, mapVal := range vv {
				recurse(mapVal)
			}
		case []interface{}:
			for _, sliceVal := range vv {
				recurse(sliceVal)
			}
		}
	}

	recurse(f)
	return values
}
