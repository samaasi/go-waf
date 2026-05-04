package utils

import "github.com/buger/jsonparser"

// ExtractValuesOnly flattens a JSON object and returns ONLY the values.
// This is used by analysis engines to scan data without being distracted by keys.
func ExtractValuesOnly(data []byte) []string {
	var values []string

	var parse func([]byte)
	parse = func(val []byte) {
		jsonparser.ArrayEach(val, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
			switch dataType {
			case jsonparser.String:
				values = append(values, string(value))
			case jsonparser.Object, jsonparser.Array:
				parse(value)
			}
		})

		jsonparser.ObjectEach(val, func(key []byte, value []byte, dataType jsonparser.ValueType, offset int) error {
			switch dataType {
			case jsonparser.String:
				values = append(values, string(value))
			case jsonparser.Object, jsonparser.Array:
				parse(value)
			}
			return nil
		})
	}

	// Try parsing as object first, then array
	if len(data) > 0 {
		if data[0] == '{' || data[0] == '[' {
			parse(data)
		} else {
			return []string{string(data)}
		}
	}

	if len(values) == 0 && len(data) > 0 {
		return []string{string(data)}
	}

	return values
}
