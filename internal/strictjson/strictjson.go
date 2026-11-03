// Package strictjson decodes JSON objects with rules that are stricter
// than encoding/json's defaults.
//
// encoding/json is permissive in ways that matter for security-relevant
// input such as signed claims and API requests:
//
//   - Duplicate object keys are accepted and the last one wins. Other
//     languages' parsers may pick the first one instead. When the same
//     bytes are interpreted by two systems (for example a gateway that
//     signs claims and tenant-pass that verifies them), a duplicate key
//     can make them disagree about what was signed ("parser
//     differential").
//   - Unknown fields are silently ignored, which hides typos in
//     configuration and lets unexpected claims slip through.
//   - Trailing data after the first value is ignored by Decoder.
//
// Decode rejects all three.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxDepth bounds nesting so that a hostile document cannot make the
// duplicate-key scan expensive. Every document tenant-pass parses is far
// shallower than this.
const MaxDepth = 16

// Decode parses data into v (a pointer to a struct). It fails if data is
// not exactly one JSON object, if any object (at any depth) contains a
// duplicate key, if nesting exceeds MaxDepth, or if a field does not
// exist in v.
func Decode(data []byte, v any) error {
	if err := checkObject(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	// Anything other than whitespace after the object is an error.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("strictjson: trailing data after object")
	}
	return nil
}

// checkObject verifies that data is a single JSON object without
// duplicate keys at any level.
func checkObject(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("strictjson: top-level value must be an object")
	}
	if err := scanObject(dec, 1); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("strictjson: trailing data after object")
	}
	return nil
}

// scanObject consumes the remainder of an object whose '{' has already
// been read, checking keys for duplicates.
func scanObject(dec *json.Decoder, depth int) error {
	if depth > MaxDepth {
		return errors.New("strictjson: nesting too deep")
	}
	seen := make(map[string]struct{})
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); ok && d == '}' {
			return nil
		}
		key, ok := tok.(string)
		if !ok {
			return errors.New("strictjson: invalid object key")
		}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("strictjson: duplicate key %q", key)
		}
		seen[key] = struct{}{}
		if err := scanValue(dec, depth); err != nil {
			return err
		}
	}
}

// scanValue consumes one JSON value, descending into containers.
func scanValue(dec *json.Decoder, depth int) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar
	}
	switch d {
	case '{':
		return scanObject(dec, depth+1)
	case '[':
		if depth+1 > MaxDepth {
			return errors.New("strictjson: nesting too deep")
		}
		for dec.More() {
			if err := scanValue(dec, depth+1); err != nil {
				return err
			}
		}
		_, err := dec.Token() // ']'
		return err
	default:
		return errors.New("strictjson: unexpected delimiter")
	}
}
