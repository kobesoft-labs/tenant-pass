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
//   - Field names are matched case-insensitively, including Unicode case
//     folding: {"aud":"a","AUD":"b"} passes a byte-wise duplicate check,
//     and "ho\u017ft" (long s) matches the field "host". Another parser
//     would see different members than Go does.
//
// Decode rejects all four: every object key must match a field's JSON
// name exactly (case-sensitive) and appear once.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
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
	if err := checkObject(data, reflect.TypeOf(v)); err != nil {
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
// duplicate keys at any level, and that every key is the exact JSON name
// of a field of the corresponding Go type.
func checkObject(data []byte, typ reflect.Type) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("strictjson: top-level value must be an object")
	}
	if err := scanObject(dec, 1, typ); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("strictjson: trailing data after object")
	}
	return nil
}

var unmarshalerType = reflect.TypeFor[json.Unmarshaler]()

// shape describes what keys an object of a Go type may contain.
type shape struct {
	fields map[string]reflect.Type // struct: exact JSON name -> field type
	elem   reflect.Type            // map: value type
	isMap  bool
}

// shapeOf returns the object shape of t, or nil if t places no
// constraints on keys (interfaces, custom unmarshalers, unknown types).
func shapeOf(t reflect.Type) *shape {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || reflect.PointerTo(t).Implements(unmarshalerType) || t.Implements(unmarshalerType) {
		return nil
	}
	switch t.Kind() {
	case reflect.Map:
		return &shape{isMap: true, elem: t.Elem()}
	case reflect.Struct:
		sh := &shape{fields: map[string]reflect.Type{}}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name := f.Name
			if tag, ok := f.Tag.Lookup("json"); ok {
				n, _, _ := strings.Cut(tag, ",")
				if n == "-" {
					continue
				}
				if n != "" {
					name = n
				}
			}
			sh.fields[name] = f.Type
		}
		return sh
	}
	return nil
}

// elemType returns the element type for arrays/slices, or nil.
func elemType(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
		return t.Elem()
	}
	return nil
}

// scanObject consumes the remainder of an object whose '{' has already
// been read, checking keys for duplicates and, if the Go type is known,
// for an exact match with a field name.
func scanObject(dec *json.Decoder, depth int, typ reflect.Type) error {
	if depth > MaxDepth {
		return errors.New("strictjson: nesting too deep")
	}
	sh := shapeOf(typ)
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
		var vt reflect.Type
		switch {
		case sh == nil:
		case sh.isMap:
			vt = sh.elem
		default:
			ft, exact := sh.fields[key]
			if !exact {
				return fmt.Errorf("strictjson: unknown field %q (field names are case-sensitive)", key)
			}
			vt = ft
		}
		if err := scanValue(dec, depth, vt); err != nil {
			return err
		}
	}
}

// scanValue consumes one JSON value, descending into containers.
func scanValue(dec *json.Decoder, depth int, typ reflect.Type) error {
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
		return scanObject(dec, depth+1, typ)
	case '[':
		if depth+1 > MaxDepth {
			return errors.New("strictjson: nesting too deep")
		}
		et := elemType(typ)
		for dec.More() {
			if err := scanValue(dec, depth+1, et); err != nil {
				return err
			}
		}
		_, err := dec.Token() // ']'
		return err
	default:
		return errors.New("strictjson: unexpected delimiter")
	}
}
