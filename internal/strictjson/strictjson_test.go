package strictjson

import (
	"strings"
	"testing"
)

type item struct {
	N int `json:"n"`
}

type sample struct {
	Items []item          `json:"items"`
	M     map[string]item `json:"m"`
	A     string          `json:"a"`
	B     []string        `json:"b"`
	C     *struct {
		D int `json:"d"`
	} `json:"c"`
}

func TestDecode(t *testing.T) {
	var s sample
	if err := Decode([]byte(` {"a":"x","b":["1","2"],"c":{"d":3}} `), &s); err != nil {
		t.Fatal(err)
	}
	if s.A != "x" || len(s.B) != 2 || s.C.D != 3 {
		t.Fatalf("got %+v", s)
	}
}

func TestMapKeysAreFree(t *testing.T) {
	var s sample
	if err := Decode([]byte(`{"m":{"Any-Key":{"n":1},"other":{"n":2}},"items":[{"n":3}]}`), &s); err != nil {
		t.Fatal(err)
	}
	if err := Decode([]byte(`{"m":{"k":{"N":1}}}`), &s); err == nil {
		t.Fatal("case variant inside map value accepted")
	}
}

func TestDecodeRejects(t *testing.T) {
	cases := map[string]string{
		"duplicate top":    `{"a":"x","a":"y"}`,
		"duplicate nested": `{"c":{"d":1,"d":2}}`,
		"unknown field":    `{"z":1}`,
		"trailing object":  `{"a":"x"}{"a":"y"}`,
		"trailing garbage": `{"a":"x"} x`,
		"array top":        `["a"]`,
		"string top":       `"a"`,
		"empty":            ``,
		"too deep":         `{"b":` + strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1) + `}`,
		"wrong type":       `{"a":1}`,
		"case variant":     `{"A":"x"}`,
		"case duplicate":   `{"a":"x","A":"y"}`,
		"unicode fold":     "{\"\u017f\":\"x\"}",
		"nested case":      `{"c":{"D":1}}`,
		"slice elem case":  `{"items":[{"N":1}]}`,
	}
	for name, in := range cases {
		var s sample
		if err := Decode([]byte(in), &s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"a":"x","b":["1"],"c":{"d":1}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var s sample
		_ = Decode(data, &s) // must not panic
	})
}
