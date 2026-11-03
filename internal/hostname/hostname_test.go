package hostname

import (
	"strings"
	"testing"
)

func TestIsCanonical(t *testing.T) {
	good := []string{
		"acme.example.com",
		"a.b",
		"xn--bcher-kva.example",
		"a-1.b-2.c3",
		strings.Repeat("a", 63) + ".com",
	}
	for _, h := range good {
		if !IsCanonical(h) {
			t.Errorf("%q rejected", h)
		}
	}
	bad := []string{
		"",
		"localhost",
		"Acme.example.com",
		"acme.example.com.",
		"acme.example.com:443",
		".acme.example.com",
		"acme..example.com",
		"-acme.example.com",
		"acme-.example.com",
		"acme_x.example.com",
		"acme.example.com/",
		"10.0.0.1",
		"[::1]",
		"bücher.example",
		"acme.example.com\x00",
		strings.Repeat("a", 64) + ".com",
		strings.Repeat("a.", 127) + "com", // 257 bytes
	}
	for _, h := range bad {
		if IsCanonical(h) {
			t.Errorf("%q accepted", h)
		}
	}
}
