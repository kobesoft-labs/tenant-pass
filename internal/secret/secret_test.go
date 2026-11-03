package secret

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func write(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // bypass umask
		t.Fatal(err)
	}
	return p
}

func TestReadFile(t *testing.T) {
	v, err := ReadFile(write(t, "hunter2\n", 0o600))
	if err != nil || v.Reveal() != "hunter2" {
		t.Fatalf("got %q %v", v.Reveal(), err)
	}
	for name, p := range map[string]string{
		"world writable": write(t, "x", 0o602),
		"group writable": write(t, "x", 0o620),
		"empty":          write(t, "\n", 0o600),
		"too big":        write(t, strings.Repeat("x", MaxFileSize+1), 0o600),
		"directory":      t.TempDir(),
		"missing":        filepath.Join(t.TempDir(), "nope"),
		"fifo":           mkfifo(t),
	} {
		if _, err := ReadFile(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestReadKeyFile(t *testing.T) {
	good := "pQ4m0g2Yk3qvQW1o8bqgK3n4cS1u9xJ0eF7rT6yU5iA=" // 32 random bytes
	if v, err := ReadKeyFile(write(t, good, 0o400), 32); err != nil || v.Len() != 32 {
		t.Fatalf("good key: %v", err)
	}
	if _, err := ReadKeyFile(write(t, good, 0o400), 33); err == nil {
		t.Error("short key accepted")
	}
	if _, err := ReadKeyFile(write(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", 0o400), 32); err == nil {
		t.Error("all-zero key accepted")
	}
	if _, err := ReadKeyFile(write(t, "not base64!!", 0o400), 1); err == nil {
		t.Error("non-base64 accepted")
	}
}

func TestNeverPrinted(t *testing.T) {
	v := Value{b: []byte("TOPSECRET")}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "v", v, "s", struct{ V Value }{v})
	out := buf.String() + fmt.Sprint(v) + fmt.Sprintf("%v %+v %#v %s %q", v, v, v, v, v)
	if strings.Contains(out, "TOPSECRET") {
		t.Fatalf("secret leaked: %s", out)
	}
}

func TestLooksWeak(t *testing.T) {
	if !LooksWeak(bytes.Repeat([]byte("changeme"), 4)) || !LooksWeak(make([]byte, 32)) {
		t.Error("weak not detected")
	}
	if LooksWeak([]byte("pQ4m0g2Yk3qvQW1o8bqgK3n4cS1u9xJ0")) {
		t.Error("false positive")
	}
}

func mkfifo(t *testing.T) string {
	p := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	return p
}
