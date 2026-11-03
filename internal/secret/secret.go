// Package secret loads secrets from files and keeps them out of logs.
//
// tenant-pass never accepts secrets on the command line or inline in its
// configuration file: command lines are visible to every local user
// (/proc/<pid>/cmdline, ps), and configuration files tend to be copied,
// committed and pasted into tickets. Secrets come from separate files,
// typically mounted by the orchestrator (Docker/Swarm secrets,
// Kubernetes secrets, systemd credentials).
package secret

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// MaxFileSize bounds secret files. Real secrets are a few hundred bytes;
// anything larger is a misconfiguration (for example a directory of
// certificates mounted at the wrong path).
const MaxFileSize = 64 << 10

// Value holds secret bytes. Its String, GoString, Format and LogValue
// methods never reveal the contents, so a Value accidentally passed to a
// logger or fmt prints "[redacted]".
type Value struct{ b []byte }

// Bytes returns the secret. Callers must not log or retain it longer than
// necessary.
func (v Value) Bytes() []byte { return v.b }

// Reveal returns the secret as a string. Same rules as Bytes.
func (v Value) Reveal() string { return string(v.b) }

// Len returns the length of the secret.
func (v Value) Len() int { return len(v.b) }

func (Value) String() string               { return "[redacted]" }
func (Value) GoString() string             { return "[redacted]" }
func (Value) LogValue() slog.Value         { return slog.StringValue("[redacted]") }
func (Value) MarshalText() ([]byte, error) { return []byte("[redacted]"), nil }

// Warn receives non-fatal findings (for example a secret file readable by
// other users). The default discards them; main sets it to the logger.
var Warn = func(msg string, path string) {}

// ReadFile reads a secret file. It rejects files that are not regular
// files, that are writable by group or others (anyone who can write the
// file can replace the secret), or that are empty or too large. A
// trailing newline (as added by most editors and `echo`) is removed.
//
// Files readable by group or others are accepted with a warning, because
// common secret mounts (Docker Swarm, Kubernetes) are mode 0444 inside a
// container whose only user is tenant-pass.
func ReadFile(path string) (Value, error) {
	if path == "" {
		return Value{}, errors.New("secret: empty path")
	}
	f, err := os.Open(path)
	if err != nil {
		return Value{}, fmt.Errorf("secret: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return Value{}, fmt.Errorf("secret: %w", err)
	}
	if !st.Mode().IsRegular() {
		return Value{}, fmt.Errorf("secret: %s is not a regular file", path)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return Value{}, fmt.Errorf("secret: %s is writable by group or others (mode %o)", path, st.Mode().Perm())
	}
	if st.Mode().Perm()&0o044 != 0 {
		Warn("secret file is readable by group or others", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return Value{}, fmt.Errorf("secret: %w", err)
	}
	if len(b) > MaxFileSize {
		return Value{}, fmt.Errorf("secret: %s is larger than %d bytes", path, MaxFileSize)
	}
	b = bytes.TrimSuffix(b, []byte("\n"))
	b = bytes.TrimSuffix(b, []byte("\r"))
	if len(b) == 0 {
		return Value{}, fmt.Errorf("secret: %s is empty", path)
	}
	return Value{b: b}, nil
}

// ReadKeyFile reads a file containing base64 (standard or URL alphabet,
// padded or not) and returns the decoded bytes. It enforces a minimum
// decoded length and rejects obviously non-random values.
func ReadKeyFile(path string, minLen int) (Value, error) {
	v, err := ReadFile(path)
	if err != nil {
		return Value{}, err
	}
	s := strings.TrimSpace(v.Reveal())
	var raw []byte
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err = enc.DecodeString(s); err == nil {
			break
		}
	}
	if err != nil {
		return Value{}, fmt.Errorf("secret: %s does not contain base64", path)
	}
	if len(raw) < minLen {
		return Value{}, fmt.Errorf("secret: %s decodes to %d bytes, need at least %d", path, len(raw), minLen)
	}
	if LooksWeak(raw) {
		return Value{}, fmt.Errorf("secret: %s does not look random (repeated pattern)", path)
	}
	return Value{b: raw}, nil
}

// LooksWeak catches the most common placeholder keys: all one byte value,
// or a short pattern repeated (for example 32 zero bytes, or
// "changemechangeme..."). It is a sanity check, not an entropy test.
func LooksWeak(b []byte) bool {
	for period := 1; period <= 8 && period < len(b); period++ {
		repeated := true
		for i := period; i < len(b); i++ {
			if b[i] != b[i-period] {
				repeated = false
				break
			}
		}
		if repeated {
			return true
		}
	}
	return false
}
