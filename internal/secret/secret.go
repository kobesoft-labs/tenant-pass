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

// readChecked opens path once and applies every check to that open file
// (no gap between checking and reading in which the file could be
// swapped): it must be a regular file, not writable by group or others,
// owned by the current user or by root, and at most max bytes.
func readChecked(path string, max int64) ([]byte, os.FileMode, error) {
	if path == "" {
		return nil, 0, errors.New("empty path")
	}
	// openNoBlock: opening a FIFO with a plain open would block forever
	// waiting for a writer; the regular-file check below then refuses it.
	f, err := openNoBlock(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	if !st.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("%s is not a regular file", path)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return nil, 0, fmt.Errorf("%s is writable by group or others (mode %o)", path, st.Mode().Perm())
	}
	if err := checkOwner(st); err != nil {
		return nil, 0, fmt.Errorf("%s: %w", path, err)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, 0, err
	}
	if int64(len(b)) > max {
		return nil, 0, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	return b, st.Mode().Perm(), nil
}

// MaxTrustedFileSize bounds files read with ReadTrusted.
const MaxTrustedFileSize = 4 << 20

// ReadTrusted reads a file that is not secret but decides what is
// trusted: public keys, CA bundles, certificates, JWKS, configuration.
// Anyone who can write such a file can make tenant-pass trust their own
// key, so the same integrity checks as for secrets apply (regular file,
// not writable by group or others, owned by the current user or root);
// being readable by others is fine.
func ReadTrusted(path string) ([]byte, error) {
	b, _, err := readChecked(path, MaxTrustedFileSize)
	if err != nil {
		return nil, fmt.Errorf("file: %w", err)
	}
	return b, nil
}

// ReadFile reads a secret file. It rejects files that are not regular
// files, that are writable by group or others (anyone who can write the
// file can replace the secret), that are owned by another unprivileged
// user, or that are empty or too large. A trailing newline (as added by
// most editors and `echo`) is removed.
//
// Files readable by group or others are accepted with a warning, because
// common secret mounts (Docker Swarm, Kubernetes) are mode 0444 inside a
// container whose only user is tenant-pass.
func ReadFile(path string) (Value, error) {
	b, mode, err := readChecked(path, MaxFileSize)
	if err != nil {
		return Value{}, fmt.Errorf("secret: %w", err)
	}
	if mode&0o044 != 0 {
		Warn("secret file is readable by group or others", path)
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
