//go:build unix

package secret

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// checkOwner requires the file to be owned by the effective user or by
// root. A file owned by another unprivileged user can be rewritten by
// that user regardless of its mode bits (chmod is the owner's right).
func checkOwner(st fs.FileInfo) error {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot determine file owner")
	}
	if sys.Uid != 0 && int(sys.Uid) != os.Geteuid() {
		return errors.New("file is owned by another user")
	}
	return nil
}
