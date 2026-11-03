//go:build !unix

package secret

import (
	"io/fs"
	"os"
)

// checkOwner is a no-op on platforms without Unix ownership semantics.
func checkOwner(fs.FileInfo) error { return nil }

func openNoBlock(path string) (*os.File, error) { return os.Open(path) }
