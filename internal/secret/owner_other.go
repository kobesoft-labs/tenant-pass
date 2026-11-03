//go:build !unix

package secret

import "io/fs"

// checkOwner is a no-op on platforms without Unix ownership semantics.
func checkOwner(fs.FileInfo) error { return nil }
