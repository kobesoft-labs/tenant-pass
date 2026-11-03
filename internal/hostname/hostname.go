// Package hostname validates DNS host names in their canonical form.
//
// tenant-pass maps a host name (taken from a signed pass) to a tenant.
// If two spellings of the same name ("Acme.example.com",
// "acme.example.com.", "acme.example.com:443") were accepted, a directory
// lookup could match one spelling and miss another, or match the wrong
// row in a case-sensitive database column. To rule this out, tenant-pass
// does not normalize names: the gateway must send the canonical form, and
// anything else is rejected.
//
// Canonical form here means:
//
//   - ASCII only. Internationalized names must already be converted to
//     their A-label ("xn--...") form by the gateway.
//   - Lower case letters, digits and '-' only; labels separated by '.'.
//   - No port, no trailing dot, no empty labels.
//   - Each label 1-63 bytes, not starting or ending with '-'.
//   - Total length at most 253 bytes.
//   - At least two labels (a bare "localhost"-style name is almost
//     certainly a mistake for a tenant host).
//   - Not an IP address literal (the last label must not be all digits).
package hostname

import "strings"

// MaxLength is the maximum length of a host name in presentation form.
const MaxLength = 253

// IsCanonical reports whether h is a canonical host name as defined in
// the package documentation.
func IsCanonical(h string) bool {
	if len(h) == 0 || len(h) > MaxLength {
		return false
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !validLabel(l) {
			return false
		}
	}
	// Reject dotted-quad IPv4 and similar numeric names: a top-level
	// label made only of digits is never a real TLD.
	last := labels[len(labels)-1]
	allDigits := true
	for i := 0; i < len(last); i++ {
		if last[i] < '0' || last[i] > '9' {
			allDigits = false
			break
		}
	}
	return !allDigits
}

func validLabel(l string) bool {
	if len(l) == 0 || len(l) > 63 {
		return false
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return false
		}
	}
	return true
}
