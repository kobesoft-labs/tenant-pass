// Package paseto implements the PASETO v4.public token format
// (Ed25519 signatures), and nothing else.
//
// Specification: https://github.com/paseto-standard/paseto-spec
// (docs/01-Protocol-Versions/Version4.md, "Sign" and "Verify").
//
// Why a local implementation instead of a third-party library:
//
//   - tenant-pass needs exactly one PASETO purpose and version
//     (v4.public). Implementing it takes well under 200 lines on top of
//     the Go standard library's crypto/ed25519, and keeps the
//     security-critical dependency surface at zero.
//   - Only "v4.public." tokens are ever accepted. There is no algorithm
//     negotiation, so the classic JWT "alg" confusion attacks do not
//     apply.
//
// The implementation is checked against the official PASETO test vectors
// (see paseto_test.go).
//
// Note on footers: the footer of a v4.public token is authenticated (it
// is covered by the signature through PAE), but it is NOT encrypted, and
// it must not be trusted until the signature is verified. Callers that
// need to read the footer *before* verification (for example to select a
// key by key ID) must use [Footer] and treat the result as untrusted input
// that only selects which key to try.
package paseto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
)

// header is the only token header this package accepts or produces.
const header = "v4.public."

// MaxTokenLength bounds the size of a token string this package will
// even look at. It exists to make the cost of handling hostile input
// small and predictable. tenant-pass tokens are a few hundred bytes.
const MaxTokenLength = 8192

// Errors returned by [Verify] and [Footer]. They are deliberately coarse:
// callers log them for diagnostics, but should not leak which check failed
// to an untrusted party.
var (
	// ErrMalformed means the string is not a syntactically valid
	// v4.public token (wrong header, bad base64, too short, too long).
	ErrMalformed = errors.New("paseto: malformed token")
	// ErrSignature means the token is well formed but the signature does
	// not verify with the given key, footer and implicit assertion.
	ErrSignature = errors.New("paseto: invalid signature")
)

// b64 is unpadded base64url, as required by PASETO.
//
// Strict() makes the decoder reject encodings whose unused trailing bits
// are non-zero. Without it, several distinct strings would decode to the
// same bytes ("token malleability"), which is harmless for the signature
// but surprising for anything that compares or caches tokens as strings.
var b64 = base64.RawURLEncoding.Strict()

// pae implements Pre-Authentication Encoding (PAE) from the PASETO spec:
//
//	PAE(p1..pn) = LE64(n) || LE64(len(p1)) || p1 || ... || LE64(len(pn)) || pn
//
// where LE64 is a little-endian 64-bit unsigned integer with the most
// significant bit cleared. PAE makes the boundaries between pieces
// unambiguous, so no two different (message, footer, assertion) tuples
// can produce the same signed byte string.
func pae(pieces ...[]byte) []byte {
	size := 8
	for _, p := range pieces {
		size += 8 + len(p)
	}
	out := make([]byte, 0, size)
	out = appendLE64(out, uint64(len(pieces)))
	for _, p := range pieces {
		out = appendLE64(out, uint64(len(p)))
		out = append(out, p...)
	}
	return out
}

// appendLE64 appends n as LE64. The spec requires clearing the top bit
// so that implementations in languages without unsigned 64-bit integers
// interoperate; real lengths never come close to 2^63 anyway.
func appendLE64(b []byte, n uint64) []byte {
	return binary.LittleEndian.AppendUint64(b, n&^(uint64(1)<<63))
}

// Sign creates a v4.public token for message m, with optional footer f
// and optional implicit assertion i.
//
// The implicit assertion is signed but not transmitted: the verifier must
// supply the same bytes. tenant-pass uses it for domain separation, so a
// token signed by the same key for some other purpose is never accepted
// as a tenant-pass token.
//
// Ed25519 signing is deterministic, so Sign returns the same token for the
// same inputs (the official test vectors rely on this).
func Sign(sk ed25519.PrivateKey, m, f, i []byte) (string, error) {
	if len(sk) != ed25519.PrivateKeySize {
		return "", errors.New("paseto: invalid private key size")
	}
	sig := ed25519.Sign(sk, pae([]byte(header), m, f, i))

	body := make([]byte, 0, len(m)+len(sig))
	body = append(body, m...)
	body = append(body, sig...)

	var sb strings.Builder
	sb.WriteString(header)
	sb.WriteString(b64.EncodeToString(body))
	if len(f) > 0 {
		sb.WriteByte('.')
		sb.WriteString(b64.EncodeToString(f))
	}
	return sb.String(), nil
}

// split parses the outer structure of a token without verifying it.
// It returns the decoded body (message || signature) and the decoded
// footer (nil when absent).
func split(token string) (body, footer []byte, err error) {
	if len(token) > MaxTokenLength || !strings.HasPrefix(token, header) {
		return nil, nil, ErrMalformed
	}
	rest := token[len(header):]
	// Go's base64 decoder silently skips '\r' and '\n' even in strict
	// mode. Reject every byte outside the base64url alphabet and '.'
	// up front, so a token has exactly one textual form.
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return nil, nil, ErrMalformed
		}
	}

	// At most one '.' may follow the header: "<body>" or "<body>.<footer>".
	bodyPart, footerPart, hasFooter := strings.Cut(rest, ".")
	if strings.Contains(footerPart, ".") {
		return nil, nil, ErrMalformed
	}
	body, err = b64.DecodeString(bodyPart)
	if err != nil || len(body) < ed25519.SignatureSize {
		return nil, nil, ErrMalformed
	}
	if hasFooter {
		// A present-but-empty footer ("<body>.") is not something any
		// conforming implementation produces; reject it so that every
		// token has exactly one string form.
		if footerPart == "" {
			return nil, nil, ErrMalformed
		}
		footer, err = b64.DecodeString(footerPart)
		if err != nil {
			return nil, nil, ErrMalformed
		}
	}
	return body, footer, nil
}

// Footer returns the decoded footer of a token WITHOUT verifying the
// signature. The result is untrusted. It is intended only for choosing a
// verification key by key ID; everything else must wait for [Verify].
func Footer(token string) ([]byte, error) {
	_, footer, err := split(token)
	return footer, err
}

// Verify checks token against public key pk and implicit assertion i and,
// on success, returns the signed message and the (now authenticated)
// footer.
//
// Verify never returns a message unless the signature is valid.
func Verify(pk ed25519.PublicKey, token string, i []byte) (message, footer []byte, err error) {
	if len(pk) != ed25519.PublicKeySize {
		return nil, nil, errors.New("paseto: invalid public key size")
	}
	body, footer, err := split(token)
	if err != nil {
		return nil, nil, err
	}
	cut := len(body) - ed25519.SignatureSize
	m, sig := body[:cut], body[cut:]

	if !ed25519.Verify(pk, pae([]byte(header), m, footer, i), sig) {
		return nil, nil, ErrSignature
	}
	return m, footer, nil
}
