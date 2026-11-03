// Package pwhash computes the password verifiers that tenant-pass hands to
// stores, so that plaintext passwords never appear in SQL statements,
// server logs, statement statistics or replication streams.
//
//   - PostgreSQL: SCRAM-SHA-256 verifier (RFC 5802 / RFC 7677), the
//     format PostgreSQL stores in pg_authid.rolpassword.
//   - MySQL: caching_sha2_password authentication string, which is a
//     SHA-256 crypt (Ulrich Drepper's "SHA-crypt") digest with a 20-byte
//     salt and MySQL's own framing.
//   - Redis: ACL "#<hex sha256>" password hash.
//
// Every function here is deterministic given its inputs. The salts come
// from the rotation package, which derives them from the rotation key, so
// that every tenant-pass replica produces identical verifiers.
package pwhash

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// PostgreSQL SCRAM-SHA-256
// ---------------------------------------------------------------------------

// SCRAMIterations is the PBKDF2 iteration count for SCRAM verifiers.
//
// 4096 is PostgreSQL's default (scram_iterations). The iteration count
// exists to slow down guessing of human-chosen passwords; tenant-pass
// passwords are 256-bit random values, so a higher count would only add
// latency to every client connection without making anything safer.
const SCRAMIterations = 4096

// SCRAMSaltLength is the salt size PostgreSQL itself uses.
const SCRAMSaltLength = 16

// SCRAM returns a PostgreSQL SCRAM-SHA-256 verifier:
//
//	SCRAM-SHA-256$<iterations>:<base64 salt>$<base64 StoredKey>:<base64 ServerKey>
//
// The verifier does not let anyone log in: authenticating requires the
// ClientKey, and StoredKey = SHA-256(ClientKey) cannot be inverted.
func SCRAM(password string, salt []byte) (string, error) {
	if len(salt) != SCRAMSaltLength {
		return "", errors.New("pwhash: SCRAM salt must be 16 bytes")
	}
	salted, err := pbkdf2.Key(sha256.New, password, salt, SCRAMIterations, sha256.Size)
	if err != nil {
		return "", err
	}
	clientKey := hmacSHA256(salted, "Client Key")
	storedKey := sha256.Sum256(clientKey)
	serverKey := hmacSHA256(salted, "Server Key")
	enc := base64.StdEncoding
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", SCRAMIterations,
		enc.EncodeToString(salt), enc.EncodeToString(storedKey[:]), enc.EncodeToString(serverKey)), nil
}

func hmacSHA256(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

// ---------------------------------------------------------------------------
// MySQL caching_sha2_password
// ---------------------------------------------------------------------------

// MySQL framing constants, from sql/auth/sha2_password.h in the MySQL
// server source: the authentication string is
//
//	"$A$" <3 hex digits: rounds/1000> "$" <20-byte salt> <43-char digest>
const (
	mysqlPrefix        = "$A$"
	mysqlSaltLength    = 20
	mysqlRoundsDefault = 5000 // MySQL's default and minimum
	mysqlDigestLength  = 43
)

// MySQLSalt maps arbitrary random bytes to a 20-byte salt that is valid
// for MySQL. MySQL requires salt bytes to be 7-bit and never '\0' or
// '$'. Using the crypt base64 alphabet satisfies that and keeps the
// authentication string printable.
func MySQLSalt(random []byte) ([]byte, error) {
	if len(random) < mysqlSaltLength {
		return nil, errors.New("pwhash: need at least 20 random bytes for a MySQL salt")
	}
	out := make([]byte, mysqlSaltLength)
	for i := range out {
		out[i] = cryptAlphabet[random[i]&0x3f]
	}
	return out, nil
}

// MySQL returns a caching_sha2_password authentication string for
// password with the given 20-byte salt. tenant-pass passes it to MySQL as
// a hex literal ("IDENTIFIED WITH caching_sha2_password AS 0x...").
func MySQL(password string, salt []byte) (string, error) {
	if len(salt) != mysqlSaltLength {
		return "", errors.New("pwhash: MySQL salt must be 20 bytes")
	}
	for _, c := range salt {
		if c == 0 || c == '$' || c > 0x7f {
			return "", errors.New("pwhash: invalid MySQL salt byte")
		}
	}
	digest := shaCrypt256([]byte(password), salt, mysqlRoundsDefault)
	return fmt.Sprintf("%s%03X$%s%s", mysqlPrefix, mysqlRoundsDefault/1000, salt, digest), nil
}

// MySQLMatches reports whether authString (as stored in
// mysql.user.authentication_string) is the caching_sha2_password hash of
// password. tenant-pass uses it to find out which of its own windows an
// account's current passwords belong to, without trusting any metadata.
func MySQLMatches(authString, password string) bool {
	if len(authString) != len(mysqlPrefix)+4+mysqlSaltLength+mysqlDigestLength ||
		!strings.HasPrefix(authString, mysqlPrefix) || authString[6] != '$' {
		return false
	}
	if authString[3:6] != fmt.Sprintf("%03X", mysqlRoundsDefault/1000) {
		// Hashes with other round counts were not created by
		// tenant-pass; treat them as foreign.
		return false
	}
	salt := []byte(authString[7 : 7+mysqlSaltLength])
	want, err := MySQL(password, salt)
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(want), []byte(authString))
}

// MySQLHex returns s as a MySQL hex literal (0x...). Using a hex literal
// means the authentication string, which may contain quote characters
// in general, is never interpolated into SQL as text.
func MySQLHex(s string) string {
	return "0x" + strings.ToUpper(hex.EncodeToString([]byte(s)))
}

// cryptAlphabet is the base64 alphabet used by crypt(3).
const cryptAlphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// shaCrypt256 implements the SHA-256 variant of SHA-crypt, as specified by
// Ulrich Drepper ("Unix crypt using SHA-256 and SHA-512",
// https://www.akkadia.org/drepper/SHA-crypt.txt), returning only the
// 43-character encoded digest. Step numbers refer to that document.
//
// The only deviation required by MySQL is that the salt may be 20 bytes
// (Drepper truncates salts to 16); MySQL uses all 20.
func shaCrypt256(p, s []byte, rounds int) string {
	// Steps 4-8: B = SHA256(P || S || P).
	h := sha256.New()
	h.Write(p)
	h.Write(s)
	h.Write(p)
	b := h.Sum(nil)

	// Steps 1-3, 9-12: A.
	h.Reset()
	h.Write(p)
	h.Write(s)
	for n := len(p); n > 0; n -= 32 {
		h.Write(b[:min(n, 32)])
	}
	for n := len(p); n > 0; n >>= 1 {
		if n&1 != 0 {
			h.Write(b)
		} else {
			h.Write(p)
		}
	}
	a := h.Sum(nil)

	// Steps 13-16: P' derived from DP = SHA256(P repeated len(P) times).
	h.Reset()
	for range len(p) {
		h.Write(p)
	}
	dp := h.Sum(nil)
	pp := repeatTo(dp, len(p))

	// Steps 17-20: S' derived from DS = SHA256(S repeated 16+A[0] times).
	h.Reset()
	for range 16 + int(a[0]) {
		h.Write(s)
	}
	ds := h.Sum(nil)
	sp := repeatTo(ds, len(s))

	// Step 21: the rounds.
	c := a
	for i := range rounds {
		h.Reset()
		if i&1 != 0 {
			h.Write(pp)
		} else {
			h.Write(c)
		}
		if i%3 != 0 {
			h.Write(sp)
		}
		if i%7 != 0 {
			h.Write(pp)
		}
		if i&1 != 0 {
			h.Write(c)
		} else {
			h.Write(pp)
		}
		c = h.Sum(nil)
	}

	// Step 22: encode with the SHA-256 byte permutation.
	var out strings.Builder
	enc := func(b2, b1, b0 byte, n int) {
		w := uint(b2)<<16 | uint(b1)<<8 | uint(b0)
		for range n {
			out.WriteByte(cryptAlphabet[w&0x3f])
			w >>= 6
		}
	}
	for _, g := range [10][3]int{{0, 10, 20}, {21, 1, 11}, {12, 22, 2}, {3, 13, 23}, {24, 4, 14},
		{15, 25, 5}, {6, 16, 26}, {27, 7, 17}, {18, 28, 8}, {9, 19, 29}} {
		enc(c[g[0]], c[g[1]], c[g[2]], 4)
	}
	enc(0, c[31], c[30], 3)
	return out.String()
}

// repeatTo returns d repeated (and truncated) to exactly n bytes.
func repeatTo(d []byte, n int) []byte {
	out := make([]byte, 0, n)
	for len(out) < n {
		out = append(out, d[:min(len(d), n-len(out))]...)
	}
	return out
}

// ---------------------------------------------------------------------------
// Redis ACL
// ---------------------------------------------------------------------------

// Redis returns the lowercase hex SHA-256 of password, which is how Redis
// stores ACL passwords and how "ACL SETUSER <user> #<hash>" accepts them.
//
// An unsalted SHA-256 is Redis's choice, not ours. It is adequate here
// only because tenant-pass passwords are 256-bit random values; it would
// be inadequate for human-chosen passwords.
func Redis(password string) string {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:])
}
