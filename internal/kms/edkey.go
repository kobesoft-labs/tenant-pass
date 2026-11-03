package kms

import (
	"crypto/ed25519"
	"errors"

	"filippo.io/edwards25519"
)

// CheckEd25519PublicKey rejects public keys that must never be trusted
// as verification keys:
//
//   - encodings that are not a valid curve point, or not the canonical
//     encoding of one;
//   - points of small order (the identity, the all-zero encoding, and the
//     other low-order points). Go's ed25519.Verify accepts signatures
//     under such keys that anyone can produce without a private key, so a
//     placeholder or corrupted key in the configuration would let anyone
//     forge passes and tickets.
func CheckEd25519PublicKey(pk ed25519.PublicKey) error {
	if len(pk) != ed25519.PublicKeySize {
		return errors.New("Ed25519 public key must be 32 bytes")
	}
	p, err := new(edwards25519.Point).SetBytes(pk)
	if err != nil {
		return errors.New("Ed25519 public key is not a valid point")
	}
	if string(p.Bytes()) != string(pk) {
		return errors.New("Ed25519 public key is not canonically encoded")
	}
	// [8]P == identity  <=>  P has small order.
	if new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return errors.New("Ed25519 public key has small order (placeholder or corrupted key?)")
	}
	return nil
}
