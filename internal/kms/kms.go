// Package kms abstracts where tenant-pass's own keys live.
//
// Two kinds of keys are needed:
//
//   - MAC keys (HMAC-SHA256): the rotation keys from which passwords are
//     derived.
//   - Signing keys (Ed25519): the key tenant-pass uses to sign job
//     tickets, and the key tenant-pass-gateway uses to sign passes.
//
// Each can be held locally (a key file loaded into memory) or remotely in
// HashiCorp Vault / OpenBao Transit, where the key never leaves the key
// management system: tenant-pass sends the message and receives the MAC
// or signature.
//
// What remote keys buy, precisely: an attacker who compromises a
// tenant-pass host can use the key only while they keep access to the
// host and its Vault token. They cannot copy the key and keep deriving
// passwords offline after they have been evicted, and Vault's audit log
// records every use. Remote keys do not stop an attacker who is in
// control of the host right now.
package kms

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// MAC computes HMAC-SHA256 with a key it holds.
type MAC interface {
	// MAC returns HMAC-SHA256(key, msg).
	MAC(ctx context.Context, msg []byte) ([]byte, error)
	// Fingerprint identifies the key material for duplicate detection,
	// without revealing it. Remote keys return their location.
	Fingerprint() string
}

// Signer signs with an Ed25519 key it holds.
type Signer interface {
	// Public returns the public key.
	Public() ed25519.PublicKey
	// Sign returns the Ed25519 signature of msg.
	Sign(ctx context.Context, msg []byte) ([]byte, error)
}

// ---------------------------------------------------------------------------
// Local keys
// ---------------------------------------------------------------------------

// LocalMAC is an HMAC key held in memory.
type LocalMAC struct{ key []byte }

// NewLocalMAC returns a MAC over key. The caller has validated key.
func NewLocalMAC(key []byte) *LocalMAC { return &LocalMAC{key: append([]byte(nil), key...)} }

// MAC implements MAC.
func (l *LocalMAC) MAC(_ context.Context, msg []byte) ([]byte, error) {
	m := hmac.New(sha256.New, l.key)
	m.Write(msg)
	return m.Sum(nil), nil
}

// Fingerprint implements MAC. It is a hash of the key, so identical keys
// configured under two IDs are detected without comparing raw secrets in
// more places than necessary.
func (l *LocalMAC) Fingerprint() string {
	h := sha256.Sum256(append([]byte("tenant-pass/v1/key-fingerprint"), l.key...))
	return "local:" + hex.EncodeToString(h[:])
}

// LocalSigner is an Ed25519 private key held in memory.
type LocalSigner struct{ key ed25519.PrivateKey }

// NewLocalSigner wraps key.
func NewLocalSigner(key ed25519.PrivateKey) (*LocalSigner, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("kms: invalid Ed25519 private key")
	}
	return &LocalSigner{key: key}, nil
}

// Public implements Signer.
func (l *LocalSigner) Public() ed25519.PublicKey { return l.key.Public().(ed25519.PublicKey) }

// Sign implements Signer.
func (l *LocalSigner) Sign(_ context.Context, msg []byte) ([]byte, error) {
	return ed25519.Sign(l.key, msg), nil
}
