package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/kobesoft-labs/tenant-pass/internal/config"
	"github.com/kobesoft-labs/tenant-pass/internal/kms"
	"github.com/kobesoft-labs/tenant-pass/pass"
)

// Build loads keys (signing key locally or from Vault Transit, and the
// identity provider's JWKS) and returns a Gateway.
func Build(ctx context.Context, f *File, logger *slog.Logger) (*Gateway, error) {
	if _, err := f.validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration:\n%w", err)
	}

	// Signing key.
	sk := f.SigningKey
	if !pass.NamePattern.MatchString(sk.ID) {
		return nil, errors.New("signing_key.id is invalid")
	}
	var signer pass.Signer
	switch {
	case (sk.PrivateKeyFile == "") == (sk.Transit == nil):
		return nil, errors.New("signing_key: exactly one of private_key_file and transit is required")
	case sk.Transit != nil:
		v, err := vaultFromConfig(f)
		if err != nil {
			return nil, err
		}
		ts, err := v.NewTransitSigner(ctx, sk.Transit.Key, sk.Transit.Version)
		if err != nil {
			return nil, fmt.Errorf("signing_key: %w", err)
		}
		signer = pass.Signer{KeyID: sk.ID, Remote: ts.Sign}
	default:
		k, err := config.ReadEd25519PrivateKey(sk.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("signing_key: %w", err)
		}
		signer = pass.Signer{KeyID: sk.ID, Key: k}
	}

	// Identity provider keys.
	var ks *keySet
	var err error
	if f.Identity.JWKSFile != "" {
		ks, err = newFileKeySet(f.Identity.JWKSFile)
	} else {
		u, perr := url.Parse(f.Identity.JWKSURL)
		if perr != nil {
			return nil, perr
		}
		var tc *tls.Config
		if tc, err = f.Identity.JWKSTLS.Build(u.Hostname()); err == nil {
			ks, err = newURLKeySet(ctx, f.Identity.JWKSURL, tc)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	g, err := New(f, ks, signer, logger)
	if err != nil {
		return nil, err
	}
	go ks.refreshLoop(context.WithoutCancel(ctx), logger)
	return g, nil
}

func vaultFromConfig(f *File) (*kms.Vault, error) {
	v := f.KMS.Vault
	if v == nil {
		return nil, errors.New("signing_key.transit requires kms.vault")
	}
	vc := kms.VaultConfig{Address: v.Address, TokenFile: v.TokenFile, Namespace: v.Namespace, Mount: v.Mount}
	if v.InsecurePlaintext {
		if !f.AllowInsecurePlaintext {
			return nil, errors.New("kms.vault.insecure_plaintext requires allow_insecure_plaintext (testing only)")
		}
	} else {
		u, err := url.Parse(v.Address)
		if err != nil {
			return nil, err
		}
		if vc.TLS, err = v.TLS.Build(u.Hostname()); err != nil {
			return nil, err
		}
	}
	return kms.NewVault(vc)
}
