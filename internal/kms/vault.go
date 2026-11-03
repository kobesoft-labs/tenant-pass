package kms

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kobesoft-labs/tenant-pass/internal/secret"
)

// VaultConfig configures a connection to HashiCorp Vault or OpenBao.
type VaultConfig struct {
	// Address is the base URL, for example "https://vault.internal:8200".
	// It must be https unless plaintext was explicitly allowed.
	Address string
	// TokenFile contains the Vault token. It is re-read on every request
	// (with the usual secret-file checks), so a token rotated by Vault
	// Agent or a sidecar takes effect without a restart.
	TokenFile string
	// Namespace is sent as X-Vault-Namespace (Vault Enterprise / HCP).
	Namespace string
	// Mount is the Transit mount path (default "transit").
	Mount string
	// TLS is the client TLS configuration (verifying the server). Nil
	// means plaintext, which the caller only allows for testing.
	TLS *tls.Config
}

// Vault is a minimal client for the Transit secrets engine. It
// implements only what tenant-pass needs (hmac, sign, read key) on top of
// net/http, to avoid a large SDK dependency.
type Vault struct {
	cfg  VaultConfig
	base *url.URL
	hc   *http.Client
}

// safePathSegment restricts path segments interpolated into Vault URLs.
// It must start with an alphanumeric character, which excludes "." and
// "..".
var safePathSegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// NewVault validates cfg and returns a client.
func NewVault(cfg VaultConfig) (*Vault, error) {
	u, err := url.Parse(cfg.Address)
	if err != nil || u.Host == "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.User != nil {
		return nil, errors.New("kms: vault address must be a bare URL such as https://vault.internal:8200")
	}
	switch {
	case u.Scheme == "https" && cfg.TLS != nil:
	case u.Scheme == "http" && cfg.TLS == nil:
	default:
		return nil, errors.New("kms: vault address scheme does not match the TLS setting")
	}
	if cfg.Mount == "" {
		cfg.Mount = "transit"
	}
	for _, seg := range strings.Split(cfg.Mount, "/") {
		if !safePathSegment.MatchString(seg) {
			return nil, errors.New("kms: invalid transit mount path")
		}
	}
	if cfg.TokenFile == "" {
		return nil, errors.New("kms: vault token_file is required")
	}
	if _, err := secret.ReadFile(cfg.TokenFile); err != nil {
		return nil, err
	}
	u.Path = ""
	tr := &http.Transport{
		TLSClientConfig:     cfg.TLS,
		Proxy:               nil, // never send key material through an environment-configured proxy
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	return &Vault{cfg: cfg, base: u, hc: &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
		// Never follow redirects: a redirect could send the token to
		// another host.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// call sends a request to /v1/<mount>/<path> and decodes the "data"
// member of the response into out.
func (v *Vault) call(ctx context.Context, method, path string, body any, out any) error {
	token, err := secret.ReadFile(v.cfg.TokenFile)
	if err != nil {
		return err
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	u := *v.base
	u.Path = "/v1/" + v.cfg.Mount + "/" + path
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", token.Reveal())
	req.Header.Set("X-Vault-Request", "true")
	if v.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.cfg.Namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := v.hc.Do(req)
	if err != nil {
		// url.Error contains the URL but never the token header.
		return fmt.Errorf("kms: vault request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("kms: vault response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// The error body may echo request details; report the status only.
		return fmt.Errorf("kms: vault returned HTTP %d for %s", resp.StatusCode, path)
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil || len(env.Data) == 0 {
		return errors.New("kms: unexpected vault response")
	}
	return json.Unmarshal(env.Data, out)
}

// parseVaultValue decodes "vault:v<version>:<base64>" and checks the
// version.
func parseVaultValue(s string, wantVersion int) ([]byte, error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 || parts[0] != "vault" || parts[1] != "v"+strconv.Itoa(wantVersion) {
		return nil, errors.New("kms: unexpected vault value format or key version")
	}
	return base64.StdEncoding.DecodeString(parts[2])
}

// TransitMAC is an HMAC key in Transit, pinned to one key version.
//
// Pinning matters: passwords are derived from the MAC, so the same input
// must give the same output for as long as the rotation key is in force.
// Rotating the Transit key creates a new version; configure it as a new
// tenant-pass rotation key with its own not_before.
type TransitMAC struct {
	v       *Vault
	key     string
	version int
}

// NewTransitMAC returns a MAC backed by Transit key name at version.
func (v *Vault) NewTransitMAC(name string, version int) (*TransitMAC, error) {
	if !safePathSegment.MatchString(name) || version < 1 {
		return nil, errors.New("kms: transit key name and version (>= 1) are required")
	}
	return &TransitMAC{v: v, key: name, version: version}, nil
}

// MAC implements MAC.
func (t *TransitMAC) MAC(ctx context.Context, msg []byte) ([]byte, error) {
	var out struct {
		HMAC string `json:"hmac"`
	}
	err := t.v.call(ctx, http.MethodPost, "hmac/"+t.key+"/sha2-256", map[string]any{
		"input":       base64.StdEncoding.EncodeToString(msg),
		"key_version": t.version,
	}, &out)
	if err != nil {
		return nil, err
	}
	mac, err := parseVaultValue(out.HMAC, t.version)
	if err != nil || len(mac) != sha256.Size {
		return nil, errors.New("kms: invalid HMAC from vault")
	}
	return mac, nil
}

// Fingerprint implements MAC.
func (t *TransitMAC) Fingerprint() string {
	return fmt.Sprintf("transit:%s/%s/%s@%d", t.v.base.Host, t.v.cfg.Mount, t.key, t.version)
}

// TransitSigner is an Ed25519 key in Transit, pinned to one key version.
type TransitSigner struct {
	v       *Vault
	key     string
	version int
	pub     ed25519.PublicKey
}

// NewTransitSigner reads the public key of Transit key name at version
// (which requires read access to <mount>/keys/<name>) and returns a
// signer.
func (v *Vault) NewTransitSigner(ctx context.Context, name string, version int) (*TransitSigner, error) {
	if !safePathSegment.MatchString(name) || version < 1 {
		return nil, errors.New("kms: transit key name and version (>= 1) are required")
	}
	var out struct {
		Type string `json:"type"`
		Keys map[string]struct {
			PublicKey string `json:"public_key"`
		} `json:"keys"`
	}
	if err := v.call(ctx, http.MethodGet, "keys/"+name, nil, &out); err != nil {
		return nil, err
	}
	if out.Type != "ed25519" {
		return nil, fmt.Errorf("kms: transit key %s is %q, need ed25519", name, out.Type)
	}
	k, ok := out.Keys[strconv.Itoa(version)]
	if !ok {
		return nil, fmt.Errorf("kms: transit key %s has no version %d", name, version)
	}
	pub, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize || CheckEd25519PublicKey(pub) != nil {
		return nil, errors.New("kms: invalid public key from vault")
	}
	return &TransitSigner{v: v, key: name, version: version, pub: pub}, nil
}

// Public implements Signer.
func (t *TransitSigner) Public() ed25519.PublicKey { return t.pub }

// Sign implements Signer. The signature is verified locally before it is
// returned, so a misbehaving or misconfigured KMS cannot make tenant-pass
// emit tokens that do not verify under the advertised public key.
func (t *TransitSigner) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	var out struct {
		Signature string `json:"signature"`
	}
	err := t.v.call(ctx, http.MethodPost, "sign/"+t.key, map[string]any{
		"input":       base64.StdEncoding.EncodeToString(msg),
		"key_version": t.version,
	}, &out)
	if err != nil {
		return nil, err
	}
	sig, err := parseVaultValue(out.Signature, t.version)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(t.pub, msg, sig) {
		return nil, errors.New("kms: invalid signature from vault")
	}
	return sig, nil
}
