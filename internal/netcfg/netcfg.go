// Package netcfg builds client connection settings for the stores and
// directories tenant-pass connects to.
//
// tenant-pass deliberately does not accept driver connection strings
// (DSNs/URLs). Each driver has its own DSN dialect with its own insecure
// defaults (libpq's sslmode=prefer silently falls back to plaintext;
// MySQL's tls=skip-verify and tls=preferred are easy to miss), and some
// read environment variables or service files. Instead, connections are
// described by a small, uniform structure, and tenant-pass builds the TLS
// configuration itself: certificate verification and host name checking
// are always on unless plaintext is explicitly requested for testing.
package netcfg

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/kobesoft-labs/tenant-pass/internal/secret"
)

// Endpoint describes how tenant-pass connects to one server.
type Endpoint struct {
	Address      string `json:"address"`       // host:port
	User         string `json:"user"`          // login name
	PasswordFile string `json:"password_file"` // file containing the password
	Database     string `json:"database,omitempty"`
	TLS          TLS    `json:"tls"`
	// InsecurePlaintext disables TLS. It exists for local testing only;
	// tenant-pass refuses to start with it unless the global
	// allow_insecure_plaintext flag is also set.
	InsecurePlaintext bool `json:"insecure_plaintext,omitempty"`
}

// TLS holds client-side TLS settings.
type TLS struct {
	// CAFile is a PEM bundle of trusted CAs. Empty means the system pool.
	CAFile string `json:"ca_file,omitempty"`
	// ServerName overrides the name checked against the server
	// certificate. Empty means the host part of Address.
	ServerName string `json:"server_name,omitempty"`
	// CertFile/KeyFile enable client certificate authentication.
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
}

// Resolved is a validated Endpoint with secrets loaded.
type Resolved struct {
	Host, Port string
	PortNum    uint16
	User       string
	Password   secret.Value
	Database   string
	TLS        *tls.Config // nil only for InsecurePlaintext
}

// Resolve validates e, loads its password and builds its TLS config.
func (e Endpoint) Resolve(allowPlaintext bool) (*Resolved, error) {
	host, port, err := net.SplitHostPort(e.Address)
	if err != nil || host == "" {
		return nil, fmt.Errorf("address %q must be host:port", e.Address)
	}
	pn, err := strconv.ParseUint(port, 10, 16)
	if err != nil || pn == 0 {
		return nil, fmt.Errorf("address %q has an invalid port", e.Address)
	}
	if e.User == "" {
		return nil, errors.New("user is required")
	}
	r := &Resolved{Host: host, Port: port, PortNum: uint16(pn), User: e.User, Database: e.Database}
	if e.PasswordFile != "" {
		if r.Password, err = secret.ReadFile(e.PasswordFile); err != nil {
			return nil, err
		}
	}
	if e.InsecurePlaintext {
		if !allowPlaintext {
			return nil, errors.New("insecure_plaintext requires allow_insecure_plaintext at the top level (testing only)")
		}
		if e.TLS != (TLS{}) {
			return nil, errors.New("insecure_plaintext cannot be combined with tls settings")
		}
		return r, nil
	}
	if r.TLS, err = e.TLS.Build(host); err != nil {
		return nil, err
	}
	return r, nil
}

// LoadCertPool reads a PEM CA bundle with the integrity checks of
// secret.ReadTrusted (whoever can write a CA file decides whom we trust).
func LoadCertPool(path string) (*x509.CertPool, error) {
	pem, err := secret.ReadTrusted(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s contains no certificates", path)
	}
	return pool, nil
}

// LoadKeyPair loads a certificate chain and its private key from the
// exact bytes that passed the integrity checks (no second read).
func LoadKeyPair(certFile, keyFile string) (tls.Certificate, error) {
	certPEM, err := secret.ReadTrusted(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := secret.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, key.Bytes())
}

// Build returns a client TLS configuration that verifies the server
// certificate chain and host name.
func (t TLS) Build(defaultServerName string) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: t.ServerName,
	}
	if cfg.ServerName == "" {
		cfg.ServerName = defaultServerName
	}
	if t.CAFile != "" {
		pool, err := LoadCertPool(t.CAFile)
		if err != nil {
			return nil, fmt.Errorf("tls ca_file: %w", err)
		}
		cfg.RootCAs = pool
	}
	if (t.CertFile == "") != (t.KeyFile == "") {
		return nil, errors.New("tls cert_file and key_file must be set together")
	}
	if t.CertFile != "" {
		cert, err := LoadKeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("tls client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}
