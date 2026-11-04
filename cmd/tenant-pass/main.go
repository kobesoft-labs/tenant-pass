// Command tenant-pass issues short-lived, tenant-scoped credentials for
// PostgreSQL, MySQL and Redis to applications that present a pass signed
// by a trusted gateway.
//
// Usage:
//
//	tenant-pass serve           -config FILE
//	tenant-pass check-config    -config FILE [-connect]
//	tenant-pass gen-gateway-key -private FILE -public FILE
//	tenant-pass gen-rotation-key -out FILE
//	tenant-pass gen-app-token
//	tenant-pass sign-pass       -key FILE -kid ID -aud APP (-host H | -tenant T) [-ttl 30s]
//	tenant-pass sign-job-ticket -key FILE -kid ID -aud APP -tenant T [-ttl 1h]
//	tenant-pass version
//
// See docs/en/ for the full documentation.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/kobesoft-labs/tenant-pass/internal/auth"
	"github.com/kobesoft-labs/tenant-pass/internal/config"
	"github.com/kobesoft-labs/tenant-pass/pass"
	"github.com/kobesoft-labs/tenant-pass/tenantpass"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = cmdServe(args)
	case "check-config":
		err = cmdCheckConfig(args)
	case "gen-gateway-key":
		err = cmdGenGatewayKey(args)
	case "gen-rotation-key":
		err = cmdGenRotationKey(args)
	case "gen-app-token":
		err = cmdGenAppToken(os.Stdout)
	case "sign-pass":
		err = cmdSignPass(args)
	case "sign-job-ticket":
		err = cmdSignJobTicket(args)
	case "gen-signing-key":
		err = cmdGenGatewayKey(args)
	case "version":
		fmt.Println(versionString())
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "tenant-pass:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: tenant-pass <command> [flags]

commands:
  serve             run the server
  check-config      validate a configuration file (-connect also tests connections)
  gen-gateway-key   create an Ed25519 key pair for a gateway
  gen-signing-key   same as gen-gateway-key (job ticket keys, scheduler keys)
  gen-rotation-key  create a rotation key file
  gen-app-token     create an application token and its hash
  sign-pass         sign a pass with a gateway key (testing and integration)
  sign-job-ticket   sign a job ticket with a scheduler key
  version           print the version
`)
}

func versionString() string {
	v := version
	if bi, ok := debug.ReadBuildInfo(); ok {
		v += " " + bi.GoVersion
	}
	return "tenant-pass " + v
}

func cmdCheckConfig(args []string) error {
	fs := flag.NewFlagSet("check-config", flag.ExitOnError)
	path := fs.String("config", "", "configuration file")
	connect := fs.Bool("connect", false, "also connect to the directory and every node")
	fs.Parse(args)
	if err := tenantpass.CheckConfig(context.Background(), *path, *connect); err != nil {
		return err
	}
	fmt.Println("configuration OK")
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	path := fs.String("config", "", "configuration file")
	fs.Parse(args)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return tenantpass.Serve(ctx, tenantpass.Options{ConfigPath: *path, Version: version})
}

// writeNewFile creates path with mode 0600, failing if it exists, so a
// key generator can never overwrite an existing key.
func writeNewFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func cmdGenGatewayKey(args []string) error {
	fs := flag.NewFlagSet("gen-gateway-key", flag.ExitOnError)
	priv := fs.String("private", "", "output file for the private key (PEM, PKCS #8)")
	pub := fs.String("public", "", "output file for the public key (PEM, PKIX)")
	fs.Parse(args)
	if *priv == "" || *pub == "" {
		return errors.New("-private and -public are required")
	}
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	skDER, err := x509.MarshalPKCS8PrivateKey(sk)
	if err != nil {
		return err
	}
	pkDER, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return err
	}
	if err := writeNewFile(*priv, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: skDER}), 0o600); err != nil {
		return err
	}
	return writeNewFile(*pub, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkDER}), 0o644)
}

func cmdGenRotationKey(args []string) error {
	fs := flag.NewFlagSet("gen-rotation-key", flag.ExitOnError)
	out := fs.String("out", "", "output file")
	fs.Parse(args)
	if *out == "" {
		return errors.New("-out is required")
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	return writeNewFile(*out, []byte(base64.StdEncoding.EncodeToString(b)+"\n"), 0o600)
}

func cmdGenAppToken(w io.Writer) error {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	tok := auth.TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	fmt.Fprintf(w, "token:        %s\n", tok)
	fmt.Fprintf(w, "token_sha256: %s\n", hex.EncodeToString(auth.HashToken(tok)))
	fmt.Fprintln(w, "\nGive the token to the application (as a secret). Put token_sha256 in the tenant-pass configuration.")
	return nil
}

func cmdSignPass(args []string) error {
	fs := flag.NewFlagSet("sign-pass", flag.ExitOnError)
	keyFile := fs.String("key", "", "gateway private key (PEM)")
	kid := fs.String("kid", "", "gateway key ID")
	aud := fs.String("aud", "", "application name")
	host := fs.String("host", "", "tenant host name")
	tenant := fs.String("tenant", "", "tenant ID")
	ttl := fs.Duration("ttl", 30*time.Second, "lifetime")
	fs.Parse(args)
	sk, err := config.ReadEd25519PrivateKey(*keyFile)
	if err != nil {
		return err
	}
	now := time.Now()
	p, err := pass.Signer{KeyID: *kid, Key: sk}.Sign(pass.Claims{
		Audience: *aud, Host: *host, Tenant: *tenant, IssuedAt: now, Expiry: now.Add(*ttl),
	})
	if err != nil {
		return err
	}
	fmt.Println(p)
	return nil
}

func cmdSignJobTicket(args []string) error {
	fs := flag.NewFlagSet("sign-job-ticket", flag.ExitOnError)
	keyFile := fs.String("key", "", "issuer private key (PEM)")
	kid := fs.String("kid", "", "issuer key ID")
	aud := fs.String("aud", "", "application name")
	tenant := fs.String("tenant", "", "tenant ID")
	ttl := fs.Duration("ttl", time.Hour, "lifetime (at most 24h; tenant-pass enforces its own max_ttl)")
	fs.Parse(args)
	sk, err := config.ReadEd25519PrivateKey(*keyFile)
	if err != nil {
		return err
	}
	now := time.Now()
	t, err := pass.Signer{KeyID: *kid, Key: sk}.SignJob(context.Background(), pass.JobClaims{
		Audience: *aud, Tenant: *tenant, IssuedAt: now, Expiry: now.Add(*ttl),
	})
	if err != nil {
		return err
	}
	fmt.Println(t)
	return nil
}
