// Command tenant-pass-gateway is a forward-auth service for reverse
// proxies. It verifies the end user's session token and, if the user
// belongs to the tenant of the requested host, signs a tenant-pass pass
// that the proxy forwards to the application.
//
// Usage:
//
//	tenant-pass-gateway serve        -config FILE
//	tenant-pass-gateway check-config -config FILE
//	tenant-pass-gateway version
//
// See docs/en/gateway.md.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/kobesoft-labs/tenant-pass/internal/gateway"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:], false)
	case "check-config":
		err = serve(os.Args[2:], true)
	case "version":
		v := version
		if bi, ok := debug.ReadBuildInfo(); ok {
			v += " " + bi.GoVersion
		}
		fmt.Println("tenant-pass-gateway " + v)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "tenant-pass-gateway:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, "usage: tenant-pass-gateway serve|check-config -config FILE | version\n")
}

func serve(args []string, checkOnly bool) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	path := fs.String("config", "", "configuration file")
	fs.Parse(args)

	f, err := gateway.LoadFile(*path)
	if err != nil {
		return err
	}
	var level slog.Level
	_ = level.UnmarshalText([]byte(f.LogLevel))
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	bctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	g, err := gateway.Build(bctx, f, logger)
	cancel()
	if err != nil {
		return err
	}
	if checkOnly {
		fmt.Println("configuration OK")
		return nil
	}

	hs := &http.Server{
		Addr:              f.Listen,
		Handler:           g.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10, // session cookies can be large
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	if !f.InsecurePlaintextHTTP {
		hs.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		if f.TLS.ClientCAFile != "" {
			// Only the proxy, holding a certificate from this CA, may call
			// the gateway.
			pemBytes, err := os.ReadFile(f.TLS.ClientCAFile)
			if err != nil {
				return err
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pemBytes) {
				return errors.New("tls.client_ca_file contains no certificates")
			}
			hs.TLSConfig.ClientCAs = pool
			hs.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}
	errc := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", f.Listen, "version", version)
		if hs.TLSConfig != nil {
			errc <- hs.ListenAndServeTLS(f.TLS.CertFile, f.TLS.KeyFile)
		} else {
			errc <- hs.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	sctx, scancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer scancel()
	return hs.Shutdown(sctx)
}
