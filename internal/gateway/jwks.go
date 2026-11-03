package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// keySet holds the identity provider's verification keys.
//
// Only public keys intended for signatures are kept (use "sig" or unset);
// keys without a kid are dropped, because selecting a key by anything
// else invites confusion. For a URL source, the set is refreshed
// periodically, and on an unknown kid at most once per minRefetch, so a
// flood of tokens with random kids cannot turn into a flood of requests
// to the identity provider.
type keySet struct {
	url    string
	client *http.Client

	mu        sync.Mutex
	keys      map[string]jose.JSONWebKey
	fetchedAt time.Time
	lastTry   time.Time
}

const (
	jwksRefresh    = 10 * time.Minute
	jwksMinRefetch = 30 * time.Second
	jwksMaxBytes   = 1 << 20
)

func newFileKeySet(path string) (*keySet, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	keys, err := parseJWKS(b)
	if err != nil {
		return nil, err
	}
	return &keySet{keys: keys, fetchedAt: time.Now()}, nil
}

func newURLKeySet(ctx context.Context, url string, tc *tls.Config) (*keySet, error) {
	ks := &keySet{url: url, client: &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     tc,
			Proxy:               http.ProxyFromEnvironment,
			TLSHandshakeTimeout: 5 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	if err := ks.fetch(ctx); err != nil {
		return nil, err
	}
	return ks, nil
}

func parseJWKS(b []byte) (map[string]jose.JSONWebKey, error) {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(b, &set); err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	keys := map[string]jose.JSONWebKey{}
	for _, k := range set.Keys {
		if k.KeyID == "" || !k.Valid() || !k.IsPublic() || (k.Use != "" && k.Use != "sig") {
			continue
		}
		if _, dup := keys[k.KeyID]; dup {
			// Two keys with one kid: ambiguous. Drop both.
			keys[k.KeyID] = jose.JSONWebKey{}
			continue
		}
		keys[k.KeyID] = k
	}
	for kid, k := range keys {
		if k.Key == nil {
			delete(keys, kid)
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("jwks: no usable signature keys (public, with kid, use=sig)")
	}
	return keys, nil
}

func (ks *keySet) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ks.url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := ks.client.Do(req)
	if err != nil {
		return fmt.Errorf("jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, jwksMaxBytes))
	if err != nil {
		return err
	}
	keys, err := parseJWKS(b)
	if err != nil {
		return err
	}
	ks.mu.Lock()
	ks.keys, ks.fetchedAt = keys, time.Now()
	ks.mu.Unlock()
	return nil
}

// jwksMaxStale is how long keys from a URL source stay usable without a
// successful refresh. After that the gateway fails closed: if the
// identity provider removed a (possibly leaked) key, we must not keep
// trusting it indefinitely just because refreshes keep failing.
const jwksMaxStale = time.Hour

// refreshLoop refreshes a URL key set every jwksRefresh until ctx ends.
func (ks *keySet) refreshLoop(ctx context.Context, logger interface{ Warn(string, ...any) }) {
	if ks.url == "" {
		return
	}
	t := time.NewTicker(jwksRefresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			if err := ks.fetch(fctx); err != nil && logger != nil {
				logger.Warn("jwks refresh failed", "error", err.Error())
			}
			cancel()
		}
	}
}

// get returns the key with kid. On an unknown kid it refreshes the set,
// at most once per jwksMinRefetch. The fetch runs with a context the
// client cannot cancel (context.WithoutCancel), so a client that
// disconnects immediately cannot abort refreshes and pin stale keys.
func (ks *keySet) get(ctx context.Context, kid string) (jose.JSONWebKey, bool) {
	ks.mu.Lock()
	if ks.url != "" && time.Since(ks.fetchedAt) > jwksMaxStale {
		// Too old: refuse every key until a refresh succeeds.
		ks.keys = map[string]jose.JSONWebKey{}
	}
	k, ok := ks.keys[kid]
	canTry := ks.url != "" && !ok && time.Since(ks.lastTry) > jwksMinRefetch
	if canTry {
		ks.lastTry = time.Now()
	}
	ks.mu.Unlock()
	if canTry {
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		_ = ks.fetch(fctx) // on failure keep the previous keys (until jwksMaxStale)
		cancel()
		ks.mu.Lock()
		k, ok = ks.keys[kid]
		ks.mu.Unlock()
	}
	return k, ok
}
