# Embedding and extensions

[日本語](../ja/embedding.md)

The `tenant-pass` command is a thin wrapper around the exported package
`github.com/kobesoft-labs/tenant-pass/tenantpass`. You can build your own
binary that runs the same server and adds **extensions**: extra HTTP routes
served on the same listener.

```go
err := tenantpass.Serve(ctx, tenantpass.Options{
	ConfigPath: "/etc/tenant-pass/config.json",
	Version:    version,
	Extensions: []tenantpass.Extension{{
		Name: "legacy",
		Mount: func(ctx context.Context, h tenantpass.Host) (map[string]http.Handler, error) {
			return map[string]http.Handler{"POST /v1/legacy": legacyHandler}, nil
		},
		Ready: legacyReady, // optional, part of /readyz
		Close: legacyClose, // optional
	}},
})
```

## What an extension gets

- The same listener and TLS configuration (including client certificate
  verification, if configured).
- The same response headers (`Cache-Control: no-store`, CSP, `nosniff`,
  `Referrer-Policy`).
- Readiness: `Ready` is part of `/readyz` (cached with the core checks for 5 s).
- Graceful shutdown: requests to extension routes are drained like core requests.
- A logger (`Host.Logger`, with an `extension` attribute).

## What an extension does not get

Nothing of the core's configuration: no gateway keys, rotation keys, app
token hashes, store credentials or directory. An extension that needs to
verify passes uses the public `pass` package with its own key list; an
extension that authenticates applications does it itself. This keeps the
core's trust boundary unchanged: adding an extension cannot weaken
`/v1/credentials` or `/v1/job-tickets`.

## Rules

- Route patterns use `net/http` `ServeMux` syntax. They must not use the
  core's paths (`/v1/credentials`, `/v1/job-tickets`, `/healthz`, `/readyz`)
  or `/`, and two extensions cannot register the same pattern. Violations
  are startup errors.
- `Mount` runs once, after the configuration is loaded and before the
  listener opens. An error from `Mount` stops the server.
- Extensions share the process with the rotation keys. Treat extension code
  with the same care as tenant-pass itself: no logging of secrets, strict
  input parsing, bounded request bodies.

Typical use: a deployment-specific endpoint that must live behind the same
trust boundary, or a legacy protocol kept for compatibility while clients
migrate to `/v1/credentials`.
