# CLI verification — 2026-11-04

`go test -race ./...` and `go vet ./...` pass. Tests exercise actual Cobra
commands over HTTP, all six asset update commands and three aliases, denied
requests, invalid input, PKCE callback/exchange and wrong-state rejection.

`python3 scripts/smoke_cli.py` builds and runs the executable with an isolated
configuration directory and a synthetic Edge HTTP server. Verified:

- Browser launch -> simulated UI -> real CLI loopback callback -> PKCE exchange.
- Saved session credential file permissions: 0600.
- Token create, get, update, get updated description, revoke.
- Secret create, put updated value, get updated description, revoke.
- Logout calls sign-out and removes the saved credentials.
- All synthetic assets are removed; no live credentials are used.

Linux, macOS and Windows binaries build for amd64 and arm64. Only the Linux
amd64 executable was run; cross-compilation is not runtime verification.

Live management CLI authentication/create/update has not been verified. The
supplied Gateway SECRET token is not an Edge user session. The default
`app.certlocker.io` hostname did not resolve, and GET requests under
`trust.certlocker.io/edge/rest` returned HTML. A working Edge URL plus browser
login/2FA is needed. Unit/fixture success is not reported as live success.

Separately, the actual Gateway was tested through Ansible plus the Go and Rust
SDK smoke executables: secret creation, idempotent repeat, exact value readback,
token metadata, and revocation all passed. Sanitized evidence is committed in
those repositories; no token or secret value is included.
