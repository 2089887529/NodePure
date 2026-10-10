# Contributing

Use Go 1.26 or later. The frontend is plain JavaScript/CSS embedded by `web/embed.go`; Node.js is needed only for frontend tests.

Before proposing a change, run:

```sh
gofmt -w cmd pkg
go test ./...
go test -race ./...
go vet ./...
node --test web/test/*.test.cjs
go build ./cmd/server
```

For kernel changes, also set `NODEPURE_TEST_MIHOMO` to a trusted local binary and run `TestRealMihomoLifecycle`. It starts a temporary, authenticated loopback proxy and a local fixture, then checks pruning and process/port/config cleanup. It never uses your active system proxy. Without the environment variable the test explicitly skips.

Use redacted fixtures. Do not commit subscription URLs/tokens, hashes, private keys, real proxy passwords, local deployment configs or compiled Mihomo binaries. Avoid transmitting full node configuration in ordinary API results. Unknown measurements must remain unknown; service webpage reachability must not be described as API access or regional unlock. A score provider must expose its source, sampling time and confidence rather than deriving numeric scores from ISP names.

Describe observable behavior and relevant verification in pull requests. Keep new network requests bounded, cancellable and tested. Preserve third-party license notices. See [SECURITY.md](SECURITY.md) for reporting vulnerabilities privately.
