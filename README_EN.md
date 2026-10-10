# NodePure

[中文文档](README.md)

A self-hosted Go web application that starts isolated Mihomo instances to inspect proxy exit IPs, IP metadata, HTTP latency, and website connectivity. The frontend is embedded and has no CDN or Node.js build dependency.

**Measurement limits:** No verified commercial fraud-score source is configured. Risk scores, native-IP status and Anycast are unknown. ISP names provide heuristics only. ChatGPT/Claude/YouTube tests measure webpage HTTP connectivity, not API access, account eligibility, regional playback or service unlocks. Results are observations at a particular time.

Supports Clash YAML, Base64 subscriptions and common SS, Trojan, VMess, VLESS, Hysteria2, HTTP(S) and SOCKS5 URIs, including common TLS/SNI/WS/gRPC/Reality parameters. Unsupported transports are reported; use Clash YAML for advanced protocol settings.

## Run locally

Install Go 1.26+ and a trusted [official Mihomo binary](https://github.com/MetaCubeX/mihomo/releases) at `bin/mihomo` (`bin/mihomo.exe` on Windows), or set `MIHOMO_BIN`. Make the Linux binary executable. Mihomo v1.19.32 was used for the real integration test. Mihomo is a separate GPL-3.0 program and is not bundled.

```sh
git clone https://github.com/2089887529/NodePure.git
cd NodePure
go build -trimpath -o nodepure ./cmd/server
./nodepure
```

Open `http://127.0.0.1:8099`. On Windows build with `-o nodepure.exe` and run `./nodepure.exe`. The default is loopback-only. Optional automatic download requires the trusted SHA-256 of the matching official v1.19.32 archive in `MIHOMO_SHA256`; no unchecked executable is downloaded.

Non-loopback binding requires a bcrypt file. Generate one without putting the password in command arguments, environment variables or shell history:

```sh
python3 -c 'import getpass,sys; sys.stdout.write(getpass.getpass())' | ./nodepure --set-password password.hash
NODEPURE_HOST=0.0.0.0 NODEPURE_PASSWORD_HASH_FILE=./password.hash ./nodepure
```

Use a 12–72-byte password. The generator never overwrites existing files. Use private networking, SSH tunneling or an HTTPS reverse proxy. This is a trusted-admin tool, not an anonymous public or sandboxed multitenant service. Read [SECURITY.md](SECURITY.md) before remote deployment.

Docker: place a verified Linux Mihomo executable in `bin/mihomo`, run `docker compose build`, pipe a hidden password prompt into `docker compose --profile tools run --rm -T password`, then `docker compose up -d nodepure`. The container runs as UID 10001 with a read-only root filesystem and publishes only the host loopback interface.

Defaults: global concurrency 20, nodes per task 500, retained tasks 50, active tasks 2 plus queue 4, input 2 MiB, task deadline 20 minutes, completed-task retention 1 hour. Task histories and sessions are process-local. Raw node credentials are excluded from JSON/SSE; explicit authorized Clash export contains them. Metadata requests use HTTPS, an explicit-IP cache and a shared query rate limit. Subscription fetching blocks private/reserved addresses by default, including redirects and resolved addresses. Local proxy listeners require per-task random credentials.

See [README.md](README.md) for configuration and API routes; all mutation endpoints require `X-NodePure: 1` and a session Cookie. Browser sessions only access their own tasks. Do not commit subscriptions, password hashes or exported proxy configurations.

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
node --test web/test/*.test.cjs
NODEPURE_TEST_MIHOMO=/absolute/path/to/mihomo go test ./pkg/core -run TestRealMihomoLifecycle -v
```

The real-kernel test uses only an isolated local fixture and skips explicitly if the binary is not configured. CI covers tests, races, formatting, vet, frontend checks and cross-platform compilation. The manual Release workflow uploads build artifacts and SHA-256 checksums for review; it does not automatically publish a release.

Licensed under [MIT](LICENSE). Mihomo and other third-party components retain their own licenses. See [CONTRIBUTING.md](CONTRIBUTING.md).
