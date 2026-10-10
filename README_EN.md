# NodePure

[中文文档](README.md)

A self-hosted Go web application that starts isolated Mihomo instances to inspect proxy exit IPs, IP metadata, HTTP latency, and website connectivity. The frontend is embedded and has no CDN or Node.js build dependency.

IP reputation scoring defaults to [proxycheck.io v3](https://proxycheck.io/api/) without requiring a key. Cards show raw risk (0–100, lower is better), purity (100 minus risk, higher is better), grade, source, timestamp and detection flags. Scores support sorting, threshold filtering and CSV provenance export.

**Measurement limits:** Provider models differ; scores need not match IPCheck or IPPure and do not guarantee account eligibility. Failed, missing, null or out-of-range scores remain unknown, never zero. ISP names are hints; residential filtering requires an explicit provider classification. Native-IP status remains unknown when unavailable. Website HTTP tests do not establish API access, regional playback or service unlocks.

## Reputation configuration

`REPUTATION_PROVIDER=proxycheck` uses explicit-IP v3 queries pinned to `24-June-2026`, directly from the server, with `tag=0` (query tagging disabled). Exit IPs are sent to the third-party service. Official [free quotas](https://proxycheck.io/pricing/) currently allow 100 daily unregistered queries or 1000 with a free registered key. Optional `PROXYCHECK_API_KEY` or `PROXYCHECK_API_KEY_FILE` supplies your own key; choose only one. Keys are excluded from frontend responses and errors. Keep files private and outside Git, e.g. `secrets/proxycheck.key`.

`REPUTATION_DAILY_LIMIT` defaults to 100 without a key or 1000 with one; adjust to your actual plan (range 1–100000). This is a process-local UTC daily budget; other applications may consume the same provider quota. Restarting does not reset provider quotas. Requests are limited to two concurrent queries and two starts per second, with one-hour successful and one-minute failed IP caches. Proxy exits are never rotated to evade limits.

Grades use raw risk: A 0–25, B 26–50, C 51–75, D 76–100. Purity ≥80 means risk ≤20. JSON `verified` means a valid provider score matched the observed IP, not an independent reputation audit; `type_verified` tracks explicit network classification separately.

For authorized use, `REPUTATION_PROVIDER=ippure` selects the [IPPure current-exit API](https://ippure.com/MyIP-Info-API) through each target node. Responses must match that node's observed exit IP; HTTP 403, quota errors, mismatches and unsupported IPv6 remain unknown. IPCheck/IPPure informed score direction and source presentation; their UI, private algorithms and keys are not copied. Set `REPUTATION_PROVIDER=off` to disable reputation queries.

Supports Clash YAML, Base64 subscriptions and common SS, Trojan, VMess, VLESS, Hysteria2, HTTP(S) and SOCKS5 URIs, including common TLS/SNI/WS/gRPC/Reality parameters. Unsupported transports are reported; use Clash YAML for advanced protocol settings.

## Run locally

Install Go 1.26+ and a trusted [official Mihomo binary](https://github.com/MetaCubeX/mihomo/releases) at `bin/mihomo` (`bin/mihomo.exe` on Windows), or set `MIHOMO_BIN`. Make the Linux binary executable. Mihomo v1.19.32 was used for the real integration test. Mihomo is a separate GPL-3.0 program and is not bundled.

```sh
git clone https://github.com/2089887529/NodePure.git
cd NodePure
go build -trimpath -o nodepure ./cmd/server
./nodepure
```

Open `http://127.0.0.1:8099`. On Windows build with `-o nodepure.exe` and run `./start.cmd` (`./start.ps1` is also provided). The script resolves paths relative to itself and creates a current-user-only `.nodepure-tmp` directory, supporting spaces/Unicode and environments that deny access to the OS temp directory. No PowerShell execution-policy changes are required. Alternatively create a private directory, set `NODEPURE_TEMP_DIR` to its absolute path, and run `./nodepure.exe` directly. Without an override the application tries OS temp, then user cache. The default is loopback-only. Optional automatic download requires the trusted SHA-256 of the matching official v1.19.32 archive in `MIHOMO_SHA256`; no unchecked executable is downloaded.

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

Real subscription tests have run on Linux and Windows, including Windows paths containing spaces/Unicode and Windows-to-Linux LAN authentication, SSE, session isolation and exports. CI also runs native Windows Go tests. macOS and Linux ARM64 are compile-checked only; physical-machine runtime testing remains outstanding. Install the matching Mihomo binary on each new machine, and configure password-protected LAN binding before accessing it from another computer.

Licensed under [MIT](LICENSE). Mihomo and other third-party components retain their own licenses. See [CONTRIBUTING.md](CONTRIBUTING.md).
