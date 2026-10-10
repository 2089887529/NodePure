# Changelog

## Unreleased

- Add real proxycheck.io v3 reputation scores with raw risk, complementary purity, source/time/status, bounded daily budget, shared cache and optional private key file; include an exit-bound IPPure adapter.
- Add score coverage, average purity, score sorting, explicit residential classification, correct purity ≥80 filtering and CSV score provenance; unavailable scores remain null.

- Remove fabricated fraud/purity numbers and unsupported native/Anycast claims; show uncertainty and label ISP heuristics.
- Join service checks before publishing immutable results; independently validate HTTP statuses and Google's 204 endpoint; separate HTTPS RTT and connection/TLS timing.
- Add task ownership, local-default binding, password-file login for LAN access, session revocation, CSRF/Host/CSP protections and redacted result serialization.
- Bound tasks, global workers, request size, node count, downloads and logs; add cancellation, deadlines and retained-task expiry.
- Replace lossy buffered SSE with cursor-based replay and snapshot recovery; lock task snapshots and histories.
- Reject private/reserved subscription destinations, DNS rebinding and unsafe redirects unless explicitly allowlisted.
- Support common VMess/VLESS/Hysteria2/auth/TLS/transport URI fields, collision-safe names and visible parse/kernel rejection records.
- Reserve dynamic loopback ports; validate all authenticated listeners; reap kernel processes and remove temporary configs.
- Require trusted archive checksums for automatic Mihomo installation and perform atomic bounded downloads.
- Render external values as text; add local assets, pagination, incremental counts, formula-safe CSV and verified-only score filtering.
- Add Go regression/race/integration tests, frontend tests, CI, portable build artifacts, container isolation and accurate installation/security documentation.
