# Security

NodePure is intended for trusted personal/admin use. Do not expose an unrestricted public detector or accept arbitrary users' configurations on a shared host. Mihomo proxy options can access user-selected remote destinations and may reference local files. Subscription-fetch protections do not sandbox the entire proxy process. Multitenant hosting needs isolated operating-system identities, filesystems and outbound network policies.

## Boundaries

- Default binding is loopback. A bcrypt password file is mandatory for non-loopback access. Use TLS or an SSH tunnel for remote login. Password hashes and proxy exports are secrets; keep them out of Git and container build contexts.
- Sessions expire after 24 hours, live in memory and own their task histories. Re-authentication with the same shared password in a new session does not grant the old session's tasks. Logout revokes its token; process restart revokes all tokens.
- Task bodies, subscription URLs and node credentials are not written to request logs. JSON/SSE omit raw proxy configuration. Explicit Clash exports contain credentials. The process retains node configuration in memory until task expiry/deletion; temporary kernel configuration files are removed after stop.
- Internal mixed proxy listeners bind only to 127.0.0.1 and require a per-task random username/password. Port allocation avoids active listeners and readiness checks verify authentication, but NodePure does not sandbox an untrusted executable. Install Mihomo from its official source and verify integrity.
- Fetching subscription URLs checks HTTP(S), hostname/IP, every DNS answer, redirects and size. The checked IP is dialed directly. `SUBSCRIPTION_ALLOWLIST` deliberately permits private destinations by exact hostname; DNS names on the allowlist trust all resolved addresses. Do not use broad exceptions.
- Host allowlisting, same-origin checks, strict HttpOnly cookies and a custom mutation header mitigate CSRF and DNS rebinding. The UI creates text nodes for untrusted data and uses self-hosted scripts/styles with a restrictive CSP. CSV formula prefixes are escaped.
- Requests/tasks/nodes/history/downloads/log buffers are bounded. Two active kernels and the shared node concurrency budget prevent per-request unbounded probing; authentication attempt throttling is local and is not a substitute for an internet-facing gateway.
- Exit IPs are queried against third-party metadata and reputation services. Default explicit-IP reputation queries use the server connection, bounded cache/rate/budget and no redirect following; they do not rotate proxy exits to evade quotas. Set `REPUTATION_PROVIDER=off` to disable reputation requests. API keys are service-side secrets; keep their files private and excluded from Git and image contexts. Valid scores reflect the chosen provider model, not independent guarantees.

## Reverse proxy

Preserve the original `Host` and `Origin`. Set `NODEPURE_PUBLIC_ORIGIN` to your exact HTTPS origin, for example `https://nodes.example.com` (including a non-default port if used). NodePure then allows that hostname, requires that precise origin for requests carrying an Origin header, and marks session cookies Secure even when upstream transport is HTTP. No rewrite of browser Origin is needed. NodePure does not trust `Forwarded` or `X-Forwarded-*` headers to make security decisions. Restrict upstream exposure to the trusted proxy or loopback. For simpler deployment, use an SSH tunnel or a private network. Disable response buffering for `/api/stream/` and use a read timeout above the heartbeat interval. Do not enable permissive CORS.

## Reporting

Avoid putting real subscription tokens, passwords, addresses of private infrastructure or exploitable details into public issues. Use GitHub's private vulnerability reporting if enabled for this repository, or contact the repository owner through an existing private channel. Include a minimal redacted reproduction and tested version. There is currently no guarantee of an independent security audit or of a commercial risk database.
