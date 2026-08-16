# Security policy

## Supported version

Security fixes are applied to the current `main` branch. Use the latest release or commit and
keep Python, Nmap, the container base image, and Python dependencies updated.

## Threat model (essentials)

Recon Operator is a **self-hosted authorized recon control plane**, not a multi-tenant SaaS
scanner and not an exploit framework.

| Asset | Threat | Control |
| --- | --- | --- |
| API keys | theft, over-scope use | `API_AUTH_*`, scopes (`read`/`scan`/`admin`), audit events, revoke flags |
| Scan capability | scanning beyond engagement | `TARGET_ALLOWLIST`, target size bounds, auth + rate limits, job leases |
| Encrypted results | key loss / unauthorized read | Fernet primary + `FERNET_PREVIOUS_KEYS`, owner-prefixed files, `LEGACY_RESULTS_SHARED` |
| AI packs | exfil of secrets into LLM chat | packs never include tokens/keys; default `budget=s` hard size caps; prefer `/ai/pack` over full `/results` |
| AI packs (prompt injection) | banner/NSE output smuggle instructions into LLM context | control characters and newlines stripped, field lengths bounded, `data_is_untrusted` marker, parser rejects illegal XML chars |
| Metrics (`/metrics`) | internal state recon if exposed | **loopback-first deploy**; optional `METRICS_AUTH_REQUIRED=true` (read scope) |
| Planner commands | blind execution | review-only suggestions (`ready`/`missing`); no auto-exec |
| Telegram notifications | scan targets visible on external channels | target omitted unless `TELEGRAM_INCLUDE_TARGET=true` (default false) |

### Metrics exposure policy

- **Default:** `GET /metrics` is unauthenticated Prometheus text for local scrapers.
- **Deploy rule:** bind `APP_HOST=127.0.0.1` (default) or firewall the port so scrapers are local only.
- **Hardening:** set `METRICS_AUTH_REQUIRED=true` when the metrics port may be reachable beyond loopback.
- Health still reports `metrics_path` and `metrics_auth_required` without secrets.

## Reporting a vulnerability

Please report vulnerabilities privately through the repository's GitHub Security Advisories
page. Include the affected version, impact, reproduction steps, and any proposed mitigation.
Do not open a public issue containing working exploit details or credentials.

If private reporting is unavailable, open a minimal issue asking the maintainer for a secure
contact channel without disclosing the vulnerability.

## Deployment baseline

- Keep `API_AUTH_REQUIRED=true` and use a randomly generated token.
- Prefer named keys (`API_AUTH_KEYS`) with least-privilege scopes (`read` / `scan` / `admin`)
  over a single shared admin token; revoke by setting `"revoked": true`.
- For multi-token deploys, set `LEGACY_RESULTS_SHARED=false` so pre-ownership result files
  are not visible to every operator, and `LEGACY_JOBS_SHARED=false` so pre-ownership
  jobs/tasks are hidden and not cancellable by others.
- Keep `TELEGRAM_INCLUDE_TARGET=false` (default) unless the notification channel is
  as restricted as the operator UI; the flag also gates target text in scan errors.
- Prefer an explicit `TARGET_ALLOWLIST` / `TARGET_ALLOWLIST_FILE` so scans cannot leave the
  authorized engagement scope (IPs, CIDRs, hostnames, or `*.suffix` wildcards).
- For multi-worker deploys set `REDIS_URL` so rate limits are shared; without it each process
  enforces its own window.
- Share `STATE_DB_PATH` (and preferably Redis) across workers so job leases prevent duplicate
  scans and scheduler leadership avoids duplicate recurring schedules; set a distinct
  `WORKER_ID` per process.
- Bind to loopback unless a trusted reverse proxy or firewall restricts access.
- If the app sits behind a reverse proxy and you need accurate client IPs for rate
  limits, set `TRUSTED_PROXY_MODE=true` **and** a non-empty `TRUSTED_PROXIES`
  allowlist (IPs/CIDRs of the proxy peers). Spoofed `X-Forwarded-For` /
  `X-Real-IP` headers from untrusted peers are ignored.
- Never publish `.env`, Fernet keys, API tokens, Telegram credentials, decrypted results, or
  assessment artifacts.
- Keep target-size, concurrency, rate, and timeout limits appropriate for the authorized
  environment.
- Run the default non-root container and add network privileges only when an authorized scan
  profile requires them.
- Treat generated recon commands as operator-reviewed suggestions, not autonomous actions.
- Back up the Fernet key separately from encrypted results and rotate API credentials after
  suspected exposure.
- Fernet rotation: generate a new `FERNET_KEY`, move the old value into
  `FERNET_PREVIOUS_KEYS` (comma-separated or JSON array). New results encrypt with the
  primary key; decrypt accepts primary + previous until legacy files are re-written.
- Audit trail: `GET /audit` (admin) lists who scanned what when (key id + owner prefix,
  no tokens/keys). Optionally set `AUDIT_LOG_PATH` for a JSONL mirror.
