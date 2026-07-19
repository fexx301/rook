# Rook

Rook is a local-first AI-agent honeypot written in Rust. It presents a fake developer-tools site ("FrameShift") while it fingerprints sessions, scores automation signals, plants benign prompt-injection canaries, and records canaries that return in later request paths, queries, or headers.

The payloads are intended to reveal automated behavior. They do not exploit browsers or human visitors.

Rook is intended for defensive research, controlled testing, and monitoring systems you operate or have permission to instrument. Operators are responsible for notice, consent, retention, and privacy obligations in their jurisdiction.

## Screenshots

Rook dashboard:

![Rook dashboard overview](docs/images/rook-dashboard.png)

FrameShift decoy site:

![FrameShift decoy site homepage](docs/images/frameshift-home.png)

## Quick start

Requirements: a current stable Rust toolchain.

```bash
cargo run
```

Open <http://127.0.0.1:7788/>. On first start, Rook creates the SQLite database configured in `config.example.toml` and applies the bundled schema. If `config.toml` exists, Rook uses that local file instead.

The dashboard defaults to `/__rook__` and requires its bearer token on every request. For example:

```bash
curl -H 'Authorization: Bearer rook-demo-token-change-me' \
  http://127.0.0.1:7788/__rook__
```

A normal browser address bar cannot attach a bearer header; use an API client or a browser header extension when viewing the dashboard interactively.

To view the dashboard as a normal page in Chrome, Brave, or Edge, install a trusted header-modification extension such as Requestly and create a scoped request-header rule:

- URL: `http://127.0.0.1:7788/__rook__`
- Header name: `Authorization`
- Header value: `Bearer rook-demo-token-change-me`

Then open <http://127.0.0.1:7788/__rook__> in that browser. Keep the rule scoped to the local dashboard URL so the bearer token is not sent to other sites.

For Firefox, use a header-modification add-on such as `simple-modify-headers` or another trusted equivalent with the same scoped URL, header name, and header value.

## Configuration

`config.example.toml` documents all supported settings. For local changes, copy it to `config.toml`; that file is ignored by Git.

```bash
cp config.example.toml config.toml
```

The config controls:

- `server.host`, `server.port`, and `server.secure_cookies` — listener and cookie transport settings.
- `database.path` — SQLite database location.
- `dashboard.path` and `dashboard.token` — protected dashboard route and credential.
- `persona.*` — fake company identity and number of visible blog posts.
- `detection.*` — signal weights and the cumulative agent threshold.

Set `ROOK_CONFIG` to load a different TOML file. Use `ROOK_DASHBOARD_TOKEN` to supply the dashboard secret without committing it to disk, and `ROOK_DATABASE_PATH` to override the SQLite location. The legacy `AGENTSBANE_*` environment variables still work as fallbacks. Invalid configuration fails fast with a descriptive error.

`.env.example` shows the environment variables commonly used for local development, but Rook does not automatically load `.env` files. Load them through your shell, process manager, Docker Compose, or hosting platform.

Before binding to a non-loopback address:

1. Replace the demo token (at least 16 characters); the application rejects the bundled token on public bind addresses.
2. Put the service behind HTTPS and set `server.secure_cookies = true`.
3. Apply an explicit retention policy to the SQLite database and protect its backups.

## Detection model

Each tracked request can add weighted signals for:

- Missing `Sec-Fetch-*` or `Accept-Language` headers.
- Suspicious or empty User-Agent values.
- A missing JavaScript canary after the first page had a chance to run JavaScript.
- Page-to-page request cadence under 500 ms.
- Access to `robots.txt`, `sitemap.xml`, or the session-specific honeypot route.

Static assets, the favicon, and `/health` do not create or score sessions. Score updates and threshold flags are committed atomically, and the total is capped at `1.0`.

This is heuristic detection, not proof of identity. Tune the weights against representative traffic before using the result operationally.

## Canary traps

Every session receives deterministic SHA-256-derived canaries through several channels:

- HTML comments, including confession and loop prompts.
- Hidden and ARIA-hidden elements.
- A `data-*` attribute and generator metadata.
- CSS `content` and zero-width Unicode text.

The in-memory index extracts canary-shaped values before doing direct hash-map lookups, avoiding a full scan of every known session for each request. It retains the 10,000 most recently indexed sessions and evicts the oldest entries to keep memory usage bounded; historical rows remain in SQLite.

## Dashboard and stored data

The dashboard reports totals, recent sessions, request-level scores/signals, response status, network metadata, and canary catches. Dashboard responses use `no-store` and `noindex` policies; unauthorized responses include a bearer authentication challenge.

Rook stores IP addresses, User-Agent values, request paths and queries, timestamps, scores, and caught canaries. It does not store request bodies. Operators are responsible for providing any required notice and complying with applicable privacy and retention requirements.

The recorded IP is the direct TCP peer. Rook deliberately does not trust forwarded-IP headers; when deploying behind a reverse proxy, use the proxy's trusted-client-IP controls and logs for origin attribution.

## Development checks

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo build --release
cargo install cargo-audit --locked
cargo audit --deny warnings
```

The GitHub Actions workflow runs formatting, Clippy, tests, a release build, and a RustSec audit.

## Project structure

```text
src/
  config.rs       # TOML parsing, environment overrides, validation
  dashboard/      # protected dashboard routes
  detect/         # agent signal extraction
  persona/        # fake website content and templates
  server.rs       # router, response hardening, startup/shutdown
  session.rs      # session and detection middleware
  store/          # transactional SQLite persistence
  traps/          # canary generation, indexing, and payloads
templates/        # Askama HTML templates
static/           # CSS and JavaScript
migrations/       # SQLite schema
```

## License

MIT. See `LICENSE`.
