# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/). The envelope format has its own version byte; 1.x reads and writes format v1.

## [1.0.0] - 2026-11-17

First release.

### Envelope format v1

- 36-byte public header (magic, version, flags, PBKDF2 iterations, salt, chunk size, chunk count), an encrypted metadata record and encrypted 512 KiB chunks, each AES-256-GCM with AAD = header, record kind and index.
- Content key from HKDF-SHA256 over the 256-bit fragment key, plus PBKDF2-HMAC-SHA256 (600,000 iterations, NFC-normalised password) when a password is set.
- Payload and metadata padded to 256-byte blocks before encryption.
- Implemented in PHP (OpenSSL) and in JavaScript (WebCrypto), pinned by `tests/fixtures/vector-v1.json`.

### Server

- Framework-free PHP 8.3 kernel: immutable request and response, router with 404/405 distinction, middleware pipeline, autowiring DI container.
- SQLite storage with checksummed migrations; `bin/hush-admin migrate | gc | stats`.
- API to create a secret, upload chunks, seal, read status without consuming a view, open (POST, atomic view claim with burn on the last view, streamed response) and delete with a bearer deletion token stored as SHA-256.
- Expiry by time (60 s to 7 days) and by views (1 to 100); unsealed uploads expire after 15 minutes.
- Security headers on every response (CSP without inline script and with Trusted Types, HSTS, no-referrer, Permissions-Policy, COOP/COEP/CORP), origin and Fetch Metadata checks, per-route body limits, token-bucket rate limiting keyed by an HMAC of the client network.

### Clients

- Browser pages for create, view and delete in vanilla ES modules; the view page checks key and password on the encrypted metadata before spending a view and removes the key from the address bar after decryption.
- `bin/hush send | get | delete | encrypt | decrypt`, interoperable with the browser in both directions.

### Operations and documentation

- Docker image (Apache, unprivileged, no access log) and compose stack with a garbage-collection service, built and tested in CI.
- STRIDE threat model, security policy, architecture document and four ADRs.
- Static how-it-works page on GitHub Pages with an in-browser envelope inspector.

[1.0.0]: https://github.com/TIENDUNG21/hush-zero-knowledge-vault/releases/tag/v1.0.0
