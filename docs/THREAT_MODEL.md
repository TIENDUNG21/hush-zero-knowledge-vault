# Threat model

This document states what Hush protects, against whom, and where the protection ends. It uses STRIDE per component. File and test names are given so that each claim can be checked against the code.

## What is being protected

| Asset | Where it exists |
|---|---|
| Plaintext (text, file bytes) | Sender's and recipient's device only |
| File name and MIME type | Inside the encrypted metadata record |
| Fragment key (32 random bytes) | The share link after `#`; never in an HTTP request |
| Password (optional) | Typed by sender and recipient; never sent |
| Deletion token (32 random bytes) | The sender's delete link after `#`; the server stores only its SHA-256 |
| Ciphertext and the 36-byte public header | Server database until the last view, expiry or deletion |

## What the server can see

Hush is zero-knowledge about content, not about traffic. The server operator, or anyone who copies the database, learns:

- the ciphertext length, rounded up to a multiple of 256 bytes (the client pads before encrypting), and the chunk size and count;
- whether a password was used, its PBKDF2 iteration count and salt (the public header);
- expiry time, view limit and how many views are left;
- the client IP address and time of every request, for as long as the request is in flight. The application stores neither: rate-limit buckets are keyed by `HMAC-SHA256(server key, IPv4 address or IPv6 /64)` and are pruned once full, and the Docker image disables Apache's access log. A reverse proxy in front of it may still log; that is outside this code.

The creation page shows the sender exactly this list after upload ("What the server received", see `docs/screenshots/created.png`).

## Trust boundaries

```
 sender device                 network (TLS)            server (PHP + SQLite)           recipient device
 [plaintext, key] --encrypt--> [header, meta, chunks] --> [ciphertext rows]  --open-->  [package] --decrypt--> [plaintext]
        ^                                                        |
        +-------------- JavaScript served by the same server ----+
```

The last arrow is the important one. The browser client is delivered by the server it is meant to distrust. See "Limits" below.

## Attackers considered

1. **Database or backup thief.** Gets every row. Learns sizes and timing, cannot decrypt: the key never reached the server.
2. **Curious or compelled operator, passive.** Same as above plus live request metadata (IP, time). Cannot decrypt.
3. **Network attacker without TLS keys.** Sees TLS metadata only. HSTS (`max-age=63072000; includeSubDomains`) prevents downgrade after the first visit.
4. **Someone who obtains the link.** Can open the secret if views are left and, when a password is set, if they know the password. Hush cannot tell them apart from the intended recipient.
5. **Link-preview bots and mail scanners.** Fetch `GET /s/{id}`. That page never consumes a view; only `POST /api/secrets/{id}/open` does (`WebIntegrationTest::testViewPageIsStaticAndDoesNotConsumeAView`).
6. **Abusive clients.** Try to fill the disk, exhaust CPU or race the last view.
7. **Malicious web page in the victim's browser.** Tries cross-site requests or framing.

Not considered: an attacker who controls the sender's or recipient's device, browser extensions with page access, or an active attacker who controls the server's code (see Limits).

## STRIDE

### Spoofing

| Threat | Mitigation | Evidence |
|---|---|---|
| Another user deletes or modifies a secret | Owner operations (upload chunk, seal, delete) need the bearer deletion token. The server stores `SHA-256(token)` and compares with `hash_equals`. | `src/Vault/Token.php`, `VaultServiceTest` |
| Guessing a secret id | 128-bit random ids (22 base64url chars); unknown, expired and burned ids all return the same 404. | `src/Vault/SecretId.php`, `SecretsApiIntegrationTest` |
| Forged `X-Forwarded-For` to dodge rate limits | The header is read only when the TCP peer is in `HUSH_TRUSTED_PROXIES`; the right-most untrusted hop wins; a malformed chain falls back to the peer. | `src/Security/ClientIp.php`, `RateLimitTest` |

### Tampering

| Threat | Mitigation | Evidence |
|---|---|---|
| Server flips bits, swaps, reorders, drops or duplicates chunks | Every record is AES-256-GCM with AAD = header ‖ kind ‖ index. The header carries the chunk count, so truncation and reordering fail authentication; the decoder also rejects short non-final chunks and wrong counts. | `src/Crypto/RecordCipher.php`, `resources/assets/js/core/crypto.js`, `SecretRoundTripTest`, `crypto.test.mjs` |
| Server edits the public header (e.g. lowers iterations, drops the password flag) | The full 36-byte header is part of the AAD of every record, so any edit makes every record fail authentication. Salt and iterations also feed the key derivation. | `RecordCipher`, `KeySchedule`, vector test `tests/fixtures/vector-v1.json` |
| Server swaps in another secret's ciphertext | Each secret has its own random 256-bit fragment key; foreign records fail authentication. | `SecretRoundTripTest` |
| Hostile header makes the client hang | Iterations are bounded to 100,000..5,000,000 and chunk size to 1 KiB..1 MiB before any key derivation; meta length is capped at 4 KiB. | `src/Crypto/Format.php`, `FormatTest`, `format.test.mjs` |
| Chunks changed after the sender sealed | `PUT .../chunks` is refused once sealed and after the upload window (15 minutes by default). | `VaultService::putChunk`, `VaultServiceTest` |

### Repudiation

Hush keeps no audit log on purpose; there is nothing to correlate a sender with a recipient. The cost is that an operator cannot prove who created or opened a secret. This is a deliberate trade-off for this product, recorded here rather than fixed.

### Information disclosure

| Threat | Mitigation | Evidence |
|---|---|---|
| Key reaches the server | The key sits in the URL fragment, which browsers do not send in requests or in `Referer`. `Referrer-Policy: no-referrer` covers the path as well. The CLI parses the fragment locally. | `links.js`, `ShareLink.php` |
| Key stays in the address bar or history after reading | The view page removes the fragment with `history.replaceState` once the secret is decrypted. Before that, the full link is in the browser history like any URL. | `pages/view.js` |
| Exact length reveals content (e.g. a 4-digit PIN) | Payload and metadata are padded to 256-byte blocks before encryption. | `Format::PAD_BLOCK`, `FormatTest` |
| File names leak | Name, MIME type and true size are inside the encrypted metadata record. | `src/Crypto/Meta.php` |
| Ciphertext outlives its last view | The burn happens in the same `UPDATE ... RETURNING` that claims the view; rows are deleted after the response stream ends, and `hush-admin gc` removes anything a broken stream left behind after 5 minutes. | `SecretRepository::claimView`, `VaultService::open` |
| Search engines or caches keep pages | `Cache-Control: no-store`, `X-Robots-Tag: noindex, nofollow`. | `SecurityHeadersMiddleware` |
| Wrong password guesses burn the secret | The page fetches the header and encrypted metadata with `GET` and checks the password against the metadata record first; only a correct key triggers `POST .../open`. | `pages/view.js`, browser check "wrong password does not consume a view" |

### Denial of service

| Threat | Mitigation | Evidence |
|---|---|---|
| Disk filling | Header-declared size is checked against `HUSH_MAX_SECRET_BYTES` (32 MiB) at creation; each chunk must have the exact length the header allows; unsealed uploads expire after the upload window. | `VaultService::create`, `putChunk` |
| Oversized or lying bodies | Per-route body limits; `Content-Length` above the limit is a 413 before reading; the body is read with a hard cap; chunked transfer encoding gets 411. | `BodyLimitMiddleware`, `SecurityIntegrationTest` |
| Request floods | Token buckets per client (IPv4 address or IPv6 /64) and per route class: create, chunk, read, delete, page. Every response carries `RateLimit-*` headers; exhaustion returns 429 with `Retry-After`. | `RateLimiter`, `RateLimitTest` |
| Racing the last view | `claimView` is a single conditional `UPDATE ... WHERE views < max_views RETURNING`. Two processes on two connections to one database: exactly one wins. | `VaultConcurrencyTest` |

### Elevation of privilege

| Threat | Mitigation | Evidence |
|---|---|---|
| Script injection in pages | No inline script or style. CSP `default-src 'none'; script-src 'self'; ... require-trusted-types-for 'script'; trusted-types 'none'`, so DOM HTML sinks throw. Templates escape every value. The browser check fails on any CSP violation. | `SecurityHeadersMiddleware`, `ui/dom.js`, `scripts/browser-check.mjs` |
| Cross-site request forgery | Hush uses no cookies. State-changing requests that carry `Origin` or `Sec-Fetch-Site` must be same-origin. | `OriginCheckMiddleware`, `OriginAndHeadersTest` |
| Clickjacking | `frame-ancestors 'none'`, `X-Frame-Options: DENY`. | `SecurityHeadersMiddleware` |
| Cross-origin leaks | COOP `same-origin`, COEP `require-corp`, CORP `same-origin`. | same |
| Container breakout surface | The image runs Apache as `www-data` on port 8080; compose sets `read_only`, `cap_drop: [ALL]`, `no-new-privileges`. There is no admin web interface; administration is `bin/hush-admin` inside the container. | `Dockerfile`, `compose.yaml` |

## Limits

These are the cases where Hush does not protect the user. They are properties of the design, not bugs waiting for a patch.

**A malicious server can serve malicious JavaScript.** Every browser-based end-to-end scheme that loads its code from the same origin has this weakness (Firefox Send and PrivateBin share it). An operator who wants to read secrets can change `crypto.js` to send the key home, and the user cannot see the difference. Hush narrows the window (no third-party scripts, strict CSP, a small auditable client), but the real defence is not to trust the browser path for high-value secrets: `bin/hush` encrypts with code the user already has, so a compromised server only ever sees ciphertext from it.

**The link is the capability.** Whoever has the link and any remaining view can read the secret. A password adds a second factor that must travel over a different channel. Mail scanners that execute JavaScript and press buttons would consume a view; Hush cannot detect that.

**Metadata is visible.** Sizes to 256 bytes, timing, IP addresses in flight, and the password flag. Hush does not hide that two people used it.

**Deletion is best effort at the storage layer.** SQLite runs with `secure_delete = ON`, which overwrites freed pages in the database file with zeros. In WAL mode a copy of a page can remain in the `-wal` file until the next checkpoint, and filesystem snapshots or backups keep whatever they captured. All of it is ciphertext, but an operator who promises deletion should also run the host with full-disk encryption and short backup retention.

**Weak passwords are guessable offline by whoever holds the ciphertext and the link key.** PBKDF2-SHA256 with 600,000 iterations (the OWASP 2023 recommendation) slows that down; it does not make a four-letter password safe. Without the fragment key, the password alone is useless because the HKDF input also contains the 256-bit link key.

## Review checklist for changes

- Does a new endpoint take a body? Give it a `maxBody` and a rate class in `Application::routes`.
- Does it change state? It must go through `OriginCheckMiddleware` (all non-GET routes do) and must not be reachable by `GET`.
- Does it touch the envelope? Regenerate `tests/fixtures/vector-v1.json` only for a new format version; v1 vectors never change.
- Does it log? Nothing that contains an id, token, header or IP.
