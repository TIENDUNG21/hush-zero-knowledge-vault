# Security policy

## Supported versions

Only the latest release on `main` receives fixes. The envelope format is versioned separately (byte 4 of every package); format v1 will stay readable by every 1.x release.

## Reporting a vulnerability

Please report privately through GitHub's "Report a vulnerability" form on this repository (Security tab), not through a public issue. Include the version or commit, what an attacker gains, and a reproduction if you have one. You should get a first answer within 7 days.

Findings that are in scope:

- anything that lets the server, a network attacker or a third party learn plaintext, the fragment key, the password or the deletion token;
- ways to read a secret more often than its view limit, after expiry, or after deletion;
- envelope inputs that crash, hang or mis-decrypt either implementation (PHP or JavaScript) instead of failing with a typed error;
- bypasses of the body limits, rate limits, origin check or Content Security Policy;
- anything that makes the server write ids, tokens or client addresses to disk.

Out of scope, because they are documented limits of the design (see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md#limits)):

- an operator who serves modified JavaScript;
- someone who has the link opening the secret;
- ciphertext size, timing and IP metadata visible to the server;
- attacks that need control of the sender's or recipient's device or browser extensions.

## Running it safely

- Serve it over HTTPS only and set `HUSH_PUBLIC_ORIGIN` to the public `https://` origin. HSTS is sent on every response; it has no effect over plain HTTP.
- If a reverse proxy sits in front, list its address in `HUSH_TRUSTED_PROXIES`, and turn off its access log or strip the path: secret ids appear in request paths.
- Run `bin/hush-admin gc` regularly (the compose file does it every five minutes).
- Keep the database volume on an encrypted disk with short backup retention; see "Deletion is best effort" in the threat model.

## Cryptography in use

AES-256-GCM (96-bit random nonce per record), HKDF-SHA256, PBKDF2-HMAC-SHA256 with 600,000 iterations by default, all from the platform: WebCrypto in the browser, OpenSSL and `hash_pbkdf2` in PHP. No primitive is implemented in this repository. The exact construction is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#envelope-format-v1) and pinned by `tests/fixtures/vector-v1.json`, which both implementations must reproduce byte for byte.
