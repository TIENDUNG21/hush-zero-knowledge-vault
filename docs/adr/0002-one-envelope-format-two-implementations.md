# ADR 0002: One binary envelope format, implemented twice and pinned by a vector

Status: accepted

## Context

Two clients encrypt: the browser (WebCrypto) and `bin/hush` (PHP OpenSSL). A secret sent from one must open in the other, files may be up to 32 MiB, and the server must be able to check sizes without reading content.

Options considered:

1. JSON with base64 fields, one AES-GCM blob per secret. Easy to debug, but a 32 MiB file becomes a 43 MiB string that has to fit in memory on both ends and in one request.
2. An existing container (age, JWE, OpenPGP). age has no browser implementation without a WebAssembly build; JWE has no chunking; OpenPGP pulls in a large library and a large attack surface for a two-party format.
3. A small binary format of our own, built only from primitives both platforms provide: AES-256-GCM, HKDF-SHA256, PBKDF2-HMAC-SHA256.

## Decision

Option 3, specified in [ARCHITECTURE.md](../ARCHITECTURE.md#envelope-format-v1): a 36-byte public header, an encrypted metadata record, and fixed-size encrypted chunks, each authenticated with the header, its kind and its index as AAD.

The two implementations are kept honest three ways:

- A test vector (`tests/fixtures/vector-v1.json`) generated once from fixed key, salt and nonces. Both `VectorTest.php` and `vector.test.mjs` must reproduce it byte for byte and decrypt it. The v1 vector never changes; a format change means version 2 and a second vector.
- Offline interop: PHP seals and the browser module running under Node opens, and the reverse, including NFD vs NFC passwords, an empty file and a three-chunk file (`OfflineInteropTest`).
- HTTP interop: `bin/hush` and the browser API client send to and receive from one `php -S` server in both directions (`HttpInteropTest`), and the browser check opens a CLI link in headless Edge.

## Consequences

- No cryptographic primitive is implemented in this repository, only the composition. The composition is small enough (about 650 non-blank lines of PHP and 590 of JavaScript) to review in one sitting.
- Chunks can be uploaded, stored and streamed one at a time; neither PHP nor the browser needs the whole ciphertext in one string on the server side.
- The server parses the public header to enforce size limits before accepting any chunk, and checks each chunk's length against it. It never sees a key.
- Every parsing rule exists twice. The cost is paid in tests: hostile-input cases are written for both `FormatTest.php` and `format.test.mjs`.
- Passwords are normalised to NFC on both sides. Without that, "é" typed on macOS (often NFD) and on Windows (NFC) would derive different keys, a bug that only shows up across platforms.
