# ADR 0001: The key travels in the URL fragment

Status: accepted

## Context

The server must store a secret it cannot read, yet a single link has to be enough for the recipient. Something has to carry the key from sender to recipient, and the obvious channel, the link itself, is also what gets pasted into chat apps, mail and ticket systems.

Options considered:

1. Key in the path or query string. Simple, but the key reaches the server in every request line, every proxy log and every `Referer` header. The server would have to promise not to look, which is exactly the trust Hush is meant to remove.
2. Key exchanged out of band (a second message, a QR code). Strong, but two messages per secret is friction people route around by pasting both into the same chat.
3. Key in the fragment (`/s/{id}#{key}`). Browsers never send the fragment in HTTP requests or in `Referer` (RFC 3986 section 3.5, Fetch standard). JavaScript on the page reads it from `location.hash`.
4. Asymmetric: recipient publishes a public key first. Needs a recipient account or a prior round trip; out of scope for "send a link".

## Decision

Option 3. The share link is `https://host/s/{22-char id}#{43-char base64url key}`. The delete link uses the same idea: `/d/{id}#{deletion token}`.

An optional password adds a second factor for the cases where the link may be seen by others. It is combined with the fragment key in HKDF, never used alone, so a weak password does not weaken the link key ([ARCHITECTURE.md](../ARCHITECTURE.md#envelope-format-v1)).

## Consequences

- The server never receives the key, so a database leak or a subpoena yields ciphertext only.
- The fragment is still in the browser history and in whatever the link was pasted into. The view page removes it with `history.replaceState` after decryption; it cannot clean up the chat log.
- Link-preview bots fetch the URL without the fragment's meaning but with a `GET`. Opening therefore has to be a `POST` triggered by a person ([ADR 0004](0004-sqlite-and-a-single-statement-claim.md) covers the claim itself).
- The scheme only protects users if the JavaScript that reads the fragment is honest. That is the main limit in [THREAT_MODEL.md](../THREAT_MODEL.md#limits), and the reason `bin/hush` exists: it parses the fragment with code the user already has.
