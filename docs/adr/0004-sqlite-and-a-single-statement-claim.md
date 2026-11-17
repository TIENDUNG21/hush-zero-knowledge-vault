# ADR 0004: SQLite, and a view is claimed by one statement

Status: accepted

## Context

Burn-after-read has one hard requirement: when a one-view secret is opened by two clients at the same moment, exactly one of them may receive it. PHP runs each request in its own process (Apache prefork, FPM, or `php -S`), so in-memory locks are useless. The storage is small: a few rows per secret, chunks up to 1 MiB, and a rate-limit table.

Options considered:

1. Files on disk with `flock`. No dependencies, but expiry, garbage collection and the rate-limit table would each need their own file layout and locking rules.
2. PostgreSQL or MySQL. Correct and well understood, but a second service to run for a single-host tool, and the race would still need care.
3. SQLite through PDO. One file, transactions, `RETURNING` since 3.35, WAL mode for concurrent readers.

For the claim itself: a `SELECT` followed by an `UPDATE` races unless both run in one write transaction; a single conditional `UPDATE ... RETURNING` does not race at all.

## Decision

SQLite, with versioned, checksummed SQL migrations (`migrations/*.sql`, applied by `bin/hush-admin migrate` and by the Docker entrypoint). Connections set `journal_mode = WAL`, `busy_timeout = 5000`, `foreign_keys = ON` and `secure_delete = ON`.

A view is claimed with one statement that increments the counter, flips the state to `burned` on the last view, and returns the views left, conditioned on `state = 'sealed' AND expires_at > :now AND views < max_views`. No row returned means not found, expired or already burned; the API returns the same 404 for all three.

## Consequences

- SQLite serialises writers, so the claim is atomic without explicit locking. `VaultConcurrencyTest` checks it with real processes: one winner out of two for a one-view secret, three out of six for a three-view secret.
- Deletion happens after the package has been streamed, not inside the claim, so a large secret is not deleted before the client has it. A client that disconnects mid-stream has still spent the view; the rows are already unreadable and `gc` removes them after five minutes. Spending the view on a failed transfer is the safer failure.
- One server process tree per database file. Horizontal scaling would need a shared database; the repository layer is the only code that would change.
- `secure_delete` zeroes freed pages in the main file. Copies in the WAL until checkpoint and in host backups are outside its reach, as stated in the threat model.
