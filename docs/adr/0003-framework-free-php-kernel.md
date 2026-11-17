# ADR 0003: A framework-free PHP kernel

Status: accepted

## Context

The server handles eleven routes, stores opaque blobs, and is security-sensitive mainly at its edges: headers, body limits, rate limits, origin checks. It will be deployed by people who want to read what they run.

Options considered:

1. Laravel or Symfony. Mature, but each brings tens of thousands of lines of runtime dependencies, sessions and cookies by default, and update churn. Most of it would be switched off.
2. A micro-framework (Slim + PSR-7 + a PSR-11 container). Smaller, still around ten packages at runtime, and the security layers would be written by hand anyway.
3. Our own small kernel: request and response value objects, a router, a middleware pipeline, a DI container. Composer only for autoloading and development tools.

## Decision

Option 3. `composer.json` has no `require` entries besides PHP and its extensions. The kernel is split the way a framework would split it, so each part can be tested on its own:

- `Http`: immutable `Request` and `Response`, a case-insensitive `HeaderBag`, a `RequestFactory` that reads the body lazily, and a `ResponseEmitter`, the only class that calls `header()`. Responses can carry a generator body, which is how a large package is streamed.
- `Routing`: a linear-scan router with typed placeholders; 404 and 405 (with `Allow`) are distinct.
- `Middleware`: interfaces in the PSR-15 shape and a `Pipeline`.
- `Container`: shared services, factories, constructor autowiring, and cycle detection that reports the full chain.
- `Kernel`: `Application` is the single composition root that names concrete classes, routes and middleware order.

## Consequences

- The production dependency tree is the PHP binary and its bundled extensions (`pdo_sqlite`, `openssl`; `intl` is optional and only used by the CLI to normalise non-ASCII passwords). `composer install --no-dev` produces an autoloader and nothing else, which the Dockerfile relies on.
- Security behaviour is visible in one file: the middleware order and per-route attributes (`rate`, `maxBody`) in `Application.php`.
- PHPStan runs at `level: max` with strict rules over `src/`, `tests/`, `bin/` and `scripts/`, which is practical because there is no framework magic to describe to it.
- What a framework would have given for free had to be written and tested: about 1,150 non-blank lines for HTTP, routing, middleware, container and kernel, covered by `tests/Unit/{Http,Routing,Kernel,Container}`.
- There is no ORM. The repository is hand-written SQL, which is the right size for two tables and makes the atomic claim in [ADR 0004](0004-sqlite-and-a-single-statement-claim.md) explicit.
