<?php

declare(strict_types=1);

namespace Hush\Http;

use Closure;
use LogicException;

/**
 * Immutable HTTP request.
 *
 * The body starts out as a reader closure so that nothing is read from the
 * socket until a middleware has decided how many bytes this route accepts
 * (see {@see \Hush\Security\BodyLimitMiddleware}).
 */
final class Request
{
    /**
     * @param array<string, string> $query
     * @param array<string, string> $server
     * @param string|Closure(int): string $body a string, or a reader that returns at most N bytes
     * @param array<string, mixed> $attributes
     */
    public function __construct(
        private readonly string $method,
        private readonly string $path,
        private readonly array $query = [],
        private readonly HeaderBag $headers = new HeaderBag(),
        private readonly array $server = [],
        private string|Closure $body = '',
        private array $attributes = [],
    ) {}

    public function method(): string
    {
        return $this->method;
    }

    public function path(): string
    {
        return $this->path;
    }

    public function query(string $name): ?string
    {
        return $this->query[$name] ?? null;
    }

    public function headers(): HeaderBag
    {
        return $this->headers;
    }

    public function header(string $name): ?string
    {
        return $this->headers->get($name);
    }

    public function server(string $name): ?string
    {
        return $this->server[$name] ?? null;
    }

    /**
     * The TCP peer address as seen by PHP; proxies are resolved elsewhere.
     */
    public function remoteAddress(): string
    {
        return $this->server['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    public function isSecure(): bool
    {
        $https = $this->server['HTTPS'] ?? '';

        return $https !== '' && strtolower($https) !== 'off';
    }

    public function attribute(string $name): mixed
    {
        return $this->attributes[$name] ?? null;
    }

    public function withAttribute(string $name, mixed $value): self
    {
        $clone = clone $this;
        $clone->attributes[$name] = $value;

        return $clone;
    }

    public function routeParam(string $name): string
    {
        $params = $this->attributes['route.params'] ?? null;
        if (!is_array($params) || !isset($params[$name]) || !is_string($params[$name])) {
            throw new LogicException(sprintf('Route parameter "%s" is not available', $name));
        }

        return $params[$name];
    }

    public function hasBodyReader(): bool
    {
        return $this->body instanceof Closure;
    }

    /**
     * Reads at most $maxBytes + 1 bytes so callers can tell "exactly at the
     * limit" from "over the limit" without trusting Content-Length.
     */
    public function readBody(int $maxBytes): string
    {
        if ($this->body instanceof Closure) {
            return ($this->body)($maxBytes + 1);
        }

        return substr($this->body, 0, $maxBytes + 1);
    }

    public function withBody(string $body): self
    {
        $clone = clone $this;
        $clone->body = $body;

        return $clone;
    }

    /**
     * The bounded body. Throws if no middleware has read it with a limit yet.
     */
    public function body(): string
    {
        if ($this->body instanceof Closure) {
            throw new LogicException('The request body has not been read with a size limit');
        }

        return $this->body;
    }
}
