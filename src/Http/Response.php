<?php

declare(strict_types=1);

namespace Hush\Http;

/**
 * Immutable HTTP response. The body is either a string or an iterable of
 * string pieces, so large downloads can be streamed from the database.
 */
final class Response
{
    /**
     * @param string|iterable<string> $body
     */
    public function __construct(
        private int $status = 200,
        private HeaderBag $headers = new HeaderBag(),
        private string|iterable $body = '',
    ) {}

    /**
     * @param array<array-key, mixed> $data
     */
    public static function json(array $data, int $status = 200): self
    {
        $json = json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        return new self($status, new HeaderBag([
            'Content-Type' => 'application/json; charset=utf-8',
            'Content-Length' => (string) strlen($json),
        ]), $json);
    }

    public static function html(string $html, int $status = 200): self
    {
        return new self($status, new HeaderBag([
            'Content-Type' => 'text/html; charset=utf-8',
            'Content-Length' => (string) strlen($html),
        ]), $html);
    }

    /**
     * @param string|iterable<string> $body
     */
    public static function bytes(string|iterable $body, string $contentType, ?int $length = null, int $status = 200): self
    {
        $headers = new HeaderBag(['Content-Type' => $contentType]);
        if (is_string($body)) {
            $length = strlen($body);
        }
        if ($length !== null) {
            $headers = $headers->with('Content-Length', (string) $length);
        }

        return new self($status, $headers, $body);
    }

    public static function noContent(): self
    {
        return new self(204);
    }

    public function status(): int
    {
        return $this->status;
    }

    public function headers(): HeaderBag
    {
        return $this->headers;
    }

    public function header(string $name): ?string
    {
        return $this->headers->get($name);
    }

    public function withStatus(int $status): self
    {
        $clone = clone $this;
        $clone->status = $status;

        return $clone;
    }

    public function withHeader(string $name, string $value): self
    {
        $clone = clone $this;
        $clone->headers = $this->headers->with($name, $value);

        return $clone;
    }

    public function withoutBody(): self
    {
        $clone = clone $this;
        $clone->body = '';

        return $clone;
    }

    /**
     * @return iterable<string>
     */
    public function body(): iterable
    {
        if (is_string($this->body)) {
            return $this->body === '' ? [] : [$this->body];
        }

        return $this->body;
    }

    /**
     * Collects the whole body; consumes a streamed body (tests, small payloads).
     */
    public function bodyString(): string
    {
        if (is_string($this->body)) {
            return $this->body;
        }
        $out = '';
        foreach ($this->body as $piece) {
            $out .= $piece;
        }

        return $out;
    }
}
