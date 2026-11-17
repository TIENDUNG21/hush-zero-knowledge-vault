<?php

declare(strict_types=1);

namespace Hush\Http;

use InvalidArgumentException;

/**
 * Immutable, case-insensitive HTTP header collection.
 *
 * Names are validated against the RFC 9110 token grammar and values may not
 * contain CR, LF or NUL, so nothing that reaches this bag can split a response.
 */
final class HeaderBag
{
    /** @var array<string, array{name: string, values: list<string>}> keyed by lower-case name */
    private array $headers = [];

    /**
     * @param array<string, string|list<string>> $headers
     */
    public function __construct(array $headers = [])
    {
        foreach ($headers as $name => $values) {
            $values = is_array($values) ? $values : [$values];
            foreach ($values as $value) {
                $this->append($name, $value);
            }
        }
    }

    public function has(string $name): bool
    {
        return isset($this->headers[strtolower($name)]);
    }

    /**
     * All values of a header joined with ", " (RFC 9110 field combination), or null.
     */
    public function get(string $name): ?string
    {
        $entry = $this->headers[strtolower($name)] ?? null;

        return $entry === null ? null : implode(', ', $entry['values']);
    }

    /**
     * @return list<string>
     */
    public function values(string $name): array
    {
        return $this->headers[strtolower($name)]['values'] ?? [];
    }

    public function with(string $name, string $value): self
    {
        $clone = clone $this;
        unset($clone->headers[strtolower($name)]);
        $clone->append($name, $value);

        return $clone;
    }

    public function withAdded(string $name, string $value): self
    {
        $clone = clone $this;
        $clone->append($name, $value);

        return $clone;
    }

    public function without(string $name): self
    {
        $clone = clone $this;
        unset($clone->headers[strtolower($name)]);

        return $clone;
    }

    /**
     * @return array<string, list<string>> original-case names
     */
    public function all(): array
    {
        $out = [];
        foreach ($this->headers as $entry) {
            $out[$entry['name']] = $entry['values'];
        }

        return $out;
    }

    private function append(string $name, string $value): void
    {
        if (preg_match('/\A[!#$%&\'*+\-.^_`|~0-9A-Za-z]+\z/', $name) !== 1) {
            throw new InvalidArgumentException(sprintf('Invalid header name "%s"', $name));
        }
        if (preg_match('/[\r\n\0]/', $value) === 1) {
            throw new InvalidArgumentException(sprintf('Header "%s" contains a line break or NUL', $name));
        }
        $key = strtolower($name);
        if (isset($this->headers[$key])) {
            $this->headers[$key]['values'][] = trim($value);

            return;
        }
        $this->headers[$key] = ['name' => $name, 'values' => [trim($value)]];
    }
}
