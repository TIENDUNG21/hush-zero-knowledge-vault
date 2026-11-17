<?php

declare(strict_types=1);

namespace Hush\Http;

use Closure;
use InvalidArgumentException;

/**
 * Builds a {@see Request} from PHP's superglobals without touching the body.
 */
final class RequestFactory
{
    /**
     * @param array<array-key, mixed> $server usually $_SERVER
     * @param Closure(int): string $bodyReader returns at most N bytes of the raw body
     * @param array<array-key, mixed>|null $rawHeaders getallheaders() when the SAPI provides it
     */
    public static function fromGlobals(array $server, Closure $bodyReader, ?array $rawHeaders = null): Request
    {
        $strings = [];
        foreach ($server as $key => $value) {
            if (is_string($key) && (is_string($value) || is_int($value))) {
                $strings[$key] = (string) $value;
            }
        }

        $method = strtoupper($strings['REQUEST_METHOD'] ?? 'GET');
        if (preg_match('/\A[A-Z]{1,16}\z/', $method) !== 1) {
            $method = 'INVALID';
        }

        $uri = $strings['REQUEST_URI'] ?? '/';
        $rawPath = explode('?', $uri, 2)[0];
        $path = rawurldecode($rawPath === '' ? '/' : $rawPath);

        $query = [];
        parse_str($strings['QUERY_STRING'] ?? '', $parsed);
        foreach ($parsed as $key => $value) {
            if (is_string($value)) {
                $query[(string) $key] = $value;
            }
        }

        return new Request(
            $method,
            $path,
            $query,
            self::headers($strings, $rawHeaders),
            $strings,
            $bodyReader,
        );
    }

    /**
     * @param array<string, string> $server
     * @param array<array-key, mixed>|null $rawHeaders
     */
    private static function headers(array $server, ?array $rawHeaders): HeaderBag
    {
        $pairs = [];
        if ($rawHeaders !== null) {
            foreach ($rawHeaders as $name => $value) {
                if (is_string($name) && is_string($value)) {
                    $pairs[] = [$name, $value];
                }
            }
        } else {
            foreach ($server as $key => $value) {
                if (str_starts_with($key, 'HTTP_')) {
                    $name = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($key, 5)))));
                    $pairs[] = [$name, $value];
                } elseif ($key === 'CONTENT_TYPE' || $key === 'CONTENT_LENGTH') {
                    $pairs[] = [$key === 'CONTENT_TYPE' ? 'Content-Type' : 'Content-Length', $value];
                }
            }
        }

        $bag = new HeaderBag();
        foreach ($pairs as [$name, $value]) {
            try {
                $bag = $bag->withAdded($name, $value);
            } catch (InvalidArgumentException) {
                // A header that cannot be represented safely is dropped, never echoed back.
            }
        }

        return $bag;
    }
}
