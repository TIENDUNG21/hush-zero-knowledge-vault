<?php

declare(strict_types=1);

namespace Hush\Http;

use RuntimeException;

/**
 * An error that maps one-to-one onto an HTTP response.
 *
 * The message is shown to clients, so it must never contain secrets,
 * file paths or SQL.
 */
final class HttpException extends RuntimeException
{
    /**
     * @param array<string, string> $headers
     */
    public function __construct(
        public readonly int $status,
        public readonly string $errorCode,
        string $message,
        public readonly array $headers = [],
    ) {
        parent::__construct($message, $status);
    }

    public static function badRequest(string $errorCode, string $message): self
    {
        return new self(400, $errorCode, $message);
    }

    public static function unauthorized(string $message): self
    {
        return new self(401, 'missing_token', $message, ['WWW-Authenticate' => 'Bearer']);
    }

    public static function forbidden(string $errorCode, string $message): self
    {
        return new self(403, $errorCode, $message);
    }

    public static function notFound(string $message = 'Nothing here.'): self
    {
        return new self(404, 'not_found', $message);
    }

    /**
     * @param list<string> $allowed
     */
    public static function methodNotAllowed(array $allowed): self
    {
        return new self(405, 'method_not_allowed', 'This method is not allowed here.', ['Allow' => implode(', ', $allowed)]);
    }

    public static function conflict(string $errorCode, string $message): self
    {
        return new self(409, $errorCode, $message);
    }

    public static function lengthRequired(): self
    {
        return new self(411, 'length_required', 'Send a Content-Length header; chunked uploads are not accepted.');
    }

    public static function payloadTooLarge(int $limit): self
    {
        return new self(413, 'payload_too_large', sprintf('The request body exceeds the %d byte limit for this endpoint.', $limit));
    }

    public static function unsupportedMediaType(string $expected): self
    {
        return new self(415, 'unsupported_media_type', sprintf('Expected Content-Type %s.', $expected));
    }

    public static function unprocessable(string $errorCode, string $message): self
    {
        return new self(422, $errorCode, $message);
    }

    public static function tooManyRequests(int $retryAfterSeconds): self
    {
        return new self(429, 'rate_limited', 'Too many requests. Try again later.', ['Retry-After' => (string) $retryAfterSeconds]);
    }
}
