<?php

declare(strict_types=1);

namespace Hush\Vault;

use RuntimeException;

/**
 * Domain errors of the vault. $kind is one of not_found, forbidden,
 * conflict, invalid, too_large; the API layer maps kinds to HTTP statuses.
 */
final class VaultException extends RuntimeException
{
    private function __construct(
        public readonly string $kind,
        public readonly string $errorCode,
        string $message,
    ) {
        parent::__construct($message);
    }

    public static function notFound(): self
    {
        return new self('not_found', 'not_found', 'This secret does not exist, has expired or has already been viewed.');
    }

    public static function forbidden(): self
    {
        return new self('forbidden', 'invalid_token', 'The deletion token does not match this secret.');
    }

    public static function conflict(string $errorCode, string $message): self
    {
        return new self('conflict', $errorCode, $message);
    }

    public static function invalid(string $errorCode, string $message): self
    {
        return new self('invalid', $errorCode, $message);
    }

    public static function tooLarge(string $message): self
    {
        return new self('too_large', 'secret_too_large', $message);
    }
}
