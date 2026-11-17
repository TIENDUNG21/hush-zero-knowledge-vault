<?php

declare(strict_types=1);

namespace Hush\Crypto;

use RuntimeException;

/**
 * Raised for malformed envelopes and failed decryption.
 *
 * $reason is one of: format (bytes do not follow the v1 layout),
 * authentication (wrong key or password, or tampered ciphertext),
 * integrity (authenticated pieces that do not fit together),
 * password_required, unsupported.
 */
final class CryptoException extends RuntimeException
{
    public function __construct(public readonly string $reason, string $message)
    {
        parent::__construct($message);
    }

    public static function format(string $message): self
    {
        return new self('format', $message);
    }

    public static function authentication(): self
    {
        return new self('authentication', 'Decryption failed: wrong key or password, or the data was modified.');
    }

    public static function integrity(string $message): self
    {
        return new self('integrity', $message);
    }

    public static function passwordRequired(): self
    {
        return new self('password_required', 'This secret is protected by a password.');
    }

    public static function unsupported(string $message): self
    {
        return new self('unsupported', $message);
    }
}
