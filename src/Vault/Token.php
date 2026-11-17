<?php

declare(strict_types=1);

namespace Hush\Vault;

use Hush\Support\Base64Url;

/**
 * Deletion (owner) tokens: 256 random bits shown once to the creator.
 * Only the SHA-256 is stored, so a database leak does not let anyone
 * delete or append to secrets.
 */
final class Token
{
    public const string PATTERN = '[A-Za-z0-9_-]{43}';

    public static function generate(): string
    {
        return Base64Url::encode(random_bytes(32));
    }

    public static function hash(string $token): string
    {
        return hash('sha256', $token, true);
    }

    public static function matches(string $presented, string $storedHash): bool
    {
        return hash_equals($storedHash, self::hash($presented));
    }

    /**
     * Extracts the token from "Authorization: Bearer <token>".
     */
    public static function fromAuthorization(?string $header): ?string
    {
        if ($header === null || preg_match('/\ABearer (' . self::PATTERN . ')\z/', $header, $m) !== 1) {
            return null;
        }

        return $m[1];
    }
}
