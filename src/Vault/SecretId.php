<?php

declare(strict_types=1);

namespace Hush\Vault;

use Hush\Support\Base64Url;

/**
 * Secret identifiers: 128 random bits, base64url (22 characters).
 * Unguessable, so the id alone does not let anyone enumerate secrets.
 */
final class SecretId
{
    public const string PATTERN = '[A-Za-z0-9_-]{22}';

    public static function generate(): string
    {
        return Base64Url::encode(random_bytes(16));
    }

    public static function isValid(string $id): bool
    {
        return preg_match('/\A' . self::PATTERN . '\z/', $id) === 1;
    }
}
