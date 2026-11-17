<?php

declare(strict_types=1);

namespace Hush\Support;

use InvalidArgumentException;

/**
 * RFC 4648 section 5 base64url without padding, strict on decode.
 */
final class Base64Url
{
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    public static function decode(string $text): string
    {
        if (preg_match('/\A[A-Za-z0-9_-]*\z/', $text) !== 1) {
            throw new InvalidArgumentException('base64url text contains characters outside [A-Za-z0-9_-]');
        }
        if (strlen($text) % 4 === 1) {
            throw new InvalidArgumentException('base64url text has an impossible length');
        }
        $decoded = base64_decode(strtr($text, '-_', '+/'), true);
        if ($decoded === false || self::encode($decoded) !== $text) {
            throw new InvalidArgumentException('base64url text is not canonical');
        }

        return $decoded;
    }
}
