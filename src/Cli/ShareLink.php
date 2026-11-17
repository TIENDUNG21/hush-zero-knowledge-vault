<?php

declare(strict_types=1);

namespace Hush\Cli;

use Hush\Crypto\Format;
use Hush\Support\Base64Url;
use Hush\Vault\SecretId;
use Hush\Vault\Token;
use InvalidArgumentException;

/**
 * Share links (/s/{id}#{key}) and delete links (/d/{id}#{token}); the PHP
 * twin of resources/assets/js/client/links.js.
 */
final class ShareLink
{
    private function __construct(
        public readonly string $origin,
        public readonly string $id,
        public readonly string $secret,
    ) {}

    public static function share(string $origin, string $id, string $fragmentKey): string
    {
        return rtrim($origin, '/') . '/s/' . $id . '#' . Base64Url::encode($fragmentKey);
    }

    public static function delete(string $origin, string $id, string $token): string
    {
        return rtrim($origin, '/') . '/d/' . $id . '#' . $token;
    }

    /**
     * @return self with $secret = the raw 32-byte key
     */
    public static function parseShare(string $url): self
    {
        [$origin, $id, $fragment] = self::split($url, 's');
        try {
            $key = Base64Url::decode($fragment);
        } catch (InvalidArgumentException) {
            throw new UsageException('The key after "#" is damaged.');
        }
        if (strlen($key) !== Format::KEY_LENGTH) {
            throw new UsageException('The key after "#" has the wrong length; the link may be cut off.');
        }

        return new self($origin, $id, $key);
    }

    /**
     * @return self with $secret = the deletion token
     */
    public static function parseDelete(string $url): self
    {
        [$origin, $id, $fragment] = self::split($url, 'd');
        if (preg_match('/\A' . Token::PATTERN . '\z/', $fragment) !== 1) {
            throw new UsageException('This delete link is incomplete.');
        }

        return new self($origin, $id, $fragment);
    }

    /**
     * @return array{string, string, string}
     */
    private static function split(string $url, string $prefix): array
    {
        $parts = parse_url($url);
        $scheme = $parts['scheme'] ?? '';
        $host = $parts['host'] ?? '';
        if (!in_array($scheme, ['http', 'https'], true) || $host === '') {
            throw new UsageException('Expected an http:// or https:// Hush link.');
        }
        $path = $parts['path'] ?? '';
        if (preg_match('#\A/' . $prefix . '/(' . SecretId::PATTERN . ')\z#', $path, $m) !== 1) {
            throw new UsageException(sprintf('Expected a link of the form https://host/%s/<id>#...', $prefix));
        }
        $fragment = $parts['fragment'] ?? '';
        if ($fragment === '') {
            throw new UsageException('The link has nothing after "#"; ask the sender for the complete link.');
        }
        $origin = $scheme . '://' . (str_contains($host, ':') ? '[' . $host . ']' : $host) . (isset($parts['port']) ? ':' . $parts['port'] : '');

        return [$origin, $m[1], $fragment];
    }
}
