<?php

declare(strict_types=1);

namespace Hush\Config;

use Hush\Security\RateRule;
use InvalidArgumentException;

/**
 * Runtime configuration, read once from environment variables.
 * Invalid values fail at boot instead of degrading silently.
 */
final class Config
{
    public const int MIB = 1048576;

    /**
     * @param array<string, RateRule> $rateRules
     * @param list<string> $trustedProxies
     */
    public function __construct(
        public readonly string $projectRoot,
        public readonly string $databasePath,
        public readonly ?string $publicOrigin = null,
        public readonly int $maxSecretBytes = 32 * self::MIB,
        public readonly int $maxTtlSeconds = 604800,
        public readonly int $uploadWindowSeconds = 900,
        public readonly int $burnGraceSeconds = 300,
        public readonly array $rateRules = [],
        public readonly array $trustedProxies = [],
    ) {}

    /**
     * @return array<string, RateRule>
     */
    public static function defaultRateRules(): array
    {
        return [
            'create' => new RateRule(30, 0.05),  // 30 burst, then 3 per minute
            'chunk' => new RateRule(600, 10),
            'read' => new RateRule(120, 2),
            'delete' => new RateRule(30, 0.5),
            'page' => new RateRule(300, 5),
        ];
    }

    /**
     * @param array<array-key, mixed> $env usually getenv()
     */
    public static function fromEnvironment(array $env, string $projectRoot): self
    {
        $string = static function (string $name) use ($env): ?string {
            $value = $env[$name] ?? null;

            return is_string($value) && trim($value) !== '' ? trim($value) : null;
        };

        $databasePath = $string('HUSH_DB_PATH') ?? 'var/hush.sqlite';
        if (!self::isAbsolutePath($databasePath)) {
            $databasePath = rtrim($projectRoot, '/\\') . '/' . $databasePath;
        }

        $origin = $string('HUSH_PUBLIC_ORIGIN');
        if ($origin !== null && preg_match('#\Ahttps?://[A-Za-z0-9.-]+(:\d{1,5})?\z#', $origin) !== 1) {
            throw new InvalidArgumentException('HUSH_PUBLIC_ORIGIN must be scheme://host[:port] without a path');
        }

        $rules = self::defaultRateRules();
        foreach (array_keys($rules) as $bucket) {
            $spec = $string('HUSH_RATE_' . strtoupper($bucket));
            if ($spec !== null) {
                $rules[$bucket] = RateRule::parse($spec);
            }
        }

        $proxies = [];
        foreach (explode(',', $string('HUSH_TRUSTED_PROXIES') ?? '') as $proxy) {
            $proxy = trim($proxy);
            if ($proxy === '') {
                continue;
            }
            if (filter_var($proxy, FILTER_VALIDATE_IP) === false) {
                throw new InvalidArgumentException(sprintf('HUSH_TRUSTED_PROXIES entry "%s" is not an IP address', $proxy));
            }
            $proxies[] = $proxy;
        }

        return new self(
            projectRoot: $projectRoot,
            databasePath: $databasePath,
            publicOrigin: $origin,
            maxSecretBytes: self::int($string('HUSH_MAX_SECRET_BYTES'), 32 * self::MIB, 1024, 256 * self::MIB, 'HUSH_MAX_SECRET_BYTES'),
            maxTtlSeconds: self::int($string('HUSH_MAX_TTL'), 604800, 60, 2592000, 'HUSH_MAX_TTL'),
            uploadWindowSeconds: self::int($string('HUSH_UPLOAD_WINDOW'), 900, 30, 86400, 'HUSH_UPLOAD_WINDOW'),
            burnGraceSeconds: 300,
            rateRules: $rules,
            trustedProxies: $proxies,
        );
    }

    private static function int(?string $raw, int $default, int $min, int $max, string $name): int
    {
        if ($raw === null) {
            return $default;
        }
        if (preg_match('/\A\d{1,12}\z/', $raw) !== 1 || (int) $raw < $min || (int) $raw > $max) {
            throw new InvalidArgumentException(sprintf('%s must be an integer between %d and %d', $name, $min, $max));
        }

        return (int) $raw;
    }

    private static function isAbsolutePath(string $path): bool
    {
        return str_starts_with($path, '/') || preg_match('#\A[A-Za-z]:[/\\\\]#', $path) === 1;
    }
}
