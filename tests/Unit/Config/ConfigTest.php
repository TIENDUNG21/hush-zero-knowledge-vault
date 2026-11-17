<?php

declare(strict_types=1);

namespace Hush\Tests\Unit\Config;

use Hush\Config\Config;
use Hush\Security\RateRule;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ConfigTest extends TestCase
{
    public function testDefaults(): void
    {
        $config = Config::fromEnvironment([], '/srv/hush');

        self::assertSame('/srv/hush/var/hush.sqlite', $config->databasePath);
        self::assertNull($config->publicOrigin);
        self::assertSame(32 * 1048576, $config->maxSecretBytes);
        self::assertSame(604800, $config->maxTtlSeconds);
        self::assertSame([], $config->trustedProxies);
        self::assertEqualsWithDelta(0.05, $config->rateRules['create']->refillPerSecond, 1e-9);
    }

    public function testReadsOverrides(): void
    {
        $config = Config::fromEnvironment([
            'HUSH_DB_PATH' => '/data/vault.sqlite',
            'HUSH_PUBLIC_ORIGIN' => 'https://hush.example:8443',
            'HUSH_MAX_SECRET_BYTES' => '2048',
            'HUSH_RATE_CREATE' => '2, 0.5',
            'HUSH_TRUSTED_PROXIES' => '10.0.0.1, ::1',
        ], '/srv/hush');

        self::assertSame('/data/vault.sqlite', $config->databasePath);
        self::assertSame('https://hush.example:8443', $config->publicOrigin);
        self::assertSame(2048, $config->maxSecretBytes);
        self::assertEquals(new RateRule(2, 0.5), $config->rateRules['create']);
        self::assertSame(['10.0.0.1', '::1'], $config->trustedProxies);
    }

    public function testWindowsAbsoluteDatabasePathIsKept(): void
    {
        $config = Config::fromEnvironment(['HUSH_DB_PATH' => 'C:\\data\\hush.sqlite'], '/srv');

        self::assertSame('C:\\data\\hush.sqlite', $config->databasePath);
    }

    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function invalidEnvironments(): iterable
    {
        yield 'origin with path' => [['HUSH_PUBLIC_ORIGIN' => 'https://hush.example/app']];
        yield 'origin without scheme' => [['HUSH_PUBLIC_ORIGIN' => 'hush.example']];
        yield 'size too small' => [['HUSH_MAX_SECRET_BYTES' => '10']];
        yield 'size not a number' => [['HUSH_MAX_SECRET_BYTES' => '1e9']];
        yield 'ttl too long' => [['HUSH_MAX_TTL' => '99999999']];
        yield 'bad rate rule' => [['HUSH_RATE_READ' => 'fast']];
        yield 'zero refill' => [['HUSH_RATE_READ' => '10,0']];
        yield 'bad proxy' => [['HUSH_TRUSTED_PROXIES' => 'proxy.local']];
    }

    /**
     * @param array<string, string> $env
     */
    #[DataProvider('invalidEnvironments')]
    public function testRejectsInvalidValues(array $env): void
    {
        $this->expectException(InvalidArgumentException::class);
        Config::fromEnvironment($env, '/srv');
    }
}
