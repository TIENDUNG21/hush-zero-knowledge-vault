<?php

declare(strict_types=1);

namespace Hush\Tests\Unit\Admin;

use Hush\Admin\AdminApplication;
use Hush\Config\Config;
use Hush\Kernel\Application;
use Hush\Support\Clock;
use Hush\Tests\Support\FrozenClock;
use Hush\Tests\Support\VaultFixture;
use Hush\Vault\SecretRepository;
use Hush\Vault\VaultService;
use PDO;
use PHPUnit\Framework\TestCase;

final class AdminApplicationTest extends TestCase
{
    public function testMigrateThenReportUpToDate(): void
    {
        $app = $this->admin();

        [$code, $out] = $this->runCommand($app, ['migrate']);
        self::assertSame(0, $code);
        self::assertStringContainsString('Applied: 0001_secrets, 0002_chunks', $out);

        [, $again] = $this->runCommand($app, ['migrate']);
        self::assertSame('Database is up to date.' . PHP_EOL, $again);
    }

    public function testGcAndStatsPrintCountsOnly(): void
    {
        $fixture = new VaultFixture();
        $clock = new FrozenClock();
        $config = new Config(dirname(__DIR__, 3), ':memory:', maxSecretBytes: 64 * 1024);
        $app = new Application($config, [
            PDO::class => $fixture->pdo,
            Clock::class => $clock,
            VaultService::class => new VaultService(new SecretRepository($fixture->pdo), $config, $clock),
        ]);
        [$id] = $fixture->store(VaultFixture::sealText(), ttl: 60);
        $clock->advance(3600);

        [$code, $stats] = $this->runCommand(new AdminApplication($config, $app), ['stats']);
        self::assertSame(0, $code);
        self::assertMatchesRegularExpression('/secrets\s+1/', $stats);
        self::assertStringNotContainsString($id, $stats);

        [, $gc] = $this->runCommand(new AdminApplication($config, $app), ['gc']);
        self::assertSame('Removed 1 expired, 0 abandoned and 0 burned secrets; pruned 0 rate-limit buckets.' . PHP_EOL, $gc);
    }

    public function testUnknownCommandFails(): void
    {
        [$code, , $err] = $this->runCommand($this->admin(), ['explode']);

        self::assertSame(2, $code);
        self::assertStringContainsString('unknown command "explode"', $err);
    }

    public function testHelp(): void
    {
        [$code, $out] = $this->runCommand($this->admin(), []);

        self::assertSame(0, $code);
        self::assertStringContainsString('migrate', $out);
    }

    private function admin(): AdminApplication
    {
        return new AdminApplication(new Config(dirname(__DIR__, 3), ':memory:'));
    }

    /**
     * @param list<string> $args
     *
     * @return array{int, string, string}
     */
    private function runCommand(AdminApplication $app, array $args): array
    {
        $out = fopen('php://memory', 'w+');
        $err = fopen('php://memory', 'w+');
        self::assertIsResource($out);
        self::assertIsResource($err);
        $code = $app->run($args, $out, $err);
        rewind($out);
        rewind($err);

        return [$code, (string) stream_get_contents($out), (string) stream_get_contents($err)];
    }
}
