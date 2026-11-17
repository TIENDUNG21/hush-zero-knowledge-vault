<?php

declare(strict_types=1);

namespace Hush\Admin;

use Hush\Config\Config;
use Hush\Kernel\Application;
use Hush\Security\RateLimiter;
use Hush\Storage\Migrator;
use Hush\Vault\SecretRepository;
use Hush\Vault\VaultService;
use PDO;
use Throwable;

/**
 * bin/hush-admin: server maintenance commands (migrate, gc, stats).
 * Prints counts only; never ids, tokens or ciphertext.
 */
final class AdminApplication
{
    private readonly Application $app;

    public function __construct(private readonly Config $config, ?Application $app = null)
    {
        $this->app = $app ?? new Application($config);
    }

    /**
     * @param list<string> $args
     * @param resource $stdout
     * @param resource $stderr
     */
    public function run(array $args, $stdout, $stderr): int
    {
        $command = $args[0] ?? 'help';
        try {
            return match ($command) {
                'migrate' => $this->migrate($stdout),
                'gc' => $this->gc($stdout),
                'stats' => $this->stats($stdout),
                'help', '--help', '-h' => $this->help($stdout),
                default => $this->unknown($command, $stderr),
            };
        } catch (Throwable $e) {
            fwrite($stderr, 'hush-admin: ' . $e->getMessage() . PHP_EOL);

            return 1;
        }
    }

    /**
     * @param resource $out
     */
    private function migrate($out): int
    {
        $applied = (new Migrator($this->app->container()->get(PDO::class), $this->config->projectRoot . '/migrations'))->migrate();
        fwrite($out, $applied === []
            ? 'Database is up to date.' . PHP_EOL
            : 'Applied: ' . implode(', ', $applied) . PHP_EOL);

        return 0;
    }

    /**
     * @param resource $out
     */
    private function gc($out): int
    {
        $report = $this->app->container()->get(VaultService::class)->collectGarbage();
        $buckets = $this->app->container()->get(RateLimiter::class)->prune();
        fwrite($out, sprintf(
            'Removed %d expired, %d abandoned and %d burned secrets; pruned %d rate-limit buckets.%s',
            $report['expired'],
            $report['abandoned'],
            $report['burned'],
            $buckets,
            PHP_EOL,
        ));

        return 0;
    }

    /**
     * @param resource $out
     */
    private function stats($out): int
    {
        $stats = $this->app->container()->get(SecretRepository::class)->stats();
        foreach ($stats as $name => $value) {
            fwrite($out, sprintf('%-12s %d%s', $name, $value, PHP_EOL));
        }

        return 0;
    }

    /**
     * @param resource $out
     */
    private function help($out): int
    {
        fwrite($out, <<<'TXT'
            Usage: hush-admin <command>

              migrate   apply pending database migrations
              gc        delete expired, abandoned and burned secrets and idle rate-limit buckets
              stats     print row counts and stored ciphertext bytes

            Configuration comes from HUSH_* environment variables (see README).

            TXT);

        return 0;
    }

    /**
     * @param resource $err
     */
    private function unknown(string $command, $err): int
    {
        fwrite($err, sprintf('hush-admin: unknown command "%s" (try "help")%s', $command, PHP_EOL));

        return 2;
    }
}
