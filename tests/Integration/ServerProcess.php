<?php

declare(strict_types=1);

namespace Hush\Tests\Integration;

use Hush\Client\StreamTransport;
use Hush\Client\TransportException;
use Hush\Storage\Database;
use Hush\Storage\Migrator;
use RuntimeException;

/**
 * Runs the real front controller under `php -S 127.0.0.1:<port>` with its
 * own temporary SQLite database.
 */
final class ServerProcess
{
    public readonly string $baseUrl;
    public readonly string $databasePath;

    /** @var resource */
    private $process;

    private readonly string $logPath;

    /**
     * @param array<string, string> $env extra HUSH_* settings
     */
    public function __construct(public readonly int $port, array $env = [])
    {
        $root = dirname(__DIR__, 2);
        $dir = sys_get_temp_dir() . '/hush-it-' . $port . '-' . bin2hex(random_bytes(4));
        mkdir($dir, 0o700, true);
        $this->databasePath = $dir . '/hush.sqlite';
        $this->logPath = $dir . '/server.log';
        (new Migrator(Database::connect($this->databasePath), $root . '/migrations'))->migrate();

        $environment = getenv();
        $environment['HUSH_DB_PATH'] = $this->databasePath;
        foreach ($env as $name => $value) {
            $environment[$name] = $value;
        }

        $process = proc_open(
            [PHP_BINARY, '-d', 'display_errors=stderr', '-S', '127.0.0.1:' . $port, 'public/index.php'],
            [0 => ['file', $dir . '/stdin', 'w'], 1 => ['file', $this->logPath, 'a'], 2 => ['file', $this->logPath, 'a']],
            $pipes,
            $root,
            $environment,
        );
        if (!is_resource($process)) {
            throw new RuntimeException('Could not start php -S');
        }
        $this->process = $process;
        $this->baseUrl = 'http://127.0.0.1:' . $port;
        $this->waitUntilReady();
    }

    public function stop(): void
    {
        if (is_resource($this->process)) {
            proc_terminate($this->process);
            proc_close($this->process);
        }
    }

    public function log(): string
    {
        $log = file_get_contents($this->logPath);

        return $log === false ? '' : $log;
    }

    private function waitUntilReady(): void
    {
        $transport = new StreamTransport(1.0);
        $deadline = microtime(true) + 10;
        while (microtime(true) < $deadline) {
            try {
                if ($transport->send('GET', $this->baseUrl . '/healthz')->status === 200) {
                    return;
                }
            } catch (TransportException) {
                usleep(100_000);
            }
        }
        $this->stop();
        throw new RuntimeException('php -S did not become ready: ' . $this->log());
    }
}
