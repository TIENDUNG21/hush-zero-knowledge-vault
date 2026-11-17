<?php

declare(strict_types=1);

namespace Hush\Tests\Unit\Vault;

use Hush\Tests\Support\VaultFixture;
use PHPUnit\Framework\TestCase;

/**
 * Real OS processes race for the same one-view secret on one SQLite file.
 */
final class VaultConcurrencyTest extends TestCase
{
    private const int RACERS = 6;

    public function testExactlyOneProcessWinsABurnAfterReadSecret(): void
    {
        $path = sys_get_temp_dir() . '/hush-proc-race-' . bin2hex(random_bytes(4)) . '.sqlite';
        $fixture = new VaultFixture($path);

        for ($round = 0; $round < 3; $round++) {
            [$id] = $fixture->store(VaultFixture::sealFile(5000), maxViews: 1);
            $outputs = $this->race($path, $id);

            self::assertCount(1, array_keys($outputs, 'won', true), 'round ' . $round . ': ' . implode(',', $outputs));
            self::assertCount(self::RACERS - 1, array_keys($outputs, 'lost', true));
        }

        unset($fixture);
        foreach (['', '-wal', '-shm'] as $suffix) {
            @unlink($path . $suffix);
        }
    }

    public function testThreeViewSecretServesExactlyThreeOfSixProcesses(): void
    {
        $path = sys_get_temp_dir() . '/hush-proc-race-' . bin2hex(random_bytes(4)) . '.sqlite';
        $fixture = new VaultFixture($path);
        [$id] = $fixture->store(VaultFixture::sealText(), maxViews: 3);

        $outputs = $this->race($path, $id);

        self::assertCount(3, array_keys($outputs, 'won', true), implode(',', $outputs));
        unset($fixture);
        foreach (['', '-wal', '-shm'] as $suffix) {
            @unlink($path . $suffix);
        }
    }

    /**
     * @return list<string>
     */
    private function race(string $database, string $id): array
    {
        $script = dirname(__DIR__, 2) . '/Support/race-open.php';
        $startAt = sprintf('%.4F', microtime(true) + 0.8);
        $processes = [];
        $pipes = [];
        for ($i = 0; $i < self::RACERS; $i++) {
            $process = proc_open(
                [PHP_BINARY, $script, $database, $id, $startAt],
                [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
                $procPipes,
            );
            self::assertIsResource($process);
            $processes[] = $process;
            $pipes[] = $procPipes;
        }

        $outputs = [];
        foreach ($processes as $i => $process) {
            $stdout = stream_get_contents($pipes[$i][1]);
            $stderr = stream_get_contents($pipes[$i][2]);
            fclose($pipes[$i][1]);
            fclose($pipes[$i][2]);
            proc_close($process);
            self::assertSame('', $stderr);
            $outputs[] = trim((string) $stdout);
        }

        return $outputs;
    }
}
