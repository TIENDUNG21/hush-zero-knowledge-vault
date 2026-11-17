<?php

declare(strict_types=1);

namespace Hush\Tests\Interop;

use PHPUnit\Framework\Assert;
use RuntimeException;

/**
 * Runs a process with JSON (or text) on stdin and captures its output.
 */
final class Node
{
    public static function binary(): string
    {
        $configured = getenv('NODE_BINARY');

        return is_string($configured) && $configured !== '' ? $configured : 'node';
    }

    /**
     * Calls tests/js/interop/hush-node.mjs and decodes its JSON answer.
     *
     * @param array<string, mixed> $input
     *
     * @return array<string, mixed>
     */
    public static function call(string $command, string $target, array $input): array
    {
        [$code, $stdout, $stderr] = self::run(
            [self::binary(), dirname(__DIR__) . '/js/interop/hush-node.mjs', $command, $target],
            json_encode($input, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE),
        );
        Assert::assertSame(0, $code, 'node ' . $command . ' failed: ' . $stderr);
        $data = json_decode($stdout, true, 16, JSON_THROW_ON_ERROR);
        Assert::assertIsArray($data);
        $out = [];
        foreach ($data as $key => $value) {
            $out[(string) $key] = $value;
        }

        return $out;
    }

    /**
     * @param list<string> $command
     *
     * @return array{int, string, string}
     */
    public static function run(array $command, string $stdin = ''): array
    {
        $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, dirname(__DIR__, 2));
        if (!is_resource($process)) {
            throw new RuntimeException('Could not start ' . $command[0]);
        }
        fwrite($pipes[0], $stdin);
        fclose($pipes[0]);
        $stdout = (string) stream_get_contents($pipes[1]);
        $stderr = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        return [proc_close($process), $stdout, $stderr];
    }
}
