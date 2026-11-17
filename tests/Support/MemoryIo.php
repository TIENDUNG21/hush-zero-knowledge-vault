<?php

declare(strict_types=1);

namespace Hush\Tests\Support;

use Hush\Cli\Io;

final class MemoryIo implements Io
{
    public string $stdout = '';
    public string $stderr = '';

    /**
     * @param array<string, string> $env
     */
    public function __construct(private string $stdin = '', private readonly array $env = []) {}

    public function readStdin(): string
    {
        $data = $this->stdin;
        $this->stdin = '';

        return $data;
    }

    public function readStdinLine(): string
    {
        $parts = preg_split('/\r?\n/', $this->stdin, 2);
        $line = $parts[0] ?? '';
        $this->stdin = $parts[1] ?? '';

        return $line;
    }

    public function out(string $text): void
    {
        $this->stdout .= $text;
    }

    public function err(string $text): void
    {
        $this->stderr .= $text;
    }

    public function env(string $name): ?string
    {
        return $this->env[$name] ?? null;
    }
}
