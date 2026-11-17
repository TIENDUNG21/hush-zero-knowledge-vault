<?php

declare(strict_types=1);

namespace Hush\Cli;

final class ConsoleIo implements Io
{
    public function readStdin(): string
    {
        $data = stream_get_contents(STDIN);

        return $data === false ? '' : $data;
    }

    public function readStdinLine(): string
    {
        $line = fgets(STDIN);

        return $line === false ? '' : rtrim($line, "\r\n");
    }

    public function out(string $text): void
    {
        fwrite(STDOUT, $text);
    }

    public function err(string $text): void
    {
        fwrite(STDERR, $text);
    }

    public function env(string $name): ?string
    {
        $value = getenv($name);

        return $value === false ? null : $value;
    }
}
