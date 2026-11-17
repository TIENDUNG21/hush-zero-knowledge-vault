<?php

declare(strict_types=1);

namespace Hush\Cli;

/**
 * Console streams and environment, injectable for tests.
 */
interface Io
{
    /** Everything on standard input. */
    public function readStdin(): string;

    /** One line of standard input without its line ending (used for passwords). */
    public function readStdinLine(): string;

    public function out(string $text): void;

    public function err(string $text): void;

    public function env(string $name): ?string;
}
