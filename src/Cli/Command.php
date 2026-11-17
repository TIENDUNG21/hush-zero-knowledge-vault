<?php

declare(strict_types=1);

namespace Hush\Cli;

interface Command
{
    public function name(): string;

    /** One line for "hush help". */
    public function summary(): string;

    /** Full usage text. */
    public function usage(): string;

    /**
     * @param list<string> $args arguments after the command name
     *
     * @return int exit code
     */
    public function run(array $args, Io $io): int;
}
