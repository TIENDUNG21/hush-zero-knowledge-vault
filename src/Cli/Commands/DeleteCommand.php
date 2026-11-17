<?php

declare(strict_types=1);

namespace Hush\Cli\Commands;

use Closure;
use Hush\Cli\Argv;
use Hush\Cli\Command;
use Hush\Cli\Io;
use Hush\Cli\ShareLink;
use Hush\Cli\UsageException;
use Hush\Client\ApiClient;

/**
 * hush delete: remove a secret with its delete link.
 */
final class DeleteCommand implements Command
{
    /**
     * @param Closure(string): ApiClient $clients
     */
    public function __construct(private readonly Closure $clients) {}

    public function name(): string
    {
        return 'delete';
    }

    public function summary(): string
    {
        return 'delete a secret with its delete link';
    }

    public function usage(): string
    {
        return "Usage: hush delete DELETE_LINK\n";
    }

    public function run(array $args, Io $io): int
    {
        $argv = Argv::parse($args, []);
        $link = ShareLink::parseDelete($argv->positionals[0] ?? throw new UsageException('Give the delete link'));
        ($this->clients)($link->origin)->delete($link->id, $link->secret);
        $io->err("Deleted.\n");

        return 0;
    }
}
