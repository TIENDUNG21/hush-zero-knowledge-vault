<?php

declare(strict_types=1);

namespace Hush\Cli\Commands;

use Closure;
use Hush\Cli\Argv;
use Hush\Cli\Command;
use Hush\Cli\Inputs;
use Hush\Cli\Io;
use Hush\Cli\ShareLink;
use Hush\Cli\UsageException;
use Hush\Client\ApiClient;
use Hush\Crypto\Meta;
use Hush\Crypto\Package;
use Hush\Crypto\SecretOpener;
use RuntimeException;

/**
 * hush get: check the link (and password) on the encrypted metadata, then
 * consume one view, decrypt, and print or save the secret.
 */
final class GetCommand implements Command
{
    /**
     * @param Closure(string): ApiClient $clients
     */
    public function __construct(private readonly Closure $clients) {}

    public function name(): string
    {
        return 'get';
    }

    public function summary(): string
    {
        return 'open a share link: text to standard output, files to disk';
    }

    public function usage(): string
    {
        return <<<'TXT'
            Usage: hush get LINK [--out PATH] [--force] [--password-stdin | --password-env VAR]

            Text secrets are written to standard output as they are. Files are
            saved under the sender's file name (base name only) or --out.
            Nothing is consumed until the link key and password have been
            checked against the encrypted metadata.

            TXT;
    }

    public function run(array $args, Io $io): int
    {
        $argv = Argv::parse($args, ['out' => true, 'force' => false] + Inputs::PASSWORD_OPTIONS);
        $link = $argv->positionals[0] ?? throw new UsageException('Give the share link');
        $parsed = ShareLink::parseShare($link);
        $client = ($this->clients)($parsed->origin);

        $status = $client->status($parsed->id);
        $password = Inputs::password($argv, $io);
        if ($status['passwordProtected'] && $password === null) {
            throw new UsageException('This secret has a password: use --password-stdin or --password-env VAR (no view was used)');
        }
        // Pre-flight: a wrong key or password fails here, before a view is spent.
        $meta = SecretOpener::openMeta($status['header'], $status['meta'], $parsed->secret, $password);

        $path = null;
        if ($meta->kind === Meta::KIND_FILE) {
            $path = Inputs::savePath($argv->string('out'), $meta->name);
            if (file_exists($path) && !$argv->flag('force')) {
                throw new UsageException(sprintf('%s already exists; use --out or --force (no view was used)', $path));
            }
        }

        $opened = $client->open($parsed->id);
        $secret = SecretOpener::open(Package::unpack($opened['package']), $parsed->secret, $password);

        if ($path === null) {
            $out = $argv->string('out');
            if ($out !== null) {
                $this->write($out, $secret->data);
                $io->err(sprintf("Saved text to %s.\n", $out));
            } else {
                $io->out($secret->data);
            }
        } else {
            $this->write($path, $secret->data);
            $io->err(sprintf("Saved %s (%d bytes).\n", $path, strlen($secret->data)));
        }
        $io->err($opened['viewsLeft'] === 0
            ? "That was the last view; the server has deleted it.\n"
            : sprintf("Views left: %d.\n", $opened['viewsLeft']));

        return 0;
    }

    private function write(string $path, string $data): void
    {
        if (file_put_contents($path, $data) !== strlen($data)) {
            throw new RuntimeException(sprintf('Could not write %s', $path));
        }
    }
}
