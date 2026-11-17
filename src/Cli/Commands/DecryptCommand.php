<?php

declare(strict_types=1);

namespace Hush\Cli\Commands;

use Hush\Cli\Argv;
use Hush\Cli\Command;
use Hush\Cli\Inputs;
use Hush\Cli\Io;
use Hush\Cli\UsageException;
use Hush\Crypto\Package;
use Hush\Crypto\SecretOpener;
use Hush\Support\Base64Url;
use InvalidArgumentException;
use RuntimeException;

/**
 * hush decrypt: offline, opens a .hush package with its key.
 */
final class DecryptCommand implements Command
{
    public function name(): string
    {
        return 'decrypt';
    }

    public function summary(): string
    {
        return 'offline: open a .hush file with its key';
    }

    public function usage(): string
    {
        return <<<'TXT'
            Usage: hush decrypt FILE.hush --key KEY [--out PATH] [--force]
                                [--password-stdin | --password-env VAR]

            Text goes to standard output unless --out is given; files are saved
            under their original base name or --out.

            TXT;
    }

    public function run(array $args, Io $io): int
    {
        $argv = Argv::parse($args, ['key' => true, 'out' => true, 'force' => false] + Inputs::PASSWORD_OPTIONS);
        $file = $argv->positionals[0] ?? throw new UsageException('Give the .hush file');
        $keyText = $argv->string('key') ?? throw new UsageException('--key is required');
        try {
            $key = Base64Url::decode($keyText);
        } catch (InvalidArgumentException) {
            throw new UsageException('--key must be base64url');
        }
        $bytes = is_file($file) ? file_get_contents($file) : false;
        if ($bytes === false) {
            throw new UsageException(sprintf('Cannot read %s', $file));
        }

        $secret = SecretOpener::open(Package::unpack($bytes), $key, Inputs::password($argv, $io));

        $out = $argv->string('out');
        if ($secret->kind === 'text' && $out === null) {
            $io->out($secret->data);

            return 0;
        }
        $path = Inputs::savePath($out, $secret->name);
        if (file_exists($path) && !$argv->flag('force')) {
            throw new UsageException(sprintf('%s already exists; use --out or --force', $path));
        }
        if (file_put_contents($path, $secret->data) !== strlen($secret->data)) {
            throw new RuntimeException(sprintf('Could not write %s', $path));
        }
        $io->err(sprintf("Saved %s (%d bytes).\n", $path, strlen($secret->data)));

        return 0;
    }
}
