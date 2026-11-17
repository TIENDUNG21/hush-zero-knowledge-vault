<?php

declare(strict_types=1);

namespace Hush\Cli\Commands;

use Hush\Cli\Argv;
use Hush\Cli\Command;
use Hush\Cli\Inputs;
use Hush\Cli\Io;
use Hush\Cli\UsageException;
use Hush\Crypto\SealOptions;
use Hush\Crypto\SecretSealer;
use Hush\Support\Base64Url;
use RuntimeException;

/**
 * hush encrypt: offline, writes a .hush package and prints its key.
 */
final class EncryptCommand implements Command
{
    public function name(): string
    {
        return 'encrypt';
    }

    public function summary(): string
    {
        return 'offline: write an encrypted .hush file and print its key';
    }

    public function usage(): string
    {
        return <<<'TXT'
            Usage: hush encrypt [TEXT] [--file PATH [--type MEDIA/TYPE]] --out FILE.hush
                                [--password-stdin | --password-env VAR]

            Prints the base64url key on standard output. The package is the same
            format the server stores, so the browser code can open it too.

            TXT;
    }

    public function run(array $args, Io $io): int
    {
        $argv = Argv::parse($args, ['file' => true, 'type' => true, 'out' => true] + Inputs::PASSWORD_OPTIONS);
        $out = $argv->string('out') ?? throw new UsageException('--out FILE.hush is required');
        $password = Inputs::password($argv, $io);
        $secret = Inputs::secret($argv, $io, 256 * 1_048_576);

        $sealed = SecretSealer::seal($secret, new SealOptions(password: $password));
        $package = $sealed->toPackage()->pack();
        if (file_put_contents($out, $package) !== strlen($package)) {
            throw new RuntimeException(sprintf('Could not write %s', $out));
        }
        $io->out(Base64Url::encode($sealed->fragmentKey) . PHP_EOL);

        return 0;
    }
}
