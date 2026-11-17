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
use Hush\Crypto\SealOptions;
use Hush\Crypto\SecretSealer;

/**
 * hush send: encrypt locally, upload ciphertext, print the share link.
 */
final class SendCommand implements Command
{
    public const string DEFAULT_SERVER = 'http://127.0.0.1:5140';
    private const int MAX_FILE_BYTES = 256 * 1_048_576;

    /**
     * @param Closure(string): ApiClient $clients builds a client for a server origin
     */
    public function __construct(private readonly Closure $clients) {}

    public function name(): string
    {
        return 'send';
    }

    public function summary(): string
    {
        return 'encrypt text or a file locally, upload it and print the link';
    }

    public function usage(): string
    {
        return <<<'TXT'
            Usage: hush send [TEXT] [--file PATH [--type MEDIA/TYPE]] [options]

            The secret is TEXT, the contents of --file, or standard input.

              --server URL        Hush server (default: $HUSH_SERVER or http://127.0.0.1:5140)
              --expires TIME      30m, 1h, 1d, 7d or seconds (default 1d)
              --views N           how many times it can be opened (default 1)
              --password-stdin    read a password from the first line of standard input
              --password-env VAR  read a password from an environment variable
              --json              print {"link", "deleteLink", "id", "expiresAt"} as JSON

            The link goes to standard output, the delete link to standard error.

            TXT;
    }

    public function run(array $args, Io $io): int
    {
        $argv = Argv::parse($args, [
            'file' => true, 'type' => true, 'server' => true, 'expires' => true, 'views' => true, 'json' => false,
        ] + Inputs::PASSWORD_OPTIONS);
        if (count($argv->positionals) > 1) {
            throw new UsageException('Quote the text: only one TEXT argument is allowed');
        }

        $server = rtrim($argv->string('server') ?? $io->env('HUSH_SERVER') ?? self::DEFAULT_SERVER, '/');
        if (preg_match('~\Ahttps?://[^/\s?#]+\z~', $server) !== 1) {
            throw new UsageException('--server must look like https://hush.example (no path)');
        }
        $expiresIn = Inputs::duration($argv->string('expires') ?? '1d');
        $views = $argv->string('views') ?? '1';
        if (preg_match('/\A\d{1,3}\z/', $views) !== 1) {
            throw new UsageException('--views must be a number');
        }

        $password = Inputs::password($argv, $io);
        $secret = Inputs::secret($argv, $io, self::MAX_FILE_BYTES);
        $sealed = SecretSealer::seal($secret, new SealOptions(password: $password));
        $created = ($this->clients)($server)->upload($sealed, $expiresIn, (int) $views);

        $link = ShareLink::share($server, $created['id'], $sealed->fragmentKey);
        $deleteLink = ShareLink::delete($server, $created['id'], $created['deletionToken']);

        if ($argv->flag('json')) {
            $io->out(json_encode([
                'link' => $link,
                'deleteLink' => $deleteLink,
                'id' => $created['id'],
                'expiresAt' => $created['expiresAt'],
            ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . PHP_EOL);

            return 0;
        }

        $io->out($link . PHP_EOL);
        $io->err(sprintf(
            "Can be opened %s until %s%s.\nDelete link (keep it private): %s\n",
            (int) $views === 1 ? 'once' : $views . ' times',
            gmdate('Y-m-d H:i', $created['expiresAt']) . ' UTC',
            $password !== null ? '; send the password through another channel' : '',
            $deleteLink,
        ));

        return 0;
    }
}
