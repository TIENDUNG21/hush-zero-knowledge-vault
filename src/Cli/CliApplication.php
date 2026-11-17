<?php

declare(strict_types=1);

namespace Hush\Cli;

use Closure;
use Hush\Cli\Commands\DecryptCommand;
use Hush\Cli\Commands\DeleteCommand;
use Hush\Cli\Commands\EncryptCommand;
use Hush\Cli\Commands\GetCommand;
use Hush\Cli\Commands\SendCommand;
use Hush\Client\ApiClient;
use Hush\Client\ApiException;
use Hush\Client\StreamTransport;
use Hush\Client\TransportException;
use Hush\Crypto\CryptoException;

/**
 * bin/hush. Exit codes: 0 ok, 1 server or network error, 2 usage error,
 * 3 the secret could not be decrypted.
 */
final class CliApplication
{
    public const string VERSION = '1.0.0';

    public const int OK = 0;
    public const int FAILURE = 1;
    public const int USAGE = 2;
    public const int DECRYPT_FAILED = 3;

    /** @var array<string, Command> */
    private array $commands = [];

    /**
     * @param list<Command> $commands
     */
    public function __construct(array $commands)
    {
        foreach ($commands as $command) {
            $this->commands[$command->name()] = $command;
        }
    }

    /**
     * @param (Closure(string): ApiClient)|null $clients
     */
    public static function create(?Closure $clients = null): self
    {
        $clients ??= static fn(string $origin): ApiClient => new ApiClient(new StreamTransport(), $origin);

        return new self([
            new SendCommand($clients),
            new GetCommand($clients),
            new DeleteCommand($clients),
            new EncryptCommand(),
            new DecryptCommand(),
        ]);
    }

    /**
     * @param list<string> $args arguments without the program name
     */
    public function run(array $args, Io $io): int
    {
        $name = $args[0] ?? 'help';
        $rest = array_slice($args, 1);

        if ($name === 'help' || $name === '--help' || $name === '-h') {
            $topic = $this->commands[$rest[0] ?? ''] ?? null;
            $io->out($topic !== null ? $topic->usage() : $this->overview());

            return self::OK;
        }
        if ($name === 'version' || $name === '--version') {
            $io->out('hush ' . self::VERSION . PHP_EOL);

            return self::OK;
        }

        $command = $this->commands[$name] ?? null;
        if ($command === null) {
            $io->err(sprintf("hush: unknown command \"%s\"\n\n%s", $name, $this->overview()));

            return self::USAGE;
        }
        if (in_array('--help', $rest, true)) {
            $io->out($command->usage());

            return self::OK;
        }

        try {
            return $command->run($rest, $io);
        } catch (UsageException $e) {
            $io->err('hush ' . $name . ': ' . $e->getMessage() . PHP_EOL);

            return self::USAGE;
        } catch (CryptoException $e) {
            $io->err('hush ' . $name . ': ' . self::explain($e) . PHP_EOL);

            return self::DECRYPT_FAILED;
        } catch (ApiException $e) {
            $io->err(sprintf('hush %s: %s (%s)%s', $name, $e->getMessage(), $e->errorCode, PHP_EOL));

            return self::FAILURE;
        } catch (TransportException $e) {
            $io->err('hush ' . $name . ': ' . $e->getMessage() . PHP_EOL);

            return self::FAILURE;
        }
    }

    private static function explain(CryptoException $e): string
    {
        return match ($e->reason) {
            'authentication' => 'the link key or password does not open this secret (no view was used if this happened before download)',
            'password_required' => 'this secret has a password: use --password-stdin or --password-env VAR',
            default => $e->getMessage(),
        };
    }

    private function overview(): string
    {
        $lines = ['hush ' . self::VERSION . " - zero-knowledge secret sharing from the terminal\n", 'Commands:'];
        foreach ($this->commands as $command) {
            $lines[] = sprintf('  %-8s %s', $command->name(), $command->summary());
        }
        $lines[] = '';
        $lines[] = 'Run "hush help COMMAND" for details. Keys never leave this machine;';
        $lines[] = 'the server receives ciphertext only.';

        return implode(PHP_EOL, $lines) . PHP_EOL;
    }
}
