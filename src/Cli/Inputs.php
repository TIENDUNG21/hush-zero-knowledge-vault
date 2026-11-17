<?php

declare(strict_types=1);

namespace Hush\Cli;

use Hush\Crypto\Meta;
use Hush\Crypto\PlainSecret;
use InvalidArgumentException;

/**
 * Reading secrets, passwords and durations from arguments, files and stdin.
 * Passwords are never accepted as plain arguments (they would show up in
 * the process list and shell history).
 */
final class Inputs
{
    /** @var array<string, bool> */
    public const array PASSWORD_OPTIONS = ['password-stdin' => false, 'password-env' => true];

    public static function password(Argv $argv, Io $io): ?string
    {
        if ($argv->flag('password-stdin')) {
            $password = $io->readStdinLine();
            if ($password === '') {
                throw new UsageException('--password-stdin read an empty line');
            }

            return $password;
        }
        $variable = $argv->string('password-env');
        if ($variable !== null) {
            $password = $io->env($variable);
            if ($password === null || $password === '') {
                throw new UsageException(sprintf('Environment variable %s is empty or not set', $variable));
            }

            return $password;
        }

        return null;
    }

    /**
     * Text from the first positional argument, a file from --file, or text
     * from standard input.
     */
    public static function secret(Argv $argv, Io $io, int $maxBytes): PlainSecret
    {
        $file = $argv->string('file');
        $text = $argv->positionals[0] ?? null;
        if ($file !== null && $text !== null) {
            throw new UsageException('Give either a text argument or --file, not both');
        }

        if ($file !== null) {
            if (!is_file($file) || !is_readable($file)) {
                throw new UsageException(sprintf('Cannot read %s', $file));
            }
            $size = filesize($file);
            if ($size === false || $size > $maxBytes) {
                throw new UsageException(sprintf('%s is larger than %d bytes', $file, $maxBytes));
            }
            $data = file_get_contents($file);
            if ($data === false) {
                throw new UsageException(sprintf('Cannot read %s', $file));
            }
            $type = $argv->string('type');
            if ($type !== null && !Meta::isMediaType($type)) {
                throw new UsageException('--type must be a media type such as application/pdf');
            }

            return PlainSecret::file($data, self::displayName($file), $type);
        }

        if ($text === null) {
            if ($argv->flag('password-stdin')) {
                throw new UsageException('With --password-stdin, pass the secret as an argument or with --file');
            }
            $text = $io->readStdin();
        }
        if ($text === '') {
            throw new UsageException('Nothing to send: the secret is empty');
        }
        try {
            return PlainSecret::text($text);
        } catch (InvalidArgumentException) {
            throw new UsageException('Standard input is not UTF-8 text; send binary data with --file');
        }
    }

    /**
     * "30m", "1h", "2d", "7d" or plain seconds.
     */
    public static function duration(string $value): int
    {
        if (preg_match('/\A(\d{1,7})([smhd]?)\z/', $value, $m) !== 1) {
            throw new UsageException(sprintf('Invalid duration "%s"; use e.g. 30m, 1h or 7d', $value));
        }
        $factor = ['' => 1, 's' => 1, 'm' => 60, 'h' => 3600, 'd' => 86400][$m[2]];

        return (int) $m[1] * $factor;
    }

    /**
     * A file name safe to send: base name only, control characters removed,
     * at most 255 characters.
     */
    public static function displayName(string $path): string
    {
        $name = preg_replace('/[\x00-\x1f\x7f]/u', '', basename(str_replace('\\', '/', $path)));
        $name = trim(is_string($name) ? $name : '');
        if ($name === '') {
            return 'file';
        }

        return preg_match('/\A.{1,255}/su', $name, $m) === 1 ? $m[0] : 'file';
    }

    /**
     * Where to save a received file: an explicit --out, or the sender's file
     * name reduced to a safe base name in the current directory.
     */
    public static function savePath(?string $out, ?string $senderName): string
    {
        if ($out !== null) {
            return $out;
        }
        $name = self::displayName($senderName ?? 'secret.bin');
        if ($name === '.' || $name === '..' || str_starts_with($name, '.')) {
            $name = 'secret-' . ltrim($name, '.');
        }

        return $name;
    }
}
