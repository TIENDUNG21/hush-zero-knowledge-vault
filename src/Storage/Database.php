<?php

declare(strict_types=1);

namespace Hush\Storage;

use PDO;
use RuntimeException;

/**
 * Opens SQLite with the settings the vault relies on.
 */
final class Database
{
    public static function connect(string $path): PDO
    {
        if ($path !== ':memory:') {
            $directory = dirname($path);
            if (!is_dir($directory) && !mkdir($directory, 0o700, true) && !is_dir($directory)) {
                throw new RuntimeException(sprintf('Cannot create database directory %s', $directory));
            }
        }

        $pdo = new PDO('sqlite:' . $path, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_TIMEOUT => 5,
        ]);

        // Concurrent readers with one writer; wait instead of failing on a busy lock.
        $pdo->exec('PRAGMA busy_timeout = 5000');
        if ($path !== ':memory:') {
            $pdo->exec('PRAGMA journal_mode = WAL');
        }
        $pdo->exec('PRAGMA synchronous = NORMAL');
        $pdo->exec('PRAGMA foreign_keys = ON');
        // Overwrite deleted content with zeros so burned ciphertext does not linger in free pages.
        $pdo->exec('PRAGMA secure_delete = ON');

        return $pdo;
    }
}
