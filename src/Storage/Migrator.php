<?php

declare(strict_types=1);

namespace Hush\Storage;

use PDO;
use RuntimeException;
use Throwable;

/**
 * Applies numbered SQL files (NNNN_name.sql) in order, each inside its own
 * transaction, and refuses to run if an applied file was edited afterwards.
 */
final class Migrator
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly string $directory,
    ) {}

    /**
     * @return list<string> names of the migrations applied by this call
     */
    public function migrate(): array
    {
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS schema_migrations ('
            . ' name TEXT NOT NULL PRIMARY KEY, checksum TEXT NOT NULL, applied_at INTEGER NOT NULL'
            . ') STRICT, WITHOUT ROWID',
        );

        $applied = $this->applied();
        $ran = [];
        foreach ($this->available() as $name => $file) {
            $sql = $this->read($file);
            $checksum = hash('sha256', $sql);
            if (isset($applied[$name])) {
                if (!hash_equals($applied[$name], $checksum)) {
                    throw new RuntimeException(sprintf('Migration %s changed after it was applied', $name));
                }
                continue;
            }

            $this->pdo->beginTransaction();
            try {
                $this->pdo->exec($sql);
                $insert = $this->pdo->prepare('INSERT INTO schema_migrations (name, checksum, applied_at) VALUES (?, ?, ?)');
                $insert->execute([$name, $checksum, time()]);
                $this->pdo->commit();
            } catch (Throwable $error) {
                $this->pdo->rollBack();
                throw new RuntimeException(sprintf('Migration %s failed: %s', $name, $error->getMessage()), 0, $error);
            }
            $ran[] = $name;
        }

        return $ran;
    }

    /**
     * @return list<string>
     */
    public function pending(): array
    {
        $applied = $this->tableExists() ? $this->applied() : [];

        return array_values(array_filter(
            array_keys($this->available()),
            static fn(string $name): bool => !isset($applied[$name]),
        ));
    }

    /**
     * @return array<string, string> name => path, sorted by name
     */
    private function available(): array
    {
        $files = glob(rtrim($this->directory, '/\\') . '/[0-9][0-9][0-9][0-9]_*.sql');
        if ($files === false) {
            return [];
        }
        $out = [];
        foreach ($files as $file) {
            $out[basename($file, '.sql')] = $file;
        }
        ksort($out, SORT_STRING);

        return $out;
    }

    /**
     * @return array<string, string> name => checksum
     */
    private function applied(): array
    {
        $out = [];
        $rows = $this->pdo->query('SELECT name, checksum FROM schema_migrations');
        if ($rows === false) {
            return [];
        }
        foreach ($rows as $row) {
            if (is_array($row) && is_string($row['name'] ?? null) && is_string($row['checksum'] ?? null)) {
                $out[$row['name']] = $row['checksum'];
            }
        }

        return $out;
    }

    private function tableExists(): bool
    {
        $statement = $this->pdo->query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'");

        return $statement !== false && $statement->fetchColumn() !== false;
    }

    private function read(string $file): string
    {
        $sql = file_get_contents($file);
        if ($sql === false) {
            throw new RuntimeException(sprintf('Cannot read migration %s', basename($file)));
        }

        // Checksums must not depend on the checkout's line endings.
        return str_replace("\r\n", "\n", $sql);
    }
}
