<?php

declare(strict_types=1);

namespace Hush\Tests\Support;

use PDO;
use PDOStatement;
use RuntimeException;

/**
 * Typed shortcuts for inspecting the database in tests.
 */
final class Sql
{
    /**
     * @param list<string|int|float|null> $params
     */
    public static function scalar(PDO $pdo, string $sql, array $params = []): mixed
    {
        return self::run($pdo, $sql, $params)->fetchColumn();
    }

    /**
     * @param list<string|int|float|null> $params
     *
     * @return list<mixed>
     */
    public static function column(PDO $pdo, string $sql, array $params = []): array
    {
        return array_values(self::run($pdo, $sql, $params)->fetchAll(PDO::FETCH_COLUMN));
    }

    /**
     * @param list<string|int|float|null> $params
     */
    public static function exec(PDO $pdo, string $sql, array $params = []): int
    {
        return self::run($pdo, $sql, $params)->rowCount();
    }

    /**
     * @param list<string|int|float|null> $params
     */
    private static function run(PDO $pdo, string $sql, array $params): PDOStatement
    {
        $statement = $pdo->prepare($sql);
        if ($statement === false || !$statement->execute($params)) {
            throw new RuntimeException('Query failed: ' . $sql);
        }

        return $statement;
    }
}
