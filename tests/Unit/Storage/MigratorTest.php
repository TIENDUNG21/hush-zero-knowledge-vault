<?php

declare(strict_types=1);

namespace Hush\Tests\Unit\Storage;

use Hush\Storage\Database;
use Hush\Storage\Migrator;
use Hush\Tests\Support\Sql;
use PDO;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class MigratorTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/hush-migrations-' . bin2hex(random_bytes(6));
        mkdir($this->dir);
    }

    protected function tearDown(): void
    {
        $files = glob($this->dir . '/*');
        foreach ($files !== false ? $files : [] as $file) {
            unlink($file);
        }
        rmdir($this->dir);
    }

    public function testProjectMigrationsApplyOnAFreshDatabase(): void
    {
        $pdo = Database::connect(':memory:');
        $migrator = new Migrator($pdo, dirname(__DIR__, 3) . '/migrations');

        self::assertSame(['0001_secrets', '0002_chunks', '0003_rate_buckets', '0004_server_keys'], $migrator->pending());
        self::assertSame(['0001_secrets', '0002_chunks', '0003_rate_buckets', '0004_server_keys'], $migrator->migrate());
        self::assertSame([], $migrator->migrate(), 'second run is a no-op');
        self::assertSame([], $migrator->pending());
        self::assertSame(['chunks', 'rate_buckets', 'schema_migrations', 'secrets', 'server_keys'], $this->tables($pdo));
    }

    public function testAppliesInNumericOrder(): void
    {
        file_put_contents($this->dir . '/0002_second.sql', 'INSERT INTO t (v) VALUES (2);');
        file_put_contents($this->dir . '/0001_first.sql', 'CREATE TABLE t (v INTEGER);');
        file_put_contents($this->dir . '/notes.sql', 'THIS IS NOT A MIGRATION');
        $pdo = Database::connect(':memory:');

        self::assertSame(['0001_first', '0002_second'], (new Migrator($pdo, $this->dir))->migrate());
        self::assertSame(2, Sql::scalar($pdo, 'SELECT v FROM t'));
    }

    public function testFailingMigrationRollsBackAndIsNotRecorded(): void
    {
        file_put_contents($this->dir . '/0001_ok.sql', 'CREATE TABLE a (v INTEGER);');
        file_put_contents($this->dir . '/0002_bad.sql', 'CREATE TABLE b (v INTEGER); INSERT INTO missing VALUES (1);');
        $pdo = Database::connect(':memory:');
        $migrator = new Migrator($pdo, $this->dir);

        try {
            $migrator->migrate();
            self::fail('expected the second migration to fail');
        } catch (RuntimeException $e) {
            self::assertStringContainsString('0002_bad failed', $e->getMessage());
        }

        self::assertSame(['0002_bad'], $migrator->pending());
        self::assertNotContains('b', $this->tables($pdo), 'partial DDL was rolled back');
    }

    public function testEditedMigrationIsDetected(): void
    {
        file_put_contents($this->dir . '/0001_a.sql', 'CREATE TABLE a (v INTEGER);');
        $pdo = Database::connect(':memory:');
        (new Migrator($pdo, $this->dir))->migrate();
        file_put_contents($this->dir . '/0001_a.sql', 'CREATE TABLE a (v TEXT);');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('0001_a changed after it was applied');
        (new Migrator($pdo, $this->dir))->migrate();
    }

    public function testLineEndingsDoNotChangeTheChecksum(): void
    {
        file_put_contents($this->dir . '/0001_a.sql', "CREATE TABLE a (\n v INTEGER\n);");
        $pdo = Database::connect(':memory:');
        (new Migrator($pdo, $this->dir))->migrate();
        file_put_contents($this->dir . '/0001_a.sql', "CREATE TABLE a (\r\n v INTEGER\r\n);");

        self::assertSame([], (new Migrator($pdo, $this->dir))->migrate());
    }

    public function testFileDatabaseUsesWalAndForeignKeys(): void
    {
        $path = $this->dir . '/db.sqlite';
        $pdo = Database::connect($path);

        self::assertSame('wal', Sql::scalar($pdo, 'PRAGMA journal_mode'));
        self::assertSame(1, Sql::scalar($pdo, 'PRAGMA foreign_keys'));
        self::assertSame(1, Sql::scalar($pdo, 'PRAGMA secure_delete'));
        unset($pdo);
        foreach (['-wal', '-shm'] as $suffix) {
            if (is_file($path . $suffix)) {
                unlink($path . $suffix);
            }
        }
    }

    /**
     * @return list<string>
     */
    private function tables(PDO $pdo): array
    {
        $rows = Sql::column($pdo, "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name");

        return array_values(array_filter($rows, 'is_string'));
    }
}
