<?php

declare(strict_types=1);

namespace Hush\Tests\Support;

use Hush\Config\Config;
use Hush\Crypto\PlainSecret;
use Hush\Crypto\SealedSecret;
use Hush\Crypto\SealOptions;
use Hush\Crypto\SecretSealer;
use Hush\Storage\Database;
use Hush\Storage\Migrator;
use Hush\Vault\SecretRepository;
use Hush\Vault\VaultService;
use PDO;

/**
 * Builds a migrated database plus a VaultService on a frozen clock.
 */
final class VaultFixture
{
    public readonly PDO $pdo;
    public readonly FrozenClock $clock;
    public readonly VaultService $vault;
    public readonly Config $config;

    public function __construct(string $path = ':memory:', ?Config $config = null)
    {
        $root = dirname(__DIR__, 2);
        $this->pdo = Database::connect($path);
        (new Migrator($this->pdo, $root . '/migrations'))->migrate();
        $this->clock = new FrozenClock();
        $this->config = $config ?? new Config($root, $path, maxSecretBytes: 64 * 1024);
        $this->vault = new VaultService(new SecretRepository($this->pdo), $this->config, $this->clock);
    }

    public static function sealText(string $text = 'secret', ?string $password = null): SealedSecret
    {
        return SecretSealer::seal(PlainSecret::text($text), new SealOptions(password: $password, iterations: 100_000, chunkSize: 1024));
    }

    public static function sealFile(int $bytes, int $chunkSize = 1024): SealedSecret
    {
        return SecretSealer::seal(
            PlainSecret::file($bytes > 0 ? random_bytes($bytes) : '', 'data.bin'),
            new SealOptions(chunkSize: $chunkSize),
        );
    }

    /**
     * Creates, uploads and seals; returns [id, token].
     *
     * @return array{string, string}
     */
    public function store(SealedSecret $sealed, int $maxViews = 1, int $ttl = 3600): array
    {
        $created = $this->vault->create($sealed->headerBytes, $sealed->metaRecord, $ttl, $maxViews);
        foreach ($sealed->chunkRecords() as $index => $record) {
            $this->vault->putChunk($created->id, $index, $created->deletionToken, $record);
        }
        $this->vault->seal($created->id, $created->deletionToken);

        return [$created->id, $created->deletionToken];
    }
}
