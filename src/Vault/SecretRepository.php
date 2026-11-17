<?php

declare(strict_types=1);

namespace Hush\Vault;

use Generator;
use PDO;
use PDOStatement;
use RuntimeException;

/**
 * All SQL for secrets and chunks. Binary columns are bound as LOBs because
 * the tables are STRICT and would reject TEXT in a BLOB column.
 */
final class SecretRepository
{
    public function __construct(private readonly PDO $pdo) {}

    public function insert(SecretRecord $record): void
    {
        $statement = $this->prepare(
            'INSERT INTO secrets (id, header, meta, chunk_count, chunk_size, owner_token, state, max_views, views, expires_at, upload_deadline)'
            . ' VALUES (:id, :header, :meta, :chunk_count, :chunk_size, :owner_token, :state, :max_views, 0, :expires_at, :upload_deadline)',
        );
        $statement->bindValue(':id', $record->id);
        $statement->bindValue(':header', $record->header, PDO::PARAM_LOB);
        $statement->bindValue(':meta', $record->meta, PDO::PARAM_LOB);
        $statement->bindValue(':chunk_count', $record->chunkCount, PDO::PARAM_INT);
        $statement->bindValue(':chunk_size', $record->chunkSize, PDO::PARAM_INT);
        $statement->bindValue(':owner_token', $record->ownerTokenHash, PDO::PARAM_LOB);
        $statement->bindValue(':state', $record->state);
        $statement->bindValue(':max_views', $record->maxViews, PDO::PARAM_INT);
        $statement->bindValue(':expires_at', $record->expiresAt, PDO::PARAM_INT);
        $statement->bindValue(':upload_deadline', $record->uploadDeadline, PDO::PARAM_INT);
        $statement->execute();
    }

    public function find(string $id): ?SecretRecord
    {
        $statement = $this->prepare('SELECT * FROM secrets WHERE id = ?');
        $statement->execute([$id]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? SecretRecord::fromRow($row) : null;
    }

    /**
     * Upload or re-upload (retry) one chunk while the secret is still uploading.
     */
    public function putChunk(string $id, int $index, string $data): void
    {
        $statement = $this->prepare(
            'INSERT INTO chunks (secret_id, idx, data) VALUES (:id, :idx, :data)'
            . ' ON CONFLICT (secret_id, idx) DO UPDATE SET data = excluded.data',
        );
        $statement->bindValue(':id', $id);
        $statement->bindValue(':idx', $index, PDO::PARAM_INT);
        $statement->bindValue(':data', $data, PDO::PARAM_LOB);
        $statement->execute();
    }

    public function uploadedChunks(string $id): int
    {
        $statement = $this->prepare('SELECT COUNT(*) FROM chunks WHERE secret_id = ?');
        $statement->execute([$id]);
        $count = $statement->fetchColumn();

        return is_int($count) ? $count : 0;
    }

    public function storedBytes(string $id): int
    {
        $statement = $this->prepare('SELECT COALESCE(SUM(length(data)), 0) FROM chunks WHERE secret_id = ?');
        $statement->execute([$id]);
        $bytes = $statement->fetchColumn();

        return is_int($bytes) ? $bytes : 0;
    }

    public function markSealed(string $id): bool
    {
        $statement = $this->prepare("UPDATE secrets SET state = 'sealed' WHERE id = ? AND state = 'uploading'");
        $statement->execute([$id]);

        return $statement->rowCount() === 1;
    }

    /**
     * Atomically consumes one view. A single UPDATE ... RETURNING both checks
     * and increments, and burns the secret on its last view, so two readers
     * racing for a one-view secret cannot both win.
     *
     * @return int|null views left after this one, or null if nothing could be claimed
     */
    public function claimView(string $id, int $now): ?int
    {
        $statement = $this->prepare(
            'UPDATE secrets SET'
            . ' views = views + 1,'
            . " state = CASE WHEN views + 1 >= max_views THEN 'burned' ELSE state END,"
            . ' burned_at = CASE WHEN views + 1 >= max_views THEN :now ELSE burned_at END'
            . " WHERE id = :id AND state = 'sealed' AND expires_at > :now AND views < max_views"
            . ' RETURNING max_views - views AS views_left',
        );
        $statement->bindValue(':id', $id);
        $statement->bindValue(':now', $now, PDO::PARAM_INT);
        $statement->execute();
        $left = $statement->fetchColumn();
        $statement->closeCursor();

        return is_int($left) ? $left : null;
    }

    /**
     * Streams chunk records one row at a time so a large secret never sits
     * in PHP memory as a whole.
     *
     * @return Generator<int, string>
     */
    public function chunks(string $id, int $count): Generator
    {
        $statement = $this->prepare('SELECT data FROM chunks WHERE secret_id = ? AND idx = ?');
        for ($index = 0; $index < $count; $index++) {
            $statement->execute([$id, $index]);
            $data = $statement->fetchColumn();
            $statement->closeCursor();
            if (!is_string($data)) {
                throw new RuntimeException(sprintf('Chunk %d of a sealed secret is missing', $index));
            }
            yield $index => $data;
        }
    }

    public function purge(string $id): void
    {
        // Chunks go with the secret through ON DELETE CASCADE.
        $this->prepare('DELETE FROM secrets WHERE id = ?')->execute([$id]);
    }

    /**
     * @return array{expired: int, abandoned: int, burned: int}
     */
    public function collectGarbage(int $now, int $burnedBefore): array
    {
        $expired = $this->prepare('DELETE FROM secrets WHERE expires_at <= ?');
        $expired->execute([$now]);
        $abandoned = $this->prepare("DELETE FROM secrets WHERE state = 'uploading' AND upload_deadline <= ?");
        $abandoned->execute([$now]);
        $burned = $this->prepare("DELETE FROM secrets WHERE state = 'burned' AND burned_at <= ?");
        $burned->execute([$burnedBefore]);

        return [
            'expired' => $expired->rowCount(),
            'abandoned' => $abandoned->rowCount(),
            'burned' => $burned->rowCount(),
        ];
    }

    /**
     * @return array{secrets: int, sealed: int, uploading: int, burned: int, chunk_bytes: int}
     */
    public function stats(): array
    {
        $statement = $this->prepare(
            "SELECT COUNT(*) AS secrets, COALESCE(SUM(state = 'sealed'), 0) AS sealed, COALESCE(SUM(state = 'uploading'), 0) AS uploading,"
            . " COALESCE(SUM(state = 'burned'), 0) AS burned, (SELECT COALESCE(SUM(length(data)), 0) FROM chunks) AS chunk_bytes FROM secrets",
        );
        $statement->execute();
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        $int = static fn(string $key): int => is_array($row) && is_int($row[$key] ?? null) ? $row[$key] : 0;

        return [
            'secrets' => $int('secrets'),
            'sealed' => $int('sealed'),
            'uploading' => $int('uploading'),
            'burned' => $int('burned'),
            'chunk_bytes' => $int('chunk_bytes'),
        ];
    }

    private function prepare(string $sql): PDOStatement
    {
        $statement = $this->pdo->prepare($sql);
        if ($statement === false) {
            throw new RuntimeException('Could not prepare a statement');
        }

        return $statement;
    }
}
