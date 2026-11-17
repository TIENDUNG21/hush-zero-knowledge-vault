<?php

declare(strict_types=1);

namespace Hush\Security;

use Hush\Config\Config;
use Hush\Support\Base64Url;
use Hush\Support\Clock;
use InvalidArgumentException;
use PDO;
use RuntimeException;
use Throwable;

/**
 * Token buckets persisted in SQLite (PHP keeps no memory between requests).
 *
 * Bucket rows are keyed by HMAC-SHA256(server key, client network), so the
 * table never holds a readable IP address; rows of fully refilled buckets
 * carry no information and are pruned.
 */
final class RateLimiter
{
    private ?string $key = null;

    public function __construct(
        private readonly PDO $pdo,
        private readonly Config $config,
        private readonly Clock $clock,
    ) {}

    public function hit(string $bucket, string $clientKey): BucketDecision
    {
        $rule = $this->config->rateRules[$bucket] ?? null;
        if ($rule === null) {
            throw new InvalidArgumentException(sprintf('Unknown rate-limit bucket "%s"', $bucket));
        }
        $id = $bucket . ':' . Base64Url::encode(substr(hash_hmac('sha256', $clientKey, $this->serverKey(), true), 0, 16));
        $now = $this->clock->microtime();

        $this->pdo->exec('BEGIN IMMEDIATE');
        try {
            $select = $this->pdo->prepare('SELECT tokens, updated_at FROM rate_buckets WHERE bucket = ?');
            if ($select === false) {
                throw new RuntimeException('Could not prepare a statement');
            }
            $select->execute([$id]);
            $row = $select->fetch(PDO::FETCH_ASSOC);
            $select->closeCursor();
            $tokens = is_array($row) && is_numeric($row['tokens'] ?? null) ? (float) $row['tokens'] : null;
            $updatedAt = is_array($row) && is_numeric($row['updated_at'] ?? null) ? (float) $row['updated_at'] : null;

            $decision = TokenBucket::take($rule, $tokens, $updatedAt, $now);

            $upsert = $this->pdo->prepare(
                'INSERT INTO rate_buckets (bucket, tokens, updated_at) VALUES (?, ?, ?)'
                . ' ON CONFLICT (bucket) DO UPDATE SET tokens = excluded.tokens, updated_at = excluded.updated_at',
            );
            if ($upsert === false) {
                throw new RuntimeException('Could not prepare a statement');
            }
            $upsert->execute([$id, $decision->tokens, $now]);
            $this->pdo->exec('COMMIT');
        } catch (Throwable $e) {
            $this->pdo->exec('ROLLBACK');
            throw $e;
        }

        return $decision;
    }

    /**
     * Deletes buckets that have refilled completely (equivalent to absent).
     */
    public function prune(): int
    {
        $now = $this->clock->microtime();
        $deleted = 0;
        foreach ($this->config->rateRules as $name => $rule) {
            $statement = $this->pdo->prepare('DELETE FROM rate_buckets WHERE bucket LIKE ? AND updated_at <= ?');
            if ($statement === false) {
                throw new RuntimeException('Could not prepare a statement');
            }
            $statement->execute([$name . ':%', $now - $rule->capacity / $rule->refillPerSecond]);
            $deleted += $statement->rowCount();
        }

        return $deleted;
    }

    private function serverKey(): string
    {
        if ($this->key !== null) {
            return $this->key;
        }
        $insert = $this->pdo->prepare('INSERT OR IGNORE INTO server_keys (name, value) VALUES (?, ?)');
        $select = $this->pdo->prepare('SELECT value FROM server_keys WHERE name = ?');
        if ($insert === false || $select === false) {
            throw new RuntimeException('Could not prepare a statement');
        }
        $insert->bindValue(1, 'rate_limit_hmac');
        $insert->bindValue(2, random_bytes(32), PDO::PARAM_LOB);
        $insert->execute();
        $select->execute(['rate_limit_hmac']);
        $key = $select->fetchColumn();
        if (!is_string($key) || strlen($key) !== 32) {
            throw new RuntimeException('Rate-limit key is missing');
        }

        return $this->key = $key;
    }
}
