<?php

declare(strict_types=1);

namespace Hush\Vault;

use UnexpectedValueException;

/**
 * One row of the secrets table.
 */
final class SecretRecord
{
    public const string UPLOADING = 'uploading';
    public const string SEALED = 'sealed';
    public const string BURNED = 'burned';

    public function __construct(
        public readonly string $id,
        public readonly string $header,
        public readonly string $meta,
        public readonly int $chunkCount,
        public readonly int $chunkSize,
        public readonly string $ownerTokenHash,
        public readonly string $state,
        public readonly int $maxViews,
        public readonly int $views,
        public readonly int $expiresAt,
        public readonly int $uploadDeadline,
        public readonly ?int $burnedAt,
    ) {}

    /**
     * @param array<array-key, mixed> $row
     */
    public static function fromRow(array $row): self
    {
        $burnedAt = $row['burned_at'] ?? null;

        return new self(
            self::string($row, 'id'),
            self::string($row, 'header'),
            self::string($row, 'meta'),
            self::int($row, 'chunk_count'),
            self::int($row, 'chunk_size'),
            self::string($row, 'owner_token'),
            self::string($row, 'state'),
            self::int($row, 'max_views'),
            self::int($row, 'views'),
            self::int($row, 'expires_at'),
            self::int($row, 'upload_deadline'),
            is_int($burnedAt) ? $burnedAt : null,
        );
    }

    public function isReadableAt(int $now): bool
    {
        return $this->state === self::SEALED && $this->expiresAt > $now && $this->views < $this->maxViews;
    }

    /**
     * @param array<array-key, mixed> $row
     */
    private static function string(array $row, string $column): string
    {
        $value = $row[$column] ?? null;
        if (!is_string($value)) {
            throw new UnexpectedValueException(sprintf('Column %s is not a string', $column));
        }

        return $value;
    }

    /**
     * @param array<array-key, mixed> $row
     */
    private static function int(array $row, string $column): int
    {
        $value = $row[$column] ?? null;
        if (!is_int($value)) {
            throw new UnexpectedValueException(sprintf('Column %s is not an integer', $column));
        }

        return $value;
    }
}
