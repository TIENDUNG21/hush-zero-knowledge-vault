<?php

declare(strict_types=1);

namespace Hush\Vault;

final class CreatedSecret
{
    public function __construct(
        public readonly string $id,
        public readonly string $deletionToken,
        public readonly int $expiresAt,
        public readonly int $uploadDeadline,
        public readonly int $chunkCount,
    ) {}
}
