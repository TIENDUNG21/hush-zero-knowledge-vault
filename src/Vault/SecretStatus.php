<?php

declare(strict_types=1);

namespace Hush\Vault;

/**
 * What anyone holding the id may learn without consuming a view.
 */
final class SecretStatus
{
    public function __construct(
        public readonly string $id,
        public readonly bool $passwordProtected,
        public readonly int $expiresAt,
        public readonly int $viewsLeft,
        public readonly int $chunkCount,
        public readonly int $ciphertextBytes,
    ) {}
}
