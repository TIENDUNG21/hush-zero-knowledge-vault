<?php

declare(strict_types=1);

namespace Hush\Vault;

/**
 * What anyone holding the id may learn without consuming a view: limits,
 * sizes, the public header and the encrypted metadata record. Clients use
 * the last two to check the link key and password before spending a view.
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
        public readonly string $header,
        public readonly string $meta,
    ) {}
}
