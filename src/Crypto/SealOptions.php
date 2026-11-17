<?php

declare(strict_types=1);

namespace Hush\Crypto;

use Closure;

/**
 * Parameters for {@see SecretSealer}. The key, salt and nonce overrides exist
 * only to produce reproducible test vectors; production code leaves them null
 * so everything comes from random_bytes(). A null chunk size means
 * {@see Format::chooseChunkSize()}.
 */
final class SealOptions
{
    /**
     * @param (Closure(): string)|null $nonces returns the next 12-byte nonce
     */
    public function __construct(
        public readonly ?string $password = null,
        public readonly int $iterations = Format::DEFAULT_ITERATIONS,
        public readonly ?int $chunkSize = null,
        public readonly ?string $fragmentKey = null,
        public readonly ?string $salt = null,
        public readonly ?Closure $nonces = null,
    ) {}

    public function hasPassword(): bool
    {
        return $this->password !== null && $this->password !== '';
    }
}
