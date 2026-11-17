<?php

declare(strict_types=1);

namespace Hush\Vault;

/**
 * A claimed view: the envelope as a lazily streamed package.
 */
final class OpenedSecret
{
    /**
     * @param iterable<string> $package pieces of the serialized package
     */
    public function __construct(
        public readonly int $viewsLeft,
        public readonly int $packageLength,
        public readonly iterable $package,
    ) {}
}
