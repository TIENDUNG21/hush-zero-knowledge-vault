<?php

declare(strict_types=1);

namespace Hush\Support;

/**
 * Operational log. Implementations must never receive request bodies,
 * tokens or keys; callers pass only error class, message and location.
 */
interface Logger
{
    public function error(string $message): void;
}
