<?php

declare(strict_types=1);

namespace Hush\Support;

/**
 * Writes to PHP's error_log (stderr under php -S and in the container).
 */
final class ErrorLogLogger implements Logger
{
    public function error(string $message): void
    {
        error_log('[hush] ' . $message);
    }
}
