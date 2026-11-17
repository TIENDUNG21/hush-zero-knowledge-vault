<?php

declare(strict_types=1);

namespace Hush\Support;

final class SystemClock implements Clock
{
    public function timestamp(): int
    {
        return time();
    }

    public function microtime(): float
    {
        return microtime(true);
    }
}
