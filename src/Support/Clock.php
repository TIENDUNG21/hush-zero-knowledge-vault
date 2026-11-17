<?php

declare(strict_types=1);

namespace Hush\Support;

interface Clock
{
    /** Unix time in whole seconds. */
    public function timestamp(): int;

    /** Unix time with sub-second precision (rate limiting). */
    public function microtime(): float;
}
