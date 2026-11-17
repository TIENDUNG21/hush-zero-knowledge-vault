<?php

declare(strict_types=1);

namespace Hush\Tests\Support;

use Hush\Support\Clock;

final class FrozenClock implements Clock
{
    public function __construct(private float $now = 1_800_000_000.0) {}

    public function advance(float $seconds): void
    {
        $this->now += $seconds;
    }

    public function timestamp(): int
    {
        return (int) floor($this->now);
    }

    public function microtime(): float
    {
        return $this->now;
    }
}
