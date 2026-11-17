<?php

declare(strict_types=1);

namespace Hush\Security;

use InvalidArgumentException;

/**
 * Token-bucket parameters: a burst of $capacity requests, refilled at
 * $refillPerSecond tokens per second.
 */
final class RateRule
{
    public function __construct(
        public readonly float $capacity,
        public readonly float $refillPerSecond,
    ) {
        if ($capacity < 1 || $refillPerSecond <= 0) {
            throw new InvalidArgumentException('A rate rule needs capacity >= 1 and a positive refill rate');
        }
    }

    /**
     * Parses "capacity,refillPerSecond", e.g. "30,0.05".
     */
    public static function parse(string $spec): self
    {
        if (preg_match('/\A\s*(\d+(?:\.\d+)?)\s*,\s*(\d+(?:\.\d+)?)\s*\z/', $spec, $m) !== 1) {
            throw new InvalidArgumentException(sprintf('Rate rule "%s" must look like "30,0.05"', $spec));
        }

        return new self((float) $m[1], (float) $m[2]);
    }
}
