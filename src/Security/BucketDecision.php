<?php

declare(strict_types=1);

namespace Hush\Security;

final class BucketDecision
{
    public function __construct(
        public readonly bool $allowed,
        public readonly float $tokens,
        public readonly int $retryAfterSeconds,
        public readonly RateRule $rule,
    ) {}

    public function remaining(): int
    {
        return (int) floor($this->tokens);
    }
}
