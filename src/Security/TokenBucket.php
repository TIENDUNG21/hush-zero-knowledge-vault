<?php

declare(strict_types=1);

namespace Hush\Security;

/**
 * Pure token-bucket arithmetic. A missing bucket is a full bucket, so the
 * store only has to remember clients that recently spent tokens.
 */
final class TokenBucket
{
    public static function take(RateRule $rule, ?float $tokens, ?float $updatedAt, float $now): BucketDecision
    {
        if ($tokens === null || $updatedAt === null) {
            $available = $rule->capacity;
        } else {
            $elapsed = max(0.0, $now - $updatedAt); // a clock step backwards never adds tokens
            $available = min($rule->capacity, $tokens + $elapsed * $rule->refillPerSecond);
        }

        if ($available >= 1.0) {
            return new BucketDecision(true, $available - 1.0, 0, $rule);
        }

        $retryAfter = (int) ceil((1.0 - $available) / $rule->refillPerSecond);

        return new BucketDecision(false, $available, max(1, $retryAfter), $rule);
    }
}
