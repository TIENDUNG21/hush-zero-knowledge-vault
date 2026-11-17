<?php

declare(strict_types=1);

namespace Hush\Security;

use Hush\Config\Config;
use Hush\Http\HttpException;
use Hush\Http\Request;
use Hush\Http\Response;
use Hush\Kernel\RoutingMiddleware;
use Hush\Middleware\Handler;
use Hush\Middleware\Middleware;

/**
 * Applies the route's "rate" bucket to the client's network.
 */
final class RateLimitMiddleware implements Middleware
{
    public function __construct(
        private readonly RateLimiter $limiter,
        private readonly Config $config,
    ) {}

    public function process(Request $request, Handler $next): Response
    {
        $bucket = RoutingMiddleware::matchOf($request)?->attribute('rate');
        if (!is_string($bucket)) {
            return $next->handle($request);
        }

        $client = ClientIp::bucketKey(ClientIp::resolve($request, $this->config->trustedProxies));
        $decision = $this->limiter->hit($bucket, $client);
        $limit = (string) (int) $decision->rule->capacity;

        if (!$decision->allowed) {
            throw new HttpException(429, 'rate_limited', 'Too many requests. Try again later.', [
                'Retry-After' => (string) $decision->retryAfterSeconds,
                'RateLimit-Limit' => $limit,
                'RateLimit-Remaining' => '0',
            ]);
        }

        return $next->handle($request)
            ->withHeader('RateLimit-Limit', $limit)
            ->withHeader('RateLimit-Remaining', (string) $decision->remaining());
    }
}
