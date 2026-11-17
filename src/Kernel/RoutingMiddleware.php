<?php

declare(strict_types=1);

namespace Hush\Kernel;

use Hush\Http\Request;
use Hush\Http\Response;
use Hush\Middleware\Handler;
use Hush\Middleware\Middleware;
use Hush\Routing\RouteMatch;
use Hush\Routing\Router;

/**
 * Resolves the route early so later middleware can read per-route policy
 * (rate-limit bucket, body limit) from the "route" attribute.
 */
final class RoutingMiddleware implements Middleware
{
    public function __construct(private readonly Router $router) {}

    public function process(Request $request, Handler $next): Response
    {
        $match = $this->router->match($request->method(), $request->path());

        return $next->handle(
            $request->withAttribute('route', $match)->withAttribute('route.params', $match->params),
        );
    }

    public static function matchOf(Request $request): ?RouteMatch
    {
        $match = $request->attribute('route');

        return $match instanceof RouteMatch ? $match : null;
    }
}
