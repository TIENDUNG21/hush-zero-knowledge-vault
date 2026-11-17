<?php

declare(strict_types=1);

namespace Hush\Kernel;

use Hush\Container\Container;
use Hush\Http\Request;
use Hush\Http\Response;
use Hush\Middleware\Handler;
use LogicException;

/**
 * Innermost handler: resolves the matched controller from the container and
 * calls the bound method with the request.
 */
final class DispatchHandler implements Handler
{
    public function __construct(private readonly Container $container) {}

    public function handle(Request $request): Response
    {
        $match = RoutingMiddleware::matchOf($request);
        if ($match === null) {
            throw new LogicException('RoutingMiddleware must run before dispatch');
        }

        [$class, $method] = $match->route->handler;
        $controller = $this->container->get($class);
        $callable = [$controller, $method];
        if (!is_callable($callable)) {
            throw new LogicException(sprintf('%s::%s is not callable', $class, $method));
        }

        $response = $callable($request);
        if (!$response instanceof Response) {
            throw new LogicException(sprintf('%s::%s did not return a Response', $class, $method));
        }

        return $response;
    }
}
