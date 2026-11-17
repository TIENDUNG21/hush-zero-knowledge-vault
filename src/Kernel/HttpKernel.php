<?php

declare(strict_types=1);

namespace Hush\Kernel;

use Hush\Http\Request;
use Hush\Http\Response;
use Hush\Middleware\Handler;
use Hush\Middleware\Middleware;
use Hush\Middleware\Pipeline;

/**
 * Request in, response out. Owns the middleware order.
 */
final class HttpKernel implements Handler
{
    private readonly Pipeline $pipeline;

    /**
     * @param list<Middleware> $middleware outermost first
     */
    public function __construct(array $middleware, Handler $dispatcher)
    {
        $this->pipeline = new Pipeline($middleware, $dispatcher);
    }

    public function handle(Request $request): Response
    {
        $response = $this->pipeline->handle($request);

        return $request->method() === 'HEAD' ? $response->withoutBody() : $response;
    }
}
