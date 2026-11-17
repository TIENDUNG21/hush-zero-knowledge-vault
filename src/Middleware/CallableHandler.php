<?php

declare(strict_types=1);

namespace Hush\Middleware;

use Closure;
use Hush\Http\Request;
use Hush\Http\Response;

final class CallableHandler implements Handler
{
    /**
     * @param Closure(Request): Response $callback
     */
    public function __construct(private readonly Closure $callback) {}

    public function handle(Request $request): Response
    {
        return ($this->callback)($request);
    }
}
