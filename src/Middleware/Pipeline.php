<?php

declare(strict_types=1);

namespace Hush\Middleware;

use Hush\Http\Request;
use Hush\Http\Response;

/**
 * Runs middleware in list order around a final handler.
 */
final class Pipeline implements Handler
{
    /**
     * @param list<Middleware> $middleware
     */
    public function __construct(
        private readonly array $middleware,
        private readonly Handler $final,
    ) {}

    public function handle(Request $request): Response
    {
        return $this->at(0)->handle($request);
    }

    private function at(int $index): Handler
    {
        $layer = $this->middleware[$index] ?? null;
        if ($layer === null) {
            return $this->final;
        }

        return new CallableHandler(fn(Request $request): Response => $layer->process($request, $this->at($index + 1)));
    }
}
