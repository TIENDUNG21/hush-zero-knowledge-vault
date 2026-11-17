<?php

declare(strict_types=1);

namespace Hush\Tests\Unit\Kernel;

use ArrayObject;
use Hush\Http\Request;
use Hush\Http\Response;
use Hush\Middleware\CallableHandler;
use Hush\Middleware\Handler;
use Hush\Middleware\Middleware;
use Hush\Middleware\Pipeline;
use PHPUnit\Framework\TestCase;

final class TraceMiddleware implements Middleware
{
    /**
     * @param ArrayObject<int, string> $trace
     */
    public function __construct(
        private readonly string $name,
        private readonly ArrayObject $trace,
        private readonly bool $shortCircuit = false,
    ) {}

    public function process(Request $request, Handler $next): Response
    {
        $this->trace->append('in:' . $this->name);
        if ($this->shortCircuit) {
            return Response::json(['stopped' => $this->name], 418);
        }
        $response = $next->handle($request->withAttribute('seen.' . $this->name, true));
        $this->trace->append('out:' . $this->name);

        return $response->withHeader('X-' . $this->name, '1');
    }
}

final class PipelineTest extends TestCase
{
    public function testRunsMiddlewareAsAnOnionAroundTheHandler(): void
    {
        /** @var ArrayObject<int, string> $trace */
        $trace = new ArrayObject();
        $final = new CallableHandler(static function (Request $request) use ($trace): Response {
            $trace->append('handler');

            return Response::json(['a' => $request->attribute('seen.A'), 'b' => $request->attribute('seen.B')]);
        });

        $response = (new Pipeline([new TraceMiddleware('A', $trace), new TraceMiddleware('B', $trace)], $final))
            ->handle(new Request('GET', '/'));

        self::assertSame(['in:A', 'in:B', 'handler', 'out:B', 'out:A'], $trace->getArrayCopy());
        self::assertSame('{"a":true,"b":true}', $response->bodyString());
        self::assertSame('1', $response->header('X-A'));
        self::assertSame('1', $response->header('X-B'));
    }

    public function testMiddlewareCanShortCircuit(): void
    {
        /** @var ArrayObject<int, string> $trace */
        $trace = new ArrayObject();
        $final = new CallableHandler(static function () use ($trace): Response {
            $trace->append('handler');

            return Response::noContent();
        });

        $response = (new Pipeline([new TraceMiddleware('A', $trace), new TraceMiddleware('B', $trace, true)], $final))
            ->handle(new Request('GET', '/'));

        self::assertSame(418, $response->status());
        self::assertSame(['in:A', 'in:B', 'out:A'], $trace->getArrayCopy());
    }

    public function testEmptyPipelineCallsTheHandler(): void
    {
        $response = (new Pipeline([], new CallableHandler(static fn(): Response => Response::noContent())))
            ->handle(new Request('GET', '/'));

        self::assertSame(204, $response->status());
    }
}
