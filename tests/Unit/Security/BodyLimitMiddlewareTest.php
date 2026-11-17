<?php

declare(strict_types=1);

namespace Hush\Tests\Unit\Security;

use Hush\Http\HeaderBag;
use Hush\Http\HttpException;
use Hush\Http\Request;
use Hush\Http\Response;
use Hush\Middleware\CallableHandler;
use Hush\Routing\Route;
use Hush\Routing\RouteMatch;
use Hush\Security\BodyLimitMiddleware;
use PHPUnit\Framework\TestCase;
use stdClass;

final class BodyLimitMiddlewareTest extends TestCase
{
    public function testPassesABodyWithinTheLimit(): void
    {
        $response = $this->pass(10, ['Content-Length' => '5'], 'hello');

        self::assertSame('hello', $response->bodyString());
    }

    public function testRejectsDeclaredLengthOverTheLimitWithoutReading(): void
    {
        $read = false;
        $request = $this->request(10, ['Content-Length' => '11'], static function () use (&$read): string {
            $read = true;

            return str_repeat('x', 11);
        });

        $this->assertStatus(413, $request);
        self::assertFalse($read, 'the body must not be read');
    }

    public function testRejectsABodyLongerThanItsDeclaredLength(): void
    {
        $this->assertStatus(413, $this->request(10, ['Content-Length' => '4'], static fn(int $max): string => substr(str_repeat('x', 50), 0, $max)));
    }

    public function testRejectsAShortBody(): void
    {
        $this->assertStatus(400, $this->request(10, ['Content-Length' => '8'], static fn(int $max): string => 'abc'));
    }

    public function testRequiresContentLengthForBodies(): void
    {
        $this->assertStatus(411, $this->request(10, [], static fn(int $max): string => 'abc'));
    }

    public function testRejectsChunkedTransferEncoding(): void
    {
        $this->assertStatus(411, $this->request(10, ['Transfer-Encoding' => 'chunked', 'Content-Length' => '3'], static fn(int $max): string => 'abc'));
    }

    public function testRejectsNonNumericContentLength(): void
    {
        $this->assertStatus(400, $this->request(10, ['Content-Length' => '-1'], static fn(int $max): string => ''));
    }

    public function testRoutesWithoutALimitAcceptNoBody(): void
    {
        self::assertSame('', $this->pass(0, ['Content-Length' => '0'], '')->bodyString());
        self::assertSame('', $this->pass(0, [], '')->bodyString());
        $this->assertStatus(413, $this->request(0, ['Content-Length' => '1'], static fn(int $max): string => 'x'));
    }

    /**
     * @param array<string, string> $headers
     */
    private function pass(int $limit, array $headers, string $body): Response
    {
        return (new BodyLimitMiddleware())->process(
            $this->request($limit, $headers, static fn(int $max): string => substr($body, 0, $max)),
            new CallableHandler(static fn(Request $r): Response => Response::bytes($r->body(), 'text/plain')),
        );
    }

    /**
     * @param array<string, string> $headers
     * @param \Closure(int): string $body
     */
    private function request(int $limit, array $headers, \Closure $body): Request
    {
        $route = new Route('PUT', '/x', [stdClass::class, 'x'], $limit > 0 ? ['maxBody' => $limit] : []);

        return (new Request('PUT', '/x', [], new HeaderBag($headers), [], $body))
            ->withAttribute('route', new RouteMatch($route, []));
    }

    private function assertStatus(int $status, Request $request): void
    {
        try {
            (new BodyLimitMiddleware())->process($request, new CallableHandler(static fn(): Response => Response::noContent()));
            self::fail('expected HTTP ' . $status);
        } catch (HttpException $e) {
            self::assertSame($status, $e->status);
        }
    }
}
