<?php

declare(strict_types=1);

namespace Hush\Tests\Unit\Http;

use Hush\Http\HttpException;
use Hush\Http\Response;
use PHPUnit\Framework\TestCase;

final class ResponseTest extends TestCase
{
    public function testJsonResponseSetsTypeLengthAndKeepsUnicode(): void
    {
        $response = Response::json(['path' => '/a/b', 'text' => 'mật'], 201);

        self::assertSame(201, $response->status());
        self::assertSame('application/json; charset=utf-8', $response->header('content-type'));
        self::assertSame('{"path":"/a/b","text":"mật"}', $response->bodyString());
        self::assertSame((string) strlen($response->bodyString()), $response->header('Content-Length'));
    }

    public function testStreamedBodyIsConsumedLazily(): void
    {
        /** @var \ArrayObject<int, string> $produced */
        $produced = new \ArrayObject();
        $generator = (static function () use ($produced): \Generator {
            foreach (['ab', 'cd'] as $piece) {
                $produced->append($piece);
                yield $piece;
            }
        })();
        $response = Response::bytes($generator, 'application/octet-stream', 4);

        self::assertCount(0, $produced);
        self::assertSame('4', $response->header('Content-Length'));
        self::assertSame('abcd', $response->bodyString());
        self::assertCount(2, $produced);
    }

    public function testWithersAreImmutable(): void
    {
        $response = Response::html('<p>x</p>');
        $changed = $response->withStatus(404)->withHeader('X-Test', '1')->withoutBody();

        self::assertSame(200, $response->status());
        self::assertSame('<p>x</p>', $response->bodyString());
        self::assertSame(404, $changed->status());
        self::assertSame('1', $changed->header('X-Test'));
        self::assertSame([], $changed->body());
    }

    public function testHttpExceptionFactoriesCarryStatusCodeAndHeaders(): void
    {
        $e = HttpException::methodNotAllowed(['GET', 'HEAD']);
        self::assertSame(405, $e->status);
        self::assertSame('method_not_allowed', $e->errorCode);
        self::assertSame(['Allow' => 'GET, HEAD'], $e->headers);

        $limited = HttpException::tooManyRequests(7);
        self::assertSame(429, $limited->status);
        self::assertSame(['Retry-After' => '7'], $limited->headers);

        self::assertSame(413, HttpException::payloadTooLarge(10)->status);
        self::assertSame(411, HttpException::lengthRequired()->status);
    }
}
