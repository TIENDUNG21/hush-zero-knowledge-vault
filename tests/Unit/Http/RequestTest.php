<?php

declare(strict_types=1);

namespace Hush\Tests\Unit\Http;

use Hush\Http\Request;
use Hush\Http\RequestFactory;
use LogicException;
use PHPUnit\Framework\TestCase;

final class RequestTest extends TestCase
{
    public function testFactoryParsesMethodPathQueryAndHeadersFromServerArray(): void
    {
        $request = RequestFactory::fromGlobals([
            'REQUEST_METHOD' => 'post',
            'REQUEST_URI' => '/api/secrets%2Fx?debug=1',
            'QUERY_STRING' => 'debug=1&list[]=a',
            'HTTP_X_REQUESTED_WITH' => 'test',
            'CONTENT_TYPE' => 'application/json',
            'CONTENT_LENGTH' => '12',
            'REMOTE_ADDR' => '203.0.113.9',
        ], static fn(int $limit): string => '');

        self::assertSame('POST', $request->method());
        self::assertSame('/api/secrets/x', $request->path());
        self::assertSame('1', $request->query('debug'));
        self::assertNull($request->query('list'), 'array query values are dropped');
        self::assertSame('test', $request->header('x-requested-with'));
        self::assertSame('application/json', $request->header('Content-Type'));
        self::assertSame('12', $request->header('Content-Length'));
        self::assertSame('203.0.113.9', $request->remoteAddress());
    }

    public function testFactoryPrefersRawHeadersAndDropsUnsafeOnes(): void
    {
        $request = RequestFactory::fromGlobals(
            ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/'],
            static fn(int $limit): string => '',
            ['Authorization' => 'Bearer abc', 'X-Bad' => "a\nb", 'Bad Name' => 'x'],
        );

        self::assertSame('Bearer abc', $request->header('authorization'));
        self::assertFalse($request->headers()->has('X-Bad'));
        self::assertSame(['Authorization' => ['Bearer abc']], $request->headers()->all());
    }

    public function testInvalidMethodBecomesUnroutable(): void
    {
        $request = RequestFactory::fromGlobals(['REQUEST_METHOD' => "GET\r\n"], static fn(int $limit): string => '');

        self::assertSame('INVALID', $request->method());
        self::assertSame('/', $request->path());
    }

    public function testAttributesAreImmutable(): void
    {
        $request = new Request('GET', '/');
        $with = $request->withAttribute('route.params', ['id' => 'abc']);

        self::assertNull($request->attribute('route.params'));
        self::assertSame('abc', $with->routeParam('id'));
    }

    public function testBodyMustBeReadWithALimitFirst(): void
    {
        $reads = [];
        $request = new Request('PUT', '/', body: static function (int $limit) use (&$reads): string {
            $reads[] = $limit;

            return str_repeat('x', min($limit, 100));
        });

        self::assertTrue($request->hasBodyReader());
        self::assertSame(11, strlen($request->readBody(10)), 'reads one byte past the limit');
        self::assertSame([11], $reads);

        $this->expectException(LogicException::class);
        $request->body();
    }

    public function testSecureDetection(): void
    {
        self::assertTrue((new Request('GET', '/', server: ['HTTPS' => 'on']))->isSecure());
        self::assertFalse((new Request('GET', '/', server: ['HTTPS' => 'off']))->isSecure());
        self::assertFalse((new Request('GET', '/'))->isSecure());
    }
}
