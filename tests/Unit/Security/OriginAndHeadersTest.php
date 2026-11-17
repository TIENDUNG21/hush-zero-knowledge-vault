<?php

declare(strict_types=1);

namespace Hush\Tests\Unit\Security;

use Hush\Config\Config;
use Hush\Http\HeaderBag;
use Hush\Http\HttpException;
use Hush\Http\Request;
use Hush\Http\Response;
use Hush\Middleware\CallableHandler;
use Hush\Security\OriginCheckMiddleware;
use Hush\Security\SecurityHeadersMiddleware;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class OriginAndHeadersTest extends TestCase
{
    /**
     * @return iterable<string, array{string, array<string, string>, bool}>
     */
    public static function originCases(): iterable
    {
        yield 'GET from anywhere' => ['GET', ['Origin' => 'https://evil.example', 'Sec-Fetch-Site' => 'cross-site'], true];
        yield 'same origin POST' => ['POST', ['Origin' => 'http://hush.test', 'Sec-Fetch-Site' => 'same-origin'], true];
        yield 'origin case-insensitive' => ['POST', ['Origin' => 'HTTP://HUSH.TEST'], true];
        yield 'CLI without headers' => ['DELETE', [], true];
        yield 'user typed the URL' => ['POST', ['Sec-Fetch-Site' => 'none'], true];
        yield 'cross-origin POST' => ['POST', ['Origin' => 'https://evil.example'], false];
        yield 'opaque null origin' => ['PUT', ['Origin' => 'null'], false];
        yield 'cross-site fetch metadata' => ['DELETE', ['Sec-Fetch-Site' => 'cross-site'], false];
        yield 'same-site subdomain' => ['POST', ['Sec-Fetch-Site' => 'same-site'], false];
        yield 'scheme mismatch' => ['POST', ['Origin' => 'https://hush.test'], false];
    }

    /**
     * @param array<string, string> $headers
     */
    #[DataProvider('originCases')]
    public function testOriginPolicy(string $method, array $headers, bool $allowed): void
    {
        $request = new Request($method, '/api/secrets', [], new HeaderBag(['Host' => 'hush.test'] + $headers));
        $middleware = new OriginCheckMiddleware(new Config('/srv', ':memory:'));

        try {
            $response = $middleware->process($request, new CallableHandler(static fn(): Response => Response::noContent()));
            self::assertTrue($allowed, 'request should have been refused');
            self::assertSame(204, $response->status());
        } catch (HttpException $e) {
            self::assertFalse($allowed, 'request should have been allowed');
            self::assertSame(403, $e->status);
            self::assertSame('cross_origin', $e->errorCode);
        }
    }

    public function testConfiguredPublicOriginWinsOverHostHeader(): void
    {
        $middleware = new OriginCheckMiddleware(new Config('/srv', ':memory:', publicOrigin: 'https://hush.example'));
        $request = new Request('POST', '/api/secrets', [], new HeaderBag(['Host' => 'attacker.example', 'Origin' => 'https://hush.example']));

        self::assertSame(204, $middleware->process($request, new CallableHandler(static fn(): Response => Response::noContent()))->status());
    }

    public function testSecurityHeadersOnEveryResponse(): void
    {
        $response = (new SecurityHeadersMiddleware())->process(
            new Request('GET', '/'),
            new CallableHandler(static fn(): Response => Response::json(['error' => 'x'], 404)),
        );

        $csp = $response->header('Content-Security-Policy') ?? '';
        self::assertStringContainsString("script-src 'self'", $csp);
        self::assertStringContainsString("form-action 'none'", $csp);
        self::assertStringContainsString("frame-ancestors 'none'", $csp);
        self::assertStringContainsString("require-trusted-types-for 'script'", $csp);
        self::assertStringNotContainsString('unsafe-inline', $csp);
        self::assertStringNotContainsString('unsafe-eval', $csp);
        self::assertSame('no-referrer', $response->header('Referrer-Policy'));
        self::assertSame('same-origin', $response->header('Cross-Origin-Opener-Policy'));
        self::assertSame('nosniff', $response->header('X-Content-Type-Options'));
        self::assertStringStartsWith('max-age=63072000', $response->header('Strict-Transport-Security') ?? '');
        self::assertStringContainsString('camera=()', $response->header('Permissions-Policy') ?? '');
        self::assertSame('no-store', $response->header('Cache-Control'));
    }

    public function testExistingCacheControlIsKept(): void
    {
        $response = (new SecurityHeadersMiddleware())->process(
            new Request('GET', '/assets/x.js'),
            new CallableHandler(static fn(): Response => Response::bytes('x', 'text/javascript')->withHeader('Cache-Control', 'no-cache')),
        );

        self::assertSame('no-cache', $response->header('Cache-Control'));
    }
}
