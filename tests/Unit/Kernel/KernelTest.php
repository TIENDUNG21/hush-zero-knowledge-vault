<?php

declare(strict_types=1);

namespace Hush\Tests\Unit\Kernel;

use Hush\Config\Config;
use Hush\Http\HttpException;
use Hush\Http\Request;
use Hush\Http\Response;
use Hush\Kernel\Application;
use Hush\Kernel\ErrorMiddleware;
use Hush\Kernel\JsonErrorRenderer;
use Hush\Middleware\CallableHandler;
use Hush\Support\Logger;
use Hush\Tests\Support\MemoryLogger;
use Hush\Tests\Support\VaultFixture;
use PDO;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class KernelTest extends TestCase
{
    public function testHealthEndpointThroughTheWholeKernel(): void
    {
        $kernel = $this->application()->kernel();

        $response = $kernel->handle(new Request('GET', '/healthz'));

        self::assertSame(200, $response->status());
        self::assertSame('{"status":"ok"}', $response->bodyString());
    }

    public function testHeadRequestHasHeadersButNoBody(): void
    {
        $response = $this->application()->kernel()->handle(new Request('HEAD', '/healthz'));

        self::assertSame(200, $response->status());
        self::assertSame('15', $response->header('Content-Length'));
        self::assertSame('', $response->bodyString());
    }

    public function testUnknownPathIsJsonNotFound(): void
    {
        $response = $this->application()->kernel()->handle(new Request('GET', '/nope'));

        self::assertSame(404, $response->status());
        self::assertSame('{"error":{"code":"not_found","message":"Nothing here."}}', $response->bodyString());
    }

    public function testWrongMethodCarriesAllowHeader(): void
    {
        $response = $this->application()->kernel()->handle(new Request('DELETE', '/healthz'));

        self::assertSame(405, $response->status());
        self::assertSame('GET, HEAD', $response->header('Allow'));
    }

    public function testUnexpectedErrorsAreLoggedButNotLeaked(): void
    {
        $logger = new MemoryLogger();
        $middleware = new ErrorMiddleware(new JsonErrorRenderer(), $logger);

        $response = $middleware->process(
            new Request('GET', '/'),
            new CallableHandler(static fn(): Response => throw new RuntimeException('SQLSTATE secret detail')),
        );

        self::assertSame(500, $response->status());
        self::assertStringNotContainsString('SQLSTATE', $response->bodyString());
        self::assertStringContainsString('internal_error', $response->bodyString());
        self::assertCount(1, $logger->errors);
        self::assertStringContainsString('RuntimeException: SQLSTATE secret detail', $logger->errors[0]);
    }

    public function testHttpExceptionHeadersAreCopiedToTheResponse(): void
    {
        $middleware = new ErrorMiddleware(new JsonErrorRenderer(), new MemoryLogger());

        $response = $middleware->process(
            new Request('GET', '/'),
            new CallableHandler(static fn(): Response => throw HttpException::tooManyRequests(9)),
        );

        self::assertSame(429, $response->status());
        self::assertSame('9', $response->header('Retry-After'));
    }

    private function application(): Application
    {
        return new Application(
            new Config(sys_get_temp_dir(), ':memory:'),
            [Logger::class => new MemoryLogger(), PDO::class => (new VaultFixture())->pdo],
        );
    }
}
