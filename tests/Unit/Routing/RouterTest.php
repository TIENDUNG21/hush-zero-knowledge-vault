<?php

declare(strict_types=1);

namespace Hush\Tests\Unit\Routing;

use Hush\Http\HttpException;
use Hush\Routing\Router;
use LogicException;
use PHPUnit\Framework\TestCase;
use stdClass;

final class RouterTest extends TestCase
{
    private const string ID = 'AbCdEfGhIjKlMnOpQrStUv';

    private Router $router;

    protected function setUp(): void
    {
        $this->router = new Router();
        $this->router->get('/', [stdClass::class, 'home']);
        $this->router->get('/s/{id:[A-Za-z0-9_-]{22}}', [stdClass::class, 'view'], ['rate' => 'page']);
        $this->router->put('/api/secrets/{id:[A-Za-z0-9_-]{22}}/chunks/{index:\d{1,6}}', [stdClass::class, 'chunk']);
        $this->router->delete('/api/secrets/{id:[A-Za-z0-9_-]{22}}', [stdClass::class, 'delete']);
        $this->router->get('/assets/{path:[a-z0-9/._-]+}', [stdClass::class, 'asset']);
    }

    public function testMatchesStaticRoute(): void
    {
        $match = $this->router->match('GET', '/');

        self::assertSame([stdClass::class, 'home'], $match->route->handler);
        self::assertSame([], $match->params);
    }

    public function testExtractsConstrainedParametersWithNestedQuantifiers(): void
    {
        $match = $this->router->match('PUT', '/api/secrets/' . self::ID . '/chunks/12');

        self::assertSame(['id' => self::ID, 'index' => '12'], $match->params);
    }

    public function testExposesRouteAttributes(): void
    {
        $match = $this->router->match('GET', '/s/' . self::ID);

        self::assertSame('page', $match->attribute('rate'));
        self::assertNull($match->attribute('maxBody'));
    }

    public function testConstraintViolationIsNotFound(): void
    {
        $this->expectExceptionObject(HttpException::notFound());
        $this->router->match('GET', '/s/too-short');
    }

    public function testTrailingSlashIsNotFound(): void
    {
        try {
            $this->router->match('GET', '/s/' . self::ID . '/');
            self::fail('expected 404');
        } catch (HttpException $e) {
            self::assertSame(404, $e->status);
        }
    }

    public function testWrongMethodIsMethodNotAllowedWithAllowHeader(): void
    {
        try {
            $this->router->match('POST', '/s/' . self::ID);
            self::fail('expected 405');
        } catch (HttpException $e) {
            self::assertSame(405, $e->status);
            self::assertSame(['Allow' => 'GET, HEAD'], $e->headers);
        }
    }

    public function testHeadFallsBackToGet(): void
    {
        self::assertSame('home', $this->router->match('HEAD', '/')->route->handler[1]);
    }

    public function testInvalidUtf8PathIsNotFoundInsteadOfAWarning(): void
    {
        $this->expectException(HttpException::class);
        $this->router->match('GET', "/assets/\xC3\x28");
    }

    public function testDuplicateRouteIsRejected(): void
    {
        $this->expectException(LogicException::class);
        $this->router->get('/', [stdClass::class, 'again']);
    }

    public function testUnbalancedPatternIsRejected(): void
    {
        $this->expectException(LogicException::class);
        $this->router->get('/x/{id:[a-z]{2}', [stdClass::class, 'x']);
    }

    public function testDuplicateParameterNameIsRejected(): void
    {
        $this->expectException(LogicException::class);
        $this->router->get('/x/{id}/{id}', [stdClass::class, 'x']);
    }
}
