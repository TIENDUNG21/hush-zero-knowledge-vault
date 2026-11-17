<?php

declare(strict_types=1);

namespace Hush\Kernel;

use Hush\Api\HealthController;
use Hush\Api\SecretsController;
use Hush\Config\Config;
use Hush\Container\Container;
use Hush\Crypto\Format;
use Hush\Routing\Router;
use Hush\Security\BodyLimitMiddleware;
use Hush\Storage\Database;
use Hush\Support\Clock;
use Hush\Support\ErrorLogLogger;
use Hush\Support\Logger;
use Hush\Support\SystemClock;
use Hush\Vault\SecretId;
use PDO;

/**
 * Composition root: the only place that knows which concrete classes make
 * up the application, the route table and the middleware order.
 */
final class Application
{
    public const int CREATE_BODY_LIMIT = 16_384;
    public const int CHUNK_BODY_LIMIT = Format::MAX_CHUNK_SIZE + Format::RECORD_OVERHEAD;

    private readonly Container $container;

    /**
     * @param array<string, object> $overrides services to replace (tests, embedding)
     */
    public function __construct(Config $config, array $overrides = [])
    {
        $this->container = new Container();
        $this->container->instance(Config::class, $config);
        $this->container->instance(Container::class, $this->container);
        $this->registerServices();
        foreach ($overrides as $id => $service) {
            $this->container->instance($id, $service);
        }
    }

    public function container(): Container
    {
        return $this->container;
    }

    public function kernel(): HttpKernel
    {
        $c = $this->container;

        return new HttpKernel([
            $c->get(ErrorMiddleware::class),
            $c->get(RoutingMiddleware::class),
            $c->get(BodyLimitMiddleware::class),
        ], $c->get(DispatchHandler::class));
    }

    public static function routes(Router $router): void
    {
        $id = '{id:' . SecretId::PATTERN . '}';

        $router->get('/healthz', [HealthController::class, 'health'], ['rate' => 'page']);

        $router->post('/api/secrets', [SecretsController::class, 'create'], ['rate' => 'create', 'maxBody' => self::CREATE_BODY_LIMIT]);
        $router->get('/api/secrets/' . $id, [SecretsController::class, 'status'], ['rate' => 'read']);
        $router->post('/api/secrets/' . $id . '/open', [SecretsController::class, 'open'], ['rate' => 'read']);
        $router->put('/api/secrets/' . $id . '/chunks/{index:\d{1,7}}', [SecretsController::class, 'putChunk'], ['rate' => 'chunk', 'maxBody' => self::CHUNK_BODY_LIMIT]);
        $router->post('/api/secrets/' . $id . '/seal', [SecretsController::class, 'seal'], ['rate' => 'chunk']);
        $router->delete('/api/secrets/' . $id, [SecretsController::class, 'delete'], ['rate' => 'delete']);
    }

    private function registerServices(): void
    {
        $c = $this->container;
        $c->set(Logger::class, static fn(): Logger => new ErrorLogLogger());
        $c->set(Clock::class, static fn(): Clock => new SystemClock());
        $c->set(ErrorRenderer::class, static fn(): ErrorRenderer => new JsonErrorRenderer());
        $c->set(PDO::class, static fn(Container $c): PDO => Database::connect($c->get(Config::class)->databasePath));
        $c->set(Router::class, static function (): Router {
            $router = new Router();
            self::routes($router);

            return $router;
        });
    }
}
