<?php

declare(strict_types=1);

namespace Hush\Kernel;

use Hush\Api\HealthController;
use Hush\Config\Config;
use Hush\Container\Container;
use Hush\Routing\Router;
use Hush\Support\ErrorLogLogger;
use Hush\Support\Logger;

/**
 * Composition root: the only place that knows which concrete classes make
 * up the application, the route table and the middleware order.
 */
final class Application
{
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
        ], $c->get(DispatchHandler::class));
    }

    public static function routes(Router $router): void
    {
        $router->get('/healthz', [HealthController::class, 'health'], ['rate' => 'page']);
    }

    private function registerServices(): void
    {
        $c = $this->container;
        $c->set(Logger::class, static fn(): Logger => new ErrorLogLogger());
        $c->set(ErrorRenderer::class, static fn(): ErrorRenderer => new JsonErrorRenderer());
        $c->set(Router::class, static function (): Router {
            $router = new Router();
            self::routes($router);

            return $router;
        });
    }
}
