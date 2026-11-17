<?php

declare(strict_types=1);

namespace Hush\Routing;

use Hush\Http\HttpException;
use LogicException;

/**
 * Linear-scan router. The application has a dozen routes, so clarity beats
 * a compiled trie; order of registration is the match order.
 */
final class Router
{
    /** @var list<Route> */
    private array $routes = [];

    /**
     * @param array{0: class-string, 1: string} $handler
     * @param array<string, string|int|bool> $attributes
     */
    public function add(string $method, string $pattern, array $handler, array $attributes = []): Route
    {
        $method = strtoupper($method);
        foreach ($this->routes as $existing) {
            if ($existing->method === $method && $existing->pattern === $pattern) {
                throw new LogicException(sprintf('Route %s %s is already registered', $method, $pattern));
            }
        }
        $route = new Route($method, $pattern, $handler, $attributes);
        $this->routes[] = $route;

        return $route;
    }

    /**
     * @param array{0: class-string, 1: string} $handler
     * @param array<string, string|int|bool> $attributes
     */
    public function get(string $pattern, array $handler, array $attributes = []): Route
    {
        return $this->add('GET', $pattern, $handler, $attributes);
    }

    /**
     * @param array{0: class-string, 1: string} $handler
     * @param array<string, string|int|bool> $attributes
     */
    public function post(string $pattern, array $handler, array $attributes = []): Route
    {
        return $this->add('POST', $pattern, $handler, $attributes);
    }

    /**
     * @param array{0: class-string, 1: string} $handler
     * @param array<string, string|int|bool> $attributes
     */
    public function put(string $pattern, array $handler, array $attributes = []): Route
    {
        return $this->add('PUT', $pattern, $handler, $attributes);
    }

    /**
     * @param array{0: class-string, 1: string} $handler
     * @param array<string, string|int|bool> $attributes
     */
    public function delete(string $pattern, array $handler, array $attributes = []): Route
    {
        return $this->add('DELETE', $pattern, $handler, $attributes);
    }

    /**
     * @throws HttpException 404 when no pattern matches, 405 (with Allow) when only the method is wrong
     */
    public function match(string $method, string $path): RouteMatch
    {
        $allowed = [];
        foreach ($this->routes as $route) {
            $params = $route->matchPath($path);
            if ($params === null) {
                continue;
            }
            if ($route->method === $method || ($method === 'HEAD' && $route->method === 'GET')) {
                return new RouteMatch($route, $params);
            }
            $allowed[] = $route->method;
            if ($route->method === 'GET') {
                $allowed[] = 'HEAD';
            }
        }

        if ($allowed === []) {
            throw HttpException::notFound();
        }

        $allowed = array_values(array_unique($allowed));
        sort($allowed);

        throw HttpException::methodNotAllowed($allowed);
    }

    /**
     * @return list<Route>
     */
    public function routes(): array
    {
        return $this->routes;
    }
}
