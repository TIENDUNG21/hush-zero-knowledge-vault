<?php

declare(strict_types=1);

namespace Hush\Routing;

final class RouteMatch
{
    /**
     * @param array<string, string> $params
     */
    public function __construct(
        public readonly Route $route,
        public readonly array $params,
    ) {}

    public function attribute(string $name): string|int|bool|null
    {
        return $this->route->attributes[$name] ?? null;
    }
}
