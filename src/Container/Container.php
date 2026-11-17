<?php

declare(strict_types=1);

namespace Hush\Container;

use Closure;
use ReflectionClass;
use ReflectionNamedType;

/**
 * Small dependency injection container.
 *
 * Services are shared (one instance per container). A service is either
 * registered with a factory closure or built by constructor autowiring:
 * class-typed parameters are resolved recursively, everything else must have
 * a default value. Cycles are reported with the full chain.
 */
final class Container
{
    /** @var array<string, Closure(self): object> */
    private array $factories = [];

    /** @var array<string, object> */
    private array $instances = [];

    /** @var array<string, true> */
    private array $resolving = [];

    /**
     * @param Closure(self): object $factory
     */
    public function set(string $id, Closure $factory): void
    {
        unset($this->instances[$id]);
        $this->factories[$id] = $factory;
    }

    public function instance(string $id, object $service): void
    {
        $this->instances[$id] = $service;
    }

    public function has(string $id): bool
    {
        return isset($this->instances[$id]) || isset($this->factories[$id]) || class_exists($id);
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $id
     *
     * @return T
     */
    public function get(string $id): object
    {
        if (isset($this->instances[$id])) {
            return $this->checked($id, $this->instances[$id]);
        }

        if (isset($this->resolving[$id])) {
            $chain = implode(' -> ', [...array_keys($this->resolving), $id]);
            throw new ContainerException(sprintf('Circular dependency: %s', $chain));
        }

        $this->resolving[$id] = true;
        try {
            $service = isset($this->factories[$id]) ? ($this->factories[$id])($this) : $this->autowire($id);
        } finally {
            unset($this->resolving[$id]);
        }

        $this->instances[$id] = $this->checked($id, $service);

        return $this->instances[$id];
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $id
     *
     * @return T
     */
    private function checked(string $id, object $service): object
    {
        if (!$service instanceof $id) {
            throw new ContainerException(sprintf('Service "%s" resolved to %s', $id, $service::class));
        }

        return $service;
    }

    /**
     * @param class-string $class
     */
    private function autowire(string $class): object
    {
        if (!class_exists($class) && !interface_exists($class)) {
            throw new ContainerException(sprintf('Unknown service "%s"', $class));
        }
        $reflection = new ReflectionClass($class);

        if (!$reflection->isInstantiable()) {
            throw new ContainerException(sprintf('No binding for non-instantiable type "%s"', $class));
        }

        $constructor = $reflection->getConstructor();
        if ($constructor === null) {
            return $reflection->newInstance();
        }

        $arguments = [];
        foreach ($constructor->getParameters() as $parameter) {
            $type = $parameter->getType();
            if ($type instanceof ReflectionNamedType && !$type->isBuiltin()) {
                /** @var class-string $dependency */
                $dependency = $type->getName();
                if ($parameter->isDefaultValueAvailable() && !$this->has($dependency)) {
                    $arguments[] = $parameter->getDefaultValue();
                    continue;
                }
                $arguments[] = $this->get($dependency);
                continue;
            }
            if ($parameter->isDefaultValueAvailable()) {
                $arguments[] = $parameter->getDefaultValue();
                continue;
            }
            throw new ContainerException(sprintf(
                'Cannot autowire parameter $%s of %s; register a factory',
                $parameter->getName(),
                $class,
            ));
        }

        return $reflection->newInstanceArgs($arguments);
    }
}
