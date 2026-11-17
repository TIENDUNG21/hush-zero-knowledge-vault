<?php

declare(strict_types=1);

namespace Hush\Tests\Unit\Container;

use Hush\Container\Container;
use Hush\Container\ContainerException;
use PHPUnit\Framework\TestCase;

interface Greeter
{
    public function greet(): string;
}

final class EnglishGreeter implements Greeter
{
    public function greet(): string
    {
        return 'hello';
    }
}

final class Leaf {}

final class Branch
{
    public function __construct(public readonly Leaf $leaf, public readonly int $size = 3) {}
}

final class Tree
{
    public function __construct(public readonly Branch $branch, public readonly Leaf $leaf) {}
}

final class NeedsGreeter
{
    public function __construct(public readonly Greeter $greeter) {}
}

final class NeedsScalar
{
    public function __construct(public readonly string $name) {}
}

final class CycleA
{
    public function __construct(public readonly CycleB $b) {}
}

final class CycleB
{
    public function __construct(public readonly CycleA $a) {}
}

final class ContainerTest extends TestCase
{
    public function testAutowiresNestedDependenciesAndDefaults(): void
    {
        $tree = (new Container())->get(Tree::class);

        self::assertSame(3, $tree->branch->size);
        self::assertSame($tree->leaf, $tree->branch->leaf, 'services are shared');
    }

    public function testReturnsTheSameInstanceTwice(): void
    {
        $container = new Container();

        self::assertSame($container->get(Leaf::class), $container->get(Leaf::class));
    }

    public function testFactoryReceivesTheContainerAndBindsInterfaces(): void
    {
        $container = new Container();
        $container->set(Greeter::class, static fn(Container $c): Greeter => new EnglishGreeter());

        self::assertSame('hello', $container->get(NeedsGreeter::class)->greeter->greet());
    }

    public function testRegisteredInstanceWins(): void
    {
        $container = new Container();
        $leaf = new Leaf();
        $container->instance(Leaf::class, $leaf);

        self::assertSame($leaf, $container->get(Branch::class)->leaf);
    }

    public function testUnboundInterfaceIsReported(): void
    {
        $this->expectException(ContainerException::class);
        $this->expectExceptionMessage('non-instantiable type "' . Greeter::class . '"');
        (new Container())->get(NeedsGreeter::class);
    }

    public function testCircularDependencyNamesTheChain(): void
    {
        $this->expectException(ContainerException::class);
        $this->expectExceptionMessage(CycleA::class . ' -> ' . CycleB::class . ' -> ' . CycleA::class);
        (new Container())->get(CycleA::class);
    }

    public function testScalarWithoutDefaultNeedsAFactory(): void
    {
        $this->expectException(ContainerException::class);
        $this->expectExceptionMessage('$name of ' . NeedsScalar::class);
        (new Container())->get(NeedsScalar::class);
    }

    public function testFactoryReturningTheWrongTypeIsRejected(): void
    {
        $container = new Container();
        $container->set(Leaf::class, static fn(): object => new Branch(new Leaf()));

        $this->expectException(ContainerException::class);
        $container->get(Leaf::class);
    }

    public function testHasReportsKnownAndUnknownIds(): void
    {
        $container = new Container();
        $container->set('alias', static fn(): Leaf => new Leaf());

        self::assertTrue($container->has('alias'));
        self::assertTrue($container->has(Leaf::class));
        self::assertFalse($container->has('No\Such\Service'));
    }
}
