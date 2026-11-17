<?php

declare(strict_types=1);

namespace Hush\Tests\Unit\Http;

use Hush\Http\HeaderBag;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class HeaderBagTest extends TestCase
{
    public function testNamesAreCaseInsensitiveButKeepTheirOriginalCase(): void
    {
        $bag = new HeaderBag(['Content-Type' => 'text/plain']);

        self::assertTrue($bag->has('content-type'));
        self::assertSame('text/plain', $bag->get('CONTENT-TYPE'));
        self::assertSame(['Content-Type' => ['text/plain']], $bag->all());
    }

    public function testRepeatedValuesAreCombined(): void
    {
        $bag = (new HeaderBag())->withAdded('Vary', 'Origin')->withAdded('vary', 'Accept');

        self::assertSame('Origin, Accept', $bag->get('Vary'));
        self::assertSame(['Origin', 'Accept'], $bag->values('VARY'));
    }

    public function testWithReplacesAndIsImmutable(): void
    {
        $original = new HeaderBag(['X-A' => '1']);
        $changed = $original->with('x-a', '2')->without('missing');

        self::assertSame('1', $original->get('X-A'));
        self::assertSame('2', $changed->get('X-A'));
        self::assertNull($changed->without('X-A')->get('X-A'));
    }

    public function testRejectsResponseSplittingValues(): void
    {
        $this->expectException(InvalidArgumentException::class);
        (new HeaderBag())->with('X-Evil', "a\r\nSet-Cookie: x=1");
    }

    public function testRejectsInvalidNames(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new HeaderBag(['Bad Name' => 'x']);
    }
}
