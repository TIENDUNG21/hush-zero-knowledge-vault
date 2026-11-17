<?php

declare(strict_types=1);

namespace Hush\Tests\Unit\Support;

use Hush\Support\Base64Url;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class Base64UrlTest extends TestCase
{
    public function testEmptyStringEncodesToEmpty(): void
    {
        self::assertSame('', Base64Url::encode(''));
        self::assertSame('', Base64Url::decode(''));
    }

    public function testKnownVector(): void
    {
        self::assertSame('-_8', Base64Url::encode("\xfb\xff"));
        self::assertSame("\xfb\xff", Base64Url::decode('-_8'));
    }

    public function testRoundTripsEveryLengthUpTo64Bytes(): void
    {
        for ($length = 0; $length <= 64; $length++) {
            $bytes = $length === 0 ? '' : random_bytes($length);
            $encoded = Base64Url::encode($bytes);
            self::assertMatchesRegularExpression('/\A[A-Za-z0-9_-]*\z/', $encoded);
            self::assertSame($bytes, Base64Url::decode($encoded));
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function invalidInputs(): iterable
    {
        yield 'standard alphabet plus' => ['ab+c'];
        yield 'standard alphabet slash' => ['ab/c'];
        yield 'padding' => ['YQ=='];
        yield 'whitespace' => ['YW Jj'];
        yield 'impossible length' => ['abcde'];
        yield 'non canonical trailing bits' => ['YR'];
    }

    #[DataProvider('invalidInputs')]
    public function testRejectsInvalidInput(string $input): void
    {
        $this->expectException(InvalidArgumentException::class);
        Base64Url::decode($input);
    }
}
