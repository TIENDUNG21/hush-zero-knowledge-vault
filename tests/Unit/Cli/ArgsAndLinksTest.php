<?php

declare(strict_types=1);

namespace Hush\Tests\Unit\Cli;

use Hush\Cli\Argv;
use Hush\Cli\Inputs;
use Hush\Cli\ShareLink;
use Hush\Cli\UsageException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ArgsAndLinksTest extends TestCase
{
    private const string ID = 'AbCdEfGhIjKlMnOpQrStUv';

    public function testParsesOptionsFlagsAndPositionals(): void
    {
        $argv = Argv::parse(['text', '--views', '3', '--expires=1h', '--json', '--', '--not-an-option'], [
            'views' => true, 'expires' => true, 'json' => false,
        ]);

        self::assertSame(['text', '--not-an-option'], $argv->positionals);
        self::assertSame('3', $argv->string('views'));
        self::assertSame('1h', $argv->string('expires'));
        self::assertTrue($argv->flag('json'));
        self::assertFalse($argv->flag('views'));
        self::assertNull($argv->string('missing'));
    }

    /**
     * @return iterable<string, array{list<string>, string}>
     */
    public static function badArguments(): iterable
    {
        yield 'unknown option' => [['--pasword', 'x'], 'Unknown option --pasword'];
        yield 'missing value' => [['--views'], 'needs a value'];
        yield 'value on a flag' => [['--json=yes'], 'does not take a value'];
    }

    /**
     * @param list<string> $args
     */
    #[DataProvider('badArguments')]
    public function testRejectsBadArguments(array $args, string $message): void
    {
        $this->expectException(UsageException::class);
        $this->expectExceptionMessage($message);
        Argv::parse($args, ['views' => true, 'json' => false]);
    }

    public function testDurations(): void
    {
        self::assertSame(1800, Inputs::duration('30m'));
        self::assertSame(3600, Inputs::duration('1h'));
        self::assertSame(604800, Inputs::duration('7d'));
        self::assertSame(90, Inputs::duration('90'));
        $this->expectException(UsageException::class);
        Inputs::duration('1 week');
    }

    public function testShareLinkRoundTrip(): void
    {
        $key = random_bytes(32);
        $link = ShareLink::share('https://hush.example/', self::ID, $key);
        $parsed = ShareLink::parseShare($link);

        self::assertStringStartsWith('https://hush.example/s/' . self::ID . '#', $link);
        self::assertSame('https://hush.example', $parsed->origin);
        self::assertSame(self::ID, $parsed->id);
        self::assertSame($key, $parsed->secret);
        self::assertSame('http://127.0.0.1:5140', ShareLink::parseShare('http://127.0.0.1:5140/s/' . self::ID . '#' . str_repeat('A', 43))->origin);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function badLinks(): iterable
    {
        yield 'not a url' => ['hello'];
        yield 'ftp' => ['ftp://hush.example/s/' . self::ID . '#' . str_repeat('A', 43)];
        yield 'no fragment' => ['https://hush.example/s/' . self::ID];
        yield 'short key' => ['https://hush.example/s/' . self::ID . '#AAAA'];
        yield 'bad key chars' => ['https://hush.example/s/' . self::ID . '#' . str_repeat('+', 43)];
        yield 'wrong path' => ['https://hush.example/d/' . self::ID . '#' . str_repeat('A', 43)];
        yield 'short id' => ['https://hush.example/s/abc#' . str_repeat('A', 43)];
    }

    #[DataProvider('badLinks')]
    public function testRejectsBadShareLinks(string $link): void
    {
        $this->expectException(UsageException::class);
        ShareLink::parseShare($link);
    }

    public function testDeleteLinks(): void
    {
        $token = str_repeat('T', 43);
        $parsed = ShareLink::parseDelete(ShareLink::delete('https://hush.example', self::ID, $token));

        self::assertSame($token, $parsed->secret);
        $this->expectException(UsageException::class);
        ShareLink::parseDelete('https://hush.example/d/' . self::ID . '#short');
    }

    public function testSavePathsNeverEscapeTheCurrentDirectory(): void
    {
        self::assertSame('report.pdf', Inputs::savePath(null, 'report.pdf'));
        self::assertSame('passwd', Inputs::savePath(null, '../../etc/passwd'));
        self::assertSame('evil.exe', Inputs::savePath(null, 'C:\\Windows\\evil.exe'));
        self::assertSame('secret-bashrc', Inputs::savePath(null, '.bashrc'));
        self::assertSame('secret.bin', Inputs::savePath(null, null));
        self::assertSame('ab.txt', Inputs::savePath(null, "a\x00b.txt"));
        self::assertSame('chosen.bin', Inputs::savePath('chosen.bin', '../x'));
    }
}
