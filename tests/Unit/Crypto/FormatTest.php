<?php

declare(strict_types=1);

namespace Hush\Tests\Unit\Crypto;

use Hush\Crypto\CryptoException;
use Hush\Crypto\Format;
use Hush\Crypto\Header;
use Hush\Crypto\Meta;
use Hush\Crypto\Package;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class FormatTest extends TestCase
{
    public function testHeaderRoundTripAndLayout(): void
    {
        $header = new Header(true, 600_000, str_repeat("\x07", 16), 524_288, 3);
        $bytes = $header->encode();

        self::assertSame(36, strlen($bytes));
        self::assertSame('HUSH', substr($bytes, 0, 4));
        self::assertSame("\x01\x01\x00\x00", substr($bytes, 4, 4));
        self::assertSame(pack('N', 600_000), substr($bytes, 8, 4));
        self::assertSame(pack('N', 3), substr($bytes, 32, 4));
        self::assertEquals($header, Header::parse($bytes));
        self::assertSame(524_288 * 3, $header->maxPayloadBytes());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function malformedHeaders(): iterable
    {
        $valid = (new Header(false, 0, str_repeat("\0", 16), 1024, 1))->encode();

        yield 'short' => [substr($valid, 0, 35), 'must be 36 bytes'];
        yield 'long' => [$valid . "\0", 'must be 36 bytes'];
        yield 'bad magic' => ['HUSX' . substr($valid, 4), 'bad magic'];
        yield 'future version' => [substr_replace($valid, "\x02", 4, 1), 'version 2'];
        yield 'unknown flag' => [substr_replace($valid, "\x02", 5, 1), 'flags 0x02'];
        yield 'reserved set' => [substr_replace($valid, "\x00\x01", 6, 2), 'Reserved'];
        yield 'iterations without password' => [substr_replace($valid, pack('N', 5), 8, 4), 'must be 0'];
        yield 'password with too few iterations' => [substr_replace(substr_replace($valid, "\x01", 5, 1), pack('N', 1000), 8, 4), 'iterations'];
        yield 'absurd iterations' => [substr_replace(substr_replace($valid, "\x01", 5, 1), pack('N', 0xFFFFFFFF), 8, 4), 'iterations'];
        yield 'chunk too small' => [substr_replace($valid, pack('N', 16), 28, 4), 'Chunk size'];
        yield 'chunk too large' => [substr_replace($valid, pack('N', 1_048_832), 28, 4), 'Chunk size'];
        yield 'chunk not a block multiple' => [substr_replace($valid, pack('N', 1025), 28, 4), 'multiple of 256'];
        yield 'zero chunks' => [substr_replace($valid, pack('N', 0), 32, 4), 'Chunk count'];
    }

    #[DataProvider('malformedHeaders')]
    public function testRejectsMalformedHeaders(string $bytes, string $reason): void
    {
        try {
            Header::parse($bytes);
            self::fail('expected a format error');
        } catch (CryptoException $e) {
            self::assertSame('format', $e->reason);
            self::assertStringContainsString($reason, $e->getMessage());
        }
    }

    public function testPaddingHidesShortLengths(): void
    {
        self::assertSame(256, Format::paddedLength(0));
        self::assertSame(256, Format::paddedLength(1));
        self::assertSame(256, Format::paddedLength(256));
        self::assertSame(512, Format::paddedLength(257));
        self::assertSame(3, Format::chunkCount(2560, 1024));
        self::assertSame(1, Format::chunkCount(1024, 1024));
    }

    public function testChunkSizeIsRightSized(): void
    {
        self::assertSame(1024, Format::chooseChunkSize(0));
        self::assertSame(5120, Format::chooseChunkSize(5000));
        self::assertSame(524_288, Format::chooseChunkSize(10 * 1_048_576));
    }

    public function testAadBindsHeaderKindAndIndex(): void
    {
        self::assertSame('H' . "\x01" . "\x00\x00\x01\x02", Format::aad('H', Format::KIND_CHUNK, 258));
    }

    public function testMetaIsPaddedJsonWithFixedKeyOrder(): void
    {
        $encoded = (new Meta('file', 'bảng lương.xlsx', 'application/vnd.ms-excel', 12))->encode();

        self::assertSame(256, strlen($encoded));
        self::assertStringStartsWith('{"kind":"file","name":"bảng lương.xlsx","type":"application/vnd.ms-excel","size":12}', $encoded);
        self::assertSame('', trim(substr($encoded, 90)));
        self::assertEquals(new Meta('file', 'bảng lương.xlsx', 'application/vnd.ms-excel', 12), Meta::parse($encoded));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function malformedMeta(): iterable
    {
        yield 'not padded' => ['{"kind":"text","name":null,"type":null,"size":1}'];
        yield 'not json' => [str_pad('{kind', 256)];
        yield 'extra key' => [str_pad('{"kind":"text","name":null,"type":null,"size":1,"x":1}', 256)];
        yield 'reordered keys' => [str_pad('{"size":1,"kind":"text","name":null,"type":null}', 256)];
        yield 'string size' => [str_pad('{"kind":"text","name":null,"type":null,"size":"1"}', 256)];
        yield 'unknown kind' => [str_pad('{"kind":"exe","name":null,"type":null,"size":1}', 256)];
        yield 'text with name' => [str_pad('{"kind":"text","name":"a","type":null,"size":1}', 256)];
        yield 'control char name' => [str_pad('{"kind":"file","name":"a\u0000b","type":null,"size":1}', 256)];
    }

    #[DataProvider('malformedMeta')]
    public function testRejectsMalformedMeta(string $bytes): void
    {
        $this->expectException(CryptoException::class);
        Meta::parse($bytes);
    }

    public function testTooLongMetaIsRejectedWhenEncoding(): void
    {
        $this->expectException(CryptoException::class);
        new Meta('file', str_repeat('x', 256), null, 1);
    }

    public function testPackageRoundTrip(): void
    {
        $header = (new Header(false, 0, str_repeat("\0", 16), 1024, 2))->encode();
        $meta = str_repeat('m', 256 + 28);
        $package = new Package($header, $meta, [str_repeat('a', 1052), str_repeat('b', 60)]);

        $bytes = $package->pack();

        self::assertSame(36 + 4 + 284 + 4 + 1052 + 4 + 60, strlen($bytes));
        self::assertEquals($package, Package::unpack($bytes));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function malformedPackages(): iterable
    {
        $header = (new Header(false, 0, str_repeat("\0", 16), 1024, 1))->encode();
        $good = (new Package($header, str_repeat('m', 284), [str_repeat('c', 300)]))->pack();

        yield 'empty' => ['', 'before the end of the header'];
        yield 'header only' => [$header, 'length prefix'];
        yield 'cut inside meta' => [substr($good, 0, 100), 'inside a record'];
        yield 'cut inside chunk prefix' => [substr($good, 0, 36 + 4 + 284 + 2), 'length prefix'];
        yield 'cut inside chunk' => [substr($good, 0, -1), 'inside a record'];
        yield 'extra chunk' => [$good . pack('N', 300) . str_repeat('d', 300), 'more chunks'];
        yield 'oversized chunk length' => [$header . pack('N', 284) . str_repeat('m', 284) . pack('N', 1024 + 29), 'out of range'];
        yield 'tiny record' => [$header . pack('N', 28) . str_repeat('m', 28), 'out of range'];
    }

    #[DataProvider('malformedPackages')]
    public function testRejectsMalformedPackages(string $bytes, string $reason): void
    {
        try {
            Package::unpack($bytes);
            self::fail('expected a format error');
        } catch (CryptoException $e) {
            self::assertSame('format', $e->reason);
            self::assertStringContainsString($reason, $e->getMessage());
        }
    }
}
