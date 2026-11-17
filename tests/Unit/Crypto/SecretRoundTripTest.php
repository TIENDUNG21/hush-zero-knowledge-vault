<?php

declare(strict_types=1);

namespace Hush\Tests\Unit\Crypto;

use Closure;
use Hush\Crypto\CryptoException;
use Hush\Crypto\Format;
use Hush\Crypto\KeySchedule;
use Hush\Crypto\Package;
use Hush\Crypto\PlainSecret;
use Hush\Crypto\SealOptions;
use Hush\Crypto\SecretOpener;
use Hush\Crypto\SecretSealer;
use InvalidArgumentException;
use Normalizer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SecretRoundTripTest extends TestCase
{
    public function testTextRoundTripsByteExactIncludingAstralCharacters(): void
    {
        $text = "Mật khẩu: \u{1F510} \u{20000}\r\nzero\u{200B}width";
        $sealed = SecretSealer::seal(PlainSecret::text($text), new SealOptions(chunkSize: 1024));

        $opened = SecretOpener::open(Package::unpack($sealed->toPackage()->pack()), $sealed->fragmentKey);

        self::assertSame('text', $opened->kind);
        self::assertSame($text, $opened->data);
        self::assertNull($opened->name);
    }

    public function testEmptyTextIsPaddedToOneBlock(): void
    {
        $sealed = SecretSealer::seal(PlainSecret::text(''), new SealOptions(chunkSize: 1024));
        $package = $sealed->toPackage();

        self::assertSame(1, $sealed->header->chunkCount);
        self::assertSame(256 + Format::RECORD_OVERHEAD, strlen($package->chunks[0]));
        self::assertSame('', SecretOpener::open($package, $sealed->fragmentKey)->data);
    }

    public function testShortSecretsAreIndistinguishableBySize(): void
    {
        $a = SecretSealer::seal(PlainSecret::text('no'), new SealOptions(chunkSize: 1024))->toPackage()->pack();
        $b = SecretSealer::seal(PlainSecret::text(str_repeat('y', 250)), new SealOptions(chunkSize: 1024))->toPackage()->pack();

        self::assertSame(strlen($a), strlen($b));
    }

    public function testMultiChunkFileRoundTrip(): void
    {
        $data = random_bytes(2500);
        $sealed = SecretSealer::seal(PlainSecret::file($data, 'scan.png', 'image/png'), new SealOptions(chunkSize: 1024));

        self::assertSame(3, $sealed->header->chunkCount);
        $opened = SecretOpener::open($sealed->toPackage(), $sealed->fragmentKey);
        self::assertSame($data, $opened->data);
        self::assertSame('scan.png', $opened->name);
        self::assertSame('image/png', $opened->type);
    }

    public function testFileExactlyFillingChunksHasNoExtraChunk(): void
    {
        $sealed = SecretSealer::seal(PlainSecret::file(random_bytes(2048), 'x.bin'), new SealOptions(chunkSize: 1024));

        self::assertSame(2, $sealed->header->chunkCount);
        self::assertSame(2048, strlen(SecretOpener::open($sealed->toPackage(), $sealed->fragmentKey)->data));
    }

    public function testPasswordIsRequiredAndChecked(): void
    {
        $sealed = SecretSealer::seal(PlainSecret::text('pin 4321'), new SealOptions(password: 'hunter2', iterations: 100_000, chunkSize: 1024));
        $package = $sealed->toPackage();

        self::assertTrue($sealed->header->passwordProtected);
        self::assertSame('pin 4321', SecretOpener::open($package, $sealed->fragmentKey, 'hunter2')->data);
        $this->assertReason('password_required', static fn() => SecretOpener::open($package, $sealed->fragmentKey));
        $this->assertReason('authentication', static fn() => SecretOpener::open($package, $sealed->fragmentKey, 'hunter3'));
    }

    public function testPasswordWithoutTheLinkKeyIsUseless(): void
    {
        $sealed = SecretSealer::seal(PlainSecret::text('x'), new SealOptions(password: 'pw', iterations: 100_000, chunkSize: 1024));

        $this->assertReason('authentication', static fn() => SecretOpener::open($sealed->toPackage(), random_bytes(32), 'pw'));
    }

    public function testNfdAndNfcPasswordsDeriveTheSameKey(): void
    {
        if (!class_exists(Normalizer::class)) {
            self::markTestSkipped('intl is not loaded');
        }
        $nfc = "M\u{1EAD}t kh\u{1EA9}u";
        $nfd = Normalizer::normalize($nfc, Normalizer::FORM_D);
        self::assertIsString($nfd);
        self::assertNotSame($nfc, $nfd);

        $sealed = SecretSealer::seal(PlainSecret::text('ok'), new SealOptions(password: $nfd, iterations: 100_000, chunkSize: 1024));

        self::assertSame('ok', SecretOpener::open($sealed->toPackage(), $sealed->fragmentKey, $nfc)->data);
        self::assertSame($nfc, KeySchedule::normalizePassword($nfd));
    }

    public function testWrongKeyFailsAuthentication(): void
    {
        $sealed = SecretSealer::seal(PlainSecret::text('x'), new SealOptions(chunkSize: 1024));

        $this->assertReason('authentication', static fn() => SecretOpener::open($sealed->toPackage(), random_bytes(32)));
        $this->assertReason('format', static fn() => SecretOpener::open($sealed->toPackage(), random_bytes(31)));
    }

    /**
     * @return iterable<string, array{Closure(Package): Package, string}>
     */
    public static function tamperings(): iterable
    {
        yield 'swap chunks' => [static fn(Package $p): Package => new Package($p->headerBytes, $p->meta, [$p->chunks[1], $p->chunks[0], $p->chunks[2]]), 'authentication'];
        yield 'drop last chunk' => [static fn(Package $p): Package => new Package($p->headerBytes, $p->meta, [$p->chunks[0], $p->chunks[1]]), 'integrity'];
        yield 'duplicate chunk' => [static fn(Package $p): Package => new Package($p->headerBytes, $p->meta, [$p->chunks[0], $p->chunks[0], $p->chunks[2]]), 'authentication'];
        yield 'flip chunk bit' => [static fn(Package $p): Package => new Package($p->headerBytes, $p->meta, [$p->chunks[0], self::flip($p->chunks[1], 40), $p->chunks[2]]), 'authentication'];
        yield 'flip nonce bit' => [static fn(Package $p): Package => new Package($p->headerBytes, $p->meta, [self::flip($p->chunks[0], 0), $p->chunks[1], $p->chunks[2]]), 'authentication'];
        yield 'flip tag bit' => [static fn(Package $p): Package => new Package($p->headerBytes, $p->meta, [$p->chunks[0], $p->chunks[1], self::flip($p->chunks[2], strlen($p->chunks[2]) - 1)]), 'authentication'];
        yield 'flip meta bit' => [static fn(Package $p): Package => new Package($p->headerBytes, self::flip($p->meta, 20), $p->chunks), 'authentication'];
        yield 'change salt in header' => [static fn(Package $p): Package => new Package(self::flip($p->headerBytes, 13), $p->meta, $p->chunks), 'authentication'];
        yield 'lower chunk count in header' => [static fn(Package $p): Package => new Package(substr_replace($p->headerBytes, pack('N', 2), 32, 4), $p->meta, [$p->chunks[0], $p->chunks[1]]), 'authentication'];
    }

    /**
     * @param Closure(Package): Package $tamper
     */
    #[DataProvider('tamperings')]
    public function testTamperingIsDetected(Closure $tamper, string $reason): void
    {
        $sealed = SecretSealer::seal(PlainSecret::file(random_bytes(2500), 'a.bin'), new SealOptions(chunkSize: 1024));
        $tampered = $tamper($sealed->toPackage());

        $this->assertReason($reason, static fn() => SecretOpener::open($tampered, $sealed->fragmentKey));
    }

    public function testRechunkedPayloadFromAnotherEnvelopeIsRejected(): void
    {
        $sealed = SecretSealer::seal(PlainSecret::text('one'), new SealOptions(chunkSize: 1024));
        $other = SecretSealer::seal(PlainSecret::text('two'), new SealOptions(chunkSize: 1024, fragmentKey: $sealed->fragmentKey));

        $mixed = new Package($sealed->toPackage()->headerBytes, $sealed->metaRecord, $other->toPackage()->chunks);

        $this->assertReason('authentication', static fn() => SecretOpener::open($mixed, $sealed->fragmentKey));
    }

    public function testNonUtf8TextIsRefusedBeforeEncryption(): void
    {
        $this->expectException(InvalidArgumentException::class);
        PlainSecret::text("\xC3\x28");
    }

    public function testFreshKeysSaltsAndNoncesEveryTime(): void
    {
        $a = SecretSealer::seal(PlainSecret::text('same'), new SealOptions(chunkSize: 1024));
        $b = SecretSealer::seal(PlainSecret::text('same'), new SealOptions(chunkSize: 1024));

        self::assertNotSame($a->fragmentKey, $b->fragmentKey);
        self::assertNotSame($a->header->salt, $b->header->salt);
        self::assertNotSame(substr($a->metaRecord, 0, 12), substr($b->metaRecord, 0, 12));
    }

    private static function flip(string $bytes, int $offset): string
    {
        $bytes[$offset] = chr(ord($bytes[$offset]) ^ 0x01);

        return $bytes;
    }

    /**
     * @param Closure(): mixed $action
     */
    private function assertReason(string $reason, Closure $action): void
    {
        try {
            $action();
            self::fail(sprintf('expected a %s error', $reason));
        } catch (CryptoException $e) {
            self::assertSame($reason, $e->reason, $e->getMessage());
        }
    }
}
