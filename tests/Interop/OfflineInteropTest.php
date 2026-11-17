<?php

declare(strict_types=1);

namespace Hush\Tests\Interop;

use Hush\Crypto\Package;
use Hush\Crypto\PlainSecret;
use Hush\Crypto\SealOptions;
use Hush\Crypto\SecretOpener;
use Hush\Crypto\SecretSealer;
use Hush\Support\Base64Url;
use Normalizer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Envelopes made by one implementation are opened by the other, in both
 * directions, with no server in between.
 */
final class OfflineInteropTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/hush-interop-' . bin2hex(random_bytes(4));
        mkdir($this->dir);
    }

    protected function tearDown(): void
    {
        $files = glob($this->dir . '/*');
        foreach ($files !== false ? $files : [] as $file) {
            unlink($file);
        }
        rmdir($this->dir);
    }

    /**
     * @return iterable<string, array{PlainSecret, ?string, ?string}> secret, password for sealing, password for opening
     */
    public static function cases(): iterable
    {
        $nfc = "M\u{1EAD}t kh\u{1EA9}u b\u{00ED} m\u{1EAD}t";
        $nfd = class_exists(Normalizer::class) ? Normalizer::normalize($nfc, Normalizer::FORM_D) : $nfc;

        yield 'ascii text' => [PlainSecret::text('postgres://app:s3cret@db/prod'), null, null];
        yield 'unicode text, NFD password sealed, NFC opened' => [PlainSecret::text("Tiếng Việt \u{1F510} \u{20000}\r\nline"), is_string($nfd) ? $nfd : $nfc, $nfc];
        yield 'empty file' => [PlainSecret::file('', 'empty.txt', 'text/plain'), null, null];
        yield '1.2 MB file in three chunks with password' => [PlainSecret::file(random_bytes(1_200_000), 'backup.tar.gz', 'application/gzip'), 'pw', 'pw'];
    }

    #[DataProvider('cases')]
    public function testPhpSealsJavaScriptOpens(PlainSecret $secret, ?string $sealPassword, ?string $openPassword): void
    {
        $sealed = SecretSealer::seal($secret, new SealOptions(password: $sealPassword, iterations: 100_000));
        $path = $this->dir . '/php.hush';
        file_put_contents($path, $sealed->toPackage()->pack());

        $result = Node::call('open', $path, ['key' => Base64Url::encode($sealed->fragmentKey), 'password' => $openPassword]);

        $opened = $result['opened'];
        self::assertIsArray($opened);
        self::assertSame($secret->kind, $opened['kind']);
        self::assertSame(hash('sha256', $secret->data), $opened['sha256']);
        self::assertSame($secret->name, $opened['name']);
        self::assertSame($secret->type, $opened['type']);
        if ($secret->kind === 'text') {
            self::assertSame($secret->data, $opened['text']);
        }
    }

    #[DataProvider('cases')]
    public function testJavaScriptSealsPhpOpens(PlainSecret $secret, ?string $sealPassword, ?string $openPassword): void
    {
        $path = $this->dir . '/js.hush';
        $spec = $secret->kind === 'text'
            ? ['kind' => 'text', 'text' => $secret->data]
            : ['kind' => 'file', 'dataBase64' => base64_encode($secret->data), 'name' => $secret->name, 'type' => $secret->type];

        $result = Node::call('seal', $path, ['secret' => $spec, 'password' => $sealPassword]);
        self::assertIsString($result['key']);

        $opened = SecretOpener::open(Package::unpack((string) file_get_contents($path)), Base64Url::decode($result['key']), $openPassword);
        self::assertSame($secret->kind, $opened->kind);
        self::assertSame($secret->data, $opened->data);
        self::assertSame($secret->name, $opened->name);
        self::assertSame($secret->type, $opened->type);
    }

    public function testCliEncryptsWhatNodeDecrypts(): void
    {
        $path = $this->dir . '/cli.hush';
        [$code, $stdout, $stderr] = Node::run([PHP_BINARY, 'bin/hush', 'encrypt', '--out', $path], "from the CLI \u{2713}");
        self::assertSame(0, $code, $stderr);

        $result = Node::call('open', $path, ['key' => trim($stdout)]);

        self::assertIsArray($result['opened']);
        self::assertSame("from the CLI \u{2713}", $result['opened']['text']);
    }
}
