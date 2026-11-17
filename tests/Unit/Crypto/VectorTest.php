<?php

declare(strict_types=1);

namespace Hush\Tests\Unit\Crypto;

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
 * Pins the PHP implementation to tests/fixtures/vector-v1.json; the
 * JavaScript suite checks the same file (tests/js/vector.test.mjs).
 */
final class VectorTest extends TestCase
{
    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function vectors(): iterable
    {
        $json = file_get_contents(dirname(__DIR__, 2) . '/fixtures/vector-v1.json');
        self::assertIsString($json);
        $data = json_decode($json, true, 16, JSON_THROW_ON_ERROR);
        self::assertIsArray($data);
        self::assertIsArray($data['vectors']);
        foreach ($data['vectors'] as $vector) {
            self::assertIsArray($vector);
            $name = $vector['name'];
            self::assertIsString($name);
            $typed = [];
            foreach ($vector as $key => $value) {
                $typed[(string) $key] = $value;
            }
            yield $name => [$typed];
        }
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[DataProvider('vectors')]
    public function testSealingReproducesThePackage(array $vector): void
    {
        $password = $vector['password'];
        if (is_string($password) && preg_match('/[^\x00-\x7f]/', $password) === 1 && !class_exists(Normalizer::class)) {
            self::markTestSkipped('non-ASCII password needs intl');
        }
        self::assertIsArray($vector['nonces']);
        $nonces = array_map(static fn(mixed $hex): string => self::hex($hex), $vector['nonces']);
        $next = static function () use (&$nonces): string {
            $nonce = array_shift($nonces);
            self::assertIsString($nonce);

            return $nonce;
        };

        $sealed = SecretSealer::seal($this->input($vector), new SealOptions(
            password: is_string($password) ? $password : null,
            iterations: self::int($vector['iterations']),
            chunkSize: self::int($vector['chunkSize']),
            fragmentKey: self::hex($vector['fragmentKey']),
            salt: self::hex($vector['salt']),
            nonces: $next,
        ));

        self::assertSame($vector['package'], Base64Url::encode($sealed->toPackage()->pack()));
        self::assertSame($vector['linkKey'], Base64Url::encode($sealed->fragmentKey));
    }

    /**
     * @param array<string, mixed> $vector
     */
    #[DataProvider('vectors')]
    public function testOpeningRecoversTheInput(array $vector): void
    {
        $password = $vector['password'];
        if (is_string($password) && preg_match('/[^\x00-\x7f]/', $password) === 1 && !class_exists(Normalizer::class)) {
            self::markTestSkipped('non-ASCII password needs intl');
        }
        self::assertIsString($vector['package']);
        self::assertIsString($vector['linkKey']);

        $opened = SecretOpener::open(
            Package::unpack(Base64Url::decode($vector['package'])),
            Base64Url::decode($vector['linkKey']),
            is_string($password) ? $password : null,
        );

        $expected = $this->input($vector);
        self::assertSame($expected->kind, $opened->kind);
        self::assertSame($expected->data, $opened->data);
        self::assertSame($expected->name, $opened->name);
        self::assertSame($expected->type, $opened->type);
    }

    /**
     * @param array<string, mixed> $vector
     */
    private function input(array $vector): PlainSecret
    {
        $input = $vector['input'];
        self::assertIsArray($input);
        if ($input['kind'] === 'text') {
            self::assertIsString($input['text']);

            return PlainSecret::text($input['text']);
        }
        self::assertIsString($input['name']);
        $type = $input['type'] ?? null;

        return PlainSecret::file(self::hex($input['dataHex']), $input['name'], is_string($type) ? $type : null);
    }

    private static function hex(mixed $value): string
    {
        self::assertIsString($value);
        $bytes = hex2bin($value);
        self::assertIsString($bytes);

        return $bytes;
    }

    private static function int(mixed $value): int
    {
        self::assertIsInt($value);

        return $value;
    }
}
