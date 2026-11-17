<?php

declare(strict_types=1);

/*
 * Regenerates tests/fixtures/vector-v1.json from fixed inputs.
 * Run: php tests/fixtures/make-vector.php
 * The PHP and JavaScript test suites both assert byte-for-byte equality
 * with this file, which is what keeps the two implementations compatible.
 */

use Hush\Crypto\PlainSecret;
use Hush\Crypto\SealOptions;
use Hush\Crypto\SecretSealer;
use Hush\Support\Base64Url;

require dirname(__DIR__, 2) . '/vendor/autoload.php';

/**
 * @param array{kind: string, text?: string, name?: string, type?: string|null, dataHex?: string} $input
 *
 * @return array<string, mixed>
 */
function makeVector(string $name, array $input, ?string $password, int $chunkSize, int $seed): array
{
    $fragmentKey = '';
    for ($i = 0; $i < 32; $i++) {
        $fragmentKey .= chr(($seed + $i) & 0xFF);
    }
    $salt = '';
    for ($i = 0; $i < 16; $i++) {
        $salt .= chr(($seed * 3 + 0x40 + $i) & 0xFF);
    }
    $nonces = [];
    $counter = 0;
    $nextNonce = static function () use (&$counter, &$nonces, $seed): string {
        $nonce = str_repeat(chr(($seed + 0xA0 + $counter) & 0xFF), 12);
        $counter++;
        $nonces[] = bin2hex($nonce);

        return $nonce;
    };

    $secret = $input['kind'] === 'text'
        ? PlainSecret::text($input['text'] ?? '')
        : PlainSecret::file((string) hex2bin($input['dataHex'] ?? ''), $input['name'] ?? 'file.bin', $input['type'] ?? null);

    $sealed = SecretSealer::seal($secret, new SealOptions(
        password: $password,
        iterations: 100_000,
        chunkSize: $chunkSize,
        fragmentKey: $fragmentKey,
        salt: $salt,
        nonces: $nextNonce,
    ));
    $package = $sealed->toPackage()->pack();

    return [
        'name' => $name,
        'input' => $input,
        'password' => $password,
        'iterations' => 100_000,
        'chunkSize' => $chunkSize,
        'fragmentKey' => bin2hex($fragmentKey),
        'salt' => bin2hex($salt),
        'nonces' => $nonces,
        'linkKey' => Base64Url::encode($fragmentKey),
        'package' => Base64Url::encode($package),
        'packageSha256' => hash('sha256', $package),
    ];
}

$fileData = '';
for ($i = 0; $i < 2500; $i++) {
    $fileData .= chr(($i * 7) % 251);
}

$vectors = [
    makeVector('text without password', ['kind' => 'text', 'text' => "Hush test vector: m\u{1EAD}t kh\u{1EA9}u \u{1F510}\nline two"], null, 1024, 1),
    makeVector('text with Vietnamese password', ['kind' => 'text', 'text' => 'wifi: hush-guest / 0912 345 678'], "M\u{1EAD}t kh\u{1EA9}u b\u{00ED} m\u{1EAD}t", 1024, 2),
    makeVector('three-chunk file with password', [
        'kind' => 'file',
        'name' => 'report final.pdf',
        'type' => 'application/pdf',
        'dataHex' => bin2hex($fileData),
    ], 'correct horse battery staple', 1024, 3),
];

$json = json_encode(
    ['format' => 'HUSH v1', 'generator' => 'tests/fixtures/make-vector.php', 'vectors' => $vectors],
    JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
);
file_put_contents(__DIR__ . '/vector-v1.json', $json . "\n");
echo 'Wrote ', count($vectors), " vectors\n";
