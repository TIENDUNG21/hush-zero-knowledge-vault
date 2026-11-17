<?php

declare(strict_types=1);

namespace Hush\Tests\Integration;

use Hush\Crypto\Format;
use Hush\Support\Base64Url;
use Hush\Tests\Support\VaultFixture;

/**
 * Security behaviour through the real server, with a tiny create bucket.
 */
final class SecurityIntegrationTest extends IntegrationTestCase
{
    protected static function port(): int
    {
        return 5142;
    }

    protected static function environment(): array
    {
        return ['HUSH_RATE_CREATE' => '3,0.01', 'HUSH_MAX_SECRET_BYTES' => '1048576'];
    }

    public function testSecurityHeadersOnApiAndErrors(): void
    {
        foreach (['/healthz', '/api/secrets/' . str_repeat('A', 22), '/missing'] as $path) {
            $result = $this->request('GET', $path);
            self::assertStringContainsString("default-src 'none'", $result->headers->get('Content-Security-Policy') ?? '', $path);
            self::assertSame('no-referrer', $result->headers->get('Referrer-Policy'), $path);
            self::assertSame('DENY', $result->headers->get('X-Frame-Options'), $path);
            self::assertSame('no-store', $result->headers->get('Cache-Control'), $path);
        }
    }

    public function testCrossOriginWritesAreRefused(): void
    {
        $evil = $this->request('POST', '/api/secrets', [
            'Content-Type' => 'application/json',
            'Origin' => 'https://evil.example',
        ], '{}');
        self::assertSame(403, $evil->status);
        self::assertSame('cross_origin', $this->errorCode($evil));

        $sameOrigin = $this->request('POST', '/api/secrets', [
            'Content-Type' => 'application/json',
            'Origin' => $this->server()->baseUrl,
            'Sec-Fetch-Site' => 'same-origin',
        ], '{}');
        self::assertSame(422, $sameOrigin->status, 'passes the origin check, fails validation');
    }

    public function testOversizedChunkIsRefusedBeforeReading(): void
    {
        $sealed = VaultFixture::sealText();
        [$id, $token] = $this->createOnly($sealed->headerBytes, $sealed->metaRecord);

        $tooBig = $this->request('PUT', "/api/secrets/{$id}/chunks/0", [
            'Content-Type' => 'application/octet-stream',
            'Authorization' => 'Bearer ' . $token,
        ], str_repeat("\0", Format::MAX_CHUNK_SIZE + Format::RECORD_OVERHEAD + 1));
        self::assertSame(413, $tooBig->status);
        self::assertSame('payload_too_large', $this->errorCode($tooBig));

        $wrongLength = $this->request('PUT', "/api/secrets/{$id}/chunks/0", [
            'Content-Type' => 'application/octet-stream',
            'Authorization' => 'Bearer ' . $token,
        ], str_repeat("\0", 5000));
        self::assertSame(422, $wrongLength->status);
        self::assertSame('invalid_chunk_length', $this->errorCode($wrongLength));
    }

    public function testEnvelopeOverTheServerLimitIsRefusedAtCreate(): void
    {
        $sealed = VaultFixture::sealFile(1_100_000, 65_536); // limit is 1 MiB here

        $result = $this->postJson('/api/secrets', [
            'header' => Base64Url::encode($sealed->headerBytes),
            'meta' => Base64Url::encode($sealed->metaRecord),
            'expiresIn' => 600,
            'maxViews' => 1,
        ]);

        self::assertSame(413, $result->status);
        self::assertSame('secret_too_large', $this->errorCode($result));
    }

    public function testCreateIsRateLimited(): void
    {
        $sealed = VaultFixture::sealText();
        $statuses = [];
        $last = null;
        for ($i = 0; $i < 5; $i++) {
            $last = $this->postJson('/api/secrets', [
                'header' => Base64Url::encode($sealed->headerBytes),
                'meta' => Base64Url::encode($sealed->metaRecord),
                'expiresIn' => 600,
                'maxViews' => 1,
            ]);
            $statuses[] = $last->status;
        }

        self::assertContains(429, $statuses);
        self::assertSame(429, $last->status);
        self::assertSame('rate_limited', $this->errorCode($last));
        self::assertGreaterThanOrEqual(1, (int) $last->headers->get('Retry-After'));
        self::assertSame('0', $last->headers->get('RateLimit-Remaining'));
        self::assertStringContainsString("default-src 'none'", $last->headers->get('Content-Security-Policy') ?? '');
    }

    /**
     * @return array{string, string}
     */
    private function createOnly(string $header, string $meta): array
    {
        $created = $this->postJson('/api/secrets', [
            'header' => Base64Url::encode($header),
            'meta' => Base64Url::encode($meta),
            'expiresIn' => 600,
            'maxViews' => 1,
        ]);
        self::assertSame(201, $created->status, $created->body);
        $id = $created->json()['id'] ?? null;
        $token = $created->json()['deletionToken'] ?? null;
        self::assertIsString($id);
        self::assertIsString($token);

        return [$id, $token];
    }
}
